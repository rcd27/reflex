//! Риг-loader прозрачного L2-заворота — проекция `model/wire/TransparentIntercept`.
//!
//! Фаза 0 (BL-215, make-or-break): цепляет `reflex_tc` на egress интерфейса с ПУСТОЙ
//! ACTION_TABLE = чистый passthrough (всё → `TC_ACT_OK`). Держит, пока жив. Задача теста —
//! подтвердить на R2S-стенде, что TC-clsact attach НЕ рвёт транзит (Keenetic онлайн), в
//! отличие от br_netfilter (BL-108). Фаза 1 (позже): `steer_target` для целевых флоу.
//!
//! Запуск на стенде: `l2_steer <iface>` (напр. eth0/eth1/br0), под root (CAP_NET_ADMIN).

use reflex_linux::tc::TcProgram;
use std::time::Duration;

// Собранный объект `reflex_tc` (bpfel-unknown-none). Сборка:
//   cd reflex/linux-ebpf && cargo +nightly build --target bpfel-unknown-none \
//     -Z build-std=core --release
// TODO(BL-213): заменить хрупкий относительный путь на aya-build (build.rs эмитит OUT_DIR).
static BPF_OBJECT: &[u8] =
    aya::include_bytes_aligned!("../../linux-ebpf/target/bpfel-unknown-none/release/reflex-xdp");

fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let args: Vec<String> = std::env::args().collect();
    let iface = args.get(1).cloned().unwrap_or_else(|| {
        eprintln!("usage: l2_steer <iface> [steer <proxy_ip> <proxy_port> <target_ip>...]");
        std::process::exit(2);
    });

    // Режим `steer`: reflex_steer на INGRESS + STEER_CFG (BL-213 Phase 1, verifier-load тест
    // sk_assign). Иначе — reflex_tc на EGRESS, пустая таблица (Phase 0 passthrough транзит-safety).
    let steer = args.get(2).map(|s| s == "steer").unwrap_or(false);

    // Держим `TcProgram` живым весь loop — его Drop отцепляет программу (RAII).
    let held = if steer {
        let proxy_ip: std::net::Ipv4Addr = args
            .get(3)
            .and_then(|s| s.parse().ok())
            .unwrap_or(std::net::Ipv4Addr::new(127, 0, 0, 1));
        let proxy_port: u16 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(11080);
        // Несущая (nevod0): вход steer редиректит В неё, reflex_return читает ответ ИЗ неё. Должна
        // СУЩЕСТВОВАТЬ до attach. Порт клиента (eth1): reflex_return отдаёт готовый L2-кадр туда.
        let redirect_dev =
            std::env::var("STEER_REDIRECT_DEV").unwrap_or_else(|_| "nevod0".to_string());
        let return_dev = std::env::var("STEER_RETURN_DEV").unwrap_or_else(|_| "eth1".to_string());

        // ОДИН Ebpf на ОБА хука круга → карты ОБЩИЕ (steer учит CLIENT_MACS из forward, return читает).
        let mut tc = match TcProgram::attach_steer_and_return(&iface, &redirect_dev, BPF_OBJECT) {
            Ok(tc) => tc,
            Err(e) => {
                eprintln!(
                    "[l2_steer] attach steer+return ({iface}+{redirect_dev}) провалился (verifier? nevod0 up?): {e}"
                );
                std::process::exit(1);
            }
        };
        // L2-доставка входа: dst-MAC заворота → MAC моста (br0), иначе мост форвардит по чужому MAC.
        match bridge_mac(&iface) {
            Ok(mac) => {
                if let Err(e) = tc.set_steer_mac(mac) {
                    eprintln!("[l2_steer] set_steer_mac провалился: {e}");
                    std::process::exit(1);
                }
                eprintln!(
                    "[l2_steer] L2-доставка входа: dst-MAC → {} (мост)",
                    fmt_mac(&mac)
                );
            }
            Err(e) => {
                eprintln!("[l2_steer] не прочитал MAC моста для {iface}: {e}");
                std::process::exit(1);
            }
        }
        // ВХОД: bpf_redirect(nevod0) — ifindex несущей в STEER_IFINDEX (L2-native, минует ip_forward).
        match dev_ifindex(&redirect_dev) {
            Ok(ifx) => match tc.set_steer_ifindex(ifx) {
                Ok(()) => eprintln!("[l2_steer] вход → {redirect_dev} (ifindex {ifx})"),
                Err(e) => eprintln!("[l2_steer] set_steer_ifindex провалился: {e}"),
            },
            Err(e) => eprintln!(
                "[l2_steer] нет ifindex {redirect_dev} ({e}) — подними nevod --tun ДО steer"
            ),
        }
        // ВОЗВРАТ: bpf_redirect(eth1) — ifindex порта клиента + src-MAC=eth1. dst-MAC учит сам eBPF из
        // forward-кадров (CLIENT_MACS) — портируемо ЗА ЛЮБЫМ роутером без конфига клиента.
        match dev_ifindex(&return_dev) {
            Ok(ifx) => match tc.set_return_ifindex(ifx) {
                Ok(()) => eprintln!(
                    "[l2_steer] возврат → {return_dev} (ifindex {ifx}); dst-MAC учится из forward"
                ),
                Err(e) => eprintln!("[l2_steer] set_return_ifindex: {e}"),
            },
            Err(e) => eprintln!("[l2_steer] нет ifindex {return_dev} ({e}) — возврат на транзите"),
        }
        match dev_mac(&return_dev) {
            Ok(src) => match tc.set_return_src_mac(src) {
                Ok(()) => eprintln!(
                    "[l2_steer] возврат src-MAC = {} ({return_dev})",
                    fmt_mac(&src)
                ),
                Err(e) => eprintln!("[l2_steer] set_return_src_mac: {e}"),
            },
            Err(e) => {
                eprintln!("[l2_steer] не прочитал MAC {return_dev}: {e} — возврат на транзите")
            }
        }
        // Целевые dst-IP (args[5..]) — легаси per-domain (обычно пусто; гейт = dport 443).
        for t in args.iter().skip(5) {
            match t.parse::<std::net::Ipv4Addr>() {
                Ok(ip) => match tc.add_steer_target(ip) {
                    Ok(()) => eprintln!("[l2_steer] цель заворота: {ip}"),
                    Err(e) => eprintln!("[l2_steer] add_steer_target {ip}: {e}"),
                },
                Err(_) => eprintln!("[l2_steer] пропущен не-IPv4 target: {t}"),
            }
        }
        eprintln!(
            "[l2_steer] КРУГ на {iface}: вход→{redirect_dev}, возврат→{return_dev}; несущая {proxy_ip}:{proxy_port}"
        );
        tc
    } else {
        let tc = match TcProgram::attach(&iface, BPF_OBJECT) {
            Ok(tc) => tc,
            Err(e) => {
                eprintln!("[l2_steer] attach на {iface} провалился: {e}");
                std::process::exit(1);
            }
        };
        tracing::info!(iface = %tc.interface(), "reflex_tc прицеплен на egress; ACTION_TABLE пуста (passthrough)");
        eprintln!("[l2_steer] attached на {iface}. Транзит должен ЖИТЬ (пустая таблица = всё Pass). Ctrl-C для отцепки.");
        tc
    };

    // Держим программу прицепленной. Стата каждые 5с (Правило 17): вход (steer) + возврат (return) — ОБА
    // хука живут в одном `held` (общий Ebpf, общие карты). Где счётчик проваливается в 0 — там теряется кадр.
    loop {
        std::thread::sleep(Duration::from_secs(5));
        if steer {
            match held.steer_stats_line() {
                Ok(line) => tracing::info!(target: "steer_stats", "{line}"),
                Err(e) => tracing::warn!("steer_stats недоступны: {e}"),
            }
            match held.return_stats_line() {
                Ok(line) => tracing::info!(target: "steer_stats", "{line}"),
                Err(e) => tracing::warn!("return_stats недоступны: {e}"),
            }
        }
    }
}

/// MAC, на который переписывать dst завёрнутого кадра, чтобы мост отдал его в локальный стек.
/// Кадр доставляется наверх по MAC МОСТА (master слейва), не самого слейва — читаем master,
/// иначе (не в мосту) сам iface.
fn bridge_mac(iface: &str) -> std::io::Result<[u8; 6]> {
    let master = std::fs::read_link(format!("/sys/class/net/{iface}/master"))
        .ok()
        .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
        .unwrap_or_else(|| iface.to_string());
    let raw = std::fs::read_to_string(format!("/sys/class/net/{master}/address"))?;
    parse_mac(raw.trim())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "не MAC"))
}

/// MAC самого устройства (не master) из `/sys/class/net/<dev>/address` — src обратного L2-кадра.
fn dev_mac(dev: &str) -> std::io::Result<[u8; 6]> {
    let raw = std::fs::read_to_string(format!("/sys/class/net/{dev}/address"))?;
    parse_mac(raw.trim())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "не MAC"))
}

/// 6 байт → `aa:bb:cc:dd:ee:ff` для лога.
fn fmt_mac(m: &[u8; 6]) -> String {
    m.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// ifindex устройства из `/sys/class/net/<dev>/ifindex` (для L2-редиректа в несущую).
fn dev_ifindex(dev: &str) -> std::io::Result<u32> {
    let raw = std::fs::read_to_string(format!("/sys/class/net/{dev}/ifindex"))?;
    raw.trim()
        .parse::<u32>()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// `aa:bb:cc:dd:ee:ff` → 6 байт.
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut n = 0usize;
    for (i, part) in s.split(':').enumerate() {
        if i >= 6 {
            return None;
        }
        out[i] = u8::from_str_radix(part, 16).ok()?;
        n += 1;
    }
    (n == 6).then_some(out)
}
