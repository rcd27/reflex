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
        let mut tc = match TcProgram::attach_steer(&iface, BPF_OBJECT) {
            Ok(tc) => tc,
            Err(e) => {
                eprintln!("[l2_steer] attach_steer на {iface} провалился (verifier?): {e}");
                std::process::exit(1);
            }
        };
        // proxy_ip/proxy_port (args 3/4) — легаси sk_assign-пути (STEER_CFG удалён); доставку теперь
        // делает nft DNAT в deploy-скрипте. Позиции args сохранены, чтобы deploy не менять; значения
        // лишь печатаются как «куда DNAT шлёт».
        // L2-доставка (BL-215 Phase 1): dst-MAC заворота → MAC моста, иначе мост форвардит по чужому
        // MAC и sk_assign не консультируется. Читаем MAC master'а слейва (br0), не самого слейва.
        match bridge_mac(&iface) {
            Ok(mac) => {
                if let Err(e) = tc.set_steer_mac(mac) {
                    eprintln!("[l2_steer] set_steer_mac провалился: {e}");
                    std::process::exit(1);
                }
                eprintln!(
                    "[l2_steer] L2-доставка: dst-MAC → {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (мост)",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                );
            }
            Err(e) => {
                eprintln!("[l2_steer] не прочитал MAC моста для {iface}: {e}");
                std::process::exit(1);
            }
        }
        // L2-РЕДИРЕКТ в устройство несущей (nevod0): ifindex из sysfs → карта STEER_IFINDEX. eBPF
        // отправит целевой кадр прямо в xmit устройства, минуя ip_rcv/ip_forward (L2-native, как
        // AF_PACKET) — обходит forward→tun дроп и conntrack-игнор лифтнутых кадров. Env
        // STEER_REDIRECT_DEV (дефолт nevod0); устройство должно СУЩЕСТВОВАТЬ (nevod --tun поднят до steer).
        let redirect_dev =
            std::env::var("STEER_REDIRECT_DEV").unwrap_or_else(|_| "nevod0".to_string());
        match dev_ifindex(&redirect_dev) {
            Ok(ifx) => match tc.set_steer_ifindex(ifx) {
                Ok(()) => eprintln!("[l2_steer] L2-редирект → {redirect_dev} (ifindex {ifx})"),
                Err(e) => eprintln!("[l2_steer] set_steer_ifindex провалился: {e}"),
            },
            Err(e) => eprintln!(
                "[l2_steer] нет ifindex {redirect_dev} ({e}) — fallback MAC-lift (подними nevod --tun ДО steer)"
            ),
        }
        // Целевые dst-IP (блокируемые домены) — args[5..]. eBPF заворачивает TCP-флоу к ним.
        for t in args.iter().skip(5) {
            match t.parse::<std::net::Ipv4Addr>() {
                Ok(ip) => match tc.add_steer_target(ip) {
                    Ok(()) => eprintln!("[l2_steer] цель заворота: {ip}"),
                    Err(e) => eprintln!("[l2_steer] add_steer_target {ip}: {e}"),
                },
                Err(_) => eprintln!("[l2_steer] пропущен не-IPv4 target: {t}"),
            }
        }
        tracing::info!(iface = %tc.interface(), %proxy_ip, proxy_port, "reflex_steer прицеплен на INGRESS (sk_assign)");
        eprintln!("[l2_steer] STEER на {iface} ingress → несущая {proxy_ip}:{proxy_port}. Verifier ПРИНЯЛ sk_assign.");
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

    // ОБРАТНАЯ половина круга (L2RedirectEth1, модель SteerDatapath `.tobe`): reflex_return на INGRESS
    // несущей (nevod0) сам клеит Ethernet (dst=client-MAC, src=eth1-MAC) и `bpf_redirect(eth1)` прямо в
    // порт клиента — минуя kernel-форвард (ЧД) и neigh-резолв (провал bpf_redirect_neigh). Держим живым.
    let return_held = if steer {
        let redirect_dev =
            std::env::var("STEER_REDIRECT_DEV").unwrap_or_else(|_| "nevod0".to_string());
        // Порт клиента, куда bpf_redirect отдаёт готовый L2-кадр (физпорт, не мост — детерминированно).
        let return_dev = std::env::var("STEER_RETURN_DEV").unwrap_or_else(|_| "eth1".to_string());
        let ret_ifx = dev_ifindex(&return_dev).unwrap_or(0);
        // dst=MAC клиента (STEER_CLIENT_MAC, либо резолв по STEER_CLIENT_IP из /proc/net/arp),
        // src=MAC самого порта возврата. Обе нужны, иначе eBPF оставит кадр на транзите (fail-open).
        let client_mac = resolve_client_mac();
        let src_mac = dev_mac(&return_dev).ok();
        match TcProgram::attach_return(&redirect_dev, BPF_OBJECT) {
            Ok(mut tcr) => {
                match tcr.set_return_ifindex(ret_ifx) {
                    Ok(()) => eprintln!(
                        "[l2_steer] reflex_return на {redirect_dev} INGRESS → {return_dev} (ifindex {ret_ifx})"
                    ),
                    Err(e) => eprintln!("[l2_steer] set_return_ifindex: {e}"),
                }
                match (client_mac, src_mac) {
                    (Some(dst), Some(src)) => match tcr.set_return_mac(dst, src) {
                        Ok(()) => eprintln!(
                            "[l2_steer] return L2: dst={} src={} (→ {return_dev})",
                            fmt_mac(&dst),
                            fmt_mac(&src)
                        ),
                        Err(e) => eprintln!("[l2_steer] set_return_mac: {e}"),
                    },
                    _ => eprintln!(
                        "[l2_steer] return MAC не задан (client={client_mac:?} src={src_mac:?}) — \
                         задай STEER_CLIENT_MAC/STEER_CLIENT_IP; возврат на транзите (fail-open)"
                    ),
                }
                Some(tcr)
            }
            Err(e) => {
                eprintln!("[l2_steer] attach_return на {redirect_dev} провалился: {e}");
                None
            }
        }
    } else {
        None
    };

    // Держим программу прицепленной. В режиме steer печатаем datapath-снапшот каждые 5с (Правило 17):
    // seen→ipv4_tcp→target_hit→established_hit/listener_hit→assigned. Где счётчик проваливается в 0 —
    // там теряется кадр. Это то, что делает «почему не заворачивается» наблюдаемым, а не гаданием.
    loop {
        std::thread::sleep(Duration::from_secs(5));
        if steer {
            match held.steer_stats_line() {
                Ok(line) => tracing::info!(target: "steer_stats", "{line}"),
                Err(e) => tracing::warn!("steer_stats недоступны: {e}"),
            }
            if let Some(r) = return_held.as_ref() {
                match r.return_stats_line() {
                    Ok(line) => tracing::info!(target: "steer_stats", "{line}"),
                    Err(e) => tracing::warn!("return_stats недоступны: {e}"),
                }
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

/// MAC клиента (dst обратного L2-кадра): сперва явный `STEER_CLIENT_MAC`, иначе резолв по
/// `STEER_CLIENT_IP` из `/proc/net/arp` (busybox гол — `ip neigh` нет, но /proc есть).
fn resolve_client_mac() -> Option<[u8; 6]> {
    if let Ok(m) = std::env::var("STEER_CLIENT_MAC") {
        if let Some(mac) = parse_mac(m.trim()) {
            return Some(mac);
        }
    }
    let ip = std::env::var("STEER_CLIENT_IP").ok()?;
    let arp = std::fs::read_to_string("/proc/net/arp").ok()?;
    arp.lines()
        .skip(1) // заголовок
        .find(|l| l.split_whitespace().next() == Some(ip.as_str()))
        .and_then(|l| l.split_whitespace().nth(3)) // колонка HW address
        .and_then(parse_mac)
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
