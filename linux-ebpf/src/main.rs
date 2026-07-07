#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{classifier, map},
    maps::{Array, HashMap},
    programs::TcContext,
};
use aya_ebpf_bindings::helpers::{bpf_redirect, bpf_skb_change_head, bpf_skb_store_bytes};
use reflex_linux_common::{FlowAction, SteerStat, STEER_STAT_SLOTS};

const TC_ACT_OK: i32 = 0; // pass
const TC_ACT_SHOT: i32 = 2; // drop
const MARKER_IP_ID: u16 = 0xDEAD; // injected packets marker

#[map]
static ACTION_TABLE: HashMap<u32, u8> = HashMap::with_max_entries(4096, 0);

// Цели заворота по dst-IP (__be32, network order) — блокируемые домены (`isTarget`). Ключ dst, НЕ
// 5-tuple: клиентский порт эфемерен, «завернуть всё к цели» выразимо лишь по назначению.
#[map]
static STEER_TARGETS: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

// MAC моста (br0) для L2-доставки: userspace ставит 6 байт перед attach. Заворот переписывает dst-MAC
// целевого кадра на этот адрес → мост отдаёт кадр НАВЕРХ в локальный стек (br_pass_frame_up→ip_rcv),
// а не форвардит по чужому MAC (корень «sk_assign на мосту игнорится»). Все нули = не переписывать.
#[map]
static STEER_MAC: Array<u8> = Array::with_max_entries(6, 0);

// Datapath-счётчики заворота (Правило 17): по слоту на стадию `try_steer`. Userspace читает и
// печатает — где счётчик проваливается в 0, там теряется кадр. Слоты = `SteerStat` (общий контракт).
#[map]
static STEER_STATS: Array<u64> = Array::with_max_entries(STEER_STAT_SLOTS, 0);

// ifindex устройства несущей (nevod0) для L2-РЕДИРЕКТА (`bpf_redirect`): userspace ставит перед attach.
// Редирект отправляет кадр прямо в xmit устройства на TC-хуке, МИНУЯ `ip_rcv`/`ip_forward` целиком —
// обходит forward→tun дроп И conntrack-игнор лифтнутых кадров (измерено 2026-07-07: L3-доставка
// лифтнутого мостового кадра на этой коробке ломается при brnf=0). 0 = не редиректить (fallback на
// MAC-lift, legacy). Это L2-native путь, как AF_PACKET — ничего не входит в L3, ломаться нечему.
#[map]
static STEER_IFINDEX: Array<u32> = Array::with_max_entries(1, 0);

// ifindex устройства НАЗАД к клиенту (eth1, порт клиента) для ОБРАТНОГО L2-редиректа. Датаплейн —
// КРУГ: вход мы сделали L2-native (`bpf_redirect(nevod0)`), и ВЫХОД netstack→клиент делаем ЗЕРКАЛЬНО.
// Обычный kernel-форвард nevod0→br0 эта коробка РОНЯЕТ (измерено: 176 SYN-ACK на nevod0, 0 на br0), а
// `bpf_redirect_neigh(br0)` возвращал rc=7, но ядро роняло кадр ПОЗЖЕ на резолве neigh/mgmt-IP (модель
// SteerDatapath `.neigh-fragile` RED). `.tobe` = `reflex_return` сам клеит Ethernet (`change_head`+
// `store_bytes` из RETURN_MAC) и `bpf_redirect(eth1)` — БЕЗ FIB/neigh/mgmt-IP, как AF_PACKET. 0 = off.
#[map]
static RETURN_IFINDEX: Array<u32> = Array::with_max_entries(1, 0);

// src-MAC обратного кадра (6 байт = MAC самого eth1). Userspace читает из sysfs и ставит перед attach.
// НЕ конфиг клиента — лишь наш egress-MAC. dst-MAC берётся из CLIENT_MACS (выучен), не отсюда.
#[map]
static RETURN_SRC_MAC: Array<u8> = Array::with_max_entries(6, 0);

// Выученные MAC downstream-next-hop: client-IP(__be32) → его src-MAC (6 байт). `reflex_steer` пишет на
// forward-кадре (src-MAC Ethernet = MAC роутера/клиента), `reflex_return` читает по dst-IP ответа. Так
// возврат портируем ЗА ЛЮБЫМ роутером БЕЗ конфига клиента (проекция SteerDatapath `MacLearned`).
#[map]
static CLIENT_MACS: HashMap<u32, [u8; 6]> = HashMap::with_max_entries(1024, 0);

// Наблюдаемость reflex_return: [0]=seen (кадров на nevod0-ingress), [1]=ipv4, [2]=последний rc
// (7=TC_ACT_REDIRECT успех bpf_redirect(eth1); отрицательное как u64 = ошибка change_head/store).
#[map]
static RETURN_STATS: Array<u64> = Array::with_max_entries(3, 0);

// Инкремент слота. Гонка между CPU (не PerCpu) сознательна: для диагностики важен ПОРЯДОК величины
// и «>0 vs 0», не точный счёт — плата за простоту при отсутствии BTF на риге (см. де-риск R2S).
#[inline(always)]
fn bump(slot: SteerStat) {
    if let Some(p) = STEER_STATS.get_ptr_mut(slot as u32) {
        unsafe { *p += 1 }
    }
}

#[classifier]
pub fn reflex_tc(ctx: TcContext) -> i32 {
    match unsafe { try_classify(&ctx) } {
        Ok(action) => action,
        Err(_) => TC_ACT_OK,
    }
}

#[inline(always)]
unsafe fn try_classify(ctx: &TcContext) -> Result<i32, ()> {
    let data = ctx.data() as *const u8;
    let data_end = ctx.data_end() as *const u8;

    // ethernet(14) + ip(20) + tcp(4) minimum
    let eth_end = data.add(14);
    if eth_end as usize > data_end as usize {
        return Ok(TC_ACT_OK);
    }

    // ethertype IPv4?
    if *data.add(12) != 0x08 || *data.add(13) != 0x00 {
        return Ok(TC_ACT_OK);
    }

    // IP header
    let ip_start = data.add(14);
    let ip_end = ip_start.add(20);
    if ip_end as usize > data_end as usize {
        return Ok(TC_ACT_OK);
    }

    // check marker: if IP ID == 0xDEAD, this is our injected packet — pass
    let ip_id = u16::from_be_bytes([*ip_start.add(4), *ip_start.add(5)]);
    if ip_id == MARKER_IP_ID {
        return Ok(TC_ACT_OK);
    }

    // protocol TCP?
    if *ip_start.add(9) != 6 {
        return Ok(TC_ACT_OK);
    }

    let ihl = ((*ip_start) & 0x0f) as usize * 4;
    if ihl < 20 {
        return Ok(TC_ACT_OK);
    }

    // TCP header
    let tcp_start = ip_start.add(ihl);
    let tcp_min = tcp_start.add(4);
    if tcp_min as usize > data_end as usize {
        return Ok(TC_ACT_OK);
    }

    let src_ip = u32::from_ne_bytes([
        *ip_start.add(12),
        *ip_start.add(13),
        *ip_start.add(14),
        *ip_start.add(15),
    ]);
    let dst_ip = u32::from_ne_bytes([
        *ip_start.add(16),
        *ip_start.add(17),
        *ip_start.add(18),
        *ip_start.add(19),
    ]);
    let src_port = u16::from_be_bytes([*tcp_start, *tcp_start.add(1)]);
    let dst_port = u16::from_be_bytes([*tcp_start.add(2), *tcp_start.add(3)]);

    let flow_hash = hash_5tuple(src_ip, dst_ip, src_port, dst_port, 6);

    if let Some(action_val) = ACTION_TABLE.get(&flow_hash) {
        let action = *action_val;
        if action == FlowAction::Drop as u8 || action == FlowAction::CopyAndDrop as u8 {
            return Ok(TC_ACT_SHOT);
        }
        // FlowAction::Steer: заворот целевого флоу в локальную несущую. Механизм
        // (bpf_sk_assign+TPROXY vs veth-redirect) валидируется на R2S-стенде — TODO(BL-215).
        // До валидации Steer падает в TC_ACT_OK ниже = Pass (fail-open: кадр на транзите,
        // NoBlackHole держится). Userspace ставит Steer лишь при готовой несущей (steer_fate).
    }

    Ok(TC_ACT_OK)
}

#[inline(always)]
fn hash_5tuple(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, protocol: u8) -> u32 {
    const P: u32 = 0x0100_0193;
    let mut h: u32 = 0x811c_9dc5;

    let s = src_ip.to_ne_bytes();
    h = (h ^ s[0] as u32).wrapping_mul(P);
    h = (h ^ s[1] as u32).wrapping_mul(P);
    h = (h ^ s[2] as u32).wrapping_mul(P);
    h = (h ^ s[3] as u32).wrapping_mul(P);

    let d = dst_ip.to_ne_bytes();
    h = (h ^ d[0] as u32).wrapping_mul(P);
    h = (h ^ d[1] as u32).wrapping_mul(P);
    h = (h ^ d[2] as u32).wrapping_mul(P);
    h = (h ^ d[3] as u32).wrapping_mul(P);

    let sp = src_port.to_ne_bytes();
    h = (h ^ sp[0] as u32).wrapping_mul(P);
    h = (h ^ sp[1] as u32).wrapping_mul(P);

    let dp = dst_port.to_ne_bytes();
    h = (h ^ dp[0] as u32).wrapping_mul(P);
    h = (h ^ dp[1] as u32).wrapping_mul(P);

    h = (h ^ protocol as u32).wrapping_mul(P);
    h
}

// ── reflex_steer (TC INGRESS): прозрачный заворот целевого флоу в локальную несущую ──
// Проекция `model/wire/TransparentIntercept` — механизм `Owned`. Для целевого dst (∈ STEER_TARGETS):
// sk_lookup established→listener на transparent-listener несущей (STEER_CFG), sk_assign на skb,
// sk_release. Нет сокета → TC_ACT_OK (fail-open, кадр на транзите — NoBlackHole держится).
// Слушатель — IP_TRANSPARENT (BL-214). Обратный путь (box без IP на мосту) — `ip rule`/`ip route
// local` на краю. Verifier-приёмка + reply-path валидируются на R2S-стенде (BL-215 Phase 1).
// TODO(BL-216): этот путь НЕ Guarded — заворачивает по STEER_TARGETS без carrier_ready-гейта
// (`steer_fate`); проекция `.tobe` живёт лишь в EGRESS-пути `steer_target`, боевой ingress мимо неё.
#[classifier]
pub fn reflex_steer(ctx: TcContext) -> i32 {
    match unsafe { try_steer(&ctx) } {
        Ok(v) => v,
        Err(_) => TC_ACT_OK,
    }
}

#[inline(always)]
unsafe fn try_steer(ctx: &TcContext) -> Result<i32, ()> {
    let data = ctx.data() as *const u8;
    let data_end = ctx.data_end() as *const u8;

    bump(SteerStat::Seen); // кадр дошёл до ingress-хука (видит ли он клиента на мосту?)

    if data.add(14) as usize > data_end as usize {
        return Ok(TC_ACT_OK);
    }
    if *data.add(12) != 0x08 || *data.add(13) != 0x00 {
        return Ok(TC_ACT_OK); // не IPv4
    }

    let ip_start = data.add(14);
    if ip_start.add(20) as usize > data_end as usize {
        return Ok(TC_ACT_OK);
    }
    if *ip_start.add(9) != 6 {
        return Ok(TC_ACT_OK); // не TCP
    }

    let ihl = ((*ip_start) & 0x0f) as usize * 4;
    if ihl < 20 {
        return Ok(TC_ACT_OK);
    }
    let tcp_start = ip_start.add(ihl);
    if tcp_start.add(4) as usize > data_end as usize {
        return Ok(TC_ACT_OK);
    }

    bump(SteerStat::Ipv4Tcp); // распарсен IPv4+TCP с валидными границами

    // __be32/__be16 из провода — уже network order (для bpf_sock_tuple и flow_hash-в-host).
    let src_be = u32::from_ne_bytes([
        *ip_start.add(12),
        *ip_start.add(13),
        *ip_start.add(14),
        *ip_start.add(15),
    ]);
    let dst_be = u32::from_ne_bytes([
        *ip_start.add(16),
        *ip_start.add(17),
        *ip_start.add(18),
        *ip_start.add(19),
    ]);
    let sport_be = u16::from_ne_bytes([*tcp_start, *tcp_start.add(1)]);
    let dport_be = u16::from_ne_bytes([*tcp_start.add(2), *tcp_start.add(3)]);

    // Кандидат перехвата = ВЕСЬ HTTPS (dport 443), БЕЗ per-domain списка блок-IP. Движок (nevod)
    // сам крутит Ladder per-flow: direct-first → при отсутствии байтфлоу десинк → пол. Поэтому
    // знать блокируемые домены ЗАРАНЕЕ не нужно — earned-routing открывает блок реактивно
    // (project_earned_routing_pivot_bl188). isTarget модели TransparentIntercept проецируется на
    // «HTTPS», не на «dst ∈ blocklist». Не-443 → на транзит (Surgical). STEER_TARGETS больше не гейт.
    // dport 443 на проводе (big-endian) = байты [0x01, 0xBB]. Сравниваем СЫРЫЕ байты провода —
    // без to_be()/from_ne_bytes-неоднозначности (та на bpfel НЕ матчила, хоть логически и верна:
    // tcpdump подтвердил dport-443 SYN на ingress, а target_hit оставался 0).
    if *tcp_start.add(2) != 0x01 || *tcp_start.add(3) != 0xBB {
        return Ok(TC_ACT_OK);
    }

    bump(SteerStat::TargetHit); // HTTPS-флоу к тест-цели — кандидат перехвата

    // ВЫУЧИТЬ MAC downstream-next-hop: src-MAC Ethernet кадра (data[6..12]) = MAC роутера/клиента, к
    // которому `reflex_return` погонит ответ. Ключ = client-IP (src_be) — по нему возврат найдёт MAC по
    // dst-IP ответа. Так круг портируем БЕЗ конфига клиента (SteerDatapath `MacLearned`). Границы data
    // [0..14] проверены выше (ethernet+ip). insert best-effort — промах не рвёт заворот.
    let client_mac: [u8; 6] = [
        *data.add(6),
        *data.add(7),
        *data.add(8),
        *data.add(9),
        *data.add(10),
        *data.add(11),
    ];
    let _ = CLIENT_MACS.insert(&src_be, &client_mac, 0);

    // L2-РЕДИРЕКТ (если ifindex несущей задан): кадр идёт прямо в xmit устройства, МИНУЯ ip_rcv/
    // ip_forward → обходит forward→tun дроп и conntrack-игнор (L2-native, как AF_PACKET). Возвращаем
    // код `bpf_redirect` (TC_ACT_REDIRECT). Кадр несёт Ethernet-заголовок — nevod0 (IFF_NO_PI) снимет
    // его в read-pump (или eth-strip в eBPF — следующий шаг после замера доставки).
    if let Some(ifx) = STEER_IFINDEX.get(0) {
        let ifindex = *ifx;
        if ifindex != 0 {
            bump(SteerStat::Rewritten); // переиспользуем слот как «доставлен через редирект»
            return Ok(bpf_redirect(ifindex, 0) as i32);
        }
    }

    // L2-доставка (fallback, ifindex=0): переписать dst-MAC на MAC моста → кадр уходит НАВЕРХ в L3-стек
    // (br_pass_frame_up→ip_rcv), а не форвардится по чужому MAC. Дальше policy-route (iif br0 →
    // table steer → dev tun0) доставит его в tun2socks (hev) → SOCKS5 несущей (Tun-путь, sk_assign/
    // DNAT/TPROXY на этом ядре RED — доказано на риге, TransparentCapture/Delivery, BL-215).
    // Хирургично: только HTTPS вытягиваем в L3, транзит остаётся на мосту (br_netfilter не нужен).
    // 6 явных get — развёртка без loop-verifier. Все нули = MAC не сконфигурен, не трогаем (транзит).
    let mut mac = [0u8; 6];
    let mut configured = 0u8;
    if let Some(b) = STEER_MAC.get(0) {
        mac[0] = *b;
        configured |= *b;
    }
    if let Some(b) = STEER_MAC.get(1) {
        mac[1] = *b;
        configured |= *b;
    }
    if let Some(b) = STEER_MAC.get(2) {
        mac[2] = *b;
        configured |= *b;
    }
    if let Some(b) = STEER_MAC.get(3) {
        mac[3] = *b;
        configured |= *b;
    }
    if let Some(b) = STEER_MAC.get(4) {
        mac[4] = *b;
        configured |= *b;
    }
    if let Some(b) = STEER_MAC.get(5) {
        mac[5] = *b;
        configured |= *b;
    }
    if configured != 0 {
        let rc = bpf_skb_store_bytes(
            ctx.skb.skb,
            0,
            mac.as_ptr() as *const core::ffi::c_void,
            6,
            0,
        );
        if rc == 0 {
            bump(SteerStat::Rewritten); // dst-MAC переписан → кадр пойдёт в L3-стек
        }
    }

    // src_be/sport_be/dst_be не нужны (sk_assign убран; матч теперь по dport, не по dst-IP) —
    // глушим предупреждения намеренно. dport_be используется в гейте HTTPS выше.
    let _ = (src_be, sport_be, dport_be, dst_be);

    Ok(TC_ACT_OK)
}

// ── reflex_return (TC INGRESS на nevod0): ОБРАТНАЯ половина круга (L2RedirectEth1) ──
// netstack пишет ответ (src=цель, dst=клиент) в nevod0 → ядро получает его на nevod0-ingress СЫРЫМ IP
// (tun IFF_NO_PI, без Ethernet). Мы ЗЕРКАЛИМ проверенный вход: сами клеим L2-заголовок из RETURN_MAC
// (dst=client, src=box) и `bpf_redirect(eth1)` прямо в xmit порта клиента — МИНУЯ kernel-форвард (ЧД на
// коробке) И neigh-резолв (провал `bpf_redirect_neigh`, модель `.neigh-fragile`). Проекция `.tobe`.
#[classifier]
pub fn reflex_return(ctx: TcContext) -> i32 {
    match unsafe { try_return(&ctx) } {
        Ok(v) => v,
        Err(_) => TC_ACT_OK,
    }
}

#[inline(always)]
unsafe fn try_return(ctx: &TcContext) -> Result<i32, ()> {
    let data = ctx.data() as *const u8;
    let data_end = ctx.data_end() as *const u8;

    if let Some(p) = RETURN_STATS.get_ptr_mut(0) {
        unsafe { *p += 1 } // seen: кадр на nevod0-ingress
    }

    if data.add(1) as usize > data_end as usize {
        return Ok(TC_ACT_OK);
    }
    if (*data >> 4) != 4 {
        return Ok(TC_ACT_OK); // не IPv4 (tun даёт сырой IP)
    }

    if let Some(p) = RETURN_STATS.get_ptr_mut(1) {
        unsafe { *p += 1 } // ipv4
    }

    let ifindex = match RETURN_IFINDEX.get(0) {
        Some(v) if *v != 0 => *v,
        _ => return Ok(TC_ACT_OK), // ifindex eth1 не задан → на транзит (fail-open)
    };

    // dst-IP ответа (клиент) — ключ к выученному MAC. IP-заголовок ≥ 20 байт (dst на offset 16..20).
    if data.add(20) as usize > data_end as usize {
        return Ok(TC_ACT_OK);
    }
    let dst_ip = u32::from_ne_bytes([*data.add(16), *data.add(17), *data.add(18), *data.add(19)]);

    // Ethernet-заголовок ЧИТАЕМ ДО change_head (карты переживут инвалидацию skb-указателей; после дороста
    // хедрума пакетные указатели трогать нельзя). dst-MAC = ВЫУЧЕННЫЙ из forward-кадра (CLIENT_MACS по
    // dst-IP клиента); src-MAC = eth1 (RETURN_SRC_MAC). Портируемо БЕЗ конфига клиента (`MacLearned`).
    let dst_mac = match CLIENT_MACS.get(&dst_ip) {
        Some(m) => *m,
        None => return Ok(TC_ACT_OK), // MAC клиента ещё не выучен (forward-кадр научит) → транзит, fail-open
    };
    let mut eth = [0u8; 14];
    let mut i = 0usize;
    while i < 6 {
        eth[i] = dst_mac[i]; // dst-MAC (выученный next-hop)
        i += 1;
    }
    let mut configured = 0u8;
    let mut j = 0usize;
    while j < 6 {
        if let Some(b) = RETURN_SRC_MAC.get(j as u32) {
            eth[6 + j] = *b; // src-MAC (eth1)
            configured |= *b;
        }
        j += 1;
    }
    if configured == 0 {
        return Ok(TC_ACT_OK); // src-MAC eth1 не задан → транзит (off)
    }
    eth[12] = 0x08; // ethertype IPv4
    eth[13] = 0x00;

    // Вырастить 14 байт хедрума под Ethernet (сырой IP из tun → L2-кадр для физ-порта).
    let rc_head = bpf_skb_change_head(ctx.skb.skb, 14, 0);
    if rc_head != 0 {
        if let Some(p) = RETURN_STATS.get_ptr_mut(2) {
            unsafe { *p = rc_head as u64 } // не смогли дорастить → зафиксировать ошибку
        }
        return Ok(TC_ACT_OK); // fail-open: кадр останется на ingress (дропнется форвардом), но не битый
    }

    // Вписать 14 байт заголовка в новый хедрум (offset 0).
    let rc_store = bpf_skb_store_bytes(
        ctx.skb.skb,
        0,
        eth.as_ptr() as *const core::ffi::c_void,
        14,
        0,
    );
    if rc_store != 0 {
        if let Some(p) = RETURN_STATS.get_ptr_mut(2) {
            unsafe { *p = rc_store as u64 }
        }
        return Ok(TC_ACT_SHOT); // заголовок не записан → дропнуть (не слать битый кадр)
    }

    let rc = bpf_redirect(ifindex, 0) as i64;
    if let Some(p) = RETURN_STATS.get_ptr_mut(2) {
        unsafe { *p = rc as u64 } // 7=TC_ACT_REDIRECT успех
    }
    Ok(rc as i32)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
