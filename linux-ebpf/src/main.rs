#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{classifier, map},
    maps::{Array, HashMap},
    programs::TcContext,
};
use aya_ebpf_bindings::helpers::bpf_skb_store_bytes;
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
    if dport_be != 443u16.to_be() {
        return Ok(TC_ACT_OK);
    }

    bump(SteerStat::TargetHit); // HTTPS-флоу — кандидат перехвата (судьбу решит движок)

    // L2-доставка: переписать dst-MAC на MAC моста → кадр уходит НАВЕРХ в локальный L3-стек
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
    let _ = (src_be, sport_be, dst_be);

    Ok(TC_ACT_OK)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
