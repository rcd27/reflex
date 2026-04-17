#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{classifier, map},
    maps::HashMap,
    programs::TcContext,
};
use reflex_linux_common::FlowAction;

const TC_ACT_OK: i32 = 0;    // pass
const TC_ACT_SHOT: i32 = 2;  // drop
const MARKER_IP_ID: u16 = 0xDEAD; // injected packets marker

#[map]
static ACTION_TABLE: HashMap<u32, u8> = HashMap::with_max_entries(4096, 0);

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
        *ip_start.add(12), *ip_start.add(13),
        *ip_start.add(14), *ip_start.add(15),
    ]);
    let dst_ip = u32::from_ne_bytes([
        *ip_start.add(16), *ip_start.add(17),
        *ip_start.add(18), *ip_start.add(19),
    ]);
    let src_port = u16::from_be_bytes([*tcp_start, *tcp_start.add(1)]);
    let dst_port = u16::from_be_bytes([*tcp_start.add(2), *tcp_start.add(3)]);

    let flow_hash = hash_5tuple(src_ip, dst_ip, src_port, dst_port, 6);

    if let Some(action_val) = ACTION_TABLE.get(&flow_hash) {
        let action = *action_val;
        if action == FlowAction::Drop as u8 || action == FlowAction::CopyAndDrop as u8 {
            return Ok(TC_ACT_SHOT);
        }
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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
