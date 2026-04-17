#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, PerfEventArray},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use reflex_linux_common::FlowAction;

/// Action table: flow hash → FlowAction
/// Written by userspace, read by XDP program.
#[map]
static ACTION_TABLE: HashMap<u32, u8> = HashMap::with_max_entries(4096, 0);

/// Perf event ring: copies of intercepted packets sent to userspace.
#[map]
static EVENTS: PerfEventArray<[u8; 0]> = PerfEventArray::new(0);

#[xdp]
pub fn reflex_xdp(ctx: XdpContext) -> u32 {
    match unsafe { try_classify(&ctx) } {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

unsafe fn try_classify(ctx: &XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let len = data_end - data;

    // need at least ethernet(14) + ip(20) + tcp(20) = 54 bytes
    if len < 54 {
        return Ok(xdp_action::XDP_PASS);
    }

    let eth_ptr = data as *const u8;

    // check ethertype = IPv4 (0x0800)
    let ethertype = u16::from_be_bytes([*eth_ptr.add(12), *eth_ptr.add(13)]);
    if ethertype != 0x0800 {
        return Ok(xdp_action::XDP_PASS);
    }

    // check IP protocol = TCP (6)
    let ip_start = 14;
    let ip_protocol = *eth_ptr.add(ip_start + 9);
    if ip_protocol != 6 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_ihl = (*eth_ptr.add(ip_start) & 0x0f) as usize * 4;
    let tcp_start = ip_start + ip_ihl;

    // bounds check
    if data + tcp_start + 20 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    // compute flow hash from 5-tuple
    let src_ip = u32::from_be_bytes([
        *eth_ptr.add(ip_start + 12),
        *eth_ptr.add(ip_start + 13),
        *eth_ptr.add(ip_start + 14),
        *eth_ptr.add(ip_start + 15),
    ]);
    let dst_ip = u32::from_be_bytes([
        *eth_ptr.add(ip_start + 16),
        *eth_ptr.add(ip_start + 17),
        *eth_ptr.add(ip_start + 18),
        *eth_ptr.add(ip_start + 19),
    ]);
    let src_port = u16::from_be_bytes([*eth_ptr.add(tcp_start), *eth_ptr.add(tcp_start + 1)]);
    let dst_port =
        u16::from_be_bytes([*eth_ptr.add(tcp_start + 2), *eth_ptr.add(tcp_start + 3)]);

    let flow_hash = hash_5tuple(src_ip, dst_ip, src_port, dst_port, ip_protocol);

    // lookup action table
    if let Some(action_val) = ACTION_TABLE.get(&flow_hash) {
        let action = *action_val;
        if action == FlowAction::Drop as u8 {
            return Ok(xdp_action::XDP_DROP);
        }
        if action == FlowAction::CopyAndDrop as u8 {
            // copy full packet to userspace, then drop
            EVENTS.output(ctx, &[], 0);
            return Ok(xdp_action::XDP_DROP);
        }
        // FlowAction::Pass → fall through
    }

    // default: pass everything
    Ok(xdp_action::XDP_PASS)
}

/// Simple hash of 5-tuple. Not cryptographic, just for map lookup.
fn hash_5tuple(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, protocol: u8) -> u32 {
    let mut h: u32 = 0x811c_9dc5; // FNV-1a offset basis
    let prime: u32 = 0x0100_0193;

    for byte in src_ip.to_ne_bytes()
        .iter()
        .chain(dst_ip.to_ne_bytes().iter())
        .chain(src_port.to_ne_bytes().iter())
        .chain(dst_port.to_ne_bytes().iter())
        .chain(core::slice::from_ref(&protocol).iter())
    {
        h ^= *byte as u32;
        h = h.wrapping_mul(prime);
    }

    h
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
