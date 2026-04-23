use crate::types::{Flow, Protocol, TcpFlags, TcpOptions, TcpSegment};
use std::net::{Ipv4Addr, SocketAddr};

/// Parse a raw IP packet (no ethernet header) into a TcpSegment.
/// Returns None if not IPv4 TCP or too short.
pub fn parse_tcp_from_ip(ip_data: &[u8]) -> Option<TcpSegment> {
    if ip_data.len() < 40 {
        return None;
    }
    if ip_data[0] >> 4 != 4 {
        return None;
    }
    let ihl = (ip_data[0] & 0x0F) as usize * 4;
    if ihl < 20 || ip_data.len() < ihl {
        return None;
    }
    if ip_data[9] != 6 {
        return None;
    }

    let ttl = ip_data[8];
    let src_ip = Ipv4Addr::new(ip_data[12], ip_data[13], ip_data[14], ip_data[15]);
    let dst_ip = Ipv4Addr::new(ip_data[16], ip_data[17], ip_data[18], ip_data[19]);

    let tcp = &ip_data[ihl..];
    if tcp.len() < 20 {
        return None;
    }

    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    let data_offset = ((tcp[12] >> 4) as usize) * 4;
    let flags = TcpFlags::from_bits_truncate(tcp[13]);
    let window = u16::from_be_bytes([tcp[14], tcp[15]]);

    let payload = if tcp.len() > data_offset {
        tcp[data_offset..].to_vec()
    } else {
        vec![]
    };

    Some(TcpSegment {
        flow: Flow {
            src: SocketAddr::new(src_ip.into(), src_port),
            dst: SocketAddr::new(dst_ip.into(), dst_port),
            protocol: Protocol::Tcp,
        },
        seq,
        ack,
        flags,
        window,
        options: TcpOptions::default(),
        ttl,
        payload,
    })
}
