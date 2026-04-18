use futures::StreamExt;
use reflex_core::parse::{ParseEthernetExt, ParseIpv4Ext, ParseTcpExt, ParseUdpExt};
use std::net::Ipv4Addr;

fn build_tcp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    ttl: u8,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_len = 20 + payload.len();
    let ip_total = 20 + tcp_len;
    let mut pkt = Vec::with_capacity(14 + ip_total);

    // Ethernet header
    pkt.extend_from_slice(&[0xFFu8; 6]); // dst mac
    pkt.extend_from_slice(&[0x00u8; 6]); // src mac
    pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4

    // IPv4 header
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&(ip_total as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // id
    pkt.extend_from_slice(&[0x40, 0x00]); // DF
    pkt.push(ttl);
    pkt.push(6); // TCP
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum
    pkt.extend_from_slice(&src_ip.octets());
    pkt.extend_from_slice(&dst_ip.octets());

    // TCP header
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&1u32.to_be_bytes()); // seq
    pkt.extend_from_slice(&2u32.to_be_bytes()); // ack
    pkt.push(0x50); // data offset=5
    pkt.push(flags);
    pkt.extend_from_slice(&29200u16.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum
    pkt.extend_from_slice(&[0x00, 0x00]); // urgent
    pkt.extend_from_slice(payload);

    pkt
}

fn build_udp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    ttl: u8,
    payload: &[u8],
) -> Vec<u8> {
    let udp_total = 8 + payload.len();
    let ip_total = 20 + udp_total;
    let mut pkt = Vec::with_capacity(14 + ip_total);

    // Ethernet
    pkt.extend_from_slice(&[0xFF; 6]);
    pkt.extend_from_slice(&[0x00; 6]);
    pkt.extend_from_slice(&0x0800u16.to_be_bytes());

    // IPv4
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&(ip_total as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00; 4]); // id, flags
    pkt.push(ttl);
    pkt.push(17); // UDP
    pkt.extend_from_slice(&[0x00; 2]);
    pkt.extend_from_slice(&src_ip.octets());
    pkt.extend_from_slice(&dst_ip.octets());

    // UDP
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&(udp_total as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00; 2]);
    pkt.extend_from_slice(payload);

    pkt
}

#[tokio::test]
async fn parse_pipeline_raw_to_tcp() {
    let syn_ack = build_tcp_packet(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        443,
        8080,
        64,
        0x12,
        &[],
    );
    let rst = build_tcp_packet(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        443,
        8080,
        128,
        0x04,
        &[],
    );

    let segments: Vec<_> = futures::stream::iter(vec![syn_ack, rst])
        .parse_ethernet()
        .parse_ipv4()
        .parse_tcp()
        .collect()
        .await;

    assert_eq!(segments.len(), 2);
    assert!(segments[0].flags.is_syn_ack());
    assert_eq!(segments[0].ttl, 64);
    assert!(segments[1].flags.is_rst());
    assert_eq!(segments[1].ttl, 128);
}

#[tokio::test]
async fn parse_pipeline_filters_non_ipv4() {
    let ipv4_pkt = build_tcp_packet(
        Ipv4Addr::new(1, 1, 1, 1),
        Ipv4Addr::new(2, 2, 2, 2),
        80,
        12345,
        64,
        0x10,
        &[],
    );

    // ARP packet
    let mut arp_pkt = vec![0u8; 42];
    arp_pkt[12] = 0x08;
    arp_pkt[13] = 0x06;

    let segments: Vec<_> = futures::stream::iter(vec![arp_pkt, ipv4_pkt])
        .parse_ethernet()
        .parse_ipv4()
        .parse_tcp()
        .collect()
        .await;

    assert_eq!(segments.len(), 1);
    assert_eq!(segments[0].flow.src.port(), 80);
}

#[tokio::test]
async fn parse_pipeline_filters_udp_from_tcp() {
    let tcp_pkt = build_tcp_packet(
        Ipv4Addr::new(1, 1, 1, 1),
        Ipv4Addr::new(2, 2, 2, 2),
        80,
        12345,
        64,
        0x10,
        &[],
    );
    let udp_pkt = build_udp_packet(
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(10, 0, 0, 1),
        53,
        12345,
        64,
        &[0xDE, 0xAD],
    );

    let segments: Vec<_> = futures::stream::iter(vec![tcp_pkt, udp_pkt])
        .parse_ethernet()
        .parse_ipv4()
        .parse_tcp()
        .collect()
        .await;

    assert_eq!(segments.len(), 1);
    assert_eq!(segments[0].flow.src.port(), 80);
}

#[tokio::test]
async fn parse_pipeline_raw_to_udp() {
    let udp_pkt = build_udp_packet(
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(10, 0, 0, 1),
        53,
        12345,
        64,
        &[0xCA, 0xFE],
    );
    let tcp_pkt = build_tcp_packet(
        Ipv4Addr::new(1, 1, 1, 1),
        Ipv4Addr::new(2, 2, 2, 2),
        80,
        12345,
        64,
        0x10,
        &[],
    );

    let datagrams: Vec<_> = futures::stream::iter(vec![udp_pkt, tcp_pkt])
        .parse_ethernet()
        .parse_ipv4()
        .parse_udp()
        .collect()
        .await;

    assert_eq!(datagrams.len(), 1);
    assert_eq!(datagrams[0].flow.src.port(), 53);
    assert_eq!(datagrams[0].payload, vec![0xCA, 0xFE]);
}
