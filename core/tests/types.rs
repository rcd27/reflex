use reflex_core::types::{EtherType, EthernetFrame, Mac};
use reflex_core::types::{Flow, HasFlow, Protocol, TcpFlags, TcpSegment, UdpDatagram};
use reflex_core::types::{IpProtocol, Ipv4Packet};
use std::net::{Ipv4Addr, SocketAddr};

#[test]
fn parse_ethernet_frame_ipv4() {
    let raw: Vec<u8> = vec![
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00, 0xDE,
        0xAD, 0xBE, 0xEF,
    ];
    let frame = EthernetFrame::parse(&raw).unwrap();
    assert_eq!(frame.dst_mac, Mac([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
    assert_eq!(frame.src_mac, Mac([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]));
    assert_eq!(frame.ethertype, EtherType::Ipv4);
    assert_eq!(frame.payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn parse_ethernet_frame_too_short() {
    let raw: Vec<u8> = vec![0x00; 13];
    assert!(EthernetFrame::parse(&raw).is_none());
}

#[test]
fn parse_ethernet_frame_arp() {
    let mut raw = vec![0u8; 14];
    raw[12] = 0x08;
    raw[13] = 0x06;
    let frame = EthernetFrame::parse(&raw).unwrap();
    assert_eq!(frame.ethertype, EtherType::Arp);
}

#[test]
fn mac_display() {
    let mac = Mac([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    assert_eq!(format!("{}", mac), "00:11:22:33:44:55");
}

#[test]
fn parse_ipv4_tcp_packet() {
    let raw: Vec<u8> = vec![
        0x45, 0x00, 0x00, 0x18, 0xDE, 0xAD, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0x0A, 0x00, 0x00,
        0x01, 0x0A, 0x00, 0x00, 0x02, 0xCA, 0xFE, 0xBA, 0xBE,
    ];
    let pkt = Ipv4Packet::parse(&raw).unwrap();
    assert_eq!(pkt.src, Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(pkt.dst, Ipv4Addr::new(10, 0, 0, 2));
    assert_eq!(pkt.ttl, 64);
    assert_eq!(pkt.protocol, IpProtocol::Tcp);
    assert_eq!(pkt.id, 0xDEAD);
    assert!(pkt.dont_fragment);
    assert_eq!(pkt.payload, vec![0xCA, 0xFE, 0xBA, 0xBE]);
}

#[test]
fn parse_ipv4_too_short() {
    let raw: Vec<u8> = vec![0x45; 19];
    assert!(Ipv4Packet::parse(&raw).is_none());
}

#[test]
fn parse_ipv4_udp_protocol() {
    let mut raw = vec![0u8; 24];
    raw[0] = 0x45;
    raw[2] = 0x00;
    raw[3] = 0x18;
    raw[8] = 0x80;
    raw[9] = 0x11;
    raw[12..16].copy_from_slice(&[192, 168, 1, 1]);
    raw[16..20].copy_from_slice(&[8, 8, 8, 8]);
    let pkt = Ipv4Packet::parse(&raw).unwrap();
    assert_eq!(pkt.protocol, IpProtocol::Udp);
    assert_eq!(pkt.ttl, 128);
    assert_eq!(pkt.src, Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(pkt.dst, Ipv4Addr::new(8, 8, 8, 8));
}

#[test]
fn tcp_flags_methods() {
    let syn_ack = TcpFlags::SYN | TcpFlags::ACK;
    assert!(syn_ack.is_syn_ack());
    assert!(!syn_ack.is_rst());
    assert!(!syn_ack.is_fin());

    let rst = TcpFlags::RST;
    assert!(rst.is_rst());
    assert!(!rst.is_syn_ack());
}

#[test]
fn parse_tcp_segment() {
    let raw: Vec<u8> = vec![
        0x1F, 0x90, 0x01, 0xBB, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x50, 0x12, 0x72,
        0x10, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC,
    ];

    let src_ip = Ipv4Addr::new(10, 0, 0, 1);
    let dst_ip = Ipv4Addr::new(10, 0, 0, 2);

    let seg = TcpSegment::parse(&raw, src_ip, dst_ip, 64).unwrap();

    assert_eq!(seg.flow.src, SocketAddr::new(src_ip.into(), 8080));
    assert_eq!(seg.flow.dst, SocketAddr::new(dst_ip.into(), 443));
    assert_eq!(seg.flow.protocol, Protocol::Tcp);
    assert_eq!(seg.seq, 1);
    assert_eq!(seg.ack, 2);
    assert!(seg.flags.is_syn_ack());
    assert_eq!(seg.window, 29200);
    assert_eq!(seg.ttl, 64);
    assert_eq!(seg.payload, vec![0xAA, 0xBB, 0xCC]);
}

#[test]
fn parse_tcp_too_short() {
    let raw: Vec<u8> = vec![0u8; 19];
    assert!(TcpSegment::parse(&raw, Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, 0).is_none());
}

#[test]
fn tcp_segment_has_flow() {
    let raw = vec![
        0x1F, 0x90, 0x01, 0xBB, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x50, 0x02, 0x72,
        0x10, 0x00, 0x00, 0x00, 0x00,
    ];
    let seg = TcpSegment::parse(
        &raw,
        Ipv4Addr::new(1, 2, 3, 4),
        Ipv4Addr::new(5, 6, 7, 8),
        64,
    )
    .unwrap();

    let flow = seg.flow();
    assert_eq!(flow.src.port(), 8080);
    assert_eq!(flow.dst.port(), 443);
}

#[test]
fn flow_reversed() {
    let flow = Flow {
        src: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 8080),
        dst: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 2).into(), 443),
        protocol: Protocol::Tcp,
    };
    let rev = flow.reversed();
    assert_eq!(rev.src, flow.dst);
    assert_eq!(rev.dst, flow.src);
    assert_eq!(rev.protocol, flow.protocol);
}

#[test]
fn parse_udp_datagram() {
    let raw: Vec<u8> = vec![
        0x00, 0x35, 0xC0, 0x01, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
    ];

    let dgram = UdpDatagram::parse(
        &raw,
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(10, 0, 0, 1),
        64,
    )
    .unwrap();

    assert_eq!(dgram.flow.src.port(), 53);
    assert_eq!(dgram.flow.dst.port(), 49153);
    assert_eq!(dgram.flow.protocol, Protocol::Udp);
    assert_eq!(dgram.ttl, 64);
    assert_eq!(dgram.payload, vec![0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn parse_udp_too_short() {
    let raw: Vec<u8> = vec![0u8; 7];
    assert!(UdpDatagram::parse(&raw, Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, 0).is_none());
}
