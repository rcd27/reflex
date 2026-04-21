use reflex_core::builder::{TcpBuilder, UdpBuilder};
use reflex_core::types::{
    EtherType, EthernetFrame, Flow, Ipv4Packet, Protocol, TcpFlags, TcpSegment,
};
use std::net::{Ipv4Addr, SocketAddr};

#[test]
fn tcp_builder_rst_packet() {
    let flow = Flow {
        src: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 443),
        dst: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 2).into(), 8080),
        protocol: Protocol::Tcp,
    };

    let built = TcpBuilder::new()
        .flow(&flow)
        .seq(1000)
        .ack(2000)
        .flags(TcpFlags::RST | TcpFlags::ACK)
        .ttl(3)
        .build();

    let bytes = built.serialize();
    let frame = EthernetFrame::parse(&bytes).unwrap();
    assert_eq!(frame.ethertype, EtherType::Ipv4);

    let ip = Ipv4Packet::parse(&frame.payload).unwrap();
    assert_eq!(ip.src, Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(ip.dst, Ipv4Addr::new(10, 0, 0, 2));
    assert_eq!(ip.ttl, 3);

    let seg = TcpSegment::parse(&ip.payload, ip.src, ip.dst, ip.ttl).unwrap();
    assert_eq!(seg.flow.src.port(), 443);
    assert_eq!(seg.flow.dst.port(), 8080);
    assert_eq!(seg.seq, 1000);
    assert_eq!(seg.ack, 2000);
    assert!(seg.flags.is_rst());
    assert_eq!(seg.ttl, 3);
}

#[test]
fn tcp_builder_with_payload() {
    let flow = Flow {
        src: SocketAddr::new(Ipv4Addr::new(1, 2, 3, 4).into(), 80),
        dst: SocketAddr::new(Ipv4Addr::new(5, 6, 7, 8).into(), 12345),
        protocol: Protocol::Tcp,
    };

    let payload = vec![0xCA, 0xFE, 0xBA, 0xBE];

    let built = TcpBuilder::new()
        .flow(&flow)
        .seq(42)
        .flags(TcpFlags::PSH | TcpFlags::ACK)
        .ttl(64)
        .payload(&payload)
        .build();

    let bytes = built.serialize();
    let frame = EthernetFrame::parse(&bytes).unwrap();
    let ip = Ipv4Packet::parse(&frame.payload).unwrap();
    let seg = TcpSegment::parse(&ip.payload, ip.src, ip.dst, ip.ttl).unwrap();

    assert_eq!(seg.payload, payload);
    assert!(seg.flags.is_psh_ack());
}

#[test]
fn tcp_builder_reversed_flow() {
    let original_flow = Flow {
        src: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 443),
        dst: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 2).into(), 8080),
        protocol: Protocol::Tcp,
    };

    let built = TcpBuilder::new()
        .flow(&original_flow.reversed())
        .seq(1)
        .flags(TcpFlags::RST)
        .ttl(3)
        .build();

    let bytes = built.serialize();
    let frame = EthernetFrame::parse(&bytes).unwrap();
    let ip = Ipv4Packet::parse(&frame.payload).unwrap();
    let seg = TcpSegment::parse(&ip.payload, ip.src, ip.dst, ip.ttl).unwrap();

    assert_eq!(seg.flow.src.port(), 8080);
    assert_eq!(seg.flow.dst.port(), 443);
}

#[test]
fn tcp_builder_valid_ip_checksum() {
    let flow = Flow {
        src: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 443),
        dst: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 2).into(), 8080),
        protocol: Protocol::Tcp,
    };

    let bytes = TcpBuilder::new()
        .flow(&flow)
        .seq(1000)
        .flags(TcpFlags::SYN)
        .build()
        .serialize();

    let ip_header = &bytes[14..34];
    assert_ne!(
        u16::from_be_bytes([ip_header[10], ip_header[11]]),
        0x0000,
        "IP checksum must not be zero"
    );
    assert_eq!(
        reflex_core::checksum::ip_checksum(ip_header),
        0x0000,
        "IP checksum must verify"
    );
}

#[test]
fn tcp_builder_valid_tcp_checksum() {
    let flow = Flow {
        src: SocketAddr::new(Ipv4Addr::new(192, 168, 1, 10).into(), 443),
        dst: SocketAddr::new(Ipv4Addr::new(93, 184, 216, 34).into(), 80),
        protocol: Protocol::Tcp,
    };

    let payload = vec![0x48, 0x54, 0x54, 0x50];

    let bytes = TcpBuilder::new()
        .flow(&flow)
        .seq(42)
        .ack(100)
        .flags(TcpFlags::PSH | TcpFlags::ACK)
        .payload(&payload)
        .build()
        .serialize();

    let src_ip = &bytes[26..30];
    let dst_ip = &bytes[30..34];
    let tcp_segment = &bytes[34..];

    assert_ne!(
        u16::from_be_bytes([tcp_segment[16], tcp_segment[17]]),
        0x0000,
        "TCP checksum must not be zero"
    );
    assert_eq!(
        reflex_core::checksum::tcp_checksum(
            src_ip.try_into().unwrap(),
            dst_ip.try_into().unwrap(),
            tcp_segment
        ),
        0x0000,
        "TCP checksum must verify"
    );
}

#[test]
fn udp_builder_valid_ip_checksum() {
    let flow = Flow {
        src: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 53),
        dst: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 2).into(), 1234),
        protocol: Protocol::Udp,
    };

    let bytes = UdpBuilder::new()
        .flow(&flow)
        .payload(&[0xDE, 0xAD])
        .build()
        .serialize();

    let ip_header = &bytes[14..34];
    assert_eq!(
        reflex_core::checksum::ip_checksum(ip_header),
        0x0000,
        "IP checksum must verify"
    );
}

#[test]
fn udp_builder_valid_udp_checksum() {
    let flow = Flow {
        src: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 53),
        dst: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 2).into(), 1234),
        protocol: Protocol::Udp,
    };

    let bytes = UdpBuilder::new()
        .flow(&flow)
        .payload(&[0xDE, 0xAD])
        .build()
        .serialize();

    let src_ip = &bytes[26..30];
    let dst_ip = &bytes[30..34];
    let udp_datagram = &bytes[34..];

    assert_eq!(
        reflex_core::checksum::udp_checksum(
            src_ip.try_into().unwrap(),
            dst_ip.try_into().unwrap(),
            udp_datagram
        ),
        0x0000,
        "UDP checksum must verify"
    );
}
