use reflex_core::builder::TcpBuilder;
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
