use std::net::SocketAddr;

use reflex_core::types::{Flow, HasConnectionId, Protocol, TcpFlags, TcpOptions, TcpSegment};

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn flow(src: &str, dst: &str) -> Flow {
    Flow {
        src: addr(src),
        dst: addr(dst),
        protocol: Protocol::Tcp,
    }
}

#[test]
fn both_directions_same_connection_id() {
    let f1 = flow("10.0.0.1:54321", "104.21.32.39:443");
    let f2 = flow("104.21.32.39:443", "10.0.0.1:54321");
    assert_eq!(f1.connection_id(), f2.connection_id());
}

#[test]
fn different_connections_different_ids() {
    let f1 = flow("10.0.0.1:54321", "104.21.32.39:443");
    let f2 = flow("10.0.0.1:54322", "104.21.32.39:443");
    assert_ne!(f1.connection_id(), f2.connection_id());
}

#[test]
fn connection_id_is_hashable() {
    use std::collections::HashMap;
    let f = flow("10.0.0.1:54321", "104.21.32.39:443");
    let mut map = HashMap::new();
    map.insert(f.connection_id(), "trial_1");
    assert_eq!(map.get(&f.reversed().connection_id()), Some(&"trial_1"));
}

#[test]
fn canonical_ordering_is_deterministic() {
    let f = flow("10.0.0.1:54321", "104.21.32.39:443");
    let cid = f.connection_id();
    assert!(cid.endpoints().0 <= cid.endpoints().1);
}

#[test]
fn connection_id_from_tcp_segment() {
    let segment = TcpSegment {
        flow: flow("10.0.0.1:54321", "104.21.32.39:443"),
        seq: 0,
        ack: 0,
        flags: TcpFlags::SYN,
        window: 65535,
        options: TcpOptions::default(),
        ttl: 64,
        payload: vec![],
    };
    let cid = segment.connection_id();
    let reverse_segment = TcpSegment {
        flow: flow("104.21.32.39:443", "10.0.0.1:54321"),
        seq: 0,
        ack: 1,
        flags: TcpFlags::SYN | TcpFlags::ACK,
        window: 65535,
        options: TcpOptions::default(),
        ttl: 64,
        payload: vec![],
    };
    assert_eq!(cid, reverse_segment.connection_id());
}
