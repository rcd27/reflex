use reflex_core::types::{IpProtocol, Protocol};

// --- IpProtocol from_u8 ---

#[test]
fn ip_protocol_tcp_from_u8() {
    assert_eq!(IpProtocol::from_u8(6), IpProtocol::Tcp);
}

#[test]
fn ip_protocol_udp_from_u8() {
    assert_eq!(IpProtocol::from_u8(17), IpProtocol::Udp);
}

#[test]
fn ip_protocol_icmp_from_u8() {
    assert_eq!(IpProtocol::from_u8(1), IpProtocol::Icmp);
}

#[test]
fn ip_protocol_other_from_u8() {
    assert_eq!(IpProtocol::from_u8(47), IpProtocol::Other(47));
}

#[test]
fn ip_protocol_zero_is_other() {
    assert_eq!(IpProtocol::from_u8(0), IpProtocol::Other(0));
}

#[test]
fn ip_protocol_255_is_other() {
    assert_eq!(IpProtocol::from_u8(255), IpProtocol::Other(255));
}

// --- IpProtocol to_u8 ---

#[test]
fn ip_protocol_tcp_to_u8() {
    assert_eq!(IpProtocol::Tcp.to_u8(), 6);
}

#[test]
fn ip_protocol_udp_to_u8() {
    assert_eq!(IpProtocol::Udp.to_u8(), 17);
}

#[test]
fn ip_protocol_icmp_to_u8() {
    assert_eq!(IpProtocol::Icmp.to_u8(), 1);
}

#[test]
fn ip_protocol_other_to_u8() {
    assert_eq!(IpProtocol::Other(89).to_u8(), 89);
}

// --- IpProtocol roundtrip ---

#[test]
fn ip_protocol_roundtrip_all_known() {
    [1u8, 6, 17]
        .iter()
        .for_each(|&v| assert_eq!(IpProtocol::from_u8(v).to_u8(), v));
}

#[test]
fn ip_protocol_roundtrip_other() {
    (0u8..=255)
        .filter(|v| !matches!(v, 1 | 6 | 17))
        .take(10)
        .for_each(|v| assert_eq!(IpProtocol::from_u8(v).to_u8(), v));
}

// --- IpProtocol equality / hash ---

#[test]
fn ip_protocol_eq() {
    assert_eq!(IpProtocol::Tcp, IpProtocol::Tcp);
    assert_ne!(IpProtocol::Tcp, IpProtocol::Udp);
    assert_ne!(IpProtocol::Other(6), IpProtocol::Tcp);
}

// --- Protocol Display ---

#[test]
fn protocol_tcp_display() {
    assert_eq!(format!("{}", Protocol::Tcp), "TCP");
}

#[test]
fn protocol_udp_display() {
    assert_eq!(format!("{}", Protocol::Udp), "UDP");
}

// --- Protocol equality ---

#[test]
fn protocol_eq() {
    assert_eq!(Protocol::Tcp, Protocol::Tcp);
    assert_ne!(Protocol::Tcp, Protocol::Udp);
}

#[test]
fn protocol_copy() {
    let p = Protocol::Tcp;
    let p2 = p;
    assert_eq!(p, p2);
}
