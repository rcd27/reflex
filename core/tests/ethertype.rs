use reflex_core::types::EtherType;

// --- from_u16 ---

#[test]
fn ethertype_ipv4_from_u16() {
    assert_eq!(EtherType::from_u16(0x0800), EtherType::Ipv4);
}

#[test]
fn ethertype_ipv6_from_u16() {
    assert_eq!(EtherType::from_u16(0x86DD), EtherType::Ipv6);
}

#[test]
fn ethertype_arp_from_u16() {
    assert_eq!(EtherType::from_u16(0x0806), EtherType::Arp);
}

#[test]
fn ethertype_other_from_u16() {
    assert_eq!(EtherType::from_u16(0x8100), EtherType::Other(0x8100));
}

#[test]
fn ethertype_zero_is_other() {
    assert_eq!(EtherType::from_u16(0x0000), EtherType::Other(0x0000));
}

// --- to_u16 ---

#[test]
fn ethertype_ipv4_to_u16() {
    assert_eq!(EtherType::Ipv4.to_u16(), 0x0800);
}

#[test]
fn ethertype_ipv6_to_u16() {
    assert_eq!(EtherType::Ipv6.to_u16(), 0x86DD);
}

#[test]
fn ethertype_arp_to_u16() {
    assert_eq!(EtherType::Arp.to_u16(), 0x0806);
}

#[test]
fn ethertype_other_to_u16() {
    assert_eq!(EtherType::Other(0x88CC).to_u16(), 0x88CC);
}

// --- Roundtrip ---

#[test]
fn ethertype_roundtrip_known() {
    [0x0800u16, 0x86DD, 0x0806]
        .iter()
        .for_each(|&v| assert_eq!(EtherType::from_u16(v).to_u16(), v));
}

#[test]
fn ethertype_roundtrip_other() {
    [0x8100u16, 0x88CC, 0x0000, 0xFFFF]
        .iter()
        .for_each(|&v| assert_eq!(EtherType::from_u16(v).to_u16(), v));
}

// --- Equality ---

#[test]
fn ethertype_eq() {
    assert_eq!(EtherType::Ipv4, EtherType::Ipv4);
    assert_ne!(EtherType::Ipv4, EtherType::Ipv6);
    assert_ne!(EtherType::Other(0x0800), EtherType::Ipv4);
}

#[test]
fn ethertype_copy() {
    let e = EtherType::Ipv4;
    let e2 = e;
    assert_eq!(e, e2);
}
