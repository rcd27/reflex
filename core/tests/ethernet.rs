use reflex_core::types::{EtherType, EthernetFrame, Mac};

#[test]
fn parse_ipv6_frame() {
    let mut raw = vec![0u8; 14];
    raw[12] = 0x86;
    raw[13] = 0xDD;
    let frame = EthernetFrame::parse(&raw).unwrap();
    assert_eq!(frame.ethertype, EtherType::Ipv6);
    assert!(frame.payload.is_empty());
}

#[test]
fn parse_frame_with_payload() {
    let mut raw = vec![0u8; 14];
    raw[12] = 0x08;
    raw[13] = 0x00;
    raw.extend_from_slice(&[0x45, 0x00, 0x00, 0x28]); // some IP header bytes
    let frame = EthernetFrame::parse(&raw).unwrap();
    assert_eq!(frame.ethertype, EtherType::Ipv4);
    assert_eq!(frame.payload, vec![0x45, 0x00, 0x00, 0x28]);
}

#[test]
fn parse_exactly_14_bytes() {
    let raw = vec![0u8; 14];
    let frame = EthernetFrame::parse(&raw).unwrap();
    assert!(frame.payload.is_empty());
}

#[test]
fn parse_13_bytes_too_short() {
    let raw = vec![0u8; 13];
    assert!(EthernetFrame::parse(&raw).is_none());
}

#[test]
fn parse_empty_too_short() {
    assert!(EthernetFrame::parse(&[]).is_none());
}

#[test]
fn serialize_roundtrip() {
    let original = EthernetFrame {
        dst_mac: Mac([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
        src_mac: Mac([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
        ethertype: EtherType::Ipv4,
        payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
    };
    let bytes = original.serialize();
    let parsed = EthernetFrame::parse(&bytes).unwrap();
    assert_eq!(parsed, original);
}

#[test]
fn serialize_empty_payload() {
    let frame = EthernetFrame {
        dst_mac: Mac([0; 6]),
        src_mac: Mac([0; 6]),
        ethertype: EtherType::Arp,
        payload: vec![],
    };
    let bytes = frame.serialize();
    assert_eq!(bytes.len(), 14);
    assert_eq!(bytes[12], 0x08);
    assert_eq!(bytes[13], 0x06);
}

#[test]
fn mac_bytes_preserved() {
    let raw: Vec<u8> = vec![
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // dst
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // src
        0x08, 0x00, // ethertype
    ];
    let frame = EthernetFrame::parse(&raw).unwrap();
    assert_eq!(frame.dst_mac, Mac([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]));
    assert_eq!(frame.src_mac, Mac([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]));
}

#[test]
fn mac_display() {
    let mac = Mac([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    assert_eq!(format!("{}", mac), "aa:bb:cc:dd:ee:ff");
}

#[test]
fn serialize_preserves_ethertype_other() {
    let frame = EthernetFrame {
        dst_mac: Mac([0; 6]),
        src_mac: Mac([0; 6]),
        ethertype: EtherType::Other(0x8100), // VLAN
        payload: vec![],
    };
    let bytes = frame.serialize();
    assert_eq!(bytes[12], 0x81);
    assert_eq!(bytes[13], 0x00);
}
