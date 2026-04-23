use reflex_core::parse::parse_tcp_from_ip;
use reflex_core::types::TcpFlags;

#[test]
fn parse_syn_packet() {
    let mut pkt = vec![0u8; 40];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
    pkt[16..20].copy_from_slice(&[93, 184, 216, 34]);
    pkt[20..22].copy_from_slice(&12345u16.to_be_bytes());
    pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
    pkt[24..28].copy_from_slice(&1000u32.to_be_bytes());
    pkt[28..32].copy_from_slice(&0u32.to_be_bytes());
    pkt[32] = 0x50;
    pkt[33] = TcpFlags::SYN.bits();
    pkt[34..36].copy_from_slice(&29200u16.to_be_bytes());

    let seg = parse_tcp_from_ip(&pkt).expect("should parse");
    assert_eq!(seg.flow.src.port(), 12345);
    assert_eq!(seg.flow.dst.port(), 443);
    assert_eq!(seg.seq, 1000);
    assert_eq!(seg.ttl, 64);
    assert!(seg.flags.contains(TcpFlags::SYN));
    assert!(seg.payload.is_empty());
}

#[test]
fn parse_with_payload() {
    let payload = b"hello";
    let total_len = 40 + payload.len();
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
    pkt[16..20].copy_from_slice(&[1, 2, 3, 4]);
    pkt[20..22].copy_from_slice(&1000u16.to_be_bytes());
    pkt[22..24].copy_from_slice(&80u16.to_be_bytes());
    pkt[24..28].copy_from_slice(&500u32.to_be_bytes());
    pkt[28..32].copy_from_slice(&600u32.to_be_bytes());
    pkt[32] = 0x50;
    pkt[33] = (TcpFlags::PSH | TcpFlags::ACK).bits();
    pkt[34..36].copy_from_slice(&16384u16.to_be_bytes());
    pkt[40..].copy_from_slice(payload);

    let seg = parse_tcp_from_ip(&pkt).expect("should parse");
    assert_eq!(seg.payload, payload);
    assert!(seg.flags.contains(TcpFlags::PSH));
}

#[test]
fn parse_too_short_returns_none() {
    assert!(parse_tcp_from_ip(&[0u8; 10]).is_none());
}

#[test]
fn parse_non_tcp_returns_none() {
    let mut pkt = vec![0u8; 40];
    pkt[0] = 0x45;
    pkt[9] = 17;
    assert!(parse_tcp_from_ip(&pkt).is_none());
}
