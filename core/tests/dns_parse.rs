#![cfg(feature = "dns")]

use reflex_core::dns::{DnsDirection, DnsMessage};

#[test]
fn parse_dns_query() {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&[0x12, 0x34]); // ID
    pkt.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
    pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    pkt.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
    pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
    pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0
                                          // Question: example.com
    pkt.push(7);
    pkt.extend_from_slice(b"example");
    pkt.push(3);
    pkt.extend_from_slice(b"com");
    pkt.push(0);
    pkt.extend_from_slice(&[0x00, 0x01]); // A
    pkt.extend_from_slice(&[0x00, 0x01]); // IN

    let msg = DnsMessage::parse(&pkt).unwrap();
    assert_eq!(msg.id, 0x1234);
    assert_eq!(msg.direction, DnsDirection::Query);
    assert_eq!(msg.queries.len(), 1);
    assert_eq!(msg.queries[0].name, "example.com");
    assert!(msg.answers.is_empty());
}

#[test]
fn parse_dns_response_with_answer() {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&[0xAB, 0xCD]); // ID
    pkt.extend_from_slice(&[0x81, 0x80]); // flags: QR=1, RD=1, RA=1
    pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    pkt.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    // Question: test.com
    pkt.push(4);
    pkt.extend_from_slice(b"test");
    pkt.push(3);
    pkt.extend_from_slice(b"com");
    pkt.push(0);
    pkt.extend_from_slice(&[0x00, 0x01]); // A
    pkt.extend_from_slice(&[0x00, 0x01]); // IN
                                          // Answer: pointer to question name
    pkt.extend_from_slice(&[0xC0, 0x0C]); // name pointer
    pkt.extend_from_slice(&[0x00, 0x01]); // A
    pkt.extend_from_slice(&[0x00, 0x01]); // IN
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL=60
    pkt.extend_from_slice(&[0x00, 0x04]); // RDLENGTH=4
    pkt.extend_from_slice(&[93, 184, 216, 34]); // IP

    let msg = DnsMessage::parse(&pkt).unwrap();
    assert_eq!(msg.direction, DnsDirection::Response);
    assert_eq!(msg.queries[0].name, "test.com");
    assert_eq!(msg.answers.len(), 1);
    assert_eq!(msg.answers[0].name, "test.com");
    assert_eq!(msg.answers[0].rdata, vec![93, 184, 216, 34]);
}

#[test]
fn parse_dns_too_short() {
    let pkt = vec![0u8; 11];
    assert!(DnsMessage::parse(&pkt).is_none());
}
