#![cfg(feature = "dns")]

use std::net::Ipv4Addr;

use reflex_core::dns::{DnsCache, DnsDirection, DnsMessage};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_dns_response(domain: &str, ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
    let mut pkt = Vec::new();

    // Header
    pkt.extend_from_slice(&[0xAA, 0xBB]); // ID
    pkt.extend_from_slice(&[0x81, 0x80]); // flags: QR=1, RD=1, RA=1
    pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    pkt.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
    pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
    pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0

    // Question section: encode domain labels
    for label in domain.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0); // end of name
    pkt.extend_from_slice(&[0x00, 0x01]); // QTYPE=A
    pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN

    // Answer section: compression pointer 0xC00C -> offset 12 (start of question name)
    pkt.extend_from_slice(&[0xC0, 0x0C]); // name pointer
    pkt.extend_from_slice(&[0x00, 0x01]); // TYPE=A
    pkt.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
    pkt.extend_from_slice(&ttl.to_be_bytes()); // TTL
    pkt.extend_from_slice(&[0x00, 0x04]); // RDLENGTH=4
    pkt.extend_from_slice(&ip.octets()); // RDATA

    pkt
}

fn build_dns_query(domain: &str) -> Vec<u8> {
    let mut pkt = Vec::new();

    // Header
    pkt.extend_from_slice(&[0x12, 0x34]); // ID
    pkt.extend_from_slice(&[0x01, 0x00]); // flags: RD=1, QR=0 (query)
    pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    pkt.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
    pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
    pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0

    // Question section
    for label in domain.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0);
    pkt.extend_from_slice(&[0x00, 0x01]); // QTYPE=A
    pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN

    pkt
}

/// Extract A-record IPs from a parsed DnsMessage response.
fn extract_a_records(msg: &DnsMessage) -> Vec<(Ipv4Addr, u32)> {
    msg.answers
        .iter()
        .filter(|a| a.rtype == 1 && a.rdata.len() == 4)
        .map(|a| {
            let ip = Ipv4Addr::new(a.rdata[0], a.rdata[1], a.rdata[2], a.rdata[3]);
            (ip, a.ttl)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests: DNS parsing
// ---------------------------------------------------------------------------

#[test]
fn parse_a_record_response() {
    let ip: Ipv4Addr = "93.184.216.34".parse().unwrap();
    let pkt = build_dns_response("example.com", ip, 300);

    let msg = DnsMessage::parse(&pkt).unwrap();

    assert_eq!(msg.direction, DnsDirection::Response);
    assert_eq!(msg.queries.len(), 1);
    assert_eq!(msg.queries[0].name, "example.com");

    let a_records = extract_a_records(&msg);
    assert_eq!(a_records.len(), 1);
    assert_eq!(a_records[0].0, ip);
    assert_eq!(a_records[0].1, 300);
}

#[test]
fn ignore_dns_query() {
    let pkt = build_dns_query("example.com");

    let msg = DnsMessage::parse(&pkt).unwrap();

    // It parses, but direction is Query — callers should filter by Response
    assert_eq!(msg.direction, DnsDirection::Query);
    assert!(msg.answers.is_empty());
}

// ---------------------------------------------------------------------------
// Tests: DnsCache
// ---------------------------------------------------------------------------

#[test]
fn cache_insert_and_lookup() {
    let mut cache = DnsCache::new(100);
    let ip: Ipv4Addr = "93.184.216.34".parse().unwrap();

    cache.insert("example.com", &[ip], 300.0, 0.0);

    assert_eq!(cache.lookup(ip, 0.0), Some("example.com"));
    assert_eq!(cache.lookup(ip, 299.0), Some("example.com"));
}

#[test]
fn cache_expired_entry_returns_none() {
    let mut cache = DnsCache::new(100);
    let ip: Ipv4Addr = "1.2.3.4".parse().unwrap();

    cache.insert("example.com", &[ip], 60.0, 0.0);

    // At TTL boundary — still valid
    assert_eq!(cache.lookup(ip, 60.0), Some("example.com"));
    // Past TTL — expired
    assert_eq!(cache.lookup(ip, 60.1), None);
}

#[test]
fn cache_evicts_oldest_when_full() {
    let mut cache = DnsCache::new(2);

    let ip1: Ipv4Addr = "1.1.1.1".parse().unwrap();
    let ip2: Ipv4Addr = "2.2.2.2".parse().unwrap();
    let ip3: Ipv4Addr = "3.3.3.3".parse().unwrap();

    cache.insert("first.com", &[ip1], 300.0, 1.0);
    cache.insert("second.com", &[ip2], 300.0, 2.0);
    cache.insert("third.com", &[ip3], 300.0, 3.0);

    // first.com (oldest, inserted_at=1.0) should be evicted
    assert_eq!(cache.len(), 2);
    assert_eq!(cache.lookup(ip1, 3.0), None);
    assert_eq!(cache.lookup(ip2, 3.0), Some("second.com"));
    assert_eq!(cache.lookup(ip3, 3.0), Some("third.com"));
}
