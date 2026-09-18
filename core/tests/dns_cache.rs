#![cfg(feature = "dns")]

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

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
// Карта «адрес → имя»
// ---------------------------------------------------------------------------

/// ЗАПИСЬ ЧИТАЕТСЯ ДО КОНЦА СВОЕГО СРОКА, и срок назначил отвечающий, а не мы.
#[test]
fn an_entry_is_read_until_the_end_of_its_own_ttl() {
    let mut cache = DnsCache::new(100);
    let ip: Ipv4Addr = "93.184.216.34".parse().unwrap();
    let t0 = Instant::now();

    cache.insert("example.com", &[ip], Duration::from_secs(300), t0);

    assert_eq!(cache.lookup(ip, t0), Some("example.com"));
    assert_eq!(
        cache.lookup(ip, t0 + Duration::from_secs(299)),
        Some("example.com"),
        "до истечения имя называется"
    );
}

/// ИСТЁКШАЯ ЗАПИСЬ МОЛЧИТ, А НЕ НАЗЫВАЕТ СТАРОЕ ИМЯ: адрес, переживший TTL, принадлежит уже не той
/// цели, и назвать прежнюю значило бы соврать приборам о том, с кем идёт разговор.
///
/// Граница включительна: секунда TTL — обещание отвечающего, а не наше округление.
#[test]
fn an_expired_entry_stays_silent_instead_of_naming_the_old_name() {
    let mut cache = DnsCache::new(100);
    let ip: Ipv4Addr = "1.2.3.4".parse().unwrap();
    let t0 = Instant::now();

    cache.insert("example.com", &[ip], Duration::from_secs(60), t0);

    assert_eq!(
        cache.lookup(ip, t0 + Duration::from_secs(60)),
        Some("example.com"),
        "ровно на границе срок ещё держится"
    );
    assert_eq!(
        cache.lookup(ip, t0 + Duration::from_millis(60_100)),
        None,
        "за границей — молчание, а не прежнее имя"
    );
}

/// ТЕСНОЙ КАРТЕ МЕСТО ОСВОБОЖДАЕТ САМАЯ СТАРАЯ ЗАПИСЬ — по времени ВСТАВКИ, не последнего чтения:
/// срок назначил отвечающий, и наше обращение к записи его не продлевает.
#[test]
fn in_a_full_map_the_oldest_entry_gives_up_its_place() {
    let mut cache = DnsCache::new(2);
    let t0 = Instant::now();
    let after = |secs| t0 + Duration::from_secs(secs);

    let ip1: Ipv4Addr = "1.1.1.1".parse().unwrap();
    let ip2: Ipv4Addr = "2.2.2.2".parse().unwrap();
    let ip3: Ipv4Addr = "3.3.3.3".parse().unwrap();

    cache.insert("first.com", &[ip1], Duration::from_secs(300), after(1));
    cache.insert("second.com", &[ip2], Duration::from_secs(300), after(2));
    cache.insert("third.com", &[ip3], Duration::from_secs(300), after(3));

    assert_eq!(cache.len(), 2, "предел карты держится");
    assert_eq!(
        cache.lookup(ip1, after(3)),
        None,
        "старейшая уступила место"
    );
    assert_eq!(cache.lookup(ip2, after(3)), Some("second.com"));
    assert_eq!(
        cache.lookup(ip3, after(3)),
        Some("third.com"),
        "свежий ответ входит всегда — иначе полная карта перестала бы узнавать новое"
    );
}
