//! ВОПРОС DNS И АДРЕСА ОТВЕТА (RFC 1035 §4.1): вопрос, собранный `asked`, читается тем же разбором,
//! что и чужой; адреса `A` вынимаются из ответа вместе со сроком.
#![cfg(feature = "dns")]

use std::net::Ipv4Addr;
use std::time::Duration;

use reflex_core::dns::{asked, DnsDirection, DnsMessage, Resolved};

#[test]
fn an_asked_question_reads_back_as_the_same_question() {
    let Some(wire) = asked(0x1234, "cloudflare-dns.com") else {
        panic!("имя годное — вопрос обязан сложиться")
    };
    let Some(read) = DnsMessage::parse(&wire) else {
        panic!("свой вопрос обязан читаться своим разбором")
    };
    assert_eq!(read.id, 0x1234);
    assert_eq!(read.direction, DnsDirection::Query);
    assert_eq!(read.queries.len(), 1);
    assert_eq!(read.queries[0].name, "cloudflare-dns.com");
    assert_eq!((read.queries[0].qtype, read.queries[0].qclass), (1, 1));
    // Рекурсия желательна (`RD`): спрашиваем рекурсор, а не хозяина зоны.
    assert_eq!(wire[2] & 0x01, 0x01);
}

#[test]
fn a_name_the_wire_cannot_carry_is_not_asked() {
    assert_eq!(asked(1, ""), None);
    assert_eq!(asked(1, "a..b"), None);
    assert_eq!(asked(1, &format!("{}.com", "x".repeat(64))), None);
    assert_eq!(asked(1, &vec!["abcdefgh"; 32].join(".")), None);
    // Точка в конце — корень, законная форма полного имени.
    assert!(asked(1, "example.com.").is_some());
}

/// Ответ: два `A`, `CNAME` между ними и `A` с кривой длиной — адресами считаются ровно два.
#[test]
fn addresses_are_the_a_records_with_their_ttl() {
    let header = [0x12, 0x34, 0x81, 0x80, 0, 1, 0, 4, 0, 0, 0, 0];
    let question: Vec<u8> = [
        &[3][..],
        b"www",
        &[7],
        b"example",
        &[3],
        b"com",
        &[0, 0, 1, 0, 1],
    ]
    .concat();
    // Имя ответа — указатель на вопрос (смещение 12).
    let record = |rtype: u16, ttl: u32, rdata: &[u8]| -> Vec<u8> {
        [
            &[0xC0, 12][..],
            &rtype.to_be_bytes(),
            &1u16.to_be_bytes(),
            &ttl.to_be_bytes(),
            &(rdata.len() as u16).to_be_bytes(),
            rdata,
        ]
        .concat()
    };
    let wire = [
        &header[..],
        &question,
        &record(1, 300, &[104, 16, 248, 249]),
        &record(5, 60, &[0xC0, 12]),
        &record(1, 30, &[104, 16, 249, 249]),
        &record(1, 30, &[1, 2, 3]),
    ]
    .concat();
    let Some(message) = DnsMessage::parse(&wire) else {
        panic!("ответ обязан читаться")
    };
    assert_eq!(
        message.addresses(),
        vec![
            Resolved {
                address: Ipv4Addr::new(104, 16, 248, 249),
                ttl: Duration::from_secs(300)
            },
            Resolved {
                address: Ipv4Addr::new(104, 16, 249, 249),
                ttl: Duration::from_secs(30)
            },
        ]
    );
}
