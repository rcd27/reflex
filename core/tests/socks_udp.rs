use reflex_core::socks_udp::{decapsulated, encapsulated, Decapsulated};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

fn target() -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::new(91, 108, 9, 68), 1400)
}

/// ЗАВЁРНУТОЕ РАЗВОРАЧИВАЕТСЯ В ТО ЖЕ САМОЕ: адрес и нагрузка переживают круг encapsulated →
/// decapsulated — ровно то, что проходит настоящий ответ рефлектора Telegram через `xray`.
#[test]
fn a_wrapped_ipv4_datagram_round_trips() {
    let wrapped = encapsulated(target(), b"rtp-payload");
    match decapsulated(&wrapped) {
        Decapsulated::Datagram { from, payload } => {
            assert_eq!(from, SocketAddr::V4(target()));
            assert_eq!(payload, b"rtp-payload");
        }
        other => panic!("ожидалась Datagram, получено {other:?}"),
    }
}

/// IPv6-ОТВЕТ РАЗБИРАЕТСЯ: RFC не запрещает релею ответить этим видом адреса, и наш разбор
/// не вправе о нём не знать только потому, что в проде мы пока называем цель по IPv4.
#[test]
fn an_ipv6_reply_is_parsed() {
    let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let header: Vec<u8> = [0x00, 0x00, 0x00, 0x04]
        .into_iter()
        .chain(addr.octets())
        .chain(443u16.to_be_bytes())
        .chain(*b"voice")
        .collect();
    match decapsulated(&header) {
        Decapsulated::Datagram { from, payload } => {
            assert_eq!(from, SocketAddr::V6(SocketAddrV6::new(addr, 443, 0, 0)));
            assert_eq!(payload, b"voice");
        }
        other => panic!("ожидалась Datagram, получено {other:?}"),
    }
}

/// ФРАГМЕНТ — ОТДЕЛЬНЫЙ ИСХОД, А НЕ ОШИБКА: склеивать куски догадкой мы не умеем, и подавать
/// его как `Malformed` стёрло бы разницу между «не наш протокол» и «наш протокол, но не влезли».
#[test]
fn a_nonzero_frag_is_reported_as_fragmented() {
    let mut fragment = encapsulated(target(), b"half");
    fragment[2] = 1;
    assert_eq!(decapsulated(&fragment), Decapsulated::Fragmented);
}

/// ОБРЕЗАННЫЙ ЗАГОЛОВОК — `Malformed`, А НЕ ПУСТАЯ НАГРУЗКА ДОГАДКОЙ.
///
/// Контроль рядом: та же датаграмма целиком разбирается без отказа — значит дело в обрезке.
#[test]
fn a_truncated_header_is_malformed() {
    let whole = encapsulated(target(), b"x");
    assert_ne!(
        decapsulated(&whole),
        Decapsulated::Malformed,
        "контроль: целая датаграмма не должна быть Malformed"
    );
    assert_eq!(decapsulated(&whole[..6]), Decapsulated::Malformed);
    assert_eq!(decapsulated(&[]), Decapsulated::Malformed);
}

/// ДОМЕН (ATYP 3) — `Malformed`: адрес ответа релея обязан быть адресом, иначе впрыскивать
/// пакет человеку не от кого — заголовку IP нужен адрес, а не имя.
#[test]
fn a_domain_reply_is_malformed() {
    let header: Vec<u8> = vec![0x00, 0x00, 0x00, 0x03, 3, b'a', b'b', b'c', 0x01, 0xbb];
    assert_eq!(decapsulated(&header), Decapsulated::Malformed);
}

/// ПОЛЕЗНАЯ НАГРУЗКА ОТДАЁТСЯ СРЕЗОМ, А НЕ КОПИЕЙ: указатель совпадает с хвостом исходного
/// буфера. Копия на каждой звонковой датаграмме — это аллокация в горячем пути голоса.
#[test]
fn the_payload_is_a_slice_not_a_copy() {
    let wrapped = encapsulated(target(), b"no-copy");
    let source_ptr = wrapped[10..].as_ptr();
    match decapsulated(&wrapped) {
        Decapsulated::Datagram { payload, .. } => {
            assert_eq!(
                payload.as_ptr(),
                source_ptr,
                "нагрузка обязана быть срезом исходного буфера, не копией"
            );
        }
        other => panic!("ожидалась Datagram, получено {other:?}"),
    }
}
