#![cfg(feature = "dns")]
//! ОТКАЗ ИМЕНИ: «такого имени нет» бывает правдой и бывает стиранием — различает их ОДИН бит.
//!
//! Рекурсор не авторитетен для чужой зоны: не найдя имени, он так и отвечает — `NXDOMAIN` без
//! `AA`. Подделке на пути нужен ОКОНЧАТЕЛЬНЫЙ ответ (иначе клиент пойдёт спрашивать дальше), и
//! она присваивает авторитетность, которой у отвечающего нет. Тесты держат ОБА конца: без бита
//! и с битом, — иначе правило зелено на разборе, который всегда говорит «да» или всегда «нет».

use reflex_core::dns::DnsMessage;

/// Отказ на имя `rutracker.org` с заданными флагами заголовка. Секции ответов у отказа нет
/// вовсе — тем он и коварен: смотреть не на что, кроме флагов.
fn denial(flags: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&[0xAA, 0xBB]);
    packet.extend_from_slice(&flags.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    packet.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
    packet.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
    packet.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0
    for label in "rutracker.org".split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&[0x00, 0x01]); // QTYPE=A
    packet.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
    packet
}

/// Честный отказ рекурсора: `QR·RD·RA·NXDOMAIN`, авторитетность не присвоена.
#[test]
fn an_honest_denial_claims_no_authority() {
    let message = DnsMessage::parse(&denial(0x8183)).expect("отказ разбирается");

    assert_eq!(message.rcode, 3, "«имени не существует» есть третий код");
    assert!(
        !message.authoritative,
        "рекурсор хозяином чужой зоны себя не объявляет"
    );
}

/// Тот же отказ с присвоенной авторитетностью (`AA`) — подпись подделки на пути.
#[test]
fn a_forged_denial_claims_authority() {
    let message = DnsMessage::parse(&denial(0x8583)).expect("отказ разбирается");

    assert_eq!(message.rcode, 3, "код тот же — различие только в бите `AA`");
    assert!(
        message.authoritative,
        "подделке нужен окончательный ответ, и она присваивает авторитетность"
    );
}
