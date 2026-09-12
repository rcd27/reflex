#![cfg(feature = "dns")]
//! ОТКАЗ ИМЕНИ: «такого имени нет» бывает правдой и бывает стиранием — различает их ОДИН бит.
//!
//! Рекурсор не авторитетен для чужой зоны: не найдя имени, он так и отвечает — `NXDOMAIN` без
//! `AA`. Подделке на пути нужен ОКОНЧАТЕЛЬНЫЙ ответ (иначе клиент пойдёт спрашивать дальше), и
//! она присваивает авторитетность, которой у отвечающего нет. Тесты держат ОБА конца: без бита
//! и с битом, — иначе правило зелено на разборе, который всегда говорит «да» или всегда «нет».
//!
//! Улика вторая, от флагов НЕЗАВИСИМАЯ: сколько записей в секции AUTHORITY. Хозяин зоны, отказывая,
//! обязан положить туда `SOA` — клиенту нужен срок кеширования отрицания (RFC 2308). Счётчик лежит
//! в заголовке, и потому читается даже у отказа, где разбирать больше нечего.

use reflex_core::dns::DnsMessage;

/// Отказ на имя `rutracker.org` с заданными флагами и числом записей в секции AUTHORITY. Секции
/// ответов у отказа нет вовсе — тем он и коварен: смотреть не на что, кроме заголовка.
///
/// Сами записи AUTHORITY в тело не кладутся: предмет здесь — СЧЁТЧИК заголовка, а он от тела не
/// зависит. Разбор обязан прочитать его и там, где секцию не приложили вовсе.
fn denial(flags: u16, authority: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&[0xAA, 0xBB]);
    packet.extend_from_slice(&flags.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    packet.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
    packet.extend_from_slice(&authority.to_be_bytes()); // NSCOUNT
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
    let message = DnsMessage::parse(&denial(0x8183, 1)).expect("отказ разбирается");

    assert_eq!(message.rcode, 3, "«имени не существует» есть третий код");
    assert!(
        !message.authoritative,
        "рекурсор хозяином чужой зоны себя не объявляет"
    );
}

/// Тот же отказ с присвоенной авторитетностью (`AA`) — подпись подделки на пути.
#[test]
fn a_forged_denial_claims_authority() {
    let message = DnsMessage::parse(&denial(0x8583, 0)).expect("отказ разбирается");

    assert_eq!(message.rcode, 3, "код тот же — различие только в бите `AA`");
    assert!(
        message.authoritative,
        "подделке нужен окончательный ответ, и она присваивает авторитетность"
    );
}

/// ВТОРАЯ УЛИКА: счётчик секции AUTHORITY доезжает из заголовка.
///
/// Без него подделку от хозяина зоны, спрошенного НАПРЯМУЮ, не отличить: оба ставят `AA` по
/// одинаковому праву — один присвоив его, другой имея. Различает их долг хозяина: срок отрицания.
#[test]
fn the_authority_count_reaches_the_reader() {
    let with_soa = DnsMessage::parse(&denial(0x8583, 1)).expect("отказ разбирается");
    let without = DnsMessage::parse(&denial(0x8583, 0)).expect("отказ разбирается");

    assert_eq!(
        with_soa.authority_records, 1,
        "хозяин зоны кладёт в отказ срок отрицания, и счётчик обязан это донести"
    );
    assert_eq!(
        without.authority_records, 0,
        "подделке срок не нужен: она живёт один пакет"
    );
}
