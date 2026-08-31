#![cfg(feature = "tls")]
//! ПРИЗНАК ECH В ClientHello (#317).
//!
//! # Зачем этот прибор заводится ЗАРАНЕЕ
//!
//! Encrypted Client Hello — то, ради чего SNI перестанет читаться вовсе (записано в шапке
//! `crate::tls` и `crate::quic` ещё до этого прибора). Весь наш ключ действия сегодня стоит на
//! имени из открытого hello, и когда ECH придёт, мы узнаем об этом ПОСТФАКТУМ — по тому, что
//! продукт перестал лечить цели.
//!
//! Признак стоит копейки и читается тем же проходом по расширениям, что и SNI. Заведённый сегодня,
//! он даёт РЯД: доля соединений с ECH во времени. К моменту, когда доля станет заметной, у нас
//! будет история вместо нулевой отметки.
//!
//! # И вторая причина, менее очевидная: «имя добыто» ≠ «имя верно»
//!
//! Когда ECH применён по-настоящему, в открытом hello стоит `public_name` провайдера (например,
//! `cloudflare-ech.com`), а настоящее имя лежит в зашифрованном `ClientHelloInner`. То есть SNI
//! ЧИТАЕТСЯ и при этом называет НЕ ТУ цель.
//!
//! Отличить это от `GREASE ECH` (Chrome шлёт фиктивное расширение, а имя настоящее) снаружи
//! нельзя — в этом смысл GREASE. Значит признак говорит не «имя ложно», а «имя МОЖЕТ БЫТЬ
//! внешним», и потребитель обязан это различать: сегодня прибор считает ряд, а не правит решения.

use reflex_core::tls::{ech, extract_sni, Ech};

/// Минимальный ClientHello с произвольным набором расширений.
///
/// Построитель скопирован из `tls_sni.rs` намеренно: интеграционные тесты в Rust кода не делят, а
/// заводить общий модуль ради одной функции дороже, чем держать её рядом с предметом.
fn hello_with(extensions: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0x00; 32]);
    body.push(0x00);
    body.extend_from_slice(&[0x00, 0x02, 0x00, 0x2F]);
    body.extend_from_slice(&[0x01, 0x00]);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(extensions);

    let mut handshake = vec![0x01];
    handshake.push(0x00);
    handshake.extend_from_slice(&(body.len() as u16).to_be_bytes());
    handshake.extend_from_slice(&body);

    let mut record = vec![0x16];
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

fn sni_ext(domain: &str) -> Vec<u8> {
    let entry_len = 1 + 2 + domain.len();
    let mut ext = vec![0x00, 0x00];
    ext.extend_from_slice(&((entry_len + 2) as u16).to_be_bytes());
    ext.extend_from_slice(&(entry_len as u16).to_be_bytes());
    ext.push(0x00);
    ext.extend_from_slice(&(domain.len() as u16).to_be_bytes());
    ext.extend_from_slice(domain.as_bytes());
    ext
}

fn ext_of(kind: u16, body: &[u8]) -> Vec<u8> {
    let mut ext = kind.to_be_bytes().to_vec();
    ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
    ext.extend_from_slice(body);
    ext
}

/// ОБЫЧНЫЙ hello ECH НЕ НЕСЁТ — и это должно быть отдельным ответом, а не «ложью по умолчанию».
#[test]
fn a_plain_hello_carries_no_ech() {
    let plain = hello_with(&sni_ext("rutracker.org"));
    assert_eq!(ech(&plain), Ech::Absent);
    assert_eq!(extract_sni(&plain).as_deref(), Some("rutracker.org"));
}

/// ТРИ ЧЕРНОВИКА ECH РАСПОЗНАЮТСЯ ВСЕ. Расширение меняло номер по ходу стандартизации
/// (0xfe0d — draft-13 и позже, 0xfe0e и 0xfe0f — раньше), и клиенты в поле встречаются разные.
/// Признать только последний значило бы считать долю ECH заниженной, ничего об этом не сказав.
#[test]
fn every_ech_draft_is_recognised_and_names_itself() {
    [0xfe0du16, 0xfe0e, 0xfe0f].into_iter().for_each(|draft| {
        let mut exts = sni_ext("cloudflare-ech.com");
        exts.extend_from_slice(&ext_of(draft, &[0x00, 0x00, 0x01]));
        match ech(&hello_with(&exts)) {
            Ech::Offered { draft: seen } => {
                assert_eq!(seen, draft, "черновик распознан, но назван чужим номером")
            }
            Ech::Absent => panic!("черновик {draft:#06x} не распознан"),
        }
    });
}

/// ГЛАВНОЕ: ПРИ ECH ИМЯ ЧИТАЕТСЯ — И ИМЕННО ПОЭТОМУ ПРИЗНАК НУЖЕН.
///
/// В открытом hello стоит `public_name` провайдера, настоящее имя зашифровано. Прибор, знающий
/// только SNI, доложит «цель — cloudflare-ech.com» и будет формально прав, а по существу назовёт
/// не ту цель. Признак ECH — единственное, что отличает этот случай от обычного.
#[test]
fn with_ech_the_readable_name_may_be_the_providers_not_the_targets() {
    let mut exts = sni_ext("cloudflare-ech.com");
    exts.extend_from_slice(&ext_of(0xfe0d, &[0x00, 0x00, 0x01]));
    let hello = hello_with(&exts);

    assert_eq!(extract_sni(&hello).as_deref(), Some("cloudflare-ech.com"));
    assert!(
        matches!(ech(&hello), Ech::Offered { .. }),
        "имя прочиталось, а признак того, что оно может быть внешним, потерян"
    );
}

/// ECH БЕЗ SNI ВООБЩЕ — законный случай, и он не должен читаться как «не ClientHello».
#[test]
fn ech_without_any_sni_is_still_a_hello() {
    let hello = hello_with(&ext_of(0xfe0d, &[0x00, 0x00, 0x01]));
    assert_eq!(extract_sni(&hello), None);
    assert!(matches!(ech(&hello), Ech::Offered { .. }));
}

/// НЕ-HELLO ПРИЗНАКА НЕ ИМЕЕТ. Контроль к остальным: без него все проверки выше проходили бы и на
/// приборе, который отвечает `Offered` на что угодно.
#[test]
fn bytes_that_are_not_a_hello_have_no_ech() {
    assert_eq!(ech(b"not a tls record at all"), Ech::Absent);
    assert_eq!(ech(&[]), Ech::Absent);
    // Запись TLS, но не ClientHello: тип рукопожатия 0x02 (ServerHello).
    assert_eq!(
        ech(&[0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00]),
        Ech::Absent
    );
}
