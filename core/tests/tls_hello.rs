#![cfg(feature = "tls")]

use reflex_core::tls::build_client_hello;

#[test]
fn client_hello_is_valid_tls_record() {
    let ch = build_client_hello("example.com");
    assert_eq!(ch[0], 0x16, "content type must be Handshake");
    assert_eq!(ch[1], 0x03, "major version");
    assert_eq!(ch[5], 0x01, "handshake type must be ClientHello");
    assert!(
        ch.windows(b"example.com".len())
            .any(|w| w == b"example.com"),
        "SNI must contain domain"
    );
}

#[test]
fn client_hello_different_domains_differ() {
    let ch1 = build_client_hello("foo.com");
    let ch2 = build_client_hello("bar.org");
    assert_ne!(ch1, ch2);
    assert!(ch1.windows(b"foo.com".len()).any(|w| w == b"foo.com"));
    assert!(ch2.windows(b"bar.org".len()).any(|w| w == b"bar.org"));
}

/// Переписанный SNI читается ТЕМ ЖЕ парсером — «что положили» и «что прочтут» сверяются
/// одним источником, а не двумя таблицами.
#[test]
fn rewrite_sni_replaces_name_and_stays_parsable() {
    let ch = build_client_hello("www.google.com");
    let out = reflex_core::tls::rewrite_sni(&ch, "rutracker.org").expect("переписалось");
    assert_eq!(
        reflex_core::tls::extract_sni(&out).as_deref(),
        Some("rutracker.org")
    );
}

/// ДЛИНЫ КОНСИСТЕНТНЫ: объявленная длина записи совпадает с фактической при имени и короче,
/// и длиннее исходного. Парс этого не ловит — он читает по объявленным длинам и врёт вместе
/// с ними; ловит только сверка с фактом.
#[test]
fn rewrite_sni_keeps_all_declared_lengths_consistent() {
    let ch = build_client_hello("www.google.com");
    for name in ["a.io", "очень-длинное-имя-домена-для-проверки.example.com"] {
        let out = reflex_core::tls::rewrite_sni(&ch, name).expect("переписалось");
        let record = u16::from_be_bytes([out[3], out[4]]) as usize;
        assert_eq!(5 + record, out.len(), "{name}: длина записи разошлась с фактом");
        let hs = u32::from_be_bytes([0, out[6], out[7], out[8]]) as usize;
        assert_eq!(4 + hs, record, "{name}: длина handshake разошлась с записью");
        assert_eq!(reflex_core::tls::extract_sni(&out).as_deref(), Some(name));
    }
}

/// Не ClientHello и hello без SNI — `None`, а не мусор на выходе.
#[test]
fn rewrite_sni_refuses_what_it_cannot_rewrite() {
    assert!(reflex_core::tls::rewrite_sni(b"not a hello at all", "x.com").is_none());
}

/// БЛОК РАСШИРЕНИЙ обязан кончаться ровно на конце ClientHello.
///
/// Заведён после обезоруживания: снятие правки этой длины НЕ роняло ни один прежний тест —
/// парс SNI идёт по расширениям до `min(объявленное, длина)` и находит имя даже при
/// разъехавшемся заголовке, а сверка record/handshake до него не добирается. Тест, который
/// не краснеет на снятой защите, ничего не проверяет.
#[test]
fn rewrite_sni_keeps_extensions_block_length_exact() {
    // Смещение поля «длина блока расширений»: тот же проход, что делает парсер.
    fn ext_len_offset(h: &[u8]) -> usize {
        let mut pos = 5 + 38;
        pos += 1 + h[pos] as usize; // session_id
        pos += 2 + u16::from_be_bytes([h[pos], h[pos + 1]]) as usize; // cipher_suites
        pos += 1 + h[pos] as usize; // compression_methods
        pos
    }
    let ch = build_client_hello("www.google.com");
    for name in ["a.io", "очень-длинное-имя.example.com"] {
        let out = reflex_core::tls::rewrite_sni(&ch, name).expect("переписалось");
        let at = ext_len_offset(&out);
        let ext_total = u16::from_be_bytes([out[at], out[at + 1]]) as usize;
        assert_eq!(
            at + 2 + ext_total,
            out.len(),
            "{name}: блок расширений кончается не на конце hello"
        );
    }
}
