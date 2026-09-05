#![cfg(feature = "tls")]

use reflex_core::tls::{
    record_need, RecordNeed, TlsContentType, TlsFragment, TlsRecord, TlsVersion,
};

// --- Helper: build a minimal ClientHello with SNI ---

fn build_client_hello_record(domain: &str) -> Vec<u8> {
    let sni_ext_data_len = 2 + 1 + 2 + domain.len();
    let extensions_len = 2 + 2 + sni_ext_data_len;

    let mut hello_payload = Vec::new();
    hello_payload.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
    hello_payload.extend_from_slice(&[0x00; 32]); // random
    hello_payload.push(0x00); // session_id len = 0
    hello_payload.extend_from_slice(&[0x00, 0x02, 0x00, 0x2F]); // cipher suites (1 suite)
    hello_payload.extend_from_slice(&[0x01, 0x00]); // compression methods
    hello_payload.extend_from_slice(&(extensions_len as u16).to_be_bytes());
    // SNI extension
    hello_payload.extend_from_slice(&[0x00, 0x00]); // extension type = SNI
    hello_payload.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
    hello_payload.extend_from_slice(&((sni_ext_data_len - 2) as u16).to_be_bytes());
    hello_payload.push(0x00); // host_name type
    hello_payload.extend_from_slice(&(domain.len() as u16).to_be_bytes());
    hello_payload.extend_from_slice(domain.as_bytes());

    let hello_len = hello_payload.len();
    let mut handshake = vec![0x01]; // ClientHello type
    handshake.push(0x00);
    handshake.extend_from_slice(&(hello_len as u16).to_be_bytes());
    handshake.extend_from_slice(&hello_payload);

    let hs_len = handshake.len();
    let mut record = vec![0x16]; // content_type = Handshake
    record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0
    record.extend_from_slice(&(hs_len as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

// --- extract_sni ---

#[test]
fn extract_sni_valid_client_hello() {
    let record = build_client_hello_record("rutracker.org");
    let sni = reflex_core::tls::extract_sni(&record);
    assert_eq!(sni.as_deref(), Some("rutracker.org"));
}

#[test]
fn extract_sni_truncated_after_sni_extension() {
    // Build a full record, then truncate *after* the SNI extension
    // but before the TLS record length is fully satisfied.
    // The greedy parser should still extract the SNI.
    let record = build_client_hello_record("discord.com");

    // Corrupt the TLS record length to be larger than actual data,
    // simulating a truncated first TCP segment where SNI is still present.
    let mut truncated = record.clone();
    // Increase the TLS record length field beyond actual data
    let fake_len = (truncated.len() - 5 + 100) as u16;
    truncated[3] = (fake_len >> 8) as u8;
    truncated[4] = (fake_len & 0xFF) as u8;

    // extract_sni uses greedy parsing and doesn't require full record
    let sni = reflex_core::tls::extract_sni(&truncated);
    assert_eq!(sni.as_deref(), Some("discord.com"));
}

#[test]
fn extract_sni_non_tls_data() {
    let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let sni = reflex_core::tls::extract_sni(data);
    assert!(sni.is_none());
}

#[test]
fn extract_sni_too_short() {
    let data = [0x16, 0x03, 0x01, 0x00];
    let sni = reflex_core::tls::extract_sni(&data);
    assert!(sni.is_none());
}

#[test]
fn extract_sni_empty() {
    let sni = reflex_core::tls::extract_sni(&[]);
    assert!(sni.is_none());
}

#[test]
fn extract_sni_server_hello_returns_none() {
    // Build a ServerHello record
    let mut handshake = vec![0x02]; // ServerHello type
    handshake.extend_from_slice(&[0x00, 0x00, 0x04]); // length = 4
    handshake.extend_from_slice(&[0x03, 0x03, 0x00, 0x00]); // minimal body

    let hs_len = handshake.len();
    let mut record = vec![0x16]; // Handshake
    record.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
    record.extend_from_slice(&(hs_len as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    let sni = reflex_core::tls::extract_sni(&record);
    assert!(sni.is_none());
}

#[test]
fn extract_sni_wrong_content_type() {
    // Application data (0x17), not handshake (0x16)
    let data = [0x17, 0x03, 0x03, 0x00, 0x04, 0x01, 0xDE, 0xAD, 0xBE, 0xEF];
    let sni = reflex_core::tls::extract_sni(&data);
    assert!(sni.is_none());
}

// --- TlsRecord::parse ---

#[test]
fn parse_valid_tls_record() {
    let record = build_client_hello_record("example.com");
    let parsed = TlsRecord::parse(&record).unwrap();
    assert_eq!(parsed.content_type, TlsContentType::Handshake);
    assert_eq!(parsed.version, TlsVersion { major: 3, minor: 1 });
    if let TlsFragment::ClientHello { sni } = &parsed.fragment {
        assert_eq!(sni.as_deref(), Some("example.com"));
    } else {
        panic!("expected ClientHello");
    }
}

#[test]
fn parse_too_short_data() {
    assert!(TlsRecord::parse(&[0x16, 0x03]).is_none());
    assert!(TlsRecord::parse(&[]).is_none());
    assert!(TlsRecord::parse(&[0x16]).is_none());
}

#[test]
fn parse_length_exceeds_data() {
    // Header says 100 bytes of payload but only 5 total
    let data = [0x16, 0x03, 0x01, 0x00, 0x64];
    assert!(TlsRecord::parse(&data).is_none());
}

#[test]
fn parse_application_data() {
    let data = [0x17, 0x03, 0x03, 0x00, 0x03, 0xAA, 0xBB, 0xCC];
    let parsed = TlsRecord::parse(&data).unwrap();
    assert_eq!(parsed.content_type, TlsContentType::ApplicationData);
    assert_eq!(parsed.fragment, TlsFragment::Other);
}

/// ТРЕВОГА РАЗБИРАЕТСЯ ДО КОДА, а не сводится к «что-то иное» (исправлено 06.09.2026).
///
/// Тест ждал `Other` и был прав ровно до того дня, когда у `TlsFragment` появился вариант `Alert`
/// с уровнем и кодом. Расхождение прожило незамеченным, потому что весь файл стоит под
/// `#![cfg(feature = "tls")]`, а фича не включалась ни в одном обычном прогоне: `cargo test -p
/// reflex-core --test tls_sni` давал `0 passed` — то есть проверка была написана и НЕ ЗВАЛАСЬ.
///
/// Обнажилось переездом `reflex-instrument` в workspace: он требует `reflex-core` с `tls`, фичи в
/// workspace объединяются, и мёртвый файл ожил целиком. Ровно та причина, по которой прибор
/// доверия `unknown_ca` (48) от `handshake_failure` (40) и отличает — без кода тревоги ответ не
/// сужает круг.
#[test]
fn parse_alert_record() {
    let data = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]; // fatal, handshake_failure
    let parsed = TlsRecord::parse(&data).unwrap();
    assert_eq!(parsed.content_type, TlsContentType::Alert);
    assert_eq!(
        parsed.fragment,
        TlsFragment::Alert {
            level: 2,
            description: 40
        }
    );
}

#[test]
fn parse_change_cipher_spec() {
    let data = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
    let parsed = TlsRecord::parse(&data).unwrap();
    assert_eq!(parsed.content_type, TlsContentType::ChangeCipherSpec);
    assert_eq!(parsed.fragment, TlsFragment::Other);
}

#[test]
fn parse_server_hello_record() {
    let mut handshake = vec![0x02]; // ServerHello
    handshake.extend_from_slice(&[0x00, 0x00, 0x02]);
    handshake.extend_from_slice(&[0x03, 0x03]);

    let hs_len = handshake.len();
    let mut record = vec![0x16, 0x03, 0x03];
    record.extend_from_slice(&(hs_len as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    let parsed = TlsRecord::parse(&record).unwrap();
    assert_eq!(parsed.content_type, TlsContentType::Handshake);
    assert_eq!(parsed.fragment, TlsFragment::ServerHello);
}

#[test]
fn parse_empty_handshake_body() {
    // Handshake record with zero-length body
    let data = [0x16, 0x03, 0x03, 0x00, 0x00];
    let parsed = TlsRecord::parse(&data).unwrap();
    assert_eq!(parsed.content_type, TlsContentType::Handshake);
    assert_eq!(parsed.fragment, TlsFragment::Other);
}

// --- TlsContentType ---

#[test]
fn content_type_other_variant() {
    let data = [0x19, 0x03, 0x03, 0x00, 0x01, 0x00]; // type 25, unknown
    let parsed = TlsRecord::parse(&data).unwrap();
    assert_eq!(parsed.content_type, TlsContentType::Other(25));
}

// --- ClientHello without SNI ---

#[test]
fn client_hello_no_extensions() {
    let mut hello_payload = Vec::new();
    hello_payload.extend_from_slice(&[0x03, 0x03]); // version
    hello_payload.extend_from_slice(&[0x00; 32]); // random
    hello_payload.push(0x00); // session_id len
    hello_payload.extend_from_slice(&[0x00, 0x02, 0x00, 0x2F]); // cipher suites
    hello_payload.extend_from_slice(&[0x01, 0x00]); // compression

    let hello_len = hello_payload.len();
    let mut handshake = vec![0x01, 0x00];
    handshake.extend_from_slice(&(hello_len as u16).to_be_bytes());
    handshake.extend_from_slice(&hello_payload);

    let hs_len = handshake.len();
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(hs_len as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    let parsed = TlsRecord::parse(&record).unwrap();
    if let TlsFragment::ClientHello { sni } = &parsed.fragment {
        assert!(sni.is_none());
    } else {
        panic!("expected ClientHello");
    }
}

// --- sni_span: byte range of SNI hostname within the ClientHello payload ---

#[test]
fn sni_span_points_at_hostname_bytes() {
    let hello = reflex_core::tls::build_client_hello("rutracker.org");
    let sni = reflex_core::tls::sni(&hello).expect("sni found");
    assert_eq!(sni.name, "rutracker.org", "имя и диапазон неразделимы");
    let (offset, len) = sni.span;
    assert_eq!(len, "rutracker.org".len(), "длина = длина хоста");
    assert_eq!(
        &hello[offset..offset + len],
        b"rutracker.org",
        "диапазон указывает ровно на байты хоста"
    );
}

#[test]
fn sni_span_none_when_no_sni() {
    // Обычные байты, не ClientHello — span отсутствует.
    assert_eq!(reflex_core::tls::sni(b"not a tls hello"), None);
}

// --- sni_span accuracy: structural parse, not substring search ---

/// ClientHello, где КОПИЯ hostname лежит в session_id (decoy) ПЕРЕД настоящим SNI.
/// Поиск подстроки нашёл бы decoy (ранний offset); структурный парс — настоящий SNI.
fn hello_decoy_in_session_id(domain: &str) -> (Vec<u8>, usize) {
    let d = domain.as_bytes();
    let sid_len = d.len();
    let sni_list_len = 1 + 2 + d.len();
    let sni_ext_data_len = 2 + sni_list_len;
    let extensions_len = 2 + 2 + sni_ext_data_len;
    let ch_body_len = 2 + 32 + 1 + sid_len + 2 + 2 + 1 + 1 + 2 + extensions_len;
    let record_len = 1 + 3 + ch_body_len;

    let mut pkt = Vec::new();
    pkt.push(0x16);
    pkt.extend_from_slice(&[0x03, 0x01]);
    pkt.extend_from_slice(&(record_len as u16).to_be_bytes());
    pkt.push(0x01);
    let bl = ch_body_len as u32;
    pkt.push((bl >> 16) as u8);
    pkt.push((bl >> 8) as u8);
    pkt.push(bl as u8);
    pkt.extend_from_slice(&[0x03, 0x03]);
    pkt.extend_from_slice(&[0xAA; 32]);
    pkt.push(sid_len as u8);
    pkt.extend_from_slice(d); // DECOY копия домена в session_id
    pkt.extend_from_slice(&[0x00, 0x02]);
    pkt.extend_from_slice(&[0x00, 0x2F]);
    pkt.push(0x01);
    pkt.push(0x00);
    pkt.extend_from_slice(&(extensions_len as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
    pkt.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
    pkt.push(0x00);
    pkt.extend_from_slice(&(d.len() as u16).to_be_bytes());
    let real_offset = pkt.len(); // настоящий SNI hostname начинается здесь
    pkt.extend_from_slice(d);
    (pkt, real_offset)
}

#[test]
fn sni_span_skips_decoy_hostname_in_session_id() {
    let (hello, real_offset) = hello_decoy_in_session_id("rutracker.org");
    let sni = reflex_core::tls::sni(&hello).expect("sni");
    let (offset, len) = sni.span;
    assert_eq!(
        offset, real_offset,
        "span указывает на SNI, не на decoy в session_id"
    );
    assert_eq!(len, "rutracker.org".len());
    assert_eq!(&hello[offset..offset + len], b"rutracker.org");
}

// ── ПОЛНОТА ЗАПИСИ (#3): различить «не TLS» и «TLS не дочитан» ──────────────────────────────────
//
// Оплачено полем: 1500 флоу с `serve None`, у 815 SNI не извлёкся вовсе, у 765 из них прочитано
// меньше 1400 байт, а плечи при этом ВСТАЛИ (`connected=true, Silent`). Соединение есть, данных
// нет — сервер ждёт остаток записи. Причина: читатель звал `read()` один раз, а сколькими
// сегментами придёт запись, решает TCP.
//
// `extract_sni` на оба случая отвечает `None`, и по этому ответу нельзя решить, ЖДАТЬ ли ещё.
// Вопрос «сколько не хватает» — отдельный, и ответ на него обязан быть значением, а не догадкой.

#[test]
fn полная_запись_названа_полной() {
    let rec = build_client_hello_record("example.com");
    assert_eq!(record_need(&rec), RecordNeed::Complete);
}

#[test]
fn обрезанная_запись_называет_сколько_не_хватает() {
    let rec = build_client_hello_record("example.com");
    let cut = 40;
    assert_eq!(
        record_need(&rec[..cut]),
        RecordNeed::More {
            at_least: rec.len() - cut
        },
        "обрезок обязан назвать НЕДОСТАЧУ числом — иначе читателю нечем решить, ждать ли"
    );
}

#[test]
fn заголовок_короче_пяти_байт_тоже_недостача() {
    let rec = build_client_hello_record("example.com");
    // Длина записи объявлена в байтах 3..5 — пока их нет, недостача известна лишь снизу.
    assert_eq!(record_need(&rec[..3]), RecordNeed::More { at_least: 2 });
    assert_eq!(record_need(&[]), RecordNeed::More { at_least: 5 });
}

#[test]
fn не_tls_названо_не_tls_а_не_недостачей() {
    // Ключевое различение: ждать продолжения тут НЕЛЬЗЯ — его не будет никогда, и ожидание
    // превратилось бы в задержку на каждом не-TLS соединении.
    assert_eq!(record_need(b"GET / HTTP/1.1\r\n"), RecordNeed::NotTls);
    assert_eq!(
        record_need(&[0xFF, 0x00, 0x00, 0x00, 0x01]),
        RecordNeed::NotTls
    );
}

#[test]
fn запись_с_хвостом_полна() {
    // За ClientHello может сразу идти следующая запись — это не мешает первой быть полной.
    let mut rec = build_client_hello_record("example.com");
    rec.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5]);
    assert_eq!(record_need(&rec), RecordNeed::Complete);
}
