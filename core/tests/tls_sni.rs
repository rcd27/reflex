#![cfg(feature = "tls")]

//! TLS: ИМЯ ЦЕЛИ И ГРАНИЦЫ ЗАПИСИ — шесть законов вместо двадцати двух случаев (11.09.2026).
//!
//! Прежде здесь стояли двадцать два теста, и половина из них — представители, выбранные рукой:
//! `extract_sni_too_short`, `extract_sni_empty`, `parse_too_short_data`, `parse_length_exceeds_data`.
//! Подборка «подозрительных» входов ловит ровно то, что подозревали; злой вход тем и зол, что его
//! никто не заподозрил.
//!
//! Заменено на то же, чем схлопнуты опции TCP: ТОТАЛЬНОСТЬ перебором и НЕ ВЫДУМЫВАЕТ, плюс законы
//! о существе — про диапазон имени и про приманку.
//!
//! # Закон, который держится ЗДЕСЬ и больше нигде
//!
//! `sni` идёт по ClientHello СТРУКТУРНО, а не ищет подстроку. Отсюда следует, что копия имени,
//! подложенная в `session_id`, разбор не обманет. Замер 11.09.2026: в каноне об этом НЕТ НИ СЛОВА
//! (`грep приманк|decoy|session_id` = 0), и держится закон одним лишь тестом ниже плюс фразой в
//! докблоке `core/src/tls/mod.rs`.
//!
//! Это промашка канона, а не теста: `Target` расслаивается по ключу (§4), ключ цели здесь — имя из
//! ClientHello, и если имя берётся байтовым поиском, то КЛЮЧ ОБЛАСТИ становится выдумываемым
//! снаружи. Всякий, кто формирует пакет, назначает себе чужую область — и весь копредел по цели
//! считает не то, что думает. Закон уровня §4, а живёт в одном тесте.

use reflex_core::tls::{
    build_client_hello, record_need, sni, RecordNeed, TlsContentType, TlsFragment, TlsRecord,
    TlsVersion,
};

/// Минимальный ClientHello с именем — тот же, что строит продуктовый [`build_client_hello`].
/// Отдельной копии построителя здесь нет НАРОЧНО: две копии одного формата разошлись бы молча, и
/// тест проверял бы выдумку вместо того, что ездит по проводу.
fn hello(domain: &str) -> Vec<u8> {
    build_client_hello(domain)
}

/// РАЗБОР ТОТАЛЕН: на любых байтах — значение, а не паника. Перебором всех входов до двух байт и
/// всех троек с правдоподобным началом записи, а не подборкой подозрительных.
#[test]
fn разбор_тотален_на_всех_коротких_входах() {
    for first in 0u8..=255 {
        let _ = TlsRecord::parse(&[first]);
        let _ = sni(&[first]);
        let _ = record_need(&[first]);
        for second in 0u8..=255 {
            let bytes = [first, second];
            let _ = TlsRecord::parse(&bytes);
            let _ = sni(&bytes);
            let _ = record_need(&bytes);
        }
    }
    // Вокруг настоящего начала записи (`0x16` handshake) ветвление глубже всего.
    for len_hi in 0u8..=255 {
        for len_lo in 0u8..=255 {
            let bytes = [0x16, 0x03, 0x01, len_hi, len_lo, 0x01];
            let _ = TlsRecord::parse(&bytes);
            let _ = sni(&bytes);
            let _ = record_need(&bytes);
        }
    }
    let _ = TlsRecord::parse(&[]);
    let _ = sni(&[]);
    let _ = record_need(&[]);
}

/// НЕ ВЫДУМЫВАЕТ: на входе, который не может нести ClientHello целиком, имени не рождается.
///
/// Сильнее прежних `too_short` и `empty`: проверяется отсутствие выдумки на ВСЕХ коротких входах
/// разом, а не на двух выбранных. Имя, взятое из ниоткуда, адресовало бы наблюдение чужой цели.
#[test]
fn на_коротком_входе_имя_не_рождается() {
    for first in 0u8..=255 {
        for second in 0u8..=255 {
            let bytes = [first, second];
            assert_eq!(sni(&bytes), None, "два байта {first:#04x} {second:#04x} родили имя");
        }
    }
}

/// ДИАПАЗОН УКАЗЫВАЕТ НА САМИ БАЙТЫ ИМЕНИ, а не «куда-то рядом».
///
/// `span` есть `(смещение, ДЛИНА)`, не `(начало, конец)` — докблок поля говорит это, а тип не
/// говорит: безымянная пара `(usize, usize)` обе половины называет одинаково. Первый читатель (я,
/// 11.09.2026) прочёл вторую как конец и получил `slice index starts at 61 but ends at 13`.
/// Повезло: срез запаниковал. Будь длина больше смещения — вышел бы молча неверный кусок.
///
/// Проверяется срезом: `&hello[off..off + len] == name`. Без этого `span` был бы украшением —
/// число, о котором никто не спросил.
///
/// ЗАМЕР 11.09.2026: `.span` не читается НИГДЕ в дереве, кроме этого теста. Поле не мёртвое, а
/// ждущее: его потребитель — тот, кто правит ClientHello на проводе, а способность переписать
/// пакет (`CanRewrite`) вернулась в боевой носитель только сегодня (`3e7438f`). До неё править
/// запись было нечем, и `span` показывал на байты, которых никто не мог тронуть.
#[test]
fn диапазон_имени_указывает_на_его_байты() {
    for domain in ["rutracker.org", "a.b", "очень-длинное-имя-цели.example.com"] {
        let bytes = hello(domain);
        let found = sni(&bytes).expect("имя найдено");
        assert_eq!(found.name, domain);
        let (offset, length) = found.span;
        assert_eq!(
            &bytes[offset..offset + length],
            domain.as_bytes(),
            "диапазон указывает не на байты имени: {domain}"
        );
    }
}

/// ПРИМАНКА НЕ ОБМАНЫВАЕТ: копия имени в `session_id` не уводит разбор.
///
/// Разбор идёт СТРУКТУРНО — по длинам полей, — а не ищет подстроку. Разница не теоретическая:
/// `session_id` приходит от клиента и содержит что угодно, и байтовый поиск нашёл бы там первое
/// совпадение. Тогда ключ области `Target` (§4) стал бы выдумываемым снаружи.
#[test]
fn приманка_в_session_id_не_уводит_разбор() {
    let real = "rutracker.org";
    let decoy = "example.com";

    // ClientHello, где `session_id` набит именем-приманкой целиком.
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0x00; 32]);
    body.push(decoy.len() as u8);
    body.extend_from_slice(decoy.as_bytes());
    body.extend_from_slice(&[0x00, 0x02, 0x00, 0x2F]);
    body.extend_from_slice(&[0x01, 0x00]);

    let name = real.as_bytes();
    let sni_ext = [
        &((name.len() + 5) as u16).to_be_bytes()[..],
        &((name.len() + 3) as u16).to_be_bytes(),
        &[0x00],
        &(name.len() as u16).to_be_bytes(),
        name,
    ]
    .concat();
    let ext = [&[0x00u8, 0x00][..], &sni_ext].concat();
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let mut handshake = vec![0x01];
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);

    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    let found = sni(&record).expect("настоящее имя найдено");
    assert_eq!(found.name, real, "разбор взял приманку вместо имени");
    let (offset, length) = found.span;
    assert_eq!(
        &record[offset..offset + length],
        real.as_bytes(),
        "диапазон указывает на приманку"
    );
    assert!(
        found.span.0 > 38 + decoy.len(),
        "диапазон лежит раньше конца session_id — значит найден байтовым поиском, а не структурно"
    );
}

/// ЗАПИСЬ РАЗБИРАЕТСЯ В СВОЙ ВИД, И ВИД НЕ ПУТАЕТСЯ. Здесь остаются именно те случаи, что
/// различают ВЕТКИ разбора: у каждой свой исход, и слить их нельзя.
#[test]
fn запись_разбирается_в_свой_вид() {
    let handshake = hello("rutracker.org");
    let parsed = TlsRecord::parse(&handshake).expect("запись разобрана");
    assert_eq!(parsed.content_type, TlsContentType::Handshake);
    assert_eq!(parsed.version, TlsVersion { major: 3, minor: 1 }, "версия записи — байты провода, не наш словарь");
    assert!(matches!(parsed.fragment, TlsFragment::ClientHello { sni: Some(_) }));

    for (byte, expected) in [
        (0x17u8, TlsContentType::ApplicationData),
        (0x15, TlsContentType::Alert),
        (0x14, TlsContentType::ChangeCipherSpec),
    ] {
        let record = [byte, 0x03, 0x01, 0x00, 0x01, 0x00];
        let parsed = TlsRecord::parse(&record).expect("запись разобрана");
        assert_eq!(parsed.content_type, expected, "вид {byte:#04x}");
        assert!(
            !matches!(parsed.fragment, TlsFragment::ClientHello { .. }),
            "не-handshake прочтён как приветствие"
        );
    }

    // ServerHello — тот же вид записи, но ДРУГОЕ рукопожатие: имени в нём нет.
    let server = [0x16u8, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00];
    let parsed = TlsRecord::parse(&server).expect("запись разобрана");
    assert!(!matches!(parsed.fragment, TlsFragment::ClientHello { .. }));
    assert_eq!(sni(&server), None, "у ответа сервера имени цели нет");
}

/// СКОЛЬКО ЕЩЁ ЖДАТЬ — вопрос о ГРАНИЦЕ записи, и ответ на него значение, а не догадка.
#[test]
fn нужда_записи_называет_недостачу() {
    let full = hello("rutracker.org");
    assert!(matches!(record_need(&full), RecordNeed::Complete { .. }));

    let head = &full[..4];
    assert!(
        !matches!(record_need(head), RecordNeed::Complete { .. }),
        "по четырём байтам длина записи ещё не известна"
    );

    let half = &full[..full.len() / 2];
    assert!(
        !matches!(record_need(half), RecordNeed::Complete { .. }),
        "половина записи не есть запись"
    );
}
