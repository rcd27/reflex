//! QUIC-ГОЛОВА — имя цели из зашифрованного `Initial`.
//!
//! # Почему это вообще возможно
//!
//! Пакет `Initial` зашифрован, но ключ выводится из **идентификатора соединения (DCID)**, который
//! лежит в том же пакете открытым текстом (RFC 9001, §5.2). Шифрование здесь не прячет содержимое
//! от наблюдателя — оно защищает от порчи в пути. Читать `Initial` может кто угодно: мы, DPI, и
//! именно так DPI и различает цели по SNI.
//!
//! # Зачем нам
//!
//! Без имени цель по QUIC ключуется сетью `/24`, и знание не переносится между узлами CDN —
//! ровно та болезнь, из-за которой «после ребута день-два кругляш». С именем QUIC-цель попадает в
//! тот же ключ, что и её TCP-двойник, и всё уже накопленное знание работает на неё.
//!
//! # Что здесь НЕ делается
//!
//! Не расшифровывается ничего, кроме `Initial` клиента. Пакеты `1-RTT` защищены ключами, которые
//! выводятся из рукопожатия, и наблюдателю недоступны — это уже настоящее шифрование, а не
//! обфускация. Оттого темп QUIC-потока мы видеть будем, а содержимое — нет.

//! ═══ ПЕРЕЕХАЛО В REFLEX 30.08 — опознание цели с провода живёт в одном месте ═══
//!
//! Прежде опознание было разрезано по границе подмодуля: TLS-сторона в `reflex_core::tls`,
//! QUIC-сторона в краю невода. При этом QUIC-сторона ЗВАЛА TLS-сторону — собрав `CRYPTO`-куски,
//! заворачивала их в TLS-запись и отдавала `extract_sni`. Один предмет, разрезанный по месту
//! написания, а не по смыслу.
//!
//! Здесь всё — ЧИСТЫЕ ФУНКЦИИ: байты на входе, `Option<имя>` на выходе, ни сокета, ни состояния.
//! Оттого место им в субстрате, а не в краю продукта: «узнать цель по проводу» есть general-purpose
//! умение, ровно как разбор TCP или TLS. «Дурение ТСПУ» остаётся у нас (`desync`), опознание — тут.
//!
//! ЗАЧЕМ ЭТО БЫЛО ВАЖНО, А НЕ КОСМЕТИКА: зонд задуман самостоятельной утилитой, и способность
//! узнать цель с провода САМОМУ делает его отдельным продуктом, а не библиотекой невода. Пока
//! половина опознания лежала в краю невода, вынести зонд было нельзя.
//!
//! `ring` подключён ФИЧЕЙ `quic`: по умолчанию его нет, и крейт остаётся лёгким для тех, кому
//! QUIC не нужен. Тот же приём, что у `tls` и `dns`.
//!
//! ЧЕГО ЗДЕСЬ ПО-ПРЕЖНЕМУ НЕТ, названо: только клиентский `Initial` (ни 0-RTT, ни `Retry`); версии
//! TLS 1.2/1.3 не различаются, хотя чужой корпус считает версию осью; ECH не поддержан вовсе — а
//! он и есть то, ради чего SNI перестанет читаться.
//!
//! УСЛОВИЕ ВЫНОСА, названное владельцем: «когда доведём её до ума». Признаки готовности, которые
//! видны сегодня: QUIC-сторона умеет только `Initial` клиента (не 0-RTT, не Retry); TLS-сторона
//! не различает версии 1.2/1.3, хотя чужой корпус считает версию осью; ни одна из сторон не
//! умеет ECH, а он и есть то, ради чего SNI перестанет читаться вовсе.
//!

use ring::aead::{quic as hp, Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use ring::hkdf::{Salt, HKDF_SHA256};

/// СОЛЬ ПЕРВОНАЧАЛЬНЫХ КЛЮЧЕЙ, QUIC v1 (RFC 9001, §5.2). Константа протокола, не наша.
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// Наибольшая длина идентификатора соединения (RFC 9000, §17.2).
const MAX_CID: usize = 20;

/// Имя цели из `Initial`, если оно там названо.
///
/// `None` — не `Initial`, не та версия, не расшифровался, либо SNI в `ClientHello` отсутствует.
/// Все четыре случая законны и неразличимы для вызывающего намеренно: делать с ними ему нечего.
pub fn sni(datagram: &[u8]) -> Option<String> {
    let header = parse_header(datagram)?;
    let keys = initial_keys(header.dcid)?;
    let opened = open(datagram, &header, &keys)?;
    extract_from_handshake(&crypto_frames(&opened))
}

/// Разобранный длинный заголовок — ровно то, что нужно для расшифровки.
pub struct Header<'a> {
    dcid: &'a [u8],
    /// Где начинается защищённый номер пакета.
    pn_offset: usize,
    /// Длина остатка (номер пакета плюс полезная нагрузка), как её объявил отправитель.
    length: usize,
}

/// РАЗБОР ДЛИННОГО ЗАГОЛОВКА. Тотальный: всякая нехватка байтов даёт `None`, а не панику —
/// датаграмма приходит с провода и может быть любой.
fn parse_header(data: &[u8]) -> Option<Header<'_>> {
    let first = *data.first()?;
    // Длинная форма, фиксированный бит, тип `Initial` (00).
    match first & 0xf0 == 0xc0 {
        false => return None,
        true => (),
    }

    let version = u32::from_be_bytes([*data.get(1)?, *data.get(2)?, *data.get(3)?, *data.get(4)?]);
    // Только v1: у черновых версий другая соль, и подставлять её наугад значило бы получать мусор
    // и толковать его как «имени нет».
    match version {
        0x0000_0001 => (),
        _ => return None,
    }

    let dcid_len = *data.get(5)? as usize;
    match dcid_len <= MAX_CID {
        false => return None,
        true => (),
    }
    let dcid = data.get(6..6 + dcid_len)?;

    let scid_at = 6 + dcid_len;
    let scid_len = *data.get(scid_at)? as usize;
    match scid_len <= MAX_CID {
        false => return None,
        true => (),
    }

    let token_at = scid_at + 1 + scid_len;
    let (token_len, token_size) = varint(data, token_at)?;
    let length_at = token_at + token_size + token_len as usize;
    let (length, length_size) = varint(data, length_at)?;

    Some(Header {
        dcid,
        pn_offset: length_at + length_size,
        length: length as usize,
    })
}

/// Переменное целое QUIC (RFC 9000, §16): длина закодирована в двух старших битах.
fn varint(data: &[u8], at: usize) -> Option<(u64, usize)> {
    let first = *data.get(at)?;
    let size = 1usize << (first >> 6);
    let bytes = data.get(at..at + size)?;

    let value = bytes
        .iter()
        .enumerate()
        .fold(0u64, |acc, (n, byte)| match n {
            // У первого байта два старших бита — длина, а не значение.
            0 => u64::from(byte & 0x3f),
            _ => (acc << 8) | u64::from(*byte),
        });

    Some((value, size))
}

/// Ключи первоначального пакета, выведенные из DCID.
struct Keys {
    key: LessSafeKey,
    iv: [u8; 12],
    hp: hp::HeaderProtectionKey,
}

fn initial_keys(dcid: &[u8]) -> Option<Keys> {
    let initial = Salt::new(HKDF_SHA256, &INITIAL_SALT_V1).extract(dcid);
    // Клиентская половина: нас интересует то, что прислал клиент, — в ней `ClientHello`.
    let client = expand_label(&initial, b"client in", 32)?;

    // СЕКРЕТ УЖЕ ЕСТЬ PRK, и повторно извлекать его НЕЛЬЗЯ. Первая редакция делала
    // `extract(&client)` с пустой солью — то есть прогоняла готовый секрет через HKDF ещё раз и
    // получала другие ключи. Расшифровка молча не удавалась, и это читалось как «имени нет»:
    // ошибка крипты неотличима от законного исхода, если не проверить на живом пакете.
    let client_secret = ring::hkdf::Prk::new_less_safe(HKDF_SHA256, &client);
    let key = expand_label(&client_secret, b"quic key", 16)?;
    let iv = expand_label(&client_secret, b"quic iv", 12)?;
    let hp_key = expand_label(&client_secret, b"quic hp", 16)?;

    Some(Keys {
        key: LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &key).ok()?),
        iv: iv.try_into().ok()?,
        hp: hp::HeaderProtectionKey::new(&hp::AES_128, &hp_key).ok()?,
    })
}

/// `HKDF-Expand-Label` из TLS 1.3 (RFC 8446, §7.1) — QUIC пользуется ею как есть.
fn expand_label(secret: &ring::hkdf::Prk, label: &[u8], out: usize) -> Option<Vec<u8>> {
    // Структура: длина вывода (u16), длина метки (u8), «tls13 » + метка, длина контекста (u8).
    let info: Vec<u8> = (out as u16)
        .to_be_bytes()
        .iter()
        .copied()
        .chain(std::iter::once((6 + label.len()) as u8))
        .chain(b"tls13 ".iter().copied())
        .chain(label.iter().copied())
        .chain(std::iter::once(0u8))
        .collect();

    let mut buffer = vec![0u8; out];
    secret
        .expand(&[&info], Len(out))
        .ok()?
        .fill(&mut buffer)
        .ok()?;
    Some(buffer)
}

/// Обёртка длины для `ring::hkdf`: своей у него нет, а тип требуется.
#[derive(Debug, Clone, Copy)]
struct Len(usize);

impl ring::hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// СНЯТЬ ЗАЩИТУ ЗАГОЛОВКА И РАСШИФРОВАТЬ. Возвращает открытый текст полезной нагрузки.
fn open(data: &[u8], header: &Header<'_>, keys: &Keys) -> Option<Vec<u8>> {
    // Образец для маски берётся ЗА четыре байта от начала номера пакета — длина номера ещё
    // неизвестна, и протокол назначает фиксированное смещение именно поэтому (RFC 9001, §5.4.2).
    let sample = data.get(header.pn_offset + 4..header.pn_offset + 20)?;
    let mask = keys.hp.new_mask(sample.try_into().ok()?).ok()?;

    let first = data.first()? ^ (mask[0] & 0x0f);
    let pn_len = (first & 0x03) as usize + 1;

    let pn_bytes: Vec<u8> = data
        .get(header.pn_offset..header.pn_offset + pn_len)?
        .iter()
        .zip(mask.iter().skip(1))
        .map(|(byte, m)| byte ^ m)
        .collect();
    let number = pn_bytes
        .iter()
        .fold(0u64, |acc, b| (acc << 8) | u64::from(*b));

    // Связанные данные — весь заголовок с УЖЕ снятой защитой; шифр проверяет их целиком.
    let aad: Vec<u8> = std::iter::once(first)
        .chain(data.get(1..header.pn_offset)?.iter().copied())
        .chain(pn_bytes.iter().copied())
        .collect();

    let body_at = header.pn_offset + pn_len;
    let body_len = header.length.checked_sub(pn_len)?;
    let mut body = data.get(body_at..body_at + body_len)?.to_vec();

    let nonce: Vec<u8> = keys
        .iv
        .iter()
        .enumerate()
        .map(|(n, byte)| match n + 8 >= keys.iv.len() {
            true => byte ^ (number >> (8 * (keys.iv.len() - 1 - n))) as u8,
            false => *byte,
        })
        .collect();

    keys.key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce.try_into().ok()?),
            Aad::from(&aad),
            &mut body,
        )
        .ok()?;

    let plain = body.len().checked_sub(AES_128_GCM.tag_len())?;
    Some(body[..plain].to_vec())
}

/// СОБРАТЬ `CRYPTO`-ФРЕЙМЫ В ОДИН ПОТОК.
///
/// `ClientHello` разложен по фреймам и НЕ ОБЯЗАН идти по порядку — у каждого свой сдвиг. Клеим по
/// сдвигам: склейка «как пришло» дала бы перемешанный ClientHello, из которого имя не достать.
fn crypto_frames(payload: &[u8]) -> Vec<u8> {
    assemble(pieces(payload, 0, Vec::new()))
}

/// Куски `CRYPTO` из одного расшифрованного пакета, со сдвигами.
fn pieces(payload: &[u8], at: usize, acc: Vec<(u64, Vec<u8>)>) -> Vec<(u64, Vec<u8>)> {
    match payload.get(at) {
        None => acc,
        // PADDING (0x00) и PING (0x01) — по одному байту, пропускаем.
        Some(0x00) | Some(0x01) => pieces(payload, at + 1, acc),
        Some(0x06) => match crypto_at(payload, at) {
            None => acc,
            Some((offset, data, next)) => pieces(
                payload,
                next,
                acc.into_iter()
                    .chain(std::iter::once((offset, data.to_vec())))
                    .collect(),
            ),
        },
        // Любой другой фрейм в `Initial` клиента означает, что дальше читать нечего полезного.
        Some(_) => acc,
    }
}

/// Разбор одного `CRYPTO`-фрейма: тип, сдвиг, длина, данные.
fn crypto_at(payload: &[u8], at: usize) -> Option<(u64, &[u8], usize)> {
    let (offset, offset_size) = varint(payload, at + 1)?;
    let (length, length_size) = varint(payload, at + 1 + offset_size)?;
    let data_at = at + 1 + offset_size + length_size;
    let data = payload.get(data_at..data_at + length as usize)?;
    Some((offset, data, data_at + length as usize))
}

/// Склеить куски по сдвигам. Дыры не заполняются: неполный `ClientHello` лучше склеенного
/// неверно — из первого имя просто не достанется, из второго достанется ЧУЖОЕ.
fn assemble(pieces: Vec<(u64, Vec<u8>)>) -> Vec<u8> {
    let ordered: std::collections::BTreeMap<u64, Vec<u8>> = pieces.into_iter().collect();
    ordered.into_iter().fold(Vec::new(), |acc, (offset, data)| {
        match offset as usize == acc.len() {
            true => acc.into_iter().chain(data).collect(),
            // Кусок не встык — дальше склеивать нельзя.
            false => acc,
        }
    })
}

/// КУСКИ `ClientHello` ИЗ ОДНОЙ ДАТАГРАММЫ — со сдвигами, как они лежат на проводе.
///
/// Отдаются кусками, а не склеенным потоком, потому что `ClientHello` НЕ ОБЯЗАН помещаться в один
/// пакет: Chrome разбивает его на два `Initial`, и во втором первый же фрейм идёт со сдвигом
/// больше нуля. Склеивать надо по всему потоку, а не по датаграмме — иначе половина имени всегда
/// теряется.
pub fn crypto_of(datagram: &[u8]) -> Vec<(u64, Vec<u8>)> {
    match parse_header(datagram).and_then(|header| {
        initial_keys(header.dcid).and_then(|keys| open(datagram, &header, &keys))
    }) {
        None => Vec::new(),
        Some(opened) => pieces(&opened, 0, Vec::new()),
    }
}

/// СКЛЕИТЬ КУСКИ, СОБРАННЫЕ С НЕСКОЛЬКИХ ДАТАГРАММ, и попробовать достать имя.
pub fn sni_of(pieces: &[(u64, Vec<u8>)]) -> Option<String> {
    extract_from_handshake(&assemble(pieces.to_vec()))
}

/// ДОСТАТЬ ИМЯ ИЗ ГОЛОГО РУКОПОЖАТИЯ.
///
/// В TLS поверх TCP `ClientHello` завёрнут в ЗАПИСЬ: пять байт заголовка, потом рукопожатие.
/// В QUIC записи нет вовсе — её роль играют сами `CRYPTO`-фреймы, и в них лежит рукопожатие
/// голым. Готовый разбор (`reflex_core::tls`) ждёт запись и на голом молчит.
///
/// Оборачиваем в заголовок записи, а не пишем второй разбор рукопожатия: своя реализация была бы
/// ВТОРОЙ правдой о том, что такое `ClientHello`, — и разошлась бы с первой на первом же
/// нетипичном поле.
fn extract_from_handshake(handshake: &[u8]) -> Option<String> {
    let length = u16::try_from(handshake.len()).ok()?;
    let record: Vec<u8> = [0x16, 0x03, 0x01]
        .iter()
        .copied()
        .chain(length.to_be_bytes())
        .chain(handshake.iter().copied())
        .collect();

    crate::tls::extract_sni(&record)
}

/// ГДЕ ИМЕННО РВЁТСЯ ЧТЕНИЕ — для отладки, не для решений.
///
/// `sni` возвращает `None` на четырёх разных причинах и не различает их намеренно: вызывающему с
/// ними делать нечего. Но при разработке НЕразличение стоит дорого — ошибка крипты читается как
/// «имени нет», а это совершенно разные факты.
pub fn stages(datagram: &[u8]) -> Result<String, String> {
    let header = parse_header(datagram).ok_or("заголовок не разобран")?;
    let keys = initial_keys(header.dcid).ok_or("ключи не выведены")?;
    let opened = open(datagram, &header, &keys).ok_or("не расшифровалось")?;
    let assembled = crypto_frames(&opened);

    Ok(format!(
        "DCID {} Б · длина {} · расшифровано {} Б · CRYPTO собрано {} Б · SNI {}",
        header.dcid.len(),
        header.length,
        opened.len(),
        assembled.len(),
        match extract_from_handshake(&assembled) {
            Some(name) => name,
            None => "НЕТ".into(),
        }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ПЕРЕМЕННОЕ ЦЕЛОЕ: длина закодирована двумя старшими битами (RFC 9000, §16).
    #[test]
    fn varints_of_every_length() {
        assert_eq!(varint(&[0x25], 0), Some((37, 1)));
        assert_eq!(varint(&[0x7b, 0xbd], 0), Some((15293, 2)));
        // Два старших бита — длина, а не значение: `0x44 0xd0` есть 1232, а не 17616.
        assert_eq!(varint(&[0x44, 0xd0], 0), Some((1232, 2)));
    }

    /// НЕХВАТКА БАЙТОВ — `None`, А НЕ ПАНИКА: датаграмма приходит с провода и бывает любой.
    #[test]
    fn a_truncated_varint_is_refused() {
        assert_eq!(varint(&[0x44], 0), None);
        assert_eq!(varint(&[], 0), None);
    }

    /// ЗАГОЛОВОК РАЗБИРАЕТСЯ ДО НОМЕРА ПАКЕТА.
    ///
    /// Байты с провода (x.com, 28.08): длинный заголовок, версия 1, DCID восемь байт, пустой
    /// SCID, пустой токен, длина 1232.
    #[test]
    fn a_real_initial_header_is_parsed() {
        let head = [
            0xcd, 0x00, 0x00, 0x00, 0x01, 0x08, 0x48, 0xc7, 0x75, 0xcc, 0x74, 0xd1, 0xf8, 0xab,
            0x00, 0x00, 0x44, 0xd0, 0x17,
        ];
        match parse_header(&head) {
            None => panic!("заголовок настоящего Initial не разобран"),
            Some(header) => {
                assert_eq!(header.dcid.len(), 8);
                assert_eq!(header.length, 1232);
                assert_eq!(header.pn_offset, 18);
            }
        }
    }

    /// ЧУЖАЯ ВЕРСИЯ НЕ РАЗБИРАЕТСЯ: у черновых версий другая соль, и подставлять свою наугад
    /// значило бы получать мусор и толковать его как «имени нет».
    ///
    /// БАЙТОВ ДАЁМ ВДОВОЛЬ. Первая редакция обрывала массив на четырнадцатом байте, и разбор
    /// падал на нехватке ДО проверки версии — тест зеленел со снятой проверкой. Найдено
    /// обезоруживанием.
    #[test]
    fn a_foreign_version_is_refused() {
        let draft29 = [
            0xc0, 0xff, 0x00, 0x00, 0x1d, 0x08, 0x48, 0xc7, 0x75, 0xcc, 0x74, 0xd1, 0xf8, 0xab,
            0x00, 0x00, 0x44, 0xd0, 0x17,
        ];
        // Тот же пакет с версией 1 разбирается — значит дело именно в версии.
        let v1 = [
            0xcd, 0x00, 0x00, 0x00, 0x01, 0x08, 0x48, 0xc7, 0x75, 0xcc, 0x74, 0xd1, 0xf8, 0xab,
            0x00, 0x00, 0x44, 0xd0, 0x17,
        ];
        assert!(parse_header(&draft29).is_none(), "чужая версия принята");
        assert!(
            parse_header(&v1).is_some(),
            "контроль: своя версия не разобралась"
        );
    }

    /// КОРОТКИЙ ЗАГОЛОВОК — НЕ `Initial`: это уже защищённые данные, ключей к ним у нас нет.
    #[test]
    fn a_short_header_is_not_an_initial() {
        assert!(parse_header(&[0x40, 0x00, 0x00, 0x00, 0x01]).is_none());
    }

    /// КУСКИ КЛЕЯТСЯ ПО СДВИГАМ, а не в порядке прихода: `ClientHello` разложен по фреймам, и
    /// они не обязаны идти подряд. Сдвиги взяты с живого провода.
    #[test]
    fn pieces_are_glued_by_offset_not_by_arrival() {
        // КУСКИ ВСТЫК, НО В ОБРАТНОМ ПОРЯДКЕ. Первая редакция подавала куски С ДЫРАМИ — тогда
        // результат один и тот же при любой сортировке, и тест зеленел со снятой. Найдено
        // обезоруживанием.
        let backwards = vec![(6u64, b"second".to_vec()), (0u64, b"first-".to_vec())];
        assert_eq!(assemble(backwards), b"first-second".to_vec());
    }

    /// ДЫРА ОСТАНАВЛИВАЕТ СКЛЕЙКУ.
    ///
    /// Неполный `ClientHello` лучше склеенного неверно: из первого имя просто не достанется, из
    /// второго достанется ЧУЖОЕ — то есть цель будет опознана как другая.
    #[test]
    fn a_gap_stops_the_assembly() {
        let with_hole = vec![(0u64, b"aaa".to_vec()), (10u64, b"bbb".to_vec())];
        assert_eq!(assemble(with_hole), b"aaa".to_vec());
    }

    /// ГОЛОЕ РУКОПОЖАТИЕ ОБОРАЧИВАЕТСЯ В ЗАПИСЬ.
    ///
    /// В TLS поверх TCP `ClientHello` завёрнут в запись, в QUIC — нет. Готовый разбор ждёт
    /// запись и на голом молчит; пишем обёртку, а не второй разбор рукопожатия.
    #[test]
    fn a_bare_handshake_gets_a_record_wrapper() {
        // Пустое рукопожатие имени не даёт, но и не паникует — проверяется тотальность.
        assert_eq!(extract_from_handshake(&[]), None);
    }
}
