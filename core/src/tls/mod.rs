//! ═══ ОПОЗНАНИЕ ЦЕЛИ С ПРОВОДА — здесь и в `crate::quic` (30.08) ═══
//!
//! ```text
//! TLS    crate::tls    sni · extract_sni · rewrite_sni · RecordAssembler
//! QUIC   crate::quic   Initial (ключ из DCID) · склейка CRYPTO · sni_of   [фича `quic`]
//! ```
//!
//! До 30.08 QUIC-половина жила в краю невода и через границу подмодуля ЗВАЛА эту: собрав
//! `CRYPTO`-куски, заворачивала их в TLS-запись и отдавала `extract_sni`. Один предмет,
//! разрезанный по месту написания, а не по смыслу. Теперь обе стороны здесь.
//!
//! ПОЧЕМУ В СУБСТРАТЕ, А НЕ В ПРОДУКТЕ: всё это чистые функции «байты → `Option<имя>`», и «узнать
//! цель по проводу» есть general-purpose умение, ровно как разбор TCP. «Дурение ТСПУ» остаётся у
//! потребителя (`desync`), опознание — тут. Практическое следствие: зонд, задуманный
//! самостоятельной утилитой, теперь может узнавать цель сам, не завися от края невода.
//!
//! ЧЕГО НЕТ, названо: версии TLS 1.2/1.3 не различаются (чужой корпус считает версию осью); ECH
//! не поддержан вовсе — а он и есть то, ради чего SNI перестанет читаться.
//!
mod assembly;
mod hello;

pub use assembly::{Assembly, RecordAssembler, RecordChunk};
pub use hello::{build_client_hello, rewrite_sni};

/// True if the TCP payload starts with a TLS 1.x ClientHello record.
/// Cheap signature check: TLS record type 0x16 (Handshake) + handshake type 0x01 (ClientHello).
pub fn is_client_hello(payload: &[u8]) -> bool {
    payload.len() >= 6 && payload[0] == 0x16 && payload[5] == 0x01
}

/// True if the TCP payload starts with any TLS record type the server emits
/// during/after a successful handshake (ChangeCipherSpec, Alert, Handshake, ApplicationData).
pub fn is_server_response(payload: &[u8]) -> bool {
    payload.len() >= 5 && matches!(payload[0], 0x14..=0x17)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsContentType {
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
    Other(u8),
}

impl TlsContentType {
    fn from_u8(v: u8) -> Self {
        match v {
            20 => TlsContentType::ChangeCipherSpec,
            21 => TlsContentType::Alert,
            22 => TlsContentType::Handshake,
            23 => TlsContentType::ApplicationData,
            other => TlsContentType::Other(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsVersion {
    pub major: u8,
    pub minor: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsFragment {
    ClientHello {
        sni: Option<String>,
    },
    ServerHello,
    /// ТРЕВОГА С ЕЁ КОДОМ. Код обязателен, а не желателен: `unknown_ca` (48) и `handshake_failure`
    /// (40) есть РАЗНЫЕ беды с разным лечением — первая говорит «я не доверяю этому сертификату»
    /// (подмена личности, свой корень, MITM), вторая «мы не договорились о параметрах».
    ///
    /// Без кода прибор сообщал бы «клиент чем-то недоволен», то есть ответ, не сужающий круг.
    Alert {
        level: u8,
        description: u8,
    },
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsRecord {
    pub content_type: TlsContentType,
    pub version: TlsVersion,
    pub fragment: TlsFragment,
}

/// Server Name Indication из TLS ClientHello: имя хоста И его байтовый диапазон в payload,
/// НЕРАЗДЕЛИМО. `span` — `(offset, len)`, offset абсолютный в payload. Связка убирает
/// нелегальное состояние «имя есть, позиции нет»: SNI либо целиком (имя+диапазон), либо нет.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sni {
    pub name: String,
    pub span: (usize, usize),
}

/// SNI из ClientHello структурным проходом: `None` если это не ClientHello ИЛИ SNI нет
/// (SNI — опциональное TLS-расширение). Диапазон указывает на РЕАЛЬНЫЙ hostname, не на
/// первое байтовое совпадение (копия-decoy в session_id/другом расширении не обманет).
pub fn sni(hello: &[u8]) -> Option<Sni> {
    // Record: type(0x16) + version(2) + length(2) = 5; handshake type 0x01.
    if hello.len() < 6 || hello[0] != 0x16 || hello[5] != 0x01 {
        return None;
    }
    // Handshake body от offset 5: type(1)+length(3)+version(2)+random(32) = 38 → session_id.
    let mut pos = 5 + 38;
    if pos >= hello.len() {
        return None;
    }
    pos += 1 + hello[pos] as usize; // session_id

    if pos + 2 > hello.len() {
        return None;
    }
    pos += 2 + u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize; // cipher_suites

    if pos >= hello.len() {
        return None;
    }
    pos += 1 + hello[pos] as usize; // compression_methods

    if pos + 2 > hello.len() {
        return None;
    }
    let ext_total = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total).min(hello.len());

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([hello[pos], hello[pos + 1]]);
        let ext_len = u16::from_be_bytes([hello[pos + 2], hello[pos + 3]]) as usize;
        pos += 4;
        // SNI extension body: list_len(2) + name_type(1) + name_len(2) + hostname.
        if ext_type == 0x0000 && ext_len >= 5 && pos + ext_len <= hello.len() {
            let name_type = hello[pos + 2];
            let name_len = u16::from_be_bytes([hello[pos + 3], hello[pos + 4]]) as usize;
            if name_type == 0 && 5 + name_len <= ext_len {
                let start = pos + 5;
                let name = String::from_utf8(hello[start..start + name_len].to_vec()).ok()?;
                return Some(Sni {
                    name,
                    span: (start, name_len),
                });
            }
        }
        pos += ext_len;
    }
    None
}

/// ПРЕДЛОЖЕН ЛИ КЛИЕНТОМ ECH (#317) — и, значит, может ли читаемое имя быть НЕ ТЕМ.
///
/// # Почему тип, а не `bool`
///
/// Номер расширения меняется от черновика к черновику (`0xfe0d` — draft-13 и позже, `0xfe0e` и
/// `0xfe0f` — раньше), и знать, КАКОЙ именно предложен, полезно: доля черновиков в поле есть
/// прибор зрелости самого ECH. `bool` это выбросил бы, а вернуть потом было бы уже неоткуда —
/// ряд наблюдений копится с сегодняшнего дня.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ech {
    /// Расширения нет: имя в открытом hello есть имя цели.
    Absent,
    /// Расширение предложено. **Имя, прочитанное рядом, МОЖЕТ БЫТЬ внешним** (`public_name`
    /// провайдера), а настоящее — в зашифрованном `ClientHelloInner`.
    ///
    /// Отличить это от `GREASE ECH` (фиктивное расширение при настоящем имени) снаружи НЕЛЬЗЯ —
    /// в этом смысл GREASE. Потому вариант говорит «может быть внешним», а не «ложно».
    Offered { draft: u16 },
}

/// Черновики ECH, встречающиеся в поле. Список закрытый: расширение с другим номером — не ECH,
/// и записывать его сюда «на всякий случай» значило бы завысить долю, ничего об этом не сказав.
const ECH_DRAFTS: [u16; 3] = [0xfe0d, 0xfe0e, 0xfe0f];

/// Признак ECH тем же структурным проходом, что и `sni`.
///
/// ЗАВЕДЁН ДО ТОГО, КАК ПОНАДОБИЛСЯ, и это осознанно: ECH — то, ради чего SNI перестанет читаться,
/// а узнаем мы об этом иначе только постфактум, по тому, что продукт перестал лечить цели. Признак
/// стоит одного прохода по уже разбираемым расширениям и даёт РЯД: доля соединений с ECH во
/// времени. К моменту, когда доля станет заметной, у нас будет история, а не нулевая отметка.
pub fn ech(hello: &[u8]) -> Ech {
    if hello.len() < 6 || hello[0] != 0x16 || hello[5] != 0x01 {
        return Ech::Absent;
    }
    let mut pos = 5 + 38;
    if pos >= hello.len() {
        return Ech::Absent;
    }
    pos += 1 + hello[pos] as usize; // session_id

    if pos + 2 > hello.len() {
        return Ech::Absent;
    }
    pos += 2 + u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize; // cipher_suites

    if pos >= hello.len() {
        return Ech::Absent;
    }
    pos += 1 + hello[pos] as usize; // compression_methods

    if pos + 2 > hello.len() {
        return Ech::Absent;
    }
    let ext_total = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total).min(hello.len());

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([hello[pos], hello[pos + 1]]);
        let ext_len = u16::from_be_bytes([hello[pos + 2], hello[pos + 3]]) as usize;
        pos += 4;
        if ECH_DRAFTS.contains(&ext_type) {
            return Ech::Offered { draft: ext_type };
        }
        pos += ext_len;
    }
    Ech::Absent
}

/// SNI hostname как строка (без диапазона). Тонкая обёртка над `sni` — единый источник парса.
pub fn extract_sni(data: &[u8]) -> Option<String> {
    sni(data).map(|s| s.name)
}

impl TlsRecord {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 5 {
            return None;
        }

        let content_type = TlsContentType::from_u8(data[0]);
        let version = TlsVersion {
            major: data[1],
            minor: data[2],
        };
        let length = u16::from_be_bytes([data[3], data[4]]) as usize;

        if data.len() < 5 + length {
            return None;
        }

        let body = &data[5..5 + length];

        let fragment = match content_type {
            TlsContentType::Handshake => Self::parse_handshake(body),
            // ТЕЛО ТРЕВОГИ — РОВНО ДВА БАЙТА: уровень и описание (RFC 8446 §6). Короче — запись
            // битая, и притворяться, что мы её поняли, вреднее молчания.
            TlsContentType::Alert if body.len() >= 2 => TlsFragment::Alert {
                level: body[0],
                description: body[1],
            },
            TlsContentType::Alert
            | TlsContentType::ChangeCipherSpec
            | TlsContentType::ApplicationData
            | TlsContentType::Other(_) => TlsFragment::Other,
        };

        Some(TlsRecord {
            content_type,
            version,
            fragment,
        })
    }

    fn parse_handshake(data: &[u8]) -> TlsFragment {
        if data.is_empty() {
            return TlsFragment::Other;
        }

        match data[0] {
            1 => Self::parse_client_hello(data),
            2 => TlsFragment::ServerHello,
            _ => TlsFragment::Other,
        }
    }

    pub(crate) fn parse_client_hello(data: &[u8]) -> TlsFragment {
        // handshake_type(1) + length(3) + client_version(2) + random(32) = 38 min
        if data.len() < 38 {
            return TlsFragment::ClientHello { sni: None };
        }

        let mut pos = 38;

        // session_id
        if pos >= data.len() {
            return TlsFragment::ClientHello { sni: None };
        }
        let session_id_len = data[pos] as usize;
        pos += 1 + session_id_len;

        // cipher_suites
        if pos + 2 > data.len() {
            return TlsFragment::ClientHello { sni: None };
        }
        let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2 + cipher_suites_len;

        // compression_methods
        if pos >= data.len() {
            return TlsFragment::ClientHello { sni: None };
        }
        let comp_methods_len = data[pos] as usize;
        pos += 1 + comp_methods_len;

        // extensions
        if pos + 2 > data.len() {
            return TlsFragment::ClientHello { sni: None };
        }
        let extensions_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        let extensions_end = (pos + extensions_len).min(data.len());
        let sni = Self::find_sni(&data[pos..extensions_end]);

        TlsFragment::ClientHello { sni }
    }

    fn find_sni(extensions: &[u8]) -> Option<String> {
        let mut pos = 0;
        while pos + 4 <= extensions.len() {
            let ext_type = u16::from_be_bytes([extensions[pos], extensions[pos + 1]]);
            let ext_len = u16::from_be_bytes([extensions[pos + 2], extensions[pos + 3]]) as usize;
            pos += 4;

            if ext_type == 0x0000 && ext_len >= 5 && pos + ext_len <= extensions.len() {
                let sni_data = &extensions[pos..pos + ext_len];
                if sni_data.len() >= 5 {
                    let name_type = sni_data[2];
                    let name_len = u16::from_be_bytes([sni_data[3], sni_data[4]]) as usize;
                    if name_type == 0 && 5 + name_len <= sni_data.len() {
                        return String::from_utf8(sni_data[5..5 + name_len].to_vec()).ok();
                    }
                }
            }

            pos += ext_len;
        }
        None
    }
}

/// Чего не хватает читателю, чтобы увидеть ПЕРВУЮ TLS-запись целиком.
///
/// Заведено по #3: `extract_sni` отвечает `None` и на «это не TLS», и на «TLS не дочитан», а
/// читателю нужно решить прямо противоположное — ЖДАТЬ или ИДТИ. Слитый ответ стоил полю 815
/// флоу из 1500 с `serve None`: в плечи уезжал обрезок, сервер ждал остаток записи и молчал, обе
/// ноги при этом стояли `connected=true`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordNeed {
    /// Первая запись видна целиком — ждать нечего.
    Complete,
    /// Записи не хватает; сколько именно — известно ТОЧНО, когда прочитан заголовок (5 байт), и
    /// СНИЗУ, пока он не прочитан.
    More { at_least: usize },
    /// Это не TLS-рукопожатие. Ждать продолжения НЕЛЬЗЯ: его не будет, а ожидание стало бы
    /// задержкой на каждом не-TLS соединении.
    NotTls,
}

/// Сколько ещё нужно байт, чтобы первая TLS-запись стала полной.
///
/// Судит ТОЛЬКО по объявленной длине — той же, по которой `TlsRecord::parse` отдаёт `None`.
/// Отдельная функция, а не флаг у парсера, потому что вопросы разные: парсер отвечает «что это»,
/// эта — «доколе читать».
pub fn record_need(data: &[u8]) -> RecordNeed {
    match data.first() {
        // Пусто — заголовок целиком впереди; больше сказать нечего.
        None => RecordNeed::More { at_least: 5 },
        // Handshake. Только он может нести ClientHello, и только его стоит дочитывать.
        Some(0x16) => match data.len() < 5 {
            true => RecordNeed::More {
                at_least: 5 - data.len(),
            },
            false => {
                let declared = u16::from_be_bytes([data[3], data[4]]) as usize;
                let whole = 5 + declared;
                match data.len() < whole {
                    true => RecordNeed::More {
                        at_least: whole - data.len(),
                    },
                    false => RecordNeed::Complete,
                }
            }
        },
        Some(_) => RecordNeed::NotTls,
    }
}
