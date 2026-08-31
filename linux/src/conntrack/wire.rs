//! РАЗБОР ДАМПА CTNETLINK — чистый, без сокета и без ядра.
//!
//! Отделён от IO намеренно: разбор вложенных TLV — единственное место, где эта дверь может соврать
//! молча, а проверять его только на живом ядре значило бы проверять его только там, где есть root.

/// СКОЛЬКО ПРОШЛО В ОДНУ СТОРОНУ по счёту ЯДРА.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counts {
    pub packets: u64,
    pub bytes: u64,
}

/// ЧЕТВЁРКА РАЗГОВОРА В ТОМ ВИДЕ, В КАКОМ ЕГО ЗАВЕЛИ. Для исходящего соединения `src` — клиент.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Tuple {
    pub src: u32,
    pub dst: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}

/// ОДНА ЗАПИСЬ CONNTRACK.
///
/// `orig`/`reply` — не украшение: счёт ведётся по НАПРАВЛЕНИЯМ разговора, и сложить их значило бы
/// потерять ровно то различение, ради которого запись и читается (цель ответила на SYN и замолчала
/// после приветствия — пакеты вниз есть, байт нет).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Entry {
    pub orig: Tuple,
    pub orig_counts: Counts,
    pub reply_counts: Counts,
    pub mark: u32,
}

pub const NLMSG_DONE: u16 = 3;
pub const NLMSG_ERROR: u16 = 2;

const HDR: usize = 16;
const NFGEN: usize = 4;
const ATTR_HDR: usize = 4;
const NESTED: u16 = 0x8000;

const CTA_TUPLE_ORIG: u16 = 1;
const CTA_MARK: u16 = 8;
const CTA_COUNTERS_ORIG: u16 = 9;
const CTA_COUNTERS_REPLY: u16 = 10;

const CTA_TUPLE_IP: u16 = 1;
const CTA_TUPLE_PROTO: u16 = 2;

const CTA_IP_V4_SRC: u16 = 1;
const CTA_IP_V4_DST: u16 = 2;

const CTA_PROTO_NUM: u16 = 1;
const CTA_PROTO_SRC_PORT: u16 = 2;
const CTA_PROTO_DST_PORT: u16 = 3;

const CTA_COUNTERS_PACKETS: u16 = 1;
const CTA_COUNTERS_BYTES: u16 = 2;

const fn aligned(len: usize) -> usize {
    (len + 3) & !3
}

/// ЧЕМ КОНЧИЛСЯ РАЗБОР ОДНОЙ ПОРЦИИ ДАМПА.
///
/// `Done` — не «пусто», а «ядро сказало, что записей больше нет». Различение обязательно: дамп
/// приходит НЕСКОЛЬКИМИ порциями, и остановка по пустой порции читала бы обрыв как конец.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Chunk {
    More(Vec<Entry>),
    Done(Vec<Entry>),
    Failed(i32),
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    bytes
        .get(at..at + 2)
        .map(|two| u16::from_ne_bytes([two[0], two[1]]))
}

fn be16_at(bytes: &[u8], at: usize) -> Option<u16> {
    bytes
        .get(at..at + 2)
        .map(|two| u16::from_be_bytes([two[0], two[1]]))
}

fn be32_at(bytes: &[u8], at: usize) -> Option<u32> {
    bytes
        .get(at..at + 4)
        .map(|four| u32::from_be_bytes([four[0], four[1], four[2], four[3]]))
}

fn be64_at(bytes: &[u8], at: usize) -> Option<u64> {
    bytes.get(at..at + 8).map(|eight| {
        u64::from_be_bytes([
            eight[0], eight[1], eight[2], eight[3], eight[4], eight[5], eight[6], eight[7],
        ])
    })
}

fn i32_at(bytes: &[u8], at: usize) -> Option<i32> {
    bytes
        .get(at..at + 4)
        .map(|four| i32::from_ne_bytes([four[0], four[1], four[2], four[3]]))
}

/// Обход TLV одного уровня. Длина в заголовке ВКЛЮЧАЕТ его самого; короче заголовка — обрыв, и
/// обход прекращается, а не пропускает байты наугад.
struct Attrs<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Attrs<'a> {
    type Item = (u16, &'a [u8]);

    /// ВЫХОД ОДИН, И ОН ГАСИТ ОСТАТОК. Прежде обрыв уходил через `?`, не тронув `self.rest`, —
    /// итератор возвращал `None`, а на следующем шаге снова `Some` те же байты. Внешне это
    /// незаметно (`fold` останавливается на первом `None`), и потому сверка длины выглядела
    /// дублем `.get`: обезоруживание её сняло, и НИЧЕГО не покраснело. Дублем она не была —
    /// она держала фьюзность. Держит её теперь единственная ветка отказа.
    fn next(&mut self) -> Option<(u16, &'a [u8])> {
        match (u16_at(self.rest, 0), u16_at(self.rest, 2)) {
            (Some(len), Some(kind)) => match self.rest.get(ATTR_HDR..len as usize) {
                Some(body) => {
                    self.rest = self.rest.get(aligned(len as usize)..).unwrap_or(&[]);
                    Some((kind & !NESTED, body))
                }
                None => {
                    self.rest = &[];
                    None
                }
            },
            (Some(_), _) | (None, _) => {
                self.rest = &[];
                None
            }
        }
    }
}

fn attrs(body: &[u8]) -> Attrs<'_> {
    Attrs { rest: body }
}

fn counted(body: &[u8]) -> Counts {
    attrs(body).fold(Counts::default(), |so_far, (kind, value)| match kind {
        CTA_COUNTERS_PACKETS => Counts {
            packets: be64_at(value, 0).unwrap_or(so_far.packets),
            ..so_far
        },
        CTA_COUNTERS_BYTES => Counts {
            bytes: be64_at(value, 0).unwrap_or(so_far.bytes),
            ..so_far
        },
        _unknown_to_us => so_far,
    })
}

fn addressed(body: &[u8], so_far: Tuple) -> Tuple {
    attrs(body).fold(so_far, |built, (kind, value)| match kind {
        CTA_IP_V4_SRC => Tuple {
            src: be32_at(value, 0).unwrap_or(built.src),
            ..built
        },
        CTA_IP_V4_DST => Tuple {
            dst: be32_at(value, 0).unwrap_or(built.dst),
            ..built
        },
        _unknown_to_us => built,
    })
}

fn ported(body: &[u8], so_far: Tuple) -> Tuple {
    attrs(body).fold(so_far, |built, (kind, value)| match kind {
        CTA_PROTO_NUM => Tuple {
            proto: value.first().copied().unwrap_or(built.proto),
            ..built
        },
        CTA_PROTO_SRC_PORT => Tuple {
            src_port: be16_at(value, 0).unwrap_or(built.src_port),
            ..built
        },
        CTA_PROTO_DST_PORT => Tuple {
            dst_port: be16_at(value, 0).unwrap_or(built.dst_port),
            ..built
        },
        _unknown_to_us => built,
    })
}

fn tupled(body: &[u8]) -> Tuple {
    attrs(body).fold(Tuple::default(), |built, (kind, value)| match kind {
        CTA_TUPLE_IP => addressed(value, built),
        CTA_TUPLE_PROTO => ported(value, built),
        _unknown_to_us => built,
    })
}

/// Тело одного сообщения `IPCTNL_MSG_CT_NEW` в запись.
pub fn entry_of(payload: &[u8]) -> Option<Entry> {
    payload.get(NFGEN..).map(|body| {
        attrs(body).fold(Entry::default(), |built, (kind, value)| match kind {
            CTA_TUPLE_ORIG => Entry {
                orig: tupled(value),
                ..built
            },
            CTA_COUNTERS_ORIG => Entry {
                orig_counts: counted(value),
                ..built
            },
            CTA_COUNTERS_REPLY => Entry {
                reply_counts: counted(value),
                ..built
            },
            CTA_MARK => Entry {
                mark: be32_at(value, 0).unwrap_or(built.mark),
                ..built
            },
            _unknown_to_us => built,
        })
    })
}

/// РАЗБОР ПОРЦИИ ДАМПА. Тотален по построению: обрыв на любой границе прекращает обход, а не
/// уводит указатель в мусор.
pub fn chunk_of(buffer: &[u8]) -> Chunk {
    fn walk(rest: &[u8], so_far: Vec<Entry>) -> Chunk {
        match (
            rest.get(0..4)
                .map(|four| u32::from_ne_bytes([four[0], four[1], four[2], four[3]]) as usize),
            u16_at(rest, 4),
        ) {
            (Some(len), Some(kind)) if len >= HDR && len <= rest.len() => match kind {
                NLMSG_DONE => Chunk::Done(so_far),
                NLMSG_ERROR => match i32_at(rest, HDR) {
                    Some(0) => Chunk::Done(so_far),
                    Some(code) => Chunk::Failed(code),
                    None => Chunk::Failed(0),
                },
                _record => match rest.get(HDR..len).and_then(entry_of) {
                    Some(found) => walk(
                        rest.get(aligned(len)..).unwrap_or(&[]),
                        so_far.into_iter().chain(core::iter::once(found)).collect(),
                    ),
                    None => walk(rest.get(aligned(len)..).unwrap_or(&[]), so_far),
                },
            },
            (Some(_), _) | (None, _) => Chunk::More(so_far),
        }
    }
    walk(buffer, Vec::new())
}
