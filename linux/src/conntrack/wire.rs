//! Разбор дампа ctnetlink — чистый, без сокета и без ядра. Отделён от IO намеренно: разбор вложенных
//! TLV — единственное место, где эта дверь может соврать молча, а проверять его только на живом ядре
//! значило бы проверять только там, где есть root.

use crate::netlink::{aligned, attrs, be16_at, be32_at, be64_at, i32_at, u16_at};

/// Сколько прошло в одну сторону по счёту ЯДРА.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counts {
    pub packets: u64,
    pub bytes: u64,
}

/// Четвёрка разговора в том виде, в каком его завели. Для исходящего соединения `src` — клиент.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Tuple {
    pub src: u32,
    pub dst: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}

/// Одна запись conntrack. `orig`/`reply` — не украшение: счёт по НАПРАВЛЕНИЯМ, сложить их значило бы
/// потерять различение, ради которого запись и читается (цель ответила на SYN и замолчала — пакеты
/// вниз есть, байт нет).
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

/// Чем кончился разбор одной порции дампа. `Done` — не «пусто», а «ядро сказало, что записей больше
/// нет»: дамп приходит несколькими порциями, остановка по пустой порции читала бы обрыв как конец.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Chunk {
    More(Vec<Entry>),
    Done(Vec<Entry>),
    Failed(i32),
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

/// Разбор порции дампа. Тотален по построению: обрыв на любой границе прекращает обход, не уводит
/// указатель в мусор.
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
