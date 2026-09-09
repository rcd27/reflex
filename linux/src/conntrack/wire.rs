//! Разбор дампа ctnetlink — чистый, без сокета и без ядра. Отделён от IO намеренно: разбор вложенных
//! TLV — единственное место, где эта дверь может соврать молча, а проверять его только на живом ядре
//! значило бы проверять только там, где есть root.

use std::time::Duration;

use crate::netlink::{
    aligned, attrs, be16_at, be32_at, be64_at, i32_at, u16_at, NLMSG_DONE, NLMSG_ERROR,
};

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

/// TCP-состояние разговора по мнению ЯДРА (из `CTA_PROTOINFO`). Свой автомат TCP не нужен — ядро
/// уже держит этот счёт. `Other` заселяет неназванные коды (NONE, SYN_SENT2, …), а не роняет их.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtTcp {
    SynSent,
    SynRecv,
    Established,
    FinWait,
    CloseWait,
    LastAck,
    TimeWait,
    Close,
    Other(u8),
}

impl CtTcp {
    fn of_state(state: u8) -> CtTcp {
        match state {
            1 => CtTcp::SynSent,
            2 => CtTcp::SynRecv,
            3 => CtTcp::Established,
            4 => CtTcp::FinWait,
            5 => CtTcp::CloseWait,
            6 => CtTcp::LastAck,
            7 => CtTcp::TimeWait,
            8 => CtTcp::Close,
            other => CtTcp::Other(other),
        }
    }
}

/// Концы разговора из кортежа ядра. V4 ключуется; V6 РАЗБИРАЕТСЯ и НЕ ключуется (иначе все IPv6-
/// потоки схлопнулись бы в один ключ по умолчанию — §7: незнание обитаемо, порча молчаливая нет);
/// `Unknown` — семейства в кортеже нет вовсе. Будущей работе по IPv6 остаётся одно место — ковка ключа.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CtEnds {
    V4 {
        src: u32,
        dst: u32,
        src_port: u16,
        dst_port: u16,
        proto: u8,
    },
    V6 {
        src: [u8; 16],
        dst: [u8; 16],
        src_port: u16,
        dst_port: u16,
        proto: u8,
    },
    #[default]
    Unknown,
}

/// Вид края разговора из тела `NFQA_CT` — то, что ядро считает за нас даром (§ спеки ct-края).
/// Отсутствие атрибута — `None`/`Unknown`, не ноль: ядро без `acct` счётчиков не шлёт, и ноль был
/// бы ложью, неотличимой от правды. Начало (`started_at`) кладётся АБСОЛЮТНЫМ, как прислало ядро:
/// возраст считает прибор из `at` своей буквы, разбор часов не дёргает (§8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CtView {
    pub id: u32,
    pub ends: CtEnds,
    pub tuple: Option<Tuple>,
    pub down: Counts,
    pub up: Counts,
    pub started_at: Option<u64>,
    pub expires_in: Option<Duration>,
    pub tcp: Option<CtTcp>,
    pub mark: u32,
}

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

// Сверены с `nfnetlink_conntrack.h` (не по памяти: `NFQA_*` и `CTA_*` путаются, номера рядом).
const CTA_ID: u16 = 12;
const CTA_TIMEOUT: u16 = 7;
const CTA_TIMESTAMP: u16 = 20;
const CTA_TIMESTAMP_START: u16 = 1;
const CTA_PROTOINFO: u16 = 4;
const CTA_PROTOINFO_TCP: u16 = 1;
const CTA_PROTOINFO_TCP_STATE: u16 = 1;
const CTA_IP_V6_SRC: u16 = 3;
const CTA_IP_V6_DST: u16 = 4;

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

/// Части кортежа до решения о семействе: адреса обоих семейств копятся раздельно, выбор — в конце.
/// Ронять V6 на лету значило бы терять разбор ради ключа, который его всё равно не примет.
#[derive(Default)]
struct EndsParts {
    v4_src: Option<u32>,
    v4_dst: Option<u32>,
    v6_src: Option<[u8; 16]>,
    v6_dst: Option<[u8; 16]>,
    src_port: u16,
    dst_port: u16,
    proto: u8,
}

fn v16_at(bytes: &[u8], at: usize) -> Option<[u8; 16]> {
    bytes.get(at..at + 16).map(|slice| {
        let mut out = [0u8; 16];
        out.copy_from_slice(slice);
        out
    })
}

fn addressed(body: &[u8], parts: EndsParts) -> EndsParts {
    attrs(body).fold(parts, |built, (kind, value)| match kind {
        CTA_IP_V4_SRC => EndsParts {
            v4_src: be32_at(value, 0).or(built.v4_src),
            ..built
        },
        CTA_IP_V4_DST => EndsParts {
            v4_dst: be32_at(value, 0).or(built.v4_dst),
            ..built
        },
        CTA_IP_V6_SRC => EndsParts {
            v6_src: v16_at(value, 0).or(built.v6_src),
            ..built
        },
        CTA_IP_V6_DST => EndsParts {
            v6_dst: v16_at(value, 0).or(built.v6_dst),
            ..built
        },
        _unknown_to_us => built,
    })
}

fn ported(body: &[u8], parts: EndsParts) -> EndsParts {
    attrs(body).fold(parts, |built, (kind, value)| match kind {
        CTA_PROTO_NUM => EndsParts {
            proto: value.first().copied().unwrap_or(built.proto),
            ..built
        },
        CTA_PROTO_SRC_PORT => EndsParts {
            src_port: be16_at(value, 0).unwrap_or(built.src_port),
            ..built
        },
        CTA_PROTO_DST_PORT => EndsParts {
            dst_port: be16_at(value, 0).unwrap_or(built.dst_port),
            ..built
        },
        _unknown_to_us => built,
    })
}

/// Концы из тела `CTA_TUPLE_ORIG`. V4 предпочтён (его умеет ковка ключа); иначе V6 (разобран, не
/// ключуется); иначе `Unknown`.
fn ends_of(body: &[u8]) -> CtEnds {
    let parts = attrs(body).fold(EndsParts::default(), |built, (kind, value)| match kind {
        CTA_TUPLE_IP => addressed(value, built),
        CTA_TUPLE_PROTO => ported(value, built),
        _unknown_to_us => built,
    });
    match (parts.v4_src, parts.v4_dst, parts.v6_src, parts.v6_dst) {
        (Some(src), Some(dst), _, _) => CtEnds::V4 {
            src,
            dst,
            src_port: parts.src_port,
            dst_port: parts.dst_port,
            proto: parts.proto,
        },
        (_, _, Some(src), Some(dst)) => CtEnds::V6 {
            src,
            dst,
            src_port: parts.src_port,
            dst_port: parts.dst_port,
            proto: parts.proto,
        },
        _no_family => CtEnds::Unknown,
    }
}

/// Четвёрка для ковки ключа — только из V4: то, что `keyed` умеет (§7).
fn tuple_of(ends: &CtEnds) -> Option<Tuple> {
    match *ends {
        CtEnds::V4 {
            src,
            dst,
            src_port,
            dst_port,
            proto,
        } => Some(Tuple {
            src,
            dst,
            src_port,
            dst_port,
            proto,
        }),
        CtEnds::V6 { .. } | CtEnds::Unknown => None,
    }
}

fn started_at_of(body: &[u8]) -> Option<u64> {
    attrs(body)
        .find(|(kind, _)| *kind == CTA_TIMESTAMP_START)
        .and_then(|(_, value)| be64_at(value, 0))
}

fn tcp_of(body: &[u8]) -> Option<CtTcp> {
    attrs(body)
        .find(|(kind, _)| *kind == CTA_PROTOINFO_TCP)
        .and_then(|(_, tcp)| attrs(tcp).find(|(kind, _)| *kind == CTA_PROTOINFO_TCP_STATE))
        .and_then(|(_, state)| state.first().copied())
        .map(CtTcp::of_state)
}

/// Вид края из тела `NFQA_CT` (только атрибуты `CTA_*`, без `nfgenmsg`). Один чеканщик: тот же
/// `attrs`-обход, что и у записи дампа. Отсутствие атрибута — `None`/`Unknown`, не ноль.
pub fn view_of(body: &[u8]) -> CtView {
    attrs(body).fold(CtView::default(), |built, (kind, value)| match kind {
        CTA_TUPLE_ORIG => {
            let ends = ends_of(value);
            CtView {
                tuple: tuple_of(&ends),
                ends,
                ..built
            }
        }
        CTA_COUNTERS_ORIG => CtView {
            down: counted(value),
            ..built
        },
        CTA_COUNTERS_REPLY => CtView {
            up: counted(value),
            ..built
        },
        CTA_MARK => CtView {
            mark: be32_at(value, 0).unwrap_or(built.mark),
            ..built
        },
        CTA_TIMEOUT => CtView {
            expires_in: be32_at(value, 0).map(|secs| Duration::from_secs(secs as u64)),
            ..built
        },
        CTA_TIMESTAMP => CtView {
            started_at: started_at_of(value),
            ..built
        },
        CTA_PROTOINFO => CtView {
            tcp: tcp_of(value),
            ..built
        },
        CTA_ID => CtView {
            id: be32_at(value, 0).unwrap_or(built.id),
            ..built
        },
        _unknown_to_us => built,
    })
}

/// Тело одного сообщения `IPCTNL_MSG_CT_NEW` в запись. Через [`view_of`]: `Entry` — узкий срез вида
/// (четвёрка V4, счёт, марка), а сам разбор один.
pub fn entry_of(payload: &[u8]) -> Option<Entry> {
    payload.get(NFGEN..).map(view_of).map(|view| Entry {
        orig: view.tuple.unwrap_or_default(),
        orig_counts: view.down,
        reply_counts: view.up,
        mark: view.mark,
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
