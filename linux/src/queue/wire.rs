//! Сборка и разбор сообщений NFNL_SUBSYS_QUEUE — без сокета (IO живёт в `queue/mod`? нет: сокет —
//! Task 4). Здесь чистые байты: конфигурация очереди, вердикт с `NFQA_CT{CTA_MARK}` (чего крейт
//! `nfq` не умеет) и разбор пакета вместе с видом края.
//!
//! Один чеканщик: `NFQA_CT` разбирается `conntrack::view_of`, своего обхода `CTA_*` очередь не
//! отращивает. Тела упакованных структур собираются байтами, не `repr(C)`: выравнивание добавило бы
//! байт, и ядро молча не поняло бы сообщение.

use crate::conntrack::{view_of, CtView};
use crate::netlink::{aligned, attrs, be32_at, i32_at, nested, tlv, u16_at, NLMSG_DONE, NLMSG_ERROR};

// Сверены с `include/uapi/linux/netfilter/nfnetlink_queue.h` (не по памяти).
const NFNL_SUBSYS_QUEUE: u16 = 3;
// NFQNL_MSG_PACKET (0) не назван: пакеты мы не СОБИРАЕМ, а разбор берёт всё, что не DONE/ERROR.
const NFQNL_MSG_VERDICT: u16 = 1;
const NFQNL_MSG_CONFIG: u16 = 2;

const NFQA_PACKET_HDR: u16 = 1;
const NFQA_VERDICT_HDR: u16 = 2;
const NFQA_MARK: u16 = 3; // НЕ 8: 8 — это CTA_MARK из ctnetlink, соседнее пространство имён.
const NFQA_PAYLOAD: u16 = 10;
const NFQA_CT: u16 = 11;

const NFQA_CFG_CMD: u16 = 1;
const NFQA_CFG_PARAMS: u16 = 2;
const NFQA_CFG_MASK: u16 = 4; // НЕ 6.
const NFQA_CFG_FLAGS: u16 = 5;

const NFQNL_CFG_CMD_BIND: u8 = 1;
const NFQNL_COPY_PACKET: u8 = 2;
const NFQA_CFG_F_CONNTRACK: u32 = 0x0002;

const NF_DROP: u32 = 0;
const NF_ACCEPT: u32 = 1;

// CTA_MARK из ctnetlink — то же число, что читает `view_of`; здесь оно нужно ПУТИ ЗАПИСИ (кладём
// марку в NFQA_CT вердикта). Закон одного чеканщика — про РАЗБОР, и разбор один (`view_of`).
const CTA_MARK: u16 = 8;

const NLM_F_REQUEST: u16 = 0x001;

const NLMSG_HDR: usize = 16;
const NFGEN: usize = 4;
const HEADER: usize = NLMSG_HDR + NFGEN;

/// Пакет из очереди: улика (`payload`), метка skb (`nfmark`) и вид края (`ct`, если ядро приложило
/// `NFQA_CT`). Обе половины — из одного сообщения.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub id: u32,
    pub payload: Vec<u8>,
    pub nfmark: u32,
    pub ct: Option<CtView>,
}

/// Что пришло из очереди. `Done`/`Failed` — исходы ядра, отдельные от пакета (по образцу дампа).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Incoming {
    Packet(Packet),
    Done,
    Failed(i32),
}

// --- тела упакованных структур (байтами; длины проверяет тест) ---

/// `nfqnl_msg_config_cmd`: command u8, _pad u8, pf be16 = 4 байта.
pub fn cmd_body(command: u8) -> Vec<u8> {
    let mut body = Vec::with_capacity(4);
    body.push(command);
    body.push(0); // _pad
    body.extend_from_slice(&0u16.to_be_bytes()); // pf = AF_UNSPEC
    body
}

/// `nfqnl_msg_config_params` (УПАКОВАН): copy_range be32, copy_mode u8 = 5 байт.
pub fn params_body(copy_range: u16) -> Vec<u8> {
    let mut body = Vec::with_capacity(5);
    body.extend_from_slice(&(copy_range as u32).to_be_bytes());
    body.push(NFQNL_COPY_PACKET);
    body
}

/// `nfqnl_msg_verdict_hdr`: verdict be32, id be32 = 8 байт.
pub fn verdict_body(verdict: u32, id: u32) -> Vec<u8> {
    let mut body = Vec::with_capacity(8);
    body.extend_from_slice(&verdict.to_be_bytes());
    body.extend_from_slice(&id.to_be_bytes());
    body
}

// --- сборка сообщений ---

/// Заголовок сообщения (`nlmsghdr` 16 + `nfgenmsg` 4) поверх готового тела атрибутов. `res_id`
/// (номер очереди) — big-endian. Длина уже кратна четырём: тело атрибутов выровнено.
fn message(msg: u16, queue: u16, seq: u32, body: &[u8]) -> Vec<u8> {
    let total = HEADER + body.len();
    let kind = (NFNL_SUBSYS_QUEUE << 8) | msg;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(total as u32).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(&NLM_F_REQUEST.to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes()); // pid: автопривязка ядром
    out.push(0); // family = AF_UNSPEC
    out.push(0); // version = NFNETLINK_V0
    out.extend_from_slice(&queue.to_be_bytes()); // res_id
    out.extend_from_slice(body);
    out
}

/// Привязать очередь (`NFQNL_CFG_CMD_BIND`).
pub fn bind_request(queue: u16, seq: u32) -> Vec<u8> {
    message(
        NFQNL_MSG_CONFIG,
        queue,
        seq,
        &tlv(NFQA_CFG_CMD, &cmd_body(NFQNL_CFG_CMD_BIND)),
    )
}

/// Копировать пакет целиком в очередь (`copy_range` байт).
pub fn params_request(queue: u16, seq: u32, copy_range: u16) -> Vec<u8> {
    message(
        NFQNL_MSG_CONFIG,
        queue,
        seq,
        &tlv(NFQA_CFG_PARAMS, &params_body(copy_range)),
    )
}

/// Включить `NFQA_CT`: флаг плюс маска, называющая тот же бит (ядро меняет только биты маски).
pub fn conntrack_flag_request(queue: u16, seq: u32) -> Vec<u8> {
    let flags = tlv(NFQA_CFG_FLAGS, &NFQA_CFG_F_CONNTRACK.to_be_bytes());
    let mask = tlv(NFQA_CFG_MASK, &NFQA_CFG_F_CONNTRACK.to_be_bytes());
    message(NFQNL_MSG_CONFIG, queue, seq, &[flags, mask].concat())
}

/// Вердикт пакету. При `Some(mark)` кладёт `NFQA_CT{CTA_MARK}` — состояние уезжает в ядро вместе с
/// вердиктом; при `None` атрибута `NFQA_CT` нет вовсе (не трогать ≠ записать своё).
pub fn verdict_message(queue: u16, seq: u32, id: u32, accept: bool, ct_mark: Option<u32>) -> Vec<u8> {
    let verdict = if accept { NF_ACCEPT } else { NF_DROP };
    let head = tlv(NFQA_VERDICT_HDR, &verdict_body(verdict, id));
    let body = match ct_mark {
        Some(mark) => [head, nested(NFQA_CT, &tlv(CTA_MARK, &mark.to_be_bytes()))].concat(),
        None => head,
    };
    message(NFQNL_MSG_VERDICT, queue, seq, &body)
}

// --- разбор ---

fn packet_of(message: &[u8]) -> Option<Packet> {
    let body = message.get(HEADER..)?;
    let mut id = None;
    let mut payload = Vec::new();
    let mut nfmark = 0;
    let mut ct = None;
    for (kind, value) in attrs(body) {
        match kind {
            // packet_id — первый be32 упакованного nfqnl_msg_packet_hdr.
            NFQA_PACKET_HDR => id = be32_at(value, 0),
            NFQA_PAYLOAD => payload = value.to_vec(),
            NFQA_MARK => nfmark = be32_at(value, 0).unwrap_or(nfmark),
            // Один чеканщик: тело NFQA_CT разбирает view_of, не свой обход.
            NFQA_CT => ct = Some(view_of(value)),
            _unknown_to_us => {}
        }
    }
    id.map(|id| Packet {
        id,
        payload,
        nfmark,
        ct,
    })
}

/// Разбор буфера ядра: несколько сообщений в одном ответе — обычное дело, не край. Обход прекращает
/// себя на обрыве (длина короче заголовка или длиннее буфера), не уводя указатель в мусор.
pub fn incoming_of(buffer: &[u8]) -> Vec<Incoming> {
    let mut out = Vec::new();
    let mut rest = buffer;
    while let (Some(len), Some(kind)) = (
        rest.get(0..4)
            .map(|four| u32::from_ne_bytes([four[0], four[1], four[2], four[3]]) as usize),
        u16_at(rest, 4),
    ) {
        if len < NLMSG_HDR || len > rest.len() {
            break;
        }
        match kind {
            NLMSG_DONE => {
                out.push(Incoming::Done);
                break;
            }
            NLMSG_ERROR => {
                match i32_at(rest, NLMSG_HDR) {
                    Some(0) => out.push(Incoming::Done),
                    Some(code) => out.push(Incoming::Failed(code)),
                    None => out.push(Incoming::Failed(0)),
                }
                break;
            }
            _packet => {
                if let Some(packet) = rest.get(0..len).and_then(packet_of) {
                    out.push(Incoming::Packet(packet));
                }
                rest = rest.get(aligned(len)..).unwrap_or(&[]);
            }
        }
    }
    out
}
