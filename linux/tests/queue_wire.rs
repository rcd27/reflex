//! Сообщения очереди: сборка (конфигурация, вердикт) и разбор (пакет + вид края) без сокета. Байты
//! собираются и читаются здесь руками — `netlink`-сборка крейт-приватна, а тест обязан кормить
//! разбор ровно тем, что кладёт ядро, и читать ровно то, что уходит ядру.

use reflex_linux::queue::{
    cmd_body, conntrack_flag_request, incoming_of, params_body, verdict_body, verdict_message,
    Incoming,
};

// --- ручной разбор/сборка атрибутов (зеркало формата netlink, но независимое от крейта) ---

fn walk_attrs(body: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::new();
    let mut rest = body;
    while rest.len() >= 4 {
        let len = u16::from_ne_bytes([rest[0], rest[1]]) as usize;
        let kind = u16::from_ne_bytes([rest[2], rest[3]]) & !0x8000;
        if len < 4 || len > rest.len() {
            break;
        }
        out.push((kind, rest[4..len].to_vec()));
        let advance = ((len + 3) & !3).min(rest.len());
        rest = &rest[advance..];
    }
    out
}

/// Атрибуты сообщения лежат после nlmsghdr(16) + nfgenmsg(4).
fn attrs_of(message: &[u8]) -> Vec<(u16, Vec<u8>)> {
    walk_attrs(&message[20..])
}

/// СЫРЫЕ типы атрибутов — без снятия бита вложенности: ровно то, что уходит ядру. `walk_attrs`
/// маскирует бит для чтения СМЫСЛА; здесь нужен сам бит, потому что формат — и есть обещание ядру.
fn raw_types(message: &[u8]) -> Vec<u16> {
    let mut out = Vec::new();
    let mut rest = &message[20..];
    while rest.len() >= 4 {
        let len = u16::from_ne_bytes([rest[0], rest[1]]) as usize;
        let raw = u16::from_ne_bytes([rest[2], rest[3]]);
        if len < 4 || len > rest.len() {
            break;
        }
        out.push(raw);
        let advance = ((len + 3) & !3).min(rest.len());
        rest = &rest[advance..];
    }
    out
}

fn be32(value: &[u8]) -> Option<u32> {
    value
        .get(0..4)
        .map(|four| u32::from_be_bytes([four[0], four[1], four[2], four[3]]))
}

fn contains_be32_attr(message: &[u8], kind: u16, value: u32) -> bool {
    attrs_of(message)
        .iter()
        .any(|(k, v)| *k == kind && be32(v) == Some(value))
}

fn nested_attr(message: &[u8], kind: u16) -> Option<Vec<u8>> {
    attrs_of(message)
        .into_iter()
        .find(|(k, _)| *k == kind)
        .map(|(_, v)| v)
}

fn be32_attr(body: &[u8], kind: u16) -> Option<u32> {
    walk_attrs(body)
        .into_iter()
        .find(|(k, _)| *k == kind)
        .and_then(|(_, v)| be32(&v))
}

fn tlv(kind: u16, body: &[u8]) -> Vec<u8> {
    let len = (4 + body.len()) as u16;
    let mut out = Vec::new();
    out.extend_from_slice(&len.to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(body);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

fn nested(kind: u16, body: &[u8]) -> Vec<u8> {
    tlv(kind | 0x8000, body)
}

/// Сообщение NFQNL_MSG_PACKET, как его кладёт ядро: заголовок + NFQA_PACKET_HDR(1) + NFQA_PAYLOAD(10)
/// + NFQA_CT(11){CTA_MARK(8)}.
fn packet_message(id: u32, payload: &[u8], ct_mark: u32) -> Vec<u8> {
    let mut packet_hdr = Vec::new();
    packet_hdr.extend_from_slice(&id.to_be_bytes()); // packet_id be32
    packet_hdr.extend_from_slice(&0u16.to_be_bytes()); // hw_protocol be16
    packet_hdr.push(0); // hook u8 => 7 байт, упаковано
    let ct = nested(11, &tlv(8, &ct_mark.to_be_bytes()));
    let attrs = [tlv(1, &packet_hdr), tlv(10, payload), ct].concat();

    let total = 16 + 4 + attrs.len();
    let kind = (3u16 << 8) | 0; // NFNL_SUBSYS_QUEUE=3, NFQNL_MSG_PACKET=0
    let mut message = Vec::new();
    message.extend_from_slice(&(total as u32).to_ne_bytes());
    message.extend_from_slice(&kind.to_ne_bytes());
    message.extend_from_slice(&0u16.to_ne_bytes()); // flags
    message.extend_from_slice(&0u32.to_ne_bytes()); // seq
    message.extend_from_slice(&0u32.to_ne_bytes()); // pid
    message.push(0); // family AF_UNSPEC
    message.push(0); // version NFNETLINK_V0
    message.extend_from_slice(&0u16.to_be_bytes()); // res_id (номер очереди)
    message.extend_from_slice(&attrs);
    message
}

// --- законы ---

/// Длины тел — то, что ядро не прощает: две структуры упакованы, и лишний байт выравнивания делает
/// сообщение непонятным молча.
#[test]
fn message_bodies_have_the_sizes_the_kernel_expects() {
    assert_eq!(
        params_body(0xFFFF).len(),
        5,
        "copy_range be32 + copy_mode u8, БЕЗ выравнивания"
    );
    assert_eq!(cmd_body(1).len(), 4, "command u8 + _pad u8 + pf be16");
    assert_eq!(verdict_body(1, 42).len(), 8, "verdict be32 + id be32");
}

/// Флаг conntrack — то, чем включается NFQA_CT. Без него ядро вида края не приложит, и все приборы
/// на ядерных величинах молча увидят пустоту.
#[test]
fn conntrack_flag_request_sets_flag_and_mask() {
    let built = conntrack_flag_request(200, 1);
    // NFQA_CFG_FLAGS = 5, NFQA_CFG_MASK = 4, NFQA_CFG_F_CONNTRACK = 0x0002, оба be32.
    assert!(contains_be32_attr(&built, 5, 0x0002), "флаг выставлен");
    assert!(contains_be32_attr(&built, 4, 0x0002), "маска называет тот же бит");
}

/// Состояние уезжает вложенным NFQA_CT{CTA_MARK} — именно этого не умеет крейт nfq.
#[test]
fn verdict_carries_conntrack_mark() {
    let built = verdict_message(200, 7, 42, true, Some(0x0000_1234));
    // NFQA_CT = 11 (вложенный), внутри CTA_MARK = 8, be32.
    let ct = nested_attr(&built, 11).expect("NFQA_CT в вердикте");
    assert_eq!(be32_attr(&ct, 8), Some(0x0000_1234));
    // Формат — обещание ядру: NFQA_CT обязан нести бит вложенности (сырой тип 0x800b, не 0x000b),
    // иначе плоский атрибут ядро может отвергнуть молча. `nested_attr` этого не поймал бы: он снимает
    // бит на чтении смысла.
    assert!(
        raw_types(&built).contains(&(11 | 0x8000)),
        "NFQA_CT уходит ядру без бита вложенности"
    );
}

/// Вердикт без смены состояния не несёт NFQA_CT вовсе: не трогать — не то же, что записать своё.
#[test]
fn verdict_without_state_carries_no_conntrack_attribute() {
    let built = verdict_message(200, 7, 42, true, None);
    assert!(nested_attr(&built, 11).is_none());
}

/// Пакет разбирается вместе с видом края: обе половины из одного сообщения.
#[test]
fn packet_carries_payload_and_view() {
    let message = packet_message(9, &[0x45, 0x00], 0xABC);
    match incoming_of(&message).as_slice() {
        [Incoming::Packet(packet)] => {
            assert_eq!(packet.id, 9);
            assert_eq!(packet.payload, vec![0x45, 0x00]);
            assert_eq!(packet.ct.as_ref().map(|view| view.mark), Some(0xABC));
        }
        other => panic!("ожидался один пакет, пришло {other:?}"),
    }
}

/// Несколько сообщений в одном буфере — обычный ответ ядра, а не край: считать их по одному значило
/// бы терять пакеты пачками.
#[test]
fn several_messages_in_one_buffer_are_all_read() {
    let buffer = [packet_message(1, &[1], 0), packet_message(2, &[2], 0)].concat();
    assert_eq!(incoming_of(&buffer).len(), 2);
}
