//! События conntrack: рождение, первый ответ и смерть разговора — из сообщений, которые ядро
//! шлёт подписчику групп NEW/UPDATE/DESTROY. Байты собираются руками: `netlink`-сборка крейт-приватна.

use reflex_linux::conntrack::{events_of, CtDst, CtEvent, CtKind};

const CT_NEW: u16 = 1 << 8;
const CT_DELETE: u16 = (1 << 8) | 2;
const NLM_F_CREATE: u16 = 0x400;
const IPS_SEEN_REPLY: u32 = 1 << 1;
const IPS_DST_NAT: u32 = 1 << 5;

fn tlv(kind: u16, body: &[u8]) -> Vec<u8> {
    let len = (4 + body.len()) as u16;
    let padding = (4 - body.len() % 4) % 4;
    [
        len.to_ne_bytes().as_slice(),
        kind.to_ne_bytes().as_slice(),
        body,
        &vec![0u8; padding],
    ]
    .concat()
}

fn nested(kind: u16, body: &[u8]) -> Vec<u8> {
    tlv(kind | 0x8000, body)
}

/// Разговор 10.77.0.15:40001 → 87.245.220.78:443 со статусом и счётом вниз.
fn body(status: u32, reply_bytes: u64) -> Vec<u8> {
    let ends = [tlv(1, &[10, 77, 0, 15]), tlv(2, &[87, 245, 220, 78])].concat();
    let ports = [
        tlv(1, &[6]),
        tlv(2, &40001u16.to_be_bytes()),
        tlv(3, &443u16.to_be_bytes()),
    ]
    .concat();
    [
        vec![2, 0, 0, 0],
        nested(1, &[nested(1, &ends), nested(2, &ports)].concat()),
        tlv(3, &status.to_be_bytes()),
        nested(10, &tlv(2, &reply_bytes.to_be_bytes())),
    ]
    .concat()
}

fn message(kind: u16, flags: u16, body: &[u8]) -> Vec<u8> {
    let len = (16 + body.len()) as u32;
    let padding = (4 - body.len() % 4) % 4;
    [
        len.to_ne_bytes().as_slice(),
        kind.to_ne_bytes().as_slice(),
        flags.to_ne_bytes().as_slice(),
        &[0u8; 8],
        body,
        &vec![0u8; padding],
    ]
    .concat()
}

fn kinds(events: &[CtEvent]) -> Vec<CtKind> {
    events.iter().map(|event| event.kind).collect()
}

#[test]
fn a_conversation_is_born_answered_and_dies() {
    let buffer = [
        message(CT_NEW, NLM_F_CREATE, &body(0, 0)),
        message(CT_NEW, 0, &body(IPS_SEEN_REPLY, 0)),
        message(CT_DELETE, 0, &body(IPS_SEEN_REPLY, 51_200)),
    ]
    .concat();

    let events = events_of(&buffer);

    assert_eq!(
        kinds(&events),
        vec![CtKind::Born, CtKind::Changed, CtKind::Died]
    );
    assert_eq!(
        events.iter().map(|event| event.replied).collect::<Vec<_>>(),
        vec![false, true, true]
    );
    assert_eq!(events[2].entry.reply_counts.bytes, 51_200);
    assert_eq!(events[2].entry.orig.dst_port, 443);
}

#[test]
fn a_rewritten_destination_is_the_path_as_a_fact() {
    let events = events_of(&message(CT_DELETE, 0, &body(IPS_DST_NAT, 0)));

    assert_eq!(events[0].entry.dst, CtDst::Rewritten);
}

#[test]
fn a_torn_buffer_yields_the_whole_messages_before_the_tear() {
    let whole = message(CT_NEW, NLM_F_CREATE, &body(0, 0));
    let torn = [whole.clone(), whole[..20].to_vec()].concat();

    assert_eq!(kinds(&events_of(&torn)), vec![CtKind::Born]);
}
