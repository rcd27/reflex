//! ДАТАГРАММЫ, ЧЬЮ СТОРОНУ НАЗВАЛА ОЧЕРЕДЬ, — прогоном через настоящую цепочку на бумаге.
//!
//! Звонок Telegram идёт к рефлекторам на любой порт (596–599, 1400, …), и правило сторон по порту
//! сервера его не разводит: датаграмма к `:1400` и к `:596` — один и тот же случай. Разводит ОЧЕРЕДЬ:
//! правило ядра кладёт в неё только путь человека к рефлектору. Замер (#355): один порт телефона
//! (`54209`) говорит сразу с `.68:1400` и `.88:596` — оба разговора обязаны дойти до прибора
//! каждый со своей четвёркой.

use std::net::SocketAddr;

use reflex::scenario::{log, taken, Log, Paper, PaperEdge};
use reflex::*;

const PHONE: [u8; 4] = [192, 168, 1, 100];
const PHONE_PORT: u16 = 54209;

/// Четвёрка разговора, как её видит прибор: концы и протокол ПЕЧАТЬЮ. Протокол печатью, потому что
/// тип его фасад не отдаёт, а сверять надо ровно то, что увидит потребитель.
type Ends = (SocketAddr, SocketAddr, String);

/// Что дошло до прибора. Четвёрка и груз — у датаграммы, причина — у непрочитанного кадра.
#[derive(Debug, Clone, PartialEq)]
enum Heard {
    Datagram(Ends, Vec<u8>),
    Opaque(String),
}

/// Прибор-свидетель: пишет каждую дошедшую букву. Встаёт публичной дверью `own(…)`, как встанет
/// прибор потребителя, — своей двери для теста не заводим.
#[derive(Clone, Copy)]
struct Witness {
    heard: Log<Heard>,
}

impl Mealy for Witness {
    type In = DetectorEvent<(DatagramWire, Option<PaperEdge>)>;
    type Out = SmallVec<[Distress; 2]>;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        let heard = match event {
            DetectorEvent::Packet {
                input: (wire, _edge),
                ..
            } => Some(Heard::Datagram(
                (wire.flow.src, wire.flow.dst, wire.flow.protocol.to_string()),
                wire.payload.to_vec(),
            )),
            DetectorEvent::Opaque { why, .. } => Some(Heard::Opaque(format!("{why:?}"))),
            DetectorEvent::Tick { .. } | DetectorEvent::Torn { .. } => None,
        };
        heard
            .into_iter()
            .for_each(|heard| self.heard.lock().expect("журнал не отравлен").push(heard));
        (self, SmallVec::new(), ())
    }
}

/// Кадр IPv4 с датаграммой от телефона — ровно то, что кладёт в руки очередь ядра.
fn call(dst: [u8; 4], dst_port: u16, body: &[u8]) -> Vec<u8> {
    let udp = (8 + body.len()) as u16;
    [
        &[0x45u8, 0x00][..],
        &(20 + udp).to_be_bytes(),
        &[0x00, 0x01, 0x40, 0x00, 0x40, 17, 0x00, 0x00],
        &PHONE,
        &dst,
        &PHONE_PORT.to_be_bytes(),
        &dst_port.to_be_bytes(),
        &udp.to_be_bytes(),
        &[0x00, 0x00],
        body,
    ]
    .concat()
}

/// TCP-кадр от того же телефона: в очередь звонка он попасть не должен, но попал — и обязан быть
/// чужим, а не прочитанным и не потерянным.
fn tcp(dst: [u8; 4], dst_port: u16) -> Vec<u8> {
    [
        &[0x45u8, 0x00, 0x00, 40][..],
        &[0x00, 0x01, 0x40, 0x00, 0x40, 6, 0x00, 0x00],
        &PHONE,
        &dst,
        &PHONE_PORT.to_be_bytes(),
        &dst_port.to_be_bytes(),
        &[0, 0, 0, 1, 0, 0, 0, 0],
        &[0x50, 0x18, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00],
    ]
    .concat()
}

/// Четвёрка, которую обязан увидеть прибор: телефон — клиент, рефлектор — сервер, протокол UDP.
fn flow(dst: [u8; 4], dst_port: u16) -> Ends {
    (
        SocketAddr::from((PHONE, PHONE_PORT)),
        SocketAddr::from((dst, dst_port)),
        "UDP".to_string(),
    )
}

/// Прогнать бумагу через цепочку датаграмм и отдать всё, что услышал прибор.
fn heard(paper: Paper) -> Vec<Heard> {
    let journal = log::<Heard>();
    engine(paper.then_stop())
        .from(Datagrams)
        .extract(Sni)
        .detect(own(Witness { heard: journal }))
        .on(|_target, _distress: Distress| {})
        .run();
    taken(journal)
}

/// (а) Один порт телефона — к двум рефлекторам на разных портах: оба разговора видны одним
/// прибором, каждый своей четвёркой и своим грузом.
#[test]
fn datagrams_to_reflectors_on_any_port_are_seen_with_their_own_flows() {
    let heard = heard(
        Paper::new()
            .then_packet(call([91, 108, 9, 68], 1400, b"to .68"))
            .then_packet(call([91, 108, 9, 88], 596, b"to .88")),
    );
    assert_eq!(
        heard,
        vec![
            Heard::Datagram(flow([91, 108, 9, 68], 1400), b"to .68".to_vec()),
            Heard::Datagram(flow([91, 108, 9, 88], 596), b"to .88".to_vec()),
        ]
    );
}

/// (б) TCP-кадр в той же очереди — чужой: ни буквы наблюдения, ни слепоты. Звонок начат ДО него,
/// иначе слепоту было бы некому услышать и «чужой» не отличился бы от «потерянного».
#[test]
fn a_tcp_frame_in_the_calls_queue_is_foreign() {
    let heard = heard(
        Paper::new()
            .then_packet(call([91, 108, 9, 68], 1400, b"voice"))
            .then_packet_after(
                std::time::Duration::from_secs(1),
                tcp([91, 108, 9, 68], 443),
            ),
    );
    assert_eq!(
        heard,
        vec![Heard::Datagram(
            flow([91, 108, 9, 68], 1400),
            b"voice".to_vec()
        )]
    );
}

/// (в) Обрезанная датаграмма — ПОТЕРЯ, а не чужой кадр: она могла быть голосом этого звонка, и
/// приборы, судящие по отсутствию, обязаны на ней ослепнуть. Буква потери адресована разговорам,
/// которые уже есть, — оттого сначала звонок начат целой датаграммой (тот же порядок у
/// `driver::a_truncated_frame_arrives_as_a_letter_with_a_reason_and_not_as_silence`).
#[test]
fn a_truncated_datagram_is_unread() {
    let whole = call([91, 108, 9, 68], 1400, b"voice");
    let heard = heard(
        Paper::new()
            .then_packet(whole.clone())
            .then_packet_after(std::time::Duration::from_secs(1), whole[..24].to_vec()),
    );
    assert_eq!(
        heard,
        vec![
            Heard::Datagram(flow([91, 108, 9, 68], 1400), b"voice".to_vec()),
            Heard::Opaque("Truncated".to_string()),
        ]
    );
}
