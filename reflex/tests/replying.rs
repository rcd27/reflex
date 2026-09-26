//! ОТВЕТ ЦЕЛИ (#348): первая TLS-запись её ответа на разговоре — `ServerHello`, `Alert` или иное.
//! Лечение беды «приветствие принято, ответ заглушён» (SNI-II) определено ею самой: цель прислала
//! свой `ServerHello`. Счётчики ядра этого не различают — они считают байты вместе с заголовками,
//! и 163 байта сверх их ОЦЕНКИ сошли за лечение на канарейке 26.09 18:02.
//!
//! Записи — те же, что у прибора `HelloMuted` (стенд 24.09.2026, узел кэша Google у Билайна).

use reflex::*;

#[derive(Clone, Copy, Default)]
struct Always;

impl Mealy for Always {
    type In = DetectorEvent<Seen>;
    type Out = SmallVec<[Distress; 2]>;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        match event {
            DetectorEvent::Packet { .. } => (self, smallvec![Distress::NoBytes], ()),
            DetectorEvent::Tick { .. }
            | DetectorEvent::Opaque { .. }
            | DetectorEvent::Torn { .. } => (self, SmallVec::new(), ()),
        }
    }
}

fn replies(fixture: &str) -> Vec<Reply> {
    let (tx, heard) = std::sync::mpsc::sync_channel(64);
    pcap(format!(
        "{}/tests/fixtures/{fixture}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .from(Tcp)
    .extract(Sni)
    .detect(own(Always))
    .replying(reflex_core::Tap::new(tx))
    .on(|_target, _distress| {})
    .run();
    heard
        .try_iter()
        .map(|replied: Replied| replied.reply)
        .collect()
}

/// ПРЕДМЕТ: цель ответила на приветствие — её первая запись `ServerHello`.
#[test]
fn a_target_that_answered_the_hello_replies_with_its_own_hello() {
    let replies = replies("hello-answered-ggc.pcap");

    assert!(
        replies.contains(&Reply::ServerHello),
        "ответивший узел обязан дать `ServerHello`: {replies:?}"
    );
}

/// Цель подтвердила приветствие и замолчала — ответа нет вовсе: подтверждение без данных ответом
/// не считается, и лечения здесь нет.
#[test]
fn a_muted_target_replies_nothing() {
    assert_eq!(replies("hello-muted-ggc.pcap"), Vec::<Reply>::new());
    assert_eq!(replies("hello-muted-ggc-one-ack.pcap"), Vec::<Reply>::new());
}

/// Ответ говорится один раз на разговор: дальше идут данные, а не ответ.
#[test]
fn a_reply_is_said_once_per_talk() {
    let replies = replies("hello-answered-ggc.pcap");

    assert_eq!(replies.len(), 1, "{replies:?}");
}

/// Начало записи `ServerHello` до конца `random`: заголовок записи, тип и длина сообщения,
/// `legacy_version`, затем `random`.
fn server_hello(random: [u8; 32]) -> Vec<u8> {
    [
        0x16, 0x03, 0x03, 0x00, 0x7a, 0x02, 0x00, 0x00, 0x76, 0x03, 0x03,
    ]
    .into_iter()
    .chain(random)
    .collect()
}

/// `random` у `HelloRetryRequest` (RFC 8446 §4.1.3).
const HELLO_RETRY: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// Разбор начала ответа: рукопожатие `ServerHello`, `Alert` с уровнем и кодом, иное — по типу.
#[test]
fn the_first_record_is_read_by_its_header() {
    assert_eq!(Reply::of(&server_hello([7; 32])), Some(Reply::ServerHello));
    assert_eq!(
        Reply::of(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]),
        Some(Reply::Alert {
            level: 2,
            description: 40
        })
    );
    assert_eq!(
        Reply::of(&[0x17, 0x03, 0x03]),
        Some(Reply::Other { content: 0x17 })
    );
    assert_eq!(Reply::of(&[]), None);
}

/// `HelloRetryRequest` — тот же тип рукопожатия, но не ответ на прошедшее приветствие: цель
/// просит его заново, и заглушённый второй заход был бы засчитан лечением.
#[test]
fn a_hello_retry_is_not_a_server_hello() {
    assert_eq!(
        Reply::of(&server_hello(HELLO_RETRY)),
        Some(Reply::HelloRetry)
    );
}

/// Запись TLS короче своего заголовка — «не прочесть», а не «иная запись».
#[test]
fn a_record_cut_before_its_header_ends_is_cut() {
    assert_eq!(Reply::of(&[0x16, 0x03, 0x03]), Some(Reply::Cut));
    assert_eq!(
        Reply::of(&server_hello([7; 32])[..20]),
        Some(Reply::Cut),
        "random не дочитан — HelloRetryRequest не отличить"
    );
    assert_eq!(
        Reply::of(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02]),
        Some(Reply::Cut)
    );
}

/// Ответы цели на сочинённом проводе.
fn replies_on(paper: reflex::scenario::Paper) -> Vec<Reply> {
    let (tx, heard) = std::sync::mpsc::sync_channel(64);
    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(own(Always))
        .replying(reflex_core::Tap::new(tx))
        .on(|_target, _distress| {})
        .run();
    heard
        .try_iter()
        .map(|replied: Replied| replied.reply)
        .collect()
}

/// ПЕРВАЯ ЗАПИСЬ ЦЕЛИ — С ПЕРВОГО БАЙТА ЕЁ ПОТОКА, а не первая пришедшая. Сегмент с серединой
/// полёта сертификатов пришёл раньше `ServerHello` (переставлен или первый потерян и повторён) —
/// разбор ждёт начала потока (`other_243` на канарейке 26.09).
#[test]
fn a_reordered_first_segment_of_the_target_is_waited_for() {
    use reflex::scenario::{answer_at, handshake, request, syn, Paper};
    let hello = server_hello([7; 32]);
    let paper = Paper::new()
        .then_packet(syn(40201))
        .then_packet(handshake(40201))
        .then_packet(request(40201))
        .then_packet(answer_at(40201, 1 + 1400, &[0xF3; 200]))
        .then_packet(answer_at(40201, 1, &hello))
        .then_stop();
    assert_eq!(replies_on(paper), vec![Reply::ServerHello]);
}

/// Начала потока цели не видели (подключились посреди разговора) — первая запись не судится.
#[test]
fn without_the_targets_handshake_nothing_is_said() {
    use reflex::scenario::{answer_at, request, syn, Paper};
    let paper = Paper::new()
        .then_packet(syn(40202))
        .then_packet(request(40202))
        .then_packet(answer_at(40202, 1, &server_hello([7; 32])))
        .then_stop();
    assert_eq!(replies_on(paper), Vec::<Reply>::new());
}

/// Байт 0x16 без версии записи 3.x — не TLS.
#[test]
fn a_record_of_another_version_is_other() {
    assert_eq!(
        Reply::of(&[0x16, 0x48, 0x54, 0x54, 0x50, 0x02]),
        Some(Reply::Other { content: 0x16 })
    );
}
