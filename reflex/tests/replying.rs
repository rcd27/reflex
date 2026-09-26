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

/// Разбор начала ответа: рукопожатие `ServerHello`, `Alert` с уровнем и кодом, иное — по типу.
#[test]
fn the_first_record_is_read_by_its_header() {
    assert_eq!(
        Reply::of(&[0x16, 0x03, 0x03, 0x00, 0x7a, 0x02, 0x00]),
        Some(Reply::ServerHello)
    );
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
