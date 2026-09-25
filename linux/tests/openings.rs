//! ПАМЯТЬ ОТКРЫТИЙ ОЧЕРЕДИ (#350 nevod3): возраст разговора там, где ядро собрано без
//! `nf_conntrack_timestamp` (NanoPi R2S, OpenWrt 25.12 — `age()` всегда `None`). Очередь видит
//! `SYN` сама: начало — момент, когда первым увиденным пакетом записи был `SYN`.

#![cfg(feature = "nfqueue")]

use std::time::{Duration, Instant};

use reflex_linux::conntrack::{CtEdge, CtEnds, CtTcp, CtView, TimeoutBase, Tuple};
use reflex_linux::queue::Openings;

fn secs(seconds: u64) -> Duration {
    Duration::from_secs(seconds)
}

fn view(id: u32, port: u16, tcp: CtTcp) -> CtView {
    CtView {
        id,
        ends: CtEnds::Unknown,
        tuple: Some(Tuple {
            src: 0x0A4C_0009,
            dst: 0x8C52_EC0C,
            src_port: port,
            dst_port: 443,
            proto: 6,
        }),
        tcp: Some(tcp),
        ..CtView::default()
    }
}

#[test]
fn a_talk_opened_by_a_syn_ages_from_it() {
    let at = Instant::now();
    let (openings, first) = Openings::default().seen(Some(&view(7, 40_001, CtTcp::SynSent)), at);
    assert_eq!(first, Some(Duration::ZERO));
    let (_openings, later) =
        openings.seen(Some(&view(7, 40_001, CtTcp::Established)), at + secs(2));
    assert_eq!(later, Some(secs(2)));
}

/// Разговор, впервые увиденный не с `SYN` (старше продукта), — начало НЕИЗВЕСТНО: считать его от
/// первой встречи значило бы сделать его моложе, чем он есть.
#[test]
fn a_talk_first_seen_midway_has_no_known_start() {
    let at = Instant::now();
    let (openings, first) =
        Openings::default().seen(Some(&view(7, 40_001, CtTcp::Established)), at);
    assert_eq!(first, None);
    let (_openings, later) =
        openings.seen(Some(&view(7, 40_001, CtTcp::Established)), at + secs(2));
    assert_eq!(later, None);
}

/// Повтор `SYN` (клиентский RTO) начала не сдвигает.
#[test]
fn a_repeated_syn_does_not_move_the_start() {
    let at = Instant::now();
    let (openings, _first) = Openings::default().seen(Some(&view(7, 40_001, CtTcp::SynSent)), at);
    let (_openings, again) = openings.seen(Some(&view(7, 40_001, CtTcp::SynSent)), at + secs(1));
    assert_eq!(again, Some(secs(1)));
}

/// Память ограничена: полная — забывает молчащих дольше срока и только тогда берёт новое; живые не
/// вытесняются, и новый разговор тогда честно без начала.
#[test]
fn the_memory_is_bounded_and_forgets_the_silent_first() {
    let at = Instant::now();
    let full = (0..Openings::CAPACITY as u32).fold(Openings::default(), |openings, nth| {
        openings
            .seen(Some(&view(nth, 10_000 + nth as u16, CtTcp::SynSent)), at)
            .0
    });
    assert_eq!(full.len(), Openings::CAPACITY);
    let (still_full, fresh) = full
        .clone()
        .seen(Some(&view(99_999, 60_000, CtTcp::SynSent)), at + secs(1));
    assert_eq!(fresh, None, "живых не вытесняем");
    assert_eq!(still_full.len(), Openings::CAPACITY);
    let (pruned, fresh) = full.seen(
        Some(&view(99_999, 60_000, CtTcp::SynSent)),
        at + Openings::SILENCE + secs(1),
    );
    assert_eq!(fresh, Some(Duration::ZERO));
    assert_eq!(pruned.len(), 1);
}

/// Возраст ядра старше по праву: он есть — очередь его не подменяет.
#[test]
fn the_kernels_age_wins_over_the_queues() {
    let base = TimeoutBase {
        syn_sent: secs(60),
        established: secs(120),
    };
    let unstamped = CtEdge::seen(view(7, 40_001, CtTcp::Established), base).aged_by(Some(secs(5)));
    assert_eq!(reflex_core::edge::EdgeView::age(&unstamped), Some(secs(5)));
    let started = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos() as u64)
        .saturating_sub(secs(60).as_nanos() as u64);
    let stamped = CtEdge::seen(
        CtView {
            started_at: Some(started),
            ..view(7, 40_001, CtTcp::Established)
        },
        base,
    )
    .aged_by(Some(secs(5)));
    assert!(
        reflex_core::edge::EdgeView::age(&stamped).is_some_and(|age| age >= secs(60)),
        "штамп ядра не подменён"
    );
}
