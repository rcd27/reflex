//! `CtEdge` — conntrack как носитель `EdgeView`. `idle = база − остаток` живёт здесь, где оба
//! слагаемых на руках: база (sysctl, старт машины) и остаток (`CTA_TIMEOUT`, с пакетом).

#![cfg(feature = "conntrack")]

use std::time::Duration;

use reflex_core::edge::EdgeView;
use reflex_linux::conntrack::{CtEdge, CtEnds, CtTcp, CtView, TimeoutBase};

fn view(down: u64, up: u64, expires_in_secs: u64, tcp: Option<CtTcp>) -> CtView {
    CtView {
        id: 0,
        ends: CtEnds::Unknown,
        tuple: None,
        down: reflex_linux::conntrack::Counts {
            packets: down,
            bytes: 0,
        },
        up: reflex_linux::conntrack::Counts {
            packets: up,
            bytes: 0,
        },
        started_at: None,
        expires_in: Some(Duration::from_secs(expires_in_secs)),
        tcp,
        mark: 0,
    }
}

fn base() -> TimeoutBase {
    TimeoutBase {
        syn_sent: Duration::from_secs(60),
        established: Duration::from_secs(120),
    }
}

/// idle = база(состояние) − остаток. established: 120 − 110 = 10.
#[test]
fn idle_is_base_minus_remaining() {
    let edge = CtEdge::seen(view(2, 3, 110, Some(CtTcp::Established)), base());
    assert_eq!(edge.idle(), Some(Duration::from_secs(10)));
    assert_eq!(edge.down_packets(), Some(2));
    assert_eq!(edge.up_packets(), Some(3));
}

/// Базы для состояния нет — idle не выдумывается (None), а не считается по чужой базе.
#[test]
fn idle_is_unknown_without_a_base_for_the_state() {
    let edge = CtEdge::seen(view(1, 0, 30, Some(CtTcp::TimeWait)), base());
    assert_eq!(edge.idle(), None);
}

/// Возраст — СНИМОК на приходе (`seen`), не запрос часов при вызове: два обращения к одному виду за
/// разное настенное время дают ОДНО значение. Иначе часы жили бы под шагом прибора (§2), и переигровка
/// одной записи расходилась бы (§10). Мутируй `age()` обратно на `SystemTime::now()` при вызове — и
/// пауза между обращениями разведёт значения, тест покраснеет.
#[test]
fn age_is_a_snapshot_stable_across_calls() {
    let mut v = view(2, 1, 110, Some(CtTcp::SynSent));
    // Начало — 10 с назад от эпохи (абсолютные ns, как кладёт ядро).
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    v.started_at = Some(now_ns - 10_000_000_000);
    let edge = CtEdge::seen(v, base());
    let first = edge.age();
    std::thread::sleep(Duration::from_millis(20));
    let second = edge.age();
    assert_eq!(first, second, "возраст замер на приходе, часов в шаге нет");
    assert!(
        first.is_some_and(|age| age >= Duration::from_secs(10)),
        "снимок реален — поток открыт ~10 с назад"
    );
}
