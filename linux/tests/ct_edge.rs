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
    let edge = CtEdge {
        view: view(2, 3, 110, Some(CtTcp::Established)),
        base: base(),
    };
    assert_eq!(edge.idle(), Some(Duration::from_secs(10)));
    assert_eq!(edge.down_packets(), Some(2));
    assert_eq!(edge.up_packets(), Some(3));
}

/// Базы для состояния нет — idle не выдумывается (None), а не считается по чужой базе.
#[test]
fn idle_is_unknown_without_a_base_for_the_state() {
    let edge = CtEdge {
        view: view(1, 0, 30, Some(CtTcp::TimeWait)),
        base: base(),
    };
    assert_eq!(edge.idle(), None);
}
