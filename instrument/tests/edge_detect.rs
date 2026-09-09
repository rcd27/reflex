//! Приборы края читают ЯДЕРНЫЕ величины (через `EdgeView`) и марку, состояния в юзерспейсе не держат.
//! Носитель здесь — локальный `TestEdge` (не conntrack): прибор о носителе не знает по построению.

use std::time::Duration;

use reflex_core::edge::EdgeView;
use reflex_core::mealy::Mealy;
use reflex_core::DetectorEvent;
use reflex_instrument::distress::Distress;
use reflex_instrument::edge::{Layout, Memo, Phase};
use reflex_instrument::edge_detect::EdgeSilence;
use reflex_instrument::edge_word::Edged;
use reflex_instrument::wire::Seen;

fn layout() -> Layout {
    Layout::new(0x0FFF_E000, 0b101).expect("15-битная маска, ненулевой тег")
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

/// Носитель края для теста — величины кладём прямо, conntrack не при чём.
#[derive(Clone)]
struct TestEdge {
    down: Option<u64>,
    up: Option<u64>,
    idle: Option<Duration>,
    mark: u32,
}

impl EdgeView for TestEdge {
    fn down_packets(&self) -> Option<u64> {
        self.down
    }
    fn up_packets(&self) -> Option<u64> {
        self.up
    }
    fn idle(&self) -> Option<Duration> {
        self.idle
    }
    fn mark(&self) -> u32 {
        self.mark
    }
}

/// `idle = база − остаток`, как считал бы носитель; здесь кладём готовым.
fn view(down: u64, up: u64, expires_in: u64, base: u64) -> TestEdge {
    TestEdge {
        down: Some(down),
        up: Some(up),
        idle: Some(Duration::from_secs(base - expires_in)),
        mark: 0,
    }
}

fn with_mark(mut edge: TestEdge, mark: u32) -> TestEdge {
    edge.mark = mark;
    edge
}

fn packet(edge: TestEdge) -> DetectorEvent<Edged<Seen, TestEdge>> {
    DetectorEvent::packet_now(Edged {
        narrow: Seen::Received { count: 1 },
        edge,
    })
}

/// Цель не ответила вовсе — ядро знает это счётчиком (`up_packets == Some(0)`), нам хранить нечего.
#[test]
fn no_reply_at_all_is_read_from_the_edge() {
    let (_next, said, ()) = EdgeSilence::new(secs(5), layout()).step(packet(view(4, 0, 110, 120)));
    assert!(said.iter().any(|(distress, _)| *distress == Distress::NoBytes));
}

/// Тишина меряется ядерной величиной (`idle`), не нашими часами: 120 − 114 = 6 с простоя.
#[test]
fn silence_is_measured_by_the_kernel_clock() {
    let (_next, said, ()) = EdgeSilence::new(secs(5), layout()).step(packet(view(2, 3, 114, 120)));
    assert!(
        said.iter()
            .any(|(distress, _)| matches!(distress, Distress::Silence { ms } if *ms >= 6000)),
        "шесть секунд простоя видны без наших часов"
    );
}

/// Направление существенно: молчит ЦЕЛЬ (`up == 0`), не клиент. При живом ответе цели тишины нет —
/// иначе прибор кричал бы о дропе на каждом простаивающем соединении, где молчит клиент.
#[test]
fn a_silent_client_is_not_a_silent_drop() {
    // Цель ответила (up = 5), клиент молчит (down мал) — но простой ещё не набран (idle < after).
    let (_next, said, ()) = EdgeSilence::new(secs(5), layout()).step(packet(view(1, 5, 118, 120)));
    assert!(said.is_empty(), "ответ цели есть — беды нет");
}

/// `None` (край не считает, acct off) ≠ `Some(0)`: `NoBytes` на `None` объявил бы дроп на КАЖДОМ
/// потоке машины без `nf_conntrack_acct` — состояние вантажа прямо сейчас.
#[test]
fn unknown_counters_are_not_a_silent_drop() {
    let edge = TestEdge {
        down: None,
        up: None,
        idle: None,
        mark: 0,
    };
    let (_next, said, ()) = EdgeSilence::new(secs(5), layout()).step(packet(edge));
    assert!(said.is_empty(), "не считали — не тишина");
}

/// Сказанное однажды не повторяется: фаза лежит в марке, второй пакет её оттуда читает.
#[test]
fn a_told_flow_stays_silent_on_the_next_packet() {
    let told = Memo::new(layout(), Phase::Confirmed, 3).apply_to(0);
    let (_next, said, ()) =
        EdgeSilence::new(secs(5), layout()).step(packet(with_mark(view(2, 3, 114, 120), told)));
    assert!(said.is_empty(), "повторно не жалуемся");
}

/// Прибор состояния не держит: два шага из одного значения дают один и тот же исход.
#[test]
fn the_instrument_is_stateless() {
    let instrument = EdgeSilence::new(secs(5), layout());
    let (again, first, ()) = instrument.step(packet(view(4, 0, 114, 120)));
    let (_, second, ()) = again.step(packet(view(4, 0, 114, 120)));
    assert_eq!(first, second, "исход зависит от края, не от прожитого");
}

/// По нашим битам писал другой — это буква `Diverged`, а не тишина: прибор вправе сказать о находке.
#[test]
fn a_foreign_writer_is_observed() {
    let alien = 0x0055_0000;
    let (_next, said, ()) =
        EdgeSilence::new(secs(5), layout()).step(packet(with_mark(view(2, 0, 114, 120), alien)));
    assert!(said
        .iter()
        .any(|(distress, _)| matches!(distress, Distress::Diverged { .. })));
}
