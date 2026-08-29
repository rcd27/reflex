use reflex_core::stream::Keys;
use futures::StreamExt;
use reflex_core::reactor::{drive, group_by_reactor, Reactor};

/// Игрушечный reactor: счётчик, событие — дельта, эффект — новый итог.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Counter(i32);

impl Reactor for Counter {
    type Event = i32;
    type Effect = i32;

    fn start() -> (Self, Option<i32>) {
        (Counter(0), Some(0))
    }

    fn step(self, delta: i32) -> (Self, Option<i32>) {
        let next = Counter(self.0 + delta);
        (next, Some(next.0))
    }
}

/// Reactor, чей `step` иногда молчит (эффект — только на чётный итог).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EvenOnly(i32);

impl Reactor for EvenOnly {
    type Event = i32;
    type Effect = i32;

    fn start() -> (Self, Option<i32>) {
        (EvenOnly(0), None)
    }

    fn step(self, delta: i32) -> (Self, Option<i32>) {
        let next = EvenOnly(self.0 + delta);
        (next, (next.0 % 2 == 0).then_some(next.0))
    }
}

/// `drive`: старт всегда эмитит свой эффект первым, затем — эффект на каждое событие.
#[tokio::test]
async fn drive_emits_start_effect_then_step_effects() {
    let events = futures::stream::iter(vec![1, 2, 3]);
    let effects: Vec<i32> = drive::<Counter>(events).collect().await;
    assert_eq!(effects, vec![0, 1, 3, 6]);
}

/// `drive`: пустой поток событий — эффект старта всё равно приходит (старт не зависит от событий).
#[tokio::test]
async fn drive_emits_only_start_effect_on_empty_stream() {
    let events = futures::stream::iter(Vec::<i32>::new());
    let effects: Vec<i32> = drive::<Counter>(events).collect().await;
    assert_eq!(effects, vec![0]);
}

/// `drive`: `None` из `step` не порождает эффект (молчание — легальный исход).
#[tokio::test]
async fn drive_skips_none_step_effects() {
    let events = futures::stream::iter(vec![1, 1, 1]); // 1,2,3 → эффект лишь на чётных
    let effects: Vec<i32> = drive::<EvenOnly>(events).collect().await;
    assert_eq!(effects, vec![2]);
}

/// `group_by_reactor`: у каждого ключа — свой независимый reactor (свежий `start` на первое событие).
#[tokio::test]
async fn group_by_reactor_tracks_independent_state_per_key() {
    let events = futures::stream::iter(vec![("a", 1), ("b", 10), ("a", 2)]);
    let effects: Vec<(&str, i32)> = group_by_reactor::<Counter, _>(events, Keys::Finite).collect().await;
    assert_eq!(effects, vec![("a", 1), ("b", 10), ("a", 3)]);
}
