//! Контракт `expand_effects` — реактивного `expand` над эффектами реактора (G3). Единственный
//! узаконенный способ выразить «решил → сделал async-IO → увидел исход → решил» БЕЗ ручного
//! tokio-loop+spawn. Reactor чист; эффект-запрос обслуживается краём и порождает следующее событие
//! (обратная подача); терминальный эффект (край вернул None) выходит наружу. Наблюдаемость — даром
//! через `tap` (форма трассы = форма пайпа).
//!
//! Тест — Ловца-подобной КОМПОЗИЦИЕЙ (реактор × край × наблюдаемость), не изолированным атомом:
//! приход флоу → OpenLegs → (гонка) → Raced → Serve.

use futures::StreamExt;
use reflex_core::{Reactor, Tap, Transition};
use reflex_runtime::expand_effects;

#[derive(Clone, Copy)]
enum TinyCatcher {
    Idle,
    Racing,
    Done,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Ev {
    Arrived,
    Raced { direct: bool },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fx {
    OpenLegs,
    Serve { direct: bool },
}

impl Reactor for TinyCatcher {
    type Event = Ev;
    type Effect = Fx;

    fn start() -> (Self, Option<Fx>) {
        (TinyCatcher::Idle, None)
    }

    fn step(self, ev: Ev) -> (Self, Option<Fx>) {
        match (self, ev) {
            // Приход флоу → запрос async-гонки (эффект-запрос).
            (TinyCatcher::Idle, Ev::Arrived) => (TinyCatcher::Racing, Some(Fx::OpenLegs)),
            // Исход гонки вернулся событием → терминальный эффект (унести победителя).
            (TinyCatcher::Racing, Ev::Raced { direct }) => {
                (TinyCatcher::Done, Some(Fx::Serve { direct }))
            }
            (s, _) => (s, None),
        }
    }
}

/// Разворот замыкает эффект-запрос через async-край обратно в событие и крутится до терминального
/// эффекта (край вернул None). Терминал выходит в поток исходов; наблюдаемость — в tap.
#[tokio::test]
async fn expand_closes_effect_to_event_until_terminal() {
    let (tx, rx) = std::sync::mpsc::sync_channel::<Transition<Ev, Fx>>(16);
    let tap = Tap::new(tx);

    let seed = futures::stream::iter(vec![Ev::Arrived]);

    // Край: OpenLegs → async-гонка отдаёт Raced; Serve → None (терминал, выходит наружу).
    let edge = |fx: Fx| match fx {
        Fx::OpenLegs => Some(async { Ev::Raced { direct: true } }),
        Fx::Serve { .. } => None,
    };

    let out: Vec<Fx> = expand_effects::<TinyCatcher, _, _, _>(seed, edge, tap)
        .collect()
        .await;

    // Наружу вышел РОВНО терминальный эффект.
    assert_eq!(out, vec![Fx::Serve { direct: true }]);

    // Наблюдаемость даром: tap увидел ОБА перехода (внешний Arrived + обратную подачу Raced).
    let seen: Vec<Ev> = rx.try_iter().map(|t| t.event).collect();
    assert_eq!(seen, vec![Ev::Arrived, Ev::Raced { direct: true }]);
}

/// ИНВАРИАНТ НЕПОДКЛЮЧАЕМОСТИ: без терминала (поток не поллят) НИЧЕГО не крутится — ни один эффект
/// не обслужен, ни один переход не сделан. Пайп либо отрабатывает целиком по терминалу, либо ВИДИМО
/// мёртв — нет «тихо-полурабочего» состояния (guard: лочит свойство, упадёт, если примитив станет
/// eager, напр. заспавнит таску).
#[tokio::test]
async fn no_terminal_means_nothing_runs() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let calls = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = std::sync::mpsc::sync_channel::<Transition<Ev, Fx>>(16);
    let tap = Tap::new(tx);
    let seed = futures::stream::iter(vec![Ev::Arrived]);

    let c = calls.clone();
    let edge = move |fx: Fx| {
        c.fetch_add(1, Ordering::SeqCst);
        match fx {
            Fx::OpenLegs => Some(async { Ev::Raced { direct: true } }),
            Fx::Serve { .. } => None,
        }
    };

    let pipe = expand_effects::<TinyCatcher, _, _, _>(seed, edge, tap);

    // Терминал НЕ подключён (пайп построен, но не поллится).
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "без терминала край не звался"
    );
    assert!(
        rx.try_recv().is_err(),
        "без терминала реактор не шагал (tap пуст)"
    );

    // Подключаем терминал — теперь разворот крутится.
    let out: Vec<Fx> = pipe.collect().await;
    assert_eq!(out, vec![Fx::Serve { direct: true }]);
    assert!(
        calls.load(Ordering::SeqCst) > 0,
        "терминал запустил разворот"
    );
}
