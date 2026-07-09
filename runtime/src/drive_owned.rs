//! `drive_owned` — драйвер реактора, НЕСУЩИЙ владеемый контекст сквозь интерпретатор (сосед
//! [`expand_effects`](crate::expand_effects)). Замыкает ровно то, чего `expand_effects` не мог:
//! там терминал — ДАННЫЕ наружу (`Effect: Copy`), а здесь терминал — IO над ВЛАДЕЕМЫМ ресурсом
//! (напр. splice сокета-победителя в ловце). Отсюда весь императив вокруг сервировки уходит.
//!
//! Разделение (Правило 2): чистый `Reactor` РЕШАЕТ (`Copy`, сокет держать физически не может),
//! IO-край `interp` ВЛАДЕЕТ ресурсами и исполняет. Контекст `Ctx` едет ПО ЗНАЧЕНИЮ через
//! интерпретатор — без `Arc<Mutex>`, без self-borrow, живёт в одном скоупе и НЕ течёт. Под капотом
//! — тот же анаморфизм, что у `expand_effects`, но с явным владеемым носителем. Наблюдаемость
//! даром: каждый переход эмитится в `tap` (форма трассы = форма пайпа, Правило 17).

use std::future::Future;

use reflex_core::{Reactor, Tap, Transition};

/// Шаг интерпретатора над эффектом реактора: либо ОБСЛУЖИЛ (async-край дал следующее событие и
/// вернул владеемый контекст для следующего шага), либо ТЕРМИНАЛ (исполнил IO над ресурсом →
/// исход, пайп завершён). `Ctx` несёт владеемые ресурсы (сокеты) — не `Copy`, ездит по значению.
pub enum InterpStep<Ev, Ctx, Out> {
    /// Эффект обслужен: обратная подача события + владеемый контекст для следующего шага.
    Feed { event: Ev, ctx: Ctx },
    /// Терминальный эффект: IO над ресурсом исполнено, пайп завершён с исходом.
    Done(Out),
}

/// Гонит ОДИН реактор от первого события до терминала, протаскивая владеемый `Ctx` через
/// интерпретатор `interp`. Каждый переход эмитится в `tap`. Возвращает `Some(исход)` терминала.
///
/// `None` возвращается лишь если реактор шагнул БЕЗ эффекта (`step` вернул `None`) — «нечего
/// исполнять и события нет» = тупик формы. Для well-formed реактора (каждый нетерминальный шаг
/// несёт эффект) не наступает; ловец таков по построению.
pub async fn drive_owned<R, Ctx, Out, Interp, Fut>(
    reactor: R,
    ctx: Ctx,
    first_event: R::Event,
    interp: Interp,
    tap: Tap<Transition<R::Event, R::Effect>>,
) -> Option<Out>
where
    R: Reactor,
    R::Event: Copy,
    Interp: Fn(Ctx, R::Effect) -> Fut,
    Fut: Future<Output = InterpStep<R::Event, Ctx, Out>>,
{
    let mut reactor = reactor;
    let mut ctx = ctx;
    let mut event = first_event;
    loop {
        let (next, effect) = reactor.step(event);
        reactor = next;
        tap.emit(Transition { event, effect });
        // Нет эффекта → нечего исполнять и события нет → пайп встал (видимый `None`, не тихо-полу).
        let effect = effect?;
        match interp(ctx, effect).await {
            InterpStep::Feed { event: ev, ctx: c } => {
                event = ev;
                ctx = c;
            }
            InterpStep::Done(out) => return Some(out),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    enum St {
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

    impl Reactor for St {
        type Event = Ev;
        type Effect = Fx;

        fn start() -> (Self, Option<Fx>) {
            (St::Idle, None)
        }

        fn step(self, ev: Ev) -> (Self, Option<Fx>) {
            match (self, ev) {
                (St::Idle, Ev::Arrived) => (St::Racing, Some(Fx::OpenLegs)),
                (St::Racing, Ev::Raced { direct }) => (St::Done, Some(Fx::Serve { direct })),
                (s, _) => (s, None),
            }
        }
    }

    /// Владеемый (не `Copy`) ресурс проезжает СКВОЗЬ реактор в краю, а терминал исполняет IO над
    /// ним (тут — дописывает байт «победителя») и отдаёт исход. Пайп замкнут: и решение, и
    /// сервировка внутри; наблюдаемость — оба перехода в tap.
    #[tokio::test]
    async fn owned_resource_rides_through_to_terminal_io() {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Transition<Ev, Fx>>(16);
        let tap = Tap::new(tx);

        // Ctx — владеемый «сокет» (Vec<u8>, не Copy). Реактор его касаться не может.
        let socket: Vec<u8> = vec![0xAA];

        let interp = |ctx: Vec<u8>, fx: Fx| async move {
            match fx {
                Fx::OpenLegs => InterpStep::Feed {
                    event: Ev::Raced { direct: true },
                    ctx, // ресурс едет дальше по значению
                },
                Fx::Serve { direct } => {
                    let mut c = ctx; // терминал ВЛАДЕЕТ ресурсом и исполняет IO над ним
                    c.push(if direct { 0xD1 } else { 0xF0 });
                    InterpStep::Done(c)
                }
            }
        };

        let out = drive_owned(St::Idle, socket, Ev::Arrived, interp, tap).await;

        // Терминал вернул владеемый ресурс, «прокачанный» победителем (direct).
        assert_eq!(out, Some(vec![0xAA, 0xD1]));

        // Наблюдаемость даром: tap увидел оба перехода (внешний Arrived + обратную подачу Raced).
        let seen: Vec<Ev> = rx.try_iter().map(|t| t.event).collect();
        assert_eq!(seen, vec![Ev::Arrived, Ev::Raced { direct: true }]);
    }
}
