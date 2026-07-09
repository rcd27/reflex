//! `expand_effects` — реактивный `expand` над эффектами реактора (G3): каждый эффект либо
//! ОБСЛУЖИВАЕТСЯ краём и порождает следующее событие (обратная подача), либо терминален и выходит
//! наружу. Единственный узаконенный способ выразить «решил → сделал async-IO → увидел исход →
//! решил» БЕЗ ручного tokio-loop+spawn.
//!
//! reflex уже имеет [`drive`](reflex_core::drive) (Reactor → эффекты наружу) и
//! [`drive_observed`](reflex_core::drive_observed) (то же + tap), но у них эффект — ТУПИК: он
//! утекает наружу, и замкнуть его через async-край обратно в событие нечем. Отсюда весь императив
//! в датаплейне (tokio-`loop`+`spawn`, зовущий доменную функцию руками). `expand_effects` замыкает
//! цикл КОНСТРУКЦИЕЙ: множество эффектов РАЗРАСТАЕТСЯ по ходу (не линейный `traverse` — рекурсивный
//! `expand`), пока не выйдет терминал.
//!
//! Reactor остаётся ЧИСТ (`Reactor: Copy` физически не даёт ему держать сокет — IO живёт в `edge`,
//! Правило 2 конструкцией). Наблюдаемость даром: КАЖДЫЙ переход эмитится в `tap` (край маппит
//! `Transition` в спан; форма трассы = форма пайпа, Правило 17). Под капотом — анаморфизм
//! (`futures::stream::unfold`): `expand` — реактивное имя, `unfold` — категориальное.

use std::collections::VecDeque;
use std::future::Future;

use futures::{Stream, StreamExt};

use reflex_core::{Reactor, Tap, Transition};

struct Loop<R: Reactor, S, Edge> {
    reactor: R,
    seed: S,
    pending: VecDeque<R::Event>,
    start_fx: Option<R::Effect>,
    edge: Edge,
    tap: Tap<Transition<R::Event, R::Effect>>,
}

/// Разворачивает эффекты `Reactor`'а: каждый эффект `edge` либо ОБСЛУЖИВАЕТ (async → следующее
/// событие, обратная подача), либо помечает терминальным (`None`) — тот выходит в поток исходов.
/// Внешние события (`seed`) и обратная подача (исходы `edge`) сливаются в один фолд реактора,
/// который крутится, пока `seed` не иссякнет и петля не опустеет.
///
/// `edge`: эффект-запрос → `Some(future)` (async-край даёт следующее событие) | `None`
/// (терминальный эффект — наружу, событие не порождает).
pub fn expand_effects<R, S, Edge, Fut>(
    seed: S,
    edge: Edge,
    tap: Tap<Transition<R::Event, R::Effect>>,
) -> impl Stream<Item = R::Effect>
where
    R: Reactor,
    R::Event: Copy,
    S: Stream<Item = R::Event> + Unpin,
    Edge: Fn(R::Effect) -> Option<Fut>,
    Fut: Future<Output = R::Event>,
{
    let (reactor, start_fx) = R::start();
    let init = Loop {
        reactor,
        seed,
        pending: VecDeque::new(),
        start_fx,
        edge,
        tap,
    };

    futures::stream::unfold(init, |mut st| async move {
        loop {
            // Эффект старта (если рождение — само действие) — до первого события; события нет, tap не бьём.
            if let Some(fx) = st.start_fx.take() {
                match (st.edge)(fx) {
                    Some(fut) => st.pending.push_back(fut.await),
                    None => return Some((fx, st)),
                }
                continue;
            }

            // Следующее событие: обратная подача (pending) вперёд внешнего потока (seed).
            let ev = match st.pending.pop_front() {
                Some(e) => e,
                None => match st.seed.next().await {
                    Some(e) => e,
                    None => return None, // seed иссяк и петля пуста → поток исходов закрыт
                },
            };

            let (next, fx) = st.reactor.step(ev);
            st.reactor = next;
            st.tap.emit(Transition {
                event: ev,
                effect: fx,
            });

            if let Some(fx) = fx {
                match (st.edge)(fx) {
                    Some(fut) => st.pending.push_back(fut.await), // обратная подача: исход → событие
                    None => return Some((fx, st)),                // терминал → наружу
                }
            }
        }
    })
}
