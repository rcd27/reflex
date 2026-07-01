//! `Reactor` — сущность, реагирующая на события провода (сетевой Reactor-паттерн + реактивный
//! `react`): `start` рождает начальное состояние (с возможным эффектом), `step` переводит
//! состояние по событию (тоже с возможным эффектом). Единственный узаконенный вход —
//! свободные функции `drive`/`group_by_reactor` этого модуля: инерентных `start`/`step` у
//! типов больше нет — забыть `start`, протащить протухший `self`, вызвать `step` не в том
//! порядке — не форма кода, а не «пожалуйста, не забудь».

use std::hash::Hash;

use futures::Stream;
use futures::StreamExt;

use crate::ext::ReflexExt;

pub trait Reactor: Sized + Copy {
    type Event;
    type Effect: Copy;

    /// Начальное состояние; эффект — если рождение само по себе действие (напр. «открой direct»).
    fn start() -> (Self, Option<Self::Effect>);

    /// Переход по событию; эффект — если переход сам по себе действие.
    fn step(self, event: Self::Event) -> (Self, Option<Self::Effect>);
}

/// Прогоняет ОДИН reactor по потоку событий: сперва эффект `start` (если есть), затем —
/// эффект `step` на каждое событие (если есть). Единственный способ увидеть эффекты reactor'а.
pub fn drive<R: Reactor>(events: impl Stream<Item = R::Event>) -> impl Stream<Item = R::Effect> {
    let (initial, start_fx) = R::start();
    let stepped = events
        .scan_state((initial, None::<R::Effect>), |st, ev| {
            let (next, fx) = st.0.step(ev);
            st.0 = next;
            st.1 = fx;
        })
        .filter_map(|(_, fx)| async move { fx });
    futures::stream::iter(start_fx).chain(stepped)
}

/// То же, но сгруппировано по ключу: на ПЕРВОЕ событие ключа — свежий `start` (эффект старта
/// отбрасывается: единственный текущий потребитель его не производит; понадобится
/// second use-case — тогда обобщать, не раньше).
pub fn group_by_reactor<R, K>(
    events: impl Stream<Item = (K, R::Event)>,
) -> impl Stream<Item = (K, R::Effect)>
where
    R: Reactor,
    K: Hash + Eq + Clone,
{
    events.group_by(
        |(k, _)| k.clone(),
        || R::start().0,
        |state, (k, ev)| {
            let (next, fx) = state.step(ev);
            *state = next;
            fx.map(|f| (k, f))
        },
    )
}
