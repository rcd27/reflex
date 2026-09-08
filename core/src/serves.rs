//! Источник, отдающий владение, а не копию. Канон §9. Очередь ядра не [`Source`](crate::backend::
//! Source): `packets(&mut self)` заимствует бэкенд на весь поток, а ответить удержанному — второй
//! `&mut` (`E0499`). Отсюда [`Serves`]: взять и ответить — один неделимый шаг, носитель наружу не
//! выходит, потому «взял и забыл ответить» непредставимо по построению.

use crate::held::{Delivered, Held, Refused, Terminal};

/// Исход шага обслуживания. Алгебра, не `Option`: «не было работы» и «ждать не на чем» чинятся
/// по-разному.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Served<D, R> {
    /// Пакет взят, решение отдано миру — принято или отказано.
    Answered(Result<D, R>),
    /// Работы не было. Не ошибка: очередь пуста.
    Idle,
    /// Ждать не на чем — дескриптор очереди не добыт. Ведущий цикл сам не жжёт процессор.
    Blind,
}

/// Бэкенд, у которого взять пакет и ответить — один шаг. Носителя наружу не вынести — это держит
/// лайфтайм, не `#[must_use]`:
///
/// ```compile_fail
/// use reflex_core::held::Held;
/// use reflex_core::Serves;
///
/// fn steals<T: Serves>(queue: &mut T) -> Option<&Held<T::Carrier>>
/// where
///     T::Answer: Default,
/// {
///     let mut stolen = None;
///     queue.serve(|held| {
///         stolen = Some(held);
///         T::Answer::default()
///     });
///     stolen
/// }
/// ```
pub trait Serves: Terminal {
    /// Взять удержанный пакет, решить, отдать решение — неделимо. Исход — [`Served`], не `Option`.
    /// `decide` видит носителя по ссылке: читает наблюдение, распоряжается им терминал, один раз.
    fn serve<F>(
        &mut self,
        decide: F,
    ) -> Served<Delivered<Self::Answer>, Refused<Self::Answer, Self::Refusal>>
    where
        F: FnOnce(&Held<Self::Carrier>) -> Self::Answer;
}
