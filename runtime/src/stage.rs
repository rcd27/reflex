//! Типизированная композиция стадий — domain-agnostic примитив.
//!
//! Стадия — асинхронное преобразование `In` с коротким замыканием: либо
//! «дальше по главному пути» (`Advance(Out)`), либо «приземлить весь конвейер»
//! терминалом (`Settle(Settled)`). Композиция `.then()` определена только когда
//! выход одной стадии = вход следующей (проверяет компилятор). Терминал —
//! параметр, никаких доменных типов внутри reflex.
//!
//! `Out`/`Settled` — ассоциированные типы (как `Output` у `Fn`), поэтому при
//! композиции `Mid = A::Out` детерминирован, а `Settled` обязан совпадать у
//! соседних стадий.

use async_trait::async_trait;

/// Исход одной стадии. `Advance` — продолжить конвейер с результатом `Out`;
/// `Settle` — завершить весь конвейер терминалом `Settled` (минуя хвост).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageOutcome<Out, Settled> {
    Advance(Out),
    Settle(Settled),
}

/// Стадия конвейера: `In -> StageOutcome<Out, Settled>` (async, на краю — IO).
#[async_trait]
pub trait Stage<In>: Send + Sync {
    type Out;
    type Settled;
    async fn run(&self, input: In) -> StageOutcome<Self::Out, Self::Settled>;
}

/// Последовательная композиция `a` затем `b`. `Advance` от `a` подаётся в `b`;
/// `Settle` от `a` коротит до конца.
pub struct Then<A, B> {
    a: A,
    b: B,
}

#[async_trait]
impl<In, A, B> Stage<In> for Then<A, B>
where
    In: Send + 'static,
    A: Stage<In>,
    A::Out: Send + 'static,
    A::Settled: Send + 'static,
    B: Stage<A::Out, Settled = A::Settled>,
    B::Out: Send + 'static,
{
    type Out = B::Out;
    type Settled = A::Settled;

    async fn run(&self, input: In) -> StageOutcome<Self::Out, Self::Settled> {
        match self.a.run(input).await {
            StageOutcome::Advance(mid) => self.b.run(mid).await,
            StageOutcome::Settle(s) => StageOutcome::Settle(s),
        }
    }
}

/// Расширение: `a.then(b)` с проверкой `вход(b) == выход(a)` и
/// `Settled(b) == Settled(a)` компилятором (DR-9).
pub trait StageExt<In>: Stage<In> + Sized {
    fn then<B>(self, b: B) -> Then<Self, B>
    where
        B: Stage<Self::Out, Settled = Self::Settled>,
    {
        Then { a: self, b }
    }
}

impl<In, T> StageExt<In> for T where T: Stage<In> {}

#[cfg(test)]
mod tests {
    use super::*;

    struct AddOne;
    #[async_trait]
    impl Stage<i32> for AddOne {
        type Out = i32;
        type Settled = String;
        async fn run(&self, x: i32) -> StageOutcome<i32, String> {
            StageOutcome::Advance(x + 1)
        }
    }

    struct SettleIfBig;
    #[async_trait]
    impl Stage<i32> for SettleIfBig {
        type Out = i32;
        type Settled = String;
        async fn run(&self, x: i32) -> StageOutcome<i32, String> {
            if x >= 10 {
                StageOutcome::Settle(format!("settled at {x}"))
            } else {
                StageOutcome::Advance(x)
            }
        }
    }

    #[tokio::test]
    async fn then_advances_through_both() {
        let pipe = AddOne.then(AddOne);
        assert_eq!(pipe.run(0).await, StageOutcome::Advance(2));
    }

    #[tokio::test]
    async fn settle_short_circuits_tail() {
        // SettleIfBig приземляет на 10 → второй AddOne не выполняется.
        let pipe = SettleIfBig.then(AddOne);
        assert_eq!(
            pipe.run(10).await,
            StageOutcome::Settle("settled at 10".to_string())
        );
    }

    #[tokio::test]
    async fn settle_passes_below_threshold() {
        let pipe = SettleIfBig.then(AddOne);
        assert_eq!(pipe.run(5).await, StageOutcome::Advance(6));
    }
}
