//! Шаг с областью определённости = **restriction category** (Cockett–Lack, 2002). Канон §6.
//! Каждому морфизму `f` сопоставлен идемпотент `f̄` — его область определённости; аксиома
//! `f ∘ f̄ = f` («проверка готовности ничего не меняет») разрешает читать готовность в любой момент.
//! Отображение: готовность → `guard: Level<bool>`, наблюдаемость (`f̄` без `f`) → `ready()`, ошибки
//! → `StepOutcome::Failed`, перезапускаемость (`f ∘ f = f`) → закон (property-тест), не флаг.

use crate::Level;
use std::sync::Arc;

/// Исход попытки. Три конструктора: **отсутствие успеха не является уликой поломки**. `NotReady` и
/// `Failed` разведены — иначе страж спутал бы «сети не было» с «идентичность сломана» и сжёг бы
/// рабочий одноразовый кред.
#[derive(Debug, PartialEq, Eq)]
pub enum StepOutcome<B, E> {
    Advanced(B),
    NotReady,
    Failed(E),
}

/// Шаг: охраняемое действие. Действие возвращает `StepOutcome`, не `Result`: `then` обязан уметь
/// сказать «голова отработала, хвост не готов», а у `Result` такого конструктора нет.
pub struct Step<A, B, E> {
    guard: Level<bool>,
    run: Arc<dyn Fn(A) -> StepOutcome<B, E> + Send + Sync>,
}

impl<A: 'static, E: 'static> Step<A, A, E> {
    /// Необязательный шаг: вне своей области — ТОЖДЕСТВО, не преграда. Охрана отвечает «действие
    /// применимо?», не «конвейеру идти дальше?». Категорно `f ⊔ id`; выразимо только для
    /// эндоморфизма (вход и выход обязаны совпадать, чтобы пропустить вход наружу).
    pub fn optional(
        guard: Level<bool>,
        run: impl Fn(A) -> Result<A, E> + Send + Sync + 'static,
    ) -> Step<A, A, E> {
        Step {
            // Композит не преграждает: неприменимость выражена внутри, не охраной.
            guard: Level::always(true),
            run: Arc::new(move |input| match guard.get() {
                false => StepOutcome::Advanced(input),
                true => match run(input) {
                    Ok(out) => StepOutcome::Advanced(out),
                    Err(err) => StepOutcome::Failed(err),
                },
            }),
        }
    }
}

impl<A: 'static, B: 'static, E: 'static> Step<A, B, E> {
    /// Собрать шаг из `Result`-действия: неготовность добавляет охрана.
    pub fn new(
        guard: Level<bool>,
        run: impl Fn(A) -> Result<B, E> + Send + Sync + 'static,
    ) -> Step<A, B, E> {
        Step {
            guard,
            run: Arc::new(move |input| match run(input) {
                Ok(out) => StepOutcome::Advanced(out),
                Err(err) => StepOutcome::Failed(err),
            }),
        }
    }

    /// Готов ли шаг — без выполнения. Наблюдение, не действие.
    pub fn ready(&self) -> bool {
        self.guard.get()
    }

    /// Попытаться продвинуться. Неготовность ошибкой не притворяется.
    pub fn attempt(&self, input: A) -> StepOutcome<B, E> {
        match self.guard.get() {
            false => StepOutcome::NotReady,
            true => (self.run)(input),
        }
    }

    /// Последовательная композиция. Готовность композита — готовность ГОЛОВЫ, не встреча:
    /// готовность хвоста вычислима лишь после эффекта головы (откат `ḡ` вдоль `f`; `start_dataplane`
    /// сам делает истинной готовность `await_witness`). Отсюда требование к голове —
    /// перезапускаемость (`f ∘ f ≡ f`): при неготовом хвосте цикл повторит весь композит.
    pub fn then<C: 'static>(self, next: Step<B, C, E>) -> Step<A, C, E> {
        let head = self.run.clone();
        let tail = next.run.clone();
        let tail_guard = next.guard;
        Step {
            guard: self.guard,
            run: Arc::new(move |input| match head(input) {
                StepOutcome::NotReady => StepOutcome::NotReady,
                StepOutcome::Failed(err) => StepOutcome::Failed(err),
                StepOutcome::Advanced(middle) => match tail_guard.get() {
                    false => StepOutcome::NotReady,
                    true => tail(middle),
                },
            }),
        }
    }
}
