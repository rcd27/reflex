use smallvec::SmallVec;
use std::time::Instant;

/// Событие для детектора: пакет или tick от scheduler'а.
///
/// Время — всегда часть события. Edge (driver/runner) проставляет `Instant::now()`
/// при попадании пакета в pipeline и при тике. Детектор никогда не дёргает часы
/// сам — это нарушает правило 1 (pure SM) и ломает детерминированные тесты.
#[derive(Debug, Clone)]
pub enum DetectorEvent<T> {
    /// Входящий пакет, наблюдаемый в момент `at`.
    Packet { input: T, at: Instant },
    /// Периодический tick от scheduler'а.
    Tick { at: Instant },
}

impl<T> DetectorEvent<T> {
    /// Wall-clock момент наблюдения события (для логов и таймеров).
    pub fn at(&self) -> Instant {
        match self {
            DetectorEvent::Packet { at, .. } => *at,
            DetectorEvent::Tick { at } => *at,
        }
    }

    /// Construct a `Packet` event stamped with `Instant::now()`.
    /// Reserved for edge code that has direct access to the system clock;
    /// pure detectors must receive `at` via the constructor argument.
    pub fn packet_now(input: T) -> Self {
        Self::Packet {
            input,
            at: Instant::now(),
        }
    }

    /// Construct a `Tick` event stamped with `Instant::now()`.
    /// Same caveat as `packet_now` — edge-only convenience.
    pub fn tick_now() -> Self {
        Self::Tick { at: Instant::now() }
    }
}

/// Stateful detector как чистая state machine.
///
/// `(State, Event) → (State, Signals)` — DDD паттерн.
/// Нет &mut self, нет side effects. Фреймворк управляет state.
///
/// # Contract
///
/// - `step` вызывается для каждого пакета (DetectorEvent::Packet)
///   и периодически (DetectorEvent::Tick).
/// - Возвращает новый state и SmallVec сигналов (stack-allocated до 2).
/// - type Input определяет уровень стека (TcpSegment, UdpDatagram, etc.)
///   и проверяется compile-time через type narrowing в pipeline.
pub trait Detector: Sized {
    type Input;
    type Signal;

    fn step(self, event: DetectorEvent<Self::Input>) -> (Self, SmallVec<[Self::Signal; 2]>);
}

/// Композиция двух детекторов над ОДНИМ входом и ОДНИМ словарём сигналов.
///
/// # Зачем
///
/// Детектор, живущий шагом внутри группировки, нельзя добавить или снять, не тронув соседний
/// код: правило детекции оказывается вплавлено в обработчик. Композиция делает детекторы
/// звеньями — новая болезнь заводится дописыванием `.and(…)`, и существующие правила при этом
/// не читаются и не редактируются.
///
/// # Что гарантирует тип
///
/// `Input` у обоих обязан совпасть, и это не формальность: детектор троттлинга UDP-датаграмм
/// физически не соберётся в цепочке над TCP-сегментами. Уровень стека проверяется компилятором,
/// а не внимательностью.
///
/// # Порядок и цена
///
/// Оба детектора видят КАЖДОЕ событие — это независимые наблюдатели, а не цепочка фильтров.
/// Сигналы выдаются в порядке `A`, затем `B`. Цена названа: событие клонируется по разу на
/// детектор, потому `Input` обязан быть `Clone`, а очень длинная цепочка `.and` умножает
/// клонирование на свою длину.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct And<A, B>(pub A, pub B);

impl<A, B> Detector for And<A, B>
where
    A: Detector,
    B: Detector<Input = A::Input, Signal = A::Signal>,
    A::Input: Clone,
{
    type Input = A::Input;
    type Signal = A::Signal;

    fn step(self, event: DetectorEvent<Self::Input>) -> (Self, SmallVec<[Self::Signal; 2]>) {
        let (first, mut signals) = self.0.step(event.clone());
        let (second, more) = self.1.step(event);
        signals.extend(more);
        (And(first, second), signals)
    }
}

/// Комбинаторы детектора. Реализован для всех — писать `impl DetectorExt` не требуется.
pub trait DetectorExt: Detector + Sized {
    /// Наблюдать обоими. См. [`And`].
    fn and<B>(self, other: B) -> And<Self, B>
    where
        B: Detector<Input = Self::Input, Signal = Self::Signal>,
        Self::Input: Clone,
    {
        And(self, other)
    }
}

impl<D: Detector> DetectorExt for D {}
