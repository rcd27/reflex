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
