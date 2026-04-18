use smallvec::SmallVec;
use std::time::Instant;

/// Событие для детектора: пакет или tick от scheduler'а.
#[derive(Debug, Clone)]
pub enum DetectorEvent<T> {
    /// Входящий пакет.
    Packet(T),
    /// Периодический tick от scheduler'а.
    Tick(Instant),
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
