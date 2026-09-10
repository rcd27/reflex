//! Выпустить последнее, когда поток затих — оператор времени без часов (канон §8). Операторы
//! КОНКУРЕНТНОСТИ (`switch_map`, `merge_map_bounded`) на носителе шага невыразимы (нужна вторая
//! нить); операторы ВРЕМЕНИ — другой род: время стало буквой входа ([`crate::interleave`]),
//! `debounce` — чистая `(состояние, событие) → состояние`. Цена: точность квантуется сеткой (выпуск
//! на первом узле после конца окна, опоздание не более шага) — взамен работает в синхронной
//! плоскости, на записи со скоростью чтения файла. Конца потока у детектора нет: удержанное
//! выпускается только тиком, досказать при обрыве источника — дело потребителя.

use core::time::Duration;
use std::time::Instant;

use smallvec::{smallvec, SmallVec};

use crate::detector::DetectorEvent;
use crate::mealy::Mealy;

/// Держит последнее событие и отдаёт его, когда окно тишины прошло.
#[derive(Debug, Clone)]
pub struct Debounce<T> {
    window: Duration,
    held: Option<(T, Instant)>,
}

impl<T> Debounce<T> {
    /// Окно тишины, после которого удержанное считается окончательным.
    pub fn over(window: Duration) -> Self {
        Self { window, held: None }
    }
}

/// Задержка адреса не меняет: наружу то же событие, тому же адресату, только позже.
impl<T: crate::word::Word> Mealy for Debounce<T> {
    type In = DetectorEvent<T>;
    type Out = SmallVec<[T; 2]>;
    /// Показаний не заводит: говорит, что увидел, не говорит, чем мерил.
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        match event {
            // Новое событие вытесняет удержанное и отодвигает окно. Отсчёт от ПОСЛЕДНЕГО, не
            // первого: иначе поток чуть чаще окна выпускался бы регулярно, и оператор перестал бы
            // отличать «затих» от «идёт ровно».
            DetectorEvent::Packet { input, at } => (
                Self {
                    held: Some((input, at)),
                    ..self
                },
                smallvec![],
                (),
            ),
            DetectorEvent::Tick { at, .. } => match self.held {
                Some((held, since)) if at.saturating_duration_since(since) >= self.window => {
                    (Self { held: None, ..self }, smallvec![held], ())
                }
                still_waiting => (
                    Self {
                        held: still_waiting,
                        ..self
                    },
                    smallvec![],
                    (),
                ),
            },
            // Непонятое не есть затихающий разговор: оператор мерит паузу между разобранными
            // значениями, непрочтённые байты к ней не относятся — ни окна не двигают, ни выпускают.
            // Дыра — тем более не наблюдение: пропавшие байты не говорят, продолжился разговор или
            // затих, а тик всё равно придёт независимо от неё и проверит окно по факту тишины.
            DetectorEvent::Opaque { .. } | DetectorEvent::Torn { .. } => (self, smallvec![], ()),
        }
    }
}
