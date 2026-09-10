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
            // Прячущая буква (дыра, обрезанный кадр) не есть наблюдение и удержанного не вытесняет
            // — но ОКНО ЗАТИШЬЯ она рвёт: выпуск означает вывод «разговор затих», а пропавшее
            // наблюдение вытеснило бы удержанное и окно сдвинуло. Гасить выпуск нельзя, иначе
            // значение застрянет навсегда; поэтому окно отсчитывается ОТ НЕЁ — затишье меряется по
            // наблюдаемому участку (§7, Д7).
            hiding if hiding.hides_observation() => {
                let at = hiding.at();
                (
                    Self {
                        held: self.held.map(|(held, _since)| (held, at)),
                        ..self
                    },
                    smallvec![],
                    (),
                )
            }
            // Непонятое чужого протокола не есть затихающий разговор: оператор мерит паузу между
            // разобранными значениями, а чужие байты к ней не относятся — ни окна не двигают, ни
            // выпускают.
            DetectorEvent::Opaque { .. } | DetectorEvent::Torn { .. } => (self, smallvec![], ()),
        }
    }
}
