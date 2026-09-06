//! ДИАЛЕКТЫ ВХОДЯТ В КАТЕГОРИЮ ШАГА — проверкой, а не заявлением.
//!
//! Vision §3 утверждает: сводить нечего, подпись уже написана, диалекты входят в неё дисциплиной
//! на алфавиты. Утверждение проверяемо ровно одним способом — собрать цепочку, где звено из
//! чужого диалекта стоит рядом с обычным шагом. Соберётся — носитель общий; не соберётся —
//! совпадение подписей было косметическим.

use reflex_core::detector::{Detector, DetectorEvent};
use reflex_core::lifting::Detecting;
use reflex_core::step::{Step, StepExt};
use smallvec::{smallvec, SmallVec};
use std::time::Instant;

/// СЧЁТЧИК ПАКЕТОВ: отдаёт порядковый номер и молчит на тике.
///
/// Тик обязан быть в алфавите и обязан НЕ порождать сигнала: тишина есть наблюдение, а не
/// выдуманное событие.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Counting(u32);

impl Detector for Counting {
    type Input = u8;
    type Signal = u32;

    fn step(self, event: DetectorEvent<u8>) -> (Self, SmallVec<[u32; 2]>) {
        match event {
            DetectorEvent::Packet { .. } => (Counting(self.0 + 1), smallvec![self.0]),
            DetectorEvent::Tick { .. } => (self, SmallVec::new()),
        }
    }
}

/// ВТОРОЕ ЗВЕНО — обычный шаг, не детектор. В этом и предмет теста.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Summing(u32);

impl Step for Summing {
    type From = SmallVec<[u32; 2]>;
    type To = u32;

    fn step(self, input: SmallVec<[u32; 2]>) -> (Self, u32) {
        let total = self.0 + input.iter().sum::<u32>();
        (Summing(total), total)
    }
}

/// ДЕТЕКТОР СТАНОВИТСЯ ЗВЕНОМ ЦЕПОЧКИ, и состояние живёт у обоих.
#[test]
fn detector_enters_the_step_category() {
    let chain = Detecting(Counting(0)).then(Summing(0));

    let (chain, first) = chain.step(DetectorEvent::Packet {
        input: 1,
        at: Instant::now(),
    });
    let (chain, second) = chain.step(DetectorEvent::Packet {
        input: 2,
        at: Instant::now(),
    });
    let (_chain, on_tick) = chain.step(DetectorEvent::Tick { at: Instant::now() });

    assert_eq!(first, 0, "первый пакет: номер 0, сумма 0");
    assert_eq!(second, 1, "второй: номер 1, сумма 0+1");
    assert_eq!(on_tick, 1, "тик сигнала не дал — сумма не сдвинулась");
}
