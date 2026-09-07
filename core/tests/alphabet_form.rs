//! ФОРМА АЛФАВИТА ПРЕДЪЯВЛЕНА, А НЕ ОБЕЩАНА.
//!
//! Комбинаторы получают форму конкретными равенствами в границах, без единого нового трейта.
//! Отвергнуто: трейты `Observed`/`Told` на структуру алфавита — они заводят два имени под один
//! употребляющий алфавит, то есть ровно ту болезнь, которую впитывание лечит.
//!
//! Здесь проверяется не поведение комбинаторов (это `detector_combinators.rs`), а то, что форма
//! ВЫРАЗИМА и ВЫВОДИМА: `E0207` не кусается, вложение собирается без аннотаций.
use reflex_core::detector::DetectorEvent;
use reflex_core::step::{Step, StepExt};
use smallvec::SmallVec;
use std::time::Instant;

#[derive(Clone, Copy)]
struct Rst;

impl Step for Rst {
    type From = DetectorEvent<u8>;
    type To = SmallVec<[u8; 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
        match event {
            DetectorEvent::Packet { input: 1, .. } => (self, SmallVec::from_slice(&[7])),
            DetectorEvent::Packet { .. } => (self, SmallVec::new()),
            DetectorEvent::Tick { .. } => (self, SmallVec::new()),
            DetectorEvent::Opaque { .. } => (self, SmallVec::new()),
        }
    }
}

fn packet(input: u8) -> DetectorEvent<u8> {
    DetectorEvent::Packet {
        input,
        at: Instant::now(),
    }
}

#[test]
fn оба_слушателя_говорят_в_один_словарь() {
    let (_, told) = Rst.and(Rst).step(packet(1));
    assert_eq!(&told[..], &[7, 7], "событие дошло до обоих");
}

#[test]
fn вложение_комбинаторов_выводится_без_единой_аннотации() {
    // САМОЕ ХРУПКОЕ ДЛЯ ВЫВОДА: комбинатор над комбинатором. Если форма выражена неверно,
    // падает именно здесь, а не на одиночном звене.
    let (_, told) = Rst.and(Rst).rmap(|s: u8| s as u32 * 10).step(packet(1));
    assert_eq!(
        &told[..],
        &[70u32, 70],
        "переименование прошло сквозь сложение"
    );
}

#[test]
fn тождество_нейтрально_и_в_этой_форме() {
    // Второй закон категории на алфавите детектора: `f ∘ id` даёт то же, что `f`.
    use reflex_core::step::Id;
    let (_, прямо) = Rst.step(packet(1));
    let (_, через_тождество) = Id::<DetectorEvent<u8>>::new().then(Rst).step(packet(1));
    assert_eq!(прямо, через_тождество, "тождество ничего не изменило");
}
