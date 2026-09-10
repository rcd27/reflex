//! ДИАЛЕКТЫ ВХОДЯТ В КАТЕГОРИЮ ШАГА — проверкой, а не заявлением.
//!
//! Канон §1 утверждает: сводить нечего, подпись уже написана, диалекты входят в неё дисциплиной
//! на алфавиты. Утверждение проверяемо ровно одним способом — собрать цепочку, где звено из
//! чужого диалекта стоит рядом с обычным шагом. Соберётся — носитель общий; не соберётся —
//! совпадение подписей было косметическим.

use reflex_core::detector::DetectorEvent;
use reflex_core::mealy::{Mealy, MealyExt};
use reflex_core::word::{Base, Word};
use smallvec::{smallvec, SmallVec};
use std::time::Instant;

/// ОБЛАСТЬ ЗАКОННОГО СТЕНДА.
///
/// Объявляется здесь, а не в фундаменте: закон обязан быть выразим для того, кто заводит свою
/// область снаружи, и стенд — законный заводящий.
struct Bench;
impl Base for Bench {
    type Fibre = ();
}

/// СЧЁТ СВИДЕТЕЛЯ — с именем, а не голым числом: адрес объявляет значение, а число молчит.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Count(u32);

impl Word for Count {
    type Of = Bench;
}

/// СЧЁТЧИК ПАКЕТОВ: отдаёт порядковый номер и молчит на тике.
///
/// Тик обязан быть в алфавите и обязан НЕ порождать сигнала: тишина есть наблюдение, а не
/// выдуманное событие.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Counting(u32);

impl Mealy for Counting {
    type In = DetectorEvent<u8>;
    type Out = SmallVec<[Count; 2]>;
    type Log = ();

    fn step(self, event: DetectorEvent<u8>) -> (Self, SmallVec<[Count; 2]>, ()) {
        match event {
            DetectorEvent::Packet { .. } => (Counting(self.0 + 1), smallvec![Count(self.0)], ()),
            DetectorEvent::Tick { .. } => (self, SmallVec::new(), ()),
            // Счётчик считает разобранные пакеты; непонятое и дыра ему не пакет и не тик — молчат
            // так же.
            DetectorEvent::Opaque { .. } | DetectorEvent::Torn { .. } => {
                (self, SmallVec::new(), ())
            }
        }
    }
}

/// ВТОРОЕ ЗВЕНО — обычный шаг, не детектор. В этом и предмет теста.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Summing(u32);

impl Mealy for Summing {
    type In = SmallVec<[Count; 2]>;
    type Out = Count;
    type Log = ();

    fn step(self, input: SmallVec<[Count; 2]>) -> (Self, Count, ()) {
        let total = self.0 + input.iter().map(|Count(n)| n).sum::<u32>();
        (Summing(total), Count(total), ())
    }
}

/// ДЕТЕКТОР ВХОДИТ В ЦЕПОЧКУ НАПРЯМУЮ, БЕЗ ПОСРЕДНИКА.
///
/// Одно имя — `Counting` реализует `Mealy` напрямую, а не через обёртку над отдельным трейтом:
/// два имени для одной машины Мили потребовали бы либо посредника, либо blanket-`impl`,
/// невозможного как раз потому, что он конфликтовал бы со всякой другой реализацией `Mealy`.
#[test]
fn detector_enters_the_step_category() {
    let chain = Counting(0).then(Summing(0));

    let (chain, first, _) = chain.step(DetectorEvent::Packet {
        input: 1,
        at: Instant::now(),
    });
    let (chain, second, _) = chain.step(DetectorEvent::Packet {
        input: 2,
        at: Instant::now(),
    });
    let (_chain, on_tick, _) = chain.step(DetectorEvent::Tick {
        node: 1,
        at: Instant::now(),
    });

    assert_eq!(first, Count(0), "первый пакет: номер 0, сумма 0");
    assert_eq!(second, Count(1), "второй: номер 1, сумма 0+1");
    assert_eq!(
        on_tick,
        Count(1),
        "тик сигнала не дал — сумма не сдвинулась"
    );
}
