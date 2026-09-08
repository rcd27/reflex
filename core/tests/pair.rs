//! ВЫХОД ШАГА ЕСТЬ ПАРА: СЛОВО И ПОКАЗАНИЯ.
//!
//! Слово уходит соседу по стрелке; показание уходит вбок и не читается никем. Композиция цепляет
//! слова и ПЕРЕМНОЖАЕТ показания: двум звеньям не нужно говорить на одном языке, чтобы их
//! показания сложились, — а кто сказал, называет позиция в типе.
use reflex_core::mealy::{Id, Mealy, MealyExt};
use reflex_core::word::{Base, Word};

struct Bench;
impl Base for Bench {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Count(u8);
impl Word for Count {
    type Of = Bench;
}

/// СЧИТАЕТ ВХОДЫ И ОТМЕЧАЕТ, СКОЛЬКО ИХ БЫЛО ДО ЭТОГО.
#[derive(Debug, Clone, Copy)]
struct Counting(u8);

impl Mealy for Counting {
    type In = Count;
    type Out = Count;
    type Log = u8;

    fn step(self, input: Count) -> (Self, Count, u8) {
        (Counting(self.0 + 1), Count(input.0 + 1), self.0)
    }
}

/// УДВАИВАЕТ И НЕ ОТМЕЧАЕТ НИЧЕГО — «нечего сказать» выражено ТИПОМ.
#[derive(Debug, Clone, Copy)]
struct Doubling;

impl Mealy for Doubling {
    type In = Count;
    type Out = Count;
    type Log = ();

    fn step(self, input: Count) -> (Self, Count, ()) {
        (self, Count(input.0 * 2), ())
    }
}

#[test]
fn composition_multiplies_the_notes() {
    let chain = Counting(0).then(Doubling);
    let (_, said, notes) = chain.step(Count(1));

    assert_eq!(said, Count(4), "слова сцепились: (1+1)*2");
    assert_eq!(
        notes,
        (0u8, ()),
        "показания перемножились, и позиция называет автора"
    );
}

#[test]
fn nothing_to_note_weighs_nothing() {
    // «Пусто» здесь по ТИПУ, а не по проверке в работе: пустые показания не занимают памяти.
    assert_eq!(
        core::mem::size_of::<<Doubling as Mealy>::Log>(),
        0,
        "пустое показание обязано быть бесплатным"
    );
}

#[test]
fn identity_notes_nothing() {
    // Звено, отмечающее что-либо, соседям не безразлично — значит тождеством не является.
    let (_, said, notes) = Id::<Count>::new().step(Count(7));
    assert_eq!(said, Count(7));
    assert_eq!(notes, ());
}
