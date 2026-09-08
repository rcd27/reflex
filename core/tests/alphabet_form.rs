//! ФОРМА АЛФАВИТА ПРЕДЪЯВЛЕНА, А НЕ ОБЕЩАНА.
//!
//! Комбинаторы получают форму конкретными равенствами в границах, без единого нового трейта.
//! Отвергнуто: трейты `Observed`/`Told` на структуру алфавита — они заводят два имени под один
//! употребляющий алфавит, то есть ровно ту болезнь, которую впитывание лечит.
//!
//! Здесь проверяется не поведение комбинаторов (это `detector_combinators.rs`), а то, что форма
//! ВЫРАЗИМА и ВЫВОДИМА: `E0207` не кусается, вложение собирается без аннотаций.
use reflex_core::detector::DetectorEvent;
use reflex_core::mealy::{Mealy, MealyExt};
use reflex_core::word::{Base, Word};
use smallvec::SmallVec;
use std::time::Instant;

/// ОБЛАСТЬ ЗАКОННОГО СТЕНДА.
///
/// Объявляется здесь, а не в фундаменте: закон обязан быть выразим для того, кто заводит свою
/// область снаружи, и стенд — законный заводящий.
struct Bench;
impl Base for Bench {}

/// ПОКАЗАНИЕ СТЕНДА — с именем, а не голым числом: адрес объявляет значение, а число молчит.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Sig(u8);

impl Word for Sig {
    type Of = Bench;
}

/// ПЕРЕИМЕНОВАННОЕ ПОКАЗАНИЕ. Переименование адресата не меняет — область та же.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Loud(u32);

impl Word for Loud {
    type Of = Bench;
}

/// СЛОВО СТЕНДА НА ВХОДЕ: буква алфавита несёт наблюдение, и оно тоже адресное.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Beat(u8);

impl Word for Beat {
    type Of = Bench;
}

#[derive(Clone, Copy)]
struct Rst;

impl Mealy for Rst {
    type In = DetectorEvent<Beat>;
    type Out = SmallVec<[Sig; 2]>;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        match event {
            DetectorEvent::Packet { input: Beat(1), .. } => {
                (self, SmallVec::from_slice(&[Sig(7)]), ())
            }
            DetectorEvent::Packet { .. } => (self, SmallVec::new(), ()),
            DetectorEvent::Tick { .. } => (self, SmallVec::new(), ()),
            DetectorEvent::Opaque { .. } => (self, SmallVec::new(), ()),
        }
    }
}

fn packet(input: u8) -> DetectorEvent<Beat> {
    DetectorEvent::Packet {
        input: Beat(input),
        at: Instant::now(),
    }
}

#[test]
fn оба_слушателя_говорят_каждый_своим_словом() {
    let (_, (left, right), _) = Rst.and(Rst).step(packet(1));
    assert_eq!(&left[..], &[Sig(7)], "левое звено сказало своё");
    assert_eq!(
        &right[..],
        &[Sig(7)],
        "правое звено сказало своё, отдельно от левого"
    );
}

#[test]
fn вложение_комбинаторов_выводится_без_единой_аннотации() {
    // САМОЕ ХРУПКОЕ ДЛЯ ВЫВОДА: комбинатор над комбинатором, да ещё и над одной из сторон
    // произведения. Если форма выражена неверно, падает именно здесь, а не на одиночном звене.
    let (_, (left, right), _) = Rst
        .and(Rst.rmap(|Sig(s)| Loud(s as u32 * 10)))
        .step(packet(1));
    assert_eq!(&left[..], &[Sig(7)], "левое слово не переименовано");
    assert_eq!(
        &right[..],
        &[Loud(70)],
        "переименование прошло сквозь сложение с правой стороны"
    );
}

#[test]
fn тождество_нейтрально_и_в_этой_форме() {
    // Второй закон категории на алфавите детектора: `f ∘ id` даёт то же, что `f`.
    use reflex_core::mealy::Id;
    let (_, прямо, _) = Rst.step(packet(1));
    let (_, через_тождество, _) = Id::<DetectorEvent<Beat>>::new().then(Rst).step(packet(1));
    assert_eq!(прямо, через_тождество, "тождество ничего не изменило");
}
