//! «НЕ РАЗОБРАЛОСЬ» — БУКВА, А НЕ СЧЁТЧИК В КРАЮ.
//!
//! Пока такой буквы нет, наблюдение «пришло, но разобрать не смог» выразить нечем, и его
//! приходится считать руками ДО того, как родится событие. Ради этого счётчика держится второй
//! разбор пакета и переезд сырых байтов через шов.
//!
//! С буквой счётчик встаёт на цепочку — обычным звеном, считающим то, что видит.
use std::time::Instant;

use reflex_core::detector::DetectorEvent;
use reflex_core::mealy::Mealy;
use reflex_core::parse::Unread;
use reflex_core::word::{Base, Word};
use smallvec::SmallVec;

/// ОБЛАСТЬ ЗАКОННОГО СТЕНДА.
///
/// Объявляется здесь, а не в фундаменте: закон обязан быть выразим для того, кто заводит свою
/// область снаружи, и стенд — законный заводящий.
struct Bench;
impl Base for Bench {
    type Fibre = ();
}

/// СЧЁТ СТЕНДА: разобранное и непонятое. С именем, а не голой парой чисел — адрес объявляет
/// значение, а числа молчат.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Tally(u32, u32);

impl Word for Tally {
    type Of = Bench;
}

/// Звено, считающее непонятое. Ровно то, ради чего буква заводится.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Counting {
    seen: u32,
    unread: u32,
}

impl Mealy for Counting {
    type In = DetectorEvent<u8>;
    type Out = SmallVec<[Tally; 2]>;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        let next = match event {
            DetectorEvent::Packet { .. } => Counting {
                seen: self.seen + 1,
                ..self
            },
            DetectorEvent::Opaque { .. } => Counting {
                unread: self.unread + 1,
                ..self
            },
            DetectorEvent::Tick { .. } | DetectorEvent::Torn { .. } => self,
        };
        (
            next,
            SmallVec::from_slice(&[Tally(next.seen, next.unread)]),
            (),
        )
    }
}

fn opaque(why: Unread) -> DetectorEvent<u8> {
    DetectorEvent::Opaque {
        why,
        at: Instant::now(),
    }
}

#[test]
fn unread_is_counted_by_the_chain_not_by_the_edge() {
    let events = vec![
        DetectorEvent::Packet {
            input: 1u8,
            at: Instant::now(),
        },
        opaque(Unread::NotIpv4),
        opaque(Unread::Truncated),
    ];

    let (counted, _, ()) = events.into_iter().fold(
        (Counting::default(), SmallVec::new(), ()),
        |(machine, _, ()), event| machine.step(event),
    );

    assert_eq!(counted.seen, 1, "разобранное сосчитано");
    assert_eq!(counted.unread, 2, "непонятое сосчитано ТАМ ЖЕ, а не в краю");
}

#[test]
fn the_reason_is_a_value_whose_completeness_the_compiler_guards() {
    // ПРИЧИНА — ЗНАЧЕНИЕ, А НЕ ФЛАГ. «Не наш протокол» и «обрезан» лечатся по-разному:
    // первое законно и вечно, второе означает потерю и может чиниться.
    let (_, told, ()) = Counting::default().step(opaque(Unread::Truncated));
    assert_eq!(&told[..], &[Tally(0, 1)]);

    // ПОЛНОТУ СТОРОЖИТ КОМПИЛЯТОР — не длина литерала (она равна трём всегда и не упадёт
    // ни от какой четвёртой причины), а исчерпывающий `match` БЕЗ `_`: заведи кто-нибудь
    // четвёртый вариант `Unread`, эта функция перестанет собираться, а не промолчит.
    fn describe(reason: Unread) -> &'static str {
        match reason {
            Unread::NotIpv4 => "не IPv4 — адреса и протокола выше взять неоткуда",
            Unread::NotOurProtocol => "не TCP и не UDP — разбирать нечем",
            Unread::Truncated => "обрезан — заголовок не поместился целиком",
        }
    }

    assert_eq!(
        describe(Unread::NotIpv4),
        "не IPv4 — адреса и протокола выше взять неоткуда"
    );
    assert_eq!(
        describe(Unread::NotOurProtocol),
        "не TCP и не UDP — разбирать нечем"
    );
    assert_eq!(
        describe(Unread::Truncated),
        "обрезан — заголовок не поместился целиком"
    );
}
