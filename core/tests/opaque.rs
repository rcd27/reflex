//! «НЕ РАЗОБРАЛОСЬ» — БУКВА, А НЕ СЧЁТЧИК В КРАЮ.
//!
//! Пока такой буквы нет, наблюдение «пришло, но разобрать не смог» выразить нечем, и его
//! приходится считать руками ДО того, как родится событие. Ради этого счётчика держится второй
//! разбор пакета и переезд сырых байтов через шов.
//!
//! С буквой счётчик встаёт на цепочку — обычным звеном, считающим то, что видит.
use std::time::Instant;

use reflex_core::detector::DetectorEvent;
use reflex_core::parse::Unread;
use reflex_core::step::Step;
use smallvec::SmallVec;

/// Звено, считающее непонятое. Ровно то, ради чего буква заводится.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Counting {
    seen: u32,
    unread: u32,
}

impl Step for Counting {
    type From = DetectorEvent<u8>;
    type To = SmallVec<[(u32, u32); 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
        let next = match event {
            DetectorEvent::Packet { .. } => Counting {
                seen: self.seen + 1,
                ..self
            },
            DetectorEvent::Opaque { .. } => Counting {
                unread: self.unread + 1,
                ..self
            },
            DetectorEvent::Tick { .. } => self,
        };
        (next, SmallVec::from_slice(&[(next.seen, next.unread)]))
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

    let (counted, _) = events.into_iter().fold(
        (Counting::default(), SmallVec::new()),
        |(machine, _), event| machine.step(event),
    );

    assert_eq!(counted.seen, 1, "разобранное сосчитано");
    assert_eq!(counted.unread, 2, "непонятое сосчитано ТАМ ЖЕ, а не в краю");
}

#[test]
fn the_reason_is_a_value_whose_completeness_the_compiler_guards() {
    // ПРИЧИНА — ЗНАЧЕНИЕ, А НЕ ФЛАГ. «Не наш протокол» и «обрезан» лечатся по-разному:
    // первое законно и вечно, второе означает потерю и может чиниться.
    let (_, told) = Counting::default().step(opaque(Unread::Truncated));
    assert_eq!(&told[..], &[(0, 1)]);

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
