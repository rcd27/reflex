//! ОТВЕТ — ЗНАЧЕНИЕ, ЭФФЕКТ — ТЕРМИНАЛЬНЫЙ МОРФИЗМ. Законы того, что ничего не съедается.
//!
//! Невод 1 отстрелил здесь ногу дважды, и обе видно в его коде. Вердикт был ВЫЗОВОМ
//! (`msg.set_verdict(…); let _ = queue.verdict(msg)`) — записать, сравнить и развернуть назад его
//! нельзя. А рядом, в том же выражении, `let _ =` выбрасывал единственный факт о ДОСТАВКЕ: ядро
//! могло отказать, и мы бы не узнали. Четыре вердикта — четыре выброшенных свидетельства.
//!
//! Здесь и то, и другое разведено: цепочка порождает ЗНАЧЕНИЕ, а мира касается ровно одно место.

use reflex_core::held::{Answered, Held, Terminal};
use std::time::{Duration, Instant};

/// Чем отвечают ЭТОМУ носителю. У очереди ядра будет свой алфавит; здесь — расписка.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Word {
    Pass,
    Stop,
}

/// Носитель права ответа: в бою сообщение ядра, здесь — номерок.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ticket(u32);

/// МИР ЗА ТЕРМИНАЛОМ. Единственное место с `&mut`, и оно же единственное, где что-то случается.
struct Window {
    took: Vec<(Ticket, Word)>,
    refuses: bool,
}

impl Window {
    fn open() -> Self {
        Self {
            took: Vec::new(),
            refuses: false,
        }
    }
    fn shut() -> Self {
        Self {
            took: Vec::new(),
            refuses: true,
        }
    }
}

impl Terminal for Window {
    type Carrier = Ticket;
    type Answer = Word;
    type Refusal = &'static str;

    fn apply(
        &mut self,
        answered: Answered<Ticket, Word>,
    ) -> Result<reflex_core::held::Delivered<Word>, reflex_core::held::Refused<Word, &'static str>>
    {
        match self.refuses {
            true => Err(answered.refused("окно закрыто")),
            false => {
                self.took.push((answered.carrier, answered.answer));
                Ok(answered.delivered())
            }
        }
    }
}

fn held(at: Instant) -> Held<Ticket> {
    Held::new(Ticket(7), vec![1u8, 2, 3], at)
}

/// РЕШЕНИЕ НЕ ЕСТЬ ЭФФЕКТ. Пока значение не дошло до терминала, в мире не случилось НИЧЕГО.
///
/// Это и есть разрыв, который лечится: прежде `answered` сам звал носителя, то есть цепочка
/// трогала мир посередине и не могла быть значением.
#[test]
fn deciding_is_not_doing_nothing_happens_until_the_terminal() {
    let mut window = Window::open();
    let _answered = held(Instant::now()).answered(Word::Pass);

    assert!(
        window.took.is_empty(),
        "решение принято, а мира никто не касался"
    );
    let _ = &mut window;
}

/// ДОСТАВКА — ОТДЕЛЬНОЕ СВИДЕТЕЛЬСТВО, и его выдаёт МИР, а не мы.
#[test]
fn delivery_is_witnessed_by_the_world_not_by_us() {
    let at = Instant::now();
    let mut window = Window::open();

    let outcome = window.apply(held(at).answered(Word::Pass));

    match outcome {
        Err(_refused) => panic!("окно было открыто, а ответ не принят"),
        Ok(delivered) => {
            assert_eq!(delivered.answer, Word::Pass);
            assert_eq!(delivered.seen, vec![1, 2, 3], "предмет пережил доставку");
            assert_eq!(delivered.at, at, "и момент тоже");
        }
    }
    assert_eq!(window.took, vec![(Ticket(7), Word::Pass)]);
}

/// ОТКАЗ МИРА НЕ ТЕРЯЕТСЯ. Прежде здесь стоял `let _ =`, и отказ ядра исчезал бесследно.
#[test]
fn a_refusal_by_the_world_is_kept_not_discarded() {
    let at = Instant::now();
    let mut window = Window::shut();

    let outcome = window.apply(held(at).answered(Word::Stop));

    match outcome {
        Ok(_delivered) => panic!("окно закрыто, а ответ объявлен доставленным"),
        Err(refused) => {
            assert_eq!(refused.why, "окно закрыто", "причина названа");
            assert_eq!(refused.answer, Word::Stop, "и чем отвечали — цело");
            assert_eq!(refused.seen, vec![1, 2, 3], "и предмет цел");
            assert_eq!(refused.at, at);
        }
    }
}

/// НАБЛЮДЕНИЕ ЧИТАЕТСЯ НА ЛЮБОМ ШАГЕ. Ответ не отнимает у дела его предмет.
#[test]
fn what_was_seen_is_readable_at_every_step() {
    let at = Instant::now() - Duration::from_secs(3);
    let waiting = held(at);
    assert_eq!(waiting.seen(), &[1, 2, 3]);
    assert_eq!(waiting.seen(), &[1, 2, 3], "чтение не съедает");

    let decided = waiting.answered(Word::Pass);
    assert_eq!(decided.seen, vec![1, 2, 3]);
    assert_eq!(decided.at, at);
}

// ЗАКОН «ЗАБЫТОЕ РЕШЕНИЕ — ОШИБКА КОМПИЛЯТОРА» ЖИВЁТ У `Answered`, А НЕ ЗДЕСЬ.
//
// Первая редакция положила его сюда `compile_fail`-докстрингом — и он не гонялся НИ РАЗУ:
// doc-тесты собираются только у библиотечной цели, интеграционные их не видят. Проверено
// (`cargo test --doc` не знает ни одного теста из `tests/`), и это ровно тот класс, что репа ловит
// у себя каждый день: написано и не зовётся.
