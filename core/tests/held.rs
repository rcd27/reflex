//! ОТВЕТ — ЗНАЧЕНИЕ, ЭФФЕКТ — ТЕРМИНАЛЬНЫЙ МОРФИЗМ, БАЙТЫ — НЕ НАШИ.
//!
//! Невод 1 отстрелил здесь ногу дважды, и обе видно в одном выражении: вердикт был ВЫЗОВОМ
//! (`msg.set_verdict(…); let _ = queue.verdict(msg)`), а `let _ =` выбрасывал единственный факт о
//! ДОСТАВКЕ. Четыре вердикта — четыре выброшенных свидетельства.
//!
//! Третья беда была моя и вчерашняя: свидетельство несло КОПИЮ полезной нагрузки. Дёшево на вид и
//! неограниченно по памяти — при том что сырьё у нас снимает независимый прибор, а дело помнит
//! УЛИКУ, а не байты.

use reflex_core::held::{Answered, Held, Observed, Terminal};
use std::time::{Duration, Instant};

/// Чем отвечают ЭТОМУ носителю. У очереди ядра будет свой алфавит; здесь — расписка.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Word {
    Pass,
    Stop,
}

/// Носитель права ответа: в бою сообщение ядра, здесь — конверт с байтами.
struct Envelope {
    id: u32,
    bytes: Vec<u8>,
}

impl Observed for Envelope {
    fn payload(&self) -> &[u8] {
        &self.bytes
    }
}

/// МИР ЗА ТЕРМИНАЛОМ. Единственное место с `&mut`, и оно же единственное, где что-то случается.
struct Window {
    took: Vec<(u32, Word)>,
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
    type Carrier = Envelope;
    type Answer = Word;
    type Refusal = &'static str;

    fn apply(
        &mut self,
        answered: Answered<Envelope, Word>,
    ) -> Result<reflex_core::held::Delivered<Word>, reflex_core::held::Refused<Word, &'static str>>
    {
        let Answered {
            carrier,
            at,
            answer,
        } = answered;
        match self.refuses {
            true => Err(reflex_core::held::Refused {
                at,
                answer,
                why: "окно закрыто",
            }),
            false => {
                self.took.push((carrier.id, answer));
                Ok(reflex_core::held::Delivered { at, answer })
            }
        }
    }
}

fn held(at: Instant) -> Held<Envelope> {
    Held::new(
        Envelope {
            id: 7,
            bytes: vec![1u8, 2, 3],
        },
        at,
    )
}

/// НАБЛЮДЕНИЕ ЧИТАЕТСЯ У НОСИТЕЛЯ, А НЕ КОПИРУЕТСЯ В НАС.
///
/// Прежняя редакция клала `Vec<u8>` в само дело — то есть аллокацию на КАЖДЫЙ пакет и копию
/// полезной нагрузки в записи. Байты принадлежат носителю, пока он жив; дальше их место в сырье,
/// снятом независимым прибором.
#[test]
fn what_was_seen_is_read_from_the_carrier_not_copied_into_us() {
    let waiting = held(Instant::now());

    assert_eq!(waiting.seen(), &[1, 2, 3]);
    assert_eq!(waiting.seen(), &[1, 2, 3], "чтение не съедает наблюдение");
}

/// РЕШЕНИЕ НЕ ЕСТЬ ЭФФЕКТ. Пока значение не дошло до терминала, в мире не случилось НИЧЕГО.
#[test]
fn deciding_is_not_doing_nothing_happens_until_the_terminal() {
    let window = Window::open();
    let _answered = held(Instant::now()).answered(Word::Pass);

    assert!(
        window.took.is_empty(),
        "решение принято, а мира никто не касался"
    );
}

/// ДОСТАВКА — ОТДЕЛЬНОЕ СВИДЕТЕЛЬСТВО, и его выдаёт МИР, а не мы.
#[test]
fn delivery_is_witnessed_by_the_world_not_by_us() {
    let at = Instant::now();
    let mut window = Window::open();

    match window.apply(held(at).answered(Word::Pass)) {
        Err(_refused) => panic!("окно было открыто, а ответ не принят"),
        Ok(delivered) => {
            assert_eq!(delivered.answer, Word::Pass);
            assert_eq!(delivered.at, at, "момент пережил доставку");
        }
    }
    assert_eq!(window.took, vec![(7, Word::Pass)]);
}

/// ОТКАЗ МИРА НЕ ТЕРЯЕТСЯ. Прежде здесь стоял `let _ =`, и отказ ядра исчезал бесследно.
#[test]
fn a_refusal_by_the_world_is_kept_not_discarded() {
    let at = Instant::now() - Duration::from_secs(2);
    let mut window = Window::shut();

    match window.apply(held(at).answered(Word::Stop)) {
        Ok(_delivered) => panic!("окно закрыто, а ответ объявлен доставленным"),
        Err(refused) => {
            assert_eq!(refused.why, "окно закрыто", "причина названа");
            assert_eq!(refused.answer, Word::Stop, "и чем отвечали — цело");
            assert_eq!(refused.at, at, "и момент тоже");
        }
    }
}

/// СВИДЕТЕЛЬСТВО НЕ НЕСЁТ БАЙТОВ — И ЭТО ЗАКОН, А НЕ ЭКОНОМИЯ.
///
/// Сырьё снимает независимый прибор, а дело помнит улику — то, что из наблюдения ИЗВЛЕКЛИ.
/// Тащить полезную нагрузку в запись значило бы держать в памяти каждый пакет и при этом
/// дублировать то, что уже лежит на диске.
///
/// Проверяется КОПИРУЕМОСТЬЮ, а не размером: тип, владеющий буфером, `Copy` быть не может по
/// построению. Первая редакция сравнивала `size_of` с суммой полей и покраснела на выравнивании —
/// то есть НЕ НА СВОЮ причину; размер о владении кучей не говорит вовсе.
#[test]
fn a_witness_carries_no_payload_only_the_moment_and_the_answer() {
    use reflex_core::held::{Delivered, Refused};

    fn owns_no_buffer<T: Copy>() {}

    owns_no_buffer::<Delivered<Word>>();
    owns_no_buffer::<Refused<Word, &'static str>>();
}

// ЗАКОН «ЗАБЫТОЕ РЕШЕНИЕ — ОШИБКА КОМПИЛЯТОРА» ЖИВЁТ У `Answered`, А НЕ ЗДЕСЬ.
//
// Первая редакция положила его сюда `compile_fail`-докстрингом — и он не гонялся НИ РАЗУ:
// doc-тесты собираются только у библиотечной цели, интеграционные их не видят. Проверено
// (`cargo test --doc` не знает ни одного теста из `tests/`), и это ровно тот класс, что репа ловит
// у себя каждый день: написано и не зовётся.
