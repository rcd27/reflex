//! ВЗЯТЬ И ОТВЕТИТЬ — ОДИН ШАГ, И ДРУГОГО СПОСОБА НЕТ.
//!
//! Форма заведена после того, как компилятор запретил очереди быть `Source`: поток заимствует
//! бэкенд на всё своё время, а ответ требует второго `&mut`. Здесь конфликта нет по построению —
//! заимствование одно, и внутри него укладываются оба действия.

use reflex_core::held::{Answered, Delivered, Held, Observed, Refused, Terminal};
use reflex_core::serves::Served;
use reflex_core::Serves;
use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};

struct Envelope(Vec<u8>);

impl Observed for Envelope {
    fn payload(&self) -> &[u8] {
        &self.0
    }
}

/// ОЧЕРЕДЬ ПАМЯТНОГО МИРА: отдаёт заготовленные пакеты по одному и помнит ответы.
struct Memo {
    waiting: Vec<Vec<u8>>,
    answered: Rc<RefCell<Vec<u8>>>,
}

impl Terminal for Memo {
    type Carrier = Envelope;
    type Answer = u8;
    type Refusal = ();

    fn apply(
        &mut self,
        answered: Answered<Envelope, u8>,
    ) -> Result<Delivered<u8>, Refused<u8, ()>> {
        self.answered.borrow_mut().push(answered.answer);
        Ok(Delivered {
            at: answered.at,
            answer: answered.answer,
        })
    }
}

impl Memo {
    /// Носитель без работы — играет обе безответные клетки шва (`Idle` в реальной очереди и
    /// `Blind` слепого дескриптора неотличимы отсюда: ни у той, ни у другой нет наблюдения). Закон
    /// шва один на обе: не возвращаться раньше `until`.
    fn empty() -> Self {
        Memo {
            waiting: Vec::new(),
            answered: Rc::new(RefCell::new(Vec::new())),
        }
    }

    /// Носитель с одним пакетом наготове — работа есть, срок её не касается.
    fn with_one_packet() -> Self {
        Memo {
            waiting: vec![b"a".to_vec()],
            answered: Rc::new(RefCell::new(Vec::new())),
        }
    }
}

impl Serves for Memo {
    fn serve<F>(&mut self, until: Instant, decide: F) -> Served<Delivered<u8>, Refused<u8, ()>>
    where
        F: FnOnce(&Held<Envelope>) -> u8,
    {
        match self.waiting.is_empty() {
            // Закон шва: без работы носитель спит до `until` сам — часы у того же, у кого
            // дескриптор. Без сна здесь ведущий цикл был бы вынужден заводить своё ожидание мимо
            // шва, как это уже случилось (регресс 3202628).
            true => {
                std::thread::sleep(until.saturating_duration_since(Instant::now()));
                Served::Idle
            }
            false => {
                let held = Held::new(Envelope(self.waiting.remove(0)), Instant::now());
                let answer = decide(&held);
                Served::Answered(self.apply(held.answered(answer)))
            }
        }
    }
}

/// РЕШЕНИЕ ЧИТАЕТ НАБЛЮДЕНИЕ И ДОХОДИТ ДО МИРА.
#[test]
fn a_decision_made_from_the_observation_reaches_the_world() {
    let answered = Rc::new(RefCell::new(Vec::new()));
    let mut queue = Memo {
        waiting: vec![b"first".to_vec(), b"second".to_vec()],
        answered: Rc::clone(&answered),
    };

    let outcome = queue.serve(Instant::now(), |held| held.seen().len() as u8);

    assert!(
        matches!(outcome, Served::Answered(Ok(_))),
        "ответ доставлен"
    );
    assert_eq!(*answered.borrow(), vec![5], "решение принято по наблюдению");
}

/// ПУСТАЯ ОЧЕРЕДЬ — ЭТО `None`, А НЕ ОШИБКА И НЕ ПУСТОЙ ОТВЕТ.
///
/// Слить «работы не было» с отказом ядра значило бы стереть разницу между тихо и сломано — ту
/// самую, которую весь этот день и разводили по разным вариантам.
#[test]
fn nothing_to_serve_is_not_a_failure() {
    let mut queue = Memo {
        waiting: Vec::new(),
        answered: Rc::new(RefCell::new(Vec::new())),
    };

    assert_eq!(queue.serve(Instant::now(), |_held| 0), Served::Idle);
}

/// КАЖДЫЙ ВЗЯТЫЙ ПОЛУЧАЕТ РОВНО ОДИН ОТВЕТ.
#[test]
fn every_taken_packet_gets_exactly_one_answer() {
    let answered = Rc::new(RefCell::new(Vec::new()));
    let mut queue = Memo {
        waiting: vec![b"a".to_vec(), b"bb".to_vec(), b"ccc".to_vec()],
        answered: Rc::clone(&answered),
    };

    let served = std::iter::from_fn(
        || match queue.serve(Instant::now(), |held| held.seen().len() as u8) {
            Served::Answered(done) => Some(done),
            Served::Idle | Served::Blind | Served::Torn => None,
        },
    )
    .count();

    assert_eq!(served, 3);
    assert_eq!(*answered.borrow(), vec![1, 2, 3]);
}

/// Закон шва: не возвращаться раньше срока, кроме как с работой. Не будь его, ведущий цикл
/// крутился бы вхолостую на пустой очереди — и завёл бы своё ожидание мимо шва, что и случилось.
#[test]
fn пустой_носитель_держит_срок() {
    let mut carrier = Memo::empty();
    let until = Instant::now() + Duration::from_millis(50);

    let outcome = carrier.serve(until, |_held| unreachable!("работы не было"));

    assert!(matches!(outcome, Served::Idle));
    assert!(Instant::now() >= until, "вернулся раньше срока");
}

/// Работа не ждёт срока: пакет отдаётся сразу, иначе задержка решения равнялась бы шагу сетки.
#[test]
fn работа_возвращается_сразу() {
    let mut carrier = Memo::with_one_packet();
    let until = Instant::now() + Duration::from_secs(60);

    let outcome = carrier.serve(until, |_held| 1);

    assert!(matches!(outcome, Served::Answered(Ok(_))));
    assert!(Instant::now() < until, "ждал срока, имея работу");
}
