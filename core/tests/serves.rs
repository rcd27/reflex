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
use std::time::Instant;

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

impl Serves for Memo {
    fn serve<F>(&mut self, decide: F) -> Served<Delivered<u8>, Refused<u8, ()>>
    where
        F: FnOnce(&Held<Envelope>) -> u8,
    {
        match self.waiting.is_empty() {
            true => Served::Idle,
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

    let outcome = queue.serve(|held| held.seen().len() as u8);

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

    assert_eq!(queue.serve(|_held| 0), Served::Idle);
}

/// КАЖДЫЙ ВЗЯТЫЙ ПОЛУЧАЕТ РОВНО ОДИН ОТВЕТ.
#[test]
fn every_taken_packet_gets_exactly_one_answer() {
    let answered = Rc::new(RefCell::new(Vec::new()));
    let mut queue = Memo {
        waiting: vec![b"a".to_vec(), b"bb".to_vec(), b"ccc".to_vec()],
        answered: Rc::clone(&answered),
    };

    let served = std::iter::from_fn(|| match queue.serve(|held| held.seen().len() as u8) {
        Served::Answered(done) => Some(done),
        Served::Idle | Served::Blind => None,
    })
    .count();

    assert_eq!(served, 3);
    assert_eq!(*answered.borrow(), vec![1, 2, 3]);
}
