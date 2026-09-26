//! УДЕРЖАНИЕ (#348): кусок приветствия, пришедший раньше имени, не уходит без решения — его
//! вердикт выносится после куска с именем, по порядку прихода и решением двери.
//!
//! Замер, которым это оплачено (стенд 26.09): имя во втором куске — первый кусок уходил без марки
//! мимо движка, имя к фильтру открытым, и 0 из 62 таких разговоров на канарейке получили данные.
#![cfg(feature = "telling")]

mod paper;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use paper::{segment, syn, PaperEdge};
use reflex::carrier::{
    Answered, Delivered, Held, Layout, Observed, Refused, Served, Serves, Terminal,
};
use reflex::telling::Telling;
use reflex::*;
use reflex_core::mark::{Marked, Region};

#[derive(Clone, Copy, Default)]
struct Always;

impl Mealy for Always {
    type In = DetectorEvent<Seen>;
    type Out = SmallVec<[Distress; 2]>;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        match event {
            DetectorEvent::Packet { .. } => (self, smallvec![Distress::NoBytes], ()),
            DetectorEvent::Tick { .. }
            | DetectorEvent::Opaque { .. }
            | DetectorEvent::Torn { .. } => (self, SmallVec::new(), ()),
        }
    }
}

fn leg() -> Region {
    Region::new(0x0000_0F00).expect("связная область")
}

/// Кадр очереди: номер, по которому ему выносят вердикт, и байты.
struct Frame {
    id: u32,
    bytes: Vec<u8>,
}

impl Observed for Frame {
    fn payload(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Word {
    Pass,
    Remembered(u32),
    Held,
}

/// Когда вынесен вердикт: сразу, в том же обороте, или позже — удержанному.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum When {
    Now,
    Later,
}

/// Вердикт, как его получила бы очередь: номер кадра, слово и когда — в порядке, в каком ушли.
type Verdicts = Arc<Mutex<Vec<(u32, Word, When)>>>;

/// Очередь, которая держит: отдаёт кадры по списку, а вердикт выносит сразу или позже по номеру.
struct Queue {
    frames: VecDeque<Frame>,
    verdicts: Verdicts,
    /// Сколько оборотов простоять после последнего кадра — срок удержания меряется ими.
    idle: u32,
}

#[derive(Debug)]
enum Never {}

impl Queue {
    fn told(&self, id: u32, word: Word, when: When) {
        self.verdicts.lock().expect("журнал").push((id, word, when));
    }
}

impl Terminal for Queue {
    type Carrier = Frame;
    type Answer = Word;
    type Refusal = Never;

    fn apply(
        &mut self,
        answered: Answered<Frame, Word>,
    ) -> Result<Delivered<Word>, Refused<Word, Never>> {
        match answered.answer {
            Word::Held => (),
            Word::Pass | Word::Remembered(_) => {
                self.told(answered.carrier.id, answered.answer.clone(), When::Now)
            }
        }
        Ok(Delivered {
            at: answered.at,
            answer: answered.answer,
        })
    }
}

impl CanHold for Queue {
    fn release() -> Word {
        Word::Pass
    }
}

impl CanRemember for Queue {
    fn remember(state: u32, _accept: bool) -> Word {
        Word::Remembered(state)
    }
}

impl CanDefer for Queue {
    type Token = u32;

    fn deferred(carrier: &Frame) -> Option<(u32, Word)> {
        Some((carrier.id, Word::Held))
    }

    fn settle(
        &mut self,
        token: u32,
        answer: Word,
        at: Instant,
    ) -> Result<Delivered<Word>, Refused<Word, Never>> {
        self.told(token, answer.clone(), When::Later);
        Ok(Delivered { at, answer })
    }
}

impl Serves for Queue {
    type Edge = PaperEdge;

    fn serve<F>(
        &mut self,
        until: Instant,
        decide: F,
    ) -> Served<Delivered<Word>, Refused<Word, Never>>
    where
        F: FnOnce(&Held<Frame>, Option<PaperEdge>) -> Word,
    {
        match self.frames.pop_front() {
            Some(frame) => {
                let held = Held::new(frame, Instant::now());
                let answer = decide(&held, None);
                Served::Answered(self.apply(held.answered(answer)))
            }
            None => {
                std::thread::sleep(until.saturating_duration_since(Instant::now()));
                self.idle = self.idle.saturating_sub(1);
                Served::Idle
            }
        }
    }

    fn exhausted(&self) -> bool {
        self.frames.is_empty() && self.idle == 0
    }
}

/// Рецепт очереди.
struct Queued {
    frames: Vec<Vec<u8>>,
    verdicts: Verdicts,
    idle: u32,
}

impl IntoCarrier for Queued {
    type Carrier = Queue;

    fn open(self) -> Result<Queue, Cause> {
        Ok(Queue {
            frames: self
                .frames
                .into_iter()
                .enumerate()
                .map(|(nth, bytes)| Frame {
                    id: nth as u32,
                    bytes,
                })
                .collect(),
            verdicts: self.verdicts,
            idle: self.idle,
        })
    }

    fn layout(&self) -> Layout {
        Layout::preset()
    }

    fn name(&self) -> String {
        "держащая очередь".to_string()
    }
}

/// Вердикты прогона: кадры идут по порядку, решение двери по имени `x.example` положено заранее.
fn verdicts(frames: Vec<Vec<u8>>, idle: u32) -> Vec<(u32, Word, When)> {
    let journal: Verdicts = Arc::new(Mutex::new(Vec::new()));
    let telling = Telling::over(leg());
    let posting = telling.clone();
    engine(Queued {
        frames,
        verdicts: journal.clone(),
        idle,
    })
    .from(Tcp)
    .extract(Sni)
    .detect(own(Always))
    .telling(telling)
    // Решение кладётся на первом же пакете — рукопожатии, до приветствия: дверь подписывается при
    // постройке цепочки, и сказанное до неё не доходит.
    .on(move |_target: &str, _distress: Distress| {
        assert!(posting.tell("x.example", 0b1010), "решение обязано влезть");
    })
    .run();
    let verdicts = journal.lock().expect("журнал").clone();
    verdicts
}

/// Решение двери, которое несёт вердикт.
fn decided(word: &Word) -> Option<u32> {
    match word {
        Word::Remembered(state) => Some(Marked::read(&leg(), *state)),
        Word::Pass | Word::Held => None,
    }
}

fn hello() -> Vec<u8> {
    reflex_core::tls::build_client_hello("x.example")
}

/// Номер кадра и когда ему вынесен вердикт.
fn when(verdicts: &[(u32, Word, When)]) -> Vec<(u32, When)> {
    verdicts
        .iter()
        .map(|(id, _word, when)| (*id, *when))
        .collect()
}

/// ПРЕДМЕТ: имя во втором куске — первый кусок отпущен ПОСЛЕ второго не был, а вместе с ним, по
/// порядку, и оба несут решение двери.
#[test]
fn a_piece_before_the_name_is_released_after_it_in_order_with_the_decision() {
    let hello = hello();
    let (first, second) = hello.split_at(20);
    let verdicts = verdicts(
        vec![
            syn(40001),
            segment(40001, 1, first),
            segment(40001, 1 + first.len() as u32, second),
        ],
        2,
    );

    assert_eq!(
        when(&verdicts),
        [(0, When::Now), (1, When::Later), (2, When::Later)],
        "куски удержаны и отпущены по порядку прихода: {verdicts:?}"
    );
    assert_eq!(
        decided(&verdicts[1].1),
        Some(0b1010),
        "первый кусок несёт решение: {verdicts:?}"
    );
    assert_eq!(
        decided(&verdicts[2].1),
        Some(0b1010),
        "и кусок с именем: {verdicts:?}"
    );
}

/// Имя так и не пришло — удержанный отпускается по сроку, без решения: держать дольше значит
/// платить задержкой человека за разговор, который мы всё равно не назвали.
#[test]
fn a_piece_whose_name_never_comes_is_released_by_the_deadline() {
    let hello = hello();
    let (first, _lost) = hello.split_at(20);
    let started = Instant::now();
    let verdicts = verdicts(vec![syn(40001), segment(40001, 1, first)], 12);

    assert_eq!(
        when(&verdicts),
        [(0, When::Now), (1, When::Later)],
        "удержанный обязан быть отпущен: {verdicts:?}"
    );
    assert_eq!(decided(&verdicts[1].1), None, "и без решения — имени нет");
    assert!(
        started.elapsed() >= Duration::from_secs(1),
        "и не раньше срока"
    );
}

/// Приветствие одним куском не держится: имя в нём, вердикт выносится сразу.
#[test]
fn a_whole_hello_is_not_held() {
    let verdicts = verdicts(vec![syn(40001), segment(40001, 1, &hello())], 2);

    assert_eq!(
        when(&verdicts),
        [(0, When::Now), (1, When::Now)],
        "{verdicts:?}"
    );
}

/// Приветствие целиком, но без имени: ждать нечего — держать значило бы задержать человека даром.
#[test]
fn a_whole_hello_without_a_name_is_not_held() {
    let nameless = [0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00];
    let verdicts = verdicts(vec![syn(40001), segment(40001, 1, &nameless)], 2);

    assert_eq!(
        when(&verdicts),
        [(0, When::Now), (1, When::Now)],
        "{verdicts:?}"
    );
}
