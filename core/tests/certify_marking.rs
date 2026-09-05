//! ЗАКОН МЕТКИ: ПОМЕТИЛИ — И ТОТ, КТО НИЖЕ, ЭТО ПРОЧИТАЛ.
//!
//! # Единственный закон, чей свидетель не смотрит на провод
//!
//! Метка не уезжает в сеть. Она живёт внутри ядра и адресована не собеседнику, а правилам, стоящим
//! ниже по обходу пакета. Поэтому `dumpcap` тут бесполезен по построению, и свидетельствовать
//! способен только ЧИТАТЕЛЬ — правило со счётчиком, поставленное ниже очереди.
//!
//! # Грабля, ради которой закон и заведён
//!
//! Пакет продолжает обход С МЕСТА, ГДЕ ЕГО ЗАБРАЛИ. Правило, читающее метку, обязано стоять НИЖЕ
//! правила очереди; поставь его выше — метка встанет и не будет прочитана НИКЕМ, а прибор покажет
//! «решение принято».
//!
//! Знание это записано в коде у `Answer::Marked` с 31.08.2026 и до сегодня не проверялось ничем.
//! Изнутри процесса «метку поставили» и «метку прочитали» неотличимы совершенно: вердикт вынесен,
//! `Delivered` подтверждает, счётчик движется — а тот, для кого метка ставилась, о ней не узнал.

use reflex_core::capability::CanMark;
use reflex_core::certify::marking::{marks, Broken, Invalid, Reader};
use reflex_core::certify::Verdict;
use reflex_core::held::{Answered, Delivered, Held, Observed, Refused, Terminal};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Instant;

type Downhill = Rc<RefCell<Vec<Vec<u8>>>>;
/// СКОЛЬКО ПАКЕТОВ С МЕТКОЙ ПРОЧИТАЛ ТОТ, КТО НИЖЕ. В бою — счётчик правила `meta mark`.
type Tally = Rc<RefCell<usize>>;

const MARK: u32 = 0x2a;
const OURS: &[u8] = b"\x45\x00nonce-mark-5e";

struct Envelope(Vec<u8>);

impl Observed for Envelope {
    fn payload(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Word {
    Marked(u32),
}

/// ЧЕСТНАЯ СВЯЗКА: очередь метит, читатель НИЖЕ метку видит.
struct Honest {
    downhill: Downhill,
    tally: Tally,
}

impl Terminal for Honest {
    type Carrier = Envelope;
    type Answer = Word;
    type Refusal = ();

    fn apply(
        &mut self,
        answered: Answered<Envelope, Word>,
    ) -> Result<Delivered<Word>, Refused<Word, ()>> {
        let Word::Marked(_mark) = &answered.answer;
        self.downhill.borrow_mut().push(answered.carrier.0.clone());
        *self.tally.borrow_mut() += 1;
        Ok(Delivered {
            at: answered.at,
            answer: answered.answer,
        })
    }
}

impl CanMark for Honest {
    fn mark(mark: u32) -> Word {
        Word::Marked(mark)
    }
}

/// ЧИТАТЕЛЬ СТОИТ ВЫШЕ ОЧЕРЕДИ — ТА САМАЯ ГРАБЛЯ.
///
/// Пакет проходит, метка на него встаёт, и никто её не читает: правило-читатель осталось позади,
/// пакет продолжил обход с места, где его забрали. Типом это невыразимо совершенно — порядок
/// правил живёт в чужой машине.
struct ReaderAbove(Downhill);

impl Terminal for ReaderAbove {
    type Carrier = Envelope;
    type Answer = Word;
    type Refusal = ();

    fn apply(
        &mut self,
        answered: Answered<Envelope, Word>,
    ) -> Result<Delivered<Word>, Refused<Word, ()>> {
        // Пакет идёт дальше, счётчик читателя не двигается: он уже позади.
        self.0.borrow_mut().push(answered.carrier.0.clone());
        Ok(Delivered {
            at: answered.at,
            answer: answered.answer,
        })
    }
}

impl CanMark for ReaderAbove {
    fn mark(mark: u32) -> Word {
        Word::Marked(mark)
    }
}

/// ОЧЕРЕДЬ, КОТОРАЯ ПОМЕТИЛА, НО ПАКЕТ НЕ ОТПУСТИЛА.
struct Muted;

impl Terminal for Muted {
    type Carrier = Envelope;
    type Answer = Word;
    type Refusal = ();

    fn apply(
        &mut self,
        answered: Answered<Envelope, Word>,
    ) -> Result<Delivered<Word>, Refused<Word, ()>> {
        Ok(Delivered {
            at: answered.at,
            answer: answered.answer,
        })
    }
}

impl CanMark for Muted {
    fn mark(mark: u32) -> Word {
        Word::Marked(mark)
    }
}

/// ЖИВОЙ СВИДЕТЕЛЬ ПРОВОДА: всегда показывает фон плюс прошедшее с прошлого вопроса.
struct Below(Downhill);

impl reflex_core::certify::Downstream for Below {
    fn passed(&mut self) -> Vec<Vec<u8>> {
        let fresh: Vec<Vec<u8>> = std::mem::take(&mut *self.0.borrow_mut());
        std::iter::once(b"background chatter".to_vec())
            .chain(fresh)
            .collect()
    }
}

/// МЁРТВЫЙ СВИДЕТЕЛЬ ПРОВОДА.
struct Dead;

impl reflex_core::certify::Downstream for Dead {
    fn passed(&mut self) -> Vec<Vec<u8>> {
        Vec::new()
    }
}

/// ЧИТАТЕЛЬ МЕТКИ: счётчик того, кто стоит ниже.
struct Counting(Tally);

impl Reader for Counting {
    fn read(&mut self, _mark: u32) -> usize {
        let seen = *self.0.borrow();
        *self.0.borrow_mut() = 0;
        seen
    }
}

fn held() -> Held<Envelope> {
    Held::new(Envelope(OURS.to_vec()), Instant::now())
}

fn stand() -> (Downhill, Tally, Below, Counting) {
    let downhill: Downhill = Rc::new(RefCell::new(Vec::new()));
    let tally: Tally = Rc::new(RefCell::new(0));
    let below = Below(Rc::clone(&downhill));
    let counting = Counting(Rc::clone(&tally));
    (downhill, tally, below, counting)
}

/// ЧЕСТНАЯ СВЯЗКА ЗАКОН ДЕРЖИТ: пометили, прошло, читатель ниже увидел.
#[test]
fn a_mark_that_the_reader_below_sees_keeps_the_law() {
    let (downhill, tally, mut below, mut reader) = stand();

    let outcome = marks(
        &mut Honest {
            downhill,
            tally: Rc::clone(&tally),
        },
        held(),
        MARK,
        &mut below,
        &mut reader,
    );

    assert_eq!(outcome, Verdict::Held);
}

/// ЧИТАТЕЛЬ ВЫШЕ ОЧЕРЕДИ — ГЛАВНАЯ ПРОВЕРКА ФАЙЛА.
///
/// Ровно та грабля, что записана у `Answer::Marked` словами и до сегодня не проверялась: метка
/// поставлена, пакет прошёл, а тот, ради кого метка ставилась, о ней не узнал.
#[test]
fn a_reader_standing_above_the_queue_is_caught() {
    let (downhill, _tally, mut below, mut reader) = stand();

    let outcome = marks(
        &mut ReaderAbove(downhill),
        held(),
        MARK,
        &mut below,
        &mut reader,
    );

    assert_eq!(outcome, Verdict::Broken(Broken::MarkUnread));
}

/// ПОМЕТИЛИ — И НЕ ПРОШЛО. Другая беда: метка тут ни при чём, пакета просто нет.
#[test]
fn a_marked_packet_that_never_passes_is_its_own_trouble() {
    let (_downhill, _tally, mut below, mut reader) = stand();

    let outcome = marks(&mut Muted, held(), MARK, &mut below, &mut reader);

    assert_eq!(outcome, Verdict::Broken(Broken::NotPassed));
}

/// МЁРТВЫЙ СВИДЕТЕЛЬ ПРОВОДА НЕ ДАЁТ ВЕРДИКТА.
///
/// Без него «не прошло» и «не смотрели» слились бы, и `NotPassed` предъявлялся бы всякий раз,
/// когда сломался стенд. Урок, который в этот день пришлось выучить дважды.
#[test]
fn a_dead_witness_gives_the_mark_no_verdict() {
    let (_downhill, tally, _below, mut reader) = stand();

    let outcome = marks(
        &mut Honest {
            downhill: Rc::new(RefCell::new(Vec::new())),
            tally,
        },
        held(),
        MARK,
        &mut Dead,
        &mut reader,
    );

    assert_eq!(outcome, Verdict::Invalid(Invalid::WitnessSilent));
}

/// ПАКЕТ, УШЕДШИЙ ДО ОТВЕТА, ДЕЛАЕТ ПРОГОН НЕДЕЙСТВИТЕЛЬНЫМ.
#[test]
fn a_packet_gone_before_the_answer_invalidates_the_run() {
    let (downhill, tally, mut below, mut reader) = stand();
    downhill.borrow_mut().push(OURS.to_vec());

    let outcome = marks(
        &mut Honest {
            downhill: Rc::clone(&downhill),
            tally,
        },
        held(),
        MARK,
        &mut below,
        &mut reader,
    );

    assert_eq!(outcome, Verdict::Invalid(Invalid::NotHeld));
}
