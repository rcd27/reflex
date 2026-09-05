//! ЗАКОН КАЛИТКИ: ПОКА МЫ НЕ ОТВЕТИЛИ — ПАКЕТ НЕ ИДЁТ ДАЛЬШЕ.
//!
//! # Почему это главный закон очереди, а не один из
//!
//! Продукт стоит на NFQUEUE, и всё, что он делает, опирается на одну посылку: пакет ЖДЁТ нашего
//! решения. Посылка ложна, если правило очереди стоит не там, — и тогда мы не решаем, а
//! КОММЕНТИРУЕМ вдогонку уже ушедшему пакету. Снаружи эти два состояния неотличимы совершенно:
//! счётчики движутся, вердикты выносятся, спаны пишутся, а трафик идёт мимо.
//!
//! Репа уже платила за родственную беду и записала её у `Answer::Marked`: правило, читающее метку,
//! обязано стоять НИЖЕ правила очереди, иначе метка встанет и не будет прочитана никем, «а прибор
//! покажет — решение принято».
//!
//! # Что типом невыразимо
//!
//! Всё. `CanHold` требует [`Terminal`](reflex_core::held::Terminal) и слова отпускания — то есть
//! убивает заявление без предмета. Но ЖДЁТ ли ядро на самом деле, зависит не от нашего кода, а от
//! того, как настроен обход пакета в чужой машине.

use reflex_core::capability::CanHold;
use reflex_core::certify::holding::{holds, Broken, Invalid};
use reflex_core::certify::Verdict;
use reflex_core::held::{Answered, Delivered, Held, Observed, Refused, Terminal};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Instant;

/// ЧТО ПРОШЛО ДАЛЬШЕ ПО СТЕКУ. Общий на двоих: терминал кладёт, дальний конец забирает.
type Downhill = Rc<RefCell<Vec<Vec<u8>>>>;

/// КОНВЕРТ — носитель права ответить в памятном мире.
struct Envelope(Vec<u8>);

impl Observed for Envelope {
    fn payload(&self) -> &[u8] {
        &self.0
    }
}

/// ЧЕСТНАЯ ОЧЕРЕДЬ: держит пакет, пока не ответили, и отпускает ровно по слову.
struct Honest(Downhill);

impl Terminal for Honest {
    type Carrier = Envelope;
    type Answer = Word;
    type Refusal = ();

    fn apply(
        &mut self,
        answered: Answered<Envelope, Word>,
    ) -> Result<Delivered<Word>, Refused<Word, ()>> {
        self.0.borrow_mut().push(answered.carrier.0.clone());
        Ok(Delivered {
            at: answered.at,
            answer: answered.answer,
        })
    }
}

impl CanHold for Honest {
    fn release() -> Word {
        Word::Release
    }
}

/// ОЧЕРЕДЬ, КОТОРАЯ НА САМОМ ДЕЛЕ НЕ ДЕРЖИТ.
///
/// Пакет ушёл дальше ещё до того, как у нас спросили решение; наш ответ ничего не меняет. Типом
/// такая очередь БЕЗУПРЕЧНА — `Terminal` реализован, слово отпускания названо, — и ровно этим она
/// страшна: движок над ней выносит вердикты, пишет спаны и двигает счётчики, комментируя уже
/// ушедший трафик.
/// Канал ему не нужен вовсе: он в него не кладёт — пакет ушёл мимо него ещё до вопроса.
struct Leaky;

impl Terminal for Leaky {
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

impl CanHold for Leaky {
    fn release() -> Word {
        Word::Release
    }
}

/// ОЧЕРЕДЬ, КОТОРАЯ НЕ ОТПУСКАЕТ. Слово сказано, а пакет так и не пошёл — удержание без выхода.
struct Sticky;

impl Terminal for Sticky {
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

impl CanHold for Sticky {
    fn release() -> Word {
        Word::Release
    }
}

/// ОЧЕРЕДЬ, ЧЕЙ ОТВЕТ НЕ ПРИНЯЛО ЯДРО.
struct Rejecting;

impl Terminal for Rejecting {
    type Carrier = Envelope;
    type Answer = Word;
    type Refusal = ();

    fn apply(
        &mut self,
        answered: Answered<Envelope, Word>,
    ) -> Result<Delivered<Word>, Refused<Word, ()>> {
        Err(Refused {
            at: answered.at,
            answer: answered.answer,
            why: (),
        })
    }
}

impl CanHold for Rejecting {
    fn release() -> Word {
        Word::Release
    }
}

/// АЛФАВИТ ОТВЕТА В ПАМЯТНОМ МИРЕ. Одно слово, потому что закон удержания спрашивает ровно про
/// него; остальные слова очереди — предмет соседних законов, и заводить их здесь значило бы
/// держать варианты, которых никто не разбирает.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Word {
    Release,
}

/// ДАЛЬНИЙ КОНЕЦ: что прошло дальше по стеку с прошлого вопроса.
struct Below(Downhill);

impl reflex_core::certify::holding::Downstream for Below {
    fn passed(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.0.borrow_mut())
    }
}

fn held() -> Held<Envelope> {
    Held::new(Envelope(b"\x45\x00nonce-hold-3f".to_vec()), Instant::now())
}

fn wire() -> (Downhill, Below) {
    let downhill: Downhill = Rc::new(RefCell::new(Vec::new()));
    let watching = Below(Rc::clone(&downhill));
    (downhill, watching)
}

/// ЧЕСТНАЯ ОЧЕРЕДЬ ЗАКОН ДЕРЖИТ.
#[test]
fn a_queue_that_really_holds_keeps_the_law() {
    let (downhill, mut downstream) = wire();

    let outcome = holds(&mut Honest(downhill), held(), &mut downstream);

    assert_eq!(outcome, Verdict::Held);
}

/// ТЕКУЩАЯ — НЕ ДЕРЖИТ, И ЭТО ГЛАВНАЯ ПРОВЕРКА ФАЙЛА.
///
/// Пакет ушёл ДО того, как у нас спросили. Всё, что движок сделает дальше, будет комментарием к
/// случившемуся, а не решением; и ни один счётчик об этом не скажет.
#[test]
fn a_queue_that_leaks_before_the_answer_is_caught() {
    let (downhill, mut downstream) = wire();
    // Пакет утёк ещё до вопроса — ровно то, что даёт правило очереди, стоящее не в той цепочке.
    downhill
        .borrow_mut()
        .push(b"\x45\x00nonce-hold-3f".to_vec());

    let outcome = holds(&mut Leaky, held(), &mut downstream);

    assert_eq!(outcome, Verdict::Broken(Broken::PassedBeforeAnswer));
}

/// НЕ ОТПУСКАЮЩАЯ — ТОЖЕ НЕ ДЕРЖИТ ЗАКОН, И ЭТО ДРУГАЯ БЕДА.
///
/// Пакет, который держат вечно, для человека неотличим от дропа — только тише: приложение ждёт
/// таймаута вместо отказа.
#[test]
fn a_queue_that_never_lets_go_is_caught_too() {
    let (_downhill, mut downstream) = wire();

    let outcome = holds(&mut Sticky, held(), &mut downstream);

    assert_eq!(outcome, Verdict::Broken(Broken::NeverPassed));
}

/// ОТКАЗ ЯДРА — НЕ НАРУШЕНИЕ СПОСОБНОСТИ.
///
/// Терминал честно сказал, что ответ не принят. Это беда мира, о которой СООБЩИЛИ, и предъявлять
/// её как ложное заявление значило бы наказывать за честность — та же развилка, что у
/// `SinkRefused` в законе инъекции.
#[test]
fn a_kernel_that_refuses_the_answer_is_not_a_broken_capability() {
    let (_downhill, mut downstream) = wire();

    let outcome = holds(&mut Rejecting, held(), &mut downstream);

    assert_eq!(outcome, Verdict::Invalid(Invalid::AnswerNotTaken));
}

/// ЧУЖОЙ ТРАФИК ДО ОТВЕТА НЕ ОБВИНЯЕТ.
///
/// Мимо дальнего конца всё время идёт посторонний трафик. Считай закон всякое движение утечкой —
/// честная очередь в живом стеке была бы объявлена текущей немедленно.
#[test]
fn someone_elses_traffic_before_the_answer_is_not_a_leak() {
    let (downhill, mut downstream) = wire();
    downhill
        .borrow_mut()
        .push(b"traffic from a neighbour".to_vec());

    let outcome = holds(&mut Honest(downhill), held(), &mut downstream);

    assert_eq!(outcome, Verdict::Held);
}
