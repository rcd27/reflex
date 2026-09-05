//! ЗАКОНЫ ОТВЕТА: ЧЕМ ОТВЕТИЛИ, ТО С ПАКЕТОМ И СЛУЧИЛОСЬ.
//!
//! # Почему это два закона, а не один с параметром
//!
//! Соблазн был: «ответ ⟹ ожидаемое последствие» пишется одной функцией, куда ответ и ожидание
//! приходят рядом. Такой закон проверял бы СОГЛАСИЕ ВЫЗЫВАЮЩЕГО С САМИМ СОБОЙ — подставь
//! несогласованную пару, и он послушно подтвердит её.
//!
//! Здесь каждый закон берёт слово у самой способности ([`CanRefuse::refuse`],
//! [`CanRewrite::rewrite`]) и знает ожидание сам. Отсюда же и типовая связь: закон нельзя
//! применить к бэкенду, не заявившему нужного.
//!
//! # Что типом невыразимо
//!
//! Всё то же: слово алфавита названо, `Terminal` реализован, компилятор доволен — а ядро могло
//! вердикт не применить, и байты уйти прежние. Между «мы ответили» и «мир послушался» лежит
//! чужая машина.

use reflex_core::capability::{CanRefuse, CanRewrite};
use reflex_core::certify::refusal::{refuses, Broken as RefusalBroken, Invalid as RefusalInvalid};
use reflex_core::certify::rewriting::{
    rewrites, Broken as RewriteBroken, Invalid as RewriteInvalid,
};
use reflex_core::certify::Verdict;
use reflex_core::held::{Answered, Delivered, Held, Observed, Refused, Terminal};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Instant;

type Downhill = Rc<RefCell<Vec<Vec<u8>>>>;

const ORIGINAL: &[u8] = b"\x45\x00nonce-answer-9d";
const REPLACEMENT: &[u8] = b"\x45\x00nonce-rewritten-2b";

struct Envelope(Vec<u8>);

impl Observed for Envelope {
    fn payload(&self) -> &[u8] {
        &self.0
    }
}

/// СЛОВО АЛФАВИТА в памятном мире — ровно те два, про которые здесь законы.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Word {
    Refuse,
    Rewrite(Vec<u8>),
}

/// ЧЕСТНАЯ ОЧЕРЕДЬ: делает ровно то, что ей сказали.
struct Honest(Downhill);

impl Terminal for Honest {
    type Carrier = Envelope;
    type Answer = Word;
    type Refusal = ();

    fn apply(
        &mut self,
        answered: Answered<Envelope, Word>,
    ) -> Result<Delivered<Word>, Refused<Word, ()>> {
        match &answered.answer {
            Word::Refuse => (),
            Word::Rewrite(bytes) => self.0.borrow_mut().push(bytes.clone()),
        }
        Ok(Delivered {
            at: answered.at,
            answer: answered.answer,
        })
    }
}

impl CanRefuse for Honest {
    fn refuse() -> Word {
        Word::Refuse
    }
}

impl CanRewrite for Honest {
    fn rewrite(bytes: Vec<u8>) -> Word {
        Word::Rewrite(bytes)
    }
}

/// ОЧЕРЕДЬ, ЧЕЙ ОТКАЗ НЕ ИСПОЛНЯЕТСЯ: сказали «не пропускать», а пакет пошёл.
///
/// Типом безупречна, и это самый опасный из отказов — движок считает, что заблокировал.
struct Ignoring(Downhill);

impl Terminal for Ignoring {
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

impl CanRefuse for Ignoring {
    fn refuse() -> Word {
        Word::Refuse
    }
}

impl CanRewrite for Ignoring {
    fn rewrite(bytes: Vec<u8>) -> Word {
        Word::Rewrite(bytes)
    }
}

/// ОЧЕРЕДЬ, КОТОРАЯ ПРОПУСКАЕТ ИСХОДНОЕ ВМЕСТО ПОДМЕНЁННОГО.
///
/// Вердикт применён, пакет прошёл, всё зелено — а байты прежние. Ровно то, что не выражается
/// типом: подмена случилась в нашем значении и не случилась в мире.
struct Verbatim(Downhill);

impl Terminal for Verbatim {
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

impl CanRewrite for Verbatim {
    fn rewrite(bytes: Vec<u8>) -> Word {
        Word::Rewrite(bytes)
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

impl CanRefuse for Rejecting {
    fn refuse() -> Word {
        Word::Refuse
    }
}

/// ЖИВОЙ СВИДЕТЕЛЬ. Всегда показывает ФОН — посторонний трафик, который в настоящем стеке идёт
/// непрерывно, — и сверх него то, что прошло с прошлого вопроса.
///
/// Фон здесь не украшение: он и есть доказательство того, что свидетель смотрит. Без него пустой
/// ответ значил бы сразу двоё, и законы отличали бы «не прошло» от «не увидел» ничем.
struct Below(Downhill);

impl reflex_core::certify::Downstream for Below {
    fn passed(&mut self) -> Vec<Vec<u8>> {
        let fresh: Vec<Vec<u8>> = std::mem::take(&mut *self.0.borrow_mut());
        std::iter::once(b"background chatter".to_vec())
            .chain(fresh)
            .collect()
    }
}

/// МЁРТВЫЙ СВИДЕТЕЛЬ: не видит ничего, включая фон.
struct Dead;

impl reflex_core::certify::Downstream for Dead {
    fn passed(&mut self) -> Vec<Vec<u8>> {
        Vec::new()
    }
}

fn held() -> Held<Envelope> {
    Held::new(Envelope(ORIGINAL.to_vec()), Instant::now())
}

fn wire() -> (Downhill, Below) {
    let downhill: Downhill = Rc::new(RefCell::new(Vec::new()));
    let watching = Below(Rc::clone(&downhill));
    (downhill, watching)
}

// --- ЗАКОН ОТКАЗА ---

/// ЧЕСТНЫЙ ОТКАЗ ЗАКОН ДЕРЖИТ: сказали «не пропускать» — и не прошло.
#[test]
fn a_queue_that_really_refuses_keeps_the_law() {
    let (downhill, mut downstream) = wire();

    let outcome = refuses(&mut Honest(downhill), held(), &mut downstream);

    assert_eq!(outcome, Verdict::Held);
}

/// ОТКАЗ, КОТОРЫЙ НЕ ИСПОЛНИЛСЯ, — ГЛАВНАЯ ПРОВЕРКА ЗАКОНА.
///
/// Движок считает, что заблокировал; человек видит, что сайт открылся. Ни один счётчик об этом не
/// скажет: вердикт вынесен, доставка подтверждена, спан записан.
#[test]
fn a_refusal_that_does_not_stop_the_packet_is_caught() {
    let (downhill, mut downstream) = wire();

    let outcome = refuses(&mut Ignoring(downhill), held(), &mut downstream);

    assert_eq!(outcome, Verdict::Broken(RefusalBroken::PassedAnyway));
}

/// ПАКЕТ, УШЕДШИЙ ДО ОТВЕТА, ДЕЛАЕТ ПРОГОН НЕДЕЙСТВИТЕЛЬНЫМ, А НЕ ЗАКОН НАРУШЕННЫМ.
///
/// Судить об отказе, когда удержания не было, значит предъявлять способности чужую беду: это
/// нарушение ДРУГОГО закона (`holds`), и у него свой вердикт.
#[test]
fn a_packet_gone_before_the_answer_invalidates_the_run() {
    let (downhill, mut downstream) = wire();
    downhill.borrow_mut().push(ORIGINAL.to_vec());

    let outcome = refuses(&mut Honest(downhill), held(), &mut downstream);

    assert_eq!(outcome, Verdict::Invalid(RefusalInvalid::NotHeld));
}

/// ОТКАЗ ЯДРА — НЕ НАРУШЕНИЕ СПОСОБНОСТИ.
#[test]
fn a_kernel_refusing_the_refusal_is_not_a_broken_capability() {
    let (_downhill, mut downstream) = wire();

    let outcome = refuses(&mut Rejecting, held(), &mut downstream);

    assert_eq!(outcome, Verdict::Invalid(RefusalInvalid::AnswerNotTaken));
}

/// ЧУЖОЙ ТРАФИК ПОСЛЕ ОТКАЗА НЕ ОБВИНЯЕТ.
#[test]
fn someone_elses_traffic_after_the_refusal_is_not_a_leak() {
    let (downhill, mut downstream) = wire();
    downhill
        .borrow_mut()
        .push(b"traffic from a neighbour".to_vec());

    let outcome = refuses(&mut Honest(downhill), held(), &mut downstream);

    assert_eq!(outcome, Verdict::Held);
}

/// МЁРТВЫЙ СВИДЕТЕЛЬ НЕ ДАЁТ ЗЕЛЁНОГО ОТКАЗУ.
///
/// «Не прошло» и «свидетель не смотрел» дают одинаково пустой ответ, и закон отказа зелен в обоих
/// случаях. Найдено ЖИВЬЁМ 05.09.2026: остановленный `dumpcap` — и `refuses` выдал `held`.
///
/// Урок был выучен утром того же дня в законе инъекции (`WitnessSilent` плюс маяк) и НЕ перенёсся
/// в новый закон сам собой: правило, живущее в другом файле, компилятор не читает.
#[test]
fn a_dead_witness_gives_the_refusal_no_verdict() {
    let outcome = refuses(
        &mut Honest(Rc::new(RefCell::new(Vec::new()))),
        held(),
        &mut Dead,
    );

    assert_eq!(outcome, Verdict::Invalid(RefusalInvalid::WitnessSilent));
}

// --- ЗАКОН ПОДМЕНЫ ---

/// ЧЕСТНАЯ ПОДМЕНА ЗАКОН ДЕРЖИТ: прошли ИМЕННО подменённые байты.
#[test]
fn a_queue_that_really_rewrites_keeps_the_law() {
    let (downhill, mut downstream) = wire();

    let outcome = rewrites(
        &mut Honest(downhill),
        held(),
        REPLACEMENT.to_vec(),
        &mut downstream,
    );

    assert_eq!(outcome, Verdict::Held);
}

/// ПРОШЛО ИСХОДНОЕ ВМЕСТО ПОДМЕНЁННОГО — ГЛАВНАЯ ПРОВЕРКА ЗАКОНА.
///
/// Подмена случилась в нашем значении и не случилась в мире. Всё зелено: вердикт применён, пакет
/// прошёл, `Delivered` говорит, ЧЕМ ответили, — и байты прежние.
#[test]
fn a_rewrite_that_leaves_the_original_bytes_is_caught() {
    let (downhill, mut downstream) = wire();

    let outcome = rewrites(
        &mut Verbatim(downhill),
        held(),
        REPLACEMENT.to_vec(),
        &mut downstream,
    );

    assert_eq!(outcome, Verdict::Broken(RewriteBroken::OriginalPassed));
}

/// ПОДМЕНИЛИ — И НЕ ПРОШЛО ВОВСЕ. Другая беда с другой починкой: там байты не те, здесь пакета нет.
#[test]
fn a_rewrite_that_stops_the_packet_is_caught_too() {
    let (_downhill, mut downstream) = wire();

    let outcome = rewrites(&mut Muted, held(), REPLACEMENT.to_vec(), &mut downstream);

    assert_eq!(outcome, Verdict::Broken(RewriteBroken::NothingPassed));
}

/// ОЧЕРЕДЬ, КОТОРАЯ ПОДМЕНУ ПРИНЯЛА, А ПАКЕТ НЕ ОТПУСТИЛА. Канал ей не нужен: она в него не кладёт.
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

impl CanRewrite for Muted {
    fn rewrite(bytes: Vec<u8>) -> Word {
        Word::Rewrite(bytes)
    }
}

/// ПРОШЛИ ОБА — ПАКЕТ РАЗМНОЖИЛСЯ НИЖЕ ПО СТЕКУ.
///
/// Подмена сработала и НЕ отменила оригинала: адресат получит два пакета вместо одного. Беда
/// третьего рода, и объединять её с `OriginalPassed` нельзя — там подмены не случилось вовсе, а
/// здесь случилась и не заместила.
#[test]
fn both_the_rewrite_and_the_original_passing_is_its_own_trouble() {
    let (downhill, mut downstream) = wire();

    let outcome = rewrites(
        &mut Doubling(downhill),
        held(),
        REPLACEMENT.to_vec(),
        &mut downstream,
    );

    assert_eq!(outcome, Verdict::Broken(RewriteBroken::BothPassed));
}

/// ОЧЕРЕДЬ, ПРОПУСКАЮЩАЯ И ПОДМЕНЁННОЕ, И ИСХОДНОЕ.
struct Doubling(Downhill);

impl Terminal for Doubling {
    type Carrier = Envelope;
    type Answer = Word;
    type Refusal = ();

    fn apply(
        &mut self,
        answered: Answered<Envelope, Word>,
    ) -> Result<Delivered<Word>, Refused<Word, ()>> {
        match &answered.answer {
            Word::Refuse => (),
            Word::Rewrite(bytes) => {
                self.0.borrow_mut().push(bytes.clone());
                self.0.borrow_mut().push(answered.carrier.0.clone());
            }
        }
        Ok(Delivered {
            at: answered.at,
            answer: answered.answer,
        })
    }
}

impl CanRewrite for Doubling {
    fn rewrite(bytes: Vec<u8>) -> Word {
        Word::Rewrite(bytes)
    }
}

/// МЁРТВЫЙ СВИДЕТЕЛЬ НЕ ДАЁТ ВЕРДИКТА И ПОДМЕНЕ.
///
/// Здесь он вреден иначе, чем в отказе: там давал ложный зелёный, здесь дал бы ложное ОБВИНЕНИЕ
/// (`NothingPassed`) — честная очередь объявлялась бы не отпускающей всякий раз, когда сломался
/// стенд.
#[test]
fn a_dead_witness_gives_the_rewrite_no_verdict() {
    let outcome = rewrites(&mut Muted, held(), REPLACEMENT.to_vec(), &mut Dead);

    assert_eq!(outcome, Verdict::Invalid(RewriteInvalid::WitnessSilent));
}

/// ПОДМЕНА НА ТО ЖЕ САМОЕ — НЕ ПОДМЕНА, И ПРОГОН НЕДЕЙСТВИТЕЛЕН.
///
/// Ищи закон подменённые байты, не убедившись, что они ОТЛИЧАЮТСЯ от исходных, — и честная очередь,
/// и не подменяющая вовсе дали бы одинаковый `held`. Различить их было бы нечем: искомое
/// присутствует в обоих случаях.
#[test]
fn rewriting_bytes_into_themselves_yields_no_verdict() {
    let (downhill, mut downstream) = wire();

    let outcome = rewrites(
        &mut Honest(downhill),
        held(),
        ORIGINAL.to_vec(),
        &mut downstream,
    );

    assert_eq!(outcome, Verdict::Invalid(RewriteInvalid::NotAChange));
}
