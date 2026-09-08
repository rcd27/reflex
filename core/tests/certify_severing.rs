//! ЗАКОН ОБРЫВА: РАЗГОВОР НЕ СОСТОЯЛСЯ, И ВСТРЕЧНАЯ СТОРОНА ОБ ЭТОМ ЗНАЕТ.
//!
//! # Почему это отдельный закон, а не сумма двух
//!
//! Прогнать подряд [`refuses`](reflex_core::certify::refuses) и
//! [`injects`](reflex_core::certify::injects) значило бы установить, что бэкенд умеет отказывать и
//! умеет вводить. Обрыв — не эта конъюнкция: у него есть АДРЕСАТ, и вся разница между лечением и
//! бедой лежит именно в нём.
//!
//! Дроп без извещения есть ровно то, чем бьёт молчаливый дроп на пути: клиент не узнаёт, что разговора не будет,
//! ретрансмитит приветствие пять-семь раз и ждёт от двух до двенадцати секунд (замер на нашем
//! вантаже 04.09.2026). Человек называет это «страница висит». Обрыв же с извещением клиент
//! понимает мгновенно и показывает человеку отказ, а не бесконечную загрузку.
//!
//! Отсюда четвёртая беда, невыразимая ни одним из двух законов по отдельности: извещение ушло НЕ
//! ТУДА. Перепутать стороны — правка одной строки в вычислении концов, и ни `refuses`, ни
//! `injects` этого не заметят: первый увидит, что исходное не прошло, второй — что наш кадр где-то
//! наблюдаем. Оба скажут «держится».
//!
//! # Два свидетеля, потому что две границы
//!
//! [`Downstream`] стоит по пути к цели, [`NearEnd`] — на стороне, породившей разговор. Один
//! свидетель на обе границы не различал бы «дошло клиенту» и «дошло цели», а в этом весь предмет.
//!
//! # Прибор обязан быть доказанно жив
//!
//! Пустой ответ свидетеля не значит «не прошло»: он значит «мы не знаем». Поэтому там, где закон
//! обязан увидеть ОТСУТСТВИЕ нашего кадра, свидетелю подаётся чужой шум — и это не украшение
//! теста, а тот самый маяк, которым живое устройство разгоняет неразличимость.

use reflex_core::backend::Sink;
use reflex_core::capability::{CanInject, CanRefuse, CanSever, Toward};
use reflex_core::certify::severing::{severs, Broken, Invalid, NearEnd};
use reflex_core::certify::{Downstream, Verdict};
use reflex_core::command::InjectablePacket;
use reflex_core::held::{Answered, Delivered, Held, Observed, Refused, Terminal};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Instant;

/// ПРОВОД, ЗА КОТОРЫМ СМОТРИТ СВИДЕТЕЛЬ. Общий на двоих: носитель кладёт, свидетель читает.
type Wire = Rc<RefCell<Vec<Vec<u8>>>>;

const ORIGINAL: &[u8] = b"\x45\x00nonce-original-7c";
const NOTICE: &[u8] = b"\x45\x00nonce-notice-4e";

/// ЧУЖОЙ ШУМ — МАЯК ЖИВОГО ПРИБОРА. Без него «свидетель молчит» неотличимо от «нашего кадра нет»,
/// и главные проверки этого файла держались бы на неразличимости.
const SOMEONE_ELSE: &[u8] = b"traffic from someone else";

struct Envelope(Vec<u8>);

impl Observed for Envelope {
    fn payload(&self) -> &[u8] {
        &self.0
    }
}

/// СЛОВО АЛФАВИТА памятного мира — здесь довольно одного: закон обрыва берёт у терминала только
/// отказ, а извещение уходит стоком.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Word {
    Refuse,
}

/// ЧЕСТНЫЙ ТЕРМИНАЛ: сказали «не пропускать» — не пропустил.
struct Honest;

impl Terminal for Honest {
    type Carrier = Envelope;
    type Answer = Word;
    type Refusal = ();

    fn apply(
        &mut self,
        answered: Answered<Envelope, Word>,
    ) -> Result<Delivered<Word>, Refused<Word, ()>> {
        match &answered.answer {
            Word::Refuse => Ok(Delivered {
                at: answered.at,
                answer: answered.answer,
            }),
        }
    }
}

impl CanRefuse for Honest {
    fn refuse() -> Word {
        Word::Refuse
    }
}

impl CanSever for Honest {
    /// ИЗВЕЩЕНИЕ СТРОИТСЯ ИЗ НОСИТЕЛЯ, а не приходит параметром: закон, которому извещение
    /// передают снаружи, проверял бы согласие вызывающего с самим собой.
    ///
    /// В памятном мире содержимое постоянно — проверяется адресация, а не сборка TCP.
    fn notice(_seen: &[u8], _toward: Toward) -> Option<InjectablePacket> {
        Some(InjectablePacket::Raw(NOTICE.to_vec()))
    }
}

/// ТЕРМИНАЛ, ЧЕЙ ОТКАЗ НЕ ИСПОЛНЯЕТСЯ: вердикт вынесен, а пакет пошёл дальше.
struct Ignoring(Wire);

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

impl CanSever for Ignoring {
    fn notice(_seen: &[u8], _toward: Toward) -> Option<InjectablePacket> {
        Some(InjectablePacket::Raw(NOTICE.to_vec()))
    }
}

/// ТЕРМИНАЛ, ЧЕЙ ОТВЕТ НЕ ПРИНИМАЕТ ЯДРО. Беда стенда, а не способности.
struct NotAccepting;

impl Terminal for NotAccepting {
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

impl CanRefuse for NotAccepting {
    fn refuse() -> Word {
        Word::Refuse
    }
}

impl CanSever for NotAccepting {
    fn notice(_seen: &[u8], _toward: Toward) -> Option<InjectablePacket> {
        Some(InjectablePacket::Raw(NOTICE.to_vec()))
    }
}

/// ТЕРМИНАЛ, КОТОРОМУ СКАЗАТЬ НЕЧЕМ: способность заявлена, а извещения из носителя не построить.
///
/// Живой случай — не выдумка: у обрыва TCP есть форма (`RST` с номерами, которых ждёт сторона), а
/// у датаграммы её нет вовсе. Молчать здесь значило бы оборвать МОЛЧА.
struct Speechless;

impl Terminal for Speechless {
    type Carrier = Envelope;
    type Answer = Word;
    type Refusal = ();

    fn apply(
        &mut self,
        answered: Answered<Envelope, Word>,
    ) -> Result<Delivered<Word>, Refused<Word, ()>> {
        match &answered.answer {
            Word::Refuse => Ok(Delivered {
                at: answered.at,
                answer: answered.answer,
            }),
        }
    }
}

impl CanRefuse for Speechless {
    fn refuse() -> Word {
        Word::Refuse
    }
}

impl CanSever for Speechless {
    fn notice(_seen: &[u8], _toward: Toward) -> Option<InjectablePacket> {
        None
    }
}

/// ЧЕСТНЫЙ СТОК: извещение уходит на сторону клиента.
struct Speaking(Wire);

impl Sink for Speaking {
    type Command = Vec<u8>;
    type Error = ();

    fn emit(&mut self, command: Vec<u8>) -> Result<(), ()> {
        self.0.borrow_mut().push(command);
        Ok(())
    }
}

impl CanInject for Speaking {
    fn inject(packet: InjectablePacket) -> Vec<u8> {
        packet.serialize()
    }
}

/// СТОК, ПЕРЕПУТАВШИЙ СТОРОНЫ: извещение уезжает ЦЕЛИ.
///
/// Заявление безупречно по типам, `emit` отвечает `Ok`, кадр наблюдаем — и ни закон отказа, ни
/// закон инъекции не сказали бы ни слова. Это главная проверка файла.
struct Misdirected(Wire);

impl Sink for Misdirected {
    type Command = Vec<u8>;
    type Error = ();

    fn emit(&mut self, command: Vec<u8>) -> Result<(), ()> {
        self.0.borrow_mut().push(command);
        Ok(())
    }
}

impl CanInject for Misdirected {
    fn inject(packet: InjectablePacket) -> Vec<u8> {
        packet.serialize()
    }
}

/// СТОК, КОТОРЫЙ ПРОГЛАТЫВАЕТ ИЗВЕЩЕНИЕ: `Ok` есть, кадра нет нигде.
struct Mute;

impl Sink for Mute {
    type Command = Vec<u8>;
    type Error = ();

    fn emit(&mut self, _command: Vec<u8>) -> Result<(), ()> {
        Ok(())
    }
}

impl CanInject for Mute {
    fn inject(packet: InjectablePacket) -> Vec<u8> {
        packet.serialize()
    }
}

/// СТОК, ГОВОРЯЩИЙ О СВОЁМ ОТКАЗЕ. Честная беда стенда: сокет не открылся.
struct Refusing;

impl Sink for Refusing {
    type Command = Vec<u8>;
    type Error = ();

    fn emit(&mut self, _command: Vec<u8>) -> Result<(), ()> {
        Err(())
    }
}

impl CanInject for Refusing {
    fn inject(packet: InjectablePacket) -> Vec<u8> {
        packet.serialize()
    }
}

/// СВИДЕТЕЛЬ ПО ПУТИ К ЦЕЛИ.
struct Beyond(Wire);

impl Downstream for Beyond {
    fn passed(&mut self) -> Vec<Vec<u8>> {
        self.0.borrow().clone()
    }
}

/// СВИДЕТЕЛЬ НА СТОРОНЕ, ПОРОДИВШЕЙ РАЗГОВОР.
struct Behind(Wire);

impl NearEnd for Behind {
    fn arrived(&mut self) -> Vec<Vec<u8>> {
        self.0.borrow().clone()
    }
}

fn held() -> Held<Envelope> {
    Held::new(Envelope(ORIGINAL.to_vec()), Instant::now())
}

/// ПРОВОД С ЧУЖИМ ШУМОМ — доказательство, что прибор смотрит.
fn lively() -> Wire {
    Rc::new(RefCell::new(vec![SOMEONE_ELSE.to_vec()]))
}

/// ЧЕСТНЫЙ ОБРЫВ ЗАКОН ДЕРЖИТ: к цели не ушло ничего нашего, клиент извещён.
#[test]
fn a_backend_that_really_severs_holds_the_law() {
    let beyond = lively();
    let behind = lively();

    let outcome = severs(
        &mut Honest,
        &mut Speaking(Rc::clone(&behind)),
        held(),
        Toward::Sender,
        &mut Beyond(Rc::clone(&beyond)),
        &mut Behind(behind),
    );

    assert_eq!(outcome, Verdict::Held);
}

/// ОТКАЗ НЕ ИСПОЛНИЛСЯ, ХОТЯ ИЗВЕЩЕНИЕ УШЛО: разговор продолжается, и клиент получил RST по
/// живому соединению — хуже, чем не делать ничего.
#[test]
fn an_unenforced_refusal_is_caught() {
    let beyond = lively();
    let behind = lively();

    let outcome = severs(
        &mut Ignoring(Rc::clone(&beyond)),
        &mut Speaking(Rc::clone(&behind)),
        held(),
        Toward::Sender,
        &mut Beyond(beyond),
        &mut Behind(behind),
    );

    assert_eq!(outcome, Verdict::Broken(Broken::PassedAnyway));
}

/// ИЗВЕЩЕНИЯ НЕТ: пакет не прошёл, а клиент об этом не знает — то самое, чем бьёт молчаливый дроп на пути.
#[test]
fn a_silent_sever_is_caught() {
    let beyond = lively();
    let behind = lively();

    let outcome = severs(
        &mut Honest,
        &mut Mute,
        held(),
        Toward::Sender,
        &mut Beyond(beyond),
        &mut Behind(behind),
    );

    assert_eq!(outcome, Verdict::Broken(Broken::NoticeMissed));
}

/// ГЛАВНАЯ ПРОВЕРКА ФАЙЛА: извещение уехало ЦЕЛИ вместо клиента.
///
/// Отказ исполнен, кадр наблюдаем, `emit` ответил `Ok` — по отдельности оба соседних закона
/// зелены. Красит эту беду только адресация, и только двумя свидетелями.
#[test]
fn a_notice_sent_to_the_wrong_side_is_caught() {
    let beyond = lively();
    let behind = lively();

    let outcome = severs(
        &mut Honest,
        &mut Misdirected(Rc::clone(&beyond)),
        held(),
        Toward::Sender,
        &mut Beyond(beyond),
        &mut Behind(behind),
    );

    assert_eq!(outcome, Verdict::Broken(Broken::NoticeToTarget));
}

/// НИ ОТКАЗА, НИ ИЗВЕЩЕНИЯ — обрыв не состоялся вовсе.
///
/// Отдельно от [`Broken::PassedAnyway`] намеренно: «прошло, но клиент извещён» есть дефект одной
/// половины, а это — решение, не исполненное целиком. Лечится в разных местах.
#[test]
fn a_sever_that_did_not_happen_at_all_is_caught() {
    let beyond = lively();
    let behind = lively();

    let outcome = severs(
        &mut Ignoring(Rc::clone(&beyond)),
        &mut Mute,
        held(),
        Toward::Sender,
        &mut Beyond(beyond),
        &mut Behind(behind),
    );

    assert_eq!(outcome, Verdict::Broken(Broken::NeitherHappened));
}

/// БЛИЖНИЙ СВИДЕТЕЛЬ МОЛЧИТ — вердикта нет, и это не соблюдение.
///
/// Пустой провод неотличим от сломанного прибора: закон обязан сказать «не установлено», а не
/// подтвердить способность.
#[test]
fn a_mute_near_end_yields_no_verdict() {
    let beyond = lively();
    let behind: Wire = Rc::new(RefCell::new(Vec::new()));

    let outcome = severs(
        &mut Honest,
        &mut Mute,
        held(),
        Toward::Sender,
        &mut Beyond(beyond),
        &mut Behind(behind),
    );

    assert_eq!(outcome, Verdict::Invalid(Invalid::NearEndMute));
}

/// ДАЛЬНИЙ СВИДЕТЕЛЬ МОЛЧИТ — то же самое с другой границы.
#[test]
fn a_mute_downstream_yields_no_verdict() {
    let beyond: Wire = Rc::new(RefCell::new(Vec::new()));
    let behind = lively();

    let outcome = severs(
        &mut Honest,
        &mut Speaking(Rc::clone(&behind)),
        held(),
        Toward::Sender,
        &mut Beyond(beyond),
        &mut Behind(behind),
    );

    assert_eq!(outcome, Verdict::Invalid(Invalid::DownstreamMute));
}

/// СТОК ОТКАЗАЛ ЧЕСТНО: сокет не открылся, извещение не с чем послать. Вина стенда, не бэкенда.
#[test]
fn a_refusing_sink_yields_no_verdict() {
    let beyond = lively();
    let behind = lively();

    let outcome = severs(
        &mut Honest,
        &mut Refusing,
        held(),
        Toward::Sender,
        &mut Beyond(beyond),
        &mut Behind(behind),
    );

    assert_eq!(outcome, Verdict::Invalid(Invalid::SinkRefused));
}

/// ЯДРО НЕ ПРИНЯЛО ОТВЕТ — сообщение могло протухнуть по таймауту очереди.
#[test]
fn an_answer_the_kernel_refused_yields_no_verdict() {
    let beyond = lively();
    let behind = lively();

    let outcome = severs(
        &mut NotAccepting,
        &mut Speaking(Rc::clone(&behind)),
        held(),
        Toward::Sender,
        &mut Beyond(beyond),
        &mut Behind(behind),
    );

    assert_eq!(outcome, Verdict::Invalid(Invalid::AnswerNotTaken));
}

/// СКАЗАТЬ НЕЧЕМ — И ЭТО ВИНА ПОДОПЫТНОГО, а не стенда.
///
/// Проверяется заодно, что мир НЕ ТРОНУТ: закон обязан узнать о немоте ДО отказа, иначе он сам
/// оборвёт молча — исполнит ровно ту беду, которую стережёт.
#[test]
fn a_backend_with_nothing_to_say_is_caught_before_it_acts() {
    let beyond = lively();
    let behind = lively();

    let outcome = severs(
        &mut Speechless,
        &mut Speaking(Rc::clone(&behind)),
        held(),
        Toward::Sender,
        &mut Beyond(Rc::clone(&beyond)),
        &mut Behind(Rc::clone(&behind)),
    );

    assert_eq!(outcome, Verdict::Broken(Broken::NoticeUnbuildable));
    // МИР ОСТАЛСЯ КАКИМ БЫЛ: на обоих проводах ровно тот чужой шум, что лежал до прогона.
    assert_eq!(beyond.borrow().len(), 1);
    assert_eq!(behind.borrow().len(), 1);
}

/// ПАКЕТ УШЁЛ ДО НАШЕГО ОТВЕТА — удержания не было, и судить об обрыве нечего.
///
/// Предъявлять этой способности чужую беду значило бы наказывать за то, что стережёт
/// [`holds`](reflex_core::certify::holds).
#[test]
fn a_packet_gone_before_the_answer_yields_no_verdict() {
    let beyond: Wire = Rc::new(RefCell::new(vec![ORIGINAL.to_vec()]));
    let behind = lively();

    let outcome = severs(
        &mut Honest,
        &mut Speaking(Rc::clone(&behind)),
        held(),
        Toward::Sender,
        &mut Beyond(beyond),
        &mut Behind(behind),
    );

    assert_eq!(outcome, Verdict::Invalid(Invalid::NotHeld));
}
