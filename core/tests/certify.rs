//! ЗАКОН КАЛИТКИ: ЧТО ОТДАНО В СТОК — НАБЛЮДАЕМО ДАЛЬНИМ КОНЦОМ.
//!
//! # Что этим проверяется, а что нет
//!
//! Типы к этому дню убрали ПУСТЫЕ заявления: сказать «умею вводить», не назвав, как инъекция
//! становится командой стока, больше нельзя. Осталось ЛОЖНОЕ — команда построена, `emit` ответил
//! `Ok`, а на провод ничего не вышло, — и типом оно невыразимо по построению.
//!
//! Мир здесь ПАМЯТНЫЙ, и потому проверки сертифицируют САМ ЗАКОН, а не продукт. Настоящее
//! свидетельство даёт мир, устроенный ИНАЧЕ, чем подопытный, — `tshark` на дальнем конце veth, —
//! и это работа docker-устройства.

use reflex_core::backend::Sink;
use reflex_core::capability::CanInject;
use reflex_core::certify::{injects, Broken, FarEnd, Invalid, Verdict};
use reflex_core::command::InjectablePacket;
use std::cell::RefCell;
use std::rc::Rc;

/// ПРОВОД, ЗА КОТОРЫМ СМОТРИТ ДАЛЬНИЙ КОНЕЦ. Общий на двоих: сток кладёт, свидетель читает.
type Wire = Rc<RefCell<Vec<Vec<u8>>>>;

/// ДАЛЬНИЙ КОНЕЦ, СМОТРЯЩИЙ ЗА ПРОВОДОМ.
///
/// Отдельный тип, а не замыкание: у дальнего конца бывает СОСТОЯНИЕ — на живом устройстве он
/// хранит причину, по которой не смог ответить, и закон обязан уметь её донести. Замыкание такого
/// места не имеет, и до этой правки причина уезжала мимо закона.
struct Watching(Wire);

impl FarEnd for Watching {
    fn arrived(&mut self) -> Vec<Vec<u8>> {
        self.0.borrow().clone()
    }
}

/// ЧЕСТНЫЙ СТОК: что отдали — то и на проводе.
struct Honest(Wire);

impl Sink for Honest {
    type Command = Vec<u8>;
    type Error = ();
    fn emit(&mut self, command: Vec<u8>) -> Result<(), ()> {
        self.0.borrow_mut().push(command);
        Ok(())
    }
}

impl CanInject for Honest {
    fn inject(packet: InjectablePacket) -> Vec<u8> {
        packet.serialize()
    }
}

/// ЛЖИВЫЙ СТОК: команду принимает, отвечает `Ok`, на провод не кладёт.
///
/// Заявление о способности при этом БЕЗУПРЕЧНО по типам — предмет у него есть, метод написан.
/// Ровно то, что типы поймать не могут.
struct Silent;

impl Sink for Silent {
    type Command = Vec<u8>;
    type Error = ();
    fn emit(&mut self, _command: Vec<u8>) -> Result<(), ()> {
        Ok(())
    }
}

impl CanInject for Silent {
    fn inject(packet: InjectablePacket) -> Vec<u8> {
        packet.serialize()
    }
}

/// ЧЕСТНЫЙ СТОК, КОТОРЫЙ ГОВОРИТ О СВОЁМ ОТКАЗЕ.
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

fn nonce() -> InjectablePacket {
    InjectablePacket::Raw(b"nonce-8f3a".to_vec())
}

/// ЧЕСТНЫЙ БЭКЕНД ЗАКОН ДЕРЖИТ.
#[test]
fn a_backend_that_really_injects_holds_the_law() {
    let wire: Wire = Rc::new(RefCell::new(Vec::new()));
    let watching = Rc::clone(&wire);

    let outcome = injects(&mut Honest(wire), nonce(), &mut Watching(watching));

    assert_eq!(outcome, Verdict::Held);
}

/// ЛЖИВЫЙ — НЕ ДЕРЖИТ, И ЭТО ГЛАВНАЯ ПРОВЕРКА ФАЙЛА.
///
/// Закон, который не удалось заставить покраснеть, не в покрытии. Здесь краснеет бэкенд, чьё
/// заявление безупречно: команда строится, `emit` отвечает `Ok`, а нашего кадра на проводе нет.
///
/// ПРИБОР ОБЯЗАН БЫТЬ ДОКАЗАННО ЖИВ. Прежняя редакция подавала сюда ПУСТОЙ провод — то есть вход,
/// неотличимый от сломанного стенда, — и главная проверка файла держалась на неразличимости.
/// Найдено тем, что она покраснела, когда закон научился эту неразличимость называть.
#[test]
fn a_backend_that_only_pretends_is_caught() {
    let wire: Wire = Rc::new(RefCell::new(vec![b"traffic from someone else".to_vec()]));
    let watching = Rc::clone(&wire);

    let outcome = injects(&mut Silent, nonce(), &mut Watching(watching));

    assert_eq!(outcome, Verdict::Broken(Broken::NonceMissing));
}

/// ОШИБКА СТОКА — НЕ ТО ЖЕ, ЧТО МОЛЧАНИЕ ПРОВОДА.
///
/// Сток, честно сказавший «не смог», и сток, солгавший `Ok`, различаются: первый сообщил о себе,
/// второй нет. Слить их значило бы наказывать за честность.
#[test]
fn a_sink_that_admits_failure_is_not_the_same_as_one_that_lies() {
    let outcome = injects(&mut Refusing, nonce(), &mut Vec::new());

    assert_eq!(outcome, Verdict::Broken(Broken::SinkRefused));
}

/// МОЛЧАЩИЙ ПРИБОР НЕ ДАЁТ ВЕРДИКТА ВОВСЕ.
///
/// «Свидетель не работал» и «подопытный солгал» дают одинаково пустой результат, и слить их
/// значило бы объявлять нарушение всякий раз, когда сломался стенд. Различие ЕСТЬ в данных —
/// пустой список против непустого без нонса, — и до этой правки закон его съедал.
///
/// Ниже стоит [`a_near_miss_is_not_a_match`]: он держит вторую половину различия и краснеет, если
/// недействительность начнёт поглощать настоящее нарушение.
#[test]
fn a_witness_that_saw_nothing_yields_no_verdict() {
    let outcome = injects(&mut Silent, nonce(), &mut Vec::new());

    assert_eq!(outcome, Verdict::Invalid(Invalid::WitnessSilent));
}

/// ПОЧТИ-СОВПАДЕНИЕ — НЕ СОВПАДЕНИЕ.
///
/// Сосед сверху держит «чужой кадр не засчитывается»; здесь предмет уже: кадр несёт ПРЕФИКС нонса,
/// на байт короче полного. Сравнение по началу, по длине или по хешу от префикса прошло бы, и
/// закон засчитал бы обрезанный кадр — беду, ради различения которой нонс и заведён.
#[test]
fn a_near_miss_is_not_a_match() {
    let outcome = injects(
        &mut Silent,
        nonce(),
        &mut vec![b"\x88\xb5nonce-8f3".to_vec()],
    );

    assert_eq!(
        outcome,
        Verdict::Broken(Broken::NonceMissing),
        "префикс нонса — не нонс"
    );
}

/// НОНС ИЩЕТСЯ ВНУТРИ КАДРА, А НЕ РАВЕНСТВОМ ЕМУ.
///
/// В живом сегменте дальний конец видит кадр С ЗАГОЛОВКАМИ, которые дописал не подопытный.
/// Требуй закон равенства — он проверял бы «не тронул ли наш кадр никто по дороге», а это другой
/// вопрос и другой закон. Положительная сторона подстроки прежде не проверялась ничем: честный
/// сток в памятном мире кладёт на провод РОВНО отданное, и равенство с подстрокой там совпадают.
#[test]
fn the_nonce_is_found_inside_a_framed_packet() {
    let outcome = injects(
        &mut Silent,
        nonce(),
        &mut vec![
            b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x0c\xe7\x01\x88\xb5nonce-8f3a\x00\x00".to_vec(),
        ],
    );

    assert_eq!(outcome, Verdict::Held);
}
