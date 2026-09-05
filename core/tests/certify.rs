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
use reflex_core::certify::{injects, Broken, Verdict};
use reflex_core::command::InjectablePacket;
use std::cell::RefCell;
use std::rc::Rc;

/// ПРОВОД, ЗА КОТОРЫМ СМОТРИТ ДАЛЬНИЙ КОНЕЦ. Общий на двоих: сток кладёт, свидетель читает.
type Wire = Rc<RefCell<Vec<Vec<u8>>>>;

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

    let outcome = injects(&mut Honest(wire), nonce(), move || {
        watching.borrow().clone()
    });

    assert_eq!(outcome, Verdict::Held);
}

/// ЛЖИВЫЙ — НЕ ДЕРЖИТ, И ЭТО ГЛАВНАЯ ПРОВЕРКА ФАЙЛА.
///
/// Закон, который не удалось заставить покраснеть, не в покрытии. Здесь краснеет бэкенд, чьё
/// заявление безупречно: команда строится, `emit` отвечает `Ok`, а на проводе пусто.
#[test]
fn a_backend_that_only_pretends_is_caught() {
    let wire: Wire = Rc::new(RefCell::new(Vec::new()));
    let watching = Rc::clone(&wire);

    let outcome = injects(&mut Silent, nonce(), move || watching.borrow().clone());

    assert_eq!(outcome, Verdict::Broken(Broken::NonceMissing));
}

/// ОШИБКА СТОКА — НЕ ТО ЖЕ, ЧТО МОЛЧАНИЕ ПРОВОДА.
///
/// Сток, честно сказавший «не смог», и сток, солгавший `Ok`, различаются: первый сообщил о себе,
/// второй нет. Слить их значило бы наказывать за честность.
#[test]
fn a_sink_that_admits_failure_is_not_the_same_as_one_that_lies() {
    let outcome = injects(&mut Refusing, nonce(), Vec::new);

    assert_eq!(outcome, Verdict::Broken(Broken::SinkRefused));
}

/// ЗАКОН НЕ ЗАСЧИТЫВАЕТСЯ ПО ЧУЖОМУ ПАКЕТУ.
///
/// Дальний конец видит и посторонний трафик. Считай мы по числу кадров — закон прошёл бы на чужом
/// пакете; репа эту беду уже ловила («свидетель проходил ПО СЛУЧАЙНОСТИ, счётчик двигал
/// посторонний трафик»). Нонс отвечает на вопрос «дошёл ли ИМЕННО НАШ».
#[test]
fn someone_elses_packet_does_not_satisfy_the_law() {
    let outcome = injects(&mut Silent, nonce(), || {
        vec![b"chatter from a neighbour".to_vec()]
    });

    assert_eq!(
        outcome,
        Verdict::Broken(Broken::NonceMissing),
        "дальний конец не пуст, но нашего там нет"
    );
}
