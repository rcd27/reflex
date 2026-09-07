//! ДВИЖОК ВХОДИТ В КАТЕГОРИЮ ШАГА (шестой vision §3).
//!
//! Один из живых диалектов шага (`step::Step::step`, `engine::step::step`, `Plane::feed`,
//! `NfqHandler::handle`) и единственный, у которого вход НЕ БЫЛ ЗАМКНУТ: знание о цели
//! приходило Reader'ом (`look_up: Fn(&Packet) -> Plan`), то есть незаписанным входом. Здесь оно
//! становится БУКВОЙ входного алфавита, и этим переигровка одного разговора замыкается: чтобы
//! прогнать его заново, не нужна вся таблица целей — довольно того, что `look_up` ответил.

use reflex_core::step::{Step, StepExt};
use reflex_core::word::{Region, Word};
use reflex_engine::row::Naming;
use reflex_engine::step::{Advancing, Answer};
use reflex_engine::{
    Act, Addr, Basis, Cursor, Dir, Epoch, FlowKey, Interest, Packet, Plan, Programme, Tick,
};

/// ОБЛАСТЬ ЗАКОННОГО СТЕНДА.
///
/// Объявляется здесь, а не в фундаменте: закон обязан быть выразим для того, кто заводит свою
/// область снаружи, и стенд — законный заводящий.
struct Bench;
impl Region for Bench {}

/// СЧЁТ НАБЛЮДЕНИЙ — с именем, а не голым числом: у числа адресата нет, и в позицию слова оно не
/// встаёт.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Seen(u32);

impl Word for Seen {
    type Of = Bench;
}

fn plan() -> Plan {
    Plan {
        programme: Programme::Pass,
        epoch: Epoch(1),
        basis: Basis::Default,
        interest: Interest::Idle,
    }
}

fn opening(payload: &[u8]) -> Packet<'_> {
    Packet {
        flow: FlowKey(7),
        dst: Addr(0x0A00_0001),
        dir: Dir::Up,
        opens: true,
        closes: false,
        resets: false,
        payload,
        says: Naming::Awaited,
    }
}

/// ДВИЖОК СТАНОВИТСЯ МОРФИЗМОМ: курсор — состояние, вердикт и наблюдение — выход.
#[test]
fn engine_enters_the_step_category() {
    let machine = Advancing::new(Cursor::Fresh);
    let bytes = [1u8, 2, 3];

    let (machine, answer) = machine.step((plan(), opening(&bytes), Tick(1)));

    assert_eq!(answer.act, Act::Pass, "план говорит пропускать");
    assert!(answer.noted.is_some(), "открытие разговора есть наблюдение");
    assert!(
        matches!(machine.cursor, Cursor::Running(_)),
        "курсор обязан переехать в состояние машины, а не остаться в выходе"
    );
}

/// СЧЁТЧИК НАБЛЮДЕНИЙ — обычное звено, не движок. В этом и предмет теста: носитель ОБЩИЙ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CountingSightings(u32);

impl Step for CountingSightings {
    type From = Answer;
    type To = Seen;

    fn step(self, answer: Self::From) -> (Self, Seen) {
        let seen = self.0 + u32::from(answer.noted.is_some());
        (CountingSightings(seen), Seen(seen))
    }
}

/// ЦЕПОЧКА «ДВИЖОК → ЧУЖОЕ ЗВЕНО» СОБИРАЕТСЯ.
///
/// Не собралась бы — совпадение подписей было бы косметическим, и §3 vision пришлось бы
/// переписывать.
#[test]
fn engine_composes_with_a_foreign_link() {
    let chain = Advancing::new(Cursor::Fresh).then(CountingSightings(0));
    let bytes = [1u8, 2, 3];

    let (chain, first) = chain.step((plan(), opening(&bytes), Tick(1)));
    let (_chain, second) = chain.step((plan(), opening(&bytes), Tick(2)));

    assert_eq!(first, Seen(1), "открытие дало одно наблюдение");
    assert_eq!(
        second,
        Seen(1),
        "продолжение того же разговора не несёт нового наблюдения — счётчик СОХРАНИЛ единицу, а \
         не пересобрался: состояние живёт у второго звена"
    );
}
