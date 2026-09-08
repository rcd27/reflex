//! ДВИЖОК ВХОДИТ В КАТЕГОРИЮ ШАГА (канон §1).
//!
//! Один из живых диалектов шага (`step::Mealy::step`, `engine::step::step`, `Plane::feed`,
//! `NfqHandler::handle`) и единственный, у которого вход НЕ БЫЛ ЗАМКНУТ: знание о цели
//! приходило Reader'ом (`look_up: Fn(&Packet) -> Plan`), то есть незаписанным входом. Здесь оно
//! становится БУКВОЙ входного алфавита, и этим переигровка одного разговора замыкается: чтобы
//! прогнать его заново, не нужна вся таблица целей — довольно того, что `look_up` ответил.

use reflex_core::mealy::{Mealy, MealyExt};
use reflex_core::word::{Base, Word};
use reflex_engine::row::Naming;
use reflex_engine::step::Advancing;
use reflex_engine::{
    Act, Addr, Basis, Cursor, Dir, Epoch, FlowKey, Interest, Packet, Plan, Programme, Tick,
};

/// ОБЛАСТЬ ЗАКОННОГО СТЕНДА.
///
/// Объявляется здесь, а не в фундаменте: закон обязан быть выразим для того, кто заводит свою
/// область снаружи, и стенд — законный заводящий.
struct Bench;
impl Base for Bench {
    type Fibre = ();
}

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

fn opening(payload: &[u8]) -> Packet {
    Packet {
        flow: FlowKey(7),
        dst: Addr(0x0A00_0001),
        dir: Dir::Up,
        opens: true,
        closes: false,
        resets: false,
        payload_len: payload.len(),
        says: Naming::Awaited,
    }
}

/// ДВИЖОК СТАНОВИТСЯ МОРФИЗМОМ: курсор — состояние, вердикт — слово, наблюдение — показание.
///
/// ТРОЙКА, А НЕ `Answer`: прежде вердикт и наблюдение были слиты в один тип ровно потому, что
/// голому кортежу нельзя было объявить адрес, не соврав про половину — `Act` адресован пакету,
/// `Noted` не адресован никому. Второй выход шага снял нужду во временной обёртке.
#[test]
fn engine_enters_the_step_category() {
    let machine = Advancing::new(Cursor::Fresh);
    let bytes = [1u8, 2, 3];

    let (machine, act, notes) = machine.step((plan(), opening(&bytes), Tick(1)));

    assert_eq!(act, Act::Pass, "план говорит пропускать");
    assert!(notes.is_some(), "открытие разговора есть наблюдение");
    assert!(
        matches!(machine.cursor, Cursor::Running(_)),
        "курсор обязан переехать в состояние машины, а не остаться в выходе"
    );
}

/// СЧЁТЧИК ШАГОВ — обычное звено, не движок. В этом и предмет теста: носитель ОБЩИЙ.
///
/// РАНЬШЕ ОН СЧИТАЛ НАБЛЮДЕНИЯ (`answer.noted.is_some()`), потому что наблюдение приезжало
/// слитым со словом. Показание уходит ВБОК, а не в `From` соседа, и потому сосед по цепочке его
/// читать не может — это и есть закон, а не пробел в счётчике: он считает шаги, а наблюдение
/// достаётся только тому, кто вызвал `.step()` на цепочке целиком (см. ниже).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CountingSteps(u32);

impl Mealy for CountingSteps {
    type In = Act;
    type Out = Seen;
    type Log = ();

    fn step(self, _act: Act) -> (Self, Seen, ()) {
        let seen = self.0 + 1;
        (CountingSteps(seen), Seen(seen), ())
    }
}

/// ЦЕПОЧКА «ДВИЖОК → ЧУЖОЕ ЗВЕНО» СОБИРАЕТСЯ, И ПОКАЗАНИЕ ИДЁТ МИМО СОСЕДА.
///
/// Собралась бы цепочка при косметическом совпадении подписей — не было бы: `Mealy` требует
/// `B::In = A::Out`, и здесь это ровно `Act`, а не слитая пара. Показание же (`Option<Noted>`)
/// достаётся ТОЛЬКО вызывающему цепочку целиком — позиция в типе (`Advancing` первым) называет
/// автора без единого слова прозы.
#[test]
fn engine_composes_with_a_foreign_link() {
    let chain = Advancing::new(Cursor::Fresh).then(CountingSteps(0));
    let bytes = [1u8, 2, 3];

    let (chain, first, (first_notes, ())) = chain.step((plan(), opening(&bytes), Tick(1)));
    let (_chain, second, (second_notes, ())) = chain.step((plan(), opening(&bytes), Tick(2)));

    assert_eq!(first, Seen(1), "слово дошло до соседа — цепочка собралась");
    assert_eq!(
        second,
        Seen(2),
        "состояние живёт у второго звена, а не пересобирается на каждом входе"
    );

    assert!(
        first_notes.is_some(),
        "открытие разговора есть наблюдение, и оно видно вызывающему"
    );
    assert!(
        second_notes.is_none(),
        "продолжение того же разговора не несёт нового наблюдения — сосед этого не видел бы \
         в любом случае, он его и не читает"
    );
}

/// ГОРЯЧИЙ ПУТЬ ВЫРАЖЕН: одна машина, у каждого пакета свой срок жизни байтов.
///
/// Этот цикл НЕ СОБИРАЛСЯ (`E0597`, 06.09.2026), и потому продукт звал свободную функцию мимо
/// морфизма. Причина была в `Packet<'a>`: лайфтайм уходил в `Advancing<'a>`, а `Mealy::In` не
/// умеет заимствовать только на время вызова — все пакеты одной машины обязаны были делить одну
/// область заимствования, тогда как в бою байты принадлежат сообщению ядра и живут до вердикта.
///
/// Байты здесь заводятся ВНУТРИ оборота намеренно: это и есть форма боевого цикла, а не
/// украшение теста.
#[test]
fn one_machine_eats_packets_borrowed_for_their_own_turn() {
    let mut machine = Advancing::new(Cursor::Fresh);
    let mut verdicts = Vec::new();

    for turn in 1..=3u64 {
        let bytes = vec![turn as u8; turn as usize];
        let packet = Packet {
            opens: turn == 1,
            ..opening(&bytes)
        };
        let (next, act, _notes) = machine.step((plan(), packet, Tick(turn)));
        machine = next;
        verdicts.push(act);
        drop(bytes);
    }

    assert_eq!(
        verdicts,
        vec![Act::Pass; 3],
        "план говорит пропускать все три"
    );
    assert!(
        matches!(machine.cursor, Cursor::Running(_)),
        "состояние пережило все три оборота, хотя байты каждого умерли на своём"
    );
}
