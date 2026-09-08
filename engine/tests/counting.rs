//! СЧЁТ И РЕШЕНИЕ СНЯТЫ С ОДНОЙ БУКВЫ (канон §1).
//!
//! Прежде это держала свободная функция `advance(step, counted, …)` — рукописная композиция
//! «посчитать и шагнуть», собранная ровно потому, что морфизм не выражал заимствованный пакет.
//! Проверялась она подставными шагами-замыканиями, то есть на том, чего в бою нет.
//!
//! Композиция уехала в фундамент (`Alongside`), и здесь проверяется НАСТОЯЩАЯ пара продукта:
//! `Advancing` говорит вердикт, `Counting` молчит и копит. Три свойства прежних проверок —
//! «счёт идёт при потере, при отводе, при обрыве» — держатся теперь подписью, а не тестом:
//! счётчику вердикт не подаётся вовсе, его букву `(Plan, Packet, Tick)` слово не пересекает.

use reflex_core::step::{Step, StepExt};
use reflex_engine::meter::Counting;
use reflex_engine::row::Naming;
use reflex_engine::step::Advancing;
use reflex_engine::{
    Act, Addr, Basis, Cursor, Dir, Epoch, FlowKey, Interest, Packet, Plan, Programme, Tick,
};

fn plan() -> Plan {
    Plan {
        programme: Programme::Pass,
        epoch: Epoch(1),
        basis: Basis::Default,
        interest: Interest::Idle,
    }
}

fn packet(dir: Dir, bytes: usize, opens: bool) -> Packet {
    Packet {
        flow: FlowKey(7),
        dst: Addr(0x0A00_0001),
        dir,
        opens,
        closes: false,
        resets: false,
        payload_len: bytes,
        says: Naming::Awaited,
    }
}

/// БАЙТЫ СЧИТАЮТСЯ ПО ТОМУ ЖЕ ПАКЕТУ, ПО КОТОРОМУ ВЫНЕСЕН ВЕРДИКТ.
///
/// Направление разносится по своим колонкам, открытие считается один раз, а начало отсчёта
/// замирает на первом пакете и дальше не двигается.
#[test]
fn the_pair_counts_the_very_packets_it_judges() {
    let mut chain = Advancing::new(Cursor::Fresh).alongside(Counting::fresh());
    let mut verdicts = Vec::new();
    let mut last = None;

    for (turn, (dir, bytes, opens)) in [
        (Dir::Up, 100, true),
        (Dir::Down, 200, false),
        (Dir::Up, 300, false),
    ]
    .into_iter()
    .enumerate()
    {
        let now = Tick(turn as u64 + 1);
        let (next, act, (_sighting, tally)) = chain.step((plan(), packet(dir, bytes, opens), now));
        chain = next;
        verdicts.push(act);
        last = Some(tally);
    }

    let tally = last.expect("три буквы прошли");
    assert_eq!(verdicts, vec![Act::Pass; 3], "план говорит пропускать");
    assert_eq!(tally.up_bytes, 400, "вверх: 100 + 300");
    assert_eq!(tally.down_bytes, 200, "вниз: 200");
    assert_eq!(tally.packets, 3);
    assert_eq!(tally.flows_opened, 1, "открытие было одно");
    assert_eq!(
        tally.since,
        Tick(1),
        "начало отсчёта замерло на первом пакете"
    );
}

/// НАБЛЮДЕНИЕ ДОЕЗЖАЕТ ЦЕЛИКОМ И ЧЕРЕЗ СОСЕДСТВО: адресат и момент не теряются по дороге.
#[test]
fn the_sighting_survives_the_neighbour() {
    let chain = Advancing::new(Cursor::Fresh).alongside(Counting::fresh());

    let (_chain, _act, (sighting, _tally)) =
        chain.step((plan(), packet(Dir::Up, 0, true), Tick(5)));

    let noted = sighting.expect("открытие разговора есть наблюдение");
    assert_eq!(noted.at, Tick(5), "момент наблюдения");
    assert_eq!(
        noted.about,
        reflex_engine::About::Talk(FlowKey(7)),
        "адресат наблюдения"
    );
}
