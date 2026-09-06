//! ДИАЛЕКТЫ ВХОДЯТ В КАТЕГОРИЮ ШАГА — проверкой, а не заявлением.
//!
//! Vision §3 утверждает: сводить нечего, подпись уже написана, диалекты входят в неё дисциплиной
//! на алфавиты. Утверждение проверяемо ровно одним способом — собрать цепочку, где звено из
//! чужого диалекта стоит рядом с обычным шагом. Соберётся — носитель общий; не соберётся —
//! совпадение подписей было косметическим.

use reflex_core::detector::{Detector, DetectorEvent};
use reflex_core::lifting::{Detecting, Reacting};
use reflex_core::step::{Step, StepExt};
use reflex_core::Reactor;
use smallvec::{smallvec, SmallVec};
use std::time::Instant;

/// СЧЁТЧИК ПАКЕТОВ: отдаёт порядковый номер и молчит на тике.
///
/// Тик обязан быть в алфавите и обязан НЕ порождать сигнала: тишина есть наблюдение, а не
/// выдуманное событие.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Counting(u32);

impl Detector for Counting {
    type Input = u8;
    type Signal = u32;

    fn step(self, event: DetectorEvent<u8>) -> (Self, SmallVec<[u32; 2]>) {
        match event {
            DetectorEvent::Packet { .. } => (Counting(self.0 + 1), smallvec![self.0]),
            DetectorEvent::Tick { .. } => (self, SmallVec::new()),
        }
    }
}

/// ВТОРОЕ ЗВЕНО — обычный шаг, не детектор. В этом и предмет теста.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Summing(u32);

impl Step for Summing {
    type From = SmallVec<[u32; 2]>;
    type To = u32;

    fn step(self, input: SmallVec<[u32; 2]>) -> (Self, u32) {
        let total = self.0 + input.iter().sum::<u32>();
        (Summing(total), total)
    }
}

/// ДЕТЕКТОР СТАНОВИТСЯ ЗВЕНОМ ЦЕПОЧКИ, и состояние живёт у обоих.
#[test]
fn detector_enters_the_step_category() {
    let chain = Detecting(Counting(0)).then(Summing(0));

    let (chain, first) = chain.step(DetectorEvent::Packet {
        input: 1,
        at: Instant::now(),
    });
    let (chain, second) = chain.step(DetectorEvent::Packet {
        input: 2,
        at: Instant::now(),
    });
    let (_chain, on_tick) = chain.step(DetectorEvent::Tick { at: Instant::now() });

    assert_eq!(first, 0, "первый пакет: номер 0, сумма 0");
    assert_eq!(second, 1, "второй: номер 1, сумма 0+1");
    assert_eq!(on_tick, 1, "тик сигнала не дал — сумма не сдвинулась");
}

/// ПЕРЕКЛЮЧАТЕЛЬ: каждое событие меняет состояние и объявляет новое.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Toggle(bool);

impl Reactor for Toggle {
    type Event = ();
    type Effect = bool;

    /// РОЖДЕНИЕ САМО ПО СЕБЕ ДЕЙСТВИЕМ НЕ ЯВЛЯЕТСЯ — эффекта нет.
    fn start() -> (Self, Option<bool>) {
        (Toggle(false), None)
    }

    fn step(self, _event: ()) -> (Self, Option<bool>) {
        (Toggle(!self.0), Some(!self.0))
    }
}

/// РЕАКТОР, ЧЬЁ РОЖДЕНИЕ ЕСТЬ ДЕЙСТВИЕ. Второй случай нужен затем, что `started` обязан эффект
/// рождения ОТДАТЬ, а не проглотить: `group_by_reactor` его сегодня отбрасывает, и это названная
/// потеря, которую подъём повторять не должен.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Announcing(u8);

impl Reactor for Announcing {
    type Event = u8;
    type Effect = u8;

    fn start() -> (Self, Option<u8>) {
        (Announcing(0), Some(255))
    }

    fn step(self, event: u8) -> (Self, Option<u8>) {
        (Announcing(self.0.wrapping_add(event)), Some(self.0))
    }
}

/// РЕАКТОР СТАНОВИТСЯ ШАГОМ — и только. Композицию доказывает
/// [`two_foreign_dialects_compose_with_each_other`], а не этот тест: здесь машина шагает одна.
#[test]
fn reactor_enters_the_step_category() {
    let (machine, birth) = Reacting::<Toggle>::started();
    assert_eq!(birth, None, "рождение переключателя действием не является");

    let (machine, first) = machine.step(());
    let (_machine, second) = machine.step(());

    assert_eq!(first, Some(true));
    assert_eq!(second, Some(false));
}

/// ЭФФЕКТ РОЖДЕНИЯ ОТДАЁТСЯ, А НЕ ГЛОТАЕТСЯ.
#[test]
fn birth_effect_is_returned_not_swallowed() {
    let (_machine, birth) = Reacting::<Announcing>::started();
    assert_eq!(
        birth,
        Some(255),
        "эффект рождения обязан выйти наружу: проглотив его, подъём повторил бы \
         названную потерю group_by_reactor"
    );
}

/// ПЕРЕКЛЮЧАТЕЛЬ, СЛУШАЮЩИЙ ПАЧКУ СИГНАЛОВ.
///
/// Вход — `SmallVec`, а не сигнал, и это не украшение: детектор отдаёт пачку, и сосед обязан
/// принимать её. Многовыходность не исчезает от того, что она ОДНО значение, — она переезжает
/// во входной алфавит следующего звена, и здесь это видно глазом.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TogglingOnSignals(bool);

impl Reactor for TogglingOnSignals {
    type Event = SmallVec<[u32; 2]>;
    type Effect = bool;

    fn start() -> (Self, Option<bool>) {
        (TogglingOnSignals(false), None)
    }

    fn step(self, signals: SmallVec<[u32; 2]>) -> (Self, Option<bool>) {
        match signals.is_empty() {
            // ПУСТАЯ ПАЧКА — НЕ СОБЫТИЕ. Тик проходит сквозь детектор, ничего не сказав, и
            // переключать по нему нечего.
            true => (self, None),
            false => (TogglingOnSignals(!self.0), Some(!self.0)),
        }
    }
}

/// ДВА ЧУЖИХ ДИАЛЕКТА В ОДНОЙ ЦЕПОЧКЕ — сильнейшая форма утверждения §3.
///
/// Прочие тесты ставят каждый диалект в пару с ОБЫЧНЫМ шагом, и этого мало: так доказано, что
/// каждый умеет стоять рядом со `Step`, но не что они умеют стоять рядом ДРУГ С ДРУГОМ. Носитель
/// общий ровно тогда, когда верно второе.
#[test]
fn two_foreign_dialects_compose_with_each_other() {
    let (reactor, birth) = Reacting::<TogglingOnSignals>::started();
    assert_eq!(birth, None, "рождение переключателя действием не является");

    let chain = Detecting(Counting(0)).then(reactor);

    let (chain, first) = chain.step(DetectorEvent::Packet {
        input: 1,
        at: Instant::now(),
    });
    let (chain, on_tick) = chain.step(DetectorEvent::Tick { at: Instant::now() });
    let (_chain, second) = chain.step(DetectorEvent::Packet {
        input: 2,
        at: Instant::now(),
    });

    assert_eq!(first, Some(true), "пакет дал сигнал — реактор переключился");
    assert_eq!(on_tick, None, "тик сигнала не дал — переключать нечего");
    assert_eq!(
        second,
        Some(false),
        "второй пакет переключил обратно: состояние живёт у ОБОИХ звеньев, а не пересобирается"
    );
}
