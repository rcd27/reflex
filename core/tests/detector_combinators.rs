//! КОМБИНАТОРЫ ДЕТЕКТОРА — `rmap`, `lmap`, `contextual`, `changes`.
//!
//! # Зачем они заведены
//!
//! Прибор говорит о МИРЕ и не должен знать доменных типов: у наблюдения на проводе (`Seen`)
//! мировая природа, у сообщения о беде (`Notice { identity, leg, … }`) — доменная. Пока
//! детектор принимает доменный вход и выдаёт доменный сигнал, вынести его в крейт приборов
//! нельзя вовсе — он тащит домен за собой.
//!
//! `lmap` сужает вход, `rmap` переименовывает сигнал. Вместе они делают детектор ПРОФУНКТОРОМ:
//! ядро прибора остаётся чистым про мир, а домен надевается снаружи отдельным звеном.
//!
//! `contextual` — третий, и он про память: сигнал одевается в то, что несло ПОСЛЕДНЕЕ
//! наблюдение. Нужен там, где `rmap` бессилен по природе — прибор со своими часами
//! высказывается по ТИКУ, когда наблюдения в этот момент нет вовсе. Сегодня эту роль играют
//! поля `identity`/`leg` внутри самого `Silence`, то есть доменные поля в приборе о мире.
//!
//! `changes` — четвёртый, и он про другое: переход вместо значения. Оператор потока
//! `distinct_until_changed` работает на потоке ЦЕЛИКОМ, а внутри `detect_per` экземпляр живёт
//! НА КЛЮЧ — то есть переход считается по той цели, о которой высказывание. Две цели,
//! чередуясь, прошли бы оператор потока насквозь.

use reflex_core::{Detector, DetectorEvent, DetectorExt};
use smallvec::{smallvec, SmallVec};

/// Вход: что случилось на проводе. Роль «мирового» словаря в этих тестах.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Rst,
    Byte,
}

/// Вход домена: то же событие, но с доменными полями вокруг.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Wire {
    flow: u8,
    kind: Kind,
}

/// Сигнал прибора — про мир, без единого доменного поля.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Distress {
    Rst,
}

/// Сигнал домена — с полем, которого прибор знать не может.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Trouble {
    flow: u8,
    distress: Distress,
}

/// Прибор: сигналит на каждый сброс. Знает только мировой словарь.
#[derive(Debug, Clone, Copy, Default)]
struct Rst;

impl Detector for Rst {
    type Input = Kind;
    type Signal = Distress;

    fn step(self, event: DetectorEvent<Kind>) -> (Self, SmallVec<[Distress; 2]>) {
        match event {
            DetectorEvent::Packet {
                input: Kind::Rst, ..
            } => (self, smallvec![Distress::Rst]),
            DetectorEvent::Packet {
                input: Kind::Byte, ..
            } => (self, smallvec![]),
            DetectorEvent::Tick { .. } => (self, smallvec![]),
        }
    }
}

fn packet(input: Kind) -> DetectorEvent<Kind> {
    DetectorEvent::packet_now(input)
}

/// Прогнать детектор по событиям, собрать сигналы.
///
/// Поток здесь намеренно не участвует: предмет — сам детектор, и подмешивать к нему `detect_per`
/// значило бы поверять два механизма одним тестом.
fn run<D: Detector>(detector: D, events: Vec<DetectorEvent<D::Input>>) -> Vec<D::Signal> {
    events
        .into_iter()
        .fold((detector, Vec::new()), |(state, said), event| {
            let (stepped, signals) = state.step(event);
            (stepped, said.into_iter().chain(signals).collect())
        })
        .1
}

/// ПЕРЕИМЕНОВАНИЕ СИГНАЛА — прибор говорит о мире, домен надевает своё поле снаружи.
#[test]
fn rmap_dresses_the_world_signal_in_domain_clothes() {
    let seen = run(
        Rst.rmap(|distress| Trouble { flow: 7, distress }),
        vec![packet(Kind::Rst), packet(Kind::Byte), packet(Kind::Rst)],
    );

    assert_eq!(
        seen,
        vec![
            Trouble {
                flow: 7,
                distress: Distress::Rst
            },
            Trouble {
                flow: 7,
                distress: Distress::Rst
            }
        ]
    );
}

/// ЗАКОН ФУНКТОРА 1 — `rmap id = id`. Переименование ни во что не меняет цепочку.
#[test]
fn rmap_with_identity_changes_nothing() {
    let events = || vec![packet(Kind::Rst), packet(Kind::Byte), packet(Kind::Rst)];

    let bare = run(Rst, events());
    let dressed = run(Rst.rmap(|distress| distress), events());

    assert_eq!(bare, dressed);
}

/// ЗАКОН ФУНКТОРА 2 — `rmap f ∘ rmap g = rmap (f ∘ g)`.
///
/// Без него два переименования подряд могли бы терять сигналы, и заметили бы мы это только на
/// длинной цепочке в проде.
#[test]
fn rmap_composes() {
    let events = || vec![packet(Kind::Rst), packet(Kind::Rst)];

    let twice = run(
        Rst.rmap(|distress| Trouble { flow: 7, distress })
            .rmap(|trouble| trouble.flow),
        events(),
    );

    let once = run(Rst.rmap(|_| 7u8), events());

    assert_eq!(twice, once);
}

/// Детектор со своими часами: сигналит на КАЖДЫЙ тик и молчит на пакеты.
///
/// Нужен ровно для одного закона — что сужение входа не отбирает у прибора время.
#[derive(Debug, Clone, Copy, Default)]
struct Clock;

impl Detector for Clock {
    type Input = Kind;
    type Signal = Distress;

    fn step(self, event: DetectorEvent<Kind>) -> (Self, SmallVec<[Distress; 2]>) {
        match event {
            DetectorEvent::Tick { .. } => (self, smallvec![Distress::Rst]),
            DetectorEvent::Packet { .. } => (self, smallvec![]),
        }
    }
}

fn wire(flow: u8, kind: Kind) -> DetectorEvent<Wire> {
    DetectorEvent::packet_now(Wire { flow, kind })
}

fn tick() -> DetectorEvent<Wire> {
    DetectorEvent::tick_now()
}

/// СУЖЕНИЕ ВХОДА — прибор, знающий только мировой словарь, встаёт в доменную цепочку.
#[test]
fn lmap_lets_a_world_instrument_stand_in_a_domain_chain() {
    let seen = run(
        Rst.lmap(|observed: &Wire| Some(observed.kind)),
        vec![wire(1, Kind::Rst), wire(1, Kind::Byte)],
    );

    assert_eq!(seen, vec![Distress::Rst]);
}

/// СОБЫТИЕ НЕ ПРО ЭТОТ ПРИБОР ДО НЕГО НЕ ДОХОДИТ ВОВСЕ.
///
/// Не «доходит и игнорируется»: прибор, которому подают чужой предмет, обязан не иметь
/// возможности о нём высказаться — иначе слепота одного звена становится словом о мире.
#[test]
fn lmap_drops_what_the_instrument_has_no_business_seeing() {
    let seen = run(
        Rst.lmap(|observed: &Wire| match observed.flow {
            1 => Some(observed.kind),
            _other => None,
        }),
        vec![wire(2, Kind::Rst), wire(1, Kind::Rst)],
    );

    assert_eq!(seen, vec![Distress::Rst], "чужой флоу не должен сигналить");
}

/// ТИК ПРОХОДИТ СКВОЗЬ СУЖЕНИЕ ВСЕГДА — часы прибора не отбираются фильтром входа.
///
/// Это не мелочь: `Silence` и всякий прибор со своими часами узнаёт о беде ИМЕННО тиком, и
/// сужение, съедающее тики, остановило бы ему время молча. Прибор при этом выглядел бы
/// исправным — он просто никогда бы не сработал.
#[test]
fn lmap_never_swallows_the_tick() {
    let seen = run(
        Clock.lmap(|_observed: &Wire| None),
        vec![tick(), tick(), tick()],
    );

    assert_eq!(
        seen,
        vec![Distress::Rst, Distress::Rst, Distress::Rst],
        "сужение входа, съевшее тики, останавливает часы прибора"
    );
}

/// ЗАКОН — `lmap` тождественным сужением не меняет ничего.
#[test]
fn lmap_with_a_total_narrowing_changes_nothing() {
    let bare = run(Rst, vec![packet(Kind::Rst), packet(Kind::Byte)]);
    let narrowed = run(
        Rst.lmap(|observed: &Wire| Some(observed.kind)),
        vec![wire(1, Kind::Rst), wire(1, Kind::Byte)],
    );

    assert_eq!(bare, narrowed);
}

/// Детектор СОСТОЯНИЯ: говорит, что видит, на каждый пакет. Именно такой и заваливает ленту
/// повторами — он высказывается по темпу трафика, а не по смене предмета.
#[derive(Debug, Clone, Copy, Default)]
struct Level;

impl Detector for Level {
    type Input = Kind;
    type Signal = Kind;

    fn step(self, event: DetectorEvent<Kind>) -> (Self, SmallVec<[Kind; 2]>) {
        match event {
            DetectorEvent::Packet { input, .. } => (self, smallvec![input]),
            DetectorEvent::Tick { .. } => (self, smallvec![]),
        }
    }
}

/// ПОВТОР ТОГО ЖЕ ПОКАЗАНИЯ ПОДАВЛЯЕТСЯ — наружу выходит смена, а не темп трафика.
#[test]
fn changes_says_it_once_however_often_it_is_seen() {
    let events = || {
        vec![
            packet(Kind::Rst),
            packet(Kind::Rst),
            packet(Kind::Rst),
            packet(Kind::Byte),
        ]
    };

    let every_time = run(Level, events());
    let on_change = run(Level.changes(), events());

    assert_eq!(
        every_time,
        vec![Kind::Rst, Kind::Rst, Kind::Rst, Kind::Byte],
        "контроль невакуумности: без комбинатора повторы идут все"
    );
    assert_eq!(on_change, vec![Kind::Rst, Kind::Byte]);
}

/// СРАВНЕНИЕ С ПОСЛЕДНИМ, А НЕ С МНОЖЕСТВОМ ВИДЕННОГО.
///
/// Возврат к прежнему показанию есть СОБЫТИЕ: «снова стало плохо» надо сказать, даже если
/// «плохо» уже звучало раньше. Комбинатор, помнящий всё виденное, проглотил бы вторую беду.
#[test]
fn changes_reports_a_return_to_a_previous_reading() {
    let said = run(
        Level.changes(),
        vec![packet(Kind::Rst), packet(Kind::Byte), packet(Kind::Rst)],
    );

    assert_eq!(said, vec![Kind::Rst, Kind::Byte, Kind::Rst]);
}

/// ЗАКОН ИДЕМПОТЕНТНОСТИ — `changes ∘ changes = changes`.
///
/// Тот же закон, что у оператора потока `distinct_until_changed`, только на ступени детектора.
/// Он и разрешает навешивать комбинатор, не проверяя, не навесил ли его уже кто-то ниже.
#[test]
fn changes_is_idempotent() {
    let events = || {
        vec![
            packet(Kind::Rst),
            packet(Kind::Rst),
            packet(Kind::Byte),
            packet(Kind::Byte),
        ]
    };

    let once = run(Level.changes(), events());
    let twice = run(Level.changes().changes(), events());

    assert_eq!(once, twice);
}

/// ПЕРВОЕ ПОКАЗАНИЕ ПРОХОДИТ ВСЕГДА — ему не с чем совпадать.
///
/// Молчать о нём значило бы потерять начальное состояние: подключившийся к исправной цели не
/// узнал бы о ней ничего до первой перемены.
#[test]
fn changes_lets_the_very_first_reading_through() {
    let said = run(Level.changes(), vec![packet(Kind::Byte)]);

    assert_eq!(said, vec![Kind::Byte]);
}

/// КОНТЕКСТ БЕРЁТСЯ С ПОСЛЕДНЕГО НАБЛЮДЕНИЯ — сигнал одевается в то, чего прибор не знает.
#[test]
fn contextual_dresses_the_signal_in_what_the_last_observation_carried() {
    let said = run(
        Rst.lmap(|observed: &Wire| Some(observed.kind)).contextual(
            |observed: &Wire| observed.flow,
            |flow, distress| {
                flow.map(|flow| Trouble {
                    flow: *flow,
                    distress,
                })
            },
        ),
        vec![wire(3, Kind::Rst)],
    );

    assert_eq!(
        said,
        vec![Trouble {
            flow: 3,
            distress: Distress::Rst
        }]
    );
}

/// СИГНАЛ ПО ТИКУ ОДЕВАЕТСЯ В КОНТЕКСТ ПОСЛЕДНЕГО ПАКЕТА.
///
/// Это главный случай, ради которого комбинатор заведён: прибор тишины высказывается ИМЕННО по
/// тику, когда пакета в этот момент нет вовсе. Сегодня ради него `Silence` носит внутри
/// `identity` и `leg` — доменные поля в приборе о мире, и только затем, чтобы назвать их в
/// сигнале.
#[test]
fn contextual_remembers_across_the_tick() {
    let said = run(
        Clock
            .lmap(|observed: &Wire| Some(observed.kind))
            .contextual(
                |observed: &Wire| observed.flow,
                |flow, distress| {
                    flow.map(|flow| Trouble {
                        flow: *flow,
                        distress,
                    })
                },
            ),
        vec![wire(5, Kind::Byte), tick()],
    );

    assert_eq!(
        said,
        vec![Trouble {
            flow: 5,
            distress: Distress::Rst
        }],
        "по тику сигнал обязан нести контекст последнего пакета"
    );
}

/// КОНТЕКСТ ОБНОВЛЯЕТСЯ: одевается ПОСЛЕДНИЙ виденный, а не первый.
#[test]
fn contextual_dresses_in_the_latest_context_not_the_first() {
    let said = run(
        Rst.lmap(|observed: &Wire| Some(observed.kind)).contextual(
            |observed: &Wire| observed.flow,
            |flow, distress| {
                flow.map(|flow| Trouble {
                    flow: *flow,
                    distress,
                })
            },
        ),
        vec![wire(1, Kind::Byte), wire(2, Kind::Rst)],
    );

    assert_eq!(
        said,
        vec![Trouble {
            flow: 2,
            distress: Distress::Rst
        }]
    );
}

/// КОНТЕКСТА ЕЩЁ НЕТ — И ЭТО ВИДНО ВЫЗЫВАЮЩЕМУ, а не решается за него молча.
///
/// Сигнал, случившийся до первого наблюдения (прибор со своими часами это умеет), одеть не во
/// что. Комбинатор не выдумывает контекст и не роняет сигнал сам: он отдаёт `None` в одевалку, и
/// та решает — потерять или сказать без контекста. Молчаливое решение здесь было бы потерей
/// беды, которую никто бы не заметил.
#[test]
fn contextual_admits_when_there_is_no_context_yet() {
    let said = run(
        Clock
            .lmap(|observed: &Wire| Some(observed.kind))
            .contextual(
                |observed: &Wire| observed.flow,
                |flow, distress| {
                    flow.map(|flow| Trouble {
                        flow: *flow,
                        distress,
                    })
                },
            ),
        vec![tick()],
    );

    assert_eq!(said, Vec::<Trouble>::new());
}

/// МОМЕНТ ВЫСКАЗЫВАНИЯ ВЫХОДИТ ВМЕСТЕ С СИГНАЛОМ.
///
/// Без этого комбинатора момент теряется на границе детектора: `Signal` времени не несёт, а
/// `detect_per` отдаёт наружу пару `(ключ, сигнал)` — и всякий, кому нужна ЛЕНТА, вынужден
/// обходить оператор и катать детекторы руками. Ровно та беда, ради которой заведены комбинаторы.
#[test]
fn timed_carries_the_moment_the_instrument_spoke() {
    let start = std::time::Instant::now();
    let at = start + std::time::Duration::from_millis(500);

    let said = run(
        Rst.timed(),
        vec![DetectorEvent::Packet {
            input: Kind::Rst,
            at,
        }],
    );

    assert_eq!(said, vec![(at, Distress::Rst)]);
}

/// МОМЕНТ БЕРЁТСЯ У ТИКА ТОЖЕ — иначе прибор со своими часами метил бы беду временем последнего
/// пакета, то есть ВРАЛ БЫ О ТОМ, КОГДА ЗАМЕТИЛ.
#[test]
fn timed_stamps_a_tick_signal_with_the_tick_moment() {
    let start = std::time::Instant::now();
    let tick_at = start + std::time::Duration::from_secs(2);

    let said = run(Clock.timed(), vec![DetectorEvent::Tick { at: tick_at }]);

    assert_eq!(said, vec![(tick_at, Distress::Rst)]);
}

/// КОНТРОЛЬ НЕВАКУУМНОСТИ к обоим законам выше: цепочка НЕ пуста и различает входы.
///
/// Без него `rmap id = id` держался бы даром на детекторе, который всегда молчит.
#[test]
fn the_chain_actually_signals() {
    let with_rst = run(Rst.rmap(|_| 1u8), vec![packet(Kind::Rst)]);
    let without = run(Rst.rmap(|_| 1u8), vec![packet(Kind::Byte)]);

    assert_eq!(with_rst, vec![1]);
    assert_eq!(without, Vec::<u8>::new());
}
