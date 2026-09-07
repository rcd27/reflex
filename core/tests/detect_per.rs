//! Тесты `detect_per` и композиции детекторов.
//!
//! Оба примитива заведены ради одного требования: **доменный шаг обязан быть звеном цепочки, а
//! не кодом внутри чужого шага**. Пока правило детекции живёт в теле `group_by`, добавить
//! детекцию троттлинга UDP нельзя, не тронув существующий обработчик, — и цепочка перестаёт быть
//! конструктором.

use std::time::{Duration, Instant};

use futures::{stream, StreamExt};
use reflex_core::step::{Step, StepExt};
use reflex_core::word::{Region, Word};
use reflex_core::{DetectorEvent, ReflexExt};
use smallvec::{smallvec, SmallVec};

/// ОБЛАСТЬ ЗАКОННОГО СТЕНДА.
///
/// Объявляется здесь, а не в фундаменте: закон обязан быть выразим для того, кто заводит свою
/// область снаружи, и стенд — законный заводящий.
struct Bench;
impl Region for Bench {}

/// Вход: адрес плюс что случилось. Свой тип, чтобы тест не зависел от словаря `TcpSegment`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Event {
    addr: u8,
    kind: Kind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Rst,
    Byte,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Signal {
    SawRst,
    WentQuiet,
    SawByte,
}

impl Word for Signal {
    type Of = Bench;
}

/// Детектор сброса: сигналит на каждый RST, времени не знает.
#[derive(Debug, Clone, Copy, Default)]
struct Rst;

impl Step for Rst {
    type From = DetectorEvent<Event>;
    type To = SmallVec<[Signal; 2]>;
    type Notes = ();

    fn step(self, event: Self::From) -> (Self, Self::To, ()) {
        match event {
            DetectorEvent::Packet {
                input: Event {
                    kind: Kind::Rst, ..
                },
                ..
            } => (self, smallvec![Signal::SawRst], ()),
            DetectorEvent::Packet { .. } => (self, smallvec![], ()),
            DetectorEvent::Tick { .. } => (self, smallvec![], ()),
            DetectorEvent::Opaque { .. } => (self, smallvec![], ()),
        }
    }
}

/// Детектор тишины: сигналит по ТИКУ, если пакетов не было дольше порога.
///
/// Он и есть причина, по которой `Tick` обязан приходить во все живые состояния: тишина есть
/// ОТСУТСТВИЕ пакетов, а отсутствие пакетов не порождает элементов потока.
#[derive(Debug, Clone, Copy)]
struct Quiet {
    last: Option<Instant>,
    after: Duration,
    fired: bool,
}

impl Quiet {
    fn after(after: Duration) -> Self {
        Self {
            last: None,
            after,
            fired: false,
        }
    }
}

impl Step for Quiet {
    type From = DetectorEvent<Event>;
    type To = SmallVec<[Signal; 2]>;
    type Notes = ();

    fn step(self, event: Self::From) -> (Self, Self::To, ()) {
        match event {
            DetectorEvent::Packet { at, .. } => (
                Self {
                    last: Some(at),
                    ..self
                },
                smallvec![],
                (),
            ),
            DetectorEvent::Tick { at, .. } => match (self.last, self.fired) {
                (Some(last), false) if at.duration_since(last) >= self.after => (
                    Self {
                        fired: true,
                        ..self
                    },
                    smallvec![Signal::WentQuiet],
                    (),
                ),
                _ => (self, smallvec![], ()),
            },
            // ТИШИНА МЕРИТСЯ МЕЖДУ РАЗОБРАННЫМИ СОБЫТИЯМИ: непонятое не гарантирует, что это
            // вообще наш разговор, и не вправе отодвигать порог, — состояние не трогается.
            DetectorEvent::Opaque { .. } => (self, smallvec![], ()),
        }
    }
}

/// Третий детектор — существует, чтобы доказать, что цепочка `Both` РАСТЁТ, а не переписывается.
#[derive(Debug, Clone, Copy, Default)]
struct Bytes;

impl Step for Bytes {
    type From = DetectorEvent<Event>;
    type To = SmallVec<[Signal; 2]>;
    type Notes = ();

    fn step(self, event: Self::From) -> (Self, Self::To, ()) {
        match event {
            DetectorEvent::Packet {
                input: Event {
                    kind: Kind::Byte, ..
                },
                ..
            } => (self, smallvec![Signal::SawByte], ()),
            DetectorEvent::Packet { .. } => (self, smallvec![], ()),
            DetectorEvent::Tick { .. } => (self, smallvec![], ()),
            DetectorEvent::Opaque { .. } => (self, smallvec![], ()),
        }
    }
}

fn packet(addr: u8, kind: Kind, at: Instant) -> DetectorEvent<Event> {
    DetectorEvent::Packet {
        input: Event { addr, kind },
        at,
    }
}

/// УПЛОЩЕНИЕ ЖИВЁТ У ПОТРЕБИТЕЛЯ, И ЗДЕСЬ ОН — СТЕНД.
///
/// Плоский список «ключ и сигнал» удобен ассерту, но добывается он ЗДЕСЬ, из вышедших наружу пар,
/// а не в подъёме: подъём поднимает шаг, а не разбирает его слово. Форма помощника нарочно
/// беднее подъёма — она теряет молчание и показание, — и потому годится только тем проверкам,
/// чей предмет есть сказанное.
fn spoke<W: Clone, N>(got: &[(u8, (SmallVec<[W; 2]>, N))]) -> Vec<(u8, W)> {
    got.iter()
        .flat_map(|(key, (said, _))| said.iter().map(|signal| (*key, signal.clone())))
        .collect()
}

/// СОСТОЯНИЕ ЖИВЁТ ПО КЛЮЧУ и не смешивается между целями.
#[tokio::test]
async fn state_is_per_key() {
    let t0 = Instant::now();
    let got: Vec<(
        u8,
        ((SmallVec<[Signal; 2]>, SmallVec<[Signal; 2]>), ((), ())),
    )> = stream::iter([
        packet(1, Kind::Rst, t0),
        packet(2, Kind::Byte, t0),
        packet(1, Kind::Byte, t0),
    ])
    .detect_per(
        |e: &Event| e.addr,
        || Rst.and(Bytes),
        reflex_core::stream::Lifetime::Bounded,
    )
    .collect()
    .await;

    // СЛОЖЕННЫЕ НАБЛЮДАТЕЛИ ВСТАЮТ В ПОДЪЁМ БЕЗ ПЕРЕХОДНИКА, и слово выходит произведением: кто
    // из двоих сказал, называет позиция, а не метка в работе.
    assert_eq!(
        got.iter()
            .map(|(key, (said, _))| (*key, said.clone()))
            .collect::<Vec<_>>(),
        vec![
            (1, (smallvec![Signal::SawRst], smallvec![])),
            (2, (smallvec![], smallvec![Signal::SawByte])),
            (1, (smallvec![], smallvec![Signal::SawByte])),
        ]
    );
}

/// ГЛАВНОЕ, РАДИ ЧЕГО ОПЕРАТОР СУЩЕСТВУЕТ: тик приходит ВО ВСЕ живые состояния.
///
/// Через `group_by` это невыразимо — он ключует каждый элемент, а у тика ключа нет. Детектор
/// тишины без этого не сработал бы никогда.
#[tokio::test]
async fn tick_reaches_every_live_state() {
    let t0 = Instant::now();
    let later = t0 + Duration::from_secs(2);

    let got: Vec<(u8, (SmallVec<[Signal; 2]>, ()))> = stream::iter([
        packet(1, Kind::Byte, t0),
        packet(2, Kind::Byte, t0),
        DetectorEvent::Tick { node: 1, at: later },
    ])
    .detect_per(
        |e: &Event| e.addr,
        || Quiet::after(Duration::from_secs(1)),
        reflex_core::stream::Lifetime::Bounded,
    )
    .collect()
    .await;

    assert_eq!(
        spoke(&got),
        vec![(1, Signal::WentQuiet), (2, Signal::WentQuiet)],
        "тик обязан дойти до обоих ключей, и в детерминированном порядке: {got:?}"
    );
}

/// КОНТРОЛЬ: тик до истечения порога не сигналит. Без него тест выше зеленел бы и при
/// детекторе, который сигналит на любой тик.
#[tokio::test]
async fn tick_before_threshold_is_silent() {
    let t0 = Instant::now();
    let got: Vec<(u8, (SmallVec<[Signal; 2]>, ()))> = stream::iter([
        packet(1, Kind::Byte, t0),
        DetectorEvent::Tick {
            node: 1,
            at: t0 + Duration::from_millis(500),
        },
    ])
    .detect_per(
        |e: &Event| e.addr,
        || Quiet::after(Duration::from_secs(1)),
        reflex_core::stream::Lifetime::Bounded,
    )
    .collect()
    .await;

    // Шаг был на каждом событии, и пара вышла с каждого шага; сказано при этом не было ничего.
    assert!(spoke(&got).is_empty(), "сработало раньше порога: {got:?}");
}

/// Тик до первого пакета не сигналит: состояний ещё нет, будить некого.
#[tokio::test]
async fn tick_without_any_state_is_silent() {
    let got: Vec<(u8, (SmallVec<[Signal; 2]>, ()))> = stream::iter([DetectorEvent::Tick {
        node: 1,
        at: Instant::now(),
    }])
    .detect_per(
        |e: &Event| e.addr,
        || Quiet::after(Duration::from_secs(1)),
        reflex_core::stream::Lifetime::Bounded,
    )
    .collect()
    .await;

    // Ни одного шага не случилось вовсе: будить было некого — значит и пары ни одной.
    assert!(got.is_empty());
}

/// ОБА ДЕТЕКТОРА ВИДЯТ КАЖДОЕ СОБЫТИЕ — это независимые наблюдатели, а не цепочка фильтров.
/// Порядок сигналов: сначала левый, затем правый.
#[tokio::test]
async fn composition_lets_both_observe() {
    let t0 = Instant::now();

    #[derive(Debug, Clone, Copy, Default)]
    struct Everything;
    impl Step for Everything {
        type From = DetectorEvent<Event>;
        type To = SmallVec<[Signal; 2]>;
        type Notes = ();
        fn step(self, event: Self::From) -> (Self, Self::To, ()) {
            match event {
                DetectorEvent::Packet { .. } => (self, smallvec![Signal::SawByte], ()),
                DetectorEvent::Tick { .. } => (self, smallvec![], ()),
                // Витнес «видит всё» из разобранного потока; непонятое в это «всё» не входит.
                DetectorEvent::Opaque { .. } => (self, smallvec![], ()),
            }
        }
    }

    let got: Vec<(
        u8,
        ((SmallVec<[Signal; 2]>, SmallVec<[Signal; 2]>), ((), ())),
    )> = stream::iter([packet(1, Kind::Rst, t0)])
        .detect_per(
            |e: &Event| e.addr,
            || Rst.and(Everything),
            reflex_core::stream::Lifetime::Bounded,
        )
        .collect()
        .await;

    assert_eq!(
        got.iter()
            .map(|(key, (said, _))| (*key, said.clone()))
            .collect::<Vec<_>>(),
        vec![(1, (smallvec![Signal::SawRst], smallvec![Signal::SawByte]))]
    );
}

/// ЦЕПОЧКА РАСТЁТ ДОПИСЫВАНИЕМ. Третий детектор добавлен оборачиванием в `Both`, снаружи — правила
/// `Rst` и `Quiet` при этом не читались и не правились. Это и есть требование, ради которого оба
/// примитива заведены.
#[tokio::test]
async fn chain_grows_by_appending() {
    let t0 = Instant::now();
    let later = t0 + Duration::from_secs(2);

    type Word3 = (
        (SmallVec<[Signal; 2]>, SmallVec<[Signal; 2]>),
        SmallVec<[Signal; 2]>,
    );

    let got: Vec<(u8, (Word3, (((), ()), ())))> = stream::iter([
        packet(1, Kind::Rst, t0),
        packet(1, Kind::Byte, t0),
        DetectorEvent::Tick { node: 1, at: later },
    ])
    .detect_per(
        |e: &Event| e.addr,
        || Rst.and(Quiet::after(Duration::from_secs(1))).and(Bytes),
        reflex_core::stream::Lifetime::Bounded,
    )
    .collect()
    .await;

    // ТРЕТИЙ ПРИБОР ПРИСТРОЕН СБОКУ, А НЕ ВПИСАН В ЧУЖОЕ СЛОВО: место каждого в произведении
    // видно на глаз, и добавление не тронуло ни одного из двух прежних.
    assert_eq!(
        got.iter()
            .map(|(key, (said, _))| (*key, said.clone()))
            .collect::<Vec<_>>(),
        vec![
            (1, ((smallvec![Signal::SawRst], smallvec![]), smallvec![])),
            (1, ((smallvec![], smallvec![]), smallvec![Signal::SawByte])),
            (
                1,
                ((smallvec![], smallvec![Signal::WentQuiet]), smallvec![])
            ),
        ]
    );
}

/// СЛОВО ВЫХОДИТ ЦЕЛИКОМ, а не по буквам, и не теряется, когда источник завершается сразу за
/// событием, его породившим.
///
/// Разбери подъём слово на сигналы — и он объявил бы себя знатоком его формы; тогда всякое слово,
/// формы этой не имеющее (произведение, например), в подъём бы не встало. Здесь проверяется, что
/// он этого не делает: два сигнала выходят ОДНИМ словом, а не двумя элементами потока.
#[tokio::test]
async fn signals_survive_source_completion() {
    let t0 = Instant::now();

    #[derive(Debug, Clone, Copy, Default)]
    struct Twice;
    impl Step for Twice {
        type From = DetectorEvent<Event>;
        type To = SmallVec<[Signal; 2]>;
        type Notes = ();
        fn step(self, event: Self::From) -> (Self, Self::To, ()) {
            match event {
                DetectorEvent::Packet { .. } => {
                    (self, smallvec![Signal::SawRst, Signal::SawByte], ())
                }
                DetectorEvent::Tick { .. } => (self, smallvec![], ()),
                // Витнес видит только разобранные события; непонятое молчит так же, как тик.
                DetectorEvent::Opaque { .. } => (self, smallvec![], ()),
            }
        }
    }

    let got: Vec<(u8, (SmallVec<[Signal; 2]>, ()))> = stream::iter([packet(1, Kind::Rst, t0)])
        .detect_per(
            |e: &Event| e.addr,
            || Twice,
            reflex_core::stream::Lifetime::Bounded,
        )
        .collect()
        .await;

    assert_eq!(
        got.len(),
        1,
        "шаг был один — и пара обязана быть одна: {got:?}"
    );
    assert_eq!(
        spoke(&got),
        vec![(1, Signal::SawRst), (1, Signal::SawByte)],
        "потерян сигнал на завершении источника: {got:?}"
    );
}

/// ДЕТЕКТОР С ПАМЯТЬЮ: считает пакеты и на тике говорит, сколько насчитал. По нему видно, забыто
/// состояние или нет, — булев сигнал этого не показал бы.
#[derive(Debug, Clone, Copy, Default)]
struct Counting(u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Counted(u8);

impl Word for Counted {
    type Of = Bench;
}

impl Step for Counting {
    type From = DetectorEvent<Event>;
    type To = SmallVec<[Counted; 2]>;
    type Notes = ();

    fn step(self, event: Self::From) -> (Self, Self::To, ()) {
        match event {
            DetectorEvent::Packet { .. } => (Counting(self.0 + 1), smallvec![], ()),
            DetectorEvent::Tick { .. } => (self, smallvec![Counted(self.0)], ()),
            // Считающий детектор мерит разобранные события; непонятое ни пакет, ни тик — молчит.
            DetectorEvent::Opaque { .. } => (self, smallvec![], ()),
        }
    }
}

/// СОСТОЯНИЕ КЛЮЧА, ПО КОТОРОМУ ДАВНО НИЧЕГО НЕ БЫЛО, СНИМАЕТСЯ.
///
/// Ключей у потока соединений неограниченно много: каждое новое соединение — новый ключ, и ни
/// одно не возвращается. Состояние, которое живёт до конца потока, на коробке, работающей
/// неделями, растёт без границы.
#[tokio::test]
async fn a_key_that_went_quiet_for_too_long_is_forgotten() {
    let t0 = Instant::now();
    let limit = Duration::from_secs(10);

    let counts: Vec<(u8, (SmallVec<[Counted; 2]>, ()))> = stream::iter([
        packet(1, Kind::Byte, t0),
        packet(1, Kind::Byte, t0),
        // Простой ДОЛЬШЕ предела: тик приходит, но по ключу 1 событий не было.
        DetectorEvent::Tick {
            node: 1,
            at: t0 + limit,
        },
        // Новый пакет того же ключа — состояние обязано быть НОВЫМ.
        packet(1, Kind::Byte, t0 + limit * 2),
        DetectorEvent::Tick {
            node: 2,
            at: t0 + limit * 2,
        },
    ])
    .detect_per(
        |e: &Event| e.addr,
        Counting::default,
        reflex_core::stream::Lifetime::UntilIdle(limit),
    )
    .collect()
    .await;

    assert_eq!(
        spoke(&counts).last(),
        Some(&(1, Counted(1))),
        "состояние ключа пережило простой: считает {counts:?}, а обязано начать заново"
    );
}

/// КОНТРОЛЬ: пока по ключу идут события, состояние НЕ снимается.
///
/// Без него тест выше зеленел бы и на операторе, который забывает всё подряд, — а такой оператор
/// не детектор вовсе: тишина меряется накопленным.
#[tokio::test]
async fn an_active_key_keeps_its_state() {
    let t0 = Instant::now();
    let limit = Duration::from_secs(10);
    let step = Duration::from_secs(1);

    let counts: Vec<(u8, (SmallVec<[Counted; 2]>, ()))> = stream::iter([
        packet(1, Kind::Byte, t0),
        packet(1, Kind::Byte, t0 + step),
        packet(1, Kind::Byte, t0 + step * 2),
        DetectorEvent::Tick {
            node: 3,
            at: t0 + step * 3,
        },
    ])
    .detect_per(
        |e: &Event| e.addr,
        Counting::default,
        reflex_core::stream::Lifetime::UntilIdle(limit),
    )
    .collect()
    .await;

    assert_eq!(
        spoke(&counts).last(),
        Some(&(1, Counted(3))),
        "состояние живого ключа снято: {counts:?}"
    );
}

/// ЗАЯВЛЕННАЯ ОГРАНИЧЕННОСТЬ ЧТИТСЯ: при `Bounded` состояние живёт до конца потока.
///
/// Это не поблажка, а другой случай: ключей конечное число (ноги, классы, порты), расти памяти
/// некуда, и снимать состояние по простою значило бы терять накопленное о том, что вернётся.
#[tokio::test]
async fn bounded_keys_keep_their_state_forever() {
    let t0 = Instant::now();
    let long = Duration::from_secs(3600);

    let counts: Vec<(u8, (SmallVec<[Counted; 2]>, ()))> = stream::iter([
        packet(1, Kind::Byte, t0),
        packet(1, Kind::Byte, t0),
        DetectorEvent::Tick {
            node: 1,
            at: t0 + long,
        },
        packet(1, Kind::Byte, t0 + long * 2),
        DetectorEvent::Tick {
            node: 2,
            at: t0 + long * 2,
        },
    ])
    .detect_per(
        |e: &Event| e.addr,
        Counting::default,
        reflex_core::stream::Lifetime::Bounded,
    )
    .collect()
    .await;

    assert_eq!(
        spoke(&counts).last(),
        Some(&(1, Counted(3))),
        "заявленная ограниченность не почтена — состояние снято: {counts:?}"
    );
}

/// ЧЕМ ПРИБОР РАСПОЛАГАЛ, КОГДА ГОВОРИЛ. Адресата у этого нет: цепочке читать его нечем, наружу
/// оно выходит вбок.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Looked {
    events: u8,
}

/// Прибор, который молчит соседу и ОТМЕЧАЕТ, сколько событий видел.
///
/// Слово у него пустое всегда: без такого прибора потеря показания неотличима от «сказать было
/// нечего», и подъём, роняющий третий элемент, зеленел бы на всех прочих стендах.
#[derive(Debug, Clone, Copy, Default)]
struct Attentive(u8);

impl Step for Attentive {
    type From = DetectorEvent<Event>;
    type To = SmallVec<[Signal; 2]>;
    type Notes = Looked;

    fn step(self, event: Self::From) -> (Self, Self::To, Looked) {
        let seen = match event {
            DetectorEvent::Packet { .. } => self.0 + 1,
            DetectorEvent::Tick { .. } => self.0,
            DetectorEvent::Opaque { .. } => self.0,
        };
        (Attentive(seen), smallvec![], Looked { events: seen })
    }
}

/// ПОКАЗАНИЕ ПОКИДАЕТ ЦЕПОЧКУ ПОДЪЁМОМ — и подъём, расслоённый по ключу, не исключение.
///
/// Слово прибора здесь пусто всегда, и единственное, что он произвёл, — показание. Подъём,
/// выпускающий одно слово, отдал бы наружу пустоту и был бы неотличим от исправного.
#[tokio::test]
async fn the_keyed_lift_carries_the_note_out() {
    let t0 = Instant::now();

    let got: Vec<(u8, (SmallVec<[Signal; 2]>, Looked))> = stream::iter([
        packet(1, Kind::Byte, t0),
        packet(2, Kind::Byte, t0),
        packet(1, Kind::Byte, t0),
    ])
    .detect_per(
        |e: &Event| e.addr,
        Attentive::default,
        reflex_core::stream::Lifetime::Bounded,
    )
    .collect()
    .await;

    assert_eq!(
        got.iter().map(|(k, (_, n))| (*k, *n)).collect::<Vec<_>>(),
        vec![
            (1, Looked { events: 1 }),
            (2, Looked { events: 1 }),
            (1, Looked { events: 2 })
        ],
        "показание не вышло наружу или перепуталось между ключами: {got:?}"
    );
}
