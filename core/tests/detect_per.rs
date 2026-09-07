//! Тесты `detect_per` и композиции детекторов.
//!
//! Оба примитива заведены ради одного требования: **доменный шаг обязан быть звеном цепочки, а
//! не кодом внутри чужого шага**. Пока правило детекции живёт в теле `group_by`, добавить
//! детекцию троттлинга UDP нельзя, не тронув существующий обработчик, — и цепочка перестаёт быть
//! конструктором.

use std::time::{Duration, Instant};

use futures::{stream, StreamExt};
use reflex_core::step::{Step, StepExt};
use reflex_core::{DetectorEvent, ReflexExt};
use smallvec::{smallvec, SmallVec};

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

/// Детектор сброса: сигналит на каждый RST, времени не знает.
#[derive(Debug, Clone, Copy, Default)]
struct Rst;

impl Step for Rst {
    type From = DetectorEvent<Event>;
    type To = SmallVec<[Signal; 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
        match event {
            DetectorEvent::Packet {
                input: Event {
                    kind: Kind::Rst, ..
                },
                ..
            } => (self, smallvec![Signal::SawRst]),
            DetectorEvent::Packet { .. } => (self, smallvec![]),
            DetectorEvent::Tick { .. } => (self, smallvec![]),
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

    fn step(self, event: Self::From) -> (Self, Self::To) {
        match event {
            DetectorEvent::Packet { at, .. } => (
                Self {
                    last: Some(at),
                    ..self
                },
                smallvec![],
            ),
            DetectorEvent::Tick { at, .. } => match (self.last, self.fired) {
                (Some(last), false) if at.duration_since(last) >= self.after => (
                    Self {
                        fired: true,
                        ..self
                    },
                    smallvec![Signal::WentQuiet],
                ),
                _ => (self, smallvec![]),
            },
        }
    }
}

/// Третий детектор — существует, чтобы доказать, что цепочка `Both` РАСТЁТ, а не переписывается.
#[derive(Debug, Clone, Copy, Default)]
struct Bytes;

impl Step for Bytes {
    type From = DetectorEvent<Event>;
    type To = SmallVec<[Signal; 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
        match event {
            DetectorEvent::Packet {
                input: Event {
                    kind: Kind::Byte, ..
                },
                ..
            } => (self, smallvec![Signal::SawByte]),
            DetectorEvent::Packet { .. } => (self, smallvec![]),
            DetectorEvent::Tick { .. } => (self, smallvec![]),
        }
    }
}

fn packet(addr: u8, kind: Kind, at: Instant) -> DetectorEvent<Event> {
    DetectorEvent::Packet {
        input: Event { addr, kind },
        at,
    }
}

/// СОСТОЯНИЕ ЖИВЁТ ПО КЛЮЧУ и не смешивается между целями.
#[tokio::test]
async fn state_is_per_key() {
    let t0 = Instant::now();
    let got: Vec<(u8, Signal)> = stream::iter([
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

    assert_eq!(
        got,
        vec![
            (1, Signal::SawRst),
            (2, Signal::SawByte),
            (1, Signal::SawByte)
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

    let got: Vec<(u8, Signal)> = stream::iter([
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
        got,
        vec![(1, Signal::WentQuiet), (2, Signal::WentQuiet)],
        "тик обязан дойти до обоих ключей, и в детерминированном порядке"
    );
}

/// КОНТРОЛЬ: тик до истечения порога не сигналит. Без него тест выше зеленел бы и при
/// детекторе, который сигналит на любой тик.
#[tokio::test]
async fn tick_before_threshold_is_silent() {
    let t0 = Instant::now();
    let got: Vec<(u8, Signal)> = stream::iter([
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

    assert!(got.is_empty(), "сработало раньше порога: {got:?}");
}

/// Тик до первого пакета не сигналит: состояний ещё нет, будить некого.
#[tokio::test]
async fn tick_without_any_state_is_silent() {
    let got: Vec<(u8, Signal)> = stream::iter([DetectorEvent::Tick {
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
        fn step(self, event: Self::From) -> (Self, Self::To) {
            match event {
                DetectorEvent::Packet { .. } => (self, smallvec![Signal::SawByte]),
                DetectorEvent::Tick { .. } => (self, smallvec![]),
            }
        }
    }

    let got: Vec<(u8, Signal)> = stream::iter([packet(1, Kind::Rst, t0)])
        .detect_per(
            |e: &Event| e.addr,
            || Rst.and(Everything),
            reflex_core::stream::Lifetime::Bounded,
        )
        .collect()
        .await;

    assert_eq!(got, vec![(1, Signal::SawRst), (1, Signal::SawByte)]);
}

/// ЦЕПОЧКА РАСТЁТ ДОПИСЫВАНИЕМ. Третий детектор добавлен оборачиванием в `Both`, снаружи — правила
/// `Rst` и `Quiet` при этом не читались и не правились. Это и есть требование, ради которого оба
/// примитива заведены.
#[tokio::test]
async fn chain_grows_by_appending() {
    let t0 = Instant::now();
    let later = t0 + Duration::from_secs(2);

    let got: Vec<(u8, Signal)> = stream::iter([
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

    assert_eq!(
        got,
        vec![
            (1, Signal::SawRst),
            (1, Signal::SawByte),
            (1, Signal::WentQuiet)
        ]
    );
}

/// СИГНАЛЫ НЕ ТЕРЯЮТСЯ, когда источник завершается сразу после события, породившего сразу два
/// сигнала. Очередь обязана быть опустошена прежде, чем поток отдаст `None`.
#[tokio::test]
async fn signals_survive_source_completion() {
    let t0 = Instant::now();

    #[derive(Debug, Clone, Copy, Default)]
    struct Twice;
    impl Step for Twice {
        type From = DetectorEvent<Event>;
        type To = SmallVec<[Signal; 2]>;
        fn step(self, event: Self::From) -> (Self, Self::To) {
            match event {
                DetectorEvent::Packet { .. } => (self, smallvec![Signal::SawRst, Signal::SawByte]),
                DetectorEvent::Tick { .. } => (self, smallvec![]),
            }
        }
    }

    let got: Vec<(u8, Signal)> = stream::iter([packet(1, Kind::Rst, t0)])
        .detect_per(
            |e: &Event| e.addr,
            || Twice,
            reflex_core::stream::Lifetime::Bounded,
        )
        .collect()
        .await;

    assert_eq!(got.len(), 2, "потерян сигнал на завершении источника");
}

/// ДЕТЕКТОР С ПАМЯТЬЮ: считает пакеты и на тике говорит, сколько насчитал. По нему видно, забыто
/// состояние или нет, — булев сигнал этого не показал бы.
#[derive(Debug, Clone, Copy, Default)]
struct Counting(u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Counted(u8);

impl Step for Counting {
    type From = DetectorEvent<Event>;
    type To = SmallVec<[Counted; 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
        match event {
            DetectorEvent::Packet { .. } => (Counting(self.0 + 1), smallvec![]),
            DetectorEvent::Tick { .. } => (self, smallvec![Counted(self.0)]),
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

    let counts: Vec<(u8, Counted)> = stream::iter([
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
        counts.last(),
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

    let counts: Vec<(u8, Counted)> = stream::iter([
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
        counts.last(),
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

    let counts: Vec<(u8, Counted)> = stream::iter([
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
        counts.last(),
        Some(&(1, Counted(3))),
        "заявленная ограниченность не почтена — состояние снято: {counts:?}"
    );
}
