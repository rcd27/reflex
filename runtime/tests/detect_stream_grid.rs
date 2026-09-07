//! `DetectStream` — НОМЕР УЗЛА СЧИТАЕТ СЕТКА, А НЕ МОМЕНТ ПРОБУЖДЕНИЯ.
//!
//! Пробуждение таймера говорит одно: «пора посмотреть». Сколько узлов сетки наступило и как они
//! пронумерованы — решает [`reflex_core::grid`], на моменте КАЖДОГО узла, а не на моменте, когда
//! исполнитель наконец дал время сработать таймеру.
//!
//! Проверка идёт на настоящих часах (не `start_paused`): `DetectStream` берёт `Instant::now()`
//! напрямую, и виртуальное время `tokio` его не двигает. Отставание имитируется тем же способом,
//! каким оно возникает в бою, — секция без опроса потока, пока `tokio::time::Interval` копит
//! пропущенные пробуждения (умолчание `MissedTickBehavior::Burst`).
use std::time::Duration;

use futures::StreamExt;
use reflex_core::step::Step;
use reflex_core::DetectorEvent;
use reflex_runtime::ReflexRuntimeExt;
use smallvec::SmallVec;

/// Прибор, не читающий пакетов вовсе: единственное, что ему интересно, — номер узла тика.
#[derive(Debug, Clone, Copy, Default)]
struct NodeLog;

impl Step for NodeLog {
    type From = DetectorEvent<u8>;
    type To = SmallVec<[u64; 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
        match event {
            DetectorEvent::Tick { node, .. } => (self, SmallVec::from_slice(&[node])),
            DetectorEvent::Packet { .. } => (self, SmallVec::new()),
            DetectorEvent::Opaque { .. } => (self, SmallVec::new()),
        }
    }
}

/// ПРОСРОЧЕННЫЕ УЗЛЫ ВЫХОДЯТ ПОДРЯД, А НЕ ОДНИМ ПОВТОРЕННЫМ НОМЕРОМ.
///
/// Источник пуст и никогда не отдаёт пакетов — единственное, что движется, это сетка. Поток не
/// опрашивается некоторое время после постройки: за это время `tokio::time::Interval` копит
/// несколько пропущенных пробуждений, и первый же опрос обязан отдать узлы 1, 2, 3, … по одному,
/// а не один и тот же номер несколько раз.
#[tokio::test]
async fn late_ticks_come_out_as_a_sequence_not_a_repeated_number() {
    let step = Duration::from_millis(20);
    let source = futures::stream::pending::<u8>();
    let mut stream = Box::pin(source.detect_with_tick(NodeLog, step));

    // ИМИТАЦИЯ ЗАНЯТОСТИ: поток не опрашивается несколько шагов сетки подряд.
    tokio::time::sleep(step * 5).await;

    let mut nodes = Vec::new();
    while nodes.len() < 3 {
        match tokio::time::timeout(Duration::from_secs(2), stream.next()).await {
            Ok(Some(node)) => nodes.push(node),
            other => panic!("поток обязан отдать накопленные узлы, а дал {other:?}"),
        }
    }

    assert_eq!(
        nodes,
        vec![1, 2, 3],
        "просроченные узлы обязаны идти подряд от 1, а не повторять один номер"
    );
}
