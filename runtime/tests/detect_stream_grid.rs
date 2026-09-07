//! `DetectStream` — НОМЕР УЗЛА СЧИТАЕТ СЕТКА, А НЕ МОМЕНТ ПРОБУЖДЕНИЯ; ТИШИНА БУДИТ САМА СЕБЯ.
//!
//! Пробуждение таймера говорит одно: «пора посмотреть». Сколько узлов сетки наступило и как они
//! пронумерованы — решает [`reflex_core::grid`], на моменте КАЖДОГО узла, а не на моменте, когда
//! исполнитель наконец дал время сработать таймеру.
//!
//! Второе, что здесь проверяется отдельно: поток обязан просыпаться СВОИМ таймером, а не чужим.
//! Тест, который лишь ждёт значения под `timeout`, зелен и на потоке, уснувшем навсегда, — внешний
//! таймер маскирует потерянный будильник (тот же класс ловушки, что у виртуальных часов: они
//! доказывают «сколько прошло», но не «оператор проснулся сам», #287). Проверка меряет ВРЕМЯ
//! ПРИБЫТИЯ и падает, если оно оказалось на границе внешнего таймаута, а не на границе, которую
//! назначила сетка.
//!
//! Обе проверки идут на настоящих часах (не `start_paused`) — потому что предмет здесь именно
//! настоящее пробуждение. Что сетка идёт и под управляемым временем — предмет отдельной проверки:
//! настоящие часы доказывают «оператор проснулся сам», виртуальные — «сколько прошло», и одна
//! другую не заменяет (#287).
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

/// Прибор, молчащий на всех узлах, кроме третьего, — чтобы проверка ждала РЕАЛЬНОГО пробуждения
/// потока на конкретном узле, а не первого же тика.
#[derive(Debug, Clone, Copy, Default)]
struct SpeaksOnThirdNode;

impl Step for SpeaksOnThirdNode {
    type From = DetectorEvent<u8>;
    type To = SmallVec<[u64; 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
        match event {
            DetectorEvent::Tick { node, .. } if node == 3 => (self, SmallVec::from_slice(&[node])),
            DetectorEvent::Tick { .. } => (self, SmallVec::new()),
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

/// МОЛЧАЩИЙ ИСТОЧНИК НЕ УСЫПЛЯЕТ ПОТОК НАВСЕГДА (Ruling 14).
///
/// Опрос тика, вернувшего `Ready`, обязан продолжаться до `Pending` — иначе будильник на
/// следующий узел не регистрируется, и поток, у которого источник ничего не шлёт, не проснётся
/// САМ никогда. Внешний `timeout` здесь взят НАМНОГО ШИРЕ, чем нужно (500 мс против ожидаемых
/// ~60 мс на трёх узлах по 20 мс), — чтобы граница таймаута не могла притвориться границей
/// сетки: тест обязан упасть по СВОЕЙ проверке elapsed, а не тихо зазеленеть от чужого будильника.
#[tokio::test]
async fn a_silent_source_wakes_the_stream_by_itself() {
    let step = Duration::from_millis(20);
    let source = futures::stream::pending::<u8>();
    let mut stream = Box::pin(source.detect_with_tick(SpeaksOnThirdNode, step));

    let began = std::time::Instant::now();
    let got = tokio::time::timeout(Duration::from_millis(500), stream.next())
        .await
        .expect("поток обязан проснуться сам на третьем узле, а не по внешнему таймауту");
    let elapsed = began.elapsed();

    assert_eq!(got, Some(3), "показание обязано прийти именно с узла 3");
    assert!(
        elapsed < Duration::from_millis(500),
        "узел 3 при шаге {step:?} пришёл через {elapsed:?} — поток спал и был разбужен чужим \
         таймером, а не своим"
    );
}
