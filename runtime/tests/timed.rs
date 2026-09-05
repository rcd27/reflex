//! ЖИВОЙ ВПУСК ЧЕРЕЗ ШОВ — пакеты и сетка сходятся в один поток.
//!
//! Проверяется на тестовых часах: без ожидания, без устройства, за микросекунды. Ровно то, что шов
//! и покупает — поведение во времени перестаёт требовать стенда.

use futures::StreamExt;
use reflex_core::clock::{TestClock, Ticks};
use reflex_core::detector::DetectorEvent;
use reflex_runtime::timed;
use std::time::{Duration, Instant};

const STEP: Duration = Duration::from_millis(100);

/// Форма вышедшего потока, читаемая глазами: буква и миллисекунды от начала.
fn shape(events: &[DetectorEvent<i32>], began: Instant) -> Vec<(char, u64)> {
    events
        .iter()
        .map(|event| {
            let millis = event.at().saturating_duration_since(began).as_millis() as u64;
            match event {
                DetectorEvent::Packet { .. } => ('p', millis),
                DetectorEvent::Tick { .. } => ('t', millis),
            }
        })
        .collect()
}

fn at(began: Instant, millis: u64) -> Instant {
    began + Duration::from_millis(millis)
}

/// УЗЛЫ, КОТОРЫЕ ПЕРЕШАГНУЛ ПАКЕТ, ПРИХОДЯТ ПЕРЕД НИМ — И БЕЗ ЕДИНОГО БУДИЛЬНИКА.
///
/// Часов в этой проверке нет вовсе: поток тиков пуст. Тики всё равно есть, потому что при живом
/// трафике они ВЫЧИСЛЯЮТСЯ из моментов пакетов. Это и есть половина цены решения, которую мы не
/// платим.
#[tokio::test]
async fn a_flowing_source_gets_its_grid_without_any_alarm() {
    let began = Instant::now();
    let packets = futures::stream::iter([(1, at(began, 250)), (2, at(began, 500))]);

    let out: Vec<_> = timed(packets, futures::stream::empty(), began, STEP)
        .collect()
        .await;

    assert_eq!(
        shape(&out, began),
        vec![
            ('t', 100),
            ('t', 200),
            ('p', 250),
            ('t', 300),
            ('t', 400),
            ('t', 500),
            ('p', 500)
        ]
    );
}

/// ТИШИНА ТОЖЕ ДАЁТ СОБЫТИЯ — ради этого будильник в шве и нужен, и только ради этого.
#[tokio::test]
async fn silence_still_yields_the_nodes_it_covered() {
    let clock = TestClock::new();
    let began = clock.began();
    clock.advance(Duration::from_millis(320));

    let out: Vec<_> = timed(
        futures::stream::empty::<(i32, Instant)>(),
        clock.ticks(STEP),
        began,
        STEP,
    )
    .collect()
    .await;

    assert_eq!(
        shape(&out, began),
        vec![('t', 100), ('t', 200), ('t', 300)],
        "без единого пакета обязаны прийти наступившие узлы"
    );
}

/// УЗЕЛ НЕ ВЫДАЁТСЯ ДВАЖДЫ, откуда бы он ни пришёл — из пакета или из будильника.
///
/// Два источника моментов — два повода выдать один и тот же узел. Шов держит это состояние
/// единственным, и потому двойного закрытия окна не бывает.
#[tokio::test]
async fn a_node_is_not_handed_out_twice_when_both_sources_cover_it() {
    let clock = TestClock::new();
    let began = clock.began();
    clock.advance(Duration::from_millis(250));

    let packets = futures::stream::iter([(1, at(began, 250))]);

    let out: Vec<_> = timed(packets, clock.ticks(STEP), began, STEP)
        .collect()
        .await;

    let ticks: Vec<_> = shape(&out, began)
        .into_iter()
        .filter(|(kind, _)| *kind == 't')
        .collect();

    assert_eq!(
        ticks,
        vec![('t', 100), ('t', 200)],
        "узлы 100 и 200 накрыты и пакетом, и будильником — выйти обязаны по разу"
    );
}
