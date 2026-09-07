//! `debounce` БЕЗ РАНТАЙМА — законы, проверяемые таблицей.
//!
//! Время приходит буквой `Tick`, а не часами рантайма: поведение выражено детектором, и проверка
//! становится массивом пар «событие → ожидаемый выход», без `spawn` и без ожидания настоящего
//! времени.

use reflex_core::debounce::Debounce;
use reflex_core::detector::DetectorEvent;
use reflex_core::step::Step;
use reflex_core::word::{Region, Word};
use std::time::{Duration, Instant};

/// ОБЛАСТЬ ЗАКОННОГО СТЕНДА.
///
/// Объявляется здесь, а не в фундаменте: закон обязан быть выразим для того, кто заводит свою
/// область снаружи, и стенд — законный заводящий.
struct Bench;
impl Region for Bench {}

/// СОБЫТИЕ СТЕНДА — с именем, а не голым числом: адрес объявляет значение, а число молчит.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Beat(i32);

impl Word for Beat {
    type Of = Bench;
}

const WINDOW: Duration = Duration::from_millis(300);

/// Прогнать последовательность событий и собрать всё, что вышло.
fn run(events: Vec<DetectorEvent<Beat>>) -> Vec<Beat> {
    events
        .into_iter()
        .fold(
            (Debounce::over(WINDOW), Vec::new()),
            |(detector, mut seen), event| {
                let (detector, signals, ()) = detector.step(event);
                seen.extend(signals);
                (detector, seen)
            },
        )
        .1
}

fn packet(start: Instant, millis: u64, what: i32) -> DetectorEvent<Beat> {
    DetectorEvent::Packet {
        input: Beat(what),
        at: start + Duration::from_millis(millis),
    }
}

fn tick(start: Instant, millis: u64) -> DetectorEvent<Beat> {
    DetectorEvent::Tick {
        node: millis,
        at: start + Duration::from_millis(millis),
    }
}

/// ЧАСТЫЕ ПОВТОРЫ СХЛОПЫВАЮТСЯ В ПОСЛЕДНИЙ.
#[test]
fn rapid_repeats_collapse_into_the_last_one() {
    let t = Instant::now();

    assert_eq!(
        run(vec![
            packet(t, 0, 1),
            packet(t, 50, 2),
            packet(t, 100, 3),
            tick(t, 200),
            tick(t, 400),
        ]),
        vec![Beat(3)],
        "выпускается последнее, и только когда поток затих"
    );
}

/// РАЗНЕСЁННЫЕ СОБЫТИЯ ПРОХОДЯТ ОБА.
#[test]
fn spaced_events_both_pass() {
    let t = Instant::now();

    assert_eq!(
        run(vec![
            packet(t, 0, 1),
            tick(t, 400),
            packet(t, 500, 2),
            tick(t, 900),
        ]),
        vec![Beat(1), Beat(2)]
    );
}

/// ОКНО ОТСЧИТЫВАЕТСЯ ОТ ПОСЛЕДНЕГО СОБЫТИЯ, А НЕ ОТ ПЕРВОГО.
///
/// Иначе поток, идущий чуть чаще окна, выпускался бы регулярно — то есть `debounce` перестал бы
/// отличать «затих» от «идёт ровно».
#[test]
fn the_window_is_measured_from_the_last_event_not_the_first() {
    let t = Instant::now();

    assert_eq!(
        run(vec![
            packet(t, 0, 1),
            tick(t, 200),
            packet(t, 250, 2),
            tick(t, 400),
            tick(t, 600),
        ]),
        vec![Beat(2)],
        "второе событие отодвинуло окно: до 550 мс выпускать нечего"
    );
}

/// ТИК БЕЗ УДЕРЖАННОГО СОБЫТИЯ МОЛЧИТ. Пустое окно не есть наблюдение.
#[test]
fn a_tick_with_nothing_held_says_nothing() {
    let t = Instant::now();

    assert_eq!(run(vec![tick(t, 100), tick(t, 900)]), Vec::<Beat>::new());
}

/// ВЫПУЩЕННОЕ НЕ ВЫПУСКАЕТСЯ ДВАЖДЫ — сколько бы тиков ни пришло следом.
#[test]
fn what_was_released_is_not_released_again() {
    let t = Instant::now();

    assert_eq!(
        run(vec![
            packet(t, 0, 1),
            tick(t, 400),
            tick(t, 700),
            tick(t, 1_000),
        ]),
        vec![Beat(1)]
    );
}

/// ТОЧНОСТЬ КВАНТУЕТСЯ СЕТКОЙ, И ЭТО ЦЕНА РЕШЕНИЯ, А НЕ ДЕФЕКТ.
///
/// `tokio::sleep` будил бы ровно в конце окна. Здесь выпуск случается на ПЕРВОМ узле сетки после
/// конца окна — то есть опаздывает не более чем на шаг. Взамен оператор не знает ни часов, ни
/// рантайма и работает там, где их нет.
#[test]
fn release_happens_at_the_first_node_after_the_window_not_exactly_at_its_end() {
    let t = Instant::now();

    assert_eq!(
        run(vec![packet(t, 0, 1), tick(t, 250)]),
        Vec::<Beat>::new(),
        "узел до конца окна ещё ничего не выпускает"
    );
    assert_eq!(
        run(vec![packet(t, 0, 1), tick(t, 250), tick(t, 350)]),
        vec![Beat(1)],
        "выпуск на первом узле ПОСЛЕ конца окна"
    );
}
