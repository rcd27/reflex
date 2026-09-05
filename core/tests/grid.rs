//! СЕТКА ВРЕМЕНИ — один закон на все часы.
//!
//! Заведено 05.09.2026: закон был написан ЧЕТЫРЕ раза — в часах записи (`pcap::on_grid`), в
//! тестовых часах, в системных синхронных и в асинхронных. Три считали одинаково, четвёртые
//! (`tokio::interval`) дрейфовали, и это значит, что детектор, поверенный на тестовых часах, под
//! нагрузкой исполнялся по другой сетке.

use reflex_core::grid::{due, node, nodes_between};
use std::time::{Duration, Instant};

const STEP: Duration = Duration::from_millis(100);

fn at(start: Instant, millis: u64) -> Instant {
    start + Duration::from_millis(millis)
}

/// ГЛАВНЫЙ ЗАКОН: СЕТКА ОТМЕРЯЕТСЯ ОТ НАЧАЛА, А НЕ ОТ ПРЕДЫДУЩЕГО СОБЫТИЯ.
///
/// Иначе на плотном потоке (пакеты каждые 30 мс при окне 300 мс) пауз нужной длины нет ни одной, и
/// часы не идут ВОВСЕ — приборы, чей предмет виден только при идущем трафике, молчат всегда, а
/// молчание неотличимо от «беды нет».
#[test]
fn the_grid_is_measured_from_the_start_not_from_the_previous_event() {
    let start = Instant::now();
    let dense: Vec<Instant> = (0..10)
        .map(|i| at(start, i * 30))
        .collect::<Vec<_>>()
        .windows(2)
        .flat_map(|pair| nodes_between(start, pair[0], pair[1], STEP))
        .collect();

    assert_eq!(
        dense,
        vec![at(start, 100), at(start, 200)],
        "на потоке гуще окна пауз нет, а узлы сетки обязаны наступать"
    );
}

/// ПОЛУИНТЕРВАЛ `(before, after]` — узел, совпавший с левым краем, уже выдан прошлым шагом.
#[test]
fn a_node_belongs_to_exactly_one_interval() {
    let start = Instant::now();

    assert_eq!(
        nodes_between(start, at(start, 100), at(start, 200), STEP).collect::<Vec<_>>(),
        vec![at(start, 200)],
        "левый край исключён, правый включён"
    );
    assert_eq!(
        nodes_between(start, at(start, 0), at(start, 100), STEP).collect::<Vec<_>>(),
        vec![at(start, 100)],
    );
}

/// ПАУЗА КОРОЧЕ ОКНА НЕ РОЖДАЕТ УЗЛА — если сетка в неё не попала.
#[test]
fn a_gap_shorter_than_the_step_yields_a_node_only_when_the_grid_falls_inside() {
    let start = Instant::now();

    assert_eq!(
        nodes_between(start, at(start, 110), at(start, 150), STEP).count(),
        0,
        "внутри одного окна узлов нет"
    );
    assert_eq!(
        nodes_between(start, at(start, 190), at(start, 210), STEP).count(),
        1,
        "а короткая пауза, накрывшая узел, его рождает"
    );
}

/// ДОЛГОЕ МОЛЧАНИЕ ОТДАЁТ ВСЕ ПРОПУЩЕННЫЕ УЗЛЫ, и это НЕ залп.
///
/// Разница в том, кто решает: здесь функция лишь говорит, какие узлы наступили, а схлопывать их
/// или выдавать по одному — дело потребителя. Часы, схлопывающие молча, лишают его выбора.
#[test]
fn a_long_silence_reports_every_node_it_covered() {
    let start = Instant::now();

    assert_eq!(
        nodes_between(start, at(start, 0), at(start, 550), STEP).count(),
        5
    );
}

#[test]
fn the_nth_node_is_the_start_plus_n_steps() {
    let start = Instant::now();

    assert_eq!(node(start, STEP, 0), start);
    assert_eq!(node(start, STEP, 3), at(start, 300));
}

/// СКОЛЬКО УЗЛОВ НАСТУПИЛО — счёт, а не список.
#[test]
fn due_counts_the_nodes_already_passed() {
    let start = Instant::now();

    assert_eq!(due(start, start, STEP), 0);
    assert_eq!(due(start, at(start, 99), STEP), 0);
    assert_eq!(due(start, at(start, 100), STEP), 1);
    assert_eq!(due(start, at(start, 250), STEP), 2);
}

/// ШАГ НОЛЬ — ВЫРОЖДЕННАЯ СЕТКА, и она обязана быть ПУСТОЙ, а не бесконечной.
///
/// Прежние часы отвечали на нулевой шаг `u64::MAX` тиков. Число выглядит как «очень много», а
/// значит «мы не знаем»: сетки с нулевым шагом не существует, и выдавать по ней узлы — выдумывать
/// моменты, которых не было.
#[test]
fn a_zero_step_is_an_empty_grid_not_an_infinite_one() {
    let start = Instant::now();

    assert_eq!(
        nodes_between(start, start, at(start, 1_000), Duration::ZERO).count(),
        0
    );
    assert_eq!(due(start, at(start, 1_000), Duration::ZERO), 0);
}

/// УЗЛЫ ЗА ПРЕДЕЛОМ `u32` НЕ ЗАВОРАЧИВАЮТСЯ НАЗАД.
///
/// Прежние две копии считали `every * (nth as u32)`. На миллисекундной сетке `u32` кончается через
/// 49 суток аптайма, и сетка прыгала бы в прошлое — то есть все временны́е операторы разом
/// получали бы время, идущее назад. У коробки, живущей месяцами, это не гипотеза.
#[test]
fn nodes_beyond_thirty_two_bits_do_not_wrap_backwards() {
    let start = Instant::now();
    let far = 5_000_000_000u64;

    assert!(
        node(start, Duration::from_millis(1), far) > node(start, Duration::from_millis(1), far - 1),
        "узел за пределом u32 обязан идти вперёд, а не завернуться"
    );
    assert_eq!(
        node(start, Duration::from_millis(1), far),
        start + Duration::from_millis(far)
    );
}
