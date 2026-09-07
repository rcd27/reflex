//! СЛИЯНИЕ ПАКЕТОВ И СЕТКИ В ОДИН ПОТОК — законы шва.
//!
//! Здесь время перестаёт быть сервисом и становится буквой входного алфавита: потребитель ниже по
//! течению не спрашивает часов вовсе, он читает `Packet | Tick` и всё.

use reflex_core::detector::DetectorEvent;
use reflex_core::interleave::Interleave;
use std::time::{Duration, Instant};

const STEP: Duration = Duration::from_millis(100);

fn at(start: Instant, millis: u64) -> Instant {
    start + Duration::from_millis(millis)
}

/// Что за события вышли — в виде, который читается глазами.
fn shape<T>(events: &[DetectorEvent<T>], start: Instant) -> Vec<(char, u64)> {
    events
        .iter()
        .map(|event| {
            let millis = event.at().saturating_duration_since(start).as_millis() as u64;
            match event {
                DetectorEvent::Packet { .. } => ('p', millis),
                DetectorEvent::Tick { .. } => ('t', millis),
                // Шов ([`Interleave`]) не рождает `Opaque` — он вообще не знает о разборе;
                // ветка нужна ради полноты алфавита, а не потому, что до неё дойдёт прогон.
                DetectorEvent::Opaque { .. } => ('o', millis),
            }
        })
        .collect()
}

/// ПАКЕТ ВНУТРИ ОДНОГО ОКНА НЕ РОЖДАЕТ ТИКОВ.
#[test]
fn a_packet_inside_one_window_brings_no_ticks() {
    let start = Instant::now();
    let seam = Interleave::started(start, STEP);

    let (_seam, out) = seam.saw(1u8, at(start, 40));

    assert_eq!(shape(&out, start), vec![('p', 40)]);
}

/// УЗЛЫ СЕТКИ ВЫХОДЯТ ПЕРЕД ПАКЕТОМ, КОТОРЫЙ ИХ ПЕРЕШАГНУЛ, и в порядке времени.
///
/// Порядок существен: детектор, увидевший пакет раньше закрытия окна, в которое пакет не попал,
/// отнесёт его байты не к тому окну.
#[test]
fn the_nodes_a_packet_stepped_over_come_out_before_it() {
    let start = Instant::now();
    let seam = Interleave::started(start, STEP);

    let (_seam, out) = seam.saw(1u8, at(start, 250));

    assert_eq!(shape(&out, start), vec![('t', 100), ('t', 200), ('p', 250)]);
}

/// УЗЕЛ ВЫДАЁТСЯ РОВНО ОДИН РАЗ — сколько бы пакетов ни пришло следом.
#[test]
fn a_node_is_handed_out_exactly_once() {
    let start = Instant::now();
    let seam = Interleave::started(start, STEP);

    let (seam, first) = seam.saw(1u8, at(start, 150));
    let (seam, second) = seam.saw(2u8, at(start, 160));
    let (_seam, third) = seam.saw(3u8, at(start, 210));

    assert_eq!(shape(&first, start), vec![('t', 100), ('p', 150)]);
    assert_eq!(
        shape(&second, start),
        vec![('p', 160)],
        "узел 100 уже выдан"
    );
    assert_eq!(shape(&third, start), vec![('t', 200), ('p', 210)]);
}

/// ТИШИНА ТОЖЕ НАБЛЮДЕНИЕ: будильник приносит наступившие узлы без единого пакета.
///
/// Ради этого шов и заводится. Пока трафик идёт, узлы ВЫЧИСЛЯЮТСЯ между пакетами и будильник не
/// нужен вовсе; он нужен ровно там, где событий нет, — то есть там, где приборы простоя и слепы.
#[test]
fn silence_still_produces_the_nodes_it_covered() {
    let start = Instant::now();
    let seam = Interleave::started(start, STEP);

    let (_seam, out) = seam.idle::<u8>(at(start, 320));

    assert_eq!(shape(&out, start), vec![('t', 100), ('t', 200), ('t', 300)]);
}

/// ВРЕМЯ НЕ ИДЁТ НАЗАД, ДАЖЕ ЕСЛИ ЕГО ПРИНЕСЛИ НАЗАД.
///
/// Провод переставляет пакеты, а очередь ядра отдаёт их не в порядке съёма. Событие с моментом
/// раньше уже выданного ломает всякий временной оператор ниже по течению — и ломает молча, потому
/// что тот вправе считать вход монотонным.
#[test]
fn a_packet_from_the_past_does_not_turn_time_backwards() {
    let start = Instant::now();
    let seam = Interleave::started(start, STEP);

    let (seam, _ahead) = seam.saw(1u8, at(start, 250));
    let (_seam, late) = seam.saw(2u8, at(start, 120));

    assert_eq!(
        shape(&late, start),
        vec![('p', 250)],
        "опоздавший пакет обязан выйти НЕ РАНЬШЕ последнего выданного момента"
    );
}

/// НОМЕР УЗЛА И МОМЕНТ — ОБА, А НЕ ОДИН ИЗ ДВУХ.
///
/// Номер даёт воспроизводимость: при переигровке он тот же, тогда как момент зависит от того,
/// когда прогон случился. Момент даёт сравнимость с чужими часами — с журналом ядра, с записью
/// провода, с отчётом человека.
///
/// Выбирать между ними значило бы терять одно из двух, а стоят они одно машинное слово.
#[test]
fn tick_carries_node_and_moment() {
    let start = Instant::now();
    let seam = Interleave::started(start, STEP);

    let (_, told) = seam.idle::<u8>(start + STEP * 3);

    let nodes: Vec<u64> = told
        .iter()
        .filter_map(|event| match event {
            DetectorEvent::Tick { node, .. } => Some(*node),
            DetectorEvent::Packet { .. } | DetectorEvent::Opaque { .. } => None,
        })
        .collect();

    assert_eq!(nodes, vec![1, 2, 3], "номера идут подряд от начала отсчёта");

    let moments: Vec<Instant> = told
        .iter()
        .filter_map(|event| match event {
            DetectorEvent::Tick { at, .. } => Some(*at),
            DetectorEvent::Packet { .. } | DetectorEvent::Opaque { .. } => None,
        })
        .collect();

    assert_eq!(
        moments,
        vec![start + STEP, start + STEP * 2, start + STEP * 3],
        "момент есть момент УЗЛА, а не момент выдачи"
    );
}

/// МОМЕНТЫ НЕУБЫВАЮТ ВО ВСЁМ ПОТОКЕ — сквозной закон, а не свойство одного вызова.
#[test]
fn moments_never_decrease_across_the_whole_stream() {
    let start = Instant::now();
    let arrivals = [40u64, 250, 120, 900, 30, 905];

    let (_seam, all) = arrivals.iter().fold(
        (Interleave::started(start, STEP), Vec::new()),
        |(seam, mut seen), millis| {
            let (seam, out) = seam.saw(1u8, at(start, *millis));
            seen.extend(out);
            (seam, seen)
        },
    );

    let moments: Vec<_> = all.iter().map(|event| event.at()).collect();
    assert!(
        moments.windows(2).all(|pair| pair[1] >= pair[0]),
        "поток отдал время, идущее назад: {:?}",
        shape(&all, start)
    );
}
