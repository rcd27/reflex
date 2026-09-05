//! `timeout` БЕЗ ЧАСОВ — и с двумя сроками, которые нельзя путать.
//!
//! Форма взята замером, а не выдумана: у прибора эпизода (`pribor::episode`) сроков два, и его
//! собственный паспорт называет их смешение ложью — «путать это с уходом значит считать своим
//! знанием своё нетерпение».

use reflex_core::detector::{Detector, DetectorEvent};
use reflex_core::timeout::{Expiry, Timeout};
use std::time::{Duration, Instant};

const IDLE: Duration = Duration::from_millis(300);
const CEILING: Duration = Duration::from_millis(1_000);

fn run(events: Vec<DetectorEvent<i32>>) -> Vec<Expiry> {
    events
        .into_iter()
        .fold(
            (Timeout::new(IDLE, CEILING), Vec::new()),
            |(detector, mut seen), event| {
                let (detector, signals) = detector.step(event);
                seen.extend(signals);
                (detector, seen)
            },
        )
        .1
}

fn packet(t: Instant, millis: u64) -> DetectorEvent<i32> {
    DetectorEvent::Packet {
        input: 1,
        at: t + Duration::from_millis(millis),
    }
}

fn tick(t: Instant, millis: u64) -> DetectorEvent<i32> {
    DetectorEvent::Tick {
        at: t + Duration::from_millis(millis),
    }
}

/// ТИШИНА ДОЛЬШЕ ПОРОГА — `Idle`.
#[test]
fn silence_longer_than_the_threshold_is_idle() {
    let t = Instant::now();

    assert_eq!(
        run(vec![packet(t, 0), tick(t, 200), tick(t, 400)]),
        vec![Expiry::Idle]
    );
}

/// ВСЯКОЕ СОБЫТИЕ ОТОДВИГАЕТ ТИШИНУ.
#[test]
fn any_event_pushes_the_silence_threshold_back() {
    let t = Instant::now();

    assert_eq!(
        run(vec![
            packet(t, 0),
            tick(t, 200),
            packet(t, 250),
            tick(t, 400),
            tick(t, 500),
        ]),
        Vec::<Expiry>::new(),
        "к 500 мс с последнего события прошло 250 — тишины ещё нет"
    );
}

/// ПОТОЛОК ЕСТЬ УТВЕРЖДЕНИЕ О НАС: он наступает, ДАЖЕ ЕСЛИ события идут.
///
/// Это главное различие двух сроков. `Idle` говорит «предмет замолчал», `Ceiling` — «мы перестали
/// ждать». Слить их значило бы объявить своё нетерпение свойством мира.
#[test]
fn the_ceiling_fires_even_while_events_keep_arriving() {
    let t = Instant::now();

    assert_eq!(
        run(vec![
            packet(t, 0),
            packet(t, 200),
            packet(t, 400),
            packet(t, 600),
            packet(t, 800),
            packet(t, 1_000),
            tick(t, 1_050),
        ]),
        vec![Expiry::Ceiling],
        "события шли без перерыва — значит это не про них, а про нас"
    );
}

/// ВЫИГРЫВАЕТ ТОТ СРОК, ЧЕЙ МОМЕНТ НАСТУПИЛ РАНЬШЕ, а не тот, что проверен первым.
///
/// Иначе порядок проверок в коде становился бы скрытым правилом, и при потолке короче тишины
/// прибор врал бы о причине.
#[test]
fn whichever_threshold_is_crossed_first_wins() {
    let t = Instant::now();
    let sooner_ceiling = Timeout::new(Duration::from_millis(900), Duration::from_millis(100));

    let (_detector, out) = [packet(t, 0), tick(t, 950)].into_iter().fold(
        (sooner_ceiling, Vec::new()),
        |(detector, mut seen), event| {
            let (detector, signals) = detector.step(event);
            seen.extend(signals);
            (detector, seen)
        },
    );

    assert_eq!(
        out,
        vec![Expiry::Ceiling],
        "потолок в 100 мс наступил раньше тишины в 900 — он и назван"
    );
}

/// ГОВОРИТ ОДИН РАЗ, А НОВОЕ СОБЫТИЕ ЗАВОДИТ СРОК ЗАНОВО.
///
/// Поток, замерший дважды, обязан дать два высказывания: это два разных простоя, а не один
/// длинный. Повтор же о том же простое был бы шумом.
#[test]
fn it_speaks_once_per_arming_and_a_new_event_arms_it_again() {
    let t = Instant::now();

    assert_eq!(
        run(vec![
            packet(t, 0),
            tick(t, 400),
            tick(t, 500),
            tick(t, 600),
            packet(t, 700),
            tick(t, 1_100),
        ]),
        vec![Expiry::Idle, Expiry::Idle],
        "два простоя — два высказывания, и ни одного лишнего между ними"
    );
}

/// ПОКА НИЧЕГО НЕ ПРИХОДИЛО, СРОКА НЕТ. Нельзя истечь тому, что не начиналось.
#[test]
fn nothing_ever_seen_means_nothing_to_expire() {
    let t = Instant::now();

    assert_eq!(
        run(vec![tick(t, 500), tick(t, 5_000)]),
        Vec::<Expiry>::new()
    );
}
