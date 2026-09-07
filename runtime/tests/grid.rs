//! СЕТКА НЕ ЗАВИСИТ ОТ НАГРУЗКИ.
//!
//! Тик, рождённый цепочкой задержек (`sleep(шаг)` ПОСЛЕ работы), имеет период
//! `шаг + сколько работали`, и ошибка накапливается. Линейка машины растягивается тем сильнее,
//! чем выше нагрузка, — то есть окна закрываются позже именно тогда, когда это важнее всего.
//!
//! Здесь проверяется противоположное: сколько бы работы ни легло между узлами, узлов за отрезок
//! ровно столько, сколько их в отрезке.
//!
//! # Почему основные проверки — на `TestClock`, а не на отсечке по чужим часам
//!
//! `take_until(sleep(N))` сводит в один прогон ТРИ независимые линейки времени: сетку шва
//! (`std::time::Instant`), будильник часов и виртуальные часы `tokio` под `start_paused`. Под
//! паузой виртуальное время прыгает мгновенно, а `std::Instant::now()` почти не двигается —
//! сколько тиков успеет родиться решает чужая линейка, а не сценарий. `TestClock` устраняет это:
//! её поток тиков КОНЧАЕТСЯ САМ, когда время догнало сетку ([`reflex_core::clock::TestClock`]), и
//! `collect()` завершается без единой внешней отсечки.
use std::time::{Duration, Instant};

use futures::StreamExt;
use reflex_core::clock::TestClock;
use reflex_core::detector::{DetectorEvent, Sensed};
use reflex_runtime::clock::SystemClock;

const STEP: Duration = Duration::from_millis(10);

/// Наблюдение с провода — свой тип, чтобы тест не зависел от словаря продукта.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Seen(u8);

#[tokio::test]
async fn nodes_do_not_depend_on_load() {
    let clock = TestClock::new();
    let began = clock.began();

    // ПАКЕТЫ ИДУТ ГУСТО И НЕРОВНО: три подряд, потом пусто. Ровно та неровность, на которой
    // цепочка задержек и разъезжается.
    let packets = futures::stream::iter(vec![
        (Sensed::Seen(Seen(1)), began + Duration::from_millis(1)),
        (Sensed::Seen(Seen(2)), began + Duration::from_millis(2)),
        (Sensed::Seen(Seen(3)), began + Duration::from_millis(3)),
        (Sensed::Seen(Seen(4)), began + Duration::from_millis(45)),
    ]);

    // Время продвинуто ровно настолько, сколько заняла эта картина: 45 мс. Поток тиков `TestClock`
    // кончится сам, когда сетка их догонит, — отсечки не нужно.
    clock.advance(Duration::from_millis(45));

    let mixed: Vec<DetectorEvent<Seen>> =
        reflex_runtime::timed::on_grid(packets, clock, began, STEP)
            .collect()
            .await;

    let ticks = mixed
        .iter()
        .filter(|event| matches!(event, DetectorEvent::Tick { .. }))
        .count();

    // За 45 мс при шаге 10 мс узлов ровно четыре: 10, 20, 30, 40.
    assert_eq!(ticks, 4, "узлов за отрезок столько, сколько их в отрезке");

    let seen = mixed
        .iter()
        .filter(|event| matches!(event, DetectorEvent::Packet { .. }))
        .count();
    assert_eq!(seen, 4, "ни один пакет не потерян и не задвоен");
}

/// НЕПОНЯТОЕ НА ЖИВОМ ШВЕ ДВИГАЕТ СЕТКУ ТАК ЖЕ, КАК РАЗОБРАННОЕ.
///
/// `reflex_core::pcap::on_grid` (запись) это уже умел; здесь тот же закон проверяется на живом
/// пути — через `reflex_runtime::timed::on_grid`, единственный публичный вход к нему.
#[tokio::test]
async fn unread_observations_do_not_depend_on_load_either() {
    use reflex_core::parse::Unread;

    let clock = TestClock::new();
    let began = clock.began();

    let observations = futures::stream::iter(vec![
        (
            Sensed::<Seen>::Unread(Unread::Truncated),
            began + Duration::from_millis(1),
        ),
        (
            Sensed::<Seen>::Unread(Unread::NotIpv4),
            began + Duration::from_millis(45),
        ),
    ]);

    clock.advance(Duration::from_millis(45));

    let mixed: Vec<DetectorEvent<Seen>> =
        reflex_runtime::timed::on_grid(observations, clock, began, STEP)
            .collect()
            .await;

    let ticks = mixed
        .iter()
        .filter(|event| matches!(event, DetectorEvent::Tick { .. }))
        .count();
    assert_eq!(ticks, 4, "непонятое раздвигает сетку так же, как пакет");

    let unread = mixed
        .iter()
        .filter(|event| matches!(event, DetectorEvent::Opaque { .. }))
        .count();
    assert_eq!(unread, 2, "ни одно неразобранное наблюдение не потеряно");
}

#[tokio::test]
async fn silence_still_produces_nodes() {
    // МОЛЧАНИЕ — ЗАКОННЫЙ ВХОД. Без пакетов узлы обязаны идти всё равно, иначе «замолчал»
    // неотличимо от «мы не смотрели».
    let clock = TestClock::new();
    let began = clock.began();
    let empty = futures::stream::iter(Vec::<(Sensed<Seen>, Instant)>::new());

    clock.advance(Duration::from_millis(35));

    let mixed: Vec<DetectorEvent<Seen>> = reflex_runtime::timed::on_grid(empty, clock, began, STEP)
        .collect()
        .await;

    assert_eq!(mixed.len(), 3, "в тишине узлы идут по сетке: 10, 20, 30");
}

/// КОНТРОЛЬ НА РЕАЛЬНЫХ ЧАСАХ.
///
/// Виртуальное время доказывает «сколько прошло», но не «часы сами разбудили поток»
/// ([`reflex_core::clock`]: #287, три зелёных теста на паузе не поймали потерянный waker). Этот
/// тест идёт настоящие десятки миллисекунд — цена, названная вслух, — и проверяет, что на
/// системных часах узлы приходят так же, как на тестовых.
///
/// Отсечка — не чужой таймер, а НАШ АЛФАВИТ: `take_while` смотрит на момент, который несёт сама
/// буква (`event.at()`), и останавливается, когда пришёл узел за границей окна наблюдения.
#[tokio::test]
async fn real_clock_actually_produces_nodes() {
    let began = Instant::now();
    let empty = futures::stream::iter(Vec::<(Sensed<Seen>, Instant)>::new());
    let boundary = began + STEP * 3 + STEP / 2;

    let mixed: Vec<DetectorEvent<Seen>> =
        reflex_runtime::timed::on_grid(empty, SystemClock, began, STEP)
            .take_while(|event| futures::future::ready(event.at() <= boundary))
            .collect()
            .await;

    assert_eq!(
        mixed.len(),
        3,
        "на настоящих часах узлы приходят так же, как на тестовых: 10, 20, 30"
    );
}
