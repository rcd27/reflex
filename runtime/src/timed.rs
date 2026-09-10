//! Живой впуск через шов: два потока моментов сходятся в один, где время — буква (канон §8). Шву
//! часы не нужны: первая редакция брала [`reflex_core::clock::Clock`] и стампила сама — компилятор её
//! не собрал (поток тиков привязан к заимствованию часов), и отказ подсказал конструкцию — способ
//! ожидания есть свойство того, кто ПОРОЖДАЕТ поток, а не сшивает. Оттого два потока и ни одних
//! часов. Момент приклеивает ИСТОЧНИК: наблюдения приходят парой `(Sensed<T>, момент)`
//! ([`Sensed::Seen`] — разбор состоялся, [`Sensed::Unread`] — нет, но провод был); ниже по течению
//! часов не спрашивает никто (там буквы [`DetectorEvent`]). У шва по двери на букву
//! ([`Interleave::saw`]/[`Interleave::unread`]) — иначе поток из одних неразобранных не продвигал бы
//! сетку. Будильник срабатывает только в тишине: при живом трафике узлы вычисляются из момента,
//! стоимость сетки нулевая.

use core::time::Duration;
use std::time::Instant;

use futures::{Stream, StreamExt};
use reflex_core::clock::Ticks;
use reflex_core::detector::{DetectorEvent, Sensed};
use reflex_core::interleave::Interleave;

/// Что пришло в шов: наблюдение от источника (разобранное или нет) или узел от часов.
enum Arrival<T> {
    Sensed(Sensed<T>, Instant),
    Alarm(Instant),
}

/// Сшить источник с часами в один поток с временем внутри. `began` — начало сетки, `every` — шаг;
/// шаг это ЦЕНА (мельче — чаще пробуждения в тишине, крупнее — позже реакция на простой), потому
/// аргумент. Источник тиков берётся аргументом здесь: единственный публичный путь — [`on_grid`],
/// передающий не любой поток моментов, а поток от часов, обязанных идти по сетке.
pub(crate) fn timed<S, T, K>(
    observations: S,
    ticks: K,
    began: Instant,
    every: Duration,
) -> impl Stream<Item = DetectorEvent<T>>
where
    S: Stream<Item = (Sensed<T>, Instant)>,
    K: Stream<Item = Instant>,
{
    futures::stream::select(
        observations.map(|(sensed, at)| Arrival::Sensed(sensed, at)),
        ticks.map(Arrival::Alarm),
    )
    .scan(Interleave::started(began, every), |seam, arrival| {
        let (moved, events) = match arrival {
            Arrival::Sensed(Sensed::Seen(input), at) => seam.saw(input, at),
            Arrival::Sensed(Sensed::Unread(why), at) => seam.unread(why, at),
            Arrival::Alarm(at) => seam.idle(at),
        };
        *seam = moved;
        futures::future::ready(Some(events))
    })
    .flat_map(futures::stream::iter)
}

/// Поток с тиками — единственный способ их получить. Аргумент — ЧАСЫ, не поток моментов:
/// [`reflex_core::clock::Ticks`] обязан идти по сетке [`reflex_core::grid`] от начала; прими функция
/// произвольный `Stream<Item = Instant>`, в него подали бы цепочку задержек «поспать шаг ПОСЛЕ
/// работы» — у неё сетки нет, только период `шаг + сколько работали`, и ошибка растёт с нагрузкой.
/// У часов, реализующих `Ticks`, сетка не может отсутствовать — обязательство типа: заминка сдвигает
/// узел, не сетку. Отставшие узлы схлопываются (залп есть ошибка событийная, сдвиг — величины).
pub fn on_grid<S, T, C>(
    source: S,
    clock: C,
    began: Instant,
    every: Duration,
) -> impl Stream<Item = DetectorEvent<T>>
where
    S: Stream<Item = (Sensed<T>, Instant)>,
    C: Ticks,
{
    timed(source, clock.ticks(every), began, every)
}

#[cfg(test)]
mod tests {
    //! Живой впуск через шов — пакеты и сетка сходятся в один поток. Проверяется на тестовых часах:
    //! без ожидания, за микросекунды — то, что шов и покупает.

    use futures::StreamExt;
    use reflex_core::clock::{TestClock, Ticks};
    use reflex_core::detector::{DetectorEvent, Sensed};
    use reflex_core::parse::Unread;
    use std::time::{Duration, Instant};

    use super::timed;

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
                    DetectorEvent::Opaque { .. } => ('o', millis),
                    // 'x' — дыра: 't' занято тиком, буква не пересекается с остальными.
                    DetectorEvent::Torn { .. } => ('x', millis),
                }
            })
            .collect()
    }

    fn at(began: Instant, millis: u64) -> Instant {
        began + Duration::from_millis(millis)
    }

    fn seen(input: i32, at: Instant) -> (Sensed<i32>, Instant) {
        (Sensed::Seen(input), at)
    }

    /// Узлы, которые перешагнул пакет, приходят перед ним — и без единого будильника. Поток тиков
    /// пуст, тики всё равно есть: при живом трафике они вычисляются из моментов пакетов.
    #[tokio::test]
    async fn a_flowing_source_gets_its_grid_without_any_alarm() {
        let began = Instant::now();
        let packets = futures::stream::iter([seen(1, at(began, 250)), seen(2, at(began, 500))]);

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

    /// Непонятое двигает сетку тем же способом, что и пакет: без двери для второй буквы поток из
    /// одних неразобранных не продвигал бы сетку, и молчание было бы неотличимо от «наблюдений не было».
    #[tokio::test]
    async fn an_unread_observation_gets_its_grid_too() {
        let began = Instant::now();
        let observations = futures::stream::iter([
            (Sensed::<i32>::Unread(Unread::Truncated), at(began, 250)),
            (Sensed::<i32>::Unread(Unread::NotIpv4), at(began, 500)),
        ]);

        let out: Vec<_> = timed(observations, futures::stream::empty(), began, STEP)
            .collect()
            .await;

        assert_eq!(
            shape(&out, began),
            vec![
                ('t', 100),
                ('t', 200),
                ('o', 250),
                ('t', 300),
                ('t', 400),
                ('t', 500),
                ('o', 500)
            ],
            "непонятое проходит через шов той же дверью-законом, что и пакет"
        );
    }

    /// Тишина тоже даёт события — ради этого будильник в шве и нужен, и только ради этого.
    #[tokio::test]
    async fn silence_still_yields_the_nodes_it_covered() {
        let clock = TestClock::new();
        let began = clock.began();
        clock.advance(Duration::from_millis(320));

        let out: Vec<_> = timed(
            futures::stream::empty::<(Sensed<i32>, Instant)>(),
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

    /// Узел не выдаётся дважды, откуда бы ни пришёл — из пакета или будильника. Два источника
    /// моментов — два повода выдать один узел; шов держит состояние единственным.
    #[tokio::test]
    async fn a_node_is_not_handed_out_twice_when_both_sources_cover_it() {
        let clock = TestClock::new();
        let began = clock.began();
        clock.advance(Duration::from_millis(250));

        let packets = futures::stream::iter([seen(1, at(began, 250))]);

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
}
