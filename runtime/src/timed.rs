//! ЖИВОЙ ВПУСК ЧЕРЕЗ ШОВ: два потока моментов сходятся в один, где время — буква.
//!
//! # Шву часы НЕ НУЖНЫ, и это не экономия
//!
//! Первая редакция брала [`reflex_core::clock::Clock`] и стампила сама. Компилятор её не собрал —
//! поток тиков привязан к заимствованию часов, — и отказ оказался подсказкой о конструкции:
//! **способ ожидания есть свойство того, кто ПОРОЖДАЕТ поток, а не того, кто его сшивает**.
//!
//! Оттого здесь два потока и ни одних часов. Кто их породил — системные часы со сном, тестовые,
//! запись с диска — шва не касается; он делает ровно одно и одинаково для всех.
//!
//! # Момент приклеивает ИСТОЧНИК
//!
//! Пакеты приходят парой `(значение, момент)`. Это дословно то, чего требовал
//! [`reflex_core::clock`]: «часы добавляет тот, кто читает провод, и делать это обязан ИСТОЧНИК,
//! иначе всякий потребитель напишет своё, по-разному». Ниже по течению часов не спрашивает никто:
//! там уже `Packet | Tick`.
//!
//! # Будильник срабатывает только в тишине
//!
//! Пока трафик идёт, узлы сетки между пакетами ВЫЧИСЛЯЮТСЯ из момента пакета
//! ([`Interleave::saw`]), и тик от часов оказывается пустым — узлы уже выданы. Стоимость сетки
//! при живом трафике нулевая; часы нужны ровно там, где событий нет и приборы простоя слепы.

use core::time::Duration;
use std::time::Instant;

use futures::{Stream, StreamExt};
use reflex_core::clock::Ticks;
use reflex_core::detector::DetectorEvent;
use reflex_core::interleave::Interleave;

/// ЧТО ПРИШЛО В ШОВ: наблюдение от источника или узел от часов.
enum Arrival<T> {
    Seen(T, Instant),
    Alarm(Instant),
}

/// СШИТЬ ИСТОЧНИК С ЧАСАМИ В ОДИН ПОТОК С ВРЕМЕНЕМ ВНУТРИ.
///
/// `began` — начало сетки; `every` — её шаг. Шаг это ЦЕНА, и потому он аргумент, а не константа:
/// мельче — чаще пробуждения в тишине, крупнее — позже реакция на простой.
///
/// Источник тиков берётся аргументом здесь и только здесь: наружу крейта у этой функции нет
/// имени, и единственный публичный путь к ней — [`on_grid`], который передаёт сюда не любой
/// поток моментов, а поток от часов, обязанных идти по сетке.
pub(crate) fn timed<S, T, K>(
    packets: S,
    ticks: K,
    began: Instant,
    every: Duration,
) -> impl Stream<Item = DetectorEvent<T>>
where
    S: Stream<Item = (T, Instant)>,
    K: Stream<Item = Instant>,
{
    futures::stream::select(
        packets.map(|(input, at)| Arrival::Seen(input, at)),
        ticks.map(Arrival::Alarm),
    )
    .scan(Interleave::started(began, every), |seam, arrival| {
        let (moved, events) = match arrival {
            Arrival::Seen(input, at) => seam.saw(input, at),
            Arrival::Alarm(at) => seam.idle(at),
        };
        *seam = moved;
        futures::future::ready(Some(events))
    })
    .flat_map(futures::stream::iter)
}

/// ПОТОК С ТИКАМИ — ЕДИНСТВЕННЫЙ СПОСОБ ИХ ПОЛУЧИТЬ.
///
/// # Почему аргумент — ЧАСЫ, а не поток моментов
///
/// [`reflex_core::clock::Ticks`] — договор: поток `Instant`, который он отдаёт, обязан идти по
/// сетке [`reflex_core::grid`] — от начала отсчёта, а не от предыдущего срабатывания. Прими эта
/// функция вместо часов произвольный `Stream<Item = Instant>`, дверь осталась бы открытой ровно
/// туда, откуда сама функция уводит: в него можно было бы подать цепочку задержек — «поспать шаг
/// ПОСЛЕ работы». У такой последовательности сетки нет вовсе: у неё есть только период
/// `шаг + сколько работали`, и ошибка накапливается тем сильнее, чем выше нагрузка, — окна
/// закрываются позже ровно тогда, когда это важнее всего.
///
/// У потока моментов сетка МОЖЕТ отсутствовать; у часов, реализующих `Ticks`, — не может: это
/// обязательство их типа, а не соглашение вызывающего. Заминка сдвигает узел, но не сдвигает
/// сетку — следующий узел стоит там же, где стоял.
///
/// # Отставшие узлы схлопываются
///
/// Залп из пропущенных узлов есть ошибка СОБЫТИЙНАЯ — пачка закрытий окна с одинаковым смыслом,
/// выглядящая как настоящая беда ровно под нагрузкой. Сдвиг сетки при заминке есть ошибка
/// ВЕЛИЧИНЫ, и она видна как величина.
pub fn on_grid<S, T, C>(
    source: S,
    clock: C,
    began: Instant,
    every: Duration,
) -> impl Stream<Item = DetectorEvent<T>>
where
    S: Stream<Item = (T, Instant)>,
    C: Ticks,
{
    timed(source, clock.ticks(every), began, every)
}

#[cfg(test)]
mod tests {
    //! ЖИВОЙ ВПУСК ЧЕРЕЗ ШОВ — пакеты и сетка сходятся в один поток.
    //!
    //! Проверяется на тестовых часах: без ожидания, без устройства, за микросекунды. Ровно то, что шов
    //! и покупает — поведение во времени перестаёт требовать стенда.

    use futures::StreamExt;
    use reflex_core::clock::{TestClock, Ticks};
    use reflex_core::detector::DetectorEvent;
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
                    // Шов не рождает `Opaque` — он вообще не знает о разборе; ветка нужна ради
                    // полноты алфавита, а не потому, что до неё дойдёт прогон.
                    DetectorEvent::Opaque { .. } => ('o', millis),
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
}
