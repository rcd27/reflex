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
pub fn timed<S, T, K>(
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
