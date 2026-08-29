//! `tee` — раздвоение потока: элементы идут дальше И копия уходит в приёмник.
//!
//! # Зачем оператор, если можно `map` с побочным действием
//!
//! Можно — и это ровно то, чего правило запрещает. `map(|x| { sink.send(x.clone()); x })`
//! объявлен чистым отображением, а на деле ветвит поток; читатель цепочки этого не увидит,
//! потому что сигнатура `map` о ветвлении молчит. Здесь ветвление НАЗВАНО именем оператора и
//! видно в цепочке.
//!
//! # Приёмник есть `Sink`, а не замыкание
//!
//! Замыкание-приёмник пришлось бы объявить `FnMut` (отправка требует `&mut`), и мы вернули бы
//! ту же дыру, что чинил `fold_state`. `Sink` — типизированный приёмник: оператор им ВЛАДЕЕТ,
//! опрашивает по правилам и не даёт спрятать в нём произвольный эффект.
//!
//! # ПОЛИТИКА РАЗВЕТВЛЕНИЯ НАЗЫВАЕТСЯ ВЫЗЫВАЮЩИМ (#295)
//!
//! Прежде здесь стояло: «переполнение ДРОПАЕТ, и это осознанно… кому потеря недопустима, тот
//! берёт приёмник с достаточной ёмкостью». Осознанно — да; названо — в прозе, и потому не
//! сработало, как не сработали такие же формулы у `detect_per`, `with_latest_from` и `group_by`.
//!
//! ЗАМЕР 29.08 на живом движке: при всплеске в 300 целей до расследования доходило 136 — ровно
//! ёмкость буферов (64 очередь + 64 канал + 8 в работе). Всё сверх терялось МОЛЧА. Обычная
//! веб-страница открывает сотни соединений, то есть коробка НИКОГДА не узнавала про большинство
//! целей на ней: не «узнает позже», а никогда — копия не отправлена, повода больше не будет.
//!
//! Теперь политика есть аргумент, а потеря — НАБЛЮДАЕМАЯ ВЕЛИЧИНА. Считать потери важнее, чем
//! их избежать: разветвление, которое иногда роняет копию и говорит об этом числом, честнее
//! любого, который не роняет никогда, но однажды остановит источник.

use std::pin::Pin;
use std::task::{Context, Poll};

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use futures::{Sink, Stream};
use pin_project_lite::pin_project;

/// ЧТО ДЕЛАТЬ, КОГДА ПРИЁМНИК КОПИИ НЕ ГОТОВ. Обязательный аргумент [`TeeStream::new`].
///
/// Вариант типа, а не `Option`: умолчания здесь и быть не должно — обе политики законны, и выбор
/// между ними есть решение о том, чем платить.
#[derive(Debug, Clone)]
pub enum Fanout {
    /// ТЕРЯТЬ КОПИЮ, считая потери в указанный счётчик.
    ///
    /// Основной поток не ждёт: он несёт работу человека, а копия побочна. Счётчик обязателен —
    /// именно его отсутствие делало потерю невидимой.
    Lossy(Arc<AtomicU64>),
    /// ЖДАТЬ ПРИЁМНИКА: источник не пойдёт дальше, пока копия не принята.
    ///
    /// Годится там, где копия важнее скорости источника. Для потока, который несёт работу
    /// человека, НЕ годится: ожидание оплачивает он.
    Backpressure,
}

pin_project! {
    pub struct TeeStream<S, K>
    where
        S: Stream,
    {
        #[pin]
        source: S,
        #[pin]
        sink: K,
        fanout: Fanout,
        // Элемент, чья копия ещё не принята. Существует только при `Backpressure`: при `Lossy`
        // ждать нечего, а значит и держать нечего.
        held: Option<S::Item>,
    }
}

impl<S: Stream, K> TeeStream<S, K> {
    pub fn new(source: S, sink: K, fanout: Fanout) -> Self {
        Self {
            source,
            sink,
            fanout,
            held: None,
        }
    }
}

impl<S, K> Stream for TeeStream<S, K>
where
    S: Stream,
    S::Item: Clone,
    K: Sink<S::Item>,
{
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        // ПРИДЕРЖАННЫЙ ЭЛЕМЕНТ ИДЁТ ПЕРВЫМ: он уже взят из источника, и потерять его значило бы
        // сделать ждущее разветвление теряющим — то есть отменить смысл выбора.
        match this.held.take() {
            None => (),
            Some(item) => {
                return match this.sink.as_mut().poll_ready(cx) {
                    Poll::Ready(Ok(())) => {
                        let _ = this.sink.as_mut().start_send(item.clone());
                        Poll::Ready(Some(item))
                    }
                    Poll::Ready(Err(_)) => Poll::Ready(Some(item)),
                    Poll::Pending => {
                        *this.held = Some(item);
                        Poll::Pending
                    }
                };
            }
        }

        match this.source.poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(item)) => match this.fanout {
                // ТЕРЯЕМ И СЧИТАЕМ. Копия уходит, только если приёмник готов ПРЯМО СЕЙЧАС;
                // не готов — потеря названа числом, а не тишиной.
                Fanout::Lossy(dropped) => {
                    match this.sink.as_mut().poll_ready(cx) {
                        Poll::Ready(Ok(())) => {
                            let _ = this.sink.as_mut().start_send(item.clone());
                        }
                        Poll::Ready(Err(_)) | Poll::Pending => {
                            dropped.fetch_add(1, Ordering::Relaxed);
                        }
                    };
                    Poll::Ready(Some(item))
                }
                // ЖДЁМ. Элемент придерживается, и источник не двинется, пока копия не принята.
                Fanout::Backpressure => match this.sink.as_mut().poll_ready(cx) {
                    Poll::Ready(Ok(())) => {
                        let _ = this.sink.as_mut().start_send(item.clone());
                        Poll::Ready(Some(item))
                    }
                    // Приёмник сломан — ждать больше нечего, копия невозможна.
                    Poll::Ready(Err(_)) => Poll::Ready(Some(item)),
                    Poll::Pending => {
                        *this.held = Some(item);
                        Poll::Pending
                    }
                },
            },
        }
    }
}
