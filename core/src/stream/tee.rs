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
//! # Переполнение ДРОПАЕТ, и это осознанно
//!
//! Основной поток не смеет ждать приёмника: он несёт полезную работу, а копия — побочную.
//! Приёмник не готов — копия теряется, и это лучше, чем задержать основной поток. Кому потеря
//! недопустима, тот берёт приёмник с достаточной ёмкостью, а не блокирует главную ветку.

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{Sink, Stream};
use pin_project_lite::pin_project;

pin_project! {
    pub struct TeeStream<S, K> {
        #[pin]
        source: S,
        #[pin]
        sink: K,
    }
}

impl<S, K> TeeStream<S, K> {
    pub fn new(source: S, sink: K) -> Self {
        Self { source, sink }
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

        match this.source.poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(item)) => {
                // Копия уходит, только если приёмник готов ПРЯМО СЕЙЧАС. Ждать его нельзя:
                // основной поток несёт работу человека.
                match this.sink.as_mut().poll_ready(cx) {
                    Poll::Ready(Ok(())) => {
                        let _ = this.sink.as_mut().start_send(item.clone());
                    }
                    Poll::Ready(Err(_)) => (),
                    Poll::Pending => (),
                };
                Poll::Ready(Some(item))
            }
        }
    }
}
