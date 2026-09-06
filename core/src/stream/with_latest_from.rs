//! `with_latest_from` — обогащение элементов источника ПОСЛЕДНИМ значением второго потока.
//!
//! # Оператор ТОТАЛЕН, и начальное значение обязательно (#295, срез 1)
//!
//! Прежде он был ЧАСТИЧЕН: пока `other` не выдал ни одного значения, элементы источника молча
//! ВЫБРАСЫВАЛИСЬ. Домен определённости не назывался здесь вовсе — его описал потребитель, в
//! другом крейте:
//!
//! > «`with_latest_from` из reflex ТЕРЯЕТ элемент, пока второй поток не выдал ни одного значения.
//! > Отсюда: поток знания обязан начинаться с семени, и семя есть условие работоспособности, а не
//! > оптимизация» — так сформулировал потребитель
//!
//! Оба его вызывающих подпирали это костылём `once(default).chain(...)`. Знание о частичности
//! жило не там, где частичность, и обходилось каждым заново.
//!
//! Теперь начальное значение — часть сигнатуры: обойти нельзя, забыть нельзя, и «что будет до
//! первого значения `other`» отвечает вызывающий, а не умолчание оператора.
//!
//! # Что это значило для человека
//!
//! В продукте источник — запросы человека, `other` — накопленное знание. Потерянный элемент есть
//! запрос, на который никто не ответил: первые обращения после старта коробки уходили в никуда.

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::Stream;
use pin_project_lite::pin_project;

pin_project! {
    pub struct WithLatestFromStream<S, Other, F>
    where
        Other: Stream,
    {
        #[pin]
        source: S,
        #[pin]
        other: Other,
        f: F,
        latest: Other::Item,
    }
}

impl<S, Other, F> WithLatestFromStream<S, Other, F>
where
    Other: Stream,
{
    pub fn new(source: S, other: Other, initial: Other::Item, f: F) -> Self {
        Self {
            source,
            other,
            f,
            latest: initial,
        }
    }
}

impl<S, Other, F, R> Stream for WithLatestFromStream<S, Other, F>
where
    S: Stream,
    Other: Stream,
    F: FnMut(S::Item, &Other::Item) -> R,
{
    type Item = R;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        // always drain updates from `other` to keep `latest` fresh
        while let Poll::Ready(Some(item)) = this.other.as_mut().poll_next(cx) {
            *this.latest = item;
        }

        // ИСТОЧНИК. Значение второго потока есть ВСЕГДА — либо пришедшее, либо начальное, — и
        // потому ветки «пропустить элемент» больше не существует: оператор тотален.
        match this.source.as_mut().poll_next(cx) {
            Poll::Ready(Some(item)) => Poll::Ready(Some((this.f)(item, this.latest))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
