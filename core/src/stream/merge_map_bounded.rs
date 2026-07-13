use std::pin::Pin;
use std::task::{Context, Poll};

use futures::stream::FuturesUnordered;
use futures::{Future, Stream};
use pin_project_lite::pin_project;

pin_project! {
    /// bounded-flatMap / mergeMap(Cap) — проекция молекулы `FlowPermit`
    /// (nevod/model/molecule/FlowPermit.tla).
    ///
    /// Маппит стрим айтемов в future (по одной на айтем) и гонит их конкуррентно,
    /// но одновременно живых НЕ больше `cap`. Слот в `inflight` = permit; завершение
    /// future = возврат permit (RAII, снимается сам). Пока permit'ов нет
    /// (`inflight.len() == cap`), источник НЕ опрашивается — это backpressure в ДНК:
    /// новый флоу не открывается, пока живой не терминировал (модель: `Admit`
    /// требует `inflight < Cap`, `Terminate` возвращает permit).
    ///
    /// Порядок выхода НЕ гарантирован (mergeMap неупорядочен) — эмитим по мере
    /// завершения.
    pub struct MergeMapBounded<S, F, Fut>
    where
        Fut: Future,
    {
        #[pin]
        source: S,
        f: F,
        cap: usize,
        inflight: FuturesUnordered<Fut>,
        source_done: bool,
    }
}

impl<S, F, Fut> MergeMapBounded<S, F, Fut>
where
    Fut: Future,
{
    pub fn new(source: S, cap: usize, f: F) -> Self {
        Self {
            source,
            f,
            cap,
            inflight: FuturesUnordered::new(),
            source_done: false,
        }
    }
}

impl<S, F, Fut> Stream for MergeMapBounded<S, F, Fut>
where
    S: Stream,
    F: FnMut(S::Item) -> Fut,
    Fut: Future,
{
    type Item = Fut::Output;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        // Допуск: пока есть свободный permit (inflight < cap), тянем из источника.
        // Как только потолок достигнут — источник не трогаем (backpressure).
        while !*this.source_done && this.inflight.len() < *this.cap {
            match this.source.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => this.inflight.push((this.f)(item)),
                Poll::Ready(None) => *this.source_done = true,
                Poll::Pending => break,
            }
        }

        // Терминал живых флоу: завершившаяся future эмитит результат и освобождает permit.
        match Pin::new(&mut *this.inflight).poll_next(cx) {
            Poll::Ready(Some(out)) => Poll::Ready(Some(out)),
            // Пул пуст. Источник исчерпан → весь стрим завершён; иначе ждём допуска.
            Poll::Ready(None) => {
                if *this.source_done {
                    Poll::Ready(None)
                } else {
                    Poll::Pending
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
