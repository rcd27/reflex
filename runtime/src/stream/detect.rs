use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures::Stream;
use pin_project_lite::pin_project;
use smallvec::SmallVec;
use tokio::time::{self, Interval};

use reflex_core::step::Step;
use reflex_core::DetectorEvent;

pin_project! {
    pub struct DetectStream<S, D, Sig> {
        #[pin]
        source: S,
        detector: Option<D>,
        buffer: VecDeque<Sig>,
        #[pin]
        tick: Interval,
        // НАЧАЛО СЕТКИ И ЕЁ ШАГ — номер узла берётся [`reflex_core::grid::due`], ЕДИНЫМ законом
        // сетки, а не собственным счётчиком: второй способ считать «какой это узел» лгал бы под
        // дрейфом `tokio::time::interval`, молча съедая пропуски вместо того, чтобы их назвать.
        began: Instant,
        every: Duration,
    }
}

impl<S, D, Sig> DetectStream<S, D, Sig> {
    pub fn new(source: S, detector: D, tick_interval: Duration) -> Self {
        Self {
            source,
            detector: Some(detector),
            buffer: VecDeque::new(),
            tick: time::interval(tick_interval),
            began: Instant::now(),
            every: tick_interval,
        }
    }
}

impl<S, D, Sig> Stream for DetectStream<S, D, Sig>
where
    S: Stream,
    D: Step<From = DetectorEvent<S::Item>, To = SmallVec<[Sig; 2]>>,
{
    type Item = Sig;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        // 1. Drain buffered signals first
        if let Some(signal) = this.buffer.pop_front() {
            return Poll::Ready(Some(signal));
        }

        // 2. Try tick
        if let Some(detector) = this.detector.take() {
            if this.tick.as_mut().poll_tick(cx).is_ready() {
                let at = Instant::now();
                let node = reflex_core::grid::due(*this.began, at, *this.every);
                let (new_detector, signals) = detector.step(DetectorEvent::Tick { node, at });
                *this.detector = Some(new_detector);
                for signal in signals {
                    this.buffer.push_back(signal);
                }
                if let Some(signal) = this.buffer.pop_front() {
                    return Poll::Ready(Some(signal));
                }
            } else {
                *this.detector = Some(detector);
            }
        }

        // 3. Poll source
        match this.source.as_mut().poll_next(cx) {
            Poll::Ready(Some(input)) => {
                if let Some(detector) = this.detector.take() {
                    let at = Instant::now();
                    let (new_detector, signals) =
                        detector.step(DetectorEvent::Packet { input, at });
                    *this.detector = Some(new_detector);
                    for signal in signals {
                        this.buffer.push_back(signal);
                    }
                }
                if let Some(signal) = this.buffer.pop_front() {
                    Poll::Ready(Some(signal))
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
