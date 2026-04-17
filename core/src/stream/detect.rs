use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures::Stream;
use pin_project_lite::pin_project;
use tokio::time::{self, Interval};

use crate::Detector;

pin_project! {
    pub struct DetectStream<S, D>
    where
        D: Detector,
    {
        #[pin]
        source: S,
        detector: D,
        buffer: VecDeque<D::Signal>,
        #[pin]
        tick: Interval,
    }
}

impl<S, D> DetectStream<S, D>
where
    D: Detector,
{
    pub fn new(source: S, detector: D, tick_interval: Duration) -> Self {
        Self {
            source,
            detector,
            buffer: VecDeque::new(),
            tick: time::interval(tick_interval),
        }
    }
}

impl<S, D> Stream for DetectStream<S, D>
where
    S: Stream<Item = D::Input>,
    D: Detector,
{
    type Item = D::Signal;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        // drain buffered signals first
        if let Some(signal) = this.buffer.pop_front() {
            return Poll::Ready(Some(signal));
        }

        // try tick
        if this.tick.as_mut().poll_tick(cx).is_ready() {
            let now = Instant::now();
            this.detector.on_tick(now, &mut |signal| {
                this.buffer.push_back(signal);
            });
            if let Some(signal) = this.buffer.pop_front() {
                return Poll::Ready(Some(signal));
            }
        }

        // try source
        match this.source.as_mut().poll_next(cx) {
            Poll::Ready(Some(input)) => {
                this.detector.on_packet(input, &mut |signal| {
                    this.buffer.push_back(signal);
                });
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
