use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::Stream;
use pin_project_lite::pin_project;
use tokio::time::{self, Interval};

use crate::detector::{Detector, DetectorEvent};

pin_project! {
    pub struct DetectStream<S, D>
    where
        D: Detector,
    {
        #[pin]
        source: S,
        detector: Option<D>,
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
            detector: Some(detector),
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

        // 1. Drain buffered signals first
        if let Some(signal) = this.buffer.pop_front() {
            return Poll::Ready(Some(signal));
        }

        // 2. Try tick
        if let Some(detector) = this.detector.take() {
            if this.tick.as_mut().poll_tick(cx).is_ready() {
                let at = std::time::Instant::now();
                let (new_detector, signals) = detector.step(DetectorEvent::Tick { at });
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
                    let at = std::time::Instant::now();
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
