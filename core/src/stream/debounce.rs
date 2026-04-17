use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::{Future, Stream};
use pin_project_lite::pin_project;
use tokio::time::{self, Sleep};

pin_project! {
    pub struct DebounceStream<S: Stream> {
        #[pin]
        source: S,
        duration: Duration,
        #[pin]
        delay: Option<Sleep>,
        pending: Option<S::Item>,
        source_done: bool,
    }
}

impl<S: Stream> DebounceStream<S> {
    pub fn new(source: S, duration: Duration) -> Self {
        Self {
            source,
            duration,
            delay: None,
            pending: None,
            source_done: false,
        }
    }
}

impl<S: Stream> Stream for DebounceStream<S> {
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        // check delay FIRST — if it elapsed, emit before consuming new items
        if let Some(delay) = this.delay.as_mut().as_pin_mut() {
            if delay.poll(cx).is_ready() {
                this.delay.set(None);
                if let Some(item) = this.pending.take() {
                    return Poll::Ready(Some(item));
                }
            }
        }

        // then consume from source
        if !*this.source_done {
            loop {
                match this.source.as_mut().poll_next(cx) {
                    Poll::Ready(Some(item)) => {
                        *this.pending = Some(item);
                        this.delay
                            .as_mut()
                            .set(Some(time::sleep(*this.duration)));
                    }
                    Poll::Ready(None) => {
                        *this.source_done = true;
                        // flush pending on source completion
                        if let Some(item) = this.pending.take() {
                            this.delay.set(None);
                            return Poll::Ready(Some(item));
                        }
                        return Poll::Ready(None);
                    }
                    Poll::Pending => break,
                }
            }
        }

        // source is done and no pending — we're done
        if *this.source_done && this.pending.is_none() {
            return Poll::Ready(None);
        }

        Poll::Pending
    }
}
