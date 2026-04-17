use std::pin::Pin;
use std::task::{Context, Poll};

use futures::Stream;
use pin_project_lite::pin_project;

pin_project! {
    pub struct ScanStream<S, State, F> {
        #[pin]
        source: S,
        state: State,
        f: F,
    }
}

impl<S, State, F> ScanStream<S, State, F> {
    pub fn new(source: S, initial: State, f: F) -> Self {
        Self {
            source,
            state: initial,
            f,
        }
    }
}

impl<S, State, F> Stream for ScanStream<S, State, F>
where
    S: Stream,
    State: Clone,
    F: FnMut(&mut State, S::Item),
{
    type Item = State;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        match this.source.poll_next(cx) {
            Poll::Ready(Some(input)) => {
                (this.f)(this.state, input);
                Poll::Ready(Some(this.state.clone()))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
