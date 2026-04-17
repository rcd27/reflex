use std::pin::Pin;
use std::task::{Context, Poll};

use futures::Stream;
use pin_project_lite::pin_project;

pin_project! {
    pub struct SwitchMapStream<S, F, Inner>
    where
        Inner: Stream,
    {
        #[pin]
        source: S,
        f: F,
        #[pin]
        inner: Option<Inner>,
    }
}

impl<S, F, Inner> SwitchMapStream<S, F, Inner>
where
    Inner: Stream,
{
    pub fn new(source: S, f: F) -> Self {
        Self {
            source,
            f,
            inner: None,
        }
    }
}

impl<S, F, Inner> Stream for SwitchMapStream<S, F, Inner>
where
    S: Stream,
    F: FnMut(S::Item) -> Inner,
    Inner: Stream,
{
    type Item = Inner::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        // check source for new outer element — switch inner stream
        match this.source.as_mut().poll_next(cx) {
            Poll::Ready(Some(outer)) => {
                let new_inner = (this.f)(outer);
                this.inner.as_mut().set(Some(new_inner));
            }
            Poll::Ready(None) => {
                if this.inner.as_mut().as_pin_mut().is_none() {
                    return Poll::Ready(None);
                }
            }
            Poll::Pending => {}
        }

        // poll inner stream
        if let Some(inner) = this.inner.as_mut().as_pin_mut() {
            match inner.poll_next(cx) {
                Poll::Ready(Some(item)) => Poll::Ready(Some(item)),
                Poll::Ready(None) => {
                    this.inner.set(None);
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Pending
        }
    }
}
