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
        latest: Option<Other::Item>,
    }
}

impl<S, Other, F> WithLatestFromStream<S, Other, F>
where
    Other: Stream,
{
    pub fn new(source: S, other: Other, f: F) -> Self {
        Self {
            source,
            other,
            f,
            latest: None,
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
            *this.latest = Some(item);
        }

        // poll source
        match this.source.as_mut().poll_next(cx) {
            Poll::Ready(Some(item)) => {
                if let Some(latest) = this.latest.as_ref() {
                    let result = (this.f)(item, latest);
                    Poll::Ready(Some(result))
                } else {
                    // no value from `other` yet — skip this item
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
