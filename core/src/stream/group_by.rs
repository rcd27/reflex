use std::collections::HashMap;
use std::hash::Hash;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::Stream;
use pin_project_lite::pin_project;

pin_project! {
    /// Groups items by key and applies a per-group operator.
    ///
    /// Each unique key gets its own state. The `init` closure creates initial state,
    /// `step` processes each item and may produce output. Results from all groups
    /// are flattened into a single output stream.
    ///
    /// Морфизм категории: `Stream<T> -> Stream<R>` с per-key state isolation.
    pub struct GroupByStream<S, K, State, KeyFn, Init, Step, R> {
        #[pin]
        source: S,
        key_fn: KeyFn,
        init: Init,
        step: Step,
        groups: HashMap<K, State>,
        _phantom: PhantomData<R>,
    }
}

impl<S, K, State, KeyFn, Init, Step, R> GroupByStream<S, K, State, KeyFn, Init, Step, R>
where
    K: Hash + Eq + Clone,
{
    pub fn new(source: S, key_fn: KeyFn, init: Init, step: Step) -> Self {
        Self {
            source,
            key_fn,
            init,
            step,
            groups: HashMap::new(),
            _phantom: PhantomData,
        }
    }
}

impl<S, T, K, State, KeyFn, Init, Step, R> Stream
    for GroupByStream<S, K, State, KeyFn, Init, Step, R>
where
    S: Stream<Item = T>,
    K: Hash + Eq + Clone,
    KeyFn: Fn(&T) -> K,
    Init: Fn() -> State,
    Step: FnMut(&mut State, T) -> Option<R>,
{
    type Item = R;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        match this.source.poll_next(cx) {
            Poll::Ready(Some(input)) => {
                let key = (this.key_fn)(&input);
                let state = this.groups.entry(key).or_insert_with(&*this.init);
                if let Some(result) = (this.step)(state, input) {
                    Poll::Ready(Some(result))
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
