use std::collections::HashMap;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use futures::Stream;
use pin_project_lite::pin_project;
use tokio::time::{self, Interval};

use super::group_by_flow::FlowConfig;
use crate::types::{ConnectionId, HasConnectionId};

struct FlowEntry<State> {
    state: State,
    last_seen: Instant,
}

pin_project! {
    /// Groups items by their ConnectionId (bidirectional), with per-connection state.
    ///
    /// Unlike `GroupByFlowStream`, this treats both directions of a TCP connection
    /// as the same group. The `init` callback receives the `ConnectionId` so the
    /// per-connection state knows which connection it belongs to.
    ///
    /// Morphism: `Stream<T: HasConnectionId> -> Stream<R>` with per-connection state + lifecycle.
    pub struct GroupByConnectionStream<S, State, Init, Step, R> {
        #[pin]
        source: S,
        config: FlowConfig,
        init: Init,
        step: Step,
        connections: HashMap<ConnectionId, FlowEntry<State>>,
        #[pin]
        sweep_tick: Interval,
        _phantom: PhantomData<R>,
    }
}

impl<S, State, Init, Step, R> GroupByConnectionStream<S, State, Init, Step, R> {
    pub fn new(source: S, config: FlowConfig, init: Init, step: Step) -> Self {
        let sweep_interval = config.sweep_interval;
        Self {
            source,
            config,
            init,
            step,
            connections: HashMap::new(),
            sweep_tick: time::interval(sweep_interval),
            _phantom: PhantomData,
        }
    }
}

fn sweep_expired<State>(
    connections: &mut HashMap<ConnectionId, FlowEntry<State>>,
    expire_after: std::time::Duration,
) {
    let now = Instant::now();
    connections.retain(|_, entry| now.duration_since(entry.last_seen) < expire_after);
}

fn evict_oldest<State>(connections: &mut HashMap<ConnectionId, FlowEntry<State>>) {
    if let Some(oldest_key) = connections
        .iter()
        .min_by_key(|(_, entry)| entry.last_seen)
        .map(|(k, _)| *k)
    {
        connections.remove(&oldest_key);
    }
}

impl<S, T, State, Init, Step, R> Stream for GroupByConnectionStream<S, State, Init, Step, R>
where
    S: Stream<Item = T>,
    T: HasConnectionId,
    Init: Fn(ConnectionId) -> State,
    Step: FnMut(&mut State, T) -> Option<R>,
{
    type Item = R;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        // Run expiry sweep on tick
        if this.sweep_tick.as_mut().poll_tick(cx).is_ready() {
            sweep_expired(this.connections, this.config.expire_after);
        }

        match this.source.as_mut().poll_next(cx) {
            Poll::Ready(Some(input)) => {
                let conn_id = input.connection_id();
                let now = Instant::now();

                // Evict oldest if at capacity
                if !this.connections.contains_key(&conn_id)
                    && this.connections.len() >= this.config.max_flows
                {
                    evict_oldest(this.connections);
                }

                let entry = this
                    .connections
                    .entry(conn_id)
                    .or_insert_with(|| FlowEntry {
                        state: (this.init)(conn_id),
                        last_seen: now,
                    });
                entry.last_seen = now;

                if let Some(result) = (this.step)(&mut entry.state, input) {
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
