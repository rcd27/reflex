use std::collections::HashMap;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures::Stream;
use pin_project_lite::pin_project;
use tokio::time::{self, Interval};

use reflex_core::types::{Flow, HasFlow};

/// Configuration for flow lifecycle management.
#[derive(Debug, Clone)]
pub struct FlowConfig {
    /// Expire flows after this duration of inactivity.
    pub expire_after: Duration,
    /// Maximum number of tracked flows. Oldest is evicted when exceeded.
    pub max_flows: usize,
    /// How often to run the expiry sweep.
    pub sweep_interval: Duration,
}

impl Default for FlowConfig {
    fn default() -> Self {
        Self {
            expire_after: Duration::from_secs(60),
            max_flows: 10_000,
            sweep_interval: Duration::from_secs(10),
        }
    }
}

struct FlowEntry<State> {
    state: State,
    last_seen: Instant,
}

pin_project! {
    /// Groups items by their Flow (5-tuple) and applies a per-flow operator.
    ///
    /// Handles flow lifecycle: expiry after inactivity, eviction when max_flows exceeded.
    /// Each flow gets isolated state created by `init`, processed by `step`.
    ///
    /// Морфизм категории: `Stream<T: HasFlow> -> Stream<R>` с per-flow state + lifecycle.
    pub struct GroupByFlowStream<S, State, Init, Step, R> {
        #[pin]
        source: S,
        config: FlowConfig,
        init: Init,
        step: Step,
        flows: HashMap<Flow, FlowEntry<State>>,
        #[pin]
        sweep_tick: Interval,
        _phantom: PhantomData<R>,
    }
}

impl<S, State, Init, Step, R> GroupByFlowStream<S, State, Init, Step, R> {
    pub fn new(source: S, config: FlowConfig, init: Init, step: Step) -> Self {
        let sweep_interval = config.sweep_interval;
        Self {
            source,
            config,
            init,
            step,
            flows: HashMap::new(),
            sweep_tick: time::interval(sweep_interval),
            _phantom: PhantomData,
        }
    }
}

fn sweep_expired<State>(flows: &mut HashMap<Flow, FlowEntry<State>>, expire_after: Duration) {
    let now = Instant::now();
    flows.retain(|_, entry| now.duration_since(entry.last_seen) < expire_after);
}

fn evict_oldest<State>(flows: &mut HashMap<Flow, FlowEntry<State>>) {
    if let Some(oldest_key) = flows
        .iter()
        .min_by_key(|(_, entry)| entry.last_seen)
        .map(|(k, _)| k.clone())
    {
        flows.remove(&oldest_key);
    }
}

impl<S, T, State, Init, Step, R> Stream for GroupByFlowStream<S, State, Init, Step, R>
where
    S: Stream<Item = T>,
    T: HasFlow,
    Init: Fn() -> State,
    Step: FnMut(&mut State, T) -> Option<R>,
{
    type Item = R;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        // Run expiry sweep on tick
        if this.sweep_tick.as_mut().poll_tick(cx).is_ready() {
            sweep_expired(this.flows, this.config.expire_after);
        }

        match this.source.as_mut().poll_next(cx) {
            Poll::Ready(Some(input)) => {
                let flow = input.flow().clone();
                let now = Instant::now();

                // Evict oldest if at capacity
                if !this.flows.contains_key(&flow) && this.flows.len() >= this.config.max_flows {
                    evict_oldest(this.flows);
                }

                let entry = this.flows.entry(flow).or_insert_with(|| FlowEntry {
                    state: (this.init)(),
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
