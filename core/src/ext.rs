use std::hash::Hash;
use std::time::Duration;

use futures::Stream;

use crate::detector::Detector;
use crate::stream::{
    DebounceStream, DetectStream, FlowConfig, GroupByDomainStream, GroupByFlowStream, GroupByStream,
    ScanStream, SwitchMapStream, WithLatestFromStream,
};
use crate::types::{HasFlow, TcpSegment};

pub trait ReflexExt: Stream + Sized {
    fn detect<D>(self, detector: D) -> DetectStream<Self, D>
    where
        D: Detector<Input = Self::Item>,
    {
        self.detect_with_tick(detector, Duration::from_millis(100))
    }

    fn detect_with_tick<D>(self, detector: D, tick_interval: Duration) -> DetectStream<Self, D>
    where
        D: Detector<Input = Self::Item>,
    {
        DetectStream::new(self, detector, tick_interval)
    }

    fn debounce(self, duration: Duration) -> DebounceStream<Self> {
        DebounceStream::new(self, duration)
    }

    fn scan_state<State, F>(self, initial: State, f: F) -> ScanStream<Self, State, F>
    where
        State: Clone,
        F: FnMut(&mut State, Self::Item),
    {
        ScanStream::new(self, initial, f)
    }

    fn switch_map<F, Inner>(self, f: F) -> SwitchMapStream<Self, F, Inner>
    where
        F: FnMut(Self::Item) -> Inner,
        Inner: Stream,
    {
        SwitchMapStream::new(self, f)
    }

    fn with_latest_from<Other, F, R>(
        self,
        other: Other,
        f: F,
    ) -> WithLatestFromStream<Self, Other, F>
    where
        Other: Stream,
        F: FnMut(Self::Item, &Other::Item) -> R,
    {
        WithLatestFromStream::new(self, other, f)
    }

    /// Group items by an arbitrary key, with per-group state.
    fn group_by<K, State, KeyFn, Init, Step, R>(
        self,
        key_fn: KeyFn,
        init: Init,
        step: Step,
    ) -> GroupByStream<Self, K, State, KeyFn, Init, Step, R>
    where
        K: Hash + Eq + Clone,
        KeyFn: Fn(&Self::Item) -> K,
        Init: Fn() -> State,
        Step: FnMut(&mut State, Self::Item) -> Option<R>,
    {
        GroupByStream::new(self, key_fn, init, step)
    }

    /// Group TCP segments by domain name, with per-domain state.
    ///
    /// Domain is resolved via `resolver`. Packets returning `None` are silently skipped.
    /// Domains live forever (no expiry). Output is `(String, R)`.
    fn group_by_domain<State, Resolver, Init, Step, R>(
        self,
        resolver: Resolver,
        init: Init,
        step: Step,
    ) -> GroupByDomainStream<Self, State, Resolver, Init, Step, R>
    where
        Self: Stream<Item = TcpSegment>,
        Resolver: Fn(&TcpSegment) -> Option<String>,
        Init: Fn() -> State,
        Step: FnMut(&mut State, TcpSegment) -> Option<R>,
    {
        GroupByDomainStream::new(self, resolver, init, step)
    }

    /// Group items by Flow (5-tuple), with per-flow state and lifecycle management.
    fn group_by_flow<State, Init, Step, R>(
        self,
        config: FlowConfig,
        init: Init,
        step: Step,
    ) -> GroupByFlowStream<Self, State, Init, Step, R>
    where
        Self::Item: HasFlow,
        Init: Fn() -> State,
        Step: FnMut(&mut State, Self::Item) -> Option<R>,
    {
        GroupByFlowStream::new(self, config, init, step)
    }
}

impl<T: Stream + Sized> ReflexExt for T {}
