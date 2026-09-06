use std::time::Duration;

use futures::Stream;
use reflex_core::step::Step;
use reflex_core::types::{HasConnectionId, HasFlow};
use reflex_core::DetectorEvent;
use smallvec::SmallVec;

use crate::stream::{
    DebounceStream, DetectStream, FlowConfig, GroupByConnectionStream, GroupByFlowStream,
};

pub trait ReflexRuntimeExt: Stream + Sized {
    fn detect<D, Sig>(self, detector: D) -> DetectStream<Self, D, Sig>
    where
        D: Step<From = DetectorEvent<Self::Item>, To = SmallVec<[Sig; 2]>>,
    {
        self.detect_with_tick(detector, Duration::from_millis(100))
    }

    fn detect_with_tick<D, Sig>(
        self,
        detector: D,
        tick_interval: Duration,
    ) -> DetectStream<Self, D, Sig>
    where
        D: Step<From = DetectorEvent<Self::Item>, To = SmallVec<[Sig; 2]>>,
    {
        DetectStream::new(self, detector, tick_interval)
    }

    fn debounce(self, duration: Duration) -> DebounceStream<Self> {
        DebounceStream::new(self, duration)
    }

    /// Group items by Flow (5-tuple), with per-flow state and lifecycle management.
    fn group_by_flow<State, Init, Fold, R>(
        self,
        config: FlowConfig,
        init: Init,
        step: Fold,
    ) -> GroupByFlowStream<Self, State, Init, Fold, R>
    where
        Self::Item: HasFlow,
        Init: Fn() -> State,
        Fold: FnMut(&mut State, Self::Item) -> Option<R>,
    {
        GroupByFlowStream::new(self, config, init, step)
    }

    /// Group items by ConnectionId (bidirectional), with per-connection state and lifecycle.
    fn group_by_connection<State, Init, Fold, R>(
        self,
        config: FlowConfig,
        init: Init,
        step: Fold,
    ) -> GroupByConnectionStream<Self, State, Init, Fold, R>
    where
        Self::Item: HasConnectionId,
        Init: Fn(reflex_core::types::ConnectionId) -> State,
        Fold: FnMut(&mut State, Self::Item) -> Option<R>,
    {
        GroupByConnectionStream::new(self, config, init, step)
    }
}

impl<T: Stream + Sized> ReflexRuntimeExt for T {}
