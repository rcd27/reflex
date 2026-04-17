use std::time::Duration;

use futures::Stream;

use crate::detector::Detector;
use crate::stream::{
    DebounceStream, DetectStream, ScanStream, SwitchMapStream, WithLatestFromStream,
};

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
}

impl<T: Stream + Sized> ReflexExt for T {}
