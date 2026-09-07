use std::time::Duration;

use futures::Stream;
use reflex_core::step::Step;
use reflex_core::types::{HasConnectionId, HasFlow};
use reflex_core::DetectorEvent;

use crate::stream::{
    DebounceStream, DetectStream, FlowConfig, GroupByConnectionStream, GroupByFlowStream,
};

pub trait ReflexRuntimeExt: Stream + Sized {
    /// Поднять [`Step`] на поток, сшитый с сеткой узлов.
    ///
    /// Шаг берётся ЛЮБОЙ, чей вход есть буква этого алфавита: подъём поднимает шаг, а не разбирает
    /// его слово. Наружу выходит пара — и слово, и показание.
    ///
    /// # ЧТО ЭТО ЗНАЧИТ ДЛЯ ТЕМПА ТОГО, ЧТО СТОИТ ДАЛЬШЕ
    ///
    /// Пара выходит НА КАЖДЫЙ ШАГ — на каждый пакет и на каждый узел сетки, — включая шаги, на
    /// которых прибору сказать было нечего: молчание есть такой же его выход, как и речь, и,
    /// уронив пустое слово, подъём уронил бы вместе с ним показание того же шага.
    ///
    /// Значит цепочка, стоящая за подъёмом, едет на ПАКЕТНОМ темпе, а не на сигнальном. Кому нужен
    /// прежний темп, тот ставит своё звено — уплощение слова или отсев молчания, — где это видно.
    fn detect<D>(self, detector: D) -> DetectStream<Self, D>
    where
        D: Step<From = DetectorEvent<Self::Item>>,
    {
        self.detect_with_tick(detector, Duration::from_millis(100))
    }

    /// То же с названным шагом сетки. См. [`detect`](Self::detect).
    fn detect_with_tick<D>(self, detector: D, tick_interval: Duration) -> DetectStream<Self, D>
    where
        D: Step<From = DetectorEvent<Self::Item>>,
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
