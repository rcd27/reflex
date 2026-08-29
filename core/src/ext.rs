use std::hash::Hash;

use futures::{Future, Stream};

use crate::detector::{Detector, DetectorEvent};
use crate::stream::{
    DetectPer, FoldStream, GroupByDomainStream, GroupByStream, MergeMapBounded, ScanStream,
    SwitchMapStream, TakeThroughStream, TeeStream, WithLatestFromStream,
};
use crate::types::TcpSegment;

pub trait ReflexExt: Stream + Sized {
    fn scan_state<State, F>(self, initial: State, f: F) -> ScanStream<Self, State, F>
    where
        State: Clone,
        F: FnMut(&mut State, Self::Item),
    {
        ScanStream::new(self, initial, f)
    }

    /// ЧИСТАЯ свёртка: `Fn(State, Item) -> State`.
    ///
    /// Предпочитать [`scan_state`](Self::scan_state), который правит состояние через `&mut` и
    /// потому не мешает спрятать в шаге произвольный эффект. Здесь `Fn` запрещает мутацию
    /// захваченного, а возврат состояния обязателен — нечистый шаг не соберётся.
    ///
    /// Цена: состояние передаётся по значению. Большому состоянию нужно структурное разделение.
    fn fold_state<State, F>(self, seed: State, f: F) -> FoldStream<Self, State, F>
    where
        State: Clone,
        F: Fn(State, Self::Item) -> State,
    {
        FoldStream::new(self, seed, f)
    }

    /// Раздвоение потока: элементы идут дальше, копия уходит в `sink`.
    ///
    /// Ветвление названо оператором, а не спрятано в `map` с побочным действием. Приёмник не
    /// готов — копия теряется: основной поток не ждёт побочной ветки.
    fn tee<K>(self, sink: K) -> TeeStream<Self, K>
    where
        Self::Item: Clone,
        K: futures::Sink<Self::Item>,
    {
        TeeStream::new(self, sink)
    }

    fn switch_map<F, Inner>(self, f: F) -> SwitchMapStream<Self, F, Inner>
    where
        F: FnMut(Self::Item) -> Inner,
        Inner: Stream,
    {
        SwitchMapStream::new(self, f)
    }

    /// bounded-flatMap / mergeMap(`cap`) — потолок конкуррентности живых future.
    ///
    /// По future на айтем, одновременно живых НЕ больше `cap`; пока потолок занят,
    /// источник не опрашивается (backpressure). Проекция молекулы `FlowPermit`
    /// (nevod/model/molecule/FlowPermit.tla): permit = слот, `Terminate` = завершение
    /// future. Порядок выхода не гарантирован.
    fn merge_map_bounded<F, Fut>(self, cap: usize, f: F) -> MergeMapBounded<Self, F, Fut>
    where
        F: FnMut(Self::Item) -> Fut,
        Fut: Future,
    {
        MergeMapBounded::new(self, cap, f)
    }

    /// Прогнать [`Detector`] по потоку, со своим состоянием на каждый ключ.
    ///
    /// Ключ берётся из ВХОДА события; `Tick` доставляется всем живым состояниям, потому что
    /// таймер есть событие времени, а не одной цели — без этого детектор тишины не сработал бы
    /// никогда. Детектор рождается `factory` на первом событии ключа.
    ///
    /// Правило детекции подставляется значением, а не вшивается в шаг группировки: добавить
    /// новую болезнь значит дописать `.and(…)` к детектору, не читая и не правя соседние.
    /// См. [`crate::DetectorExt::and`] и [`DetectPer`].
    fn detect_per<D, K, KeyFn, Factory>(
        self,
        key_fn: KeyFn,
        factory: Factory,
        lifetime: crate::stream::Lifetime,
    ) -> DetectPer<Self, D, K, KeyFn, Factory>
    where
        Self: Stream<Item = DetectorEvent<D::Input>> + Unpin,
        D: Detector + Unpin,
        D::Input: Clone,
        D::Signal: Unpin,
        K: Ord + Clone + Unpin,
        KeyFn: Fn(&D::Input) -> K + Unpin,
        Factory: Fn() -> D + Unpin,
    {
        DetectPer::new(self, key_fn, factory, lifetime)
    }

    /// БЕРИ, ПОКА ПРЕДИКАТ ДЕРЖИТ, ВКЛЮЧАЯ ТУ, ЧТО ЕГО СНЯЛА. См. [`TakeThroughStream`].
    ///
    /// Отличие от `take_while` не косметическое: тот роняет элемент, на котором предикат стал
    /// ложным, а для ПОИСКА это ровно тот элемент, ради которого поиск затевался.
    fn take_through<P>(self, predicate: P) -> TakeThroughStream<Self, P>
    where
        Self: Sized,
        P: FnMut(&Self::Item) -> bool,
    {
        TakeThroughStream::new(self, predicate)
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
}

impl<T: Stream + Sized> ReflexExt for T {}
