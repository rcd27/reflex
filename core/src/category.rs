//! ОБЪЕКТЫ КАТЕГОРИИ — типами, а не именами в документе (#295, срез 2).
//!
//! # Что было
//!
//! Vision (§5) объявляет шесть объектов frontend-категории и семь морфизмов между ними. В коде не
//! было заведено НИ ОДНОГО: всё — `impl Stream<Item = T>` из `futures`, а расширение раздавалось
//! всем подряд (`impl<T: Stream> ReflexExt for T {}`). Цепочку ограничивало ровно то же, что
//! ограничивает её в голом `futures`, — совпадение типа элемента. Сетевой семантики в этой
//! проверке не было.
//!
//! Обещание «нельзя случайно собрать бессмысленную цепочку» опиралось на объекты, которых не
//! существовало.
//!
//! # Что здесь
//!
//! Стадия — ТИП, а не соглашение. Морфизм — метод, определённый ТОЛЬКО на своей стадии. Отсюда
//! «классифицировать пакеты, минуя детекцию» не компилируется: метода нет, и обойти это можно
//! лишь написав другую программу, а не забыв правило.
//!
//! ```compile_fail
//! use futures::stream;
//! use reflex_core::category::Pipeline;
//!
//! // Классификация определена на СИГНАЛАХ. Пакеты классифицировать нечем — детекции не было.
//! let broken = Pipeline::of_packets(stream::iter([1u8, 2, 3])).classify(|_| "что-то");
//! ```
//!
//! А законная цепочка собирается:
//!
//! ```
//! use futures::stream;
//! use reflex_core::category::Pipeline;
//!
//! let ok = Pipeline::of_packets(stream::iter([1u8, 2, 3]))
//!     .map_signals(|byte| byte > 1)      // packets → signals
//!     .classify(|big| match big { true => "крупный", false => "мелкий" })
//!     .react(|kind| format!("лечим {kind}"))
//!     .materialize(|plan| plan.into_bytes());
//! ```
//!
//! # Чего здесь НЕТ
//!
//! `source` и `inject` — морфизмы, которые касаются бэкенда, и потому приезжают со срезами 3 и 4.
//! Пока цепочка начинается значением, а не источником, и кончается командами, а не инъекцией.
//!
//! # Отношение к `ReflexExt`
//!
//! Не замена и не второй способ сказать то же. `ReflexExt` — алгебра потоков (композиция,
//! группировка, время), она остаётся и работает под капотом. `Pipeline` добавляет то, чего у неё
//! нет по построению: СЕМАНТИКУ СТАДИИ. Одно строится из другого, а не рядом с ним.

use std::marker::PhantomData;

use futures::{Stream, StreamExt};

/// СЫРЫЕ ПАКЕТЫ С КАНАЛА. Начало всякой цепочки.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packets;

/// ПАКЕТЫ, СГРУППИРОВАННЫЕ ПО СОЕДИНЕНИЮ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flows;

/// НАБЛЮДЕНИЯ ДЕТЕКТОРА. Параметр — что именно наблюдали.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signals<S>(PhantomData<S>);

/// КЛАССИФИКАЦИИ НАБЛЮДЁННОГО.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Classifications<C>(PhantomData<C>);

/// ВЫБРАННЫЕ СТРАТЕГИИ РЕАГИРОВАНИЯ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Strategies<T>(PhantomData<T>);

/// КОМАНДЫ ИНЪЕКТОРУ — последняя стадия перед выходом из категории.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Commands<K>(PhantomData<K>);

/// ПОТОК НА ОПРЕДЕЛЁННОЙ СТАДИИ.
///
/// `Stage` не участвует в вычислении и существует только для компилятора: это и есть перенос
/// закона из головы разработчика в тип.
pub struct Pipeline<Stage, S> {
    inner: S,
    stage: PhantomData<Stage>,
}

impl<Stage, S> Pipeline<Stage, S> {
    fn at<Next>(inner: S) -> Pipeline<Next, S> {
        Pipeline {
            inner,
            stage: PhantomData,
        }
    }

    /// `X → X` — ответвление наблюдателя, не меняющее поток.
    ///
    /// Единственный морфизм, определённый на ЛЮБОЙ стадии: наблюдать можно что угодно, и от
    /// наблюдения стадия не меняется. В этом он и отличается от прочих — те ведут из объекта в
    /// объект, а этот возвращает в тот же.
    pub fn tap<F>(
        self,
        mut watch: F,
    ) -> Pipeline<Stage, futures::stream::Map<S, impl FnMut(S::Item) -> S::Item>>
    where
        S: Stream,
        S::Item: Clone,
        F: FnMut(&S::Item),
    {
        Pipeline::<Stage, _>::at(self.inner.map(move |item| {
            watch(&item);
            item
        }))
    }

    /// ВЫЙТИ ИЗ КАТЕГОРИИ к обычному потоку.
    ///
    /// Нужно и законно: `Pipeline` описывает СТАДИИ, а всё, что делает с потоком `futures`,
    /// остаётся доступным. Запирать поток внутри значило бы требовать переписать под категорию
    /// то, что и так работает.
    pub fn into_stream(self) -> S {
        self.inner
    }
}

impl<S: Stream> Pipeline<Packets, S> {
    /// ВВОД: поток пакетов становится началом цепочки.
    pub fn of_packets(inner: S) -> Self {
        Pipeline {
            inner,
            stage: PhantomData,
        }
    }

    /// `PacketStream → SignalStream<S>` — простейшая форма детекции: наблюдение выводится из
    /// пакета без состояния.
    ///
    /// Детекция С СОСТОЯНИЕМ живёт в `Detector`/`detect_per` и приедет сюда морфизмом, когда
    /// стадии срастутся с ними; пока это отдельный слой, и притворяться, что он уже здесь, нельзя.
    pub fn map_signals<F, Sig>(self, f: F) -> Pipeline<Signals<Sig>, futures::stream::Map<S, F>>
    where
        F: FnMut(S::Item) -> Sig,
    {
        Pipeline::<Packets, _>::at(self.inner.map(f))
    }
}

impl<S: Stream> Pipeline<Packets, S> {
    /// `PacketStream → FlowStream` — группировка по соединению.
    ///
    /// КЛЮЧ ЗАДАЁТ ВЫЗЫВАЮЩИЙ, и это не лень: 5-tuple живёт в его словаре пакета, а категория
    /// говорит о СТАДИЯХ, не о том, как устроен пакет. Требовать здесь конкретный тип значило бы
    /// втащить в ядро знание домена — ровно то, за что ревью 29.08 назвало утечкой соседние места.
    pub fn group_flows<F, K>(self, key: F) -> Pipeline<Flows, futures::stream::Map<S, F>>
    where
        F: FnMut(S::Item) -> K,
    {
        Pipeline::<Packets, _>::at(self.inner.map(key))
    }
}

impl<Sig, S: Stream<Item = Sig>> Pipeline<Signals<Sig>, S> {
    /// `SignalStream<S> → ClassificationStream<C>`.
    pub fn classify<F, C>(self, f: F) -> Pipeline<Classifications<C>, futures::stream::Map<S, F>>
    where
        F: FnMut(Sig) -> C,
    {
        Pipeline::<Signals<Sig>, _>::at(self.inner.map(f))
    }
}

impl<C, S: Stream<Item = C>> Pipeline<Classifications<C>, S> {
    /// `ClassificationStream<C> → StrategyStream<Σ>`.
    pub fn react<F, T>(self, f: F) -> Pipeline<Strategies<T>, futures::stream::Map<S, F>>
    where
        F: FnMut(C) -> T,
    {
        Pipeline::<Classifications<C>, _>::at(self.inner.map(f))
    }
}

impl<T, S: Stream<Item = T>> Pipeline<Strategies<T>, S> {
    /// `StrategyStream<Σ> → CommandStream<Κ>`.
    pub fn materialize<F, K>(self, f: F) -> Pipeline<Commands<K>, futures::stream::Map<S, F>>
    where
        F: FnMut(T) -> K,
    {
        Pipeline::<Strategies<T>, _>::at(self.inner.map(f))
    }
}
