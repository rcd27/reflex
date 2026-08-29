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
//! # Терминальный объект и конец цепочки (срез 3)
//!
//! `inject : CommandStream → 1` ведёт в терминальный объект. Из `1` морфизмов нет — значит после
//! инъекции цепочка кончается, и это обязано держаться ТИПОМ, а не дисциплиной.
//!
//! Отсюда решение, которое выглядит странно, пока не назовёшь причину: [`Injection`] **не
//! реализует `Stream`**. Реализуй он его — `ReflexExt` и `StreamExt` раздали бы ему все свои
//! операторы (`impl<T: Stream> ReflexExt for T {}`), и терминальность рассыпалась бы, не будучи
//! ни разу нарушенной явно.
//!
//! ДВА ЗАПРЕТА, И ОНИ РАЗНОЙ СИЛЫ — обезоруживание 29.08 показало, что путать их нельзя.
//!
//! Первый: морфизмы КАТЕГОРИИ недоступны (`Injection` — не `Pipeline`). Держится сам собой при
//! любой реализации и потому слабый.
//!
//! ```compile_fail
//! use futures::stream;
//! use reflex_core::category::Pipeline;
//!
//! // После инъекции продолжать НЕЧЕМ: из терминального объекта морфизмов нет.
//! let broken = Pipeline::of_packets(stream::iter([1u8]))
//!     .map_signals(|b| b)
//!     .classify(|b| b)
//!     .react(|b| b)
//!     .materialize(|b| b)
//!     .inject(|_cmd| ())
//!     .classify(|x| x);
//! ```
//!
//! Второй: операторы ПОТОКА недоступны (`Injection` — не `Stream`). ВОТ ЭТОТ и держит
//! терминальность: слом «сделать `Injection` потоком» красит его одного. Первый при том же сломе
//! остаётся зелёным — то есть выбросить его как «дублирующий» значило бы оставить охрану без
//! единственного работающего часового.
//!
//! ```compile_fail
//! use futures::{stream, StreamExt};
//! use reflex_core::category::Pipeline;
//!
//! // И операторы `futures` тоже не дотягиваются — `Injection` не поток.
//! let broken = Pipeline::of_packets(stream::iter([1u8]))
//!     .map_signals(|b| b)
//!     .classify(|b| b)
//!     .react(|b| b)
//!     .materialize(|b| b)
//!     .inject(|_cmd| ())
//!     .map(|x| x);
//! ```
//!
//! # Чего здесь НЕТ
//!
//! `source : () → PacketStream` касается бэкенда и приедет срезом 4. Пока цепочка начинается
//! значением, а не источником.
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

/// ТЕРМИНАЛЬНЫЙ ОБЪЕКТ КАТЕГОРИИ — `1`.
///
/// В него ведут морфизмы, завершающие цепочку: инъекция в сеть, экспорт метрик, запись в лог. Из
/// него не ведёт НИ ОДИН — это и есть формальный способ сказать, что у цепочки есть выход, за
/// которым в рамках фреймворка не происходит ничего.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Terminal;

/// МОРФИЗМ В ТЕРМИНАЛЬНЫЙ ОБЪЕКТ, готовый к исполнению.
///
/// # Почему это НЕ поток
///
/// Единственный способ запретить «оператор после инъектора» — не дать ему быть потоком. Иначе
/// `impl<T: Stream> ReflexExt for T {}` и `StreamExt` раздадут ему всю алгебру, и терминальность
/// останется словом в документе.
///
/// Отсюда же следует, что НАБЛЮДАТЬ надо ДО инъекции — `tap` определён на любой стадии, и это его
/// место. После неё наблюдать нечего: эффект ушёл в сеть, а сеть фреймворку не подотчётна.
pub struct Injection<S, F> {
    commands: S,
    emit: F,
}

impl<S, F, K> Injection<S, F>
where
    S: Stream<Item = K> + Unpin,
    F: FnMut(K),
{
    /// ИСПОЛНИТЬ. Единственное, что можно сделать с морфизмом в `1`.
    ///
    /// Возвращает `Terminal`, а не число отправленных: счёт есть НАБЛЮДЕНИЕ, и его место — `tap`
    /// до инъекции. Позволить инъектору отчитываться значило бы завести морфизм из `1`.
    pub async fn drive(mut self) -> Terminal {
        let mut commands = self.commands;
        while let Some(command) = commands.next().await {
            (self.emit)(command);
        }
        Terminal
    }
}

impl<K, S: Stream<Item = K>> Pipeline<Commands<K>, S> {
    /// `CommandStream<Κ> → 1` — терминальный морфизм.
    ///
    /// Цепочка на этом кончается: у [`Injection`] нет ни морфизмов категории, ни операторов
    /// потока, и добавить их нельзя, не написав другую программу.
    pub fn inject<F>(self, emit: F) -> Injection<S, F>
    where
        F: FnMut(K),
    {
        Injection {
            commands: self.inner,
            emit,
        }
    }
}
