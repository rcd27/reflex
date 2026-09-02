use smallvec::SmallVec;
use std::time::Instant;

/// Событие для детектора: пакет или tick от scheduler'а.
///
/// Время — всегда часть события. Edge (driver/runner) проставляет `Instant::now()`
/// при попадании пакета в pipeline и при тике. Детектор никогда не дёргает часы
/// сам — это нарушает правило 1 (pure SM) и ломает детерминированные тесты.
#[derive(Debug, Clone)]
pub enum DetectorEvent<T> {
    /// Входящий пакет, наблюдаемый в момент `at`.
    Packet { input: T, at: Instant },
    /// Периодический tick от scheduler'а.
    Tick { at: Instant },
}

impl<T> DetectorEvent<T> {
    /// МОНОТОННЫЙ момент наблюдения — для интервалов, не для показа.
    ///
    /// `Instant` в календарь не переводится: строке ленты нужен `SystemTime`, и берётся он у
    /// источника (`pcap::Frame::wall`, `SystemTime::now()` на живой очереди).
    pub fn at(&self) -> Instant {
        match self {
            DetectorEvent::Packet { at, .. } => *at,
            DetectorEvent::Tick { at } => *at,
        }
    }

    /// Construct a `Packet` event stamped with `Instant::now()`.
    /// Reserved for edge code that has direct access to the system clock;
    /// pure detectors must receive `at` via the constructor argument.
    pub fn packet_now(input: T) -> Self {
        Self::Packet {
            input,
            at: Instant::now(),
        }
    }

    /// Construct a `Tick` event stamped with `Instant::now()`.
    /// Same caveat as `packet_now` — edge-only convenience.
    pub fn tick_now() -> Self {
        Self::Tick { at: Instant::now() }
    }
}

/// Stateful detector как чистая state machine.
///
/// `(State, Event) → (State, Signals)` — DDD паттерн.
/// Нет &mut self, нет side effects. Фреймворк управляет state.
///
/// # Contract
///
/// - `step` вызывается для каждого пакета (DetectorEvent::Packet)
///   и периодически (DetectorEvent::Tick).
/// - Возвращает новый state и SmallVec сигналов (stack-allocated до 2).
/// - type Input определяет уровень стека (TcpSegment, UdpDatagram, etc.)
///   и проверяется compile-time через type narrowing в pipeline.
pub trait Detector: Sized {
    type Input;
    type Signal;

    fn step(self, event: DetectorEvent<Self::Input>) -> (Self, SmallVec<[Self::Signal; 2]>);
}

/// Два НЕЗАВИСИМЫХ наблюдателя одного потока (не конвейер: событие идёт в оба).
///
/// ЦЕНА: событие клонируется по разу на детектор; цепочка из N звеньев клонирует N раз.
/// ЦЕНА: словарь сигналов общий, поэтому после сложения не видно, кто сказал.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct And<A, B>(pub A, pub B);

impl<A, B> Detector for And<A, B>
where
    A: Detector,
    B: Detector<Input = A::Input, Signal = A::Signal>,
    A::Input: Clone,
{
    type Input = A::Input;
    type Signal = A::Signal;

    fn step(self, event: DetectorEvent<Self::Input>) -> (Self, SmallVec<[Self::Signal; 2]>) {
        let (first, mut signals) = self.0.step(event.clone());
        let (second, more) = self.1.step(event);
        signals.extend(more);
        (And(first, second), signals)
    }
}

/// Переименование сигнала. Законы функтора проверены в `tests/detector_combinators.rs`.
pub struct RMap<D, F> {
    inner: D,
    f: F,
}

impl<D, F, Renamed> Detector for RMap<D, F>
where
    D: Detector,
    F: Fn(D::Signal) -> Renamed,
{
    type Input = D::Input;
    type Signal = Renamed;

    fn step(self, event: DetectorEvent<Self::Input>) -> (Self, SmallVec<[Self::Signal; 2]>) {
        let Self { inner, f } = self;
        let (stepped, signals) = inner.step(event);
        let renamed = signals.into_iter().map(&f).collect();
        (Self { inner: stepped, f }, renamed)
    }
}

/// Сужение входа: `None` — событие до детектора не доходит.
///
/// Тик проходит ВСЕГДА: сужение фильтрует наблюдения, а не время. Съеденный тик остановил бы
/// часы прибору молча, и он выглядел бы исправным.
pub struct LMap<D, F, Wide> {
    inner: D,
    f: F,
    /// `fn(&Wide)`, а не `Wide`: не наследует авто-трейты чужого типа.
    wide: core::marker::PhantomData<fn(&Wide)>,
}

impl<D, F, Wide> Detector for LMap<D, F, Wide>
where
    D: Detector,
    F: Fn(&Wide) -> Option<D::Input>,
{
    type Input = Wide;
    type Signal = D::Signal;

    fn step(self, event: DetectorEvent<Self::Input>) -> (Self, SmallVec<[Self::Signal; 2]>) {
        let Self { inner, f, wide } = self;
        match event {
            DetectorEvent::Packet { input, at } => match f(&input) {
                Some(narrowed) => {
                    let (stepped, signals) = inner.step(DetectorEvent::Packet {
                        input: narrowed,
                        at,
                    });
                    (
                        Self {
                            inner: stepped,
                            f,
                            wide,
                        },
                        signals,
                    )
                }
                None => (Self { inner, f, wide }, SmallVec::new()),
            },
            DetectorEvent::Tick { at } => {
                let (stepped, signals) = inner.step(DetectorEvent::Tick { at });
                (
                    Self {
                        inner: stepped,
                        f,
                        wide,
                    },
                    signals,
                )
            }
        }
    }
}

/// Переход вместо значения, НА КЛЮЧ: оператор потока
/// ([`crate::stream::DistinctUntilChangedStream`]) считает смену по всему потоку, и две цели,
/// чередуясь, прошли бы его насквозь.
///
/// Сравнение с ПОСЛЕДНИМ показанием, а не со всеми виденными: возврат к прежнему есть событие.
pub struct Changes<D: Detector> {
    inner: D,
    /// Первое показание проходит всегда: ему не с чем совпадать.
    said: Option<D::Signal>,
}

/// Одеть сигнал в контекст ПОСЛЕДНЕГО наблюдения — нужен приборам, что говорят по тику, когда
/// наблюдения в этот момент нет.
///
/// Контекста ещё нет — одевалка получает `None` и решает сама: молчаливая потеря сигнала здесь
/// была бы потерей беды, которой никто не заметит.
pub struct Contextual<D, Ctx, Pick, Dress> {
    inner: D,
    pick: Pick,
    dress: Dress,
    /// Последнее увиденное. `None` — наблюдений ещё не было.
    context: Option<Ctx>,
}

impl<D, Ctx, Pick, Dress, Dressed> Detector for Contextual<D, Ctx, Pick, Dress>
where
    D: Detector,
    D::Input: Clone,
    Pick: Fn(&D::Input) -> Ctx,
    Dress: Fn(Option<&Ctx>, D::Signal) -> Option<Dressed>,
{
    type Input = D::Input;
    type Signal = Dressed;

    fn step(self, event: DetectorEvent<Self::Input>) -> (Self, SmallVec<[Self::Signal; 2]>) {
        let Self {
            inner,
            pick,
            dress,
            context,
        } = self;
        // ДО шага: сигнал этого наблюдения одевается в него, а не в предыдущее.
        let context = match &event {
            DetectorEvent::Packet { input, .. } => Some(pick(input)),
            DetectorEvent::Tick { .. } => context,
        };
        let (stepped, signals) = inner.step(event);
        let dressed = signals
            .into_iter()
            .filter_map(|signal| dress(context.as_ref(), signal))
            .collect();
        (
            Self {
                inner: stepped,
                pick,
                dress,
                context,
            },
            dressed,
        )
    }
}

impl<D> Detector for Changes<D>
where
    D: Detector,
    D::Signal: PartialEq + Clone,
{
    type Input = D::Input;
    type Signal = D::Signal;

    fn step(self, event: DetectorEvent<Self::Input>) -> (Self, SmallVec<[Self::Signal; 2]>) {
        let Self { inner, said } = self;
        let (stepped, signals) = inner.step(event);
        // Повтор внутри одного шага — тоже повтор.
        let (last, fresh) =
            signals
                .into_iter()
                .fold(
                    (said, SmallVec::new()),
                    |(previous, passed), signal| match previous.as_ref() == Some(&signal) {
                        true => (previous, passed),
                        false => (
                            Some(signal.clone()),
                            passed.into_iter().chain(core::iter::once(signal)).collect(),
                        ),
                    },
                );
        (
            Self {
                inner: stepped,
                said: last,
            },
            fresh,
        )
    }
}

/// Вынести наружу момент, в который детектор высказался: `Signal` времени не несёт, а
/// `detect_per` отдаёт только `(ключ, сигнал)`.
///
/// Момент берётся у события, включая тик: прибор со своими часами замечает беду именно тиком.
pub struct Timed<D> {
    inner: D,
}

impl<D: Detector> Detector for Timed<D> {
    type Input = D::Input;
    type Signal = (Instant, D::Signal);

    fn step(self, event: DetectorEvent<Self::Input>) -> (Self, SmallVec<[Self::Signal; 2]>) {
        let at = event.at();
        let (stepped, signals) = self.inner.step(event);
        let stamped = signals.into_iter().map(|signal| (at, signal)).collect();
        (Self { inner: stepped }, stamped)
    }
}

impl<D: Clone> Clone for Timed<D> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

/// `Clone` ручной: `derive` навесил бы лишние границы.
impl<D: Clone, F: Clone> Clone for RMap<D, F> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            f: self.f.clone(),
        }
    }
}

impl<D: Clone, F: Clone, Wide> Clone for LMap<D, F, Wide> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            f: self.f.clone(),
            wide: core::marker::PhantomData,
        }
    }
}

impl<D: Clone, Ctx: Clone, Pick: Clone, Dress: Clone> Clone for Contextual<D, Ctx, Pick, Dress> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            pick: self.pick.clone(),
            dress: self.dress.clone(),
            context: self.context.clone(),
        }
    }
}

impl<D: Detector + Clone> Clone for Changes<D>
where
    D::Signal: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            said: self.said.clone(),
        }
    }
}

/// Комбинаторы детектора. Реализован для всех — писать `impl DetectorExt` не требуется.
pub trait DetectorExt: Detector + Sized {
    /// Наблюдать обоими. См. [`And`].
    fn and<B>(self, other: B) -> And<Self, B>
    where
        B: Detector<Input = Self::Input, Signal = Self::Signal>,
        Self::Input: Clone,
    {
        And(self, other)
    }

    /// Переименовать сигнал. См. [`RMap`].
    fn rmap<Renamed, F>(self, f: F) -> RMap<Self, F>
    where
        F: Fn(Self::Signal) -> Renamed,
    {
        RMap { inner: self, f }
    }

    /// Одеть сигнал в контекст наблюдения. См. [`Contextual`].
    fn contextual<Ctx, Pick, Dress, Dressed>(
        self,
        pick: Pick,
        dress: Dress,
    ) -> Contextual<Self, Ctx, Pick, Dress>
    where
        Pick: Fn(&Self::Input) -> Ctx,
        Dress: Fn(Option<&Ctx>, Self::Signal) -> Option<Dressed>,
    {
        Contextual {
            inner: self,
            pick,
            dress,
            context: None,
        }
    }

    /// Вынести наружу момент, в который прибор высказался. См. [`Timed`].
    fn timed(self) -> Timed<Self> {
        Timed { inner: self }
    }

    /// Говорить только о смене показания. См. [`Changes`].
    fn changes(self) -> Changes<Self>
    where
        Self::Signal: PartialEq + Clone,
    {
        Changes {
            inner: self,
            said: None,
        }
    }

    /// Сузить вход. См. [`LMap`].
    fn lmap<Wide, F>(self, f: F) -> LMap<Self, F, Wide>
    where
        F: Fn(&Wide) -> Option<Self::Input>,
    {
        LMap {
            inner: self,
            f,
            wide: core::marker::PhantomData,
        }
    }
}

impl<D: Detector> DetectorExt for D {}
