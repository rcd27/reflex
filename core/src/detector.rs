//! Алфавит входа детектора ([`DetectorEvent`]) и комбинаторы, собирающие детекторы в цепочки на
//! носителе [`crate::step::Step`].
//!
//! # ЧТО ЗДЕСЬ БЫЛО (снесено 06.09.2026)
//!
//! До этой правки здесь стоял отдельный трейт `Detector` — вторая подпись машины Мили рядом со
//! `Step`:
//!
//! ```text
//! pub trait Detector: Sized {
//!     type Input;
//!     type Signal;
//!     fn step(self, event: DetectorEvent<Self::Input>) -> (Self, SmallVec<[Self::Signal; 2]>);
//! }
//! ```
//!
//! Задуман он был DDD-паттерном: stateful detector как чистая state machine — `(State, Event) →
//! (State, Signals)`, без `&mut self` и без побочных эффектов, состоянием управляет фреймворк.
//! `type Input` фиксировал уровень стека (`TcpSegment`, `UdpDatagram`, …) и проверялся
//! compile-time через сужение типа в пайплайне.
//!
//! Форма была ровно та же, что у `Step` — обе суть `(State, In) → (State, SmallVec<[Sig; 2]>)`, —
//! и держать оба трейта значило бы платить за одну машину Мили дважды: имя `Detector` не несло
//! ничего, чего не нёс бы `Step`. Семь комбинаторов этого модуля (`and`, `rmap`, `lmap`,
//! `contextual`, `timed`, `by`, `changes`) переехали на `Step` первыми, опустевший `DetectorExt`
//! (`pub trait DetectorExt: Detector + Sized {}`, без единого метода) и сам `Detector` снесены
//! следом: в `core` каждая реализация трейта стала `impl Step`, а границы `D: Detector` —
//! равенствами `D: Step<From = DetectorEvent<In>, To = SmallVec<[Sig; 2]>>`. За пределами `core`
//! реализации трейта на момент сноса ещё не переведены (замер 06.09.2026): `instrument` — 15,
//! `engine` — 2, `runtime` — 2 (обе в `tests`, ни одной в `src`); их перевод — предмет задач 4-6
//! плана `absorbing-the-detector`. `engine-nfq` своих реализаций не несёт ни одной — он не
//! собирается лишь ТРАНЗИТИВНО, как зависящий от `reflex-instrument` и `reflex-engine`
//! (`engine-nfq/Cargo.toml:19-20`).
//!
//! `DetectorEvent` трейтом не был — это буква входного алфавита, а не диалект машины, — и он
//! остался без изменений.

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

/// Два НЕЗАВИСИМЫХ наблюдателя одного потока — не конвейер: событие идёт в оба.
///
/// Имя `And` было бы ложью: в логике `A AND B` значит «сработали оба», здесь — «слушают оба».
/// Метод остаётся `.and(…)` как речь цепочки.
///
/// ЦЕНА: событие клонируется по разу на детектор; цепочка из N звеньев клонирует N раз.
/// ЦЕНА: словарь сигналов общий, поэтому после сложения не видно, кто сказал.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Both<A, B>(pub A, pub B);

impl<A, B, I, S> crate::step::Step for Both<A, B>
where
    A: crate::step::Step<From = DetectorEvent<I>, To = SmallVec<[S; 2]>>,
    B: crate::step::Step<From = DetectorEvent<I>, To = SmallVec<[S; 2]>>,
    I: Clone,
{
    type From = DetectorEvent<I>;
    type To = SmallVec<[S; 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
        let (first, mut signals) = self.0.step(event.clone());
        let (second, more) = self.1.step(event);
        signals.extend(more);
        (Both(first, second), signals)
    }
}

/// Переименование сигнала. Законы функтора проверены в `tests/detector_combinators.rs`.
pub struct RMap<D, F> {
    inner: D,
    f: F,
}

impl<D, F, I, S, Renamed> crate::step::Step for RMap<D, F>
where
    D: crate::step::Step<From = DetectorEvent<I>, To = SmallVec<[S; 2]>>,
    F: Fn(S) -> Renamed,
{
    type From = DetectorEvent<I>;
    type To = SmallVec<[Renamed; 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
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

impl<D, F, Wide, I, S> crate::step::Step for LMap<D, F, Wide>
where
    D: crate::step::Step<From = DetectorEvent<I>, To = SmallVec<[S; 2]>>,
    F: Fn(&Wide) -> Option<I>,
{
    type From = DetectorEvent<Wide>;
    type To = SmallVec<[S; 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
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
///
/// # ПОЧЕМУ У СТРУКТУРЫ ПОЯВИЛСЯ `S` (06.09.2026)
///
/// Прежде тип показания брался проекцией `D::Signal`. Проекции нет: `Step` держит алфавит целиком
/// (`To = SmallVec<[S; 2]>`), а вынуть из него элемент нечем. Тип был здесь всегда — изменилось
/// лишь то, что теперь его обязаны назвать.
pub struct Changes<D, S> {
    inner: D,
    /// Первое показание проходит всегда: ему не с чем совпадать.
    said: Option<S>,
}

impl<D, S> Changes<D, S> {
    pub(crate) fn new(inner: D) -> Self {
        Self { inner, said: None }
    }
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

impl<D, Ctx, Pick, Dress, Dressed, I, S> crate::step::Step for Contextual<D, Ctx, Pick, Dress>
where
    D: crate::step::Step<From = DetectorEvent<I>, To = SmallVec<[S; 2]>>,
    I: Clone,
    Pick: Fn(&I) -> Ctx,
    Dress: Fn(Option<&Ctx>, S) -> Option<Dressed>,
{
    type From = DetectorEvent<I>;
    type To = SmallVec<[Dressed; 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
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

impl<D, I, S> crate::step::Step for Changes<D, S>
where
    D: crate::step::Step<From = DetectorEvent<I>, To = SmallVec<[S; 2]>>,
    S: PartialEq + Clone,
{
    type From = DetectorEvent<I>;
    type To = SmallVec<[S; 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
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

impl<D, I, S> crate::step::Step for Timed<D>
where
    D: crate::step::Step<From = DetectorEvent<I>, To = SmallVec<[S; 2]>>,
{
    type From = DetectorEvent<I>;
    type To = SmallVec<[(Instant, S); 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
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

impl<D: Clone, S: Clone> Clone for Changes<D, S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            said: self.said.clone(),
        }
    }
}

/// Показание, помнящее, кто его дал.
///
/// `and` складывает наблюдателей в один поток, и без имени два прибора с общим словарём
/// (`Silence` и `Choked` оба говорят «байтов нет») дают неразличимые показания при разном
/// лечении. Имя берётся из паспорта прибора, а не пишется у места сборки.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Told<S> {
    pub by: &'static str,
    pub signal: S,
}

/// Приписать показаниям автора. См. [`Told`].
pub struct By<D> {
    inner: D,
    by: &'static str,
}

impl<D, I, S> crate::step::Step for By<D>
where
    D: crate::step::Step<From = DetectorEvent<I>, To = SmallVec<[S; 2]>>,
{
    type From = DetectorEvent<I>;
    type To = SmallVec<[Told<S>; 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
        let Self { inner, by } = self;
        let (stepped, signals) = inner.step(event);
        let told = signals
            .into_iter()
            .map(|signal| Told { by, signal })
            .collect();
        (Self { inner: stepped, by }, told)
    }
}

impl<D: Clone> Clone for By<D> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            by: self.by,
        }
    }
}

impl<D, F> RMap<D, F> {
    pub(crate) fn new(inner: D, f: F) -> Self {
        Self { inner, f }
    }
}

impl<D, F, Wide> LMap<D, F, Wide> {
    pub(crate) fn new(inner: D, f: F) -> Self {
        Self {
            inner,
            f,
            wide: core::marker::PhantomData,
        }
    }
}

impl<D, Ctx, Pick, Dress> Contextual<D, Ctx, Pick, Dress> {
    pub(crate) fn new(inner: D, pick: Pick, dress: Dress) -> Self {
        Self {
            inner,
            pick,
            dress,
            context: None,
        }
    }
}

impl<D> Timed<D> {
    pub(crate) fn new(inner: D) -> Self {
        Self { inner }
    }
}

impl<D> By<D> {
    pub(crate) fn new(inner: D, by: &'static str) -> Self {
        Self { inner, by }
    }
}
