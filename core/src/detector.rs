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
    /// Wall-clock момент наблюдения события (для логов и таймеров).
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

/// Композиция двух детекторов над ОДНИМ входом и ОДНИМ словарём сигналов.
///
/// # Зачем
///
/// Детектор, живущий шагом внутри группировки, нельзя добавить или снять, не тронув соседний
/// код: правило детекции оказывается вплавлено в обработчик. Композиция делает детекторы
/// звеньями — новая болезнь заводится дописыванием `.and(…)`, и существующие правила при этом
/// не читаются и не редактируются.
///
/// # Что гарантирует тип
///
/// `Input` у обоих обязан совпасть, и это не формальность: детектор троттлинга UDP-датаграмм
/// физически не соберётся в цепочке над TCP-сегментами. Уровень стека проверяется компилятором,
/// а не внимательностью.
///
/// # Порядок и цена
///
/// Оба детектора видят КАЖДОЕ событие — это независимые наблюдатели, а не цепочка фильтров.
/// Сигналы выдаются в порядке `A`, затем `B`. Цена названа: событие клонируется по разу на
/// детектор, потому `Input` обязан быть `Clone`, а очень длинная цепочка `.and` умножает
/// клонирование на свою длину.
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

/// ПЕРЕИМЕНОВАНИЕ СИГНАЛА — детектор говорит о своём предмете, вызывающий надевает своё поверх.
///
/// # Зачем
///
/// Прибор говорит о МИРЕ («пришёл сброс»), а сообщение потребителя доменно («беда на этой ноге у
/// этой цели»). Пока сигнал детектора обязан быть доменным типом, детектор нельзя вынести в
/// крейт приборов вовсе: он тащит домен за собой, и граница «знание о мире / знание о нас»
/// ломается в первый же переезд.
///
/// Вместе с [`LMap`] делает детектор ПРОФУНКТОРОМ: ядро остаётся чистым про свой предмет, а
/// доменная одежда надевается снаружи отдельным звеном.
///
/// # Что гарантируют законы
///
/// `rmap id = id` и `rmap f ∘ rmap g = rmap (f ∘ g)` — проверены тестами. Второй закон и есть
/// причина, по которой переименований можно навешивать сколько угодно: длинная цепочка не теряет
/// сигналов и не меняет их порядок.
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

/// СУЖЕНИЕ ВХОДА — прибор, знающий только свой словарь, встаёт в чужую цепочку.
///
/// # Зачем
///
/// Пара к [`RMap`]. Наблюдение домена несёт и мировое (что случилось на проводе), и своё (какое
/// это соединение, чьё устройство, по какой ноге пробовали). Прибор о мире обязан видеть первое
/// и не должен видеть второго — не из вежливости, а потому что иначе он не переносится: тип
/// входа привязывает его к домену навсегда.
///
/// # `None` значит «не про этот прибор»
///
/// Событие, для которого сужение вернуло `None`, до детектора НЕ ДОХОДИТ. Это сильнее, чем
/// «дошло и было проигнорировано»: прибор, которому подали чужой предмет, не должен иметь
/// возможности о нём высказаться — иначе слепота одного звена выходит наружу словом о мире.
///
/// # ТИК ПРОХОДИТ ВСЕГДА
///
/// Сужение фильтрует наблюдения и НЕ ТРОГАЕТ время. Прибор со своими часами (`Silence` и всякий,
/// чей предмет есть отсутствие событий) узнаёт о беде именно тиком; сужение, съедающее тики,
/// остановило бы ему время МОЛЧА, и он выглядел бы исправным — просто никогда не срабатывал бы.
/// Ровно тот класс отказа, ради которого заведена перепись парка (#320).
pub struct LMap<D, F, Wide> {
    inner: D,
    f: F,
    /// Ширина входа названа параметром типа: без неё `Wide` не связан структурой и не выводится.
    /// Форма `fn(&Wide)` намеренна — она не наследует авто-трейты чужого типа.
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

/// ПЕРЕХОД ВМЕСТО ЗНАЧЕНИЯ — детектор говорит, когда показание СМЕНИЛОСЬ.
///
/// # Почему комбинатор, а не оператор потока
///
/// [`crate::stream::DistinctUntilChangedStream`] делает то же самое НАД ПОТОКОМ ЦЕЛИКОМ, и для
/// потока одного предмета этого достаточно. Но детекция живёт внутри `detect_per`, где ключей
/// много: две цели, чередуясь, дают чередующиеся показания, и оператор потока пропустит их все
/// как «сменилось». Здесь экземпляр живёт НА КЛЮЧ, и переход считается по тому предмету, о
/// котором высказывание, — то есть по цели, а не по проводу.
///
/// # Кому он нужен, а кому вреден
///
/// Нужен приборам, чья форма выхода есть СОСТОЯНИЕ (`Shape::State`): они высказываются по темпу
/// трафика и без него заваливают потребителя повторами. Приборам события (`Shape::Event`)
/// избыточен — событие само есть момент, и подавлять там нечего. Выбор выводится из паспорта
/// прибора, а не из вкуса вызывающего.
///
/// # Законы
///
/// `changes ∘ changes = changes` — та же идемпотентность, что у оператора потока; она и
/// разрешает навешивать комбинатор, не проверяя, не навесил ли его уже кто-то ниже. Сравнение
/// идёт с ПОСЛЕДНИМ показанием, а не со всеми виденными: возврат к прежнему есть событие
/// («снова стало плохо» надо сказать), и память обо всём проглотила бы вторую беду.
pub struct Changes<D: Detector> {
    inner: D,
    /// Последнее сказанное. `None` — не говорили ещё ничего, и первое показание пройдёт: ему не
    /// с чем совпадать, а молчание о нём потеряло бы начальное состояние.
    said: Option<D::Signal>,
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
        // Сигналы одного шага сравниваются ПО ОЧЕРЕДИ и каждый со своим предшественником: шаг,
        // выдавший два одинаковых показания, тоже есть повтор, и различать их по границе шага
        // значило бы отдать закон на волю того, как детектор разложил свою работу.
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
