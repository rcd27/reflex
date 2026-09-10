//! Входной алфавит детектора ([`DetectorEvent`]) и комбинаторы, собирающие детекторы в цепочки на
//! носителе [`crate::mealy::Mealy`]. Время — буква события, не дёргается прибором (детерминизм).

use smallvec::SmallVec;
use std::time::Instant;

/// Событие для детектора. Время — всегда часть события: край (драйвер) проставляет `Instant`;
/// детектор часы не дёргает (иначе не чистая машина и тесты недетерминированы).
#[derive(Debug, Clone)]
pub enum DetectorEvent<T> {
    /// Входящий пакет, наблюдаемый в момент `at`.
    Packet { input: T, at: Instant },
    /// Узел сетки — единственная буква «ничего не произошло». Несёт номер (тот же при переигровке)
    /// и момент. Поля открыты для переноса через шов; цена: номер мимо сетки несравним ни с чем —
    /// оттого однострочника, штампующего тик без сетки, нет (подделка не удобнее правды).
    Tick { node: u64, at: Instant },
    /// Пришло, но разобрать не смогли — «не знаю» на входе. Без этой буквы наблюдение невыразимо.
    Opaque {
        why: crate::parse::Unread,
        at: Instant,
    },
    /// Наблюдения были и до нас не дошли — носитель объявил потерю (`ENOBUFS` у очереди ядра,
    /// переполнение у чужой ОС). Не `Opaque`: там пакет ПРИШЁЛ и не разобрался, здесь он не
    /// приходил вовсе. Слить их значило бы объявить дыру непонятым пакетом — соврать о наблюдении,
    /// которого не было. Без этой буквы прибор сравнивает наблюдения через необъявленную дыру.
    Torn { at: Instant },
}

impl<T> DetectorEvent<T> {
    /// Монотонный момент наблюдения — для интервалов, не для показа (`Instant` в календарь не
    /// переводится).
    pub fn at(&self) -> Instant {
        match self {
            DetectorEvent::Packet { at, .. } => *at,
            DetectorEvent::Tick { at, .. } => *at,
            DetectorEvent::Opaque { at, .. } => *at,
            DetectorEvent::Torn { at } => *at,
        }
    }

    /// `Packet`, штампованный `Instant::now()` — для края с прямым доступом к часам; чистый детектор
    /// получает `at` аргументом.
    pub fn packet_now(input: T) -> Self {
        Self::Packet {
            input,
            at: Instant::now(),
        }
    }
}

/// Буква входа адресована туда же, куда стадия, над которой алфавит построен: адрес один на весь
/// алфавит, включая «время шло» и «не разобрали» (тождество на стадии — морфизм категории).
impl<T: crate::word::Word> crate::word::Word for DetectorEvent<T> {
    type Of = T::Of;
}

/// Что край снял с провода: разобранное наблюдение либо причина, по которой его нет. Не
/// `Result<T, Unread>`: «не знаю» — заселённая клетка алфавита, равная наблюдению по праву быть
/// увиденной, а не отказ, ждущий обработки. Нужен шву [`crate::interleave::Interleave`]: без него
/// на потоке из одних неразобранных сетка не двигалась бы.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sensed<T> {
    /// Разбор состоялся.
    Seen(T),
    /// Разбор не состоялся — причина в закрытом перечислении.
    Unread(crate::parse::Unread),
}

/// Два независимых наблюдателя одного потока (`⟨f, g⟩` над буквой прибора): событие идёт в оба.
/// `And` было бы ложью (в логике — «сработали оба», здесь — «слушают оба»). Цена: событие
/// клонируется по разу на детектор.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Both<A, B>(pub A, pub B);

impl<A, B, I> crate::mealy::Mealy for Both<A, B>
where
    A: crate::mealy::Mealy<In = DetectorEvent<I>>,
    B: crate::mealy::Mealy<In = DetectorEvent<I>>,
    B::Out: crate::word::Word<Of = <A::Out as crate::word::Word>::Of>,
    I: Clone,
{
    type In = DetectorEvent<I>;
    /// Слова одной области, сложенные произведением: разным областям слиться нельзя, позиция
    /// называет автора.
    type Out = (A::Out, B::Out);
    /// Произведение, как у [`crate::mealy::Compose`].
    type Log = (A::Log, B::Log);

    fn step(self, event: Self::In) -> (Self, Self::Out, Self::Log) {
        let (first, said, noted) = self.0.step(event.clone());
        let (second, also, also_noted) = self.1.step(event);
        (Both(first, second), (said, also), (noted, also_noted))
    }
}

/// Функтор переименования слова. Законы (тождество и композиция) проверены отдельными тестами.
pub struct RMap<D, F> {
    inner: D,
    f: F,
}

impl<D, F, I, S, Renamed> crate::mealy::Mealy for RMap<D, F>
where
    D: crate::mealy::Mealy<In = DetectorEvent<I>, Out = SmallVec<[S; 2]>>,
    F: Fn(S) -> Renamed,
    // Новое имя обязано сказать, кому оно сказано.
    Renamed: crate::word::Word,
{
    type In = DetectorEvent<I>;
    type Out = SmallVec<[Renamed; 2]>;
    /// Меняет слово, не показания (иначе был бы звеном, а не комбинатором).
    type Log = D::Log;

    fn step(self, event: Self::In) -> (Self, Self::Out, Self::Log) {
        let Self { inner, f } = self;
        let (stepped, signals, notes) = inner.step(event);
        let renamed = signals.into_iter().map(&f).collect();
        (Self { inner: stepped, f }, renamed, notes)
    }
}

/// Сужение входа: `None` — событие до детектора не доходит. Тик проходит всегда (сужение фильтрует
/// наблюдения, не время — съеденный тик остановил бы часы молча).
pub struct LMap<D, F, Wide> {
    inner: D,
    f: F,
    /// `fn(&Wide)`, не `Wide`: не наследует авто-трейты чужого типа.
    wide: core::marker::PhantomData<fn(&Wide)>,
}

impl<D, F, Wide, I, S> crate::mealy::Mealy for LMap<D, F, Wide>
where
    D: crate::mealy::Mealy<In = DetectorEvent<I>, Out = SmallVec<[S; 2]>>,
    F: Fn(&Wide) -> Option<I>,
    S: crate::word::Word,
{
    type In = DetectorEvent<Wide>;
    type Out = SmallVec<[S; 2]>;
    /// `Option`, не голое `D::Log`: `None` — звено не шагало (зафильтровано), значение по умолчанию
    /// сказало бы «шагало и намерило пустоту».
    type Log = Option<D::Log>;

    fn step(self, event: Self::In) -> (Self, Self::Out, Self::Log) {
        let Self { inner, f, wide } = self;
        match event {
            DetectorEvent::Packet { input, at } => match f(&input) {
                Some(narrowed) => {
                    let (stepped, signals, notes) = inner.step(DetectorEvent::Packet {
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
                        Some(notes),
                    )
                }
                None => (Self { inner, f, wide }, SmallVec::new(), None),
            },
            DetectorEvent::Tick { node, at } => {
                let (stepped, signals, notes) = inner.step(DetectorEvent::Tick { node, at });
                (
                    Self {
                        inner: stepped,
                        f,
                        wide,
                    },
                    signals,
                    Some(notes),
                )
            }
            // Непонятое не несёт `Wide` — сужать нечего, проходит как есть, путём тика.
            DetectorEvent::Opaque { why, at } => {
                let (stepped, signals, notes) = inner.step(DetectorEvent::Opaque { why, at });
                (
                    Self {
                        inner: stepped,
                        f,
                        wide,
                    },
                    signals,
                    Some(notes),
                )
            }
            // Дыра тоже не несёт `Wide` — сужать нечего, проходит как есть, путём тика.
            DetectorEvent::Torn { at } => {
                let (stepped, signals, notes) = inner.step(DetectorEvent::Torn { at });
                (
                    Self {
                        inner: stepped,
                        f,
                        wide,
                    },
                    signals,
                    Some(notes),
                )
            }
        }
    }
}

/// Переход вместо значения, на ключ: смена по ключу, а не по потоку (иначе две цели, чередуясь,
/// прошли бы насквозь). Сравнение с последним сказанным (возврат к прежнему есть событие). `S`
/// параметром: `Mealy` держит алфавит целиком, вынуть элемент нечем.
pub struct Changes<D, S> {
    inner: D,
    /// Первое слово проходит всегда: ему не с чем совпадать.
    said: Option<S>,
}

impl<D, S> Changes<D, S> {
    pub(crate) fn new(inner: D) -> Self {
        Self { inner, said: None }
    }
}

/// Одеть сигнал в контекст последнего наблюдения — приборам, что говорят по тику, когда наблюдения
/// нет. Контекста ещё нет — одевалка получает `None` (молчаливая потеря была бы потерей беды).
pub struct Contextual<D, Ctx, Pick, Dress> {
    inner: D,
    pick: Pick,
    dress: Dress,
    /// Последнее увиденное. `None` — наблюдений не было.
    context: Option<Ctx>,
}

impl<D, Ctx, Pick, Dress, Dressed, I, S> crate::mealy::Mealy for Contextual<D, Ctx, Pick, Dress>
where
    D: crate::mealy::Mealy<In = DetectorEvent<I>, Out = SmallVec<[S; 2]>>,
    I: Clone,
    Pick: Fn(&I) -> Ctx,
    Dress: Fn(Option<&Ctx>, S) -> Option<Dressed>,
    // Одетое слово — тоже слово: контекст меняет наряд, не адресата.
    Dressed: crate::word::Word,
{
    type In = DetectorEvent<I>;
    type Out = SmallVec<[Dressed; 2]>;
    /// Наряд меняет слово, не показания.
    type Log = D::Log;

    fn step(self, event: Self::In) -> (Self, Self::Out, Self::Log) {
        let Self {
            inner,
            pick,
            dress,
            context,
        } = self;
        // До шага: сигнал этого наблюдения одевается в него, а не в предыдущее.
        let context = match &event {
            DetectorEvent::Packet { input, .. } => Some(pick(input)),
            // Непонятое и дыра не несут `I` — прежний контекст остаётся, как на тике.
            DetectorEvent::Tick { .. }
            | DetectorEvent::Opaque { .. }
            | DetectorEvent::Torn { .. } => context,
        };
        let (stepped, signals, notes) = inner.step(event);
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
            notes,
        )
    }
}

impl<D, I, S> crate::mealy::Mealy for Changes<D, S>
where
    D: crate::mealy::Mealy<In = DetectorEvent<I>, Out = SmallVec<[S; 2]>>,
    S: PartialEq + Clone + crate::word::Word,
{
    type In = DetectorEvent<I>;
    type Out = SmallVec<[S; 2]>;
    /// Сравнение с прошлым меняет слово, не показания.
    type Log = D::Log;

    fn step(self, event: Self::In) -> (Self, Self::Out, Self::Log) {
        let Self { inner, said } = self;
        let (stepped, signals, notes) = inner.step(event);
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
            notes,
        )
    }
}

/// Слово со штампом момента, в который оно сказано. Структура, не пара `(Instant, S)`: общий закон
/// пары накрыл бы её, и два закона адресности пересеклись бы, обвиняя не ту строку.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamped<S> {
    /// Момент наблюдения, в который слово прозвучало.
    pub at: Instant,
    pub said: S,
}

/// Штамп момента адресата не меняет: момент говорит КОГДА, не КОМУ.
impl<S: crate::word::Word> crate::word::Word for Stamped<S> {
    type Of = S::Of;
}

/// Вынести наружу момент, в который детектор высказался. Подъём момент не добавляет — значит он
/// обязан войти в слово здесь, до подъёма, или потерян. Берётся у события, включая тик.
pub struct Timed<D> {
    inner: D,
}

impl<D, I, S> crate::mealy::Mealy for Timed<D>
where
    D: crate::mealy::Mealy<In = DetectorEvent<I>, Out = SmallVec<[S; 2]>>,
    S: crate::word::Word,
{
    type In = DetectorEvent<I>;
    type Out = SmallVec<[Stamped<S>; 2]>;
    /// Штамп меняет слово, не показания.
    type Log = D::Log;

    fn step(self, event: Self::In) -> (Self, Self::Out, Self::Log) {
        let at = event.at();
        let (stepped, signals, notes) = self.inner.step(event);
        let stamped = signals
            .into_iter()
            .map(|said| Stamped { at, said })
            .collect();
        (Self { inner: stepped }, stamped, notes)
    }
}

impl<D: Clone> Clone for Timed<D> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

// Clone — руками: `derive` навесил бы лишние границы.
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

/// Слово, помнящее автора. Подпись на СЛОВЕ, не показаниях (те называют автора позицией в
/// произведении, а слово в общем потоке теряет отправителя): `and` складывает наблюдателей, и без
/// имени `Silence` и `Choked` (оба «байтов нет») неразличимы при разном лечении. Переименовано из
/// `Told` — одно слово называло два типа в крейте.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signed<S> {
    pub by: &'static str,
    pub signal: S,
}

/// Имя автора адресата не меняет: подпись говорит КТО, не КОМУ.
impl<S: crate::word::Word> crate::word::Word for Signed<S> {
    type Of = S::Of;
}

/// Приписать слову автора. См. [`Signed`].
pub struct By<D> {
    inner: D,
    by: &'static str,
}

impl<D, I, S> crate::mealy::Mealy for By<D>
where
    D: crate::mealy::Mealy<In = DetectorEvent<I>, Out = SmallVec<[S; 2]>>,
    S: crate::word::Word,
{
    type In = DetectorEvent<I>;
    type Out = SmallVec<[Signed<S>; 2]>;
    /// Подпись меняет слово, не показания.
    type Log = D::Log;

    fn step(self, event: Self::In) -> (Self, Self::Out, Self::Log) {
        let Self { inner, by } = self;
        let (stepped, signals, notes) = inner.step(event);
        let signed = signals
            .into_iter()
            .map(|signal| Signed { by, signal })
            .collect();
        (Self { inner: stepped, by }, signed, notes)
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

/// Звено с снятыми показаниями. Забывание показаний есть функтор (тождественный на объектах и
/// словах): показания не читаются никем, снять их — не изменить решения. Читаемое показание сделало
/// бы комбинатор ложью — его существование есть проверка закона.
pub struct Muted<D> {
    inner: D,
}

impl<D> Muted<D> {
    pub(crate) fn new(inner: D) -> Self {
        Self { inner }
    }
}

impl<D: crate::mealy::Mealy> crate::mealy::Mealy for Muted<D> {
    type In = D::In;
    type Out = D::Out;
    type Log = ();

    fn step(self, input: Self::In) -> (Self, Self::Out, ()) {
        let (stepped, said, _) = self.inner.step(input);
        (Self { inner: stepped }, said, ())
    }
}
