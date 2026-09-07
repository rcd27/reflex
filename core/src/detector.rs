//! Алфавит входа детектора ([`DetectorEvent`]) и комбинаторы, собирающие детекторы в цепочки на
//! носителе [`crate::step::Step`]: каждый прибор — машина Мили `(State, Event) → (State,
//! Signals)`, реализующая `Step` напрямую, без промежуточного имени.
//!
//! `DetectorEvent` — буква входного алфавита, а не диалект машины: время приходит в событии, а не
//! берётся прибором самостоятельно, чтобы наблюдение оставалось детерминированным.

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
    /// УЗЕЛ СЕТКИ — единственная буква, говорящая, что ничего не произошло.
    ///
    /// Несёт и номер, и момент. Номер тот же при переигровке; момент сравним с чужими часами.
    ///
    /// # ДЫРА, КОТОРУЮ ТЕРПЯТ: ТИК СОБИРАЕТСЯ И МИМО СЕТКИ
    ///
    /// Поля открыты, значит букву можно сложить с номером, взятым откуда угодно. Терпится это
    /// ради переноса через шов: событие, пришедшее из чужого края, бывает нужно пересобрать, и
    /// запрет постройки запретил бы перенос. Цена названа прямо: номер, не привязанный к сетке,
    /// НЕСРАВНИМ НИ С ЧЕМ — ни с номером другого источника, ни с собственным при переигровке;
    /// такой тик говорит «время шло», но не говорит, сколько именно. Поэтому однострочника,
    /// штампующего тик без сетки, здесь нет: подделка не должна быть удобнее правды.
    Tick { node: u64, at: Instant },
    /// ПРИШЛО, НО РАЗОБРАТЬ НЕ СМОГЛИ.
    ///
    /// «Не знаю» на стороне входа. Без этой буквы наблюдение выразить нечем, и считать его
    /// приходится до того, как родится событие, — то есть в краю, вторым разбором.
    Opaque {
        why: crate::parse::Unread,
        at: Instant,
    },
}

impl<T> DetectorEvent<T> {
    /// МОНОТОННЫЙ момент наблюдения — для интервалов, не для показа.
    ///
    /// `Instant` в календарь не переводится: строке ленты нужен `SystemTime`, и берётся он у
    /// источника (`pcap::Frame::wall`, `SystemTime::now()` на живой очереди).
    pub fn at(&self) -> Instant {
        match self {
            DetectorEvent::Packet { at, .. } => *at,
            DetectorEvent::Tick { at, .. } => *at,
            DetectorEvent::Opaque { at, .. } => *at,
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
}

/// БУКВА ВХОДА АДРЕСОВАНА ТУДА ЖЕ, КУДА СТАДИЯ, НАД КОТОРОЙ АЛФАВИТ ПОСТРОЕН.
///
/// Адрес берётся у наблюдения — и он один на весь алфавит, включая буквы, наблюдения В СЕБЕ НЕ
/// ДЕРЖАЩИЕ: «время шло» и «пришло, разобрать не смогли» говорят о той же стадии, что и разобранный
/// пакет, и потому едут тому же адресату.
///
/// Нужно затем, что тождество на стадии есть морфизм этой категории: выключенное настройкой звено
/// обязано выражаться в той же алгебре, а его выход — та же буква, что и вход.
impl<T: crate::word::Word> crate::word::Word for DetectorEvent<T> {
    type Of = T::Of;
}

/// ЧТО КРАЙ СНЯЛ С ПРОВОДА, ДО ШВА: разобранное наблюдение либо причина, по которой его нет.
///
/// # Почему не `Result<T, Unread>`
///
/// `Result` называет непонятое ОШИБКОЙ — тем, что распространяется через `?` и молчит, пока не
/// обработано. Здесь предмет ровно обратный: «не знаю» есть ЗАСЕЛЁННАЯ КЛЕТКА алфавита, равная
/// разобранному наблюдению по праву быть увиденной, а не отказ, дожидающийся обработки.
///
/// # Зачем этот тип живому шву
///
/// Шов ([`crate::interleave::Interleave`]) сшивает поток наблюдений с сеткой узлов. Пока у него
/// была дверь только для разобранного (`saw`), непонятое войти не могло вовсе — и на потоке из
/// одних неразобранных пакетов сетка не двигалась, будто трафика не было совсем. `Sensed<T>` даёт
/// источнику способ сказать шву, какую из двух дверей открыть.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sensed<T> {
    /// Разбор состоялся.
    Seen(T),
    /// Разбор не состоялся — причина названа отдельным закрытым перечислением.
    Unread(crate::parse::Unread),
}

/// Два НЕЗАВИСИМЫХ наблюдателя одного потока — не конвейер: событие идёт в оба.
///
/// Имя `And` было бы ложью: в логике `A AND B` значит «сработали оба», здесь — «слушают оба».
/// Метод остаётся `.and(…)` как речь цепочки.
///
/// ЦЕНА: событие клонируется по разу на детектор; цепочка из N звеньев клонирует N раз.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Both<A, B>(pub A, pub B);

impl<A, B, I> crate::step::Step for Both<A, B>
where
    A: crate::step::Step<From = DetectorEvent<I>>,
    B: crate::step::Step<From = DetectorEvent<I>>,
    B::To: crate::word::Word<Of = <A::To as crate::word::Word>::Of>,
    I: Clone,
{
    type From = DetectorEvent<I>;
    /// СЛОВА ОДНОЙ ОБЛАСТИ, СЛОЖЕННЫЕ ПРОИЗВЕДЕНИЕМ.
    ///
    /// Разным областям слиться нельзя: их слова едут в разные места, и склейка была бы ложью о
    /// том, кому сказано. Позиция в типе называет автора вернее всякой метки: левое слово пришло
    /// от левого звена, и перепутать их нечем — даже когда оба говорят на одном словаре.
    type To = (A::To, B::To);
    /// ПРОИЗВЕДЕНИЕ, КАК И У [`crate::step::Then`]: два прибора не обязаны говорить на одном
    /// языке показаний, чтобы их показания сложились, а позиция в типе называет автора.
    type Notes = (A::Notes, B::Notes);

    fn step(self, event: Self::From) -> (Self, Self::To, Self::Notes) {
        let (first, said, noted) = self.0.step(event.clone());
        let (second, also, also_noted) = self.1.step(event);
        (Both(first, second), (said, also), (noted, also_noted))
    }
}

/// Переименование сигнала. Законы функтора (тождество и композиция) проверены отдельными тестами.
pub struct RMap<D, F> {
    inner: D,
    f: F,
}

impl<D, F, I, S, Renamed> crate::step::Step for RMap<D, F>
where
    D: crate::step::Step<From = DetectorEvent<I>, To = SmallVec<[S; 2]>>,
    F: Fn(S) -> Renamed,
    // ПЕРЕИМЕНОВАНИЕ НЕ ОСВОБОЖДАЕТ ОТ АДРЕСА: новое имя обязано сказать, кому оно сказано.
    Renamed: crate::word::Word,
{
    type From = DetectorEvent<I>;
    type To = SmallVec<[Renamed; 2]>;
    /// ПЕРЕИМЕНОВАНИЕ МЕНЯЕТ СЛОВО, НЕ ПОКАЗАНИЯ: комбинатор сужает слово и проносит показания
    /// насквозь, без изменений — добавь он от себя показание, он был бы звеном, а не комбинатором.
    type Notes = D::Notes;

    fn step(self, event: Self::From) -> (Self, Self::To, Self::Notes) {
        let Self { inner, f } = self;
        let (stepped, signals, notes) = inner.step(event);
        let renamed = signals.into_iter().map(&f).collect();
        (Self { inner: stepped, f }, renamed, notes)
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
    S: crate::word::Word,
{
    type From = DetectorEvent<Wide>;
    type To = SmallVec<[S; 2]>;
    /// `Option`, А НЕ ГОЛОЕ `D::Notes`: зафильтрованный вход не зовёт внутреннее звено, и
    /// `None` записывает ровно это — звено не шагало, показания не существует. Значение по
    /// умолчанию сказало бы другое: звено шагало и намерило пустоту, — а это разные факты,
    /// неотличимые для типа с единицей, но различные для мира, который эта пара описывает.
    type Notes = Option<D::Notes>;

    fn step(self, event: Self::From) -> (Self, Self::To, Self::Notes) {
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
            // НЕПОНЯТОЕ НЕ НЕСЁТ `Wide` — сужать нечего, сужение фильтрует значение, а не факт
            // о его отсутствии. Проходит к внутреннему звену как есть, тем же путём, что тик.
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
        }
    }
}

/// Переход вместо значения, НА КЛЮЧ: оператор потока
/// ([`crate::stream::DistinctUntilChangedStream`]) считает смену по всему потоку, и две цели,
/// чередуясь, прошли бы его насквозь.
///
/// Сравнение с ПОСЛЕДНИМ показанием, а не со всеми виденными: возврат к прежнему есть событие.
///
/// Тип показания `S` назван параметром структуры, а не взят проекцией: `Step` держит алфавит
/// целиком (`To = SmallVec<[S; 2]>`), а вынуть из него элемент нечем.
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
    // ОДЕТОЕ СЛОВО — тоже слово: контекст меняет наряд, а не адресата.
    Dressed: crate::word::Word,
{
    type From = DetectorEvent<I>;
    type To = SmallVec<[Dressed; 2]>;
    /// Наряд меняет слово, не показания: показания идут сквозь без изменений.
    type Notes = D::Notes;

    fn step(self, event: Self::From) -> (Self, Self::To, Self::Notes) {
        let Self {
            inner,
            pick,
            dress,
            context,
        } = self;
        // ДО шага: сигнал этого наблюдения одевается в него, а не в предыдущее.
        let context = match &event {
            DetectorEvent::Packet { input, .. } => Some(pick(input)),
            // НЕПОНЯТОЕ НЕ НЕСЁТ `I` — контексту неоткуда взяться, а прежний остаётся в силе,
            // как и на тике.
            DetectorEvent::Tick { .. } | DetectorEvent::Opaque { .. } => context,
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

impl<D, I, S> crate::step::Step for Changes<D, S>
where
    D: crate::step::Step<From = DetectorEvent<I>, To = SmallVec<[S; 2]>>,
    S: PartialEq + Clone + crate::word::Word,
{
    type From = DetectorEvent<I>;
    type To = SmallVec<[S; 2]>;
    /// Сравнение с прошлым меняет слово, не показания: показания идут сквозь без изменений.
    type Notes = D::Notes;

    fn step(self, event: Self::From) -> (Self, Self::To, Self::Notes) {
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

/// СЛОВО СО ШТАМПОМ МОМЕНТА, В КОТОРЫЙ ОНО СКАЗАНО.
///
/// # Почему структура, а не пара `(Instant, S)`
///
/// Паре с моментом требовался СВОЙ закон адресности рядом с общим законом пары. Сосуществовать
/// эти два закона могли ровно до тех пор, пока `Instant` не объявит области: в тот день общий
/// закон накрывает частный, компилятор объявляет пересечение и винит СТРОКУ ЧАСТНОГО ЗАКОНА — то
/// есть не ту, что взвела заряд. Падение выглядит беспричинным, а взводит его правка в чужом
/// файле.
///
/// Имя вместо пары снимает заряд целиком: у структуры свой закон, и общий закон пары ей не
/// конкурент. Та же идиома уже стоит в дереве у `Admits`, `Waited`, `Leg` и `Deadline`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamped<S> {
    /// Момент наблюдения, в который слово прозвучало.
    pub at: Instant,
    pub said: S,
}

/// ШТАМП МОМЕНТА АДРЕСАТА НЕ МЕНЯЕТ.
///
/// Момент наблюдения не говорит никому ничего — он говорит, КОГДА сказано. Слово со штампом
/// адресовано туда же, куда без него, и потому не требует, чтобы момент завёл себе адресата.
impl<S: crate::word::Word> crate::word::Word for Stamped<S> {
    type Of = S::Of;
}

/// Вынести наружу момент, в который детектор высказался.
///
/// Сигнал времени в себе не несёт, а подъём его не добавляет — он поднимает шаг, а не дописывает
/// к его слову. Значит момент обязан войти в слово ЗДЕСЬ, до подъёма, или он потерян навсегда.
///
/// Момент берётся у события, включая тик: прибор со своими часами замечает беду именно тиком.
pub struct Timed<D> {
    inner: D,
}

impl<D, I, S> crate::step::Step for Timed<D>
where
    D: crate::step::Step<From = DetectorEvent<I>, To = SmallVec<[S; 2]>>,
    S: crate::word::Word,
{
    type From = DetectorEvent<I>;
    type To = SmallVec<[Stamped<S>; 2]>;
    /// Штамп времени меняет слово, не показания: показания идут сквозь без изменений.
    type Notes = D::Notes;

    fn step(self, event: Self::From) -> (Self, Self::To, Self::Notes) {
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

/// ИМЯ АВТОРА АДРЕСАТА НЕ МЕНЯЕТ: подпись говорит, КТО сказал, а не КОМУ.
impl<S: crate::word::Word> crate::word::Word for Told<S> {
    type Of = S::Of;
}

/// Приписать показаниям автора. См. [`Told`].
pub struct By<D> {
    inner: D,
    by: &'static str,
}

impl<D, I, S> crate::step::Step for By<D>
where
    D: crate::step::Step<From = DetectorEvent<I>, To = SmallVec<[S; 2]>>,
    S: crate::word::Word,
{
    type From = DetectorEvent<I>;
    type To = SmallVec<[Told<S>; 2]>;
    /// Подпись автора меняет слово, не показания: показания идут сквозь без изменений.
    type Notes = D::Notes;

    fn step(self, event: Self::From) -> (Self, Self::To, Self::Notes) {
        let Self { inner, by } = self;
        let (stepped, signals, notes) = inner.step(event);
        let told = signals
            .into_iter()
            .map(|signal| Told { by, signal })
            .collect();
        (Self { inner: stepped, by }, told, notes)
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

/// ЗВЕНО, ЧЬИ ПОКАЗАНИЯ СНЯТЫ.
///
/// Забывание показаний есть ФУНКТОР: тождественный на объектах и на словах. Оттого он и выразим —
/// показания не читаются никем, и снять их значит не изменить ни одного решения. Читаемое
/// показание сделало бы этот комбинатор ложью, и потому его существование есть проверка закона, а
/// не удобство.
pub struct Muted<D> {
    inner: D,
}

impl<D> Muted<D> {
    pub(crate) fn new(inner: D) -> Self {
        Self { inner }
    }
}

impl<D: crate::step::Step> crate::step::Step for Muted<D> {
    type From = D::From;
    type To = D::To;
    type Notes = ();

    fn step(self, input: Self::From) -> (Self, Self::To, ()) {
        let (stepped, said, _) = self.inner.step(input);
        (Self { inner: stepped }, said, ())
    }
}
