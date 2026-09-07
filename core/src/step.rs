//! ШАГ — морфизм категории стадий на носителе ЗНАЧЕНИЯ (#326).
//!
//! # Что этим лечится
//!
//! Пара `Source`/`Sink` годится для «наблюдай и вбрасывай» — независимых входа и выхода — и
//! структурно не годится для «возьми и ОТВЕТЬ»: `queue.verdict(msg)` требует владения ТЕМ САМЫМ
//! сообщением, а вход и выход, заимствующие бэкенд порознь, для одной очереди не соберутся
//! физически. Носителю «пакет вошёл, вердикт вышел» нужна собственная категория, а не встраивание
//! в категорию потоков поверх `Source`/`Sink`.
//!
//! # Почему машина Мили, а не функция
//!
//! Ответ зависит не только от входа, но и от того, что было раньше: имя цели помнится с
//! рукопожатия, окно считает байты, таблица потоков стареет. Чистой функцией это не выражается, а
//! `FnMut` прячет состояние в замыкании — то есть делает его невидимым для типа и неперемещаемым
//! между вызовами.

/// МОРФИЗМ КАТЕГОРИИ СТАДИЙ: из `From` в `To`, с памятью о пройденном.
///
/// Состояние возвращается ЗНАЧЕНИЕМ, а не правится по `&mut`: цепочка шагов есть значение, её
/// можно скопировать, отложить и прогнать заново — свойство, на котором стоят детерминированные
/// тесты домена.
pub trait Step: Sized {
    /// Стадия-источник.
    type From;
    /// СЛОВО: адресовано области и потребляется соседом.
    ///
    /// Баунд несущий: значение без объявленного адреса в позицию слова не встаёт. Без него закон
    /// остаётся уговором, а нарушают уговор первыми тесты — им адресат кажется неважным.
    ///
    /// ```
    /// use reflex_core::step::Step;
    /// use reflex_core::word::{Region, Word};
    /// struct Bench;
    /// impl Region for Bench {}
    /// struct Beat(u8);
    /// impl Word for Beat {
    ///     type Of = Bench;
    /// }
    /// struct Echo;
    /// impl Step for Echo {
    ///     type From = Beat;
    ///     type To = Beat;
    ///     type Notes = ();
    ///     fn step(self, input: Beat) -> (Self, Beat, ()) {
    ///         (self, input, ())
    ///     }
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// use reflex_core::step::Step;
    /// struct Naked;
    /// // Число ничего никому не говорит: адреса у него нет, и словом оно быть не может.
    /// impl Step for Naked {
    ///     type From = u8;
    ///     type To = u8;
    ///     type Notes = ();
    ///     fn step(self, input: u8) -> (Self, u8, ()) {
    ///         (self, input, ())
    ///     }
    /// }
    /// ```
    type To: crate::word::Word;

    /// ПОКАЗАНИЯ: не адресованы никому и не читаются никем — копятся вбок, а не соседу по стрелке.
    ///
    /// Тройкой, а не парой в `To`: будь пара одним типом, композиция `B: Step<From = A::To>`
    /// заставила бы соседа ЕСТЬ чужие показания — читать то, что было сказано не ему. Ход вбок
    /// обязан быть невыразим иначе, а не оговорён прозой у места вызова.
    type Notes;

    /// Один шаг: вход → слово и показания, и НОВОЕ состояние машины.
    fn step(self, input: Self::From) -> (Self, Self::To, Self::Notes);
}

/// ПОСЛЕДОВАТЕЛЬНОЕ СОЕДИНЕНИЕ ДВУХ ШАГОВ — композиция категории.
///
/// Стыковка проверяется КОМПИЛЯТОРОМ (`B: Step<From = A::To>`): соединить шаг, дающий сигналы, с
/// шагом, ждущим пакеты, нельзя — и это то же самое обещание, что даёт стадийная типизация
/// потоковой цепочки, только на другом носителе.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Then<A, B>(pub A, pub B);

impl<A, B> Step for Then<A, B>
where
    A: Step,
    B: Step<From = A::To>,
{
    type From = A::From;
    type To = B::To;
    /// ПРОИЗВЕДЕНИЕ, А НЕ ОБЩИЙ СЛОВАРЬ: два звена не обязаны говорить на одном языке, чтобы их
    /// показания сложились, а позиция в типе называет автора вернее всякой метки.
    type Notes = (A::Notes, B::Notes);

    /// ВОЗВРАЩАЕТСЯ НОВАЯ ПАРА МАШИН, а не пересобранная из начальных. Забудь композиция
    /// состояние второго звена — оно обнулялось бы на каждом входе, и цепочка выглядела бы
    /// исправной ровно до второго вызова.
    fn step(self, input: A::From) -> (Self, B::To, (A::Notes, B::Notes)) {
        let (first, middle, noted) = self.0.step(input);
        let (second, out, also_noted) = self.1.step(middle);
        (Then(first, second), out, (noted, also_noted))
    }
}

/// ТОЖДЕСТВЕННЫЙ МОРФИЗМ `id_X : X → X` — второй закон категории (vision 3 §6.2).
///
/// # Почему он существует, если ничего не делает
///
/// Категория определяется объектами, морфизмами И тождеством. Без него композиция есть
/// полугруппа, а не категория, и второй закон предъявить не на чем. Здесь он к тому же не
/// украшение: необязательное звено цепочки, выключенное настройкой, обязано выражаться В ТОЙ ЖЕ
/// алгебре, а не особым случаем у вызывающего.
///
/// Состояния нет по построению, и это ровно то, что делает его нейтральным: звено с памятью
/// нейтральным быть не может, потому что меняет то, что видят соседи.
pub struct Id<T>(std::marker::PhantomData<fn(T) -> T>);

impl<T> Id<T> {
    pub fn new() -> Self {
        Id(std::marker::PhantomData)
    }
}

impl<T> Default for Id<T> {
    fn default() -> Self {
        Self::new()
    }
}

// БАУНД НА РЕАЛИЗАЦИИ, А НЕ НА СТРУКТУРЕ: `PhantomData` адреса не требует, и требовать его там
// значило бы навесить ограничение, ложное по построению.
impl<T: crate::word::Word> Step for Id<T> {
    type From = T;
    type To = T;
    /// Тождество обязано быть нейтральным и в показаниях: отмечающее звено соседям не безразлично.
    type Notes = ();

    fn step(self, input: T) -> (Self, T, ()) {
        (self, input, ())
    }
}

// ТОЖДЕСТВО ОБЯЗАНО БЫТЬ НЕЙТРАЛЬНЫМ И В ТИПАХ, А НЕ ТОЛЬКО В ВЫХОДАХ (правка по ревью).
//
// `f` было `Copy + Clone + Debug + Eq`, а `id ∘ f` — ничем: производных у `Id` не было вовсе, и
// `Then<Id<T>, F>` терял их все. Тождество, теряющее свойства соседа, тождеством не является, и
// закон этого не видел: он сравнивает ВЫХОДЫ, а потеря случалась в типах.
//
// РУКАМИ, А НЕ `derive`: производный код навесил бы `impl<T: Clone> Clone for Id<T>` — баунд,
// ложный по построению, ибо `T` здесь не хранится. Ограничения нет, и в подписи его быть не должно.
impl<T> Clone for Id<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Id<T> {}

impl<T> PartialEq for Id<T> {
    /// Все тождества равны: различать их нечем и незачем — состояния у них нет.
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl<T> Eq for Id<T> {}

impl<T> std::fmt::Debug for Id<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Id")
    }
}

/// РЕЧЬ ЦЕПОЧКИ: `a.then(b)` вместо `Then(a, b)`.
pub trait StepExt: Step + Sized {
    /// Соединить с последующим шагом.
    fn then<B: Step<From = Self::To>>(self, next: B) -> Then<Self, B> {
        Then(self, next)
    }

    /// ФУНКТОР ПОДНЯТИЯ: тот же морфизм, применённый к потоку.
    ///
    /// Функтор идёт ТОЛЬКО ВВЕРХ, и это несущая стена, а не пробел. Обратного пути нет:
    /// `switch_map` и `merge_map_bounded` запускают работу, идущую ПАРАЛЛЕЛЬНО потоку, а у шага
    /// нет ни второй нити, ни того, кому отдать управление. Оттого расследование невозможно
    /// поставить в горячий путь — не потому, что сигнатура не берёт `Future`, а потому, что
    /// оператора, которым расследование выражается, здесь нет вовсе.
    ///
    /// Стена — ИМЕННО КОНКУРЕНТНОСТЬ, а не время: операторы времени, такие как
    /// [`crate::debounce::Debounce`], стену не образуют, потому что время — буква входного
    /// алфавита ([`crate::interleave`]), и такой оператор остаётся чистой функцией
    /// `(состояние, событие) → состояние`, ни часов, ни рантайма ей не нужно.
    fn over<S>(self, source: S) -> Over<S, Self>
    where
        S: futures::Stream<Item = Self::From>,
    {
        Over {
            source,
            machine: Some(self),
        }
    }

    /// Наблюдать обоими. См. [`crate::detector::Both`].
    ///
    /// Не конвейер: событие идёт в оба звена, а не из одного в другое. Имя `and` — речь цепочки,
    /// а не логическое «и»: в логике `A AND B` значит «сработали оба», здесь — «слушают оба».
    ///
    /// Баунд требует общую ОБЛАСТЬ слов, а не общий ТИП: два прибора складываются, даже говоря на
    /// разных словарях, пока оба адресованы туда же.
    fn and<B, I>(self, other: B) -> crate::detector::Both<Self, B>
    where
        Self: Step<From = crate::detector::DetectorEvent<I>>,
        B: Step<From = Self::From>,
        B::To: crate::word::Word<Of = <Self::To as crate::word::Word>::Of>,
        I: Clone,
    {
        crate::detector::Both(self, other)
    }

    /// Переименовать сигнал. См. [`crate::detector::RMap`].
    fn rmap<F, I, S, Renamed>(self, f: F) -> crate::detector::RMap<Self, F>
    where
        Self: Step<From = crate::detector::DetectorEvent<I>, To = smallvec::SmallVec<[S; 2]>>,
        F: Fn(S) -> Renamed,
    {
        crate::detector::RMap::new(self, f)
    }

    /// Сузить вход. См. [`crate::detector::LMap`].
    fn lmap<Wide, F, I, S>(self, f: F) -> crate::detector::LMap<Self, F, Wide>
    where
        Self: Step<From = crate::detector::DetectorEvent<I>, To = smallvec::SmallVec<[S; 2]>>,
        F: Fn(&Wide) -> Option<I>,
    {
        crate::detector::LMap::new(self, f)
    }

    /// Одеть сигнал в контекст наблюдения. См. [`crate::detector::Contextual`].
    fn contextual<Ctx, Pick, Dress, Dressed, I, S>(
        self,
        pick: Pick,
        dress: Dress,
    ) -> crate::detector::Contextual<Self, Ctx, Pick, Dress>
    where
        Self: Step<From = crate::detector::DetectorEvent<I>, To = smallvec::SmallVec<[S; 2]>>,
        Pick: Fn(&I) -> Ctx,
        Dress: Fn(Option<&Ctx>, S) -> Option<Dressed>,
    {
        crate::detector::Contextual::new(self, pick, dress)
    }

    /// Вынести наружу момент, в который звено высказалось. См. [`crate::detector::Timed`].
    fn timed<I, S>(self) -> crate::detector::Timed<Self>
    where
        Self: Step<From = crate::detector::DetectorEvent<I>, To = smallvec::SmallVec<[S; 2]>>,
    {
        crate::detector::Timed::new(self)
    }

    /// Приписать показаниям автора. См. [`crate::detector::Told`].
    ///
    /// `and` складывает наблюдателей в один поток, и без имени два прибора с общим словарём
    /// (`Silence` и `Choked` оба говорят «байтов нет») дают неразличимые показания при разном
    /// лечении. Имя берётся из паспорта прибора, а не пишется у места сборки.
    fn by<I, S>(self, by: &'static str) -> crate::detector::By<Self>
    where
        Self: Step<From = crate::detector::DetectorEvent<I>, To = smallvec::SmallVec<[S; 2]>>,
    {
        crate::detector::By::new(self, by)
    }

    /// Говорить только о смене показания. См. [`crate::detector::Changes`].
    fn changes<I, S>(self) -> crate::detector::Changes<Self, S>
    where
        Self: Step<From = crate::detector::DetectorEvent<I>, To = smallvec::SmallVec<[S; 2]>>,
        S: PartialEq + Clone,
    {
        crate::detector::Changes::new(self)
    }
}

impl<S: Step> StepExt for S {}

pin_project_lite::pin_project! {
    /// ПОДНЯТЫЙ МОРФИЗМ: поток входов → поток выходов, одна машина на весь поток.
    ///
    /// Машина хранится изымаемой (`Option`), потому что [`Step::step`] берёт состояние ПО
    /// ЗНАЧЕНИЮ. Так поднятие не требует от морфизма `Clone` — а требование было бы ложным
    /// ограничением: таблица потоков клонируется дорого, и цена платилась бы на каждом пакете
    /// ради удобства этих десяти строк.
    pub struct Over<S, K> {
        #[pin]
        source: S,
        machine: Option<K>,
    }
}

impl<S, K> futures::Stream for Over<S, K>
where
    S: futures::Stream<Item = K::From>,
    K: Step,
{
    /// ПАРА НАРУЖУ: за границей цепочки показания читает лента, отчёт, расследование.
    type Item = (K::To, K::Notes);

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.project();

        match this.source.poll_next(cx) {
            std::task::Poll::Ready(Some(input)) => match this.machine.take() {
                // Машины нет — значит прошлый шаг её не вернул. Наблюдаемо это лишь при панике
                // между изъятием и возвратом; поток честно кончается, а не выдаёт чужой ответ.
                None => std::task::Poll::Ready(None),
                Some(machine) => {
                    let (next, out, notes) = machine.step(input);
                    *this.machine = Some(next);
                    std::task::Poll::Ready(Some((out, notes)))
                }
            },
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}
