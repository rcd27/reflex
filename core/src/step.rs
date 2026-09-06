//! ШАГ — морфизм категории стадий на носителе ЗНАЧЕНИЯ (#326).
//!
//! # Что этим лечилось
//!
//! Категория стадий (`core/src/category.rs`, снесена 06.09.2026) СТРОИЛАСЬ НАД ПОТОКОМ: её
//! морфизмы были `self.inner.map(f)`, то есть жили в категории потоков, а стадия оставалась
//! фантомным ярлыком поверх чужой алгебры. Второй носитель — «пакет вошёл, вердикт вышел» — в
//! такую конструкцию не влезал: места для носителя в ней не было вовсе.
//!
//! Оплачено попыткой собрать вход NFQUEUE. `queue.verdict(msg)` требует владения ТЕМ САМЫМ
//! сообщением, а тогдашний вход в цепочку (`from_source`) заимствовал бэкенд на всё время потока,
//! тогда как выход (`inject_into`) брал его по значению: для одной очереди цепочка не собиралась
//! физически. У `AfPacketBackend` того же конфликта нет — там вердикта никто не ждёт, наблюдение и
//! вбрасывание независимы. То есть пара `Source`/`Sink` верна для «наблюдай и вбрасывай» и
//! структурно неверна для «возьми и ОТВЕТЬ».
//!
//! # Почему машина Мили, а не функция
//!
//! Ответ зависит не только от входа, но и от того, что было раньше: имя цели помнится с
//! рукопожатия, окно считает байты, таблица потоков стареет. Чистой функцией это не выражается, а
//! `FnMut` прячет состояние в замыкании — то есть делает его невидимым для типа и неперемещаемым
//! между вызовами.
//!
//! # Форма шага ВЗЯТА У СУЩЕСТВУЮЩИХ, а не изобретена
//!
//! `Detector::step(self, event) -> (Self, SmallVec<[Signal; 2]>)` была машиной Мили, уже написанной
//! в этой репе (снесена 06.09.2026 вместе с трейтом — задача 3 плана `absorbing-the-detector`;
//! вторая форма — `FlowTable`, `core/src/flow_table.rs:22`, та же машина по ключу, но через
//! `&mut self`, а не по значению, и она жива; `Reactor`, третья такая форма, снесена 06.09.2026
//! вместе с диалектом). Заведи мы здесь `&mut self`, форм стало бы три вместо двух; сведение их в
//! одну — предмет отдельного среза, и оно возможно ровно потому, что форма одна.

/// МОРФИЗМ КАТЕГОРИИ СТАДИЙ: из `From` в `To`, с памятью о пройденном.
///
/// Состояние возвращается ЗНАЧЕНИЕМ, а не правится по `&mut`: цепочка шагов есть значение, её
/// можно скопировать, отложить и прогнать заново — свойство, на котором стоят детерминированные
/// тесты домена.
pub trait Step: Sized {
    /// Стадия-источник.
    type From;
    /// Стадия-приёмник.
    type To;

    /// Один шаг: вход → выход, и НОВОЕ состояние машины.
    fn step(self, input: Self::From) -> (Self, Self::To);
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

    /// ВОЗВРАЩАЕТСЯ НОВАЯ ПАРА МАШИН, а не пересобранная из начальных. Забудь композиция
    /// состояние второго звена — оно обнулялось бы на каждом входе, и цепочка выглядела бы
    /// исправной ровно до второго вызова.
    fn step(self, input: A::From) -> (Self, B::To) {
        let (first, middle) = self.0.step(input);
        let (second, out) = self.1.step(middle);
        (Then(first, second), out)
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

impl<T> Step for Id<T> {
    type From = T;
    type To = T;

    fn step(self, input: T) -> (Self, T) {
        (self, input)
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
    /// # ПОПРАВКА 05.09.2026: стена — КОНКУРЕНТНОСТЬ, а не время
    ///
    /// Прежняя редакция числила в невыразимых и `debounce` с `with_latest_from`, называя их
    /// «операторами времени и конкурентности» одним списком. Два рода смешались, а держат они
    /// разные стены.
    ///
    /// Операторы ВРЕМЕНИ стали выразимы, как только время сделалось буквой входного алфавита
    /// ([`crate::interleave`]): [`crate::debounce::Debounce`] есть чистая функция
    /// `(состояние, событие) → состояние`, ни часов, ни рантайма ей не нужно. Стена осталась
    /// ровно там, где параллельная работа, — и это утверждение уже, а потому вернее.
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
    fn and<B, I, S>(self, other: B) -> crate::detector::Both<Self, B>
    where
        Self: Step<From = crate::detector::DetectorEvent<I>, To = smallvec::SmallVec<[S; 2]>>,
        B: Step<From = Self::From, To = Self::To>,
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
    type Item = K::To;

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
                    let (next, out) = machine.step(input);
                    *this.machine = Some(next);
                    std::task::Poll::Ready(Some(out))
                }
            },
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}
