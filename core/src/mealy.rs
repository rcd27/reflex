//! Машина Мили как значение — носитель категории. Канон §1.
//!
//! Коалгебра эндофунктора `S ↦ (Out × S)^In`: состояние входит и выходит значением, потому цепочку
//! можно скопировать, отложить и прогнать заново (канон §10).

/// Коалгебра машины Мили: `S × In → S × Out`. Канон §1.
pub trait Mealy: Sized {
    /// Входной алфавит.
    type In;
    /// Слово — выход, адресованный области (`Word`). Канон §5.
    ///
    /// ```
    /// use reflex_core::mealy::Mealy;
    /// use reflex_core::word::{Base, Word};
    /// struct Bench;
    /// impl Base for Bench { type Fibre = (); }
    /// struct Beat(u8);
    /// impl Word for Beat { type Of = Bench; }
    /// struct Echo;
    /// impl Mealy for Echo {
    ///     type In = Beat;
    ///     type Out = Beat;
    ///     type Log = ();
    ///     fn step(self, input: Beat) -> (Self, Beat, ()) { (self, input, ()) }
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// use reflex_core::mealy::Mealy;
    /// struct Naked;
    /// // Нет адреса — не слово: `u8` не `Word`.
    /// impl Mealy for Naked {
    ///     type In = u8;
    ///     type Out = u8;
    ///     type Log = ();
    ///     fn step(self, input: u8) -> (Self, u8, ()) { (self, input, ()) }
    /// }
    /// ```
    type Out: crate::word::Word;

    /// Показания — накопление вбок (Writer-log), не адресованное соседу. Отдельно от `Out`, иначе
    /// `B: Mealy<In = A::Out>` заставил бы соседа есть чужой лог.
    type Log;

    fn step(self, input: Self::In) -> (Self, Self::Out, Self::Log);
}

/// Композиция `∘`: `B∘A` определена при `A::Out = B::In`. Канон §3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Compose<A, B>(pub A, pub B);

impl<A, B> Mealy for Compose<A, B>
where
    A: Mealy,
    B: Mealy<In = A::Out>,
{
    type In = A::In;
    type Out = B::Out;
    /// Логи звеньев — произведением: позиция называет автора.
    type Log = (A::Log, B::Log);

    fn step(self, input: A::In) -> (Self, B::Out, (A::Log, B::Log)) {
        let (first, middle, noted) = self.0.step(input);
        let (second, out, also_noted) = self.1.step(middle);
        (Compose(first, second), out, (noted, also_noted))
    }
}

/// Тождество `id_X : X → X`. Канон §3. Без состояния — потому нейтрально; выключенное настройкой
/// звено выражается им, а не особым случаем у вызывающего.
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

impl<T: crate::word::Word> Mealy for Id<T> {
    type In = T;
    type Out = T;
    type Log = ();

    fn step(self, input: T) -> (Self, T, ()) {
        (self, input, ())
    }
}

// Производные — руками: `Id` не хранит `T`, потому `derive` навесил бы ложный баунд `T: Clone`.
// Тождество обязано нести свойства соседа сквозь `Compose<Id<T>, F>`, а закон сравнивает выходы,
// не типы — потерю derive он бы не увидел.
impl<T> Clone for Id<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Id<T> {}

impl<T> PartialEq for Id<T> {
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

/// Pairing `⟨f, !⟩`: общий вход через диагональ, левый говорит, правый — в терминал (`Out = ()`).
/// Канон §11. Отличие от [`crate::detector::Both`] (`⟨f, g⟩`, оба в одну область): правый молчит
/// по подписи. Цена — буква копируется (`A::In: Clone`).
pub struct Pair<A, B>(pub A, pub B);

impl<A, B> Mealy for Pair<A, B>
where
    A: Mealy,
    A::In: Clone,
    B: Mealy<In = A::In, Out = ()>,
{
    type In = A::In;
    type Out = A::Out;
    type Log = (A::Log, B::Log);

    fn step(self, input: Self::In) -> (Self, Self::Out, Self::Log) {
        let (first, said, noted) = self.0.step(input.clone());
        let (second, (), also_noted) = self.1.step(input);
        (Pair(first, second), said, (noted, also_noted))
    }
}

/// Речь цепочки: `a.then(b)` вместо `Compose(a, b)`.
pub trait MealyExt: Mealy + Sized {
    /// Композиция `∘`.
    fn then<B: Mealy<In = Self::Out>>(self, next: B) -> Compose<Self, B> {
        Compose(self, next)
    }

    /// Pairing `⟨f, !⟩`: молчащий наблюдатель рядом. См. [`Pair`].
    fn alongside<B>(self, other: B) -> Pair<Self, B>
    where
        Self::In: Clone,
        B: Mealy<In = Self::In, Out = ()>,
    {
        Pair(self, other)
    }

    /// Подъём в поток — единственная дверь носитель→драйвер. Канон §9.2. Функтор идёт только вверх:
    /// конкурентности у шага нет (нет второй нити), потому обратного оператора не существует.
    fn over<S>(self, source: S) -> Lift<S, Self>
    where
        S: futures::Stream<Item = Self::In>,
    {
        Lift {
            source,
            machine: Some(self),
        }
    }

    /// `⟨f, g⟩` над буквой прибора: слушают оба, слова складываются. См. [`crate::detector::Both`].
    fn and<B, I>(self, other: B) -> crate::detector::Both<Self, B>
    where
        Self: Mealy<In = crate::detector::DetectorEvent<I>>,
        B: Mealy<In = Self::In>,
        B::Out: crate::word::Word<Of = <Self::Out as crate::word::Word>::Of>,
        I: Clone,
    {
        crate::detector::Both(self, other)
    }

    /// Функтор переименования слова. См. [`crate::detector::RMap`].
    fn rmap<F, I, S, Renamed>(self, f: F) -> crate::detector::RMap<Self, F>
    where
        Self: Mealy<In = crate::detector::DetectorEvent<I>, Out = smallvec::SmallVec<[S; 2]>>,
        F: Fn(S) -> Renamed,
    {
        crate::detector::RMap::new(self, f)
    }

    /// Сужение входа. См. [`crate::detector::LMap`].
    fn lmap<Wide, F, I, S>(self, f: F) -> crate::detector::LMap<Self, F, Wide>
    where
        Self: Mealy<In = crate::detector::DetectorEvent<I>, Out = smallvec::SmallVec<[S; 2]>>,
        F: Fn(&Wide) -> Option<I>,
    {
        crate::detector::LMap::new(self, f)
    }

    /// Слово в контексте наблюдения. См. [`crate::detector::Contextual`].
    fn contextual<Ctx, Pick, Dress, Dressed, I, S>(
        self,
        pick: Pick,
        dress: Dress,
    ) -> crate::detector::Contextual<Self, Ctx, Pick, Dress>
    where
        Self: Mealy<In = crate::detector::DetectorEvent<I>, Out = smallvec::SmallVec<[S; 2]>>,
        Pick: Fn(&I) -> Ctx,
        Dress: Fn(Option<&Ctx>, S) -> Option<Dressed>,
    {
        crate::detector::Contextual::new(self, pick, dress)
    }

    /// Момент слова наружу. См. [`crate::detector::Timed`].
    fn timed<I, S>(self) -> crate::detector::Timed<Self>
    where
        Self: Mealy<In = crate::detector::DetectorEvent<I>, Out = smallvec::SmallVec<[S; 2]>>,
    {
        crate::detector::Timed::new(self)
    }

    /// Автор при слове. См. [`crate::detector::Signed`].
    fn by<I, S>(self, by: &'static str) -> crate::detector::By<Self>
    where
        Self: Mealy<In = crate::detector::DetectorEvent<I>, Out = smallvec::SmallVec<[S; 2]>>,
    {
        crate::detector::By::new(self, by)
    }

    /// Только смена слова, по ключу. См. [`crate::detector::Changes`].
    fn changes<I, S>(self) -> crate::detector::Changes<Self, S>
    where
        Self: Mealy<In = crate::detector::DetectorEvent<I>, Out = smallvec::SmallVec<[S; 2]>>,
        S: PartialEq + Clone,
    {
        crate::detector::Changes::new(self)
    }

    /// Снять показания. См. [`crate::detector::Muted`].
    fn mute(self) -> crate::detector::Muted<Self> {
        crate::detector::Muted::new(self)
    }
}

impl<S: Mealy> MealyExt for S {}

pin_project_lite::pin_project! {
    /// Образ подъёма `over`: поток входов → поток пар `(Out, Log)`, одна машина на поток.
    /// Машина изымаема (`Option`), ибо [`Mealy::step`] берёт состояние по значению — так подъём не
    /// требует `Clone` (таблица потоков клонируется дорого).
    pub struct Lift<S, K> {
        #[pin]
        source: S,
        machine: Option<K>,
    }
}

impl<S, K> futures::Stream for Lift<S, K>
where
    S: futures::Stream<Item = K::In>,
    K: Mealy,
{
    /// Пара `(Out, Log)` наружу, по одной на шаг, включая шаги без слова: подъём не разбирает слово,
    /// а выпускает ровно то, что шаг дал.
    type Item = (K::Out, K::Log);

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.project();

        match this.source.poll_next(cx) {
            std::task::Poll::Ready(Some(input)) => match this.machine.take() {
                // Машины нет — прошлый шаг её не вернул (панике между изъятием и возвратом): поток
                // честно кончается, а не выдаёт чужой ответ.
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
