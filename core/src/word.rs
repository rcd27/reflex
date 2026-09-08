//! Слово и его адрес — база расслоения. Канон §4–5.
//!
//! Слово адресовано области и потребляется соседом; показание не адресовано и копится. Различает
//! их адрес, а не наклонение. Из области берётся срок, из срока — отложимость: адрес есть проекция
//! слова в базу расслоения.

/// База расслоения — адресат слова. Канон §4. Пуста: всё, что о базе знает фундамент, — терпит ли
/// она ожидание ([`CanDefer`]).
pub trait Base {}

/// Слово — значение с проекцией `Of` в базу.
pub trait Word {
    /// Кому сказано.
    type Of: Base;
}

/// База, решение о которой можно отложить. Маркер, не градация: запрет один — ждать нельзя там, где
/// нельзя физически.
pub trait CanDefer: Base {}

/// Пакет в руках ядра. Ждать нельзя: очередь держит его до ответа.
pub struct Packet;
/// Разговор. Живёт до своего конца, ожидание терпит.
pub struct Conversation;
/// Цель. Живёт до смены плана; откладывать можно свободно.
pub struct Target;

/// Терминальный объект `1` — адресат пустого слова. Имя приватно намеренно: `Of = Nobody` снаружи
/// не написать, а обход через `Of = <() as Word>::Of` виден на ревью и ловится грепом. Резидуум
/// (`Told<()>`, `Option<()>`) законен — адрес «никому» получен структурным законом.
mod nobody {
    pub struct Nobody;
}

pub(crate) use nobody::Nobody;

impl Base for Packet {}
impl Base for Conversation {}
impl Base for Target {}
impl Base for Nobody {}

/// Охват `⊆`: `Packet ⊂ Conversation ⊂ Target`. Канон §5. Порядок объявлен, не выведен;
/// транзитивность (`Packet: Within<Target>`) — рукой, ибо спуск через уровень существует в бою.
pub trait Within<Wider: Base>: Base {}

impl Within<Conversation> for Packet {}
impl Within<Target> for Conversation {}
impl Within<Target> for Packet {}

/// Спуск по расслоению: слово широкой области, сказанное в узкой, вниз по охвату
/// (`Into::Of: Within<Self::Of>`). Канон §5. Слово пакета словом цели не станет. Кто из спущенных
/// слов победит — не здесь: ноль произведения (§5) — прекращение, а не охват.
///
/// ```
/// use reflex_core::word::{Conversation, Descends, Packet, Word};
/// struct Order;
/// impl Word for Order { type Of = Conversation; }
/// struct Verdict;
/// impl Word for Verdict { type Of = Packet; }
/// // Разговор → пакету: вниз по охвату.
/// impl Descends<Verdict> for Order {
///     fn descends(self) -> Verdict { Verdict }
/// }
/// ```
///
/// ```compile_fail
/// use reflex_core::word::{Conversation, Descends, Packet, Word};
/// struct Order;
/// impl Word for Order { type Of = Conversation; }
/// struct Verdict;
/// impl Word for Verdict { type Of = Packet; }
/// // Пакет → разговору: охвата в эту сторону нет.
/// impl Descends<Order> for Verdict {
///     fn descends(self) -> Order { Order }
/// }
/// ```
pub trait Descends<Into: Word>: Word
where
    Into::Of: Within<Self::Of>,
{
    fn descends(self) -> Into;
}

impl CanDefer for Conversation {}
impl CanDefer for Target {}
/// Сказать нечего — держать некому: ждать можно сколько угодно.
impl CanDefer for Nobody {}

/// Терминал `() → Nobody`. Область выразима (по ней ставятся границы), но имя `Nobody` снаружи
/// недоступно.
///
/// ```
/// use reflex_core::word::Word;
/// fn to_nobody<W: Word<Of = <() as Word>::Of>>() {}
/// to_nobody::<()>();
/// to_nobody::<((), ())>();
/// ```
///
/// ```compile_fail
/// use reflex_core::word::Word;
/// struct Tally(u32);
/// // Имя области приватно.
/// impl Word for Tally { type Of = reflex_core::word::Nobody; }
/// ```
impl Word for () {
    type Of = Nobody;
}

/// Пачка слов адресована туда же, куда каждое.
impl<A: smallvec::Array> Word for smallvec::SmallVec<A>
where
    A::Item: Word,
{
    type Of = <A::Item as Word>::Of;
}

/// Два слова одной области — слово той же области (полурешётка сведения, §5). Разным областям
/// слиться нельзя.
///
/// ```
/// use reflex_core::word::{Conversation, Word};
/// struct Sever;
/// impl Word for Sever { type Of = Conversation; }
/// struct Ordered;
/// impl Word for Ordered { type Of = Conversation; }
/// fn takes<W: Word>() {}
/// takes::<(Sever, Ordered)>();
/// ```
///
/// ```compile_fail
/// use reflex_core::word::{Conversation, Packet, Word};
/// struct Sever;
/// impl Word for Sever { type Of = Conversation; }
/// struct Verdict;
/// impl Word for Verdict { type Of = Packet; }
/// fn takes<W: Word>() {}
/// // Разным областям слиться нельзя.
/// takes::<(Sever, Verdict)>();
/// ```
///
/// `Instant` слова не образует: штампованное слово названо [`crate::detector::Stamped`], не парой с
/// моментом. Регрессия `impl<S: Word> Word for (Instant, S)` ловится здесь — пересеклась бы с
/// законом пары.
///
/// ```compile_fail
/// fn takes<W: reflex_core::word::Word>() {}
/// takes::<(std::time::Instant, ())>();
/// ```
impl<A: Word, B: Word<Of = A::Of>> Word for (A, B) {
    type Of = A::Of;
}

/// Молчание адресовано туда же, куда сказанное: `Option<W>` над областью `W`.
impl<W: Word> Word for Option<W> {
    type Of = W::Of;
}

/// Ожидание — только над `CanDefer`-базой. Канон §5. Всякий оператор ожидания требует этот баунд,
/// и ожидание на пакетной цепочке не соберётся.
///
/// ```
/// use reflex_core::word::{may_wait, Conversation, Word};
/// struct Sever;
/// impl Word for Sever { type Of = Conversation; }
/// may_wait::<Sever>();
/// ```
///
/// ```compile_fail
/// use reflex_core::word::{may_wait, Packet, Word};
/// struct Verdict;
/// impl Word for Verdict { type Of = Packet; }
/// // Ядро держит пакет: ожидание невыразимо.
/// may_wait::<Verdict>();
/// ```
pub fn may_wait<W: Word>()
where
    W::Of: CanDefer,
{
}
