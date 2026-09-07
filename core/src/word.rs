//! АДРЕСНОСТЬ: КОМУ СКАЗАНО.
//!
//! # Что отличает слово от показания
//!
//! Слово адресовано ОБЛАСТИ и потребляется соседом; показание не адресовано никому и не
//! потребляется никем — оно копится. Различает их адрес, а НЕ наклонение: суждение «этот разговор
//! в беде» ничего не велит, но говорит о разговоре, и потому у него есть область, срок и право
//! быть словом.
//!
//! # Зачем область типом
//!
//! Из области берётся срок, из срока — отложимость. Ядро держит пакет, пока цепочка не ответила;
//! значит ожидание на пакетной цепочке невыразимо, а не нежелательно. Живи область в списке трёх
//! слов, всякая новая область требовала бы правки фундамента — а строят на фундаменте другие.

/// ОБЛАСТЬ — то, чему адресуется слово.
///
/// Пустой трейт намеренно: область есть ИМЯ адресата, и всё, что о ней известно фундаменту, —
/// терпит ли она ожидание ([`CanDefer`]).
pub trait Region {}

/// СЛОВО — значение, объявившее свою область.
pub trait Word {
    /// Кому это сказано.
    type Of: Region;
}

/// ОБЛАСТЬ, РЕШЕНИЕ О КОТОРОЙ МОЖНО ОТЛОЖИТЬ.
///
/// Маркер, а не градация: градация нужна там, где запретов несколько и они разной силы. Пока
/// запрет один по существу — ждать нельзя там, где ждать нельзя физически, — маркер выражает его
/// полностью, а градация добавила бы клетки, которым нечего называть.
pub trait CanDefer: Region {}

/// ПАКЕТ В РУКАХ ЯДРА. Ждать нельзя: очередь держит его до ответа.
pub struct Packet;
/// РАЗГОВОР. Живёт до своего конца и ожидание терпит.
pub struct Conversation;
/// ЦЕЛЬ. Живёт до смены плана; откладывать можно свободно.
pub struct Target;
/// НИКОМУ. Адресат пустого слова.
pub struct Nobody;

impl Region for Packet {}
impl Region for Conversation {}
impl Region for Target {}
impl Region for Nobody {}

impl CanDefer for Conversation {}
impl CanDefer for Target {}
/// Сказать нечего — значит некому и держать: ждать можно сколько угодно.
impl CanDefer for Nobody {}

/// СКАЗАТЬ НЕЧЕГО — терминальный объект категории.
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

/// ДВА СЛОВА ОДНОЙ ОБЛАСТИ — одно слово той же области.
///
/// Разным областям слиться нельзя: их слова ехают в разные места, и склейка была бы ложью о том,
/// кому сказано.
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
/// // Разным областям слиться нельзя: их слова ехают в разные места.
/// takes::<(Sever, Verdict)>();
/// ```
impl<A: Word, B: Word<Of = A::Of>> Word for (A, B) {
    type Of = A::Of;
}

/// ЖДАТЬ МОЖНО ТОЛЬКО ТАМ, ГДЕ ОБЛАСТЬ ЭТО ТЕРПИТ.
///
/// Страж существует ради границы, которую нельзя перейти молча: всякий будущий оператор ожидания
/// обязан потребовать этот же баунд, и тогда ожидание на пакетной цепочке не соберётся.
///
/// ```
/// use reflex_core::word::{may_wait, Conversation, Word};
/// struct Sever;
/// impl Word for Sever { type Of = Conversation; }
/// // Разговор ожидание терпит.
/// may_wait::<Sever>();
/// ```
///
/// ```compile_fail
/// use reflex_core::word::{may_wait, Packet, Word};
/// struct Verdict;
/// impl Word for Verdict {
///     type Of = Packet;
/// }
/// // Ядро держит пакет: ожидание здесь невыразимо, а не нежелательно.
/// may_wait::<Verdict>();
/// ```
pub fn may_wait<W: Word>()
where
    W::Of: CanDefer,
{
}
