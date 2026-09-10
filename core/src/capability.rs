//! Способности бэкенда — ограничения образа функтора (канон §9.1): слово `w` собирается над
//! бэкендом только там, где способность с предметом `w` заявлена. Маркер, не пометка: пустого
//! заявления тип не пропускает, ложное ловит закон (`certify`).
//!
//! Самопроверка: гейт §9.1 («заявить способность, не назвав её предмет, нельзя») у каждого трейта
//! ниже доказывает `compile_fail`-доктест, стоящий сразу под докблоком — не именованный сторож по
//! идиоме соседнего механизма (см. `core/tests/docblock_guards.rs`), а сам себе доказательство: он
//! и есть код, которому положено не собраться. Связь стоит назвать явно ИМЕННО потому, что она не
//! ловится той идиомой — доктест не `fn`, у него нет имени функции, которое можно сверить с деревом.

/// Читает копию каждого пакета, не вмешиваясь. Канон §9.1. Своего метода нет — наблюдение уже есть
/// [`Source::packets`](crate::backend::Source::packets); супертрейт и есть предмет. «Не вмешиваясь»
/// типом не выразимо, остаётся закону. Заявить, не отдавая потока, нельзя:
///
/// ```compile_fail,E0277
/// use reflex_core::capability::CanObserve;
/// struct Blind;
/// impl CanObserve for Blind {}
/// ```
pub trait CanObserve: crate::backend::Source {}

/// Вводит пакеты в сеть. Метод, а не пустой маркер: заявить можно только назвав, как инъекция
/// становится командой ЭТОГО стока. Заявить, не построив команду, нельзя:
///
/// ```compile_fail,E0046
/// use reflex_core::backend::Sink;
/// use reflex_core::capability::CanInject;
/// struct Mute;
/// impl Sink for Mute {
///     type Command = ();
///     type Error = ();
///     fn emit(&mut self, _command: ()) -> Result<(), ()> { Ok(()) }
/// }
/// impl CanInject for Mute {}
/// ```
pub trait CanInject: crate::backend::Sink {
    /// Как инъекция становится командой стока. Ассоциированная функция: команду можно собрать до
    /// открытия калитки.
    fn inject(packet: crate::command::InjectablePacket) -> Self::Command;
}

/// Удерживает пакет, пока мы решаем. Предмет — отпускание [`release`](Self::release): удержание не
/// команда, а «ещё не ответили». Супертрейт `Terminal` (ответ ОДНОМУ пакету), не `Sink` (правило на
/// поток). Заявить, не назвав слова отпускания, нельзя:
///
/// ```compile_fail,E0046
/// use reflex_core::capability::CanHold;
/// use reflex_core::held::{Answered, Delivered, Refused, Terminal};
/// struct Immediate;
/// impl Terminal for Immediate {
///     type Carrier = ();
///     type Answer = ();
///     type Refusal = ();
///     fn apply(&mut self, answered: Answered<(), ()>)
///         -> Result<Delivered<()>, Refused<(), ()>> {
///         Ok(Delivered { at: answered.at, answer: answered.answer })
///     }
/// }
/// impl CanHold for Immediate {}
/// ```
pub trait CanHold: crate::held::Terminal {
    /// Каким словом удержанный отпускается без изменений.
    fn release() -> Self::Answer;
}

/// Не пропустить удержанный пакет. Ответ ОДНОМУ пакету, не правило на поток (ср. [`CanDrop`]) —
/// снимать нечего, потому пары «снять обратно» нет.
///
/// ```compile_fail,E0046
/// use reflex_core::capability::CanRefuse;
/// use reflex_core::held::{Answered, Delivered, Refused, Terminal};
/// struct Passing;
/// impl Terminal for Passing {
///     type Carrier = ();
///     type Answer = ();
///     type Refusal = ();
///     fn apply(&mut self, answered: Answered<(), ()>)
///         -> Result<Delivered<()>, Refused<(), ()>> {
///         Ok(Delivered { at: answered.at, answer: answered.answer })
///     }
/// }
/// impl CanRefuse for Passing {}
/// ```
pub trait CanRefuse: crate::held::Terminal {
    /// Каким словом удержанный не пропускается.
    fn refuse() -> Self::Answer;
}

/// Отпустить удержанный пакет, пометив его для тех, кто ниже. Единственная способность, чей эффект
/// не виден на проводе: свидетель — читатель метки (правило ниже очереди), не наблюдатель провода.
///
/// ```compile_fail,E0046
/// use reflex_core::capability::CanMark;
/// use reflex_core::held::{Answered, Delivered, Refused, Terminal};
/// struct Plain;
/// impl Terminal for Plain {
///     type Carrier = ();
///     type Answer = ();
///     type Refusal = ();
///     fn apply(&mut self, answered: Answered<(), ()>)
///         -> Result<Delivered<()>, Refused<(), ()>> {
///         Ok(Delivered { at: answered.at, answer: answered.answer })
///     }
/// }
/// impl CanMark for Plain {}
/// ```
pub trait CanMark: crate::held::Terminal {
    /// Каким словом удержанный отпускается с меткой.
    fn mark(mark: u32) -> Self::Answer;
}

/// Отпустить удержанный пакет с другими байтами. Адресат уже в руках — `flow` в подписи был бы
/// вторым способом сказать сказанное носителем (ср. [`CanModify`], где правило в ядре знает `Flow`).
///
/// ```compile_fail,E0046
/// use reflex_core::capability::CanRewrite;
/// use reflex_core::held::{Answered, Delivered, Refused, Terminal};
/// struct Verbatim;
/// impl Terminal for Verbatim {
///     type Carrier = ();
///     type Answer = ();
///     type Refusal = ();
///     fn apply(&mut self, answered: Answered<(), ()>)
///         -> Result<Delivered<()>, Refused<(), ()>> {
///         Ok(Delivered { at: answered.at, answer: answered.answer })
///     }
/// }
/// impl CanRewrite for Verbatim {}
/// ```
pub trait CanRewrite: crate::held::Terminal {
    /// Каким словом удержанный отпускается с новыми байтами.
    fn rewrite(bytes: Vec<u8>) -> Self::Answer;
}

/// Изменить пакет на месте и пропустить дальше. Над [`Sink`](crate::backend::Sink) — правило на
/// поток. Канон §9.1: ноль реализаций — честный ответ, фронтенд не сужается до слабейшего бэкенда.
///
/// ```compile_fail,E0046
/// use reflex_core::backend::Sink;
/// use reflex_core::capability::CanModify;
/// struct Forwarder;
/// impl Sink for Forwarder {
///     type Command = Vec<u8>;
///     type Error = ();
///     fn emit(&mut self, _command: Vec<u8>) -> Result<(), ()> { Ok(()) }
/// }
/// impl CanModify for Forwarder {}
/// ```
pub trait CanModify: crate::backend::Sink {
    /// Как модификация становится командой стока.
    fn modify(change: crate::command::ModifyPacket) -> Self::Command;
}

/// Ронять пакеты потока, не давая дойти до адресата. Над [`Sink`](crate::backend::Sink): правило в
/// ядре, живущее до снятия ([`clear_flow`](Self::clear_flow)).
///
/// ```compile_fail,E0046
/// use reflex_core::backend::Sink;
/// use reflex_core::capability::CanDrop;
/// struct Passthrough;
/// impl Sink for Passthrough {
///     type Command = Vec<u8>;
///     type Error = ();
///     fn emit(&mut self, _command: Vec<u8>) -> Result<(), ()> { Ok(()) }
/// }
/// impl CanDrop for Passthrough {}
/// ```
pub trait CanDrop: crate::backend::Sink {
    /// Команда: ронять поток.
    fn drop_flow(flow: crate::types::Flow) -> Self::Command;
    /// Команда: снять правило дропа.
    fn clear_flow(flow: crate::types::Flow) -> Self::Command;
}

/// Кому адресовано извещение об обрыве — в терминах пакета, не разговора: бэкенд разговоров не
/// помнит (кто клиент — знание входа), а у пакета две объективные стороны.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Toward {
    /// Тому, кто послал удержанный пакет.
    Sender,
    /// Тому, кому удержанный пакет был адресован.
    Receiver,
}

/// Оборвать разговор: не пропустить пакет И сказать об этом. Обрыв есть пара — [`CanRefuse`] даёт
/// слово отказа, `notice` — извещение; без обоих не собирается. Канон §5: дроп без извещения есть
/// молчаливый дроп на пути. Извещение только СТРОИТСЯ здесь; отправляет его [`CanInject`].
///
/// ```compile_fail,E0046
/// use reflex_core::capability::{CanRefuse, CanSever};
/// use reflex_core::held::{Answered, Delivered, Refused, Terminal};
/// struct Silent;
/// impl Terminal for Silent {
///     type Carrier = ();
///     type Answer = ();
///     type Refusal = ();
///     fn apply(&mut self, answered: Answered<(), ()>)
///         -> Result<Delivered<()>, Refused<(), ()>> {
///         Ok(Delivered { at: answered.at, answer: answered.answer })
///     }
/// }
/// impl CanRefuse for Silent { fn refuse() {} }
/// impl CanSever for Silent {}
/// ```
pub trait CanSever: CanRefuse {
    /// Чем сказать названной стороне, что разговора не будет. `None` — «на этом носителе сказать
    /// нечем» (у датаграммы формы обрыва нет), не пустота: движок обязан узнать это ДО решения
    /// рвать. Вход — наблюдённые байты, не носитель: закон-таблица вход→выход не требует прав.
    fn notice(seen: &[u8], toward: Toward) -> Option<crate::command::InjectablePacket>;
}

/// Способность СПРОСИТЬ — обратный ход движка: вопрос уходит контуру, ответ придёт буквой ленты
/// ([`crate::tape::Answer`]), не возвратом вызова. Ожидание — фаза машины, а не блокировка: шаг
/// Мили не ждёт, иначе он перестал бы быть шагом и лента перестала бы переигрываться (§1, §10).
///
/// Вопрос несёт КОРРЕЛЯЦИОННЫЙ ТОКЕН: ответ приходит позже и сам по себе не говорит, чей он.
/// Токен — ключ области (§4): им ответ и находит свою машину, а не «первую попавшуюся».
///
/// Строит вопрос ЧИСТАЯ таблица, как и у обрыва: `вопрос → пакет-к-контуру`. Отправляет драйвер —
/// эффект принадлежит ему (§9), не способности.
pub trait CanAsk: crate::held::Terminal {
    /// Чем спросить контур. `None` — «на этом носителе спросить нечем»: не всякая дверь умеет
    /// говорить наружу, и движок обязан узнать это ДО решения спрашивать.
    fn question(token: u64, about: &[u8]) -> Option<crate::command::InjectablePacket>;
}

/// Способность помнить на крае: следующее состояние отдаётся ТЕМ ЖЕ словом, что и вердикт.
/// Раздельные слова допускали бы «ответили, но не запомнили» — состояние осталось бы прошлым при
/// отпущенном пакете. Канон §5. Ассоциированная функция: ответ можно собрать до открытия калитки.
///
/// Сторож: `памятка_ложится_домой_и_читается_маркой` (`core/tests/local.rs`),
/// `kernel_remembers_what_was_told` (`core/tests/certify_remembering.rs`).
pub trait CanRemember: crate::held::Terminal {
    fn remember(state: u32, accept: bool) -> Self::Answer;
}
