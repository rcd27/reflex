//! АДРЕС ЕСТЬ У СЛОВА, И ОН ПРОВЕРЯЕТСЯ ТИПОМ.
//!
//! Слово — значение, объявившее свою область. Область даёт срок, срок даёт отложимость: пакет
//! держит ядро, и ждать на нём нельзя физически; разговор ожидание терпит.
//!
//! Здесь проверяется, что закон выражен типами, а не уговором: объявить область обязан всякий,
//! кто хочет стоять в позиции слова, и своя область объявляется без правки фундамента.
use reflex_core::word::{may_wait, Conversation, Region, Word};
use smallvec::SmallVec;

/// СВОЯ ОБЛАСТЬ, ОБЪЯВЛЕННАЯ СНАРУЖИ ФУНДАМЕНТА — то, ради чего закон вводится трейтом, а не
/// перечислением трёх слов движка.
struct Tunnel;
impl Region for Tunnel {}

struct Reroute;
impl Word for Reroute {
    type Of = Tunnel;
}

#[test]
fn nothing_to_say_is_a_word_addressed_to_nobody() {
    // «Сказать нечего» видно на подписи, а не после запуска: терминальный объект категории.
    fn addressed<W: Word>() -> &'static str {
        core::any::type_name::<W::Of>()
    }
    assert_eq!(
        addressed::<()>(),
        "reflex_core::word::Nobody",
        "пустое слово обязано быть адресовано никому"
    );
}

#[test]
fn a_collection_of_words_keeps_their_address() {
    // Пачка слов адресована туда же, куда каждое: сложение не меняет адресата.
    fn same_address<A: Word, B: Word<Of = A::Of>>() {}
    same_address::<Reroute, SmallVec<[Reroute; 2]>>();
}

#[test]
fn a_pair_of_words_is_a_word_of_the_same_region() {
    // Пара слов есть слово той же области — и это инстанцируется, а не описывается.
    fn addressed<W: Word>() -> &'static str {
        core::any::type_name::<W::Of>()
    }
    assert_eq!(
        addressed::<(Reroute, Reroute)>(),
        addressed::<Reroute>(),
        "пара адресована туда же, куда её половины"
    );
}

#[test]
fn waiting_is_allowed_where_the_region_tolerates_it() {
    // Страж берёт слово и требует от его области терпения. Здесь оно есть.
    struct Sever;
    impl Word for Sever {
        type Of = Conversation;
    }
    may_wait::<Sever>();
    may_wait::<()>();
}
