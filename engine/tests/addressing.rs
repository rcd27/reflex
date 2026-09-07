//! СЛОВА ДВИЖКА ОБЪЯВЛЯЮТ, КОМУ ОНИ СКАЗАНЫ.
//!
//! Три слова устроены одинаково, и это не совпадение: у каждого есть область, у области срок, из
//! срока следует отложимость. Пакет ждать не может — его держит ядро; разговор и цель могут.
use reflex_core::word::{may_wait, Word};
use reflex_engine::{Act, Ordered, Programme};

#[test]
fn each_word_names_its_region() {
    fn region_of<W: Word>() -> &'static str {
        core::any::type_name::<W::Of>()
    }
    assert!(
        region_of::<Act>().ends_with("Packet"),
        "Act адресован пакету"
    );
    assert!(
        region_of::<Ordered>().ends_with("Conversation"),
        "Ordered адресован разговору"
    );
    assert!(
        region_of::<Programme>().ends_with("Target"),
        "Programme адресован цели"
    );
}

#[test]
fn waiting_is_allowed_on_the_conversation_and_the_target() {
    // Ожидание на этих двух законно; на пакетной цепочке оно не собирается вовсе, и это
    // проверяется док-тестом стража в фундаменте, а не здесь: провал сборки тестом не выражается.
    may_wait::<Ordered>();
    may_wait::<Programme>();
}
