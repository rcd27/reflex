//! СЛОВА ДВИЖКА ОБЪЯВЛЯЮТ, КОМУ ОНИ СКАЗАНЫ.
//!
//! Слова устроены одинаково, и это не совпадение: у каждого есть область, у области срок, из
//! срока следует отложимость. Пакет ждать не может — его держит ядро; разговор и цель могут.
//!
//! Здесь же проверяется, что двум адресатам не дали одного слова: область, взятая пошире «чтобы
//! собралось», не выпадает ни на одной проверке — обе отложимы, — и потому называется вслух.
use reflex_core::word::{may_wait, Word};
use reflex_engine::{Act, Lost, Ordered, Programme, Sighting};

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

/// ДВА НАБЛЮДЕНИЯ — ДВА АДРЕСАТА, И ЭТО ПРЕДЪЯВЛЕНО, А НЕ ОБЕЩАНО.
///
/// Пока потеря цели лежала буквой среди наблюдений разговора, обе области были отложимы, и
/// расхождение не выпадало ни на одной проверке. Здесь оно выпадает: адреса называются вслух.
#[test]
fn the_loss_of_a_target_is_not_addressed_to_a_conversation() {
    fn region_of<W: Word>() -> &'static str {
        core::any::type_name::<W::Of>()
    }
    assert!(
        region_of::<Sighting>().ends_with("Conversation"),
        "наблюдение плоскости адресовано разговору"
    );
    assert!(
        region_of::<Lost>().ends_with("Target"),
        "потеря цели адресована цели"
    );
    assert_ne!(
        region_of::<Sighting>(),
        region_of::<Lost>(),
        "два адресата обязаны остаться двумя: одно слово на обоих не говорит, кому сказано"
    );
}

#[test]
fn waiting_is_allowed_on_the_conversation_and_the_target() {
    // Ожидание на этих двух законно; на пакетной цепочке оно не собирается вовсе, и это
    // проверяется док-тестом стража в фундаменте, а не здесь: провал сборки тестом не выражается.
    may_wait::<Ordered>();
    may_wait::<Programme>();
}
