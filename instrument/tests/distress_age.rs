//! Слово беды несёт ВОЗРАСТ наблюдения. Фреймворк отдаёт величину, потребитель судит о годности:
//! возраст — то, что мы видели, годность — вывод из истории и проверок, которых у наблюдателя нет.

use reflex_instrument::distress::Distress;
use std::time::{Duration, Instant};

/// Возраст считается от момента НАБЛЮДЕНИЯ до момента, когда слово произносится. Оба приходят
/// аргументами: своих часов у слова нет (§8 — время буква события, машина часов не дёргает).
#[test]
fn a_word_of_trouble_carries_the_age_of_the_observation() {
    let seen_at = Instant::now();
    let spoken = Distress::NoBytes.aged(seen_at, seen_at + Duration::from_secs(3));
    assert_eq!(spoken.since, Duration::from_secs(3));
    assert_eq!(
        spoken.distress,
        Distress::NoBytes,
        "сама беда не меняется — к ней добавлен возраст"
    );
}

/// Свежесказанное имеет нулевой возраст, а не отсутствующий: ноль — величина, «неизвестно» было бы
/// суждением о том, чего мы не измеряли.
#[test]
fn a_freshly_spoken_word_has_a_zero_age() {
    let now = Instant::now();
    assert_eq!(Distress::Rst.aged(now, now).since, Duration::ZERO);
}

/// Слово с возрастом остаётся словом СВОЕЙ области: возраст ничего не переадресует.
#[test]
fn age_does_not_readdress_the_word() {
    fn takes<W: reflex_core::word::Word<Of = reflex_core::word::Conversation>>() {}
    takes::<Distress>();
    takes::<reflex_instrument::distress::Spoken>();
}
