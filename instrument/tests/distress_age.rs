//! Слово беды несёт ВОЗРАСТ наблюдения. Фреймворк отдаёт величину, потребитель судит о годности:
//! возраст — то, что мы видели, годность — вывод из истории и проверок, которых у наблюдателя нет.

use reflex_instrument::distress::Distress;
use std::time::{Duration, Instant};

/// Возраст считается от момента НАБЛЮДЕНИЯ до момента, когда слово произносится. Оба приходят
/// аргументами: своих часов у слова нет (§8 — время буква события, машина часов не дёргает).
#[test]
fn слово_беды_несёт_возраст_наблюдения() {
    let seen_at = Instant::now();
    let spoken = Distress::NoBytes.aged(seen_at, seen_at + Duration::from_secs(3));
    assert_eq!(spoken.since, Duration::from_secs(3));
    assert_eq!(spoken.distress, Distress::NoBytes, "сама беда не меняется — к ней добавлен возраст");
}

/// Свежесказанное имеет нулевой возраст, а не отсутствующий: ноль — величина, «неизвестно» было бы
/// суждением о том, чего мы не измеряли.
#[test]
fn свежее_слово_имеет_нулевой_возраст() {
    let now = Instant::now();
    assert_eq!(Distress::Rst.aged(now, now).since, Duration::ZERO);
}

/// Слово с возрастом остаётся словом СВОЕЙ области: возраст ничего не переадресует.
#[test]
fn возраст_не_меняет_адресата() {
    fn takes<W: reflex_core::word::Word<Of = reflex_core::word::Conversation>>() {}
    takes::<Distress>();
    takes::<reflex_instrument::distress::Spoken>();
}
