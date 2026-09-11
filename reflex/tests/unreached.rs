//! ФИЛЬТР «В ОБРАТНУЮ СТОРОНУ» — прогоном по сочинённому проводу.
//!
//! Класс, который до этой буквы был невидим целиком: клиент доволен, цель старается, прогресса нет.
//! Земля, которой он оплачен, снята лабораторией потребителя (дроп ответов после 16-го пакета: цель
//! шлёт один и тот же сегмент с интервалами 0,5 · 0,9 · 1,8 · 3,4 · 6,7 с — это её RTO). Здесь тот
//! же сценарий сочинён: проверяется ДОРОГА от провода до реакции, а не разбор pcap.

mod paper;

use paper::{log, reply, reply_at, request, syn, taken, Paper};
use reflex::*;

/// ПРЕДМЕТ: цель повторяет ответ, прогресса нет — цепочка обязана это назвать.
#[test]
fn повтор_цели_без_продвижения_доходит_до_реакции() {
    let heard = log::<Distress>();

    // Клиент попросил, цель ответила — и дальше повторяет ТО ЖЕ САМОЕ: её ответы до клиента не
    // доходят, подтверждений нет, и она пробует снова.
    let paper = Paper::new()
        .then_packet(syn(40001))
        .then_packet(request(40001))
        .then_packet(reply(40001, 1248))
        .then_packet(reply(40001, 1248))
        .then_packet(reply(40001, 1248))
        .then_stop();

    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(Unreached::answers())
        .on(move |_target, distress| heard.lock().expect("слышно").push(distress))
        .run();

    let said = taken(heard);
    assert!(
        said.iter()
            .any(|distress| matches!(distress, Distress::Unreached { .. })),
        "ряд повторов цели без продвижения обязан быть назван; сказано: {said:?}"
    );
}

/// Вторая половина, и без неё первая зелена на приборе, кричащем всегда: цель, которая ПРОДВИГАЕТСЯ
/// (номер растёт), беды не даёт. Ровно так выглядит здоровая закачка, и обвинять её значило бы
/// послать человека лечить то, что не болит.
#[test]
fn продвигающаяся_цель_беды_не_даёт() {
    let heard = log::<Distress>();

    let paper = Paper::new()
        .then_packet(syn(40002))
        .then_packet(request(40002))
        .then_packet(reply_at(40002, 1, 1248))
        .then_packet(reply_at(40002, 1249, 1248))
        .then_packet(reply_at(40002, 2497, 1248))
        .then_stop();

    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(Unreached::answers())
        .on(move |_target, distress| heard.lock().expect("слышно").push(distress))
        .run();

    let said = taken(heard);
    assert!(
        !said
            .iter()
            .any(|distress| matches!(distress, Distress::Unreached { .. })),
        "растущий номер есть продвижение — беды здесь нет; сказано: {said:?}"
    );
}
