//! ЦЕЛЬ, ЗАМОЛЧАВШАЯ ПОСРЕДИ РАЗГОВОРА, — класс беды, который весь парк пропускал.
//!
//! Запись снята с провода 18.09.2026: клиент открыл TLS к цели за фильтром, получил сертификат,
//! отправил запрос, цель подтвердила его `ACK`-ом БЕЗ ДАННЫХ и замолчала на 19,4 секунды, после
//! чего ответила `301`. Блокировка сменила род: тихого дропа по имени больше нет, есть задержка.
//!
//! Восемь приборов парка на этой записи молчали. Краевая половина двери [`reflex::Silence`] видит
//! `up_packets >= 2`, считает цель живой и отпускает разговор навсегда; истории «речь шла и
//! встала» край не выражает вовсе — она видна только тому, кто ТИКАЕТ.

use reflex::*;
use std::time::Duration;

fn recording() -> String {
    format!(
        "{}/tests/fixtures/stalled-after-reply.pcap",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn heard_with(patience: Duration) -> Vec<Distress> {
    let heard = std::sync::Mutex::new(Vec::new());
    pcap(recording())
        .from(Tcp)
        .extract(Sni)
        .detect(Silence::after(patience))
        .on(|_target: &str, distress| heard.lock().expect("журнал цел").push(distress))
        .run();
    heard.into_inner().expect("журнал цел")
}

/// ШТАТНАЯ ДВЕРЬ НАЗЫВАЕТ БЕДУ, а не молчит: цель приняла просьбу и не отвечает дольше терпения.
#[test]
fn a_target_that_went_quiet_after_replying_is_named_by_the_regular_door() {
    let said = heard_with(Duration::from_secs(5));

    assert!(
        matches!(said.as_slice(), [Distress::Silence { ms }] if *ms >= 5_000),
        "19 секунд тишины при ждущем клиенте обязаны быть названы: {said:?}"
    );
}

/// ТЕРПЕНИЕ — ВЕЛИЧИНА ДОМЕННОЙ ЛОГИКИ, и беда называется тем раньше, чем оно короче. Полсекунды
/// терпения — полсекунды до слова, а не пять секунд ожидания.
#[test]
fn shorter_patience_names_the_trouble_sooner() {
    let said_quickly = heard_with(Duration::from_millis(500));

    assert!(
        matches!(said_quickly.as_slice(), [Distress::Silence { ms }] if *ms < 1_000),
        "при пороге 500 мс слово обязано прийти в пределах секунды: {said_quickly:?}"
    );
}

/// СЛОВО ОДНО, А НЕ ДВА: половины двери говорят о разном, и `NoBytes` остаётся за краем —
/// единственным, кто знает историю разговора до нашего рождения.
#[test]
fn the_two_halves_of_the_door_do_not_repeat_each_other() {
    let said = heard_with(Duration::from_millis(500));

    assert_eq!(said.len(), 1, "одна беда — одно слово: {said:?}");
    assert!(
        !said.iter().any(|w| matches!(w, Distress::NoBytes)),
        "цель отдала сертификат — `NoBytes` о ней был бы ложью: {said:?}"
    );
}

mod paper;

/// ТОТ ЖЕ ЗАКОН НА ВХОДЕ, ГДЕ ПОЛОВИНЫ МОГЛИ БЫ СТОЛКНУТЬСЯ: цель не отдала НИ БАЙТА, и `NoBytes`
/// — слово обеих по существу. Говорит его КРАЙ: он один знает историю разговора до нашего
/// рождения (счёт ведёт ядро), а провод свидетелем той истории не является.
///
/// Предыдущий закон этого не ловит и не может: на записи с ответом цели проводная половина
/// `NoBytes` не говорит вовсе, и снятый фильтр там не краснеет — проверка была бы слепа к своему
/// предмету (§10.7).
#[test]
fn when_the_target_is_wholly_silent_only_the_edge_speaks_the_word() {
    use paper::{request, Paper, PaperEdge};

    let heard = std::sync::Mutex::new(Vec::new());
    engine(
        Paper::new()
            // Край говорит то, что на живой очереди сказал бы conntrack: цель ответила ОДНИМ
            // пакетом (`SYN+ACK`), данных не дала, клиент свой запрос отправил, разговор старше терпения.
            .edging(Some(PaperEdge {
                up_packets: 1,
                down_packets: 2,
                down_bytes: 1_500,
                age: Duration::from_secs(7),
                mark: 0,
            }))
            // ДВА наблюдения: первое берёт разговор под подозрение (фаза ложится в марку),
            // второе приходит, когда возраст перешагнул терпение, — на нём край и высказывается.
            .then_packet(request(40001))
            .then_packet_after(Duration::from_secs(7), request(40001))
            .then_stop(),
    )
    .from(Tcp)
    .extract(Sni)
    .detect(Silence::after(Duration::from_secs(5)))
    .on(|_t: &str, d| heard.lock().expect("журнал цел").push(d))
    .run();

    let said = heard.into_inner().expect("журнал цел");
    assert_eq!(
        said.len(),
        1,
        "«не отдала ни байта» — одна беда, и слово о ней одно: {said:?}"
    );
    assert!(
        matches!(said.as_slice(), [Distress::NoBytes]),
        "историю разговора называет край: {said:?}"
    );
}
