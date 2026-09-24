//! ПРИВЕТСТВИЕ ПРИНЯТО, ОТВЕТ ЗАГЛУШЁН — SNI-II по Xue et al. (IMC '22, §5.2): после триггерного
//! `ClientHello` проходит ещё пять–восемь пакетов, затем симметричный дроп (#347, nevod).
//!
//! Все три записи сняты 24.09.2026 на стенде со стороны человека (нога `host0`, продукт в разрыве,
//! линия провайдера хозяина), с ОДНОГО узла кэша Google у Билайна — `128.75.236.15`,
//! `rr4---sn-8ph2xajvh-hg8l.googlevideo.com`:
//!
//! ```text
//! hello-muted-ggc          приветствие · 5 дублей ACK · 3 ack на всё приветствие · 20 с тишины · FIN клиента
//! hello-muted-ggc-one-ack  приветствие · 1 ack на всё приветствие · 20 с тишины · FIN клиента
//! hello-answered-ggc       приветствие · 5 дублей ACK · ack на всё · данные сразу · 0,96 с разговора
//! ```
//!
//! Контроль — тот же узел, та же дорога, то же начало разговора пакет в пакет: различие только в
//! том, пришли ли после подтверждения данные. Контроль ДЛИННЕЕ порога намеренно: первая редакция
//! длилась 13 мс, кончалась раньше первого тика после порога — и мутант «ответ цели не замечен»
//! проходил её зелёным. Короткий контроль молчит по случайности, а не по закону.

use reflex::{pcap, Distress, HelloDropped, HelloMuted, Sni, Tcp};

fn heard(path: &str) -> Vec<(String, Distress)> {
    let said = std::sync::Mutex::new(Vec::new());
    pcap(path)
        .from(Tcp)
        .extract(Sni)
        .detect(HelloMuted::answerless())
        .on(|target: &str, distress: Distress| {
            let _pushed = said
                .lock()
                .map(|mut said| said.push((target.to_string(), distress)));
        })
        .run();
    said.into_inner().unwrap_or_default()
}

/// Заглушённый ответ назван по имени цели, с RTT рукопожатия и временем от подтверждения.
#[test]
fn a_hello_acknowledged_and_never_answered_is_named() {
    let said = heard("tests/fixtures/hello-muted-ggc.pcap");

    let [(target, Distress::HelloMuted { rtt_ms, after_ms })] = said.as_slice() else {
        panic!("болезнь обязана быть названа ровно один раз: {said:?}")
    };
    assert_eq!(target, "rr4---sn-8ph2xajvh-hg8l.googlevideo.com");
    assert!(*rtt_ms <= 3, "рукопожатие этого узла — 2 мс, а не {rtt_ms}");
    // Порог — 10 RTT, но не меньше 200 мс; слово приносит тик сетки (шаг 200 мс).
    assert!(
        (200..=600).contains(after_ms),
        "слово — на первом тике после порога, а не через {after_ms} мс"
    );
}

/// Пять–восемь пакетов после триггера — верхняя граница; одно подтверждение — та же болезнь.
#[test]
fn a_single_acknowledgement_then_silence_is_the_same_disease() {
    let said = heard("tests/fixtures/hello-muted-ggc-one-ack.pcap");
    assert!(
        matches!(said.as_slice(), [(_, Distress::HelloMuted { .. })]),
        "{said:?}"
    );
}

/// Тот же узел, то же начало пакет в пакет — но данные пришли. Сказать нечего.
#[test]
fn a_hello_answered_after_the_same_acknowledgements_is_not_named() {
    assert_eq!(heard("tests/fixtures/hello-answered-ggc.pcap"), Vec::new());
}

/// СОСЕД ЭТУ БОЛЕЗНЬ НЕ ВИДИТ ПО ПОСТРОЕНИЮ: приветствие подтверждено, повторов нет. Ради этого
/// прибор и заведён — иначе он дублировал бы `HelloDropped`.
#[test]
fn the_neighbour_for_dropped_hellos_is_blind_to_it() {
    let said = std::sync::Mutex::new(Vec::new());
    pcap("tests/fixtures/hello-muted-ggc.pcap")
        .from(Tcp)
        .extract(Sni)
        .detect(HelloDropped::unacknowledged())
        .on(|target: &str, distress: Distress| {
            let _pushed = said
                .lock()
                .map(|mut said| said.push((target.to_string(), distress)));
        })
        .run();
    assert_eq!(said.into_inner().unwrap_or_default(), Vec::new());
}

/// И наоборот: неподтверждённое приветствие (SNI-IV) — не этот прибор.
#[test]
fn a_hello_never_acknowledged_is_not_muted() {
    assert_eq!(
        heard("tests/fixtures/hello-dropped-rutracker.pcap"),
        Vec::new()
    );
}
