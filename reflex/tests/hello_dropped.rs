//! ПРИВЕТСТВИЕ НЕ ПОДТВЕРЖДЕНО НИ РАЗУ — SNI-IV по Xue et al. (IMC '22): рукопожатие состоялось,
//! `ClientHello` с именем пропал, в ответ ничего, даже подтверждения (#347, nevod).
//!
//! Все три записи сняты 24.09.2026 на линии стенда (аплинк `raw`, провайдер хозяина) в пространстве
//! имён человека, без продукта — это болезнь в чистом виде и её контроль:
//!
//! ```text
//! rutracker.org     приветствие t=0,145 с · подтверждения нет · повторы через 0,30 0,59 1,22 2,43 4,80 9,67 с
//! ya.ru             приветствие t=0,065 с · подтверждено через 37 мс · повторов нет
//! one.one.one.one   приветствие t=0,099 с · подтверждено через 36 мс · повторов нет
//! ```
//!
//! Контроль того же CDN (Cloudflare обслуживает и `rutracker.org`, и `one.one.one.one`) отделяет
//! имя от пути: сервер и дорога одного рода, различие — в имени.

use reflex::{pcap, Distress, HelloDropped, Sni, Tcp};

fn heard(path: &str) -> Vec<(String, Distress)> {
    let said = std::sync::Mutex::new(Vec::new());
    pcap(path)
        .from(Tcp)
        .extract(Sni)
        .detect(HelloDropped::unacknowledged())
        .on(|target: &str, distress: Distress| {
            let _pushed = said
                .lock()
                .map(|mut said| said.push((target.to_string(), distress)));
        })
        .run();
    said.into_inner().unwrap_or_default()
}

/// Болезнь названа по имени цели, и величины — с записи: сколько повторов и через сколько.
#[test]
fn a_hello_never_acknowledged_is_named() {
    let said = heard("tests/fixtures/hello-dropped-rutracker.pcap");

    let [(target, Distress::HelloDropped { retries, after_ms })] = said.as_slice() else {
        panic!("болезнь обязана быть названа ровно один раз: {said:?}")
    };
    assert_eq!(target, "rutracker.org");
    assert_eq!(*retries, 3, "на пороге — третий повтор");
    // Третий повтор — через 1,22 с после приветствия; величина берётся у записи, допуск на округление.
    assert!(
        (1_150..=1_300).contains(after_ms),
        "третий повтор пришёл через ~1,22 с после приветствия, а не через {after_ms} мс"
    );
}

/// Здоровая цель подтверждает приветствие за один RTT — повторять нечего, сказать тоже.
#[test]
fn a_hello_answered_by_a_healthy_target_is_not_named() {
    assert_eq!(heard("tests/fixtures/hello-answered-ya.pcap"), Vec::new());
}

/// Тот же CDN, другое имя — тоже тишина: беда в имени, а не в пути.
#[test]
fn a_hello_answered_by_the_same_cdn_is_not_named() {
    assert_eq!(
        heard("tests/fixtures/hello-answered-cloudflare.pcap"),
        Vec::new()
    );
}
