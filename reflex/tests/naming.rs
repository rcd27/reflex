//! ИМЯ РАЗГОВОРА: цепочка один раз на разговор говорит, как его цель назвалась. Разбор
//! имени уже есть в горячем пути (SNI у TCP, `Initial` у QUIC, вопрос у DNS) — эта дверь только отдаёт
//! его наружу, чтобы тот, кто видит разговор иначе (conntrack), знал его цель по имени.

mod paper;

use paper::{dns_answer, dns_query, Paper};
use reflex::*;

fn named(paper: Paper) -> Vec<Named> {
    let (tx, heard) = std::sync::mpsc::sync_channel(16);
    engine(paper)
        .from(Udp)
        .extract(Sni)
        .detect(Resolve::names())
        .naming(reflex_core::Tap::new(tx))
        .on(|_name, _resolved| {})
        .run();
    heard.try_iter().collect()
}

#[test]
fn a_conversation_is_named_once() {
    let names = named(
        Paper::new()
            .then_packet(dns_query(40001, "youtubei.googleapis.com"))
            .then_packet(dns_answer(
                40001,
                "youtubei.googleapis.com",
                [172, 217, 114, 4],
            ))
            .then_stop(),
    );

    assert_eq!(
        names.iter().map(|named| &*named.name).collect::<Vec<_>>(),
        vec!["youtubei.googleapis.com"]
    );
}

#[test]
fn another_conversation_is_named_again() {
    let names = named(
        Paper::new()
            .then_packet(dns_query(40001, "youtubei.googleapis.com"))
            .then_packet(dns_query(40002, "firebaseinstallations.googleapis.com"))
            .then_stop(),
    );

    assert_eq!(names.len(), 2);
    assert_ne!(names[0].flow, names[1].flow);
    assert_eq!(&*names[1].name, "firebaseinstallations.googleapis.com");
}
