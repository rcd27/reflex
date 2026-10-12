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

/// Слово читателя: у него один ящик на много источников, имя — лишь одно из слов.
#[derive(Debug, PartialEq)]
enum Letter {
    Named(String),
}

impl From<Named> for Letter {
    fn from(named: Named) -> Letter {
        Letter::Named(named.name.to_string())
    }
}

/// Имя уходит в ящик читателя его словом: пайп переводит при отправке и о читателе не знает.
#[test]
fn a_name_is_spoken_in_the_readers_word() {
    let (tx, heard) = std::sync::mpsc::sync_channel::<Letter>(16);
    engine(
        Paper::new()
            .then_packet(dns_query(40001, "youtubei.googleapis.com"))
            .then_stop(),
    )
    .from(Udp)
    .extract(Sni)
    .detect(Resolve::names())
    .naming(Tap::new(tx))
    .on(|_name, _resolved| {})
    .run();

    assert_eq!(
        heard.try_iter().collect::<Vec<Letter>>(),
        vec![Letter::Named("youtubei.googleapis.com".to_string())]
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
