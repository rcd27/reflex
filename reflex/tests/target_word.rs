//! Слово о ЦЕЛИ: свёртка приходит от потребителя ЗНАЧЕНИЕМ. Фреймворк называет копредел, не угрозу —
//! «молчат все» и «молчит хоть один» суть разные слова о той же цели из тех же наблюдений.

use reflex::Distress;
use reflex_core::colimit::Layer;
use reflex_core::types::{Flow, Protocol};
use reflex_core::word::{Conversation, Target, TargetKey};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

fn target() -> TargetKey<Box<str>> {
    TargetKey::Named("rutracker.org".into())
}

fn flow(n: u32) -> Flow {
    Flow {
        src: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(0x0A00_0000 | n)), 40000 + n as u16),
        dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(0x5DB8_D822)), 443),
        protocol: Protocol::Tcp,
    }
}

/// Из одних и тех же наблюдений разные свёртки дают РАЗНЫЕ слова о цели — потому свёртка и не может
/// принадлежать фреймворку: она описывает угрозу, а угроз много.
#[test]
fn свёртка_решает_какое_слово_родится() {
    let now = Instant::now();
    let mut layer: Layer<Conversation, Target, Distress> = Layer::new();
    layer.saw(target(), flow(1), Distress::NoBytes, now);
    layer.saw(target(), flow(2), Distress::Silence { ms: 10 }, now);

    let all_silent = |words: &[&Distress]| {
        words
            .iter()
            .all(|d| matches!(d, Distress::NoBytes))
            .then_some(Distress::NoBytes)
    };
    let any_silent = |words: &[&Distress]| {
        words
            .iter()
            .any(|d| matches!(d, Distress::NoBytes))
            .then_some(Distress::NoBytes)
    };

    assert_eq!(
        layer.join(&target(), all_silent),
        None,
        "молчат не все — цель не молчит"
    );
    assert_eq!(
        layer.join(&target(), any_silent),
        Some(Distress::NoBytes),
        "хоть один молчит — цель под подозрением"
    );
}

/// Двадцать разговоров к одной цели дают ОДНО слово о ней, а не двадцать: в этом и смысл копредела.
#[test]
fn много_разговоров_одно_слово_о_цели() {
    let now = Instant::now();
    let mut layer: Layer<Conversation, Target, Distress> = Layer::new();
    (1..=20).for_each(|n| layer.saw(target(), flow(n), Distress::NoBytes, now));

    let spoken: Vec<Distress> = layer
        .targets()
        .filter_map(|key| layer.join(key, |words| words.first().map(|d| (*d).clone())))
        .collect();
    assert_eq!(spoken.len(), 1, "цель одна — слово одно");
}
