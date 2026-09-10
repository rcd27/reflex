//! ПОЧЕМУ фасад запрещает типом двух писателей марки (§4/§3, дельта Д9).
//!
//! Состояние краевого прибора вынесено в ядро: вся фаза лежит в марке, `self` в шаге не меняется.
//! Два таких прибора в одной цепочке делят одни 15 бит — и произведения машин, которое обещает
//! `.detect(A).detect(B)`, не существует: автора в ячейке не называет ни позиция, ни ключ.
//!
//! Тест держит ПРИЧИНУ запрета, а не желаемое поведение: он утверждает то, что есть. Фаза есть
//! гейт молчания (`Phase::Confirmed => (None, …)`), сосед по марке затирает её своим `Suspected`,
//! и беда называется на каждом пакете. Собрать такую цепочку через фасад больше нельзя
//! (`Detecting<_, _, MarkWriter>::detect` принимает только `MarkSilent`), но приборы соединимы
//! напрямую — и пока это так, причина обязана быть предъявлена замером, а не памятью о разговоре.
//! Покраснеет он тогда, когда приборы научатся делить марку: тогда и гейт подлежит пересмотру.

use core::time::Duration;
use reflex_core::mealy::Mealy;
use reflex_core::DetectorEvent;
use reflex_core::edge::EdgeView;
use reflex_instrument::distress::Distress;
use reflex_instrument::edge::Layout;
use reflex_instrument::edge_detect::EdgeSilence;
use reflex_instrument::edge_word::Edged;
use std::time::Instant;

fn layout() -> Layout {
    Layout::new(0x0FFF_E000, 0b101).expect("15-битная маска, ненулевой тег")
}

/// Край живого разговора: клиент просил, цель молчит, возраст растёт. `mark` подставляем снаружи —
/// это и есть состояние в ядре, общее для обоих приборов.
#[derive(Clone)]
struct Silent {
    mark: u32,
    age: Duration,
}

impl EdgeView for Silent {
    fn down_packets(&self) -> Option<u64> { Some(4) }
    fn down_bytes(&self) -> Option<u64> { Some(1_200) }
    fn up_packets(&self) -> Option<u64> { Some(0) }
    fn up_bytes(&self) -> Option<u64> { Some(0) }
    fn idle(&self) -> Option<Duration> { Some(self.age) }
    fn age(&self) -> Option<Duration> { Some(self.age) }
    fn mark(&self) -> u32 { self.mark }
}

fn packet(mark: u32, age_ms: u64) -> DetectorEvent<Edged<Option<reflex_instrument::wire::Seen>, Option<Silent>>> {
    DetectorEvent::Packet {
        input: Edged {
            narrow: None,
            edge: Some(Silent { mark, age: Duration::from_millis(age_ms) }),
        },
        at: Instant::now(),
    }
}

/// ОДИН краевой прибор: гейт молчания работает — беда называется РОВНО ОДИН раз.
#[test]
fn один_краевой_прибор_говорит_единожды() {
    let blackhole = EdgeSilence::<Silent>::new(Duration::from_secs(2), layout());
    let mut mark = 0u32;
    let mut said = Vec::new();

    for age in [500u64, 2_500, 3_000, 3_500] {
        let (_m, (memo, spoken), ()) = blackhole.step(packet(mark, age));
        if let Some(memo) = memo {
            mark = memo.apply_to(mark);
        }
        said.extend(spoken);
    }

    println!("один прибор сказал: {said:?}");
    assert_eq!(said.len(), 1, "гейт молчания: беда называется единожды");
}

/// ДВА краевых прибора с разными окнами — та же марка, тот же разговор. Гейта молчания не
/// остаётся: каждый пакет приносит беду заново.
#[test]
fn два_писателя_над_одной_маркой_ломают_гейт_молчания() {
    let blackhole = EdgeSilence::<Silent>::new(Duration::from_secs(2), layout());
    let silence = EdgeSilence::<Silent>::new(Duration::from_secs(5), layout());
    let mut mark = 0u32;
    let mut said = Vec::new();

    for age in [500u64, 2_500, 3_000, 3_500] {
        // Оба видят ОДНУ марку — как в цикле: `edge` едет с пакетом, не перечитывается.
        let (_m, (memo_b, spoken_b), ()) = blackhole.step(packet(mark, age));
        let (_m, (memo_s, spoken_s), ()) = silence.step(packet(mark, age));
        // `reflex/src/lib.rs:1457`: memo = remembered.or(memo) по порядку приборов — побеждает
        // сказавший последним.
        if let Some(memo) = memo_s.or(memo_b) {
            mark = memo.apply_to(mark);
        }
        said.extend(spoken_b);
        said.extend(spoken_s);
    }

    println!("два прибора сказали: {said:?}");
    let blackholes = said
        .iter()
        .filter(|d| matches!(d, Distress::Blackhole { .. }))
        .count();
    assert_eq!(
        blackholes, 3,
        "причина запрета: беда называется на КАЖДОМ пакете, а не однажды — под `.act` это RST на \
         каждом пакете. Покраснело? Значит приборы научились делить марку, и гейт фасада \
         (`IntoProbe::Home`) подлежит пересмотру"
    );
}
