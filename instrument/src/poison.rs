//! Детектор отравления DNS. Читает разобранное DNS-сообщение (`reflex_core::dns::DnsMessage`) — не
//! байты `Seen`: предмет в СОДЕРЖИМОМ ответа (код, наличие адреса), а не в объёме. На запрос пришёл
//! инжект — `NXDOMAIN` или пустой ответ вместо адреса. Отдельный пайп: через объёмные приборы не
//! выразить.
//!
//! ПОДОЗРЕНИЕ, не приговор — как повтор: легитимный `NXDOMAIN` (опечатка, несуществующее имя) даёт
//! ровно тот же ответ. Отличает оракул или кросс-резолвер (тот же запрос к другому DNS даёт адрес),
//! а это активная проба — живёт у потребителя, не в пассивном приборе. Здесь — факт провода:
//! «на наш запрос ответили отказом», названный подозрением.

use reflex_core::dns::{DnsDirection, DnsMessage};

use crate::distress::Distress;

/// Прибор отравления DNS. Состояние на разговор (id запроса ключует `FlowTable` снаружи): видели ли
/// запрос, жаловались ли. `NXDOMAIN`/пустой ответ на виденный запрос — подозрение.
#[derive(Debug, Clone, Copy, Default)]
pub struct DnsPoisonInstrument {
    /// Запрос видели — есть на что мерить ответ.
    asked: bool,
    fired: bool,
}

impl DnsPoisonInstrument {
    pub fn new() -> Self {
        Self::default()
    }
}

impl reflex_core::mealy::Mealy for DnsPoisonInstrument {
    type In = reflex_core::DetectorEvent<DnsMessage>;
    type Out = smallvec::SmallVec<[Distress; 2]>;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        let (state, signals) = match event {
            reflex_core::DetectorEvent::Packet { input, .. } => match input.direction {
                // Запрос открывает отсчёт: без него ответ мерить не от чего (поток с середины).
                DnsDirection::Query => (
                    Self {
                        asked: true,
                        ..self
                    },
                    smallvec::SmallVec::new(),
                ),
                DnsDirection::Response => {
                    // Отказ — это `NXDOMAIN` (rcode 3) либо «есть ответ, а адреса нет» (пустой).
                    let refused = input.rcode == 3 || input.answers.is_empty();
                    match (self.asked, self.fired, refused) {
                        (true, false, true) => (
                            Self {
                                fired: true,
                                ..self
                            },
                            smallvec::smallvec![Distress::Poisoned],
                        ),
                        // Запроса не видели, уже жаловались, либо ответ с адресом — не наш случай.
                        (false, _, _) | (_, true, _) | (_, _, false) => {
                            (self, smallvec::SmallVec::new())
                        }
                    }
                }
            },
            // Обе оси обвинения положительны: запрос ВИДЕЛИ (`asked`) и отказ ВИДЕЛИ (`refused`).
            // Прячущая буква может лишь снять одну из них и заставить прибор промолчать — выдумать
            // отравление она не может. Ослеплять нечего (§7, Д7).
            // Инжект сам есть момент: часы не нужны. Непонятое — не DNS.
            reflex_core::DetectorEvent::Tick { .. }
            | reflex_core::DetectorEvent::Opaque { .. }
            | reflex_core::DetectorEvent::Torn { .. } => (self, smallvec::SmallVec::new()),
        };
        (state, signals, ())
    }
}

impl crate::Instrument for DnsPoisonInstrument {
    type Signal = Distress;

    const INSTRUMENT: &'static str = "dns_poison";

    /// О мире: отравляют ответ снаружи.
    const SUBJECT: crate::Subject = crate::Subject::World;

    /// Уровень имени: предмет — разрешение имени, не транспорт.
    const LAYER: crate::Layer = crate::Layer::Session;

    /// DNS обычно поверх UDP.
    const PROTOCOLS: &'static [crate::Protocol] = &[crate::Protocol::Udp];

    /// Не ступень соединения: DNS случается до всякого рукопожатия.
    const RUNG: Option<crate::Rung> = None;

    /// Чужой темп: инжект приходит ответом, не по нашему тику.
    const CADENCE: crate::Cadence = crate::Cadence::Foreign;

    /// Событие: отказ уже пришёл.
    const SHAPE: crate::Shape = crate::Shape::Event;

    /// Прибор смотрел: запрос был, отказа на него не пришло.
    const SILENCE: Option<crate::Silence> = Some(crate::Silence::Nothing);

    const LIES: &'static [&'static str] = &[
        "НЕ РАЗЛИЧАЕТ ИНЖЕКТ ОТ ЛЕГИТИМНОГО `NXDOMAIN`. Несуществующее имя (опечатка, снятый домен) \
         даёт ровно тот же отказ. Показание — ПОДОЗРЕНИЕ; приговор требует оракула или кросс-\
         резолвера (тот же запрос к другому DNS даёт адрес).",
        "ПАССИВНОГО ПРИЗНАКА ДВОЙНОГО ОТВЕТА НЕ ИСПОЛЬЗУЕТ. Канонический oracle-free признак инжекта \
         — второй ответ на один запрос — на вантаже подавлен (настоящий ответ не доходит), потому \
         прибор судит по одиночному отказу.",
    ];

    const ORACLES: &'static [&'static str] = &["dns_nxdomain(nnmclub.to)", "pass"];

    const DEATH: &'static str =
        "заведён кросс-резолвер либо оракул адреса; подозрение об инжекте стало приговором";

    const EVENTS: &'static [&'static str] = &["poisoned"];

    fn name(signal: &Self::Signal) -> &'static str {
        signal.name()
    }

    fn alarming(signal: &Self::Signal) -> bool {
        signal.alarming()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reflex_core::dns::{DnsDirection, DnsMessage};
    use reflex_core::mealy::Mealy;
    use reflex_core::DetectorEvent;
    use std::time::Instant;

    fn msg(direction: DnsDirection, rcode: u8, answers: usize) -> DnsMessage {
        DnsMessage {
            id: 0x1234,
            direction,
            rcode,
            queries: vec![reflex_core::dns::DnsQuery {
                name: "nnmclub.to".into(),
                qtype: 1,
                qclass: 1,
            }],
            answers: (0..answers)
                .map(|_| reflex_core::dns::DnsAnswer {
                    name: "nnmclub.to".into(),
                    rtype: 1,
                    rclass: 1,
                    ttl: 60,
                    rdata: vec![1, 2, 3, 4],
                })
                .collect(),
        }
    }

    fn run(script: Vec<DnsMessage>) -> Vec<Distress> {
        let at = Instant::now();
        script
            .into_iter()
            .fold(
                (DnsPoisonInstrument::new(), Vec::new()),
                |(state, said), m| {
                    let (stepped, signals, ()) = state.step(DetectorEvent::Packet { input: m, at });
                    (stepped, said.into_iter().chain(signals).collect())
                },
            )
            .1
    }

    /// NXDOMAIN на наш запрос — подозрение на отравление.
    #[test]
    fn nxdomain_after_a_query_is_suspected_poisoning() {
        let said = run(vec![
            msg(DnsDirection::Query, 0, 0),
            msg(DnsDirection::Response, 3, 0),
        ]);
        assert_eq!(said, vec![Distress::Poisoned]);
    }

    /// Настоящий ответ с адресом — не отравление.
    #[test]
    fn a_real_answer_is_not_poisoning() {
        let said = run(vec![
            msg(DnsDirection::Query, 0, 0),
            msg(DnsDirection::Response, 0, 2),
        ]);
        assert!(said.is_empty());
    }

    /// Ответ без виденного запроса (поток с середины) — своей слепоты за факт не выдаём.
    #[test]
    fn a_response_without_a_seen_query_is_silent() {
        let said = run(vec![msg(DnsDirection::Response, 3, 0)]);
        assert!(said.is_empty());
    }
}
