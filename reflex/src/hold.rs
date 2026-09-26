//! УДЕРЖАНИЕ (#348): пакеты разговора, чья личность ещё собирается из кусков, остаются у носителя,
//! а ответ им выносится разом, когда она собралась, — по порядку прихода и одним решением двери.
//! Кусок приветствия, отпущенный до имени, уходит без решения: движок видит его чужим, и имя
//! уходит к фильтру открытым (стенд 26.09: 0 из 62 таких разговоров получили данные).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use reflex_core::mark::Marked;
use reflex_core::types::Flow;

/// Сколько держать, если личность так и не собралась: хвост приветствия потерян, и клиент
/// повторит его сам. Дольше — человек платит задержкой разговора, который мы всё равно не назвали.
pub(crate) const HOLD: Duration = Duration::from_secs(1);

/// Сколько разговоров держать разом. Сверх — пакет отвечается сразу, как без удержания: держать
/// всё значило бы переполнить очередь ядра, а она при переполнении роняет пакеты человека.
pub(crate) const HOLDING: usize = 1_024;

/// Сколько пакетов одного разговора держать — столько, сколько кусков приветствия копит склейка.
pub(crate) const PIECES: usize = crate::HELLO_PIECES;

/// Удержанный пакет: знак носителя и всё, из чего собирается его ответ, кроме решения двери.
#[derive(Debug, Clone)]
pub(crate) struct Kept<K> {
    pub token: K,
    /// Память приборов, уже наложенная на марку разговора; `None` — приборам нечего помнить.
    pub remembered: Option<u32>,
    /// Марка, которую разговор нёс на этом пакете.
    pub mark: u32,
    pub at: Instant,
}

/// Удержанное одного разговора.
#[derive(Debug, Clone)]
pub(crate) struct Holding<K> {
    pub kept: Vec<Kept<K>>,
    /// Решение двери на последнем пакете — оно и выносится всем удержанным.
    pub decided: Option<Marked>,
    since: Instant,
}

/// Удержанное по разговорам.
#[derive(Debug)]
pub(crate) struct Holds<K>(HashMap<Flow, Holding<K>>);

impl<K> Default for Holds<K> {
    fn default() -> Holds<K> {
        Holds(HashMap::new())
    }
}

impl<K> Holds<K> {
    /// Держим ли уже что-то этого разговора: следующий его пакет держится за ним — порядок.
    pub fn holds(&self, flow: &Flow) -> bool {
        self.0.contains_key(flow)
    }

    /// Есть ли место удержать ещё пакет этого разговора.
    pub fn room(&self, flow: &Flow) -> bool {
        match self.0.get(flow) {
            Some(holding) => holding.kept.len() < PIECES,
            None => self.0.len() < HOLDING,
        }
    }

    /// Удержать пакет. Решение двери — последнее виденное: к имени оно и относится.
    pub fn kept(&mut self, flow: Flow, kept: Kept<K>, decided: Option<Marked>) {
        let since = kept.at;
        let holding = self.0.entry(flow).or_insert(Holding {
            kept: Vec::new(),
            decided: None,
            since,
        });
        holding.kept.push(kept);
        holding.decided = decided;
    }

    /// Разговоры, которые пора отпустить: личность собралась (`holding` ложь) или срок вышел.
    pub fn released(&mut self, holding: impl Fn(&Flow) -> bool, now: Instant) -> Vec<Holding<K>> {
        let due: Vec<Flow> = self
            .0
            .iter()
            .filter(|(flow, held)| {
                !holding(flow) || now.saturating_duration_since(held.since) >= HOLD
            })
            .map(|(flow, _held)| *flow)
            .collect();
        due.iter().filter_map(|flow| self.0.remove(flow)).collect()
    }
}
