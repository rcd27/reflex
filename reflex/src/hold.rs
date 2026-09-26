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

/// Сколько разговоров держать разом. Сверх — пакет отвечается сразу, как без удержания.
pub(crate) const HOLDING: usize = 512;

/// Сколько пакетов одного разговора держать: приветствие с ключом kyber (~1,8 КБ) — два-три куска
/// при MSS 1400, до восьми при MSS 536. Разговор, заполнивший место, отпускается в том же обороте,
/// и следующий его пакет встаёт за отпущенными — порядок переживает переполнение.
pub(crate) const PIECES: usize = 8;

/// Всё удержание в пакетах — вдвое меньше очереди ядра: при её переполнении `bypass` пускает
/// пакеты человека мимо движка, а место нужно и живому потоку.
#[cfg(unix)]
const _FITS_THE_QUEUE: () =
    assert!(HOLDING * PIECES * 2 <= reflex_linux::queue::QUEUE_MAXLEN as usize);

/// Удержанный пакет: знак носителя и всё, из чего собирается его ответ, кроме решения двери.
#[derive(Debug)]
pub(crate) struct Kept<K> {
    pub token: K,
    /// Память приборов, уже наложенная на марку разговора; `None` — приборам нечего помнить.
    pub remembered: Option<u32>,
    /// Марка, которую разговор нёс на этом пакете.
    pub mark: u32,
    pub at: Instant,
}

/// Отпущенный пакет и решение двери, которым отпущен весь его разговор.
#[derive(Debug)]
pub(crate) struct Released<K> {
    pub kept: Kept<K>,
    pub decided: Option<Marked>,
}

/// Удержанное одного разговора.
#[derive(Debug)]
struct Holding<K> {
    kept: Vec<Kept<K>>,
    /// Решение двери на последнем пакете — оно и выносится всем удержанным.
    decided: Option<Marked>,
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
    pub fn hold(&mut self, flow: Flow, kept: Kept<K>, decided: Option<Marked>) {
        let since = kept.at;
        let holding = self.0.entry(flow).or_insert(Holding {
            kept: Vec::new(),
            decided: None,
            since,
        });
        holding.kept.push(kept);
        holding.decided = decided;
    }

    /// Отпустить разговоры, которые пора: личность собралась (`holding` ложь), срок вышел к
    /// моменту носителя `now` или место кончилось.
    pub fn release(&mut self, holding: impl Fn(&Flow) -> bool, now: Instant) -> Vec<Released<K>> {
        let due: Vec<Flow> = self
            .0
            .iter()
            .filter(|(flow, held)| {
                !holding(flow)
                    || now.saturating_duration_since(held.since) >= HOLD
                    || held.kept.len() >= PIECES
            })
            .map(|(flow, _held)| *flow)
            .collect();
        due.iter()
            .filter_map(|flow| self.0.remove(flow))
            .flat_map(Holding::released)
            .collect()
    }

    /// Отпустить всё: носитель уходит, и ядро сбросило бы удержанное вместе с ним.
    pub fn drain(&mut self) -> Vec<Released<K>> {
        self.0
            .drain()
            .flat_map(|(_flow, holding)| holding.released())
            .collect()
    }
}

impl<K> Holding<K> {
    /// Удержанное разговора — по порядку прихода, с решением, которым отпущен весь разговор.
    fn released(self) -> impl Iterator<Item = Released<K>> {
        let decided = self.decided;
        self.kept
            .into_iter()
            .map(move |kept| Released { kept, decided })
    }
}
