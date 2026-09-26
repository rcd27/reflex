//! ХРОНОЛОГИЯ ФАКТОВ (#348): прошлое машины — свёрткой, сроки — формулами над ней. Своих часов нет:
//! хронология только помнит моменты событий, а «который час» ей говорят аргументом.
//!
//! Закон (#348, «Закон среза 2»):
//! - сводка — `first`/`last` момент каждого рода событий (полурешётки min/max) и счёт серий
//!   ([`Runs`]); истинность часовой охраны зависит только от сводки и `now` (Т1);
//! - часовая охрана [`Since`] — монотонная ступенька по `now` с порогом `last + after`, поэтому
//!   ближайший момент смены любой охраны — [`due`] — выводится, а не пишется рукой (Т2): тот, кто
//!   будит машину, и тот, кто судит, считают одну формулу;
//! - тишина трёхзначна ([`Chronology::quiet`]): «события не было» утверждается только опросом,
//!   сделанным после начала окна (Т5).
//!
//! Сторож: `core/tests/chronology.rs`.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crate::sight::Told;

/// Первый и последний момент каждого рода событий.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chronology<K: Ord> {
    first: BTreeMap<K, Instant>,
    last: BTreeMap<K, Instant>,
}

impl<K: Ord> Default for Chronology<K> {
    fn default() -> Self {
        Chronology {
            first: BTreeMap::new(),
            last: BTreeMap::new(),
        }
    }
}

impl<K: Ord + Clone> Chronology<K> {
    /// Событие рода `kind` в момент `at`.
    pub fn noted(self, kind: K, at: Instant) -> Chronology<K> {
        let first = self.first.get(&kind).map_or(at, |seen| (*seen).min(at));
        let last = self.last.get(&kind).map_or(at, |seen| (*seen).max(at));
        Chronology {
            first: with(self.first, kind.clone(), first),
            last: with(self.last, kind, last),
        }
    }

    pub fn first(&self, kind: &K) -> Option<Instant> {
        self.first.get(kind).copied()
    }

    pub fn last(&self, kind: &K) -> Option<Instant> {
        self.last.get(kind).copied()
    }

    /// Было ли событие `event` в окне `window` до `now`. `Told(момент)` — было; `Nothing` — не было,
    /// и это знает опрос `probe`, сделанный после начала окна; `Blind` — опроса в окне не было, и
    /// отсутствие события ничего не значит. Утверждается отсутствие события от начала окна до
    /// последнего опроса: рождённое после опроса увидит следующий.
    pub fn quiet(&self, event: &K, probe: &K, window: Duration, now: Instant) -> Told<Instant> {
        let inside = |moment: Instant| now.checked_sub(window).is_none_or(|start| moment >= start);
        match (
            self.last(event).filter(|moment| inside(*moment)),
            self.last(probe).is_some_and(inside),
        ) {
            (Some(moment), _probed) => Told::Told(moment),
            (None, true) => Told::Nothing,
            (None, false) => Told::Blind,
        }
    }
}

/// ЧАСОВАЯ ОХРАНА: с последнего события `from` прошло не меньше `after`. Не было события — ложна.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Since<K> {
    pub from: K,
    pub after: Duration,
}

impl<K: Ord + Clone> Since<K> {
    pub fn holds(&self, chrono: &Chronology<K>, now: Instant) -> bool {
        self.flips(chrono).is_some_and(|flip| now >= flip)
    }

    /// Момент, с которого охрана истинна.
    pub fn flips(&self, chrono: &Chronology<K>) -> Option<Instant> {
        chrono.last(&self.from).map(|last| last + self.after)
    }
}

/// КОГДА БУДИТЬ: ближайший после `now` момент смены истинности любой из охран. `None` — без нового
/// события ни одна охрана не сменится.
pub fn due<K: Ord + Clone>(
    guards: &[Since<K>],
    chrono: &Chronology<K>,
    now: Instant,
) -> Option<Instant> {
    guards
        .iter()
        .filter_map(|guard| guard.flips(chrono))
        .filter(|flip| *flip > now)
        .min()
}

/// СЕРИИ: сколько неудач подряд у каждого рода с последнего сброса. Сбрасывает только явный
/// [`Runs::reset`] — у времени правила сброса нет (Т3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Runs<K: Ord>(BTreeMap<K, u32>);

impl<K: Ord> Default for Runs<K> {
    fn default() -> Self {
        Runs(BTreeMap::new())
    }
}

impl<K: Ord> Runs<K> {
    pub fn bumped(self, kind: K) -> Runs<K> {
        let count = self.of(&kind) + 1;
        Runs(with(self.0, kind, count))
    }

    pub fn reset(self, kind: &K) -> Runs<K> {
        Runs(
            self.0
                .into_iter()
                .filter(|(held, _count)| held != kind)
                .collect(),
        )
    }

    pub fn of(&self, kind: &K) -> u32 {
        self.0.get(kind).copied().unwrap_or(0)
    }
}

fn with<K: Ord, V>(map: BTreeMap<K, V>, key: K, value: V) -> BTreeMap<K, V> {
    map.into_iter()
        .chain(std::iter::once((key, value)))
        .collect()
}
