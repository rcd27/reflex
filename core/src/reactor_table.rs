//! Владеющая по-ключу таблица `Reactor`-состояний — синхронный сиблинг `flow_table::FlowTable`
//! (тот же идиом: `remove` → `step` → `insert`), но generic по ключу и связан с `Reactor`, не
//! `Detector`: `Reactor::start()` — контракт trait'а без аргументов (в отличие от `Detector`,
//! которому конструктор-замыкание нужен, чтобы засеять ключ в состояние — оттого `FlowTable`
//! носит `make_detector: Fn(Flow) -> D`, здесь этого не нужно).
//!
//! Закрывает дыру: единственный владеющий контейнер с синхронным `get()` в рефлексе был приколочен
//! к `Detector`+`Flow` (`FlowTable`); `group_by_reactor` — чисто-поточный комбинатор без внешнего
//! чтения. Доменному коду с `Reactor`-атомом и нуждой в синхронном запросе по ключу (напр.
//! `ladder::registry` в nevod-poc) нужен был именно этот контейнер.

use std::collections::HashMap;
use std::hash::Hash;

use crate::reactor::Reactor;

pub struct ReactorTable<K, R: Reactor> {
    states: HashMap<K, R>,
}

impl<K: Hash + Eq + Clone, R: Reactor> ReactorTable<K, R> {
    pub fn new() -> Self {
        Self {
            states: HashMap::new(),
        }
    }

    /// Применяет событие к состоянию ключа `key` (свежий `R::start()`, если ключ новый).
    pub fn step(&mut self, key: K, event: R::Event) -> Option<R::Effect> {
        let state = self.states.remove(&key).unwrap_or_else(|| R::start().0);
        let (next, fx) = state.step(event);
        self.states.insert(key, next);
        fx
    }

    /// Синхронное чтение текущего состояния ключа — `None`, если ключ ещё не заводился.
    pub fn get(&self, key: &K) -> Option<&R> {
        self.states.get(key)
    }
}

impl<K: Hash + Eq + Clone, R: Reactor> Default for ReactorTable<K, R> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Counter(i32);

    impl Reactor for Counter {
        type Event = i32;
        type Effect = i32;

        fn start() -> (Self, Option<i32>) {
            (Counter(0), Some(0))
        }

        fn step(self, delta: i32) -> (Self, Option<i32>) {
            let next = Counter(self.0 + delta);
            (next, Some(next.0))
        }
    }

    /// Незаведённый ключ — `get()` пуст, никакого фантомного состояния.
    #[test]
    fn get_on_unknown_key_is_none() {
        let table: ReactorTable<&str, Counter> = ReactorTable::new();
        assert!(table.get(&"a").is_none());
    }

    /// Первое `step` на ключе синтезирует свежий `R::start()`, затем применяет событие.
    #[test]
    fn step_on_fresh_key_starts_then_applies() {
        let mut table: ReactorTable<&str, Counter> = ReactorTable::new();
        let fx = table.step("a", 5);
        assert_eq!(fx, Some(5));
        assert_eq!(table.get(&"a"), Some(&Counter(5)));
    }

    /// Ключи независимы: `step` одного не красит состояние соседа.
    #[test]
    fn keys_are_independent() {
        let mut table: ReactorTable<&str, Counter> = ReactorTable::new();
        table.step("a", 1);
        table.step("b", 10);
        assert_eq!(table.get(&"a"), Some(&Counter(1)));
        assert_eq!(table.get(&"b"), Some(&Counter(10)));
    }

    /// Состояние ключа накапливается по последовательным `step`.
    #[test]
    fn state_accumulates_across_steps() {
        let mut table: ReactorTable<&str, Counter> = ReactorTable::new();
        table.step("a", 1);
        table.step("a", 2);
        assert_eq!(table.get(&"a"), Some(&Counter(3)));
    }
}
