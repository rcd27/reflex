//! Копредел по слою: слово о ЦЕЛИ как сведение слов о её разговорах. Канон §4 —
//! `Target ≅ ∐_{k} Conversation`, подъём вверх по расслоению; §5 — наблюдения суть слова, и подъём
//! есть их сведение.
//!
//! ФОРМА здесь наша, СОДЕРЖАНИЕ — потребителя: [`Layer::join`] собирает слова слоя и отдаёт их
//! свёртке, поданной снаружи ЗНАЧЕНИЕМ. Какое слово рождается — «молчат все», «молчит доля»,
//! «молчит хоть один» — описание угрозы, а не механики; фреймворк называет копредел, не угрозу.
//!
//! Вывод не зависит ни от порядка, ни от кратности прихода слов, и свойств этих два с разными
//! хозяевами. **Кратность гасит хранилище**: слой держит ПОСЛЕДНЕЕ слово каждого разговора, повтор
//! заменяет его, а не множит. **От свёртки остаётся быть функцией множества** — порядок ей не
//! виден. Оттого «молчит доля» законна наравне с «молчат все»: как операция доля не идемпотентна,
//! но она функция множества, а кратность уже снята. (Ограничь свёртку join'ом §5 — оба свойства дал
//! бы сам §5; свобода богаче join'а, и дедуп есть её цена.)
//!
//! Та же карта даёт и второе: последнее слово на разговор — это ТЕКУЩИЙ СНИМОК, а не история.
//! Разговор ожил, и его слово сменилось. Этим слово о цели остаётся наблюдением, а не накоплением
//! знания; годность накопленного — суждение, и оно живёт у потребителя, не здесь.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::word::Base;

/// Слова узкой области, разложенные по ключу широкой. `Narrow` — то, о чём сказано (разговор),
/// `Wide` — то, подо что сводится (цель), `W` — само слово.
pub struct Layer<Narrow: Base, Wide: Base, W> {
    said: HashMap<Wide::Fibre, HashMap<Narrow::Fibre, (W, Instant)>>,
}

impl<Narrow: Base, Wide: Base, W> Default for Layer<Narrow, Wide, W>
where
    Wide::Fibre: Clone,
    Narrow::Fibre: Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<Narrow: Base, Wide: Base, W> Layer<Narrow, Wide, W>
where
    Wide::Fibre: Clone,
    Narrow::Fibre: Clone,
{
    pub fn new() -> Self {
        Layer {
            said: HashMap::new(),
        }
    }

    /// Запомнить последнее слово разговора. Момент приходит аргументом — своих часов у слоя нет
    /// (§8), а без момента нечем было бы отличить затихший разговор от живого.
    pub fn saw(&mut self, wide: Wide::Fibre, narrow: Narrow::Fibre, said: W, at: Instant) {
        self.said
            .entry(wide)
            .or_default()
            .insert(narrow, (said, at));
    }

    /// Свести слова слоя поданной свёрткой. `None` — слов нет вовсе: «сказать нечего» и «свелось в
    /// ничто» разные вещи, и свёртке пустого множества не показываем.
    pub fn join<U>(&self, wide: &Wide::Fibre, fold: impl Fn(&[&W]) -> Option<U>) -> Option<U> {
        let slice = self.said.get(wide)?;
        match slice
            .values()
            .map(|(said, _at)| said)
            .collect::<Vec<&W>>()
            .as_slice()
        {
            [] => None,
            words => fold(words),
        }
    }

    /// Снять затихшие разговоры и вернуть цели, у которых не осталось ни одного. Срок здесь
    /// РЕСУРСНЫЙ: слово о цели живёт, пока живут слова её разговоров. Отдельного срока у цели нет —
    /// он был бы сроком годности, то есть суждением, а суждение не наше.
    pub fn forget_idle(&mut self, idle: Duration, now: Instant) -> Vec<Wide::Fibre> {
        self.said.values_mut().for_each(|slice| {
            slice.retain(|_narrow, (_said, at)| now.duration_since(*at) < idle);
        });
        let gone: Vec<Wide::Fibre> = self
            .said
            .iter()
            .filter(|(_wide, slice)| slice.is_empty())
            .map(|(wide, _slice)| wide.clone())
            .collect();
        gone.iter().for_each(|wide| {
            self.said.remove(wide);
        });
        gone
    }

    /// Цели, о разговорах которых есть что сказать. Нужен зовущему, чтобы обойти слои: свести можно
    /// лишь то, о чём слова уже есть, и спрашивать цель, которой в слое нет, незачем.
    pub fn targets(&self) -> impl Iterator<Item = &Wide::Fibre> {
        self.said.keys()
    }

    /// Момент самого свежего из слов цели. Возраст слова о цели берётся ОТСЮДА, а не из свёртки:
    /// свёртка — потребителя, она видит слова и не видит моментов, и требовать от неё вернуть время
    /// значило бы просить описание угрозы говорить о часах (§8). `None` — слов нет.
    pub fn freshest(&self, wide: &Wide::Fibre) -> Option<Instant> {
        self.said.get(wide)?.values().map(|(_said, at)| *at).max()
    }

    /// Забыть один разговор — его слово больше не участвует в сведении.
    pub fn forget(&mut self, wide: &Wide::Fibre, narrow: &Narrow::Fibre) {
        if let Some(slice) = self.said.get_mut(wide) {
            slice.remove(narrow);
        }
    }
}
