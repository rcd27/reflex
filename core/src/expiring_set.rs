//! ОТМЕТКИ С ИСТЕЧЕНИЕМ — множество ключей, где принадлежность живёт TTL и продлевается лишь
//! ЯВНОЙ отметкой (проекция `model/molecule/SightBeforeSeizure.tla`: `markAge` / `Expire` / ось
//! `Evict`).
//!
//! ЗАЧЕМ ОТДЕЛЬНЫЙ ПРИМИТИВ. Ближайший сосед — [`crate::flow_table::FlowTable`] — умеет эвиктить по
//! простою, но приколочен к `Detector`/`TcpSegment`/5-tuple: это таблица ПОТОКОВ, а нужен набор
//! КЛЮЧЕЙ. По мета-триггеру REFLEX-FIRST general-purpose примитив строится здесь и тестируется в
//! изоляции, а потребитель (карта лифта невода) его лишь потребляет.
//!
//! ГЛАВНОЕ РЕШЕНИЕ API — продления по ОБРАЩЕНИЮ здесь НЕТ, и это не упущение. Модель показала
//! (клетка `hit-renew`): TTL с продлением попаданием даёт популярной, но ВЫЗДОРОВЕВШЕЙ цели
//! продлевать себя собственным трафиком — вечно. На языке `law/Mark` это `Licence = "Proxy"`: знак
//! лицензируется обращением, а обращение горит и без земли. Оттого [`ExpiringSet::contains`] берёт
//! `&self` — не «так вышло», а конструкция: продлить при чтении физически нечем.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

/// Исход попытки отметить ключ. Отдельный тип, а не `bool`/`()`: переполнение потолка обязано быть
/// СОБЫТИЕМ, иначе набор молча перестаёт принимать новое и выглядит как «нового больше нет».
///
/// # Почему `#[must_use]`, а не строка «потребитель обязан заметить» (05.09.2026)
///
/// Она здесь и стояла — у варианта [`Rejected`](Self::Rejected), прозой. Тип был заведён РОВНО
/// ради того, чтобы переполнение стало событием, и обеспечение этого оставили вниманию
/// вызывающего: `set.mark(k, now);` без всякого разбора собирался молча, и потолок снова
/// становился невидимым — та самая беда, от которой тип и заводили.
///
/// Атрибут переводит требование из прозы в высказывание компилятора. Он даёт ПРЕДУПРЕЖДЕНИЕ, а не
/// отказ, и это названо прямо: сильнее в Rust не выразить — заставить потребить значение язык не
/// умеет. Но «компилятор сказал» и «в доке было написано» — разные вещи, и второе не читают.
///
/// ```compile_fail
/// #![deny(unused_must_use)]
/// use reflex_core::expiring_set::ExpiringSet;
/// use std::time::Instant;
///
/// // Исход брошен: потолок исчерпан или нет — вызывающий не узнает.
/// fn blind(set: &mut ExpiringSet<u32>) {
///     set.mark(1, Instant::now());
/// }
/// ```
#[must_use = "Rejected значит, что отметка НЕ поставлена: потолок исчерпан, и брошенный исход \
              делает переполнение невидимым — ровно то, ради чего этот тип заведён"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marking {
    /// Ключа не было — отметка поставлена впервые.
    Fresh,
    /// Ключ уже был — срок жизни отсчитывается заново от этого момента.
    Renewed,
    /// Потолок исчерпан, а ключ новый: отметка НЕ поставлена. Потребитель обязан это заметить.
    Rejected,
}

pub struct ExpiringSet<K> {
    marked: HashMap<K, Instant>, // ключ → момент последней ЯВНОЙ отметки
    ttl: Duration,
    capacity: usize,
}

impl<K: Eq + Hash + Clone> ExpiringSet<K> {
    /// `ttl` — сколько отметка живёт без явного продления. `capacity` — потолок: он есть у всякого
    /// набора (у потребителя это ёмкость eBPF-карты), и притворяться, что его нет, значит узнать о
    /// нём в момент отказа.
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            marked: HashMap::new(),
            ttl,
            capacity,
        }
    }

    /// Поставить или продлить отметку. ЕДИНСТВЕННЫЙ путь продления — отсюда и смысл: продлевает
    /// свежее знание о ключе, а не факт обращения к нему.
    pub fn mark(&mut self, key: K, now: Instant) -> Marking {
        match self.marked.insert(key.clone(), now) {
            Some(_previous) => Marking::Renewed,
            None if self.marked.len() <= self.capacity => Marking::Fresh,
            // Перебор потолка: откатываем вставку — набор обязан остаться в границах, о которых
            // договорился потребитель, иначе его карта в ядре переполнится раньше нашей.
            None => {
                self.marked.remove(&key);
                Marking::Rejected
            }
        }
    }

    /// Снять истёкшие и вернуть их ключи. Возврат, а не молчаливая уборка: потребитель держит
    /// ВТОРУЮ копию набора (карта в ядре), и снятие обязано доехать до неё — иначе набор чист,
    /// а датаплейн по-прежнему лифтит.
    pub fn sweep(&mut self, now: Instant) -> Vec<K> {
        let expired: Vec<K> = self
            .marked
            .iter()
            .filter(|(_, marked_at)| now.duration_since(**marked_at) >= self.ttl)
            .map(|(key, _)| key.clone())
            .collect();
        expired.iter().for_each(|key| {
            self.marked.remove(key);
        });
        expired
    }

    /// Отмечен ли ключ. `&self` НАМЕРЕННО: чтение не продлевает (см. шапку модуля).
    pub fn contains(&self, key: &K) -> bool {
        self.marked.contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.marked.len()
    }

    pub fn is_empty(&self) -> bool {
        self.marked.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{ExpiringSet, Marking};
    use std::time::{Duration, Instant};

    const TTL: Duration = Duration::from_secs(600);

    #[test]
    fn отметка_живёт_ttl_и_снимается_после() {
        let t0 = Instant::now();
        let mut set = ExpiringSet::new(TTL, 8);
        assert_eq!(set.mark("87.245.200.1", t0), Marking::Fresh);

        // За миг до срока — держится, и sweep её НЕ трогает.
        assert!(set.sweep(t0 + TTL - Duration::from_millis(1)).is_empty());
        assert!(set.contains(&"87.245.200.1"));

        // По достижении срока — снята, и ключ ВОЗВРАЩЁН: потребителю нужно убрать его у себя.
        assert_eq!(set.sweep(t0 + TTL), vec!["87.245.200.1"]);
        assert!(!set.contains(&"87.245.200.1"));
    }

    #[test]
    fn продление_отодвигает_истечение() {
        let t0 = Instant::now();
        let mut set = ExpiringSet::new(TTL, 8);
        // ПЕРВАЯ ОТМЕТКА ТОЖЕ УТВЕРЖДАЕТСЯ. Прежде её исход бросали, и тест молча прошёл бы даже
        // при `Rejected` — то есть проверял бы продление на ключе, которого в наборе нет.
        assert_eq!(set.mark("cache", t0), Marking::Fresh);
        assert_eq!(set.mark("cache", t0 + TTL / 2), Marking::Renewed);

        // Срок считается от ПОСЛЕДНЕЙ отметки, а не от первой.
        assert!(set.sweep(t0 + TTL).is_empty());
        assert_eq!(set.sweep(t0 + TTL + TTL / 2), vec!["cache"]);
    }

    #[test]
    fn чтение_НЕ_продлевает() {
        // Клетка `hit-renew` модели: если бы обращение продлевало, выздоровевшая, но популярная
        // цель осталась бы отмеченной навсегда. Здесь читаем часто — и всё равно истекаем.
        let t0 = Instant::now();
        let mut set = ExpiringSet::new(TTL, 8);
        assert_eq!(set.mark("популярная", t0), Marking::Fresh);
        (1..10).for_each(|i| {
            assert!(set.contains(&"популярная"), "тик {i}: пока жива");
        });
        assert_eq!(set.sweep(t0 + TTL), vec!["популярная"]);
    }

    #[test]
    fn переполнение_потолка_есть_событие_а_не_тишина() {
        let t0 = Instant::now();
        let mut set = ExpiringSet::new(TTL, 2);
        assert_eq!(set.mark("a", t0), Marking::Fresh);
        assert_eq!(set.mark("b", t0), Marking::Fresh);
        // Третий ключ не помещается — и об этом СКАЗАНО, а не проглочено.
        assert_eq!(set.mark("c", t0), Marking::Rejected);
        assert!(!set.contains(&"c"));
        assert_eq!(set.len(), 2, "набор остаётся в границах потолка");

        // Продление УЖЕ отмеченного проходит и при полном наборе: иначе полный набор перестал бы
        // обновляться и истёк бы весь разом.
        assert_eq!(set.mark("a", t0 + TTL / 2), Marking::Renewed);

        // Освободилось место — новый ключ снова принимается.
        assert_eq!(set.sweep(t0 + TTL), vec!["b"]);
        assert_eq!(set.mark("c", t0 + TTL), Marking::Fresh);
    }

    #[test]
    fn sweep_возвращает_только_истёкшие() {
        let t0 = Instant::now();
        let mut set = ExpiringSet::new(TTL, 8);
        assert_eq!(set.mark("старая", t0), Marking::Fresh);
        assert_eq!(set.mark("свежая", t0 + TTL / 2), Marking::Fresh);

        assert_eq!(set.sweep(t0 + TTL), vec!["старая"]);
        assert!(set.contains(&"свежая"), "свежую сносить нельзя");
    }
}
