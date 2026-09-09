//! Отметки с истечением — множество ключей, где принадлежность живёт TTL и продлевается лишь ЯВНОЙ
//! отметкой. Отдельный примитив: сосед [`crate::flow_table::FlowTable`] эвиктит по простою, но
//! приколочен к `TcpSegment`/5-tuple (таблица ПОТОКОВ), а нужен набор КЛЮЧЕЙ. Продления по ОБРАЩЕНИЮ
//! здесь нет намеренно: TTL с продлением попаданием даёт популярной, но ВЫЗДОРОВЕВШЕЙ цели продлевать
//! себя собственным трафиком вечно. Оттого [`ExpiringSet::contains`] берёт `&self` — не «так вышло»,
//! а конструкция: продлить при чтении физически нечем.
//!
//! Срок ИСПОЛНЯЕТСЯ САМ: `mark` и `contains` сверяются с возрастом, момент принимая аргументом.
//! Прежде он жил только в `sweep`, то есть объявлялся докблоком, а исполнялся дисциплиной
//! вызывающего — и не позвавший подметание получал набор, у которого срок не наступает НИКОГДА,
//! молча. `sweep` остался при другой роли: доставить снятие во вторую копию набора.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

/// Исход попытки отметить ключ. Отдельный тип, не `bool`/`()`: переполнение потолка обязано быть
/// СОБЫТИЕМ, иначе набор молча перестаёт принимать новое и выглядит как «нового больше нет».
/// `#[must_use]` переводит требование «потребитель обязан заметить» из прозы в высказывание
/// компилятора: `set.mark(k, now);` без разбора собирался бы молча, и потолок стал бы невидимым.
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

    /// Истекла ли отметка, поставленная в `at`, к моменту `now`. Момент приходит АРГУМЕНТОМ:
    /// своих часов у набора нет, иначе он читал бы мир мимо буквы события (§2, §8).
    fn expired(&self, at: Instant, now: Instant) -> bool {
        now.duration_since(at) >= self.ttl
    }

    /// Поставить или продлить отметку. ЕДИНСТВЕННЫЙ путь продления — отсюда и смысл: продлевает
    /// свежее знание о ключе, а не факт обращения к нему.
    ///
    /// Истёкшая отметка продлению не подлежит: продлить её значило бы воскресить, и срок пошёл бы
    /// от воскрешения — цель, о которой молчали дольше окна, осталась бы неуслышанной навсегда.
    /// Такая отметка снимается здесь же, поэтому потолок считает ЖИВЫХ: иначе `Rejected` значил бы
    /// «тесно памяти о мёртвых», а прочитан был бы как «тесно живым», и набор перестал бы принимать
    /// новое, имея место.
    pub fn mark(&mut self, key: K, now: Instant) -> Marking {
        // Своя истёкшая — не отметка; снимаем до всякого суждения.
        if self.marked.get(&key).is_some_and(|at| self.expired(*at, now)) {
            self.marked.remove(&key);
        }
        // Полная чистка стоит обхода набора, потому делается лишь на границе потолка — там, где
        // цена ошибки (отказ живому ключу) выше цены обхода.
        if !self.marked.contains_key(&key) && self.marked.len() >= self.capacity {
            let ttl = self.ttl;
            self.marked
                .retain(|_key, at| now.duration_since(*at) < ttl);
        }
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

    /// Снять истёкшие и ВЕРНУТЬ их ключи. Роль после того, как срок стал самоисполнимым, — не
    /// «применить TTL», а доставить снятие во ВТОРУЮ копию набора (карту в ядре у потребителя): та о
    /// наших часах не знает и узнаёт о снятии только отсюда — иначе набор чист, а датаплейн лифтит.
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

    /// Есть ли ЖИВАЯ отметка. Момент — аргументом, и `&self` при этом сохранён: сверка с возрастом
    /// не есть продление, а продлить чтением по-прежнему физически нечем. Прежде срок жил только в
    /// [`sweep`](Self::sweep), то есть закон объявлялся здесь, а исполнялся дисциплиной
    /// вызывающего: не позвавший подметание получал набор, у которого срок не наступает никогда.
    pub fn contains(&self, key: &K, now: Instant) -> bool {
        self.marked
            .get(key)
            .is_some_and(|at| !self.expired(*at, now))
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
        assert!(set.contains(&"87.245.200.1", t0 + TTL - Duration::from_millis(1)));

        // По достижении срока — снята, и ключ ВОЗВРАЩЁН: потребителю нужно убрать его у себя.
        assert_eq!(set.sweep(t0 + TTL), vec!["87.245.200.1"]);
        assert!(!set.contains(&"87.245.200.1", t0 + TTL));
    }

    #[test]
    fn продление_отодвигает_истечение() {
        let t0 = Instant::now();
        let mut set = ExpiringSet::new(TTL, 8);
        // ПЕРВАЯ ОТМЕТКА ТОЖЕ УТВЕРЖДАЕТСЯ, а не только вторая: бросить её исход значило бы
        // проверять продление на ключе, которого в наборе, быть может, и нет.
        assert_eq!(set.mark("cache", t0), Marking::Fresh);
        assert_eq!(set.mark("cache", t0 + TTL / 2), Marking::Renewed);

        // Срок считается от ПОСЛЕДНЕЙ отметки, а не от первой.
        assert!(set.sweep(t0 + TTL).is_empty());
        assert_eq!(set.sweep(t0 + TTL + TTL / 2), vec!["cache"]);
    }

    #[test]
    fn чтение_НЕ_продлевает() {
        // Если бы обращение продлевало, выздоровевшая, но популярная цель осталась бы отмеченной
        // навсегда. Здесь читаем часто — и всё равно истекаем.
        let t0 = Instant::now();
        let mut set = ExpiringSet::new(TTL, 8);
        assert_eq!(set.mark("популярная", t0), Marking::Fresh);
        (1..10).for_each(|i| {
            assert!(set.contains(&"популярная", t0 + TTL / 2), "тик {i}: пока жива");
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
        assert!(!set.contains(&"c", t0));
        assert_eq!(set.len(), 2, "набор остаётся в границах потолка");

        // Продление УЖЕ отмеченного проходит и при полном наборе: иначе полный набор перестал бы
        // обновляться и истёк бы весь разом.
        assert_eq!(set.mark("a", t0 + TTL / 2), Marking::Renewed);

        // Освободилось место — новый ключ снова принимается.
        assert_eq!(set.sweep(t0 + TTL), vec!["b"]);
        assert_eq!(set.mark("c", t0 + TTL), Marking::Fresh);
    }

    #[test]
    fn истёкшая_отметка_ставится_заново_а_не_продлевается() {
        // Продлить истёкшее — воскресить его: срок пошёл бы от воскрешения, и цель, о которой
        // молчали дольше окна, осталась бы неуслышанной навсегда.
        let t0 = Instant::now();
        let mut set = ExpiringSet::new(TTL, 8);
        assert_eq!(set.mark("цель", t0), Marking::Fresh);
        assert_eq!(
            set.mark("цель", t0 + TTL),
            Marking::Fresh,
            "срок вышел — это НОВАЯ отметка, а не продление старой"
        );
    }

    #[test]
    fn чтение_видит_срок_без_подметания() {
        // Срок исполняется сам. Пока он жил только в `sweep`, закон был объявлен здесь, а
        // исполнялся дисциплиной вызывающего — и не позвавший подметание получал набор, у
        // которого срок не наступает НИКОГДА.
        let t0 = Instant::now();
        let mut set = ExpiringSet::new(TTL, 8);
        assert_eq!(set.mark("цель", t0), Marking::Fresh);
        assert!(set.contains(&"цель", t0 + TTL - Duration::from_millis(1)));
        assert!(
            !set.contains(&"цель", t0 + TTL),
            "истекла — значит её нет, и подметание тут ни при чём"
        );
    }

    #[test]
    fn потолок_считает_живых_а_не_призраков() {
        // Иначе отказ значил бы «тесно ПАМЯТИ О МЁРТВЫХ», а прочитан был бы как «тесно живым»:
        // набор перестал бы принимать новое, имея место.
        let t0 = Instant::now();
        let mut set = ExpiringSet::new(TTL, 2);
        assert_eq!(set.mark("a", t0), Marking::Fresh);
        assert_eq!(set.mark("b", t0), Marking::Fresh);
        assert_eq!(
            set.mark("c", t0 + TTL),
            Marking::Fresh,
            "к этому моменту a и b истекли — место есть, подметания не было"
        );
    }

    #[test]
    fn sweep_возвращает_только_истёкшие() {
        let t0 = Instant::now();
        let mut set = ExpiringSet::new(TTL, 8);
        assert_eq!(set.mark("старая", t0), Marking::Fresh);
        assert_eq!(set.mark("свежая", t0 + TTL / 2), Marking::Fresh);

        assert_eq!(set.sweep(t0 + TTL), vec!["старая"]);
        assert!(set.contains(&"свежая", t0 + TTL), "свежую сносить нельзя");
    }
}
