//! Соответствие «адрес → имя», собранное из наблюдённых ответов DNS. Ключ цели — ИМЯ (§4), а на
//! проводе после разрешения остаётся один адрес: без этой карты связь «пакет → цель» теряется
//! вместе с ответом, который её назвал.
//!
//! Карта ограничена ОБОИМИ краями, и края разные по природе. Срок (`ttl`) берётся из самого ответа:
//! имя, пережившее свой TTL, называет уже не ту цель. Число записей — наш предел: наблюдатель
//! ответов на объём чужого трафика не влияет, а память обязана остаться конечной (канон §4).
//!
//! ЧАСЫ ЗДЕСЬ ТЕ ЖЕ, ЧТО У ВСЕГО ДЕРЕВА (`Instant`/`Duration`, §8), хотя TTL приходит с провода
//! числом секунд. Дверь, берущая своё время, заставляет потребителя завести второе — а он собрал
//! цепочку на часах носителя, и сводить их пришлось бы ему, молча и у себя. Тот же приём уже
//! применён к более трудному случаю: [`crate::pcap::read`] переводит штампы чужой записи в
//! `base + Duration`, оставляя календарь отдельным полем.
//!
//! Тип попутно снимает клетку, которой у предмета нет: у моментов времени не бывает
//! несравнимости, и порядок вытеснения больше не решает, что делать с `NaN`.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

struct Entry {
    domain: String,
    expires_at: Instant,
    inserted_at: Instant,
}

pub struct DnsCache {
    entries: HashMap<Ipv4Addr, Entry>,
    max_entries: usize,
}

impl DnsCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
        }
    }

    /// Ответ ложится ЦЕЛИКОМ: все адреса одного имени, а не первый из них. Отвечающий вправе
    /// раздать имя по нескольким адресам и раздавать их в разном порядке — взяв один, мы потеряли
    /// бы цель ровно на тех пакетах, что ушли к остальным.
    ///
    /// Тесно становится ПОСЛЕ вставки, не вместо неё: свежий ответ входит всегда, а место под него
    /// освобождают старые. Иначе полная карта перестала бы узнавать новое — и тем прочнее, чем
    /// дольше живёт.
    pub fn insert(&mut self, domain: &str, ips: &[Ipv4Addr], ttl: Duration, now: Instant) {
        for &ip in ips {
            self.entries.insert(
                ip,
                Entry {
                    domain: domain.to_owned(),
                    expires_at: now + ttl,
                    inserted_at: now,
                },
            );
        }

        while self.entries.len() > self.max_entries {
            self.evict_oldest();
        }
    }

    /// Истёкшая запись отвечает `None`, но из карты не уходит: чтение карту не правит. Уборка —
    /// отдельный шаг ([`DnsCache::cleanup`]), и зовёт его тот, кто знает свой темп.
    pub fn lookup(&self, ip: Ipv4Addr, now: Instant) -> Option<&str> {
        let entry = self.entries.get(&ip)?;
        if now <= entry.expires_at {
            Some(entry.domain.as_str())
        } else {
            None
        }
    }

    pub fn cleanup(&mut self, now: Instant) {
        self.entries.retain(|_, entry| now <= entry.expires_at);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Порядок вытеснения — по времени ВСТАВКИ, не по последнему чтению: срок записи назначил
    /// отвечающий, и наше обращение к ней его не продлевает.
    fn evict_oldest(&mut self) {
        let oldest_ip = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.inserted_at)
            .map(|(&ip, _)| ip);

        if let Some(ip) = oldest_ip {
            self.entries.remove(&ip);
        }
    }
}
