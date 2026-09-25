//! ПАМЯТЬ ОТКРЫТИЙ: возраст разговора, когда ядро собрано без `nf_conntrack_timestamp` (NanoPi R2S,
//! OpenWrt 25.12: `age()` края всегда `None`). Правило подачи отдаёт очереди разговор с первого
//! пакета, и очередь видит `SYN` сама — момент его приёма и есть начало.
//!
//! Начало засчитывается, ТОЛЬКО если первым увиденным пакетом записи был `SYN` (`SYN_SENT` по слову
//! ядра): разговор, открытый до старта очереди, впервые приходит посредине, и счёт от первой встречи
//! сделал бы его моложе, чем он есть. Такой разговор — без начала, и это сказано `None`.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crate::conntrack::{CtTcp, CtView, Tuple};

/// Разговор по слову ядра: номер записи и её кортеж — номер одного ядра переиспользуется.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Talk {
    id: u32,
    src: u32,
    dst: u32,
    src_port: u16,
    dst_port: u16,
    proto: u8,
}

impl Talk {
    fn of(view: &CtView) -> Option<Talk> {
        view.tuple.map(|tuple: Tuple| Talk {
            id: view.id,
            src: tuple.src,
            dst: tuple.dst,
            src_port: tuple.src_port,
            dst_port: tuple.dst_port,
            proto: tuple.proto,
        })
    }
}

/// Начало разговора и когда его видели последний раз.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Opened {
    at: Instant,
    last: Instant,
}

/// Память правится на месте: она на горячем пути очереди, пересборка на каждом пакете стоила бы
/// обхода всей памяти.
#[derive(Debug, Clone, Default)]
pub struct Openings(BTreeMap<Talk, Opened>);

impl Openings {
    /// Сколько разговоров помним. Очередь видит разговор лишь до того, как цель скажет первые
    /// килобайты, — живых в ней десятки, не тысячи.
    pub const CAPACITY: usize = 4_096;

    /// Молчащий дольше — забывается, когда память полна: очередь его больше не видит.
    pub const SILENCE: Duration = Duration::from_secs(600);

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Пакет разговора пришёл в `at` — память и возраст разговора (`None` — начало неизвестно).
    pub fn seen(mut self, view: Option<&CtView>, at: Instant) -> (Openings, Option<Duration>) {
        let talk = view.and_then(Talk::of);
        let known = talk.and_then(|talk| self.0.get_mut(&talk)).map(|opened| {
            opened.last = at;
            at.saturating_duration_since(opened.at)
        });
        let syn = view.and_then(|view| view.tcp) == Some(CtTcp::SynSent);
        let age = known.or_else(|| {
            talk.filter(|_talk| syn)
                .and_then(|talk| self.opened(talk, at))
        });
        (self, age)
    }

    /// Полная память забывает молчащих; живых не вытесняет — новый тогда без начала.
    fn opened(&mut self, talk: Talk, at: Instant) -> Option<Duration> {
        if self.0.len() >= Openings::CAPACITY {
            self.0.retain(|_talk, opened| {
                at.saturating_duration_since(opened.last) < Openings::SILENCE
            });
        }
        (self.0.len() < Openings::CAPACITY).then(|| {
            let _fresh = self.0.insert(talk, Opened { at, last: at });
            Duration::ZERO
        })
    }
}
