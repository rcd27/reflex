use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

use crate::detector::DetectorEvent;
use crate::mealy::Mealy;
use crate::types::Flow;

/// Расслоённый драйвер: гоняет морфизм `D` по семье машин, ключёванной `K`. Синхронный аналог
/// [`Lift`](crate::mealy::Lift) — канон §9.2. Ключ даёт вызывающий (снят приварок к `Flow`), эвикт
/// по простою держит память конечной (канон §4). Наружу — пара `(Out, Log)`, на тике помеченная
/// ключом (в одном ответе смешаны машины разных ключей). Через таблицу едут две буквы из трёх:
/// `Packet` и `Tick`; `Opaque` не ключуется — ключа у непонятого нет.
pub struct FlowTable<D, K> {
    machines: HashMap<K, D>,
    last_seen: HashMap<K, Instant>,
    idle_timeout: Duration,
    make: Box<dyn Fn(&K) -> D + Send>,
}

impl<D, K, In> FlowTable<D, K>
where
    D: Mealy<In = DetectorEvent<In>>,
    K: Eq + Hash + Clone,
    In: Clone,
{
    /// `idle_timeout` — сколько машина ключа может молчать до эвикта на тике. Иначе затихший ключ
    /// тикается вечно (утечка + спам наблюдаемости). Задаётся по окну детектора (напр. 2×).
    pub fn new(idle_timeout: Duration, make: impl Fn(&K) -> D + Send + 'static) -> Self {
        Self {
            machines: HashMap::new(),
            last_seen: HashMap::new(),
            idle_timeout,
            make: Box::new(make),
        }
    }

    /// Пакет — в машину своего ключа; наружу пара, которую та сказала. Ключ вычисляет вызывающий
    /// (он знает, чей вход подал) — метка на каждом пакете стоила бы клона в горячем пути.
    pub fn process(&mut self, key: K, input: &In, at: Instant) -> (D::Out, D::Log) {
        let machine = self
            .machines
            .remove(&key)
            .unwrap_or_else(|| (self.make)(&key));
        let (machine, said, noted) = machine.step(DetectorEvent::Packet {
            input: input.clone(),
            at,
        });
        self.machines.insert(key.clone(), machine);
        self.last_seen.insert(key, at);
        (said, noted)
    }

    /// Тик — во все живые машины; наружу по паре с каждой, помеченной её ключом. Пара выходит и от
    /// молчавшей: пустое слово есть речь, а показание при нём — чем машина располагала. Тик
    /// доставляется ПРЕЖДЕ эвикта: снятая, не сказав, теряет беду последнего окна. Длина ответа
    /// известна до обхода (число ключей) — память под неё берётся разом.
    pub fn tick(&mut self, at: Instant) -> Vec<(K, (D::Out, D::Log))> {
        let keys: Vec<K> = self.machines.keys().cloned().collect();
        let mut spoken = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(machine) = self.machines.remove(&key) {
                let (machine, said, noted) = machine.step(DetectorEvent::Tick { node: 0, at });
                spoken.push((key.clone(), (said, noted)));
                match self.is_idle(&key, at) {
                    true => {
                        self.last_seen.remove(&key);
                    }
                    false => {
                        self.machines.insert(key, machine);
                    }
                }
            }
        }
        spoken
    }

    fn is_idle(&self, key: &K, at: Instant) -> bool {
        self.last_seen
            .get(key)
            .is_some_and(|seen| at.saturating_duration_since(*seen) >= self.idle_timeout)
    }

    pub fn get(&self, key: &K) -> Option<&D> {
        self.machines.get(key)
    }

    pub fn flow_count(&self) -> usize {
        self.machines.len()
    }
}

/// Нормализация ключа разговора: направление приводится к одному, чтобы обе стороны легли в одну
/// машину. Вызывающий применяет её сам перед [`FlowTable::process`], ибо нормализация вправе
/// перевернуть поток.
pub fn normalize_flow(flow: &Flow) -> Flow {
    if flow.dst.port() == 443 || flow.dst.port() < 1024 {
        flow.clone()
    } else {
        flow.reversed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{HasFlow, Protocol, TcpFlags, TcpOptions, TcpSegment};
    use smallvec::SmallVec;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;

    struct Bench;
    impl crate::word::Base for Bench {
        type Fibre = ();
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Count(usize);
    impl crate::word::Word for Count {
        type Of = Bench;
    }

    const WINDOW: Duration = Duration::from_secs(3);
    const IDLE: Duration = Duration::from_secs(6);

    /// Таблица держит состояние по КЛЮЧУ для любого входа: вход — `UdpDatagram`, ключ — его флоу.
    #[test]
    fn table_keeps_state_per_key() {
        use crate::types::UdpDatagram;

        #[derive(Clone)]
        struct Counter(usize);
        impl Mealy for Counter {
            type In = DetectorEvent<UdpDatagram>;
            type Out = SmallVec<[Count; 2]>;
            type Log = ();
            fn step(self, ev: Self::In) -> (Self, Self::Out, ()) {
                match ev {
                    DetectorEvent::Packet { .. } => {
                        let next = self.0 + 1;
                        (Counter(next), SmallVec::from_slice(&[Count(next)]), ())
                    }
                    DetectorEvent::Tick { .. }
                    | DetectorEvent::Opaque { .. }
                    | DetectorEvent::Torn { .. } => (self, SmallVec::new(), ()),
                }
            }
        }

        let datagram = |port: u16| UdpDatagram {
            flow: Flow {
                src: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 2).into(), port),
                dst: SocketAddr::new(Ipv4Addr::new(1, 2, 3, 4).into(), 443),
                protocol: Protocol::Udp,
            },
            ttl: 64,
            payload: vec![],
        };

        let now = Instant::now();
        let mut table: FlowTable<Counter, Flow> = FlowTable::new(IDLE, |_key| Counter(0));

        let said = |table: &mut FlowTable<Counter, Flow>, port| {
            let d = datagram(port);
            let key = normalize_flow(d.flow());
            let (word, ()) = table.process(key, &d, now);
            word
        };
        assert_eq!(said(&mut table, 1111).as_slice(), &[Count(1)]);
        assert_eq!(said(&mut table, 2222).as_slice(), &[Count(1)]);
        assert_eq!(said(&mut table, 1111).as_slice(), &[Count(2)]);
        assert_eq!(table.flow_count(), 2);
    }

    #[derive(Debug, Clone)]
    struct TickPing;
    impl Mealy for TickPing {
        type In = DetectorEvent<TcpSegment>;
        type Out = SmallVec<[(); 2]>;
        type Log = ();
        fn step(self, ev: Self::In) -> (Self, Self::Out, ()) {
            let mut out = SmallVec::new();
            if let DetectorEvent::Tick { .. } = ev {
                out.push(());
            }
            (self, out, ())
        }
    }

    fn seg() -> TcpSegment {
        TcpSegment {
            flow: Flow {
                src: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 2).into(), 55555),
                dst: SocketAddr::new(Ipv4Addr::new(1, 2, 3, 4).into(), 443),
                protocol: Protocol::Tcp,
            },
            seq: 0,
            ack: 0,
            flags: TcpFlags::PSH | TcpFlags::ACK,
            window: 0,
            options: TcpOptions::default(),
            ttl: 64,
            payload: vec![],
        }
    }

    fn feed(ft: &mut FlowTable<TickPing, Flow>, s: TcpSegment, at: Instant) {
        let key = normalize_flow(s.flow());
        ft.process(key, &s, at);
    }

    /// Эвикт мёртвого ключа: молчавший дольше idle снимается на тике и больше не тикается — но
    /// снимается ПОСЛЕ последнего слова.
    #[test]
    fn idle_flow_evicted_and_stops_ticking() {
        let t0 = Instant::now();
        let mut ft: FlowTable<TickPing, Flow> = FlowTable::new(IDLE, |_| TickPing);
        feed(&mut ft, seg(), t0);
        assert_eq!(ft.flow_count(), 1);
        let out = ft.tick(t0 + WINDOW);
        assert_eq!(ft.flow_count(), 1);
        assert_eq!(out.iter().map(|(_, (w, ()))| w.len()).sum::<usize>(), 1);
        let out2 = ft.tick(t0 + IDLE);
        assert_eq!(ft.flow_count(), 0);
        assert_eq!(out2.iter().map(|(_, (w, ()))| w.len()).sum::<usize>(), 1);
        let out3 = ft.tick(t0 + IDLE + WINDOW);
        assert!(out3.is_empty());
    }

    /// Активность обновляет last-seen → ключ жив.
    #[test]
    fn active_flow_not_evicted() {
        let t0 = Instant::now();
        let mut ft: FlowTable<TickPing, Flow> = FlowTable::new(IDLE, |_| TickPing);
        feed(&mut ft, seg(), t0);
        feed(&mut ft, seg(), t0 + WINDOW);
        let out = ft.tick(t0 + WINDOW + Duration::from_secs(1));
        assert_eq!(ft.flow_count(), 1);
        assert_eq!(out.iter().map(|(_, (w, ()))| w.len()).sum::<usize>(), 1);
    }
}
