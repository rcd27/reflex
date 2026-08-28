use std::collections::HashMap;
use std::time::{Duration, Instant};

use smallvec::SmallVec;

use crate::detector::DetectorEvent;
use crate::types::{Flow, HasFlow};
use crate::Detector;

/// КАРТА ДЕТЕКТОРОВ ПО ФЛОУ — состояние соединения как ПРИМИТИВ, а не как чужой `HashMap`.
///
/// # Почему обобщена по входу
///
/// До #135 таблица принимала ровно `TcpSegment`. Всякий, кому состояние по флоу нужно было для
/// другого входа — разобранного пакета с L7, датаграммы, события края, — писал свою карту: в
/// одном неводе таких копий пять, и ни одна не умеет того, ради чего примитив и заведён —
/// эвикта по простою. Карта без эвикта есть склад на неограниченный рост, и растёт он ровно
/// там, где соединений много.
///
/// Обобщение обратно совместимо: `Input = TcpSegment` остаётся частным случаем, потребители не
/// правятся ни строкой.
pub struct FlowTable<D: Detector>
where
    D::Input: HasFlow + Clone,
{
    flows: HashMap<Flow, D>,
    last_seen: HashMap<Flow, Instant>, // последняя активность потока — для эвикта простоя
    idle_timeout: Duration,            // молчание дольше → поток мёртв (эвикт на тике)
    make_detector: Box<dyn Fn(Flow) -> D + Send>,
}

impl<D: Detector> FlowTable<D>
where
    D::Input: HasFlow + Clone,
{
    /// `idle_timeout` — сколько поток может молчать (без пакетов), прежде чем считается мёртвым и
    /// эвиктится на тике. Иначе завершённый/затихший поток тикается ВЕЧНО (детектор эмитит пустое
    /// окно на каждом тике) — утечка таблицы + спам наблюдаемости. Потребитель задаёт таймаут по
    /// своему окну (напр. 2× окна детектора).
    pub fn new(idle_timeout: Duration, make_detector: impl Fn(Flow) -> D + Send + 'static) -> Self {
        Self {
            flows: HashMap::new(),
            last_seen: HashMap::new(),
            idle_timeout,
            make_detector: Box::new(make_detector),
        }
    }

    pub fn process(&mut self, input: &D::Input, at: Instant) -> SmallVec<[D::Signal; 2]> {
        let flow = normalize_flow(input.flow());
        let detector = self
            .flows
            .remove(&flow)
            .unwrap_or_else(|| (self.make_detector)(flow.clone()));
        let (detector, signals) = detector.step(DetectorEvent::Packet {
            input: input.clone(),
            at,
        });
        self.flows.insert(flow.clone(), detector);
        self.last_seen.insert(flow, at); // активность продлевает жизнь потока
        signals
    }

    pub fn tick(&mut self, at: Instant) -> Vec<D::Signal> {
        let mut all_signals = Vec::new();
        let flows: Vec<Flow> = self.flows.keys().cloned().collect();
        for flow in flows {
            if self.reap_if_idle(&flow, at) {
                continue; // мёртвый поток эвиктнут — не тикаем
            }
            if let Some(detector) = self.flows.remove(&flow) {
                let (detector, signals) = detector.step(DetectorEvent::Tick { at });
                all_signals.extend(signals);
                self.flows.insert(flow, detector);
            }
        }
        all_signals
    }

    /// Как [`tick`](Self::tick), но АТРИБУТИРУЕТ сигнал флоу-ключом. Витнесу нужно адресовать
    /// здоровье конкретному соединению (per-host решение), а `tick` теряет ключ.
    pub fn tick_attributed(&mut self, at: Instant) -> Vec<(Flow, D::Signal)> {
        let mut out = Vec::new();
        let flows: Vec<Flow> = self.flows.keys().cloned().collect();
        for flow in flows {
            if self.reap_if_idle(&flow, at) {
                continue; // мёртвый поток эвиктнут — не тикаем
            }
            if let Some(detector) = self.flows.remove(&flow) {
                let (detector, signals) = detector.step(DetectorEvent::Tick { at });
                for s in signals {
                    out.push((flow.clone(), s));
                }
                self.flows.insert(flow, detector);
            }
        }
        out
    }

    /// Эвикт потока, молчавшего дольше `idle_timeout` (детектор + last-seen удаляются). Возвращает
    /// `true`, если поток эвиктнут (тикать нечего).
    fn reap_if_idle(&mut self, flow: &Flow, at: Instant) -> bool {
        let idle = self
            .last_seen
            .get(flow)
            .is_some_and(|seen| at.saturating_duration_since(*seen) >= self.idle_timeout);
        if idle {
            self.flows.remove(flow);
            self.last_seen.remove(flow);
        }
        idle
    }

    pub fn get(&self, flow: &Flow) -> Option<&D> {
        self.flows.get(&normalize_flow(flow))
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }
}

fn normalize_flow(flow: &Flow) -> Flow {
    if flow.dst.port() == 443 || flow.dst.port() < 1024 {
        flow.clone()
    } else {
        flow.reversed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::Detector;
    use crate::types::{Protocol, TcpFlags, TcpOptions, TcpSegment};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;

    const WINDOW: Duration = Duration::from_secs(3);
    const IDLE: Duration = Duration::from_secs(6); // 2 окна простоя → поток мёртв

    /// ТАБЛИЦА ДЕРЖИТ СОСТОЯНИЕ И ДЛЯ НЕ-TCP ВХОДА — витнес самого обобщения (#135).
    ///
    /// Без этого теста обобщение остаётся утверждением: старые проверки все до одной идут на
    /// `TcpSegment` и зеленели бы при таблице, по-прежнему прибитой к нему. Здесь вход —
    /// `UdpDatagram`, у которого с TCP общего ровно то, что оба несут флоу.
    #[test]
    fn table_keeps_state_for_any_input_with_a_flow() {
        use crate::types::UdpDatagram;

        #[derive(Clone)]
        struct Counter(usize);

        impl Detector for Counter {
            type Input = UdpDatagram;
            type Signal = usize;

            fn step(self, ev: DetectorEvent<UdpDatagram>) -> (Self, SmallVec<[usize; 2]>) {
                match ev {
                    DetectorEvent::Packet { .. } => {
                        let next = self.0 + 1;
                        (Counter(next), SmallVec::from_slice(&[next]))
                    }
                    DetectorEvent::Tick { .. } => (self, SmallVec::new()),
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
        let mut table = FlowTable::new(IDLE, |_flow| Counter(0));

        // ДВА РАЗНЫХ ФЛОУ СЧИТАЮТСЯ ПОРОЗНЬ: состояние принадлежит соединению, а не таблице.
        assert_eq!(table.process(&datagram(1111), now).as_slice(), &[1]);
        assert_eq!(table.process(&datagram(2222), now).as_slice(), &[1]);
        assert_eq!(table.process(&datagram(1111), now).as_slice(), &[2]);
        assert_eq!(table.flow_count(), 2);
    }

    /// Тривиальный детектор: тик всегда эмитит сигнал — так видно, тикается ли поток (жив в таблице).
    #[derive(Clone)]
    struct TickPing;

    impl Detector for TickPing {
        type Input = TcpSegment;
        type Signal = ();

        fn step(self, ev: DetectorEvent<TcpSegment>) -> (Self, SmallVec<[(); 2]>) {
            let mut out = SmallVec::new();
            if let DetectorEvent::Tick { .. } = ev {
                out.push(());
            }
            (self, out)
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

    /// ГЛАВНОЕ (эвикт мёртвых потоков): поток без активности дольше idle-таймаута удаляется на тике
    /// и БОЛЬШЕ не тикается (иначе — вечный tput=0-спам наблюдаемости + утечка таблицы).
    #[test]
    fn idle_flow_evicted_and_stops_ticking() {
        let t0 = Instant::now();
        let mut ft = FlowTable::new(IDLE, |_| TickPing);
        ft.process(&seg(), t0);
        assert_eq!(ft.flow_count(), 1);
        // Тик в пределах idle — поток жив, тикается.
        let out = ft.tick(t0 + WINDOW);
        assert_eq!(ft.flow_count(), 1);
        assert_eq!(out.len(), 1, "живой поток тикается");
        // Тик за idle-таймаутом без активности — поток мёртв → эвикт, сигнала нет.
        let out2 = ft.tick(t0 + IDLE);
        assert_eq!(ft.flow_count(), 0, "простойный поток эвиктнут");
        assert!(out2.is_empty(), "мёртвый поток не эмитит на тике эвикта");
        // Навсегда молчит — не переоткрывается сам собой.
        let out3 = ft.tick(t0 + IDLE + WINDOW);
        assert!(out3.is_empty(), "эвиктнутый поток молчит");
    }

    /// Активность (новый пакет) обновляет last-seen → поток НЕ эвиктится, пока жив.
    #[test]
    fn active_flow_not_evicted() {
        let t0 = Instant::now();
        let mut ft = FlowTable::new(IDLE, |_| TickPing);
        ft.process(&seg(), t0);
        ft.process(&seg(), t0 + WINDOW); // активность в окне
        let out = ft.tick(t0 + WINDOW + Duration::from_secs(1)); // <(last_seen + IDLE)
        assert_eq!(ft.flow_count(), 1, "активный поток жив");
        assert_eq!(out.len(), 1);
    }
}
