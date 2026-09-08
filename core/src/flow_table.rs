use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::detector::DetectorEvent;
use crate::mealy::Mealy;
use crate::types::{Flow, HasFlow};

/// КАРТА ДЕТЕКТОРОВ ПО ФЛОУ — состояние соединения как ПРИМИТИВ, а не как чужой `HashMap`.
///
/// # Почему обобщена по входу
///
/// Состояние по флоу нужно не только для `TcpSegment` — для разобранного пакета с L7, для
/// датаграммы, для события края. Писать под каждый вход свою карту значило бы плодить копии, ни
/// одна из которых не обязана уметь того, ради чего примитив и заведён — эвикта по простою. Карта
/// без эвикта есть склад на неограниченный рост, и растёт он ровно там, где соединений много.
///
/// Обобщение обратно совместимо: `In = TcpSegment` (равенство в границах `impl`, ниже) остаётся
/// частным случаем, потребители не правятся ни строкой.
///
/// # ЗАКОН ПОДЪЁМА: НАРУЖУ ВЫХОДИТ ПАРА
///
/// Таблица есть подъём шага на СЕМЬЮ машин, ключёванную потоком, и как всякий подъём выпускает
/// ровно то, что дал шаг, — слово и показание. Форма у слова не требуется никакая: подъём
/// поднимает шаг, а не разбирает его речь, и допущение «слово есть вектор сигналов» запретило бы
/// класть сюда сложенных наблюдателей, чьё слово есть произведение.
///
/// # ЗАКОН ВХОДА: ЧЕРЕЗ ТАБЛИЦУ ЕДУТ ДВЕ БУКВЫ ИЗ ТРЁХ
///
/// [`process`](Self::process) строит [`DetectorEvent::Packet`], [`tick`](Self::tick) — `Tick`, и
/// третьей буквы, `Opaque`, таблица не строит НИ ПРИ КАКОМ входе. Причина та же, по которой её не
/// разносит подъём, расслоённый по ключу: ключ берётся из РАЗОБРАННОГО входа (`In: HasFlow`),
/// которого у непонятого нет и быть не может, — у события без потока адресата в этой семье нет.
///
/// Считает непонятое тот, кто стоит ДО ключевания. Шаг, положенный сюда, ветку `Opaque` всё равно
/// обязан разобрать: дверей у алфавита больше одной, и шаг не выбирает, которой его поднимут.
pub struct FlowTable<D> {
    flows: HashMap<Flow, D>,
    last_seen: HashMap<Flow, Instant>, // последняя активность потока — для эвикта простоя
    idle_timeout: Duration,            // молчание дольше → поток мёртв (эвикт на тике)
    make_detector: Box<dyn Fn(Flow) -> D + Send>,
}

impl<D, In> FlowTable<D>
where
    D: Mealy<In = DetectorEvent<In>>,
    In: HasFlow + Clone,
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

    /// Пакет — в машину своего потока; наружу пара, которую та сказала.
    ///
    /// Ключ здесь не приписывается: машина одна, и вызывающий сам знает, чей пакет подал. Ключ,
    /// под которым она легла, вызывающий волен вычислить [`normalize_flow`] — той же функцией, что
    /// метит выход [`tick`](Self::tick), — и сшить два выхода, когда ему это нужно. Метка на
    /// каждом пакете стоила бы клона в горячем пути ради сведений, которые нужны не всякому.
    pub fn process(&mut self, input: &In, at: Instant) -> (D::Out, D::Log) {
        let flow = normalize_flow(input.flow());
        let detector = self
            .flows
            .remove(&flow)
            .unwrap_or_else(|| (self.make_detector)(flow.clone()));
        let (detector, said, noted) = detector.step(DetectorEvent::Packet {
            input: input.clone(),
            at,
        });
        self.flows.insert(flow.clone(), detector);
        self.last_seen.insert(flow, at); // активность продлевает жизнь потока
        (said, noted)
    }

    /// Тик — во все живые потоки; наружу по паре с каждого, помеченной его потоком.
    ///
    /// ПАРА ВЫХОДИТ И ОТ ТОГО, КОМУ СКАЗАТЬ БЫЛО НЕЧЕГО: пустое слово есть речь, а показание при
    /// нём — единственное, чем машина предъявляет, чем располагала. Отбрось таблица молчащих, и
    /// «замерил и намерил ноль» стало бы неотличимо от «не мерил вовсе».
    ///
    /// Поток приписывается затем, что в одном ответе смешаны машины разных потоков.
    ///
    /// # ЦЕНА ОТВЕТА ЗНАЕТСЯ ЗАРАНЕЕ
    ///
    /// Пара выходит с каждой живой машины, значит длина ответа известна ДО обхода — она есть
    /// число потоков. Отвод памяти под неё берётся разом: растущий вектор переселялся бы на
    /// каждом удвоении, и цена тика зависела бы от числа потоков логарифмом там, где может не
    /// зависеть вовсе. Примитив заведён под «соединений много», и такой рост в нём непозволителен.
    pub fn tick(&mut self, at: Instant) -> Vec<(Flow, (D::Out, D::Log))> {
        let flows: Vec<Flow> = self.flows.keys().cloned().collect();
        let mut spoken = Vec::with_capacity(flows.len());
        for flow in flows {
            if let Some(detector) = self.flows.remove(&flow) {
                // `node: 0` — таблица не хранит `start` сетки: условное «вне сетки», как у
                // всякого тика, собранного мимо неё.
                let (detector, said, noted) = detector.step(DetectorEvent::Tick { node: 0, at });
                spoken.push((flow.clone(), (said, noted)));
                // ТИК ДОСТАВЛЯЕТСЯ ПРЕЖДЕ, ЧЕМ РЕШАЕТСЯ СУДЬБА ПОТОКА: снять состояние, не дав ему
                // сказать последнее слово, значит потерять беду, о которой машина уже знала, — а
                // беда, замеченная на последнем тике, есть ровно то, ради чего заводят прибор
                // простоя. Порядок здесь тот же, что у подъёма, расслоённого по ключу.
                match self.is_idle(&flow, at) {
                    true => {
                        self.last_seen.remove(&flow);
                    }
                    false => {
                        self.flows.insert(flow, detector);
                    }
                }
            }
        }
        spoken
    }

    /// Молчал ли поток дольше `idle_timeout` — то есть мёртв ли он.
    fn is_idle(&self, flow: &Flow, at: Instant) -> bool {
        self.last_seen
            .get(flow)
            .is_some_and(|seen| at.saturating_duration_since(*seen) >= self.idle_timeout)
    }

    pub fn get(&self, flow: &Flow) -> Option<&D> {
        self.flows.get(&normalize_flow(flow))
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }
}

/// КЛЮЧ ТАБЛИЦЫ: направление разговора приводится к одному, чтобы обе его стороны попали в одну
/// машину.
///
/// Открыта затем, что [`FlowTable::process`] ключа наружу не отдаёт, а [`FlowTable::tick`] отдаёт:
/// без этой функции сшить два выхода было бы нечем — нормализация вправе ПЕРЕВЕРНУТЬ поток, и
/// вызывающий, глядя на свой же пакет, ключа не угадает.
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
    use crate::types::{Protocol, TcpFlags, TcpOptions, TcpSegment};
    use smallvec::SmallVec;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;

    /// ОБЛАСТЬ ЗАКОННОГО СТЕНДА: у счёта свидетеля адресата в домене нет, и стенд объявляет свой.
    struct Bench;
    impl crate::word::Base for Bench {
        type Fibre = ();
    }

    /// СЧЁТ СВИДЕТЕЛЯ — с именем, а не голым числом: адрес объявляет значение, а число молчит.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Count(usize);

    impl crate::word::Word for Count {
        type Of = Bench;
    }

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
                    DetectorEvent::Tick { .. } => (self, SmallVec::new(), ()),
                    // Таблица кормит детектор только `Packet` и `Tick` (см. `process`/`tick`
                    // ниже) — витнес честен об этом, а не молчит веткой-приёмником.
                    DetectorEvent::Opaque { .. } => (self, SmallVec::new(), ()),
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
        let said = |table: &mut FlowTable<Counter>, port| {
            let (word, ()) = table.process(&datagram(port), now);
            word
        };
        assert_eq!(said(&mut table, 1111).as_slice(), &[Count(1)]);
        assert_eq!(said(&mut table, 2222).as_slice(), &[Count(1)]);
        assert_eq!(said(&mut table, 1111).as_slice(), &[Count(2)]);
        assert_eq!(table.flow_count(), 2);
    }

    /// Тривиальный детектор: тик всегда эмитит сигнал — так видно, тикается ли поток (жив в таблице).
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

    /// ГЛАВНОЕ (эвикт мёртвых потоков): поток без активности дольше idle-таймаута удаляется на тике
    /// и БОЛЬШЕ не тикается (иначе — вечный tput=0-спам наблюдаемости + утечка таблицы).
    ///
    /// Но снимается он ПОСЛЕ того, как сказал: беда, замеченная на последнем тике, есть ровно то,
    /// ради чего прибор простоя и заводится, и терять её нельзя.
    #[test]
    fn idle_flow_evicted_and_stops_ticking() {
        let t0 = Instant::now();
        let mut ft = FlowTable::new(IDLE, |_| TickPing);
        ft.process(&seg(), t0);
        assert_eq!(ft.flow_count(), 1);
        // Тик в пределах idle — поток жив, тикается.
        let out = ft.tick(t0 + WINDOW);
        assert_eq!(ft.flow_count(), 1);
        assert_eq!(
            out.iter().map(|(_, (word, ()))| word.len()).sum::<usize>(),
            1,
            "живой поток тикается: {out:?}"
        );
        // Тик за idle-таймаутом без активности — поток мёртв, но последнее слово он говорит.
        let out2 = ft.tick(t0 + IDLE);
        assert_eq!(ft.flow_count(), 0, "простойный поток эвиктнут");
        assert_eq!(
            out2.iter().map(|(_, (word, ()))| word.len()).sum::<usize>(),
            1,
            "снимаемая машина обязана успеть сказать последнее слово: {out2:?}"
        );
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
        assert_eq!(
            out.iter().map(|(_, (word, ()))| word.len()).sum::<usize>(),
            1
        );
    }
}
