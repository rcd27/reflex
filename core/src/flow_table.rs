use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

use crate::detector::{DetectorEvent, Ended};
use crate::mealy::Mealy;
use crate::types::Flow;

/// Расслоённый драйвер: гоняет морфизм `D` по семье машин, ключёванной `K`. Синхронный аналог
/// [`Lift`](crate::mealy::Lift) — канон §9.2. Ключ даёт вызывающий (приварки к `Flow` нет), эвикт
/// по простою держит память конечной (канон §4). Наружу — пара `(Out, Log)`, на тике помеченная
/// ключом (в одном ответе смешаны машины разных ключей).
///
/// Дверей две, и разводит их АДРЕС, а не буква. `Packet` едет в машину СВОЕГО ключа
/// ([`FlowTable::process`]); всё, у чего ключа нет, — во ВСЕ живые машины разом
/// ([`FlowTable::each`]). Ключа нет у трёх букв, и по разным причинам. У узла сетки его нет ПОТОМУ
/// ЧТО у времени собеседника не бывает. У непонятого — ПОТОМУ ЧТО разбор не добрался до адреса, и
/// вызывающему нечего подать в `process`. У дыры — ПОТОМУ ЧТО носитель объявляет потерю на очередь
/// целиком, не на пакет: мы не знаем, чьи наблюдения пропали, и приписать её одному разговору
/// значило бы соврать об остальных, которых она не касалась.
///
/// Букву даёт ВЫЗЫВАЮЩИЙ, дверь её не штампует. Дверь, штампующая узел сама (нулевым номером, то
/// есть сеткой, которой нет вовсе), закрыта для дыры вовсе — и обещание «дыра доходит до прибора»
/// остаётся неисполнимым при зелёной сборке.
pub struct FlowTable<D, K> {
    machines: HashMap<K, D>,
    last_seen: HashMap<K, Instant>,
    idle_timeout: Duration,
    /// Потолок — ТРЕТИЙ рубеж уборки, и он нужен даже там, где есть часы. Срок снимает
    /// ЗАМОЛЧАВШИХ; против тысячи одновременно говорящих он бессилен, а память конечна независимо
    /// от того, богат ли алфавит буквой конца. Замерено: без потолка таблица приняла сто тысяч
    /// живых разговоров, не возразив ни разу.
    capacity: usize,
    /// Ключи, снятые ПО ЁМКОСТИ и ещё не объявленные наружу.
    ///
    /// Утрата по ёмкости — иного рода, чем по букве и по сроку: те снимают мёртвое (факт о мире),
    /// эта снимает ЖИВОЕ, потому что место кончилось у нас (факт о нас — то же различение, что
    /// `Expiry::Idle` и `Expiry::Ceiling` в [`crate::timeout`]). Молчаливая, она неотличима от
    /// «разговора не было»: прибор просто больше не увидит цели и решит, что та замолчала.
    forgotten: Vec<K>,
    make: Box<dyn Fn(&K) -> D + Send>,
}

impl<D, K, In> FlowTable<D, K>
where
    D: Mealy<In = DetectorEvent<In>>,
    K: Eq + Hash + Clone,
    In: Clone,
    D: Ended,
{
    /// `idle_timeout` — сколько машина ключа может молчать до эвикта на тике. Иначе затихший ключ
    /// тикается вечно (утечка + спам наблюдаемости). Задаётся по окну детектора (напр. 2×).
    pub fn new(
        idle_timeout: Duration,
        capacity: usize,
        make: impl Fn(&K) -> D + Send + 'static,
    ) -> Self {
        Self {
            machines: HashMap::new(),
            last_seen: HashMap::new(),
            idle_timeout,
            capacity,
            forgotten: Vec::new(),
            make: Box::new(make),
        }
    }

    /// Пакет — в машину своего ключа; наружу пара, которую та сказала. Ключ вычисляет вызывающий
    /// (он знает, чей вход подал) — метка на каждом пакете стоила бы клона в горячем пути.
    ///
    /// МАШИНА, ОБЪЯВИВШАЯ КОНЕЦ, УБИРАЕТСЯ ЗДЕСЬ ЖЕ, не дожидаясь простоя (§12.6, [`Ended`]).
    /// Спрашивают её ПОСЛЕ шага: она сперва говорит последнее слово — снятая молча, она потеряла
    /// бы беду последнего окна, тот же порядок, что и при эвикте по простою в [`FlowTable::each`].
    ///
    /// Прежде исчерпанный разговор занимал место весь `idle_timeout`, хотя знал о своём конце:
    /// приборы прощание слушали (`instrument`), а память — нет.
    pub fn process(&mut self, key: K, input: &In, at: Instant) -> (D::Out, D::Log) {
        let machine = self
            .machines
            .remove(&key)
            .unwrap_or_else(|| (self.make)(&key));
        let (machine, said, noted) = machine.step(DetectorEvent::Packet {
            input: input.clone(),
            at,
        });
        match machine.ended() {
            true => {
                self.last_seen.remove(&key);
            }
            false => {
                self.machines.insert(key.clone(), machine);
                self.last_seen.insert(key, at);
                self.make_room();
            }
        }
        (said, noted)
    }

    /// Освободить место, если ключей больше потолка: уходит САМЫЙ ДАВНИЙ по последнему
    /// наблюдению. Не случайный и не новейший: давний ближе всех к тому, чтобы уйти по сроку, и
    /// ошибка вытеснения стоит на нём меньше всего.
    ///
    /// Свежий разговор входит ВСЕГДА — отказ принять новое сделал бы полную таблицу слепой к
    /// происходящему сейчас, и чем дольше она живёт, тем прочнее (тот же довод, по которому
    /// `dns::cache` освобождает место, а не отвергает ответ).
    ///
    /// Снятый ключ кладётся в [`FlowTable::forgotten`] — объявление наружу; здесь его не
    /// выбрасывают, потому что утрата живого обязана быть названа.
    fn make_room(&mut self) {
        while self.machines.len() > self.capacity {
            let oldest = self
                .last_seen
                .iter()
                .min_by_key(|(_, seen)| **seen)
                .map(|(key, _)| key.clone());
            match oldest {
                None => return,
                Some(key) => {
                    self.machines.remove(&key);
                    self.last_seen.remove(&key);
                    self.forgotten.push(key);
                }
            }
        }
    }

    /// Забрать объявления об утрате ПО ЁМКОСТИ — ключи, снятые живыми, потому что место кончилось.
    ///
    /// Объявление приходит ПОЗЖЕ самой утраты (её делает горячий путь, читают на тике), и это тот
    /// же порядок, что у дыры носителя: `DetectorEvent::Torn` несёт момент ОБНАРУЖЕНИЯ, а не
    /// потери, потому что другого взять неоткуда. Цена та же и называется так же: между снятием и
    /// объявлением прибор считает цель молчащей.
    #[must_use = "утрата живого, брошенная молча, неотличима от того, что разговора не было: \
                  прибор решит, что цель замолчала, и объявит беду по собственной забывчивости"]
    pub fn forgotten(&mut self) -> Vec<K> {
        std::mem::take(&mut self.forgotten)
    }

    /// Буква БЕЗ АДРЕСА — во все живые машины; наружу по паре с каждой, помеченной её ключом. Пара
    /// выходит и от молчавшей: пустое слово есть речь, а показание при нём — чем машина
    /// располагала. Буква доставляется ПРЕЖДЕ эвикта: снятая, не сказав, теряет беду последнего
    /// окна. Длина ответа известна до обхода (число ключей) — память под неё берётся разом.
    ///
    /// Момент берётся у САМОЙ БУКВЫ, вторым доводом его не передают: два источника одного момента
    /// разошлись бы молча, и эвикт судил бы не по тому времени, по которому шагнула машина.
    ///
    /// ПОРЯДОК между машинами НЕ ОПРЕДЕЛЁН, и опираться на него нельзя (`HashMap` его не
    /// обещает). Сегодня он ни на что не влияет — машины разных разговоров между собой не
    /// разговаривают; но появись буква, адресованная каждой и меняющая ОБЩЕЕ состояние (слой
    /// целей, ленту), — он стал бы значим молча. Оттого сказано «не определён», а не «не важен».
    pub fn each(&mut self, letter: DetectorEvent<In>) -> Vec<(K, (D::Out, D::Log))> {
        let at = letter.at();
        let keys: Vec<K> = self.machines.keys().cloned().collect();
        let mut spoken = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(machine) = self.machines.remove(&key) {
                let (machine, said, noted) = machine.step(letter.clone());
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
        impl crate::detector::Ended for Counter {}
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
        let mut table: FlowTable<Counter, Flow> = FlowTable::new(IDLE, 1024, |_key| Counter(0));

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
    impl crate::detector::Ended for TickPing {}

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

    /// Узел сетки как БУКВА — со своим номером: подделывать его нулём значило бы звать сетку,
    /// которой нет.
    fn node<In>(at: Instant) -> DetectorEvent<In> {
        DetectorEvent::Tick { node: 1, at }
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
        let mut ft: FlowTable<TickPing, Flow> = FlowTable::new(IDLE, 1024, |_| TickPing);
        feed(&mut ft, seg(), t0);
        assert_eq!(ft.flow_count(), 1);
        let out = ft.each(node(t0 + WINDOW));
        assert_eq!(ft.flow_count(), 1);
        assert_eq!(out.iter().map(|(_, (w, ()))| w.len()).sum::<usize>(), 1);
        let out2 = ft.each(node(t0 + IDLE));
        assert_eq!(ft.flow_count(), 0);
        assert_eq!(out2.iter().map(|(_, (w, ()))| w.len()).sum::<usize>(), 1);
        let out3 = ft.each(node(t0 + IDLE + WINDOW));
        assert!(out3.is_empty());
    }

    /// Активность обновляет last-seen → ключ жив.
    #[test]
    fn active_flow_not_evicted() {
        let t0 = Instant::now();
        let mut ft: FlowTable<TickPing, Flow> = FlowTable::new(IDLE, 1024, |_| TickPing);
        feed(&mut ft, seg(), t0);
        feed(&mut ft, seg(), t0 + WINDOW);
        let out = ft.each(node(t0 + WINDOW + Duration::from_secs(1)));
        assert_eq!(ft.flow_count(), 1);
        assert_eq!(out.iter().map(|(_, (w, ()))| w.len()).sum::<usize>(), 1);
    }
}
