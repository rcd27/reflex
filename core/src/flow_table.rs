use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

use crate::detector::{DetectorEvent, Ended};
use crate::mealy::Mealy;
use crate::timeout::Departure;
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
    /// Ключи, снятые с наблюдения и ещё не объявленные наружу, КАЖДЫЙ СО СВОЕЙ ПРИЧИНОЙ.
    ///
    /// Причина обязательна, потому что причины разной природы: прощание и срок снимают мёртвое
    /// (факт о мире), потолок снимает ЖИВОЕ, потому что место кончилось у нас (факт о НАС).
    /// Молчаливая утрата по потолку неотличима от «разговора не было»: прибор просто больше не
    /// увидит цели и решит, что та замолчала.
    ///
    /// Объявляются ВСЕ ТРИ, а не одна: за ключом стоит состояние не только наше. Разбор транспорта
    /// (`Talks`, личности целей) живёт в чужой карте по тому же ключу, и убрать его может лишь тот,
    /// кто узнал об уходе. Пока объявлялась одна причина из трёх, две карты разбора не убирались
    /// никогда — замер потребителя 18.09.2026: рост по числу ВИДЕННЫХ четвёрок, около 0,8 КБ на
    /// каждую, монотонно и невозвращаемо, на живых машинах сутками.
    departed: Vec<(K, Departure)>,
    make: Box<dyn Fn(&K) -> D + Send>,
}

impl<D, K, In> FlowTable<D, K>
where
    D: Mealy<In = DetectorEvent<In>>,
    K: Eq + Hash + Ord + Clone,
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
            departed: Vec::new(),
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
                self.departed.push((key.clone(), Departure::Ended));
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
            // Ничью равных моментов решает КЛЮЧ: порядок обхода `HashMap` у каждой таблицы свой,
            // и переигровка вытеснила бы не того, кого бой.
            let oldest = self
                .last_seen
                .iter()
                .min_by_key(|(key, seen)| (**seen, (*key).clone()))
                .map(|(key, _)| key.clone());
            match oldest {
                None => return,
                Some(key) => {
                    self.machines.remove(&key);
                    self.last_seen.remove(&key);
                    self.departed.push((key, Departure::Ceiling));
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
    #[must_use = "уход, брошенный молча, стоит дважды: утрата живого неотличима от того, что \
                  разговора не было, а состояние разбора по этому ключу не убирает больше никто"]
    pub fn departed(&mut self) -> Vec<(K, Departure)> {
        std::mem::take(&mut self.departed)
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
        // ОДИН ПРОХОД ПО СЕМЬЕ, а не список ключей и выборка по нему: семья обходится целиком,
        // значит её можно ОСУШИТЬ и собрать заново. Прежде копировались ВСЕ ключи в отдельный
        // вектор, а затем каждая машина вынималась и вставлялась обратно по одному.
        //
        // ЭТО УПРОЩЕНИЕ, А НЕ УСКОРЕНИЕ, и сказано так потому, что замерено: на входе в 2000
        // разговоров и 600 узлов сетки разницы во времени прогона нет (0,21 с против 0,21 с, по два
        // прогона). Шаг машин стоит дороже обхода, и копия ключей в нём тонет. Место, где она могла
        // бы стоить заметно, — восемь тысяч ЖИВЫХ машин на занятой машине, — на стенде не
        // воспроизводится: чтобы столько разговоров были живы одновременно, нужен настоящий
        // busy-NAT, а не запись.
        //
        // Ключ всё же копируется — один раз, в сказанное: пара «кто сказал» уезжает вызывающему, и
        // отдать её ссылкой некуда (машина к этому моменту уже шагнула). Копия под ВЫХОД законна,
        // копия под обход была не нужна.
        let FlowTable {
            machines,
            last_seen,
            idle_timeout,
            departed,
            ..
        } = self;
        let mut kept = HashMap::with_capacity(machines.len());
        let mut spoken = Vec::with_capacity(machines.len());
        for (key, machine) in machines.drain() {
            let (machine, said, noted) = machine.step(letter.clone());
            spoken.push((key.clone(), (said, noted)));
            match idle_by(last_seen, *idle_timeout, &key, at) {
                true => {
                    last_seen.remove(&key);
                    departed.push((key, Departure::Idle));
                }
                false => {
                    kept.insert(key, machine);
                }
            }
        }
        *machines = kept;
        spoken
    }

    pub fn get(&self, key: &K) -> Option<&D> {
        self.machines.get(key)
    }

    pub fn flow_count(&self) -> usize {
        self.machines.len()
    }

    /// Живые машины — для вопроса к таблице целиком («есть ли кто в таком-то положении»).
    pub fn machines(&self) -> impl Iterator<Item = (&K, &D)> {
        self.machines.iter()
    }
}

/// ЧАСТИ ТАБЛИЦЫ — всё её состояние, упорядоченное по ключу: из них таблица собирается заново той
/// же. Фабрики здесь нет — она настройка, а не состояние, и её даёт собирающий. Потребитель
/// пишет части в снимок, и переигровка начинает с середины боя с того же, с чего продолжил бой.
///
/// Машина и её последний момент — ОДНОЙ тройкой: у живой машины момент есть всегда, и машина без
/// момента (бессмертная — ни срок, ни потолок её не снимут) формой частей невыразима.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parts<D, K> {
    pub machines: Vec<(K, D, Instant)>,
    pub idle_timeout: Duration,
    pub capacity: usize,
    /// В порядке событий, а не ключа: уход — история, и её порядок задан тем, как она шла.
    pub departed: Vec<(K, Departure)>,
}

impl<D: Clone, K: Eq + Hash + Ord + Clone> FlowTable<D, K> {
    /// Снять части. Машины — по ключу: у `HashMap` своего порядка нет, а снимок обязан быть один и
    /// тот же, в каком бы процессе его ни сняли.
    pub fn parts(&self) -> Parts<D, K> {
        Parts {
            machines: self
                .machines
                .iter()
                .filter_map(|(key, machine)| {
                    self.last_seen
                        .get(key)
                        .map(|seen| (key.clone(), (machine.clone(), *seen)))
                })
                .collect::<std::collections::BTreeMap<K, (D, Instant)>>()
                .into_iter()
                .map(|(key, (machine, seen))| (key, machine, seen))
                .collect(),
            idle_timeout: self.idle_timeout,
            capacity: self.capacity,
            departed: self.departed.clone(),
        }
    }

    /// Собрать таблицу из частей и фабрики. Живых машин больше потолка не бывает — такие части
    /// подделаны или сняты другой версией, и таблица из них не собирается.
    pub fn from_parts(
        parts: Parts<D, K>,
        make: impl Fn(&K) -> D + Send + 'static,
    ) -> Result<Self, String> {
        match parts.machines.len() > parts.capacity {
            true => Err(format!(
                "частей таблицы {} при потолке {}",
                parts.machines.len(),
                parts.capacity
            )),
            false => Ok(Self {
                last_seen: parts
                    .machines
                    .iter()
                    .map(|(key, _machine, seen)| (key.clone(), *seen))
                    .collect(),
                machines: parts
                    .machines
                    .into_iter()
                    .map(|(key, machine, _seen)| (key, machine))
                    .collect(),
                idle_timeout: parts.idle_timeout,
                capacity: parts.capacity,
                departed: parts.departed,
                make: Box::new(make),
            }),
        }
    }
}

/// КРИТЕРИЙ ПРОСТОЯ — одним местом на всю таблицу. Свободной функцией, а не методом: обход семьи
/// осушает её и держит поля `self` разъятыми, а метод потребовал бы `&self` целиком и не собрался
/// бы рядом с этим обходом. Разложить же условие по местам вызова значило бы завести два срока под
/// одним именем.
fn idle_by<K: Eq + Hash>(
    last_seen: &HashMap<K, Instant>,
    idle_timeout: Duration,
    key: &K,
    at: Instant,
) -> bool {
    last_seen
        .get(key)
        .is_some_and(|seen| at.saturating_duration_since(*seen) >= idle_timeout)
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

    /// Таблица с потолком в две машины — на ней видно вытеснение.
    fn fed() -> FlowTable<TickPing, u32> {
        FlowTable::new(IDLE, 2, |_| TickPing)
    }

    /// НИЧЬЯ ВЫТЕСНЕНИЯ РЕШАЕТСЯ КЛЮЧОМ, а не порядком обхода `HashMap`: у каждой таблицы своё
    /// зерно, и два процесса с одной записью вытесняли бы разных — переигровка разошлась бы с боем.
    #[test]
    fn equal_last_seen_evicts_the_smallest_key() {
        let t0 = Instant::now();
        let evicted: Vec<Vec<(u32, Departure)>> = (0..16)
            .map(|_fresh| {
                [7_u32, 3, 5]
                    .iter()
                    .fold(fed(), |mut ft, key| {
                        drop(ft.process(*key, &seg(), t0));
                        ft
                    })
                    .departed()
            })
            .collect();
        assert!(
            evicted
                .iter()
                .all(|departed| departed == &vec![(3, Departure::Ceiling)]),
            "при равном моменте уходит меньший ключ: {evicted:?}"
        );
    }

    /// ЧАСТИ ТАБЛИЦЫ — всё её состояние: собранная из частей таблица отдаёт те же части и ведёт себя
    /// так же. Фабрику части не несут — она настройка, а не состояние, и её даёт собирающий.
    #[test]
    fn parts_round_trip_gives_the_same_table() {
        let t0 = Instant::now();
        let ft = [(9_u32, t0), (4, t0 + WINDOW), (6, t0 + WINDOW)]
            .iter()
            .fold(fed(), |mut ft, (key, at)| {
                drop(ft.process(*key, &seg(), *at));
                ft
            });
        let parts = ft.parts();
        assert_eq!(
            parts
                .machines
                .iter()
                .map(|(key, _machine, seen)| (*key, *seen))
                .collect::<Vec<(u32, Instant)>>(),
            vec![(4, t0 + WINDOW), (6, t0 + WINDOW)],
            "части упорядочены по ключу, момент — при своей машине"
        );
        assert_eq!(parts.departed, vec![(9, Departure::Ceiling)]);
        let Ok(rebuilt) = FlowTable::<TickPing, u32>::from_parts(parts.clone(), |_| TickPing)
        else {
            panic!("части собственной таблицы собираются")
        };
        let again = rebuilt.parts();
        assert_eq!(
            (
                again
                    .machines
                    .iter()
                    .map(|(key, _machine, seen)| (*key, *seen))
                    .collect::<Vec<(u32, Instant)>>(),
                again.departed,
                again.idle_timeout,
                again.capacity
            ),
            (
                parts
                    .machines
                    .iter()
                    .map(|(key, _machine, seen)| (*key, *seen))
                    .collect::<Vec<(u32, Instant)>>(),
                parts.departed,
                parts.idle_timeout,
                parts.capacity
            )
        );
    }

    /// Невозможная таблица из частей НЕ собирается: живых машин больше потолка не бывает — такие
    /// части подделаны или сняты другой версией, и собранная из них таблица жила бы вне закона.
    #[test]
    fn parts_over_the_ceiling_are_refused() {
        let t0 = Instant::now();
        let parts: Parts<TickPing, u32> = Parts {
            machines: vec![(1, TickPing, t0), (2, TickPing, t0), (3, TickPing, t0)],
            idle_timeout: IDLE,
            capacity: 2,
            departed: Vec::new(),
        };
        assert!(FlowTable::from_parts(parts, |_| TickPing).is_err());
    }
}
