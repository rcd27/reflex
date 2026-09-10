//! `Local<C>` — форма, которую получит носитель БЕЗ ЯДЕРНОГО ДОМА (WinDivert; и второй живой
//! свидетель на Linux — задача 11). Ровно то, что `conntrack` + `ct_mark` дают очереди ядра
//! бесплатно (§ спеки «Local — край и дом состояния в юзерспейсе»), `Local` строит сам: край в
//! КАДРАХ (`EdgeView`, закон сужен задачей 4 — считать нагрузку значило бы разойтись с
//! conntrack'ом, который нагрузки не видит) и дом в своей карте (вместо `ct_mark`).
//!
//! ДЕКОРАТОР, не носитель: `Local<C>` оборачивает `C: Serves` и делегирует ему IO, подменяя ДОМ
//! (`Answer`/`CanRemember`) и то, ЧЕМ САМ СЕБЯ СЧИТАЕТ на приходе и на вердикте (`note`/
//! `write_answer` читают и пишут СВОЙ `FlowTable`, а не `C::Carrier`'ов родной `Edging`, если он у
//! носителя вообще есть). Заведи `Local` второй закон о том же предмете в каждом безъядерном
//! крейте — Windows и наш свидетель на Linux разошлись бы молча. Здесь закон один, носителей —
//! сколько угодно.
//!
//! ГРАНИЦА ЭТОЙ ЗАДАЧИ, названная явно: `Local::Carrier = C::Carrier` — БЕЗ ОБЁРТКИ. Если у
//! `C::Carrier` уже есть родной `Edging` (у `queue::terminal::Held` — `CtEdge`), декоратор его НЕ
//! перекрывает — `held.carrier().edge()` внутри чужого детектора, доведённый до `Local<C>` через
//! `Bordered`/`IntoCarrier` (`reflex/src/lib.rs`), по-прежнему видел бы `CtEdge`, не `LocalEdge`.
//! Обёртка, отдающая `LocalEdge` тем же путём, потребовала бы либо параметра времени жизни у
//! `Terminal::Carrier` (трейт фиксирован, менять его — не эта задача), либо копии байт на КАЖДЫЙ
//! пакет (`Held` нарочно СВОИХ байт не хранит — `held.rs`: «первая редакция клала `Vec<u8>` в само
//! дело», и это было ПОЧИНЕНО, не забыто). Читать `LocalEdge` предмету, минующему `Bordered`,
//! годится [`Local::edge_of`] — прямая дверь, ту же цепочку в детектор ставит задача 11, зная
//! КОНКРЕТНЫЙ тип сообщения `QueueSocket`, а не абстрактный `C`.
//!
//! ПРЕДЕЛ НОСИТЕЛЯ, названный прямо: возраст разговора, начавшегося ДО нашего запуска, неизвестен.
//! `opened` заполняется только когда `Local` САМ увидел `SYN` — иначе `age()` честно отдаёт `None`,
//! не ноль (ноль означал бы «только что открылся», и прибор тишины подтвердил бы дроп на живом
//! разговоре). `conntrack` в этом сильнее: он знает начало из ядра, а не из своего наблюдения —
//! это ПРЕДЕЛ НОСИТЕЛЯ, не закона (`EdgeView` его и не обещает: `age()` — `Option`).
//!
//! ЦЕНА ДОМА названа числом, не словами: на пакет — ДВА разбора пятёрки (IPv4 + TCP/UDP заголовки),
//! не один. Первый — на ПРИХОДЕ (`note`, внутри `serve`): найти ключ, которым завести или обновить
//! счёт. Второй — на ВЕРДИКТЕ (`Terminal::apply`): носитель `C` отдаёт вердикту только байты
//! (`Observed::payload`), разобранного кадра из шага наблюдения он не помнит и хранить не обязан —
//! отсюда второй разбор ЗА ТЕ ЖЕ БАЙТЫ. `conntrack` платит здесь НОЛЬ: связку «пакет → разговор»
//! ему даёт ядро на КАЖДОМ пакете, а марка едет с пакетом (`NFQA_CT`) без дополнительного разбора
//! фасадом. Вот чего стоит `ct_mark` — не верой, а числом: 2 разбора на пакет там, где ядро не
//! просит ни одного.

use std::time::{Duration, Instant};

use crate::capability::{CanHold, CanRefuse, CanRemember};
use crate::detector::DetectorEvent;
use crate::edge::EdgeView;
use crate::flow_table::{normalize_flow, FlowTable};
use crate::held::{Answered, Delivered, Held, Observed, Refused, Terminal};
use crate::mealy::Mealy;
use crate::serves::Served;
use crate::types::{Flow, IpProtocol, Ipv4Packet, TcpFlags, TcpSegment, UdpDatagram};
use crate::Serves;

/// Срок простоя дома по умолчанию: вдвое больше типичного таймаута `ESTABLISHED` conntrack'а на
/// таймвейт TCP (5 минут) — не потому, что число священно, а потому, что дом обязан пережить паузу
/// внутри разговора длиннее, чем самая частая, не превращая её в эвикт. Точная настройка — дело
/// вызывающего (`with_idle`), это лишь безопасное значение по умолчанию.
const DEFAULT_IDLE: Duration = Duration::from_secs(600);

/// Чем `Local<C>` отвечает удержанному. СВОЙ словарь, не `C::Answer`: `Local` не обязан знать,
/// какими вариантами C размечает решение (`QueueSocket::Answer`, будущий `WinDivertHandle::Answer`
/// — разные типы), а перевод в C-слово — дело `Terminal::apply`, единственного места, где `C`
/// снова становится конкретным.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    Pass,
    Stop,
    /// Несёт ОБА факта одним словом — вердикт и память (§5): раздельные слова допускали бы
    /// «ответили, но не запомнили».
    Remembered {
        accept: bool,
        state: u32,
    },
}

/// Разобрать `Answer` на исполнение: пропустить ли, и что (если есть что) лечь в дом.
fn asked(answer: Answer) -> (bool, Option<u32>) {
    match answer {
        Answer::Pass => (true, None),
        Answer::Stop => (false, None),
        Answer::Remembered { accept, state } => (accept, Some(state)),
    }
}

/// Что дом помнит о разговоре — прямой аналог полей `CtView` (`linux/src/conntrack/wire.rs`), но
/// заполняемых НАШИМ наблюдением, а не выданных ядром.
#[derive(Debug, Clone, Copy, Default)]
struct Counts {
    down_packets: u64,
    up_packets: u64,
    down_bytes: u64,
    up_bytes: u64,
    /// Момент, когда `Local` САМ увидел `SYN` этого разговора. `None`, пока `SYN` не пойман —
    /// докблок модуля называет почему.
    opened: Option<Instant>,
    /// Момент последнего кадра — основа `idle()`, симметрично `opened` для `age()`.
    last_seen: Option<Instant>,
    mark: u32,
}

/// Буква, которой `Local` кормит свой `FlowTable`: либо кадр (для счёта и, может быть, `opened`),
/// либо марка (из ответа, минуя счёт кадров — конверт `ct_mark` пишется решением, не наблюдением).
/// ОДИН вход, не два разных ключевания, — тот же `FlowTable`, что и у детекторов (`process`),
/// потому и создаёт запись при первом кадре ТЕМ ЖЕ механизмом (`make`), без второй копии логики
/// «завести, если нет».
#[derive(Debug, Clone)]
enum LocalEvent {
    Frame { down: bool, len: u64, syn: bool },
    Mark(u32),
}

impl Mealy for Counts {
    type In = DetectorEvent<LocalEvent>;
    type Out = ();
    type Log = ();

    fn step(mut self, event: Self::In) -> (Self, (), ()) {
        if let DetectorEvent::Packet { input, at } = event {
            match input {
                LocalEvent::Frame { down, len, syn } => {
                    match down {
                        true => {
                            self.down_packets += 1;
                            self.down_bytes += len;
                        }
                        false => {
                            self.up_packets += 1;
                            self.up_bytes += len;
                        }
                    }
                    if syn && self.opened.is_none() {
                        self.opened = Some(at);
                    }
                    self.last_seen = Some(at);
                }
                LocalEvent::Mark(mark) => self.mark = mark,
            }
        }
        (self, (), ())
    }
}

/// Величины края, как их видит `Local` — носитель [`EdgeView`], симметричный `CtEdge`
/// (`linux/src/conntrack/edge.rs`), только источник другой: не ядро, а собственное наблюдение.
#[derive(Debug, Clone, Copy)]
pub struct LocalEdge {
    counts: Counts,
    /// Часы снимка — момент, когда `edge_of` собрал `LocalEdge`. Ровно как `CtEdge::seen` берёт
    /// `SystemTime::now()` при сборке, не раньше: `idle`/`age` — снимок на МОМЕНТ ЧТЕНИЯ, а не на
    /// момент последнего кадра, иначе тишина, длящаяся дольше опроса, не двигала бы их вовсе.
    now: Instant,
}

impl EdgeView for LocalEdge {
    fn down_packets(&self) -> Option<u64> {
        Some(self.counts.down_packets)
    }

    fn up_packets(&self) -> Option<u64> {
        Some(self.counts.up_packets)
    }

    fn down_bytes(&self) -> Option<u64> {
        Some(self.counts.down_bytes)
    }

    fn up_bytes(&self) -> Option<u64> {
        Some(self.counts.up_bytes)
    }

    fn idle(&self) -> Option<Duration> {
        self.counts
            .last_seen
            .map(|seen| self.now.saturating_duration_since(seen))
    }

    /// `None` — либо `SYN` не наш (предел носителя, см. докблок модуля), либо разговор известен
    /// только домашней памяткой без единого замеченного кадра (не бывает: `Mark` без `Frame` не
    /// заводит запись, см. `apply_answer`, но `LocalEdge` строится ИЗ существующей записи — второй
    /// причины `None` здесь просто не возникает; отражена ради честности сигнатуры, не как
    /// специальный случай).
    fn age(&self) -> Option<Duration> {
        self.counts
            .opened
            .map(|opened| self.now.saturating_duration_since(opened))
    }

    fn mark(&self) -> u32 {
        self.counts.mark
    }
}

/// Пятёрка и `SYN`-флаг, снятые ОДНИМ разбором — см. докблок модуля про цену дома: считать их
/// раздельными функциями значило бы платить за разбор дважды там, где нужен один раз.
struct Parsed {
    flow: Flow,
    syn: bool,
}

fn parse_five_tuple(frame: &[u8]) -> Option<Parsed> {
    let ip = Ipv4Packet::parse(frame)?;
    match ip.protocol {
        IpProtocol::Tcp => {
            let seg = TcpSegment::parse(&ip.payload, ip.src, ip.dst, ip.ttl)?;
            Some(Parsed {
                flow: seg.flow,
                syn: seg.flags.contains(TcpFlags::SYN),
            })
        }
        // UDP не несёт `SYN` — начало разговора им не отмечено никак, и `opened` для UDP-потока
        // остаётся `None` навсегда. Тот же предел, что и у пропущенного TCP-`SYN`, только вечный:
        // назван здесь, а не скрыт нулём.
        IpProtocol::Udp => {
            let dgram = UdpDatagram::parse(&ip.payload, ip.src, ip.dst, ip.ttl)?;
            Some(Parsed {
                flow: dgram.flow,
                syn: false,
            })
        }
        IpProtocol::Icmp | IpProtocol::Other(_) => None,
    }
}

fn write_frame(
    table: &mut FlowTable<Counts, Flow>,
    key: Flow,
    down: bool,
    len: u64,
    syn: bool,
    at: Instant,
) {
    table.process(key, &LocalEvent::Frame { down, len, syn }, at);
}

/// Тело «применить ответ к дому» — используется и `Terminal::apply` (через `&mut self`), и
/// `Serves::serve` (через поле, занятое РАЗДЕЛЬНО от `self.carrier` — см. докблок `impl Serves`).
/// Логика ОДНА, входов два по причине заимствования, а не по недосмотру: тот же снаряд, которым
/// задача 8 объясняет, почему очередь ядра — `Serves`, а не `Source` (`held.rs`).
fn write_answer(
    table: &mut FlowTable<Counts, Flow>,
    flow: Flow,
    answer: Answer,
    at: Instant,
) -> bool {
    let key = normalize_flow(&flow);
    let (accept, state) = asked(answer);
    if let Some(state) = state {
        table.process(key, &LocalEvent::Mark(state), at);
    }
    accept
}

fn saw(table: &mut FlowTable<Counts, Flow>, frame: &[u8], down: bool, at: Instant) {
    if let Some(Parsed { flow, syn }) = parse_five_tuple(frame) {
        write_frame(
            table,
            normalize_flow(&flow),
            down,
            frame.len() as u64,
            syn,
            at,
        );
    }
}

/// Заметить кадр С НОСИТЕЛЯ, направление которого читается из его же адресов (клиент → цель — вниз,
/// иначе вверх), а не объявляется вызывающим. Отдельно от [`saw`] (используемого `saw_down`/
/// `saw_up`), где направление УЖЕ известно вызывающему: `WinDivert` отдаёт его флагом
/// (`WINDIVERT_DATA_NETWORK.Outbound`) прямо в API, и платить за вывод направления из портов там,
/// где оно и так дано, было бы третьим разбором сверх названных в докблоке модуля двух.
fn note(table: &mut FlowTable<Counts, Flow>, frame: &[u8], at: Instant) {
    if let Some(Parsed { flow, syn }) = parse_five_tuple(frame) {
        let key = normalize_flow(&flow);
        let down = flow == key;
        write_frame(table, key, down, frame.len() as u64, syn, at);
    }
}

/// Декоратор носителя: свой счёт (край) и своя карта (дом) поверх любого `C: Serves`. См. докблок
/// модуля целиком — предел, цена, причина «декоратор, не носитель» изложены там.
pub struct Local<C> {
    carrier: C,
    table: FlowTable<Counts, Flow>,
}

impl<C> Local<C> {
    /// Завести декоратор со сроком простоя дома по умолчанию ([`DEFAULT_IDLE`]).
    pub fn new(carrier: C) -> Local<C> {
        Local::with_idle(carrier, DEFAULT_IDLE)
    }

    /// Завести декоратор с явным сроком простоя дома — эвикт `FlowTable` (канон §4: память конечна).
    pub fn with_idle(carrier: C, idle: Duration) -> Local<C> {
        Local {
            carrier,
            table: FlowTable::new(idle, |_flow| Counts::default()),
        }
    }

    /// Заметить кадр, идущий ВНИЗ (клиент → цель), направление которого ИЗВЕСТНО вызывающему —
    /// прямой вход, минующий вывод направления из адресов (см. докблок [`note`]).
    pub fn saw_down(&mut self, frame: impl AsRef<[u8]>) {
        saw(&mut self.table, frame.as_ref(), true, Instant::now());
    }

    /// Симметрично [`saw_down`](Self::saw_down): кадр, идущий ВВЕРХ (цель → клиент).
    pub fn saw_up(&mut self, frame: impl AsRef<[u8]>) {
        saw(&mut self.table, frame.as_ref(), false, Instant::now());
    }

    /// Применить ответ к дому разговора: марка (если есть) ложится в карту, а признак пропуска
    /// возвращается вызывающему — сам `apply_answer` носителя `C` не трогает, это дело
    /// `Terminal::apply`/`Serves::serve`.
    pub fn apply_answer(&mut self, flow: Flow, answer: Answer) -> bool {
        write_answer(&mut self.table, flow, answer, Instant::now())
    }

    /// Величины края разговора — снимок НА МОМЕНТ ВЫЗОВА (докблок [`LocalEdge`]). `None` — разговор
    /// не заведён (клетка §7: «не считали» ≠ «не ответила»).
    pub fn edge_of(&self, flow: Flow) -> Option<LocalEdge> {
        let key = normalize_flow(&flow);
        self.table.get(&key).map(|counts| LocalEdge {
            counts: *counts,
            now: Instant::now(),
        })
    }
}

impl<C> Terminal for Local<C>
where
    C: Terminal + CanHold + CanRefuse,
    C::Carrier: Observed,
{
    type Carrier = C::Carrier;
    type Answer = Answer;
    type Refusal = C::Refusal;

    /// Цена дома здесь и случается: `carrier.payload()` — только байты, разобранного кадра со
    /// стороны наблюдения носитель не хранит (не обязан — это чужое знание), и ключ дома находится
    /// ВТОРЫМ разбором пятёрки за эти же байты. Докблок модуля называет это числом (2 разбора на
    /// пакет), это — вторая половина счёта.
    fn apply(
        &mut self,
        answered: Answered<C::Carrier, Answer>,
    ) -> Result<Delivered<Answer>, Refused<Answer, C::Refusal>> {
        let Answered {
            carrier,
            at,
            answer,
        } = answered;
        let accept = match parse_five_tuple(carrier.payload()) {
            Some(Parsed { flow, .. }) => self.apply_answer(flow, answer),
            // Кадр не разобрать (короткий, не IPv4, чужой протокол) — дом писать некуда, но решение
            // исполнить обязаны: конверт `asked` даёт признак пропуска и без ключа.
            None => asked(answer).0,
        };
        let c_answer = if accept { C::release() } else { C::refuse() };
        match self.carrier.apply(Answered {
            carrier,
            at,
            answer: c_answer,
        }) {
            Ok(delivered) => Ok(Delivered {
                at: delivered.at,
                answer,
            }),
            Err(refused) => Err(Refused {
                at: refused.at,
                answer,
                why: refused.why,
            }),
        }
    }
}

impl<C> CanHold for Local<C>
where
    C: Terminal + CanHold + CanRefuse,
    C::Carrier: Observed,
{
    fn release() -> Answer {
        Answer::Pass
    }
}

impl<C> CanRefuse for Local<C>
where
    C: Terminal + CanHold + CanRefuse,
    C::Carrier: Observed,
{
    fn refuse() -> Answer {
        Answer::Stop
    }
}

impl<C> CanRemember for Local<C>
where
    C: Terminal + CanHold + CanRefuse,
    C::Carrier: Observed,
{
    fn remember(state: u32, accept: bool) -> Answer {
        Answer::Remembered { accept, state }
    }
}

impl<C> Serves for Local<C>
where
    C: Serves + CanHold + CanRefuse,
    C::Carrier: Observed,
{
    /// Носитель `C` сам зовёт СВОЙ `Terminal::apply` изнутри `C::serve` (таково устройство
    /// `Serves` — задача 3/`held.rs`: взять и ответить неделимы, второго `&mut` на носителя не
    /// достать). Отсюда `Local::apply` вызвать ЗДЕСЬ нельзя — `self.carrier` уже занят вызовом
    /// `carrier.serve(...)`, а `Local::apply` просит `&mut self` целиком. Дом пишется тем же
    /// ТЕЛОМ (`write_answer`), что и `Terminal::apply`, но через поле `table`, занятое РАЗДЕЛЬНО
    /// от `carrier`, — два входа в одну логику, не два закона (см. докблок [`write_answer`]).
    fn serve<F>(
        &mut self,
        until: Instant,
        decide: F,
    ) -> Served<Delivered<Answer>, Refused<Answer, C::Refusal>>
    where
        F: FnOnce(&Held<C::Carrier>) -> Answer,
    {
        let table = &mut self.table;
        let mut local_answer: Option<Answer> = None;
        let outcome = self
            .carrier
            .serve(until, |held: &Held<C::Carrier>| -> C::Answer {
                let bytes = held.seen();
                note(table, bytes, held.at());
                let answer = decide(held);
                local_answer = Some(answer);
                let accept = match parse_five_tuple(bytes) {
                    Some(Parsed { flow, .. }) => write_answer(table, flow, answer, held.at()),
                    None => asked(answer).0,
                };
                if accept {
                    C::release()
                } else {
                    C::refuse()
                }
            });

        match outcome {
            Served::Answered(Ok(delivered)) => Served::Answered(Ok(Delivered {
                at: delivered.at,
                answer: local_answer.expect("serve зовёт decide лишь на исходе Answered"),
            })),
            Served::Answered(Err(refused)) => Served::Answered(Err(Refused {
                at: refused.at,
                answer: local_answer.expect("serve зовёт decide лишь на исходе Answered"),
                why: refused.why,
            })),
            Served::Idle => Served::Idle,
            Served::Blind => Served::Blind,
            Served::Torn(at) => Served::Torn(at),
        }
    }

    /// Конец источника — знание `C`, не наше: `Local` его не подменяет и не педалирует.
    fn exhausted(&self) -> bool {
        self.carrier.exhausted()
    }
}
