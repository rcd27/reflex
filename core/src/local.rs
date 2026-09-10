//! `Local<C>` — форма, которую получит носитель БЕЗ ЯДЕРНОГО ДОМА (WinDivert; и второй живой
//! свидетель на Linux — задача 11). Ровно то, что `conntrack` + `ct_mark` дают очереди ядра
//! бесплатно (§ спеки «Local — край и дом состояния в юзерспейсе»), `Local` строит сам: край в
//! КАДРАХ (`EdgeView`, закон сужен задачей 4 — считать нагрузку значило бы разойтись с
//! conntrack'ом, который нагрузки не видит) и дом в своей карте (вместо `ct_mark`).
//!
//! ДЕКОРАТОР, не носитель: `Local<C>` оборачивает `C: Serves` и делегирует ему IO, подменяя ДОМ
//! (`Answer`/`CanRemember`) и КРАЙ (`Serves::Edge`) — оба, а не один. `Local::Carrier = C::Carrier`
//! БЕЗ ОБЁРТКИ (сообщение он не трогает), но `Local::Edge = LocalEdge`: `Serves::serve` отдаёт
//! `decide` СВОЙ `Option<LocalEdge>`, а `Option<C::Edge>` обёрнутого носителя принимает и
//! ОТБРАСЫВАЕТ. Так `Local<QueueSocket>` в дифференциальном стенде (задача 11) кормит приборы
//! СВОИМ счётом, а не `CtEdge`, хотя обёрнутый `QueueSocket` его и строит рядом. Заведи `Local`
//! второй закон о том же предмете в каждом безъядерном крейте — Windows и наш свидетель на Linux
//! разошлись бы молча. Здесь закон один, носителей — сколько угодно.
//!
//! ПОЧЕМУ КРАЙ ПЕРЕЕХАЛ НА `Serves`, А НЕ ОСТАЛСЯ НА СООБЩЕНИИ (`Edging`, `core::held`): первая
//! редакция вешала край на тип сообщения (`C::Carrier::Carrier`), и декоратор упирался в стену —
//! подменить `impl Edging` на ЧУЖОМ типе нечем (правило сирот, да и `Edging` даёт РОВНО ОДИН
//! `Edge` на тип, второй `impl` не собрать), а обернуть сообщение своим типом `serve` не давал:
//! `decide` получает лишь ССЫЛКУ (`&Held<Self::Carrier>`), а `Held::new` требует ВЛАДЕНИЯ — обёртка
//! потребовала бы либо лайфтайма на `Terminal::Carrier` (трейт заперт нарочно), либо копии байт на
//! КАЖДЫЙ пакет (антипаттерн, который `held.rs` считает ПОЧИНЕННЫМ: «первая редакция клала
//! `Vec<u8>` в само дело»). Довод «край есть величина разговора, бэкенд видит разговор только через
//! пакет» был ВЕРНЫМ, но отвечал не на тот вопрос — вопрос был не ГДЕ край вычисляется, а КТО
//! вправе его ПОДМЕНИТЬ. `serve` уже стоит МЕЖДУ вызывающим и декоратором: перенос `Edge` туда
//! решает подмену БЕСПЛАТНО, тем же неделимым шагом «взять и ответить», ничего не переиначивая в
//! `Edging` — он остаётся ВНУТРЕННИМ помощником носителя, у которого край и правда живёт в
//! сообщении (`QueueSocket::serve` строит `Self::Edge` через него же).
//!
//! ПРЕДЕЛ НОСИТЕЛЯ, названный прямо: возраст разговора, начавшегося ДО нашего запуска, неизвестен.
//! `opened` заполняется только когда `Local` САМ увидел `SYN` — иначе `age()` честно отдаёт `None`,
//! не ноль (ноль означал бы «только что открылся», и прибор тишины подтвердил бы дроп на живом
//! разговоре). `conntrack` в этом сильнее: он знает начало из ядра, а не из своего наблюдения —
//! это ПРЕДЕЛ НОСИТЕЛЯ, не закона (`EdgeView` его и не обещает: `age()` — `Option`).
//!
//! ЦЕНА ДОМА названа числом, не словами. Внутри `Serves::serve` — ОДИН разбор пятёрки на пакет:
//! `parsed` строится раз и читает его и наблюдение (`account`, свой край), и вердикт
//! (`write_answer`, ключ дома) — оба в ОДНОМ замыкании decide-обёртки. У ОТДЕЛЬНО СТОЯЩЕГО
//! `Terminal::apply` (когда решение приходит МИМО `serve`) разбор ВТОРОЙ и независимый: носитель
//! `C` отдаёт вердикту только байты (`Observed::payload`), разобранного на наблюдении кадра не
//! помнит и хранить не обязан. `conntrack` платит здесь НОЛЬ на обоих путях: связку
//! «пакет → разговор» даёт ядро на КАЖДОМ пакете, марка едет с пакетом (`NFQA_CT`) без разбора
//! фасадом. Вот чего стоит `ct_mark` — не верой, а числом: 1–2 разбора на пакет там, где ядро не
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

/// Занести УЖЕ РАЗОБРАННЫЙ кадр С НОСИТЕЛЯ в счёт и отдать снимок дома — своё замещение края,
/// ради которого `Local` заведён. Направление читается из адресов пятёрки (клиент → цель — вниз,
/// иначе вверх), а не объявляется вызывающим: внутри `Serves::serve` (единственный вызывающий)
/// направление неоткуда взять иначе, кадр пришёл с носителя как есть. Отдельно от [`saw`]
/// (используемого `saw_down`/`saw_up`), где направление УЖЕ известно вызывающему: `WinDivert`
/// отдаёт его флагом (`WINDIVERT_DATA_NETWORK.Outbound`) прямо в API.
///
/// Принимает `&Parsed`, а не байты, — РАЗБОР УЖЕ СДЕЛАН вызывающим (`Serves::serve`) один раз на
/// весь оборот: тот же результат нужен и наблюдению (счёт, свой край), и вердикту (ключ дома), и
/// вторым разбором за те же байты платить незачем, когда оба используются в ОДНОМ замыкании —
/// см. докблок `impl Serves`, где это и есть отличие от одиночного `Terminal::apply` (там разбор
/// действительно повторный, докблок `apply` называет его цену).
fn account(
    table: &mut FlowTable<Counts, Flow>,
    parsed: &Parsed,
    len: u64,
    at: Instant,
) -> LocalEdge {
    let key = normalize_flow(&parsed.flow);
    let down = parsed.flow == key;
    write_frame(table, key, down, len, parsed.syn, at);
    let counts = *table
        .get(&key)
        .expect("write_frame только что завела или обновила запись по этому ключу");
    LocalEdge { counts, now: at }
}

/// Декоратор носителя: свой счёт (край) и своя карта (дом) поверх любого `C: Serves`. См. докблок
/// модуля целиком — предел, цена, причина «декоратор, не носитель» изложены там.
pub struct Local<C> {
    carrier: C,
    table: FlowTable<Counts, Flow>,
}

impl<C> Local<C> {
    /// Завести декоратор со сроком простоя дома по умолчанию (`DEFAULT_IDLE`, приватная деталь
    /// модуля — не ссылка: значение не часть публичного контракта, кто хочет другой срок, зовёт
    /// [`Local::with_idle`]).
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
    /// прямой вход, минующий вывод направления из адресов (его делает `account`, докблок там).
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
    /// Свой край — не `C::Edge`. ЭТО и есть предмет, ради которого `Local` заведён (докблок
    /// модуля): декоратор стоит между вызывающим и обёрнутым `serve` и волен подать `decide`
    /// СВОЙ `Option<LocalEdge>` вместо ТОГО, что вернул обёрнутый носитель — его `C::Edge`
    /// внизу принят и отброшен (`_their_edge`), не переслан. Так `Local<QueueSocket>` в дифференциальном
    /// стенде (задача 11) отдаёт приборам СВОЙ счёт, а не `CtEdge`, хотя обёрнутый `QueueSocket`
    /// его и строит.
    type Edge = LocalEdge;

    /// Носитель `C` сам зовёт СВОЙ `Terminal::apply` изнутри `C::serve` (таково устройство
    /// `Serves` — задача 3/`held.rs`: взять и ответить неделимы, второго `&mut` на носителя не
    /// достать). Отсюда `Local::apply` вызвать ЗДЕСЬ нельзя — `self.carrier` уже занят вызовом
    /// `carrier.serve(...)`, а `Local::apply` просит `&mut self` целиком. Дом пишется тем же
    /// ТЕЛОМ (`write_answer`), что и `Terminal::apply`, но через поле `table`, занятое РАЗДЕЛЬНО
    /// от `carrier`, — два входа в одну логику, не два закона (см. докблок приватной `write_answer`
    /// рядом в этом файле — не ссылка: имя не экспортировано, случай private, а не забытый public).
    ///
    /// ОДИН разбор пятёрки на пакет, не два: `parsed` строится РАЗ и читается и наблюдением
    /// (`account`, свой край), и вердиктом (`write_answer`, ключ дома) — оба внутри ОДНОГО
    /// замыкания. Второй, независимый разбор за те же байты — цена ОТДЕЛЬНО стоящего
    /// `Terminal::apply` (докблок там), когда решение приходит МИМО `serve`.
    fn serve<F>(
        &mut self,
        until: Instant,
        decide: F,
    ) -> Served<Delivered<Answer>, Refused<Answer, C::Refusal>>
    where
        F: FnOnce(&Held<C::Carrier>, Option<LocalEdge>) -> Answer,
    {
        let table = &mut self.table;
        let mut local_answer: Option<Answer> = None;
        let outcome = self.carrier.serve(
            until,
            |held: &Held<C::Carrier>, _their_edge: Option<C::Edge>| -> C::Answer {
                let bytes = held.seen();
                let at = held.at();
                let parsed = parse_five_tuple(bytes);
                let own_edge = parsed
                    .as_ref()
                    .map(|p| account(table, p, bytes.len() as u64, at));
                let answer = decide(held, own_edge);
                local_answer = Some(answer);
                let accept = match &parsed {
                    Some(Parsed { flow, .. }) => write_answer(table, *flow, answer, at),
                    None => asked(answer).0,
                };
                if accept {
                    C::release()
                } else {
                    C::refuse()
                }
            },
        );

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
