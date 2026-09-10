//! Бумажный носитель — сценарий вместо сети. Не «мок ради теста», а НОСИТЕЛЬ: тот же [`Serves`],
//! тот же [`Terminal`], та же линейность владения, что у очереди ядра. Будь он проще настоящего —
//! он проверял бы не тот шов, и ведущий цикл остался бы без единственной своей проверки.
//!
//! ЧАСЫ У НЕГО СВОИ. `silent_for` двигает их скачком, а не спит: §8 объявляет время буквой входного
//! алфавита, значит подделать его законно, и тест на сетку не обязан гнать реальную секунду. Часы
//! заводятся при ПЕРВОМ `serve`, а не при постройке: шов начинается внутри `run`, и носитель,
//! заведённый раньше, отставал бы от сетки на величину сборки цепочки — первый узел выходил бы
//! на оборот позже.
//!
//! Журналы (`applied`, `injected`, `seen`) — общие с тестом ссылки на утёкшую память. Утечка
//! нарочна: носитель уезжает в цикл целиком и назад не возвращается, посмотреть на него после
//! прогона иначе нечем; а `&'static` даёт `Copy`, без которого прибор в `own(…)` не собрать.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use reflex::{own, smallvec, Cause, Distress, IntoCarrier, Own, SmallVec};
use reflex_core::backend::Sink;
use reflex_core::capability::{CanHold, CanInject, CanRefuse, CanRemember};
use reflex_core::command::InjectablePacket;
use reflex_core::edge::EdgeView;
use reflex_core::held::{Answered, Delivered, Edging, Held, Observed, Refused, Terminal};
use reflex_core::mealy::Mealy;
use reflex_core::serves::Served;
use reflex_core::{CanSever, DetectorEvent, Serves, Toward};
use reflex_instrument::edge::Layout;
use reflex_instrument::edge_word::Edged;
use reflex_instrument::wire::Seen;

/// Общий с тестом журнал. См. докблок модуля: почему утечка, а не `Arc`.
pub type Log<T> = &'static Mutex<Vec<T>>;

/// Завести журнал.
pub fn log<T: 'static>() -> Log<T> {
    Box::leak(Box::new(Mutex::new(Vec::new())))
}

/// Взять записанное копией: держать замок через `assert!` значит уронить его на панике вместе с
/// отчётом о том, что же было записано.
pub fn taken<T: Clone>(journal: Log<T>) -> Vec<T> {
    journal.lock().expect("журнал не отравлен").clone()
}

/// Что край бумажного носителя ведёт о разговоре. Свой, а не `CtEdge`: краевой прибор читает ЗАКОН
/// (`EdgeView`), не носителя, — и тем, что здесь стоит чужой ядру край, это и предъявляется.
#[derive(Debug, Clone, Copy)]
pub struct PaperEdge {
    pub up_packets: u64,
    pub down_packets: u64,
    pub down_bytes: u64,
    pub age: Duration,
    pub mark: u32,
}

impl Default for PaperEdge {
    /// Цель не ответила ни разу, клиент отдал запрос, возраст перешагнул любое разумное окно —
    /// краевому прибору есть о чём высказаться, и памятка родится.
    fn default() -> PaperEdge {
        PaperEdge {
            up_packets: 0,
            down_packets: 2,
            down_bytes: 2 * 60 + 400,
            age: Duration::from_secs(30),
            mark: 0,
        }
    }
}

impl EdgeView for PaperEdge {
    fn down_packets(&self) -> Option<u64> {
        Some(self.down_packets)
    }
    fn up_packets(&self) -> Option<u64> {
        Some(self.up_packets)
    }
    fn down_bytes(&self) -> Option<u64> {
        Some(self.down_bytes)
    }
    fn up_bytes(&self) -> Option<u64> {
        Some(0)
    }
    fn idle(&self) -> Option<Duration> {
        Some(Duration::ZERO)
    }
    fn age(&self) -> Option<Duration> {
        Some(self.age)
    }
    fn mark(&self) -> u32 {
        self.mark
    }
}

/// Чем бумажный носитель отвечает удержанному. Тот же словарь, что у очереди ядра, — и тем же
/// законом: `Remembered` несёт вердикт И состояние ОДНИМ словом (§5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaperAnswer {
    Pass,
    Stop,
    Remembered { accept: bool, state: u32 },
}

/// Носитель права ответить — сообщение со своими байтами и своим краем.
pub struct Message {
    bytes: Vec<u8>,
    edge: Option<PaperEdge>,
}

impl Observed for Message {
    fn payload(&self) -> &[u8] {
        &self.bytes
    }
}

impl Edging for Message {
    type Edge = PaperEdge;
    fn edge(&self) -> Option<PaperEdge> {
        self.edge
    }
}

/// Шаг сценария.
enum Step {
    /// Тишина: работы нет, часы идут.
    Silence(Duration),
    /// Пакет пришёл — через столько после предыдущей буквы.
    Packet(Duration, Vec<u8>),
    /// Носитель объявил потерю.
    Tear,
    /// Сценарий кончился; часы при этом могли уйти вперёд (см. `then_stop_after`).
    Stop(Duration),
}

/// Носитель-сценарий.
pub struct Paper {
    steps: VecDeque<Step>,
    /// Свои часы; `None` — ещё не заведены (см. докблок модуля).
    at: Option<Instant>,
    edge: Option<PaperEdge>,
    /// Нарушать ли закон срока: возвращаться из тишины немедленно, часов не двигая.
    hasty: bool,
    /// Отвечать ли на тишину `Blind` вместо `Idle` — дескриптора нет, а часы идут.
    blind: bool,
    /// Отказывать ли в доставке вердикта.
    refusing: bool,
    /// Почему носитель не откроется вовсе.
    shut: Option<String>,
    applied: Log<PaperAnswer>,
    injected: Log<Vec<u8>>,
    turns: &'static AtomicU32,
}

impl Paper {
    pub fn new() -> Paper {
        Paper {
            steps: VecDeque::new(),
            at: None,
            edge: Some(PaperEdge::default()),
            hasty: false,
            blind: false,
            refusing: false,
            shut: None,
            applied: log(),
            injected: log(),
            turns: Box::leak(Box::new(AtomicU32::new(0))),
        }
    }

    /// Тишина: работы нет, часы идут. Двигает свои часы скачком — реальной секунды не ждёт.
    pub fn silent_for(mut self, how_long: Duration) -> Paper {
        self.steps.push_back(Step::Silence(how_long));
        self
    }

    /// Пакет пришёл сразу — в тот же момент, что и предыдущая буква.
    pub fn then_packet(self, bytes: Vec<u8>) -> Paper {
        self.then_packet_after(Duration::ZERO, bytes)
    }

    /// Пакет пришёл ЧЕРЕЗ `how_long`, а цикл спросил о нём позже срока — так и рождается
    /// перешагнутый узел. В бою это случается, когда приборы медленнее сетки: срок уже прошёл,
    /// `serve` не ждёт вовсе и отдаёт пакет с моментом за узлом. То есть под нагрузкой, то есть
    /// ровно тогда, когда порядок букв и важен.
    pub fn then_packet_after(mut self, how_long: Duration, bytes: Vec<u8>) -> Paper {
        self.steps.push_back(Step::Packet(how_long, bytes));
        self
    }

    /// Носитель объявил потерю — `Served::Torn`.
    pub fn then_tear(mut self) -> Paper {
        self.steps.push_back(Step::Tear);
        self
    }

    /// Сценарий кончился.
    pub fn then_stop(self) -> Paper {
        self.then_stop_after(Duration::ZERO)
    }

    /// Сценарий кончился, а часы носителя ушли вперёд. Строка E1 таблицы шва: узлы за это время
    /// цикл НЕ выдаёт — выдавать их некому, машина больше не получит ни одного пакета.
    pub fn then_stop_after(mut self, how_long: Duration) -> Paper {
        self.steps.push_back(Step::Stop(how_long));
        self
    }

    /// Край, который носитель показывает о каждом пакете. `None` — края нет вовсе (§7: «не
    /// считали» ≠ «не ответила»).
    pub fn edging(mut self, edge: Option<PaperEdge>) -> Paper {
        self.edge = edge;
        self
    }

    /// Нарушить закон срока (`Serves::serve`): возвращаться из тишины немедленно.
    pub fn hasty(mut self) -> Paper {
        self.hasty = true;
        self
    }

    /// Дескриптора нет — `Served::Blind`. Часы при этом идут.
    pub fn blindfolded(mut self) -> Paper {
        self.blind = true;
        self
    }

    /// Отказывать в доставке вердикта — `Served::Answered(Err(_))`.
    pub fn refusing(mut self) -> Paper {
        self.refusing = true;
        self
    }

    /// Носитель не откроется: цикл не начнётся вовсе.
    pub fn shut(mut self, why: &str) -> Paper {
        self.shut = Some(why.to_string());
        self
    }

    /// Ручка на журнал `apply` — что уехало терминалу.
    pub fn applied(&self) -> Log<PaperAnswer> {
        self.applied
    }

    /// Ручка на журнал инъекций.
    pub fn injected(&self) -> Log<Vec<u8>> {
        self.injected
    }

    /// Сколько оборотов сделал ведущий цикл. Буквенный тест сжигания ядра не ловит (носитель,
    /// нарушивший закон срока, даёт ТЕ ЖЕ буквы) — счётчик ловит.
    pub fn turns(&self) -> &'static AtomicU32 {
        self.turns
    }

    /// Часы: заводятся при первом обращении.
    fn clock(&mut self) -> Instant {
        *self.at.get_or_insert_with(Instant::now)
    }

    /// Конец сценария вправе двигать часы (E1) — двигает их тогда, когда становится очередным.
    fn settle(&mut self) {
        if let Some(Step::Stop(leap)) = self.steps.front() {
            let leap = *leap;
            let at = self.clock();
            self.at = Some(at + leap);
        }
    }
}

impl Terminal for Paper {
    type Carrier = Message;
    type Answer = PaperAnswer;
    type Refusal = &'static str;

    /// ЕДИНСТВЕННОЕ место, где слово становится эффектом, — и потому единственный журнал того, что
    /// цепочка сказала носителю. Фасад сюда не заглядывает: он отдаёт слово, разбирает его носитель.
    fn apply(
        &mut self,
        answered: Answered<Message, PaperAnswer>,
    ) -> Result<Delivered<PaperAnswer>, Refused<PaperAnswer, &'static str>> {
        self.applied
            .lock()
            .expect("журнал не отравлен")
            .push(answered.answer);
        match self.refusing {
            false => Ok(Delivered {
                at: answered.at,
                answer: answered.answer,
            }),
            true => Err(Refused {
                at: answered.at,
                answer: answered.answer,
                why: "бумага отказала",
            }),
        }
    }
}

impl Serves for Paper {
    /// Закон срока исполняется движением СВОИХ часов, а не сном: носитель обязан не возвращаться
    /// раньше `until`, и он возвращается ровно в срок — просто срок наступает у него мгновенно.
    fn serve<F>(
        &mut self,
        until: Instant,
        decide: F,
    ) -> Served<Delivered<PaperAnswer>, Refused<PaperAnswer, &'static str>>
    where
        F: FnOnce(&Held<Message>) -> PaperAnswer,
    {
        self.turns.fetch_add(1, Ordering::SeqCst);
        let mut decide = Some(decide);
        loop {
            let at = self.clock();
            match self.steps.front_mut() {
                None | Some(Step::Stop(_)) => {
                    self.at = Some(at.max(until));
                    return Served::Idle;
                }
                Some(Step::Silence(left)) => {
                    let waiting = until.saturating_duration_since(at);
                    // НАРУШИТЕЛЬ ЗАКОНА СРОКА: вернуться, проспав вчетверо меньше обещанного. Не
                    // «вовсе не проспав»: носитель, чьи часы стоят намертво, сценарий не двигает
                    // никогда, и проверялся бы не цикл, а вечный `loop`. Четверть — довольно,
                    // чтобы сетка ушла вперёд его часов заметно.
                    if self.hasty {
                        let dozed = (waiting / 4).min(*left);
                        *left -= dozed;
                        self.at = Some(at + dozed);
                        if left.is_zero() {
                            self.steps.pop_front();
                            self.settle();
                            continue;
                        }
                        return match self.blind {
                            true => Served::Blind,
                            false => Served::Idle,
                        };
                    }
                    if *left > waiting {
                        *left -= waiting;
                        self.at = Some(until);
                        return match self.blind {
                            true => Served::Blind,
                            false => Served::Idle,
                        };
                    }
                    // Тишина кончилась раньше срока — работа, может быть, есть дальше.
                    self.at = Some(at + *left);
                    self.steps.pop_front();
                    self.settle();
                }
                Some(Step::Tear) => {
                    self.steps.pop_front();
                    self.settle();
                    return Served::Torn;
                }
                Some(Step::Packet(..)) => {
                    let Some(Step::Packet(after, bytes)) = self.steps.pop_front() else {
                        unreachable!("шаг только что был пакетом");
                    };
                    let at = at + after;
                    self.at = Some(at);
                    self.settle();
                    let held = Held::new(
                        Message {
                            bytes,
                            edge: self.edge,
                        },
                        at,
                    );
                    let answer = decide.take().expect("решение спрашивают один раз")(&held);
                    return Served::Answered(self.apply(held.answered(answer)));
                }
            }
        }
    }

    /// Больше работы не будет НИКОГДА: сценарий дошёл до конца.
    fn exhausted(&self) -> bool {
        matches!(self.steps.front(), None | Some(Step::Stop(_)))
    }
}

impl CanHold for Paper {
    fn release() -> PaperAnswer {
        PaperAnswer::Pass
    }
}

impl CanRefuse for Paper {
    fn refuse() -> PaperAnswer {
        PaperAnswer::Stop
    }
}

impl CanRemember for Paper {
    fn remember(state: u32, accept: bool) -> PaperAnswer {
        PaperAnswer::Remembered { accept, state }
    }
}

impl CanSever for Paper {
    fn notice(seen: &[u8], toward: Toward) -> Option<InjectablePacket> {
        reflex_core::notice::rst_for(seen, toward)
    }
}

impl Sink for Paper {
    type Command = InjectablePacket;
    type Error = &'static str;

    fn emit(&mut self, command: InjectablePacket) -> Result<(), &'static str> {
        self.injected
            .lock()
            .expect("журнал не отравлен")
            .push(command.serialize_ip());
        Ok(())
    }
}

impl CanInject for Paper {
    fn inject(packet: InjectablePacket) -> InjectablePacket {
        packet
    }
}

/// Носитель — сам себе рецепт: открывать нечего, кроме отказа, который тест назначил сам.
impl IntoCarrier for Paper {
    type Carrier = Paper;

    fn open(self) -> Result<Paper, Cause> {
        match &self.shut {
            Some(why) => Err(Cause(why.clone())),
            None => Ok(self),
        }
    }

    fn layout(&self) -> Layout {
        Layout::new(0x0FFF_E000, 0b101).expect("15 бит, ненулевой тег")
    }

    fn name(&self) -> String {
        "бумага".to_string()
    }
}

// ─── Прибор, записывающий дошедшие буквы ──────────────────────────────────────────────────────

/// Буква, дошедшая до прибора: имя и момент. Момент нужен строкам E2 и B — порядок и есть предмет.
#[derive(Debug, Clone)]
pub struct Letter {
    pub name: String,
    pub at: Instant,
}

/// Прибор, пишущий имена дошедших букв. Встаёт в цепочку через `own(…)` — ПУБЛИЧНУЮ дверь чужой
/// машины: своей двери для тестов не заводим, иначе проверялась бы она, а не та, которой пользуются.
///
/// Читает `Edged<Option<Seen>, …>`, а не `Seen`: у блэкхол-потока кроме `SYN` ничего и нет, а `SYN`
/// в общий словарь не сужается — прибор, потребовавший провод целым, не увидел бы ни одного пакета
/// (тот самый вчерашний регресс).
#[derive(Clone, Copy)]
pub struct Recorder {
    seen: Log<Letter>,
}

impl Recorder {
    pub fn into(seen: Log<Letter>) -> Own<Recorder, Edged<Option<Seen>, Option<PaperEdge>>> {
        own(Recorder { seen })
    }
}

impl Mealy for Recorder {
    type In = DetectorEvent<Edged<Option<Seen>, Option<PaperEdge>>>;
    type Out = SmallVec<[Distress; 2]>;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        let name = match &event {
            DetectorEvent::Packet { .. } => "packet",
            DetectorEvent::Tick { .. } => "tick",
            DetectorEvent::Opaque { .. } => "opaque",
            DetectorEvent::Torn { .. } => "torn",
        };
        self.seen.lock().expect("журнал не отравлен").push(Letter {
            name: name.to_string(),
            at: event.at(),
        });
        (self, SmallVec::new(), ())
    }
}

/// Прибор, кричащий на КАЖДЫЙ пакет. Нужен там, где проверяется не находка, а путь находки в мир:
/// молчащий прибор не отличил бы «реакция не позвана» от «сказать было нечего».
#[derive(Clone, Copy)]
pub struct Crier;

impl Crier {
    pub fn always() -> Own<Crier, Edged<Option<Seen>, Option<PaperEdge>>> {
        own(Crier)
    }
}

impl Mealy for Crier {
    type In = DetectorEvent<Edged<Option<Seen>, Option<PaperEdge>>>;
    type Out = SmallVec<[Distress; 2]>;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        match event {
            DetectorEvent::Packet { .. } => (self, smallvec![Distress::NoBytes], ()),
            _ => (self, SmallVec::new(), ()),
        }
    }
}

/// Имена дошедших букв по порядку.
pub fn names(seen: Log<Letter>) -> Vec<String> {
    taken(seen).into_iter().map(|letter| letter.name).collect()
}

// ─── Кадры ────────────────────────────────────────────────────────────────────────────────────

/// Минимальный кадр IPv4+TCP — ровно то, что очередь ядра кладёт в руки: без Ethernet.
fn frame(src_port: u16, dst_port: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
    let total = 20 + 20 + payload.len();
    let mut packet = vec![0u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[9] = 6;
    packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
    packet[16..20].copy_from_slice(&[93, 184, 216, 34]);
    packet[20..22].copy_from_slice(&src_port.to_be_bytes());
    packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
    packet[32] = 5 << 4;
    packet[33] = flags;
    packet[34..36].copy_from_slice(&64240u16.to_be_bytes());
    packet[40..].copy_from_slice(payload);
    packet
}

/// Стук клиента: `SYN` к цели. Буква ТРАНСПОРТА (`SeenTcp::Syn`) — в общий словарь не сужается.
pub fn syn(src_port: u16) -> Vec<u8> {
    frame(src_port, 443, 0x02, &[])
}

/// Запрос клиента с нагрузкой.
pub fn request(src_port: u16) -> Vec<u8> {
    frame(src_port, 443, 0x18, &[0x16, 0x03, 0x01, 0x00, 0x40])
}

/// ЧУЖОЙ кадр: не наш порт, транспорт его не опознает (`observe → None`).
pub fn alien() -> Vec<u8> {
    frame(40000, 80, 0x18, &[0x41; 8])
}
