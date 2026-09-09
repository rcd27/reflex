//! `reflex` — единственная дверь фреймворка. Потребитель пишет цепочку и больше ничего не знает:
//!
//! ```no_run
//! use reflex::*;
//!
//! fn main() -> Report {
//!     engine(Nfqueue::queue(200))
//!         .from(Tcp)
//!         .extract(Sni)
//!         .detect(Retransmit::unanswered()) // быстрое подозрение — по повтору клиента
//!         .detect(Silence::after(secs(5)))  // медленное подтверждение — по окну тишины
//!         .on(|target, distress| match distress {
//!             Distress::Retransmit { after_ms } => {
//!                 report!("подозрение на тихий дроп: {target} (повтор через {after_ms}мс)")
//!             }
//!             Distress::Silence { ms } => report!("подтверждено: {target} молчит {ms}мс"),
//!             Distress::NoBytes => report!("подтверждено: {target} не ответил вовсе"),
//!             _ => {}
//!         })
//!         .run()
//! }
//! ```
//!
//! Ни `Plane`, ни `Interleave`, ни `DetectorEvent`, ни `parse` наружу не торчат. Две оси
//! полиморфизма закрыты в движке:
//!
//! * `.from(T)` — ТРАНСПОРТ: `Tcp` даёт словарь соединения, `Udp` — датаграммы (DNS). Каждый
//!   несёт свой широкий словарь провода и свой порт.
//! * `.detect(D)` — ПРИБОР: любой, читающий свой алфавит из широкого через `Reads` (канон §4).
//!   Приборы разных алфавитов встают в одну дверь; несовместимый транспорту прибор не соберётся.
//! * терминал — НАБЛЮДАТЬ (`.on`) или ДЕЙСТВОВАТЬ (`.act`, реакция возвращает [`Act`]: `Sever`
//!   инжектит RST — тихий дроп обрывается за ~300мс вместо вечной крутилки).
//!
//! Склейку сигналов в вывод пишет потребитель — фреймворк описывает МИР, лечение живёт у него.
//!
//! [`run`]: Running::run

use std::collections::HashMap;
use std::marker::PhantomData;
use std::time::{Duration, Instant};

use reflex_core::dns::DnsMessage;
use reflex_core::flow_table::FlowTable;
use reflex_core::mealy::Mealy;
use reflex_core::serves::Served;
use reflex_core::tls;
use reflex_core::DetectorEvent;
use reflex_core::Reads;
use reflex_core::{CanSever, Serves, Toward};
use reflex_engine::row::{host_of, keyed, Naming, TargetKey};
use reflex_engine::{Addr, FlowKey};
use reflex_engine_nfq::parse::{self, Read};
use reflex_engine_nfq::talk::Talks;
use reflex_instrument::detect::{SilenceInstrument, SynDropInstrument};
use reflex_instrument::poison::DnsPoisonInstrument;
use reflex_instrument::retransmit::RetransmitInstrument;
use reflex_instrument::wire::{Reading, Seen, SeenTcp};
use reflex_linux::nfqueue::{Answer, NfqueueBackend};
use reflex_linux::rawsend::RawSender;
use smallvec::SmallVec;

/// Алфавит беды, на который реагирует потребитель. Реэкспорт: это МИР, а не кишки фреймворка.
pub use reflex_instrument::distress::Distress;

/// Секунды — единица человека. Чтобы `secs(5)` читалось, а не `Duration::from_secs(5)`.
pub fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

/// Печать наблюдения. Обёртка над `eprintln!` с меткой — чтобы реакция читалась одной строкой.
#[macro_export]
macro_rules! report {
    ($($arg:tt)*) => {
        eprintln!("[reflex] {}", ::core::format_args!($($arg)*))
    };
}

/// Носитель — очередь ядра. `engine(Nfqueue::queue(200))` открывает движок над ней.
pub struct Nfqueue {
    queue: u16,
}

impl Nfqueue {
    /// Очередь netfilter с этим номером. Правило (`queue num N`) ставится снаружи — движок правил
    /// не ставит: кто поставил, тот и снимает.
    pub fn queue(num: u16) -> Nfqueue {
        Nfqueue { queue: num }
    }
}

/// Открыть движок над носителем — единственная точка входа фреймворка.
pub fn engine(backend: Nfqueue) -> Engine {
    Engine {
        queue: backend.queue,
    }
}

// ─── Транспорт: ось `.from` ───────────────────────────────────────────────────────────────────

/// Наблюдение из кадра: ключ разговора, имя цели (для реакции) и широкое слово провода.
pub struct Observed<W> {
    flow: FlowKey,
    target: String,
    wire: W,
}

/// Транспорт `.from(…)`. Несёт свой широкий словарь провода [`Transport::Wire`], порт сервера и своё
/// состояние разбора. Ось полиморфизма: `Tcp` и `Udp` дают РАЗНЫЕ пайпы, и прибор чужого алфавита в
/// пайп не соберётся (проверяет компилятор).
pub trait Transport {
    /// Широкий словарь наблюдений этого транспорта (из него приборы сужают свой алфавит).
    type Wire: Clone + 'static;
    /// Порт сервера: очередь ядра приносит и другой трафик.
    const PORT: u16;
    /// Состояние разбора (память разговоров, личность цели) — своё у каждого транспорта.
    type State: Default;
    /// Из разобранного кадра — наблюдение, либо ничего (не наш кадр).
    fn observe(state: &mut Self::State, read: Read<'_>) -> Option<Observed<Self::Wire>>;
}

/// Транспорт TCP: словарь соединения (`Reading`), порт 443, личность по SNI.
pub struct Tcp;

/// Личность цели TCP-разговора, копимая по ходу: адрес с первого пакета, имя — если пришло
/// приветствие с SNI. Отсюда рождается [`TargetKey`].
struct Ident {
    dst: Addr,
    naming: Naming<Box<str>>,
}

impl Ident {
    /// Как назвать цель: имя, если есть; иначе адрес (`keyed` — то же расслоение, каким цель ключует
    /// движок, §4). Безымянная цель (Телеграм, чистый IP) опознаётся по IP, не теряется.
    fn target(&self) -> String {
        match keyed(self.naming.clone(), self.dst, host_of) {
            TargetKey::Named(name) => name.to_string(),
            TargetKey::Unnamed(addr) => addr.to_string(),
        }
    }
}

/// Память TCP-разбора: разговоры (граница/повтор) и личность целей.
#[derive(Default)]
pub struct TcpState {
    talks: Talks,
    idents: HashMap<FlowKey, Ident>,
}

impl Transport for Tcp {
    type Wire = Reading;
    const PORT: u16 = 443;
    type State = TcpState;

    fn observe(state: &mut TcpState, read: Read<'_>) -> Option<Observed<Reading>> {
        let Read::Tcp(wire) = read else {
            return None;
        };
        // Личность копится; отсутствие SNI не теряется — цель по адресу.
        let ident = state.idents.entry(wire.flow).or_insert(Ident {
            dst: wire.dst,
            naming: Naming::Awaited,
        });
        if let Some(sni) = tls::extract_sni(wire.payload) {
            ident.naming = Naming::Spoken(sni.into());
        }
        let target = ident.target();
        state.talks.read(&wire).map(|tcp| Observed {
            flow: wire.flow,
            target,
            wire: Reading::Tcp(tcp),
        })
    }
}

/// Транспорт UDP: датаграммы, порт 53 (DNS). Имя цели — имя из DNS-запроса (оно в каждом сообщении,
/// потому память не нужна).
pub struct Udp;

/// У DNS имя в самом сообщении — состояния разбора нет.
#[derive(Default)]
pub struct UdpState;

impl Transport for Udp {
    type Wire = DnsMessage;
    const PORT: u16 = 53;
    type State = UdpState;

    fn observe(_state: &mut UdpState, read: Read<'_>) -> Option<Observed<DnsMessage>> {
        let Read::Udp(datagram) = read else {
            return None;
        };
        let message = DnsMessage::parse(datagram.payload)?;
        // Цель — имя из вопроса (оно же и отравляют); без имени — по адресу резолвера.
        let target = message
            .queries
            .first()
            .map(|query| query.name.clone())
            .unwrap_or_else(|| datagram.dst.to_string());
        Some(Observed {
            flow: datagram.flow,
            target,
            wire: message,
        })
    }
}

// ─── Приборы: ось `.detect` ───────────────────────────────────────────────────────────────────

/// Детектор тихого дропа по окну ТИШИНЫ: цель молчит дольше `after` — медленное подтверждение.
pub struct Silence {
    after: Duration,
}

impl Silence {
    /// Сколько молчания терпим, прежде чем назвать это тихим дропом.
    pub fn after(after: Duration) -> Silence {
        Silence { after }
    }
}

/// Детектор тихого дропа по ПОВТОРУ клиента: просьба ушла, ответа нет — самая ранняя улика (порог —
/// RTO клиента). Подозрение: обычная потеря даёт тот же повтор.
pub struct Retransmit;

impl Retransmit {
    /// Повтор без ответа цели.
    pub fn unanswered() -> Retransmit {
        Retransmit
    }
}

/// Детектор IP-blackhole: `SYN` без `SYN+ACK`, клиент повторяет `SYN` — блок по адресу, соединения
/// нет вовсе. Отдельный пайп: через `Silence`/`Retransmit` не выразить.
pub struct SynDrop;

impl SynDrop {
    /// Адрес недостижим: повтор стука без рукопожатия.
    pub fn unreachable() -> SynDrop {
        SynDrop
    }
}

/// Детектор отравления DNS: на запрос пришёл инжект (`NXDOMAIN`/пустой ответ). Подозрение: легитимный
/// `NXDOMAIN` даёт то же. Транспорт — `Udp`.
pub struct DnsPoison;

impl DnsPoison {
    /// Инжект отказа на запрос.
    pub fn injected() -> DnsPoison {
        DnsPoison
    }
}

/// Прибор в пайпе: шагает над ШИРОКИМ словом транспорта, сам сузив его до своего алфавита. `dyn` —
/// чтобы приборы разных алфавитов лежали одним списком; шаг дёшев, диспетч не на горячем счёте.
/// Скрыт из доков: потребитель его не называет (кладёт `Silence`/`SynDrop`/… через `IntoProbe`).
#[doc(hidden)]
pub trait Probe<W>: Send {
    /// Слова беды за этот шаг (пусто — прибору сказать нечего).
    fn observe(&mut self, event: &DetectorEvent<W>) -> SmallVec<[Distress; 2]>;
    /// Свежая копия шаблона — `FlowTable` заводит прибор на каждый ключ.
    fn clone_box(&self) -> Box<dyn Probe<W>>;
}

/// Сузить широкое событие до алфавита прибора (§4, `Reads`). Пакет — по букве прибора (`None` —
/// буква не его, шаг пропускается); тик и непонятое идут всем.
fn narrow<W, N: Reads<W>>(event: &DetectorEvent<W>) -> Option<DetectorEvent<N>> {
    match event {
        DetectorEvent::Packet { input, at } => {
            N::read(input).map(|input| DetectorEvent::Packet { input, at: *at })
        }
        DetectorEvent::Tick { node, at } => Some(DetectorEvent::Tick {
            node: *node,
            at: *at,
        }),
        DetectorEvent::Opaque { why, at } => Some(DetectorEvent::Opaque { why: *why, at: *at }),
    }
}

/// Подъём прибора-машины `M` над своим алфавитом `N` в пайп широкого слова `W`: сужение через
/// [`Reads`]. Так любой прибор парка (и чужой) встаёт в дверь, не зная о транспорте.
struct Lift<M, N> {
    machine: M,
    alphabet: PhantomData<fn() -> N>,
}

impl<W, N, M> Probe<W> for Lift<M, N>
where
    W: 'static,
    N: Reads<W> + 'static,
    M: Mealy<In = DetectorEvent<N>, Out = SmallVec<[Distress; 2]>> + Copy + Send + 'static,
{
    fn observe(&mut self, event: &DetectorEvent<W>) -> SmallVec<[Distress; 2]> {
        match narrow::<W, N>(event) {
            Some(event) => {
                let (machine, signals, _log) = self.machine.step(event);
                self.machine = machine;
                signals
            }
            None => SmallVec::new(),
        }
    }

    fn clone_box(&self) -> Box<dyn Probe<W>> {
        Box::new(Lift {
            machine: self.machine,
            alphabet: PhantomData,
        })
    }
}

/// Прибор, кладущийся в `.detect(…)` для транспорта с широким словом `W`. Реализуют конкретные
/// детекторы; несовместимый транспорту прибор не соберётся (нет `IntoProbe<W>`).
pub trait IntoProbe<W> {
    #[doc(hidden)]
    fn into_probe(self) -> Box<dyn Probe<W>>;
    /// Временно́е окно прибора (ноль у беспороговых) — по нему движок выбирает срок эвикта ключа.
    #[doc(hidden)]
    fn window(&self) -> Duration {
        Duration::ZERO
    }
}

/// Собрать прибор-машину в лифт над `W`.
fn lift<W, N, M>(machine: M) -> Box<dyn Probe<W>>
where
    W: 'static,
    N: Reads<W> + 'static,
    M: Mealy<In = DetectorEvent<N>, Out = SmallVec<[Distress; 2]>> + Copy + Send + 'static,
{
    Box::new(Lift {
        machine,
        alphabet: PhantomData,
    })
}

impl IntoProbe<Reading> for Silence {
    fn into_probe(self) -> Box<dyn Probe<Reading>> {
        lift::<Reading, Seen, _>(SilenceInstrument::after(self.after))
    }
    fn window(&self) -> Duration {
        self.after
    }
}

impl IntoProbe<Reading> for Retransmit {
    fn into_probe(self) -> Box<dyn Probe<Reading>> {
        lift::<Reading, Seen, _>(RetransmitInstrument::new())
    }
}

impl IntoProbe<Reading> for SynDrop {
    fn into_probe(self) -> Box<dyn Probe<Reading>> {
        lift::<Reading, SeenTcp, _>(SynDropInstrument::new())
    }
}

impl IntoProbe<DnsMessage> for DnsPoison {
    fn into_probe(self) -> Box<dyn Probe<DnsMessage>> {
        lift::<DnsMessage, DnsMessage, _>(DnsPoisonInstrument::new())
    }
}

/// Приборы разговора, гоняемые ВМЕСТЕ над одним словом провода. Пакет и тик фанаутятся в каждый,
/// слова беды сливаются в один алфавит [`Distress`].
struct Probes<W>(Vec<Box<dyn Probe<W>>>);

impl<W: Clone + 'static> Mealy for Probes<W> {
    type In = DetectorEvent<W>;
    type Out = SmallVec<[Distress; 2]>;
    type Log = ();

    fn step(mut self, event: Self::In) -> (Self, Self::Out, ()) {
        let mut said: SmallVec<[Distress; 2]> = SmallVec::new();
        for probe in self.0.iter_mut() {
            said.extend(probe.observe(&event));
        }
        (self, said, ())
    }
}

// ─── Цепочка сборки ───────────────────────────────────────────────────────────────────────────

/// Чем ключуется цель: именем из `ClientHello`, при его отсутствии — адресом (§4). Отсутствие имени
/// не теряется: Телеграм, чистый IP, ECH опознаются по IP.
pub struct Sni;

/// Движок над носителем — ждёт выбора транспорта.
pub struct Engine {
    queue: u16,
}

impl Engine {
    /// Поток разговоров этого транспорта (`Tcp` — соединения, `Udp` — датаграммы/DNS).
    pub fn from<T: Transport>(self, _transport: T) -> Watching<T> {
        Watching {
            queue: self.queue,
            transport: PhantomData,
        }
    }
}

/// Транспорт выбран — ждёт ключа разговора.
pub struct Watching<T> {
    queue: u16,
    transport: PhantomData<fn() -> T>,
}

impl<T: Transport> Watching<T> {
    /// Чем ключуется цель.
    pub fn extract(self, _key: Sni) -> Keyed<T> {
        Keyed {
            queue: self.queue,
            transport: PhantomData,
        }
    }
}

/// Ключ выбран — ждёт хотя бы одного детектора.
pub struct Keyed<T> {
    queue: u16,
    transport: PhantomData<fn() -> T>,
}

impl<T: Transport> Keyed<T> {
    /// Установить первый детектор. Прибор обязан читать словарь этого транспорта (`IntoProbe<Wire>`)
    /// — иначе не соберётся.
    pub fn detect(self, detector: impl IntoProbe<T::Wire>) -> Detecting<T> {
        Detecting {
            queue: self.queue,
            longest: detector.window(),
            probes: vec![detector.into_probe()],
            transport: PhantomData,
        }
    }
}

/// Детекторы копятся — можно добавить ещё или перейти к реакции.
pub struct Detecting<T: Transport> {
    queue: u16,
    probes: Vec<Box<dyn Probe<T::Wire>>>,
    longest: Duration,
    transport: PhantomData<fn() -> T>,
}

impl<T: Transport> Detecting<T> {
    /// Ещё прибор поверх — они гоняются ВМЕСТЕ над одним проводом.
    pub fn detect(mut self, detector: impl IntoProbe<T::Wire>) -> Detecting<T> {
        self.longest = self.longest.max(detector.window());
        self.probes.push(detector.into_probe());
        self
    }

    /// НАБЛЮДАТЬ: реакция на срабатывание, без вмешательства. `target` — имя цели, `distress` — что
    /// случилось. Пакет идёт как шёл.
    pub fn on<F: FnMut(&str, Distress)>(self, react: F) -> Running<T, F> {
        Running {
            queue: self.queue,
            probes: self.probes,
            longest: self.longest,
            react,
            transport: PhantomData,
        }
    }

    /// ДЕЙСТВОВАТЬ: реакция возвращает [`Act`], движок его исполняет. `Act::Sever` инжектит RST тому,
    /// кто прислал ПАКЕТ-улику, — так тихий дроп обрывается за ~300мс (по повтору) вместо вечной
    /// крутилки. Действует на сигналы, ПРИШЕДШИЕ С ПАКЕТОМ (повтор, сброс, стук): у тика носителя нет
    /// — рвать нечем, и тишина обрывается следующим повтором, а не тиком.
    pub fn act<F: FnMut(&str, Distress) -> Act>(self, react: F) -> Acting<T, F> {
        Acting {
            queue: self.queue,
            probes: self.probes,
            longest: self.longest,
            react,
            transport: PhantomData,
        }
    }
}

/// Что движок делает с целью после срабатывания. Словарь эффектов; пополняется по мере use-case'ов.
pub enum Act {
    /// Только смотреть — пакет идёт как шёл.
    Observe,
    /// Оборвать: инжектить RST тому, кто прислал улику (клиенту при тихом дропе). Пакет всё равно
    /// пропускается — обрыв делает инъекция, а не дроп.
    Sever,
}

/// Цепочка собрана — готова к запуску.
pub struct Running<T: Transport, F> {
    queue: u16,
    probes: Vec<Box<dyn Probe<T::Wire>>>,
    longest: Duration,
    react: F,
    transport: PhantomData<fn() -> T>,
}

/// Как часто движок будит приборы в тишине. Меньше окна детектора; выбрано, не замерено.
const TICK: Duration = Duration::from_millis(200);

/// Сколько ждать на пустой очереди, прежде чем вернуться к тику. Ожидание ведёт цикл, не бэкенд.
const POLL_MS: i32 = 100;

/// Нижний предел срока эвикта ключа: даже беспороговым приборам нужно пережить типичный разговор.
const MIN_IDLE: Duration = Duration::from_secs(10);

impl<T: Transport, F: FnMut(&str, Distress)> Running<T, F> {
    /// Ведущий цикл. Возвращается только исходом настройки (`Report`) — работает, пока жив процесс.
    ///
    /// Внутри: разбор провода (`parse`) → наблюдение транспорта (`T::observe`) → приборы на ключ
    /// ([`FlowTable`] над [`Probes`]) с фанаутом тиков и эвиктом по простою → реакция на [`Distress`].
    /// Пакет пропускается как есть (`Answer::Pass`): use-case наблюдает.
    pub fn run(mut self) -> Report {
        let mut backend = match NfqueueBackend::open(self.queue) {
            Ok(backend) => backend,
            Err(why) => return Report::not_started(self.queue, why),
        };

        let idle = self.longest.saturating_mul(2).max(MIN_IDLE);
        let templates = self.probes;
        let mut table = FlowTable::<Probes<T::Wire>, FlowKey>::new(idle, move |_flow| {
            Probes(templates.iter().map(|probe| probe.clone_box()).collect())
        });
        let mut state = T::State::default();
        // Имя цели на ключ — для сигналов, рождённых тиком (у тика пакета с именем нет).
        let mut targets: HashMap<FlowKey, String> = HashMap::new();
        let mut last_tick = Instant::now();

        loop {
            let now = Instant::now();

            let outcome = {
                let table = &mut table;
                let state = &mut state;
                let targets = &mut targets;
                let react = &mut self.react;
                backend.serve(|held| {
                    if let Some(observed) = T::observe(state, parse::read(held.seen(), T::PORT)) {
                        let (signals, ()) = table.process(observed.flow, &observed.wire, now);
                        for signal in &signals {
                            react(&observed.target, signal.clone());
                        }
                        targets.insert(observed.flow, observed.target);
                    }
                    // Наблюдаем, не вмешиваемся: пакет идёт как шёл.
                    Answer::Pass
                })
            };

            match outcome {
                Served::Answered(_) => {}
                Served::Idle => {
                    let _ = backend.wait(POLL_MS);
                }
                Served::Blind => std::thread::sleep(Duration::from_millis(1)),
            }

            if now.duration_since(last_tick) >= TICK {
                last_tick = now;
                for (flow, (signals, ())) in table.tick(now) {
                    if let Some(target) = targets.get(&flow) {
                        for signal in &signals {
                            (self.react)(target, signal.clone());
                        }
                    }
                }
                // Имя уходит вместе с ключом: зеркалим эвикт таблицы, чтобы карта не росла.
                targets.retain(|flow, _| table.get(flow).is_some());
            }
        }
    }
}

/// Метка на инъекциях движка: ядро ставит её (SO_MARK) на впрыснутый RST, чтобы он не вернулся в
/// свою же очередь. Правило очереди обязано пропускать помеченное (`meta mark != INJECT_MARK`).
pub const INJECT_MARK: u32 = 0xBB;

/// Цепочка с ДЕЙСТВИЕМ собрана — готова к запуску.
pub struct Acting<T: Transport, F> {
    queue: u16,
    probes: Vec<Box<dyn Probe<T::Wire>>>,
    longest: Duration,
    react: F,
    transport: PhantomData<fn() -> T>,
}

impl<T: Transport, F: FnMut(&str, Distress) -> Act> Acting<T, F> {
    /// Ведущий цикл с эффектом. Как [`Running::run`], но реакция возвращает [`Act`]: на `Sever`
    /// движок строит RST отправителю улики (`CanSever::notice`) и шлёт своим сокетом (`RawSender`).
    /// Обрыв делает ИНЪЕКЦИЯ, пакет всё равно пропускается. Рвать можно лишь сигнал, пришедший с
    /// пакетом (у тика носителя нет) — потому тик здесь только копит имена и убирает ключи.
    pub fn run(mut self) -> Report {
        let mut backend = match NfqueueBackend::open(self.queue) {
            Ok(backend) => backend,
            Err(why) => return Report::not_started(self.queue, why),
        };
        // Свой сокет инъекции: RST уходит мимо очереди, помеченный, чтобы не вернуться в неё.
        let sender = match RawSender::open(INJECT_MARK) {
            Ok(sender) => sender,
            Err(why) => return Report::not_started(self.queue, format!("сокет инъекции: {why}")),
        };

        let idle = self.longest.saturating_mul(2).max(MIN_IDLE);
        let templates = self.probes;
        let mut table = FlowTable::<Probes<T::Wire>, FlowKey>::new(idle, move |_flow| {
            Probes(templates.iter().map(|probe| probe.clone_box()).collect())
        });
        let mut state = T::State::default();
        let mut last_tick = Instant::now();

        loop {
            let now = Instant::now();

            let outcome = {
                let table = &mut table;
                let state = &mut state;
                let react = &mut self.react;
                let sender = &sender;
                backend.serve(|held| {
                    if let Some(observed) = T::observe(state, parse::read(held.seen(), T::PORT)) {
                        let (signals, ()) = table.process(observed.flow, &observed.wire, now);
                        for signal in &signals {
                            match react(&observed.target, signal.clone()) {
                                Act::Observe => {}
                                // Обрыв — тому, кто прислал улику (клиенту при тихом дропе). Байты
                                // улики уже в руках (`held`), из них движок и строит RST.
                                Act::Sever => {
                                    if let Some(rst) =
                                        NfqueueBackend::notice(held.seen(), Toward::Sender)
                                    {
                                        if let Err(why) = sender.send(&rst.serialize_ip()) {
                                            eprintln!("[reflex] RST не ушёл: {why}");
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // Пакет идёт как шёл: обрыв делает инъекция, не дроп.
                    Answer::Pass
                })
            };

            match outcome {
                Served::Answered(_) => {}
                Served::Idle => {
                    let _ = backend.wait(POLL_MS);
                }
                Served::Blind => std::thread::sleep(Duration::from_millis(1)),
            }

            if now.duration_since(last_tick) >= TICK {
                last_tick = now;
                // Тик двигает эвикт (беспороговым приборам он не нужен, но ключи чистит).
                let _ = table.tick(now);
            }
        }
    }
}

/// Исход настройки движка. Работающий цикл его не возвращает — только несостоявшийся запуск.
pub struct Report {
    queue: u16,
    why: Option<String>,
}

impl Report {
    fn not_started(queue: u16, why: String) -> Report {
        Report {
            queue,
            why: Some(why),
        }
    }
}

impl std::process::Termination for Report {
    fn report(self) -> std::process::ExitCode {
        match self.why {
            None => std::process::ExitCode::SUCCESS,
            Some(why) => {
                eprintln!("[reflex] очередь {} не открылась: {why}", self.queue);
                std::process::ExitCode::FAILURE
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `extract(Sni)` не теряет безымянную цель: нет имени — по адресу. Телеграм, чистый IP, ECH.
    #[test]
    fn target_falls_back_to_address_when_there_is_no_name() {
        let awaited = Ident {
            dst: Addr(0x0A00_0001),
            naming: Naming::Awaited,
        };
        assert_eq!(awaited.target(), "10.0.0.1");

        let silent = Ident {
            dst: Addr(0x0A00_0001),
            naming: Naming::Silent,
        };
        assert_eq!(silent.target(), "10.0.0.1");

        let named = Ident {
            dst: Addr(0x0A00_0001),
            naming: Naming::Spoken("rutracker.org".into()),
        };
        assert_eq!(named.target(), "rutracker.org");
    }
}
