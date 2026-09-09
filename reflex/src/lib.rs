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
//! Ни `Plane`, ни `Interleave`, ни `parse` наружу не торчат. Три оси полиморфизма закрыты в
//! движке (`DetectorEvent` и словари провода открыты как субстрат «своего детектора» — см. `.detect`):
//!
//! * `.from(T)` — ТРАНСПОРТ: `Tcp` даёт словарь соединения, `Udp` — датаграммы (DNS). Каждый
//!   несёт свой широкий словарь провода и свой порт.
//! * `.detect(D)` — ПРИБОР: любой, читающий свой алфавит из широкого через `Reads` (канон §4).
//!   Приборы разных алфавитов встают в одну дверь; несовместимый транспорту прибор не соберётся.
//!   Свой автомат — через [`own`]: чужая машина Мили, говорящая словами беды, встаёт той же дверью.
//! * терминал — НАБЛЮДАТЬ (`.on`) или ДЕЙСТВОВАТЬ (`.act`, реакция возвращает [`Act`]:
//!   `Act::sever()` инжектит RST — тихий дроп обрывается за ~300мс вместо вечной крутилки).
//!   Акт гейтится СПОСОБНОСТЬЮ носителя в точке создания (§9.1): чего носитель не умеет, того
//!   потребитель не построит.
//!
//! Поперёк этих осей стоит ОБЛАСТЬ, о которой сказано. `.on` слышит слова РАЗГОВОРОВ; чтобы
//! услышать слово о ЦЕЛИ, ставится пара `.about(свёртка).on_target(реакция)` — копредел по слою
//! (§4: `Target ≅ ∐ Conversation`). Пара держится типом: свернул — обязан сказать.
//!
//! Склейку сигналов в вывод пишет потребитель — фреймворк описывает МИР, лечение живёт у него.
//!
//! [`run`]: Running::run

use std::collections::HashMap;
use std::marker::PhantomData;
use std::time::{Duration, Instant};

use reflex_core::capability::{CanAsk, CanHold};
use reflex_core::certify::replays::{replays, Replayed};
use reflex_core::colimit::Layer;
use reflex_core::command::InjectablePacket;
use reflex_core::dns::DnsMessage;
use reflex_core::effect::Effect;
use reflex_core::flow_table::FlowTable;
pub use reflex_core::mealy::Mealy;
use reflex_core::serves::Served;
use reflex_core::tape::{Mode, Tape, TapeLetter, To};
use reflex_core::tls;
use reflex_core::word::{Conversation, Target};
pub use reflex_core::DetectorEvent;
use reflex_core::Reads;
use reflex_core::{CanSever, Serves, Toward};
use reflex_engine::row::{host_of, keyed, Naming, TargetKey};
use reflex_engine::{Addr, Flow};
use reflex_engine_nfq::parse::{self, Read};
use reflex_engine_nfq::talk::Talks;
use reflex_instrument::detect::{SilenceInstrument, SynDropInstrument};
use reflex_instrument::poison::DnsPoisonInstrument;
use reflex_instrument::retransmit::RetransmitInstrument;
pub use reflex_instrument::wire::{Reading, Seen, SeenTcp};
use reflex_linux::nfqueue::{Answer, NfqueueBackend};
use reflex_linux::rawsend::RawSender;
pub use smallvec::{smallvec, SmallVec};

/// Алфавит беды, на который реагирует потребитель. Реэкспорт: это МИР, а не кишки фреймворка.
pub use reflex_instrument::distress::{Distress, Voiced};

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
    flow: Flow,
    /// Ключ цели — расслоение §4 (`Named | Unnamed`). Им цель ключуется в слое; ярлык для человека
    /// получается из него [`label`], а не наоборот: обратный ход терял бы тег.
    key: TargetKey<Box<str>>,
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
    /// Ключ цели — расслоение §4: имя, если цепочка его дала, иначе адрес. Отдаём КЛЮЧ, а не строку:
    /// строка теряет тег, и безымянная цель метилась бы `Named` — тег стал бы ложным, а крафт-SNI,
    /// равный записи адреса, схлопнулся бы с настоящей безымянной целью того же адреса. Источник
    /// имени под контролем противника, значит коллизия достижима, а не редка.
    fn key(&self) -> TargetKey<Box<str>> {
        keyed(self.naming.clone(), self.dst, host_of)
    }
}

/// Как назвать цель человеку. Ярлык для реакции — не ключ: у него нет тега, и различать им цели
/// нельзя. Безымянная цель (Телеграм, чистый IP) показывается адресом, а не теряется.
fn label(key: &TargetKey<Box<str>>) -> String {
    match key {
        TargetKey::Named(name) => name.to_string(),
        TargetKey::Unnamed(addr) => addr.to_string(),
    }
}

/// Память TCP-разбора: разговоры (граница/повтор) и личность целей.
#[derive(Default)]
pub struct TcpState {
    talks: Talks,
    idents: HashMap<Flow, Ident>,
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
        let key = ident.key();
        state.talks.read(&wire).map(|tcp| Observed {
            flow: wire.flow,
            key,
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
        // Цель — имя из вопроса (оно же и отравляют); вопроса нет — цель безымянна, и ключуется
        // адресом резолвера. Тег сохраняется: `Unnamed` не притворяется именем.
        let key = message
            .queries
            .first()
            .map(|query| TargetKey::Named(query.name.clone().into_boxed_str()))
            .unwrap_or(TargetKey::Unnamed(datagram.dst));
        Some(Observed {
            flow: datagram.flow,
            key,
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

/// СВОЙ прибор: чужая машина Мили в ту же дверь `.detect`, что и парк. Потребитель приносит
/// СОБСТВЕННЫЙ автомат — вижн «описать все сценарии через пайпы» невозможен с фиксированным меню.
///
/// Алфавит `N` (что машина читает — `Seen`/`SeenTcp`/`Reading`/…) выводится из `M::In` конструктором
/// [`own`]; он обязан читаться из словаря транспорта (`N: Reads<Wire>`), иначе `.detect` не примет.
/// Машина обязана быть `Copy` — движок сеет свежую копию шаблона на каждый ключ ([`FlowTable`]).
pub struct Own<M, N> {
    machine: M,
    alphabet: PhantomData<fn() -> N>,
}

/// Обернуть свою машину в прибор для `.detect(own(machine))`. `N` выведется из `M::In`.
pub fn own<N, M>(machine: M) -> Own<M, N>
where
    M: Mealy<In = DetectorEvent<N>, Out = SmallVec<[Distress; 2]>> + Copy + Send + 'static,
{
    Own {
        machine,
        alphabet: PhantomData,
    }
}

impl<W, N, M> IntoProbe<W> for Own<M, N>
where
    W: 'static,
    N: Reads<W> + 'static,
    M: Mealy<In = DetectorEvent<N>, Out = SmallVec<[Distress; 2]>> + Copy + Send + 'static,
{
    fn into_probe(self) -> Box<dyn Probe<W>> {
        lift::<W, N, M>(self.machine)
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
            about: None,
            transport: PhantomData,
        }
    }
}

/// Свёртка слов о разговорах в слово о ЦЕЛИ — приходит от потребителя ЗНАЧЕНИЕМ, как приходит свой
/// автомат в `own(…)`. Какое слово рождается («молчат все», «молчит доля», «молчит хоть один») —
/// описание угрозы, а не механики: фреймворк называет копредел, не угрозу.
///
/// Свёртка видит МНОЖЕСТВО последних слов: порядок ей не показан, кратность сняло хранилище.
pub type Fold = Box<dyn Fn(&[&Distress]) -> Option<Distress> + Send>;

/// Реакция на слово о ЦЕЛИ. Отдельна от реакции на слово о разговоре: области разные, и §5 держит
/// их раздельно типом.
pub type TargetVoice = Box<dyn FnMut(&str, Voiced) + Send>;

/// Детекторы копятся — можно добавить ещё или перейти к реакции.
pub struct Detecting<T: Transport> {
    queue: u16,
    probes: Vec<Box<dyn Probe<T::Wire>>>,
    longest: Duration,
    about: Option<(Fold, TargetVoice)>,
    transport: PhantomData<fn() -> T>,
}

impl<T: Transport> Detecting<T> {
    /// Ещё прибор поверх — они гоняются ВМЕСТЕ над одним проводом.
    pub fn detect(mut self, detector: impl IntoProbe<T::Wire>) -> Detecting<T> {
        self.longest = self.longest.max(detector.window());
        self.probes.push(detector.into_probe());
        self
    }

    /// Слово о ЦЕЛИ поверх слов о её разговорах — копредел по слою (§4: `Target ≅ ∐ Conversation`).
    /// Свёртка приходит значением: фреймворк собирает последние слова разговоров цели и отдаёт их
    /// ей, не зная, что она из них сделает.
    ///
    /// Без этого оператора движок говорит только о разговорах: двадцать потоков к молчащей цели
    /// дают двадцать слов, а не одно.
    ///
    /// Реакцию на слово о цели требует ТИП: `about` отдаёт [`Folding`], у которого нет `.on` —
    /// цепочка не соберётся, пока не сказано `.on_target`. Иначе потребитель построил бы копредел и
    /// молча уронил его выход: свёл и выбросил.
    pub fn about(
        self,
        fold: impl Fn(&[&Distress]) -> Option<Distress> + Send + 'static,
    ) -> Folding<T> {
        Folding {
            detecting: self,
            fold: Box::new(fold),
        }
    }

    /// НАБЛЮДАТЬ: реакция на срабатывание, без вмешательства. `target` — имя цели, `distress` — что
    /// случилось. Пакет идёт как шёл.
    pub fn on<F: FnMut(&str, Distress)>(self, react: F) -> Running<T, F> {
        Running {
            queue: self.queue,
            probes: self.probes,
            longest: self.longest,
            about: self.about,
            react,
            certify: false,
            transport: PhantomData,
        }
    }

    /// ДЕЙСТВОВАТЬ: реакция возвращает [`Act`], движок его исполняет. `Act::Sever` инжектит RST тому,
    /// кто прислал ПАКЕТ-улику, — так тихий дроп обрывается за ~300мс (по повтору) вместо вечной
    /// крутилки. Действует на сигналы, ПРИШЕДШИЕ С ПАКЕТОМ (повтор, сброс, стук): у тика носителя нет
    /// — рвать нечем, и тишина обрывается следующим повтором, а не тиком.
    pub fn act<F: FnMut(&str, Distress) -> Act<NfqueueBackend>>(self, react: F) -> Acting<T, F> {
        Acting {
            queue: self.queue,
            probes: self.probes,
            longest: self.longest,
            react,
            transport: PhantomData,
        }
    }
}

/// ОДИН ФУНКТОР: доменный акт → слово носителя и команды миру (§9.4, §12.4).
///
/// Прежде перевод жил тремя разборами в разных местах, а обрыв исполнялся императивно прямо в
/// петле — фасад знал про сокет инъекции. Здесь перевод один и ЧИСТЫЙ: функтор отдаёт команду, а
/// не шлёт её. Исполняет петля, и в переигровке не исполняет — тем лента и остаётся
/// переигрываемой (§10). Сделай функтор эффектным — режим пришлось бы протаскивать внутрь него.
///
/// Допустимость акта проверяет ТИП, и проверяет её [`Act`] при СОЗДАНИИ: сюда акт приходит уже
/// законным, а с ним — строитель команды, взятый у способности. Оттого здесь и нет разбора по
/// вариантам: спрашивать «умеет ли носитель» в точке исполнения было бы вторым местом для того же
/// решения, и второе место разошлось бы с первым.
///
/// Над носителем без нужной способности акт не построить — это не проверка в рантайме, а отсутствие
/// импликации:
///
/// ```compile_fail,E0599
/// use reflex::Act;
/// use reflex_linux::queue::QueueSocket;
/// // Очередь ядра — терминал, она держит, рвёт и помнит, но СПРОСИТЬ не умеет: дверь у неё одна,
/// // вердикт удержанному пакету, и наружу к постороннему собеседнику она не говорит. `CanAsk` не
/// // заявлен, и конструктора `ask` у её акта просто нет.
/// let _ = Act::<QueueSocket>::ask(1);
/// ```
pub fn emit<T>(act: Act<T>, seen: &[u8]) -> (T::Answer, SmallVec<[Effect; 2]>)
where
    T: CanHold,
{
    // Пакет отпускается ВСЕГДА, каким бы ни был акт: даже обрыв рвёт инъекцией, а не дропом.
    // Команды нет (`None`) — акт всё равно исполнен: «сказать оказалось нечем» есть исход, а не
    // ошибка (§7).
    (
        T::release(),
        act.build
            .and_then(|make| make(act.token, seen))
            .into_iter()
            .map(Effect::Inject)
            .collect(),
    )
}

/// Свести слой в слова о ЦЕЛЯХ. Отдельная функция, а не тело петли: копредел живёт на обоих
/// терминалах (`.on` и `.act`), а один предмет описывается одним законом.
///
/// Затихшие разговоры снимаются ПРЕЖДЕ сведения — иначе цель говорила бы голосом разговоров,
/// которых уже нет. Возраст берётся у слоя ([`Layer::freshest`]), а не у свёртки: свёртка видит
/// слова и не видит часов.
fn voiced(
    layer: &mut Layer<Conversation, Target, Distress>,
    fold: &Fold,
    idle: Duration,
    now: Instant,
) -> Vec<(String, Voiced)> {
    layer.forget_idle(idle, now);
    layer
        .targets()
        .filter_map(|key| {
            let distress = layer.join(key, |words| fold(words))?;
            // Слово есть — значит есть и слова разговоров, значит есть и момент: `freshest` тут
            // непуст по построению, но догадка не улика, и пустой возраст роняет слово, а не врёт.
            let since = now.saturating_duration_since(layer.freshest(key)?);
            Some((label(key), Voiced { distress, since }))
        })
        .collect()
}

/// Копредел объявлен, реакция на его слово — ещё нет. Тип-состояние: `.on` здесь не живёт, и
/// цепочка не соберётся, пока не сказано [`Folding::on_target`].
///
/// Так пара «свести → сказать о цели» держится ТИПОМ. Без неё потребитель построил бы слой,
/// свёртку и копредел — и выбросил бы результат, не заметив: свёл и уронил.
pub struct Folding<T: Transport> {
    detecting: Detecting<T>,
    fold: Fold,
}

impl<T: Transport> Folding<T> {
    /// Что делать со словом о ЦЕЛИ. Дверь отдельная от [`Detecting::on`], потому что область другая:
    /// беда разговора и беда цели — слова разных слоёв, и §5 не складывает их законом пары. Спустить
    /// слово о цели к разговору тоже нельзя — это отменило бы только что сделанную агрегацию.
    pub fn on_target<G: FnMut(&str, Voiced) + Send + 'static>(self, react: G) -> Speaking<T> {
        Speaking {
            detecting: Detecting {
                about: Some((self.fold, Box::new(react) as TargetVoice)),
                ..self.detecting
            },
        }
    }
}

/// Пара «свести → сказать о цели» замкнута: цепочка снова копит приборы и ждёт терминала.
///
/// Терминал здесь только НАБЛЮДАТЬ. `.act` у копредела нет, и это не забывчивость: слово о цели
/// рождается тиком, а тик носителя не имеет — рвать по нему нечем (см. [`Acting::run`]). Пусти
/// копредел в `.act` — свёртка «молчат все» не сказала бы ни слова, потому что слова тишины до слоя
/// в том цикле не доходят. Отказ компилятора честнее молчащей цепочки.
pub struct Speaking<T: Transport> {
    detecting: Detecting<T>,
}

impl<T: Transport> Speaking<T> {
    /// Ещё прибор поверх — как в [`Detecting::detect`]: копредел не закрывает набор приборов.
    pub fn detect(self, detector: impl IntoProbe<T::Wire>) -> Speaking<T> {
        Speaking {
            detecting: self.detecting.detect(detector),
        }
    }

    /// НАБЛЮДАТЬ слова о РАЗГОВОРАХ — вторая дверь пары. Слова о цели уже адресованы `.on_target`.
    pub fn on<F: FnMut(&str, Distress)>(self, react: F) -> Running<T, F> {
        self.detecting.on(react)
    }
}

/// Что движок делает с целью после срабатывания. Словарь эффектов; пополняется по мере use-case'ов.
///
/// ГЕЙТ ПО АКТУ, а не по цепочке (§9.1). Способность требуется в точке, где акт СОЗДАЁТСЯ, и ровно
/// та, которой этот акт пользуется: наблюдение — ничего сверх удержания, обрыв — `CanSever`, вопрос
/// — `CanAsk`. Прежде все три требовались разом, и следствий было два, оба плохих: носитель, умеющий
/// только смотреть, не собирался даже под `Observe`, а носитель с формальным «спрашивать нечем»
/// пропускал `Ask` — цепочка собиралась и молча уходила ждать ответа, которого никто не пошлёт.
///
/// Рантайм-выбор при этом цел: реакция решает, что вернуть, — гейт стоит на конструкторе, а не на
/// ветке. Строитель команды берётся У СПОСОБНОСТИ здесь же и едет внутри акта указателем: к моменту
/// исполнения спрашивать «а умеет ли носитель» уже не у кого и незачем.
pub struct Act<T: CanHold> {
    /// Чем акт трогает мир. `None` — ничем (наблюдение): у отпускания команды нет.
    build: Option<fn(u64, &[u8]) -> Option<InjectablePacket>>,
    /// Корреляционный токен вопроса; прочим актам не нужен и равен нулю.
    token: u64,
    carrier: PhantomData<fn() -> T>,
}

/// Обрыв как строитель команды: способность знает, чем сказать стороне, что разговора не будет.
/// Свободная функция, а не замыкание, — чтобы акт нёс УКАЗАТЕЛЬ, без аллокации в горячем пути.
fn severing<T: CanSever>(_token: u64, seen: &[u8]) -> Option<InjectablePacket> {
    T::notice(seen, Toward::Sender)
}

/// Вопрос как строитель команды: токен едет внутрь, ибо ответ придёт позже и сам по себе не скажет,
/// чей он (§4).
fn asking<T: CanAsk>(token: u64, seen: &[u8]) -> Option<InjectablePacket> {
    T::question(token, seen)
}

impl<T: CanHold> Act<T> {
    /// Только смотреть — пакет идёт как шёл. Сверх удержания способностей не просит.
    pub fn observe() -> Act<T> {
        Act {
            build: None,
            token: 0,
            carrier: PhantomData,
        }
    }
}

impl<T: CanHold + CanSever> Act<T> {
    /// Оборвать: инжектить RST тому, кто прислал улику (клиенту при тихом дропе). Пакет всё равно
    /// пропускается — обрыв делает инъекция, а не дроп.
    pub fn sever() -> Act<T> {
        Act {
            build: Some(severing::<T>),
            token: 0,
            carrier: PhantomData,
        }
    }
}

impl<T: CanHold + CanAsk> Act<T> {
    /// Спросить контур — обратный ход. Ответ придёт БУКВОЙ ленты, не возвратом вызова: шаг Мили не
    /// ждёт (§1), ожидание живёт фазой машины. `token` — ключ, по которому ответ найдёт свою
    /// машину: сам по себе ответ не говорит, чей он.
    pub fn ask(token: u64) -> Act<T> {
        Act {
            build: Some(asking::<T>),
            token,
            carrier: PhantomData,
        }
    }
}

/// Цепочка собрана — готова к запуску.
pub struct Running<T: Transport, F> {
    queue: u16,
    probes: Vec<Box<dyn Probe<T::Wire>>>,
    longest: Duration,
    about: Option<(Fold, TargetVoice)>,
    react: F,
    /// Предъявлять ли восьмой закон на живой ленте — [`Running::certifying`].
    certify: bool,
    transport: PhantomData<fn() -> T>,
}

/// Чьё наблюдение — так сказал РАЗБОР, когда буква рождалась. Два ключа, потому что областей две
/// (§4): `flow` адресует машину разговора, `target` — слой цели. В живом прогоне их вычисляет
/// `T::observe`; на переигровке разбора нет, и оба обязаны лежать в ленте — иначе слово о цели
/// восстановить не из чего, и копредел остался бы непроверенным.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Whose {
    pub flow: Flow,
    pub target: TargetKey<Box<str>>,
}

/// Что машина СКАЗАЛА за прогон — предмет сверки восьмого закона (§10). Обе области: слово о
/// разговоре пришло бы в `.on`, слово о цели — в `.on_target`. Без второго переигровка не
/// свидетельствовала бы о копределе, а он и есть свежая постройка.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Said {
    /// Беда разговора, названная именем цели (так её видит `.on`).
    OfConversation(String, Distress),
    /// Слово о цели — итог свёртки (так его видит `.on_target`).
    OfTarget(String, Voiced),
}

/// Лента этого движка: буквы провода с адресом разбора. Отклик пока не рождается — акт вопроса в
/// потребительскую цепочку не вписан (по-актовый гейт способностей ещё не построен), потому
/// содержимое отклика здесь пусто.
type Recorded<T> = Tape<<T as Transport>::Wire, Whose, ()>;

/// Сколько букв копит окно ленты, прежде чем закон предъявляется. Окно, а не весь прогон: движок
/// живёт, пока жив процесс, и бесконечная лента была бы утечкой.
///
/// Величина СЧИТАНА, не угадана: узел сетки пишется каждые [`TICK`] (200мс), то есть пять букв в
/// секунду даже на молчащем проводе — окно закрывается примерно раз в двенадцать секунд, а с
/// трафиком быстрее. Возьми пятьсот — и короткий прогон закончился бы, не предъявив закона ни разу,
/// то есть свидетель молчал бы, выглядя исправным.
const TAPE_WINDOW: usize = 64;

/// Пере-подать записанное окно СВЕЖЕЙ семье машин и собрать сказанное.
///
/// Зеркало живой петли, и в этом весь смысл: те же вызовы (`process` на пакет, `tick` на узел
/// сетки, свёртка на нём же), но вход берётся из ЛЕНТЫ, а не из очереди и часов. Что расходится —
/// то и есть скрытый вход машины (§10).
///
/// Реакции потребителя здесь не зовутся вовсе: они печатают, то есть трогают мир, а переигровка
/// его не трогает (§9.4). Наружу идут ИСХОДЫ — их и сверяет закон.
fn replay<T: Transport>(
    seeds: &[Box<dyn Probe<T::Wire>>],
    fold: Option<&Fold>,
    idle: Duration,
    mode: Mode,
    letters: &[TapeLetter<T::Wire, Whose, ()>],
) -> Vec<Said> {
    // Живой режим сюда не приходит: пере-подача — всегда переигровка. Придёт — упадём в отладке,
    // а не соврём тихо вердиктом, добытым касанием мира.
    debug_assert_eq!(mode, Mode::Replay, "переигровка идёт только в Replay");

    let templates: Vec<Box<dyn Probe<T::Wire>>> =
        seeds.iter().map(|probe| probe.clone_box()).collect();
    let mut table = FlowTable::<Probes<T::Wire>, Flow>::new(idle, move |_flow| {
        Probes(templates.iter().map(|probe| probe.clone_box()).collect())
    });
    let mut targets: HashMap<Flow, TargetKey<Box<str>>> = HashMap::new();
    let mut layer: Layer<Conversation, Target, Distress> = Layer::new();
    let mut said: Vec<Said> = Vec::new();

    for letter in letters {
        let Some((to, event)) = letter.seen() else {
            // Отклик: до прибора он не доходит §4-сужением, а вопросов эта цепочка не задаёт.
            continue;
        };
        match (to, event) {
            (To::One(whose), DetectorEvent::Packet { input, at }) => {
                let (signals, ()) = table.process(whose.flow, input, *at);
                for signal in &signals {
                    said.push(Said::OfConversation(label(&whose.target), signal.clone()));
                    layer.saw(whose.target.clone(), whose.flow, signal.clone(), *at);
                }
                targets.insert(whose.flow, whose.target.clone());
            }
            (To::Each, DetectorEvent::Tick { at, .. }) => {
                for (flow, (signals, ())) in table.tick(*at) {
                    if let Some(key) = targets.get(&flow) {
                        for signal in &signals {
                            said.push(Said::OfConversation(label(key), signal.clone()));
                            layer.saw(key.clone(), flow, signal.clone(), *at);
                        }
                    }
                }
                if let Some(fold) = fold {
                    for (target, voice) in voiced(&mut layer, fold, idle, *at) {
                        said.push(Said::OfTarget(target, voice));
                    }
                }
            }
            // Непонятое до машин не доходит (у него нет ключа), а прочие сочетания адреса и буквы
            // лента не рождает: их пишет один и тот же код, что читает.
            _ => {}
        }
    }
    said
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
        // Семя семьи: те же шаблоны, из которых движок сеет машины, нужны и переигровке — она
        // обязана начать с ТОГО ЖЕ состояния, иначе сверяла бы две разные машины.
        let seeds: Vec<Box<dyn Probe<T::Wire>>> =
            self.probes.iter().map(|probe| probe.clone_box()).collect();
        let templates = self.probes;
        let mut table = FlowTable::<Probes<T::Wire>, Flow>::new(idle, move |_flow| {
            Probes(templates.iter().map(|probe| probe.clone_box()).collect())
        });
        let mut state = T::State::default();
        // Окно ленты: пишется всегда, когда закон предъявляется, и не пишется иначе — лента даром
        // стоила бы клона слова провода на каждый пакет.
        let mut tape: Recorded<T> = Tape::new();
        // Ключ цели на разговор — для сигналов, рождённых тиком (у тика пакета с личностью нет).
        // Именно КЛЮЧ, а не ярлык: тег `Named`/`Unnamed` нужен слою, а ярлык из ключа выводится.
        let mut targets: HashMap<Flow, TargetKey<Box<str>>> = HashMap::new();
        // Слова разговоров, разложенные по цели: из них рождается слово О ЦЕЛИ, когда потребитель
        // принёс свёртку (`.about(…)`). Ключ цели здесь — её имя, каким его назвал `extract`: фасад
        // уже свёл `Named`/`Unnamed` в одну строку (имя либо адрес), и различение живёт выше, в
        // `TargetKey`, а не тут.
        let mut layer: Layer<Conversation, Target, Distress> = Layer::new();
        let mut last_tick = Instant::now();

        loop {
            let now = Instant::now();

            let outcome = {
                let table = &mut table;
                let state = &mut state;
                let targets = &mut targets;
                let react = &mut self.react;
                let tape = &mut tape;
                let certify = self.certify;
                backend.serve(|held| {
                    if let Some(observed) = T::observe(state, parse::read(held.seen(), T::PORT)) {
                        // Буква пишется ЗДЕСЬ, где рождается, и с адресом, который знает только
                        // разбор: позже его взять неоткуда — словарь провода потока не несёт.
                        if certify {
                            tape.record([TapeLetter::Event {
                                to: To::One(Whose {
                                    flow: observed.flow,
                                    target: observed.key.clone(),
                                }),
                                event: DetectorEvent::Packet {
                                    input: observed.wire.clone(),
                                    at: now,
                                },
                            }]);
                        }
                        let (signals, ()) = table.process(observed.flow, &observed.wire, now);
                        let named = label(&observed.key);
                        for signal in &signals {
                            react(&named, signal.clone());
                            layer.saw(observed.key.clone(), observed.flow, signal.clone(), now);
                        }
                        targets.insert(observed.flow, observed.key);
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
                // Узел сетки — буква КАЖДОЙ живой машины; в ленту он ложится раз, а фанаут делает
                // тот, кто её читает: перегенерируй тик на переигровке — и она позвала бы часы,
                // то есть впустила бы в машину скрытый вход, который сама же и проверяет (§8).
                if self.certify {
                    tape.record([TapeLetter::Event {
                        to: To::Each,
                        event: DetectorEvent::Tick { node: 0, at: now },
                    }]);
                }
                for (flow, (signals, ())) in table.tick(now) {
                    if let Some(key) = targets.get(&flow) {
                        let named = label(key);
                        for signal in &signals {
                            (self.react)(&named, signal.clone());
                            layer.saw(key.clone(), flow, signal.clone(), now);
                        }
                    }
                }
                // Слово О ЦЕЛИ рождается здесь: слова её разговоров сводятся свёрткой потребителя.
                // Затихшие разговоры уходят прежде сведения — иначе цель говорила бы голосом
                // разговоров, которых уже нет.
                if let Some((fold, voice)) = &mut self.about {
                    for (target, said) in voiced(&mut layer, fold, idle, now) {
                        voice(&target, said);
                    }
                }
                // Имя уходит вместе с ключом: зеркалим эвикт таблицы, чтобы карта не росла.
                targets.retain(|flow, _| table.get(flow).is_some());

                // ВОСЬМОЙ ЗАКОН на живой ленте (§10, §12.3): окно набралось — пере-подаём его
                // свежей семье дважды и сверяем сказанное. Свидетель тут же и предъявляется: молча
                // держать закон значит не держать его вовсе.
                if self.certify && tape.len() >= TAPE_WINDOW {
                    let fold = self.about.as_ref().map(|(fold, _voice)| fold);
                    let verdict = replays(&tape, |mode, letters| {
                        replay::<T>(&seeds, fold, idle, mode, letters)
                    });
                    match verdict {
                        Replayed::Reproduced => {
                            report!("§10: окно из {} букв воспроизведено", tape.len())
                        }
                        Replayed::Unstable { at } => report!(
                            "§10 НАРУШЕН: прогоны разошлись на исходе {at} — у машины есть вход \
                             вне её алфавита"
                        ),
                        Replayed::NoTape => report!("§10: судить не о чем — лента пуста"),
                        // Окно из одних узлов сетки без живых машин: согласие двух молчаний
                        // свидетельством не считается — под ним прошла бы любая порча.
                        Replayed::Silent => report!(
                            "§10: окно из {} букв прошло молча — машине нечего было сказать, \
                             свидетельства нет",
                            tape.len()
                        ),
                    }
                    // Окно закрыто: следующее пишется с чистого места, иначе лента росла бы вечно.
                    tape = Tape::new();
                }
            }
        }
    }

    /// Предъявлять восьмой закон (§10) на СВОЕЙ ленте: движок пишет окно наблюдений и, набрав его,
    /// пере-подаёт свежей семье машин дважды — сверяя не ленту, а сказанное.
    ///
    /// Дверь отдельная и по умолчанию закрытая: запись стоит клона слова провода на каждый пакет, и
    /// платить её тем, кто закона не просит, незачем. Кто просит — получает свидетельство на СВОЁМ
    /// трафике, а не на выдуманном стенде: это и отличает предъявимость от обещания.
    pub fn certifying(mut self) -> Running<T, F> {
        self.certify = true;
        self
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

impl<T: Transport, F: FnMut(&str, Distress) -> Act<NfqueueBackend>> Acting<T, F> {
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
        let mut table = FlowTable::<Probes<T::Wire>, Flow>::new(idle, move |_flow| {
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
                        let named = label(&observed.key);
                        for signal in &signals {
                            // Один функтор: акт даёт слово носителю и список команд миру. Петля
                            // команды ИСПОЛНЯЕТ — в живом прогоне; переигровка их глушит, и потому
                            // перевод акта остаётся чистым (§9.4, §10).
                            let (_word, effects) =
                                emit::<NfqueueBackend>(react(&named, signal.clone()), held.seen());
                            for effect in &effects {
                                let Effect::Inject(packet) = effect;
                                if let Err(why) = sender.send(&packet.clone().serialize_ip()) {
                                    eprintln!("[reflex] инъекция не ушла: {why}");
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
        assert_eq!(label(&awaited.key()), "10.0.0.1");

        let silent = Ident {
            dst: Addr(0x0A00_0001),
            naming: Naming::Silent,
        };
        assert_eq!(label(&silent.key()), "10.0.0.1");

        let named = Ident {
            dst: Addr(0x0A00_0001),
            naming: Naming::Spoken("rutracker.org".into()),
        };
        assert_eq!(label(&named.key()), "rutracker.org");
    }

    /// Безымянная цель ключуется `Unnamed`, а не `Named` с адресом-строкой. Тег — не украшение:
    /// строка теряет его, и тогда крафт-SNI, равный записи адреса, схлопнулся бы с настоящей
    /// безымянной целью того же адреса. Имя приходит от противника — коллизия достижима, не редка.
    #[test]
    fn безымянная_цель_ключуется_адресом_а_не_именем_похожим_на_адрес() {
        let nameless = Ident {
            dst: Addr(0x0A00_0001),
            naming: Naming::Silent,
        };
        let crafted = Ident {
            dst: Addr(0x0A00_0001),
            naming: Naming::Spoken("10.0.0.1".into()),
        };

        assert_eq!(nameless.key(), TargetKey::Unnamed(Addr(0x0A00_0001)));
        assert_ne!(
            nameless.key(),
            crafted.key(),
            "цель без имени и цель с именем «10.0.0.1» — разные цели"
        );
        assert_eq!(
            label(&nameless.key()),
            label(&crafted.key()),
            "человеку они выглядят одинаково — тем важнее, что ключ их различает"
        );
    }

    fn flow(n: u32) -> Flow {
        Flow {
            src: std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(0x0A00_0000 | n)),
                40000 + n as u16,
            ),
            dst: std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(0x5DB8_D822)),
                443,
            ),
            protocol: reflex_core::types::Protocol::Tcp,
        }
    }

    fn всегда(_words: &[&Distress]) -> Option<Distress> {
        Some(Distress::NoBytes)
    }

    /// Слово о цели несёт возраст САМОГО СВЕЖЕГО наблюдения, а не старейшего: цель, только что
    /// заговорившая одним из двух потоков, не должна выглядеть молчащей полминуты. Без возраста
    /// потребителю нечем отличить новость от того же молчания, о котором уже сказано.
    #[test]
    fn слово_о_цели_несёт_возраст_свежайшего_наблюдения() {
        let t0 = Instant::now();
        let key = TargetKey::Named("rutracker.org".into());
        let mut layer: Layer<Conversation, Target, Distress> = Layer::new();
        layer.saw(key.clone(), flow(1), Distress::NoBytes, t0);
        layer.saw(
            key,
            flow(2),
            Distress::NoBytes,
            t0 + Duration::from_secs(20),
        );

        let fold: Fold = Box::new(всегда);
        let said = voiced(
            &mut layer,
            &fold,
            Duration::from_secs(60),
            t0 + Duration::from_secs(30),
        );
        assert_eq!(said.len(), 1, "одна цель — одно слово");
        assert_eq!(said[0].0, "rutracker.org");
        assert_eq!(
            said[0].1,
            Voiced {
                distress: Distress::NoBytes,
                since: Duration::from_secs(10),
            },
            "возраст от свежайшего (20с), а не от первого (0с)"
        );
    }

    /// Затихшие разговоры уходят ПРЕЖДЕ сведения: цель не говорит голосом разговоров, которых уже
    /// нет. Свёртка здесь согласна на что угодно — значит молчание может прийти только оттого, что
    /// сводить стало нечего.
    #[test]
    fn затихшая_цель_не_говорит() {
        let t0 = Instant::now();
        let key = TargetKey::Named("rutracker.org".into());
        let mut layer: Layer<Conversation, Target, Distress> = Layer::new();
        layer.saw(key, flow(1), Distress::NoBytes, t0);

        let fold: Fold = Box::new(всегда);
        assert!(
            voiced(
                &mut layer,
                &fold,
                Duration::from_secs(5),
                t0 + Duration::from_secs(2)
            )
            .len()
                == 1,
            "разговор жив — цель говорит"
        );
        assert!(
            voiced(
                &mut layer,
                &fold,
                Duration::from_secs(5),
                t0 + Duration::from_secs(9)
            )
            .is_empty(),
            "разговор затих — сводить нечего, и слово о цели не рождается"
        );
    }

    // ─── Восьмой закон на ленте движка ──────────────────────────────────────────────────────

    /// Прибор без своей памяти о мире: говорит на каждый пакет одно и то же.
    #[derive(Clone)]
    struct Steady;

    impl Probe<Reading> for Steady {
        fn observe(&mut self, event: &DetectorEvent<Reading>) -> SmallVec<[Distress; 2]> {
            match event {
                DetectorEvent::Packet { .. } => smallvec![Distress::NoBytes],
                _ => smallvec![],
            }
        }

        fn clone_box(&self) -> Box<dyn Probe<Reading>> {
            Box::new(self.clone())
        }
    }

    /// Прибор со СКРЫТЫМ входом: величину берёт из счётчика, живущего вне его состояния. Ровно то,
    /// что восьмой закон обязан ловить, — машина читает то, чего нет в её алфавите.
    #[derive(Clone)]
    struct Peeking;

    static PEEKED: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    impl Probe<Reading> for Peeking {
        fn observe(&mut self, event: &DetectorEvent<Reading>) -> SmallVec<[Distress; 2]> {
            match event {
                DetectorEvent::Packet { .. } => {
                    let ms = PEEKED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    smallvec![Distress::Silence { ms }]
                }
                _ => smallvec![],
            }
        }

        fn clone_box(&self) -> Box<dyn Probe<Reading>> {
            Box::new(self.clone())
        }
    }

    /// Окно ленты из двух разговоров одной цели и узла сетки между ними.
    fn window(start: Instant) -> Tape<Reading, Whose, ()> {
        let target = TargetKey::Named("rutracker.org".into());
        let mut tape: Tape<Reading, Whose, ()> = Tape::new();
        for (n, offset) in [(1u32, 0u64), (2, 10)] {
            tape.record([TapeLetter::Event {
                to: To::One(Whose {
                    flow: flow(n),
                    target: target.clone(),
                }),
                event: DetectorEvent::Packet {
                    input: Reading::Tcp(SeenTcp::sent(100)),
                    at: start + Duration::from_millis(offset),
                },
            }]);
        }
        tape.record([TapeLetter::Event {
            to: To::Each,
            event: DetectorEvent::Tick {
                node: 0,
                at: start + Duration::from_millis(200),
            },
        }]);
        tape
    }

    /// ЛЕНТА ДВИЖКА ВОСПРОИЗВОДИТСЯ: две пере-подачи одного окна свежей семье говорят одно и то же.
    /// Это и есть предмет §10 — не сравнение лент, а сверка ИСХОДОВ.
    #[test]
    fn окно_ленты_воспроизводится() {
        let start = Instant::now();
        let tape = window(start);
        let seeds: Vec<Box<dyn Probe<Reading>>> = vec![Box::new(Steady)];

        let verdict = replays(&tape, |mode, letters| {
            replay::<Tcp>(&seeds, None, Duration::from_secs(10), mode, letters)
        });
        assert_eq!(verdict, Replayed::Reproduced);
    }

    /// СКРЫТЫЙ ВХОД ЛОВИТСЯ: прибор, читающий счётчик вне своего состояния, разводит прогоны — и
    /// закон называет место расхождения. Без этого теста «Reproduced» значил бы лишь то, что мы
    /// дважды позвали одно и то же, а не то, что машина детерминирована.
    #[test]
    fn скрытый_вход_разводит_прогоны() {
        let start = Instant::now();
        let tape = window(start);
        let seeds: Vec<Box<dyn Probe<Reading>>> = vec![Box::new(Peeking)];

        let verdict = replays(&tape, |mode, letters| {
            replay::<Tcp>(&seeds, None, Duration::from_secs(10), mode, letters)
        });
        assert_eq!(
            verdict,
            Replayed::Unstable { at: 0 },
            "разошлись на первом же исходе — счётчик не вернулся к прежнему значению"
        );
    }

    /// СЛОВО О ЦЕЛИ ТОЖЕ ВОСПРОИЗВОДИТСЯ. Копредел — свежая постройка, и не проверить его
    /// переигровкой значило бы оставить непроверенным ровно то, что мы только что сделали.
    #[test]
    fn слово_о_цели_входит_в_сказанное() {
        let start = Instant::now();
        let tape = window(start);
        let seeds: Vec<Box<dyn Probe<Reading>>> = vec![Box::new(Steady)];
        let fold: Fold = Box::new(|words: &[&Distress]| {
            words
                .iter()
                .all(|distress| matches!(distress, Distress::NoBytes))
                .then_some(Distress::NoBytes)
        });

        let said = replay::<Tcp>(
            &seeds,
            Some(&fold),
            Duration::from_secs(10),
            Mode::Replay,
            tape.letters(),
        );
        assert!(
            said.iter()
                .any(|said| matches!(said, Said::OfTarget(name, _) if name == "rutracker.org")),
            "слово о цели в сказанном: {said:?}"
        );
        assert_eq!(
            replays(&tape, |mode, letters| replay::<Tcp>(
                &seeds,
                Some(&fold),
                Duration::from_secs(10),
                mode,
                letters
            )),
            Replayed::Reproduced,
            "с копределом лента тоже воспроизводится"
        );
    }
}
