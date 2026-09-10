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

use reflex_core::backend::Sink;
use reflex_core::capability::{CanAsk, CanHold, CanInject, CanRemember};
use reflex_core::certify::replays::{replays, Replayed};
use reflex_core::colimit::Layer;
use reflex_core::command::InjectablePacket;
use reflex_core::dns::DnsMessage;
use reflex_core::edge::EdgeView;
use reflex_core::effect::Effect;
use reflex_core::flow_table::FlowTable;
use reflex_core::held::{Held, Terminal};
use reflex_core::interleave::Interleave;
pub use reflex_core::mealy::Mealy;
use reflex_core::serves::Served;
use reflex_core::tape::{Mode, Tape, TapeLetter, To};
use reflex_core::tls;
use reflex_core::word::{Conversation, Target};
pub use reflex_core::DetectorEvent;
use reflex_core::Reads;
use reflex_core::Serves;
use reflex_core::{CanSever, Toward};
use reflex_engine::parse::{self, Read};
use reflex_engine::row::{host_of, keyed, Naming, TargetKey};
use reflex_engine::talk::Talks;
use reflex_engine::{Addr, Flow};
use reflex_instrument::edge::{Layout, Memo};
use reflex_instrument::edge_detect::EdgeSilence;
use reflex_instrument::poison::DnsPoisonInstrument;
use reflex_instrument::retransmit::RetransmitInstrument;
pub use reflex_instrument::wire::{Reading, Seen, SeenTcp};
pub use smallvec::{smallvec, SmallVec};

/// Носитель очереди ядра — ЕДИНСТВЕННОЕ место фасада, знающее про Linux. Отдельным модулем, чтобы
/// граница была проверяема ГРЕПОМ: имени линукс-крейта в `lib.rs` не должно встретиться ни разу,
/// иначе «WinDivert встаёт в ту же дверь» остаётся обещанием, а не свойством.
///
/// `#[cfg(unix)]` НА ВСЁМ МОДУЛЕ (задача 12½) — греп мерил СЛЕДСТВИЕ закона (имя не названо), не
/// сам закон (крейт собирается без Linux): до этой задачи `mod nfqueue` был безусловным, а
/// `reflex-engine-nfq` (его прежний источник `parse`/`talk`) безусловно зависел от `reflex-linux`,
/// и `cargo check --target x86_64-pc-windows-msvc` падал 23 ошибками из чужого крейта `nfq` —
/// раньше, чем компилятор доходил до этого модуля. Теперь `parse`/`talk` портативны (переехали в
/// `reflex-engine`), и единственное, что здесь остаётся Linux-специфичным — САМ носитель очереди:
/// `Nfqueue`/`NfqueueCarrier` открывают `reflex_linux::queue::QueueSocket`, которого на Windows нет
/// и быть не может. Потребитель на Windows пишет `engine(WinDivert::filter(..))` — дверь называет
/// носителя явно, переносимость даёт всё, что НИЖЕ первой строки.
#[cfg(unix)]
mod nfqueue;
#[cfg(unix)]
pub use nfqueue::{LocalNfqueue, Nfqueue, NfqueueCarrier, INJECT_MARK};

/// Причина, по которой кадр не прочитан. Реэкспорт, а не внутреннее имя: она стоит в подписи
/// [`Transport::observe`], и без неё свой транспорт снаружи не написать — а `Truncated` из неё
/// решает, ослепнут приборы на этой букве или нет (`DetectorEvent::hides_observation`).
pub use reflex_core::parse::Unread;

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

/// Причина, по которой носитель не открылся, — ЗНАЧЕНИЕ, а не печать. Тот же закон, по которому
/// `Refused` (`core/src/held.rs`) вытеснил `let _ =`: отказ мира есть знание, и его показывает
/// [`Report`], а не журнал.
#[derive(Debug)]
pub struct Cause(pub String);

/// Рецепт носителя: что открыть и под какой раскладкой писать состояние. Дверь `engine(…)` берёт
/// именно рецепт — открытие случается в `run`, чтобы несостоявшийся запуск был ЗНАЧЕНИЕМ, а не
/// паникой на старте `engine(…)`.
///
/// `Self::Carrier: Serves` — и этого ДОСТАТОЧНО для края: [`Serves::Edge`] несёт его сам (задача
/// 10½). Прежде край читался проекцией через тип СООБЩЕНИЯ (`Self::Carrier::Carrier: Edging`) —
/// довод был «край есть величина разговора, бэкенд видит разговор только через пакет», верный, но
/// не о том вопросе: декоратор (`Local`), вставший МЕЖДУ вызывающим и носителем, обязан ПОДМЕНИТЬ
/// край, а подменить чужой `impl Edging` ему нечем (правило сирот, да и `Edging` даёт ровно один
/// `Edge` на тип сообщения). `Serves` уже стоит в точке, где декоратор решает — перенос края туда
/// снял вопрос, не переложил его. `Edging` не исчез — он остался внутренним помощником у
/// носителей, которые и правда берут край из сообщения (`QueueSocket::serve`).
pub trait IntoCarrier {
    /// Открытый носитель — то, чем движок будет [`Serves::serve`]ить в ведущем цикле.
    type Carrier: Serves;
    /// Открыть носитель. Здесь и только здесь читаются его предпосылки (для очереди — база
    /// таймаутов conntrack).
    fn open(self) -> Result<Self::Carrier, Cause>;
    /// Раскладка марки, под которой пишут состояние краевые приборы.
    fn layout(&self) -> Layout;
    /// Имя носителя — то, чем [`Report`] назовёт несостоявшийся запуск. Число очереди больше не
    /// единственная форма имени: у WinDivert его нет вовсе.
    fn name(&self) -> String;
}

/// НОСИТЕЛЬ, ЧЕЙ `Serves` ВЕДЁТ КРАЙ, — одним именем вместо проекции в два звена
/// (`<C::Carrier as Serves>::Edge`). Не украшение: проекция стоит в границах восьми стадий
/// цепочки, и записанная восемь раз она была бы восемью местами, где её можно записать по-разному.
///
/// Реализуется САМА, всяким рецептом с `Self::Carrier: Serves` — заявлять её руками нечего, иначе
/// носитель мог бы объявить одним краем то, что показывает другим.
pub trait Bordered: IntoCarrier {
    /// Чей край едет в широком слове цепочки. `Clone` и `'static` — требование не закона, а хранения:
    /// край едет копией в каждой букве и живёт в ленте дольше пакета.
    type Edge: EdgeView + Clone + 'static;

    /// Что удержанное сообщение показывает НА ПРОВОДЕ — байты кадра. Край сюда больше не заходит:
    /// его отдаёт [`Serves::serve`] ВТОРЫМ доводом решения (`decide(held, edge)`), не сообщение —
    /// декоратор (`Local`) волен подменить его до того, как `decide` вообще позван.
    fn shown(held: &Held<Carried<Self>>) -> &[u8];
}

/// Носитель СООБЩЕНИЯ — тот, у кого спрашивают байты (внутри `serve`, где бэкенд занят одним
/// наблюдением).
type Carried<C> = <<C as IntoCarrier>::Carrier as Terminal>::Carrier;

impl<C> Bordered for C
where
    C: IntoCarrier,
    C::Carrier: Serves,
    Carried<C>: reflex_core::held::Observed,
    <C::Carrier as Serves>::Edge: Clone + 'static,
{
    type Edge = <C::Carrier as Serves>::Edge;

    fn shown(held: &Held<Carried<C>>) -> &[u8] {
        held.seen()
    }
}

/// Открыть движок над носителем — единственная точка входа фреймворка. Берёт РЕЦЕПТ, а не открытый
/// носитель: несостоявшийся запуск обязан быть значением ([`Report::not_started`]), а не паникой на
/// первой строке потребительской цепочки.
pub fn engine<C: IntoCarrier>(carrier: C) -> Engine<C> {
    Engine { carrier }
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
    /// Что вышло из кадра. ТРИ исхода, не два: наблюдение, ПРОПАВШЕЕ наблюдение и чужой кадр.
    ///
    /// Прежде подпись отдавала `Option`, и «кадр обрезан» схлопывалось с «не мой транспорт» в один
    /// `None`. Цена схлопывания замерена и была двойной: (1) обрезанный кадр доезжал до цикла
    /// неотличимым от чужого и двигал часы тишины через `Interleave::idle` — то есть кадр,
    /// СПРЯТАВШИЙ ответ цели, работал свидетельством молчания; (2) буква `Opaque { why: Truncated }`
    /// с боевого пути не рождалась вовсе, и работа пяти приборов по прячущей букве
    /// (`DetectorEvent::hides_observation`) не срабатывала ни разу за жизнь продукта — механизм,
    /// потреблённый ноль раз. `Read::Truncated` доезжал сюда из `parse::read` и терялся ровно здесь.
    ///
    /// Кто пишет свой транспорт: `Observation::Unread` — только для кадра, который БЫЛ и МОГ нести
    /// ответ этого разговора (сегодня это `Read::Truncated`). Чужой протокол, чужой порт, не-IPv4 —
    /// `Observation::Foreign`: ослепнуть на них значило бы онеметь зря (тот же довод, что в
    /// `DetectorEvent::hides_observation`).
    fn observe(state: &mut Self::State, read: Read<'_>) -> Observation<Self::Wire>;
}

/// Исход разбора кадра транспортом. Три клетки, потому что цикл отвечает на них ТРЕМЯ разными
/// буквами шва, и слить любые две значило бы солгать приборам о том, что было на проводе.
pub enum Observation<W> {
    /// Наблюдение состоялось — [`Interleave::saw`].
    Seen(Observed<W>),
    /// Кадр БЫЛ и мог нести ответ цели, но прочесть его не удалось. Причина едет в букве:
    /// [`Interleave::unread`] родит `Opaque { why }`, и приборы, судящие по ОТСУТСТВИЮ, на такой
    /// букве слепнут — отсутствие наблюдений в окне перестало быть установленным.
    Unread(Unread),
    /// Кадр не нашего разговора: чужой протокол, чужой порт, не-IPv4, либо наш протокол, но
    /// состояние разбора наблюдения из него не сделало. Момент прихода СЕТКУ ДВИГАЕТ (иначе поток
    /// чужого трафика выглядел бы тишиной), а зрения не отнимает.
    Foreign,
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

    fn observe(state: &mut TcpState, read: Read<'_>) -> Observation<Reading> {
        let wire = match read {
            Read::Tcp(wire) => wire,
            // Обрезанный кадр — ПОТЕРЯ, а не свойство чужого трафика: заголовок не поместился
            // целиком, и байты этого разговора могли быть в нём (`parse::ipv4` различает «обрезан»
            // и «чужой протокол» нарочно). Молчать о нём значило бы отдать приборам окно, которое
            // выглядит свободным от пропажи и им не является.
            Read::Truncated => return Observation::Unread(Unread::Truncated),
            Read::Udp(_) | Read::NotIpv4 | Read::NotOurProtocol | Read::NotOurPort => {
                return Observation::Foreign
            }
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
        // Разбор состоялся, а наблюдения из него не вышло (`Talks` не всякий сегмент переводит в
        // слово): кадр наш и целый — прятать нечего, потому `Foreign`, а не `Unread`.
        match state.talks.read(&wire) {
            Some(tcp) => Observation::Seen(Observed {
                flow: wire.flow,
                key,
                wire: Reading::Tcp(tcp),
            }),
            None => Observation::Foreign,
        }
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

    fn observe(_state: &mut UdpState, read: Read<'_>) -> Observation<DnsMessage> {
        let datagram = match read {
            Read::Udp(datagram) => datagram,
            // Довод тот же, что у `Tcp::observe`: обрезанный кадр мог быть нашей датаграммой.
            Read::Truncated => return Observation::Unread(Unread::Truncated),
            Read::Tcp(_) | Read::NotIpv4 | Read::NotOurProtocol | Read::NotOurPort => {
                return Observation::Foreign
            }
        };
        // Датаграмма ЦЕЛА (иначе выше был бы `Truncated`), а DNS в ней не разобрался — не наш
        // разговор на нашем порту: скрывать ему нечего.
        let Some(message) = DnsMessage::parse(datagram.payload) else {
            return Observation::Foreign;
        };
        // Цель — имя из вопроса (оно же и отравляют); вопроса нет — цель безымянна, и ключуется
        // адресом резолвера. Тег сохраняется: `Unnamed` не притворяется именем.
        let key = message
            .queries
            .first()
            .map(|query| TargetKey::Named(query.name.clone().into_boxed_str()))
            .unwrap_or(TargetKey::Unnamed(datagram.dst));
        Observation::Seen(Observed {
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

/// ШИРОКОЕ слово фасада: провод транспорта И вид края о том же разговоре. Пара, а не два входа:
/// область у них ОДНА (`Of = Conversation`) — провод говорит о разговоре с провода, край несёт о
/// НЁМ ЖЕ добавочные величины (счётчики, возраст). Одна область — одна дверь; §5 разводит области,
/// а не источники.
///
/// `Option` у края — обитаемая клетка (§7): пакет, которого край ещё не завёл в свою таблицу
/// (первый `SYN` вне conntrack), вида не имеет, и «не считали» обязано отличаться от «не ответила».
///
/// `E` — ЧЕЙ это край, и он параметр, а не `CtEdge`. Пока в слове стоял тип из `reflex-linux`,
/// прибор — вещь, о носителе не знающая по построению, — получал его через всю цепочку до себя, и
/// «носитель есть параметр» держалось на честном слове, а не на типе.
pub type Wide<W, E> = (W, Option<E>);

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
/// буква не его, шаг пропускается); тик, непонятое и дыра идут всем.
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
        DetectorEvent::Torn { at } => Some(DetectorEvent::Torn { at: *at }),
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

/// Прибор КРАЯ: состояния в юзерспейсе не держит — оно живёт в марке ядра, и потому прибор говорит
/// ДВА слова: беду и памятку, которую петля уложит в вердикт.
///
/// Отдельный трейт, а не флаг на [`Probe`], потому что ВЫХОД у него другой. Заведи общий выход с
/// полем памятки — и каждый проводной прибор обязан отдавать в нём `None`: поле, которое все обязаны
/// оставить пустым, адресовано не им (тот же довод, что развёл буквы ленты, только с выходной
/// стороны).
#[doc(hidden)]
pub trait EdgeProbe<W>: Send {
    fn observe(&mut self, event: &DetectorEvent<W>) -> (Option<Memo>, SmallVec<[Distress; 2]>);
}

/// ГДЕ ЖИВЁТ СОСТОЯНИЕ прибора — объявляет сам прибор, не потребитель. Потребитель пишет
/// `.detect(что хочет)`, род скрыт: тезис «наружу только синтаксис» держится тем, что род не
/// спрашивают, а сообщают.
///
/// Дом не украшение: от него зависит, КАК петля гонит прибор. Живущий по разговору получает копию
/// на каждый ключ и будится тиками (его часы молчания — в юзерспейсе); живущий на крае существует в
/// одном экземпляре и тиков не просит вовсе — его часы приезжают величиной с пакетом (`age`
/// conntrack), а состояние уезжает в марку.
#[doc(hidden)]
pub enum Placed<W> {
    /// По разговору: копия шаблона на ключ, тики, состояние в юзерспейсе.
    PerFlow(Box<dyn Probe<W>>),
    /// На крае: один экземпляр, состояние в марке ядра, тиков не просит.
    AtEdge(Box<dyn EdgeProbe<W>>),
}

/// Подъём КРАЕВОЙ машины в прибор края: сужение то же (§4, [`Reads`]), но выход двойной — беда и
/// памятка. Копии на ключ не делает: экземпляр один, состояние в марке.
struct AtEdge<M, N> {
    machine: M,
    alphabet: PhantomData<fn() -> N>,
}

impl<W, N, M> EdgeProbe<W> for AtEdge<M, N>
where
    W: 'static,
    N: Reads<W> + 'static,
    M: Mealy<In = DetectorEvent<N>, Out = (Option<Memo>, SmallVec<[Distress; 2]>)>
        + Copy
        + Send
        + 'static,
{
    fn observe(&mut self, event: &DetectorEvent<W>) -> (Option<Memo>, SmallVec<[Distress; 2]>) {
        match narrow::<W, N>(event) {
            Some(event) => {
                let (machine, said, _log) = self.machine.step(event);
                self.machine = machine;
                said
            }
            // Буква не его — ни слова, ни памятки: молчание тут «не моё», а не «нечего помнить».
            None => (None, SmallVec::new()),
        }
    }
}

/// Прибор, кладущийся в `.detect(…)` для транспорта с широким словом `W`. Реализуют конкретные
/// детекторы; несовместимый транспорту прибор не соберётся (нет `IntoProbe<W>`).
/// Пишет ли прибор в НАШИ биты марки. Не «краевой ли он»: краевой прибор, читающий только счётчики,
/// памятки не пишет и соседа не затирает — предмет гейта есть число ПИСАТЕЛЕЙ в одну раскладку.
pub trait MarkHome {}
/// Прибор памятки не пишет — соседей по марке у него нет.
pub struct MarkSilent;
/// Прибор пишет памятку: раскладка одна, второго писателя она не вмещает.
pub struct MarkWriter;
impl MarkHome for MarkSilent {}
impl MarkHome for MarkWriter {}

pub trait IntoProbe<W> {
    /// Пишет ли прибор марку. Объявляет САМ прибор, как и дом (`place`).
    type Home: MarkHome;

    /// Куда прибор встаёт. `layout` — раскладка НАШИХ битов марки, параметр цепочки: краевой прибор
    /// пишет под ней состояние, проводной её не смотрит. Отдаётся всем, потому что дом объявляет
    /// прибор, а не спрашивающий: спроси фасад «краевой ли ты» отдельным методом — и ответ разошёлся
    /// бы с тем, что прибор вернул.
    #[doc(hidden)]
    fn place(self, layout: Layout) -> Placed<W>;
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

/// Тишина живёт НА КРАЕ: её предмет — «цель не отвечает», а это край видит счётчиками, и держать
/// параллельно свои часы значило бы вести второй закон об одном предмете. Порог по ВОЗРАСТУ потока
/// (`age`), а не по нашему тику: возраст монотонен, тик — нет.
///
/// Блэкхол сюда же и входит той же прогрессией фаз: `up.packets` 0 — соединения не было, 1 — только
/// `SYN+ACK` и молчание, ≥2 — цель жива. Одна величина, один прибор; разводить их значило бы завести
/// две фазы над одним счётчиком.
///
/// Край — ПАРАМЕТР `E`, а не conntrack: прибор читает закон [`EdgeView`], и другой носитель ставит
/// сюда свой край, не трогая ни строки парка.
impl<E: EdgeView + Clone + 'static> IntoProbe<Wide<Reading, E>> for Silence {
    type Home = MarkWriter;
    fn place(self, layout: Layout) -> Placed<Wide<Reading, E>> {
        Placed::AtEdge(Box::new(AtEdge {
            machine: EdgeSilence::<E>::new(self.after, layout),
            alphabet: PhantomData,
        }))
    }
    fn window(&self) -> Duration {
        self.after
    }
}

/// Повтор клиента остаётся В ПРОВОДЕ: его улика — совпавший `seq`, а счётчики края номеров не
/// хранят. Носитель предмета НЕ видит — значит и состоянию его там не место (§9.1: носитель следует
/// за тем, что подложка умеет видеть).
impl<E: Clone + 'static> IntoProbe<Wide<Reading, E>> for Retransmit {
    type Home = MarkSilent;
    fn place(self, _layout: Layout) -> Placed<Wide<Reading, E>> {
        Placed::PerFlow(lift::<Wide<Reading, E>, Seen, _>(
            RetransmitInstrument::new(),
        ))
    }
}

/// Блэкхол по имени остаётся дверью потребителя, но за ней стоит КРАЙ — тот же `EdgeSilence`:
/// «соединения не было» есть его ветка `up.packets == 0`. Имя прибора называет ПРЕДМЕТ, не
/// реализацию, потому цепочка потребителя не меняется.
///
/// Часы при этом сменились честно: проводной ловил повтор `SYN` (RTO клиента, сотни мс), краевой
/// ловит возраст потока. Предмет тот же — адрес молчит; ранняя реакция на быстром повторе уходит, и
/// это цена переезда, названная вслух.
impl<E: EdgeView + Clone + 'static> IntoProbe<Wide<Reading, E>> for SynDrop {
    type Home = MarkWriter;
    fn place(self, layout: Layout) -> Placed<Wide<Reading, E>> {
        Placed::AtEdge(Box::new(AtEdge {
            machine: EdgeSilence::<E>::new(BLACKHOLE_WINDOW, layout),
            alphabet: PhantomData,
        }))
    }
    fn window(&self) -> Duration {
        BLACKHOLE_WINDOW
    }
}

/// Отравление DNS — В ПРОВОДЕ: предмет его СОДЕРЖИМОЕ ответа (инжект `NXDOMAIN`), а край
/// содержимого не читает вовсе.
impl<E: Clone + 'static> IntoProbe<Wide<DnsMessage, E>> for DnsPoison {
    type Home = MarkSilent;
    fn place(self, _layout: Layout) -> Placed<Wide<DnsMessage, E>> {
        Placed::PerFlow(lift::<Wide<DnsMessage, E>, DnsMessage, _>(
            DnsPoisonInstrument::new(),
        ))
    }
}

/// Окно возраста для блэкхола. Две секунды: шире худшего законного рукопожатия под нагрузкой (одной
/// не хватило — редкий медленный поток кричал ложно), но у́же терпения клиента, который на вечном
/// дропе повторяет `SYN` до ~15 с. Замерено на стенде 09.09.2026, не выбрано.
const BLACKHOLE_WINDOW: Duration = Duration::from_secs(2);

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

/// Свой прибор живёт ПО РАЗГОВОРУ: он держит состояние в себе, движок сеет копию на ключ. Кто хочет
/// краевой дом, кладёт машину, читающую [`Edged`], — для неё есть [`own_at_edge`].
impl<W, N, M> IntoProbe<W> for Own<M, N>
where
    W: 'static,
    N: Reads<W> + 'static,
    M: Mealy<In = DetectorEvent<N>, Out = SmallVec<[Distress; 2]>> + Copy + Send + 'static,
{
    type Home = MarkSilent;
    fn place(self, _layout: Layout) -> Placed<W> {
        Placed::PerFlow(lift::<W, N, M>(self.machine))
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

/// Движок над носителем — ждёт выбора транспорта. Носитель едет РЕЦЕПТОМ через всю цепочку и
/// открывается в `run`: цепочка собирается там, где её пишут, а мир трогается там, где бегут.
pub struct Engine<C> {
    carrier: C,
}

impl<C: IntoCarrier> Engine<C> {
    /// Поток разговоров этого транспорта (`Tcp` — соединения, `Udp` — датаграммы/DNS).
    pub fn from<T: Transport>(self, _transport: T) -> Watching<C, T> {
        Watching {
            carrier: self.carrier,
            transport: PhantomData,
        }
    }
}

/// Транспорт выбран — ждёт ключа разговора.
pub struct Watching<C, T> {
    carrier: C,
    transport: PhantomData<fn() -> T>,
}

impl<C: IntoCarrier, T: Transport> Watching<C, T> {
    /// Чем ключуется цель.
    pub fn extract(self, _key: Sni) -> Keyed<C, T> {
        Keyed {
            carrier: self.carrier,
            transport: PhantomData,
        }
    }
}

/// Ключ выбран — ждёт хотя бы одного детектора.
pub struct Keyed<C, T> {
    carrier: C,
    transport: PhantomData<fn() -> T>,
}

impl<C: Bordered, T: Transport> Keyed<C, T> {
    /// Установить первый детектор. Прибор обязан читать словарь этого транспорта над краем этого
    /// носителя (`IntoProbe<Wide<T::Wire, C::Edge>>`) — иначе не соберётся.
    ///
    /// Раскладку марки спрашивают у НОСИТЕЛЯ, а не хранят копией в стадии: копия была бы вторым
    /// источником одной величины, и разошлась бы с первым молча.
    pub fn detect<P: IntoProbe<Wide<T::Wire, C::Edge>>>(
        self,
        detector: P,
    ) -> Detecting<C, T, P::Home> {
        let mut park = Park::new();
        let longest = detector.window();
        park.add(detector.place(self.carrier.layout()));
        Detecting {
            home: PhantomData,
            carrier: self.carrier,
            park,
            longest,
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

/// Приборы цепочки, разложенные ПО ДОМУ состояния. Два списка, а не один с тегом: петля гонит их
/// по-разному, и «род» тут не пометка, а разная механика — проводные сеются по ключу и будятся
/// тиками, краевой живёт одним экземпляром и пишет марку.
struct Park<W> {
    per_flow: Vec<Box<dyn Probe<W>>>,
    at_edge: Vec<Box<dyn EdgeProbe<W>>>,
}

impl<W> Park<W> {
    fn new() -> Park<W> {
        Park {
            per_flow: Vec::new(),
            at_edge: Vec::new(),
        }
    }

    /// Поставить прибор в его дом — тот, который он сам назвал.
    fn add(&mut self, placed: Placed<W>) {
        match placed {
            Placed::PerFlow(probe) => self.per_flow.push(probe),
            Placed::AtEdge(probe) => self.at_edge.push(probe),
        }
    }
}

/// Детекторы копятся — можно добавить ещё или перейти к реакции.
pub struct Detecting<C: Bordered, T: Transport, H: MarkHome = MarkSilent> {
    home: PhantomData<fn() -> H>,
    carrier: C,
    park: Park<Wide<T::Wire, C::Edge>>,
    longest: Duration,
    about: Option<(Fold, TargetVoice)>,
    transport: PhantomData<fn() -> T>,
}

impl<C: Bordered, T: Transport, H: MarkHome> Detecting<C, T, H> {
    /// Тело установки, общее обеим дверям: дом меняется ТИПОМ, работа одна.
    fn add<P: IntoProbe<Wide<T::Wire, C::Edge>>, H2: MarkHome>(
        mut self,
        detector: P,
    ) -> Detecting<C, T, H2> {
        self.longest = self.longest.max(detector.window());
        let placed = detector.place(self.carrier.layout());
        self.park.add(placed);
        Detecting {
            home: PhantomData,
            carrier: self.carrier,
            park: self.park,
            longest: self.longest,
            about: self.about,
            transport: PhantomData,
        }
    }
}

impl<C: Bordered, T: Transport> Detecting<C, T, MarkSilent> {
    /// Ещё прибор поверх — они гоняются ВМЕСТЕ над одним проводом. Писателя марки пока нет, потому
    /// принимается ЛЮБОЙ прибор; его дом становится домом цепочки.
    pub fn detect<P: IntoProbe<Wide<T::Wire, C::Edge>>>(
        self,
        detector: P,
    ) -> Detecting<C, T, P::Home> {
        self.add::<P, P::Home>(detector)
    }
}

impl<C: Bordered, T: Transport> Detecting<C, T, MarkWriter> {
    /// Писатель марки в цепочке УЖЕ есть, и второго она не вмещает: марка одна, состояние одно, а
    /// автоматы разные — второй читал бы фазу первого как свою и повторял бы высказывание на каждом
    /// пакете (замер 10.09: один прибор говорит однажды, два — трижды за четыре пакета, и под
    /// `.act` это RST на каждом пакете). Потому здесь принимается только прибор, марки не пишущий.
    ///
    /// Отказ даёт ТИП, а не проверка при запуске: чего носитель не вмещает, того потребитель не
    /// построит (§9.1). Две краевые двери подряд не собираются —
    ///
    /// ```compile_fail
    /// use reflex::*;
    /// let _ = engine(Nfqueue::queue(200))
    ///     .from(Tcp)
    ///     .extract(Sni)
    ///     .detect(Silence::after(std::time::Duration::from_secs(5)))
    ///     .detect(SynDrop::unreachable())   // второй писатель марки — цепочка не соберётся
    ///     .on(|_, _| {});
    /// ```
    ///
    /// — а писатель рядом с не-писателем собирается, в любом порядке:
    ///
    /// ```
    /// use reflex::*;
    /// let _ = engine(Nfqueue::queue(200))
    ///     .from(Tcp)
    ///     .extract(Sni)
    ///     .detect(Silence::after(std::time::Duration::from_secs(5)))
    ///     .detect(Retransmit::unanswered())
    ///     .on(|_, _| {});
    /// let _ = engine(Nfqueue::queue(200))
    ///     .from(Tcp)
    ///     .extract(Sni)
    ///     .detect(Retransmit::unanswered())
    ///     .detect(SynDrop::unreachable())
    ///     .on(|_, _| {});
    /// ```
    pub fn detect<P: IntoProbe<Wide<T::Wire, C::Edge>, Home = MarkSilent>>(
        self,
        detector: P,
    ) -> Detecting<C, T, MarkWriter> {
        self.add::<P, MarkWriter>(detector)
    }
}

impl<C: Bordered, T: Transport, H: MarkHome> Detecting<C, T, H> {
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
    ) -> Folding<C, T, H> {
        Folding {
            detecting: self,
            fold: Box::new(fold),
        }
    }

    /// НАБЛЮДАТЬ: реакция на срабатывание, без вмешательства. `target` — имя цели, `distress` — что
    /// случилось. Пакет идёт как шёл.
    pub fn on<F: FnMut(&str, Distress)>(self, react: F) -> Running<C, T, F, H> {
        Running {
            detecting: self,
            react,
            certify: false,
        }
    }

    /// ДЕЙСТВОВАТЬ: реакция возвращает [`Act`], движок его исполняет. `Act::sever()` инжектит RST
    /// тому, кто прислал ПАКЕТ-улику, — так тихий дроп обрывается за ~300мс вместо вечной крутилки.
    ///
    /// Действует на сигналы, ПРИШЕДШИЕ С ПАКЕТОМ, и это держит КОНСТРУКЦИЯ, а не привычка приборов
    /// молчать на узле: улика едет вместе с адресом (`Alive::walk`), а у узла сетки и дыры адреса
    /// нет — им достаётся пустой срез, и строить из него нечего. Иначе слово ЧУЖОГО разговора
    /// рвало бы разговор, привёзший пакет. Тишина потому и обрывается следующим повтором клиента, а
    /// не узлом.
    pub fn act<F: FnMut(&str, Distress) -> Act<C::Carrier>>(self, react: F) -> Acting<C, T, F, H>
    where
        C::Carrier: CanHold,
    {
        Acting {
            detecting: self,
            react,
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
/// use reflex::{Act, NfqueueCarrier};
/// // Очередь ядра — терминал, она держит, рвёт и помнит, но СПРОСИТЬ не умеет: дверь у неё одна,
/// // вердикт удержанному пакету, и наружу к постороннему собеседнику она не говорит. `CanAsk` не
/// // заявлен, и конструктора `ask` у её акта просто нет.
/// let _ = Act::<NfqueueCarrier>::ask(1);
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
pub struct Folding<C: Bordered, T: Transport, H: MarkHome = MarkSilent> {
    detecting: Detecting<C, T, H>,
    fold: Fold,
}

impl<C: Bordered, T: Transport, H: MarkHome> Folding<C, T, H> {
    /// Что делать со словом о ЦЕЛИ. Дверь отдельная от [`Detecting::on`], потому что область другая:
    /// беда разговора и беда цели — слова разных слоёв, и §5 не складывает их законом пары. Спустить
    /// слово о цели к разговору тоже нельзя — это отменило бы только что сделанную агрегацию.
    pub fn on_target<G: FnMut(&str, Voiced) + Send + 'static>(self, react: G) -> Speaking<C, T, H> {
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
/// рождается на границе узла сетки, а узел носителя не имеет — рвать по нему нечем. Отказ
/// компилятора честнее цепочки, собравшейся и молчащей.
pub struct Speaking<C: Bordered, T: Transport, H: MarkHome = MarkSilent> {
    detecting: Detecting<C, T, H>,
}

impl<C: Bordered, T: Transport> Speaking<C, T, MarkSilent> {
    /// Ещё прибор поверх — как в [`Detecting::detect`]: копредел не закрывает набор приборов.
    pub fn detect<P: IntoProbe<Wide<T::Wire, C::Edge>>>(
        self,
        detector: P,
    ) -> Speaking<C, T, P::Home> {
        Speaking {
            detecting: self.detecting.detect(detector),
        }
    }
}

impl<C: Bordered, T: Transport> Speaking<C, T, MarkWriter> {
    /// Писатель марки уже стоит — принимается только прибор, её не пишущий (см. `Detecting`).
    pub fn detect<P: IntoProbe<Wide<T::Wire, C::Edge>, Home = MarkSilent>>(
        self,
        detector: P,
    ) -> Speaking<C, T, MarkWriter> {
        Speaking {
            detecting: self.detecting.detect(detector),
        }
    }
}

impl<C: Bordered, T: Transport, H: MarkHome> Speaking<C, T, H> {
    /// НАБЛЮДАТЬ слова о РАЗГОВОРАХ — вторая дверь пары. Слова о цели уже адресованы `.on_target`.
    pub fn on<F: FnMut(&str, Distress)>(self, react: F) -> Running<C, T, F, H> {
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

// ─── Голос цепочки: чем терминалы отличаются друг от друга ────────────────────────────────────

/// ГОЛОС ЦЕПОЧКИ — что она делает со словом беды. Два терминала (`.on` — смотреть, `.act` —
/// действовать) отличаются ТОЛЬКО этим, и оттого ведущий цикл у них ОДИН. Прежде их было два, по
/// сотне строк каждый, и всякая правка обязана была случиться дважды; второй раз о ней забывали —
/// цикл `.act` не знал ни слова о цели, ни ленты §10, ни дыры, и молчал об этом зелёной сборкой.
///
/// Слово и ЭФФЕКТ разведены двумя методами не для порядка: услышать беду цикл обязан ВНУТРИ
/// решения (носитель заимствован, пакет в руках), а тронуть мир — снаружи, когда носитель
/// свободен. Тронь мир из `hears` — второго `&mut` не нашлось бы (`E0499`), и обрыв поехал бы мимо
/// носителя своим сокетом, как ездил до §9.4.
trait Voice<K> {
    /// Беда услышана — чем цепочка обещает тронуть мир. Пусто у наблюдателя.
    fn hears(&mut self, target: &str, distress: Distress, seen: &[u8]) -> SmallVec<[Effect; 2]>;
    /// Исполнить обещанное носителем. У наблюдателя обещаний не бывает — тело пусто по построению.
    fn does(&mut self, carrier: &mut K, effects: SmallVec<[Effect; 2]>);
}

/// СМОТРЕТЬ: реакция потребителя, мира не касающаяся.
struct Watch<F>(F);

impl<K, F: FnMut(&str, Distress)> Voice<K> for Watch<F> {
    fn hears(&mut self, target: &str, distress: Distress, _seen: &[u8]) -> SmallVec<[Effect; 2]> {
        (self.0)(target, distress);
        SmallVec::new()
    }

    fn does(&mut self, _carrier: &mut K, _effects: SmallVec<[Effect; 2]>) {}
}

/// ДЕЙСТВОВАТЬ: реакция возвращает акт, [`emit`] переводит его в слово носителю и команды миру,
/// исполняет их цикл — и в переигровке не исполняет, тем лента и остаётся переигрываемой (§10).
struct Do<F>(F);

impl<K, F> Voice<K> for Do<F>
where
    K: CanHold + CanInject,
    K::Error: std::fmt::Debug,
    F: FnMut(&str, Distress) -> Act<K>,
{
    fn hears(&mut self, target: &str, distress: Distress, seen: &[u8]) -> SmallVec<[Effect; 2]> {
        let (_word, effects) = emit::<K>((self.0)(target, distress), seen);
        effects
    }

    fn does(&mut self, carrier: &mut K, effects: SmallVec<[Effect; 2]>) {
        for effect in effects {
            let Effect::Inject(packet) = effect;
            if let Err(why) = carrier.emit(K::inject(packet)) {
                report!("инъекция не ушла: {why:?}");
            }
        }
    }
}

/// Цепочка собрана — готова к запуску.
pub struct Running<C: Bordered, T: Transport, F, H: MarkHome = MarkSilent> {
    detecting: Detecting<C, T, H>,
    react: F,
    /// Предъявлять ли восьмой закон на живой ленте — [`Running::certifying`].
    certify: bool,
}

impl<C, T, F, H: MarkHome> Running<C, T, F, H>
where
    C: Bordered,
    C::Carrier: CanHold + CanRemember,
    // См. докблок `drive`: тождество ассоциированных путей края нужно явным, иначе `drive::<C,…>`
    // ниже не соберётся — компилятор не отождествляет их через сторонний `impl Bordered`.
    C::Carrier: Serves<Edge = <C as Bordered>::Edge>,
    <C::Carrier as Terminal>::Refusal: std::fmt::Debug,
    T: Transport,
    F: FnMut(&str, Distress),
{
    /// НАБЛЮДАТЬ. Ведущий цикл один на оба терминала — см. [`drive`]; отсюда в него едет голос
    /// [`Watch`], мира не касающийся.
    pub fn run(self) -> Report {
        let Running {
            detecting,
            react,
            certify,
        } = self;
        drive::<C, T, _, H>(detecting, certify, &mut Watch(react))
    }

    /// Предъявлять восьмой закон (§10) на СВОЕЙ ленте: движок пишет окно наблюдений и, набрав его,
    /// пере-подаёт свежей семье машин дважды — сверяя не ленту, а сказанное.
    ///
    /// Дверь отдельная и по умолчанию закрытая: запись стоит клона слова провода на каждый пакет, и
    /// платить её тем, кто закона не просит, незачем. Кто просит — получает свидетельство на СВОЁМ
    /// трафике, а не на выдуманном стенде: это и отличает предъявимость от обещания.
    pub fn certifying(mut self) -> Running<C, T, F, H> {
        self.certify = true;
        self
    }
}

/// Цепочка с ДЕЙСТВИЕМ собрана — готова к запуску.
pub struct Acting<C: Bordered, T: Transport, F, H: MarkHome = MarkSilent> {
    detecting: Detecting<C, T, H>,
    react: F,
}

impl<C, T, F, H: MarkHome> Acting<C, T, F, H>
where
    C: Bordered,
    C::Carrier: CanHold + CanRemember + CanInject,
    // См. докблок `drive`: тождество ассоциированных путей края нужно явным, иначе `drive::<C,…>`
    // ниже не соберётся — компилятор не отождествляет их через сторонний `impl Bordered`.
    C::Carrier: Serves<Edge = <C as Bordered>::Edge>,
    <C::Carrier as Terminal>::Refusal: std::fmt::Debug,
    <C::Carrier as Sink>::Error: std::fmt::Debug,
    T: Transport,
    F: FnMut(&str, Distress) -> Act<C::Carrier>,
{
    /// ДЕЙСТВОВАТЬ. Тот же ведущий цикл, что и у `.on` ([`drive`]), — отличается только голосом
    /// [`Do`]: он переводит акт в команды и отдаёт их СТОКУ НОСИТЕЛЯ. Узлы сетки, дыра и памятка
    /// работают здесь ровно так же, как у наблюдателя, и это не совпадение, а следствие одного
    /// цикла: прежде у действия был свой, и он молча разошёлся — слова узлов выбрасывал (`let _ =
    /// table.tick(now)`), дыры не знал вовсе.
    ///
    /// Чего здесь НЕ БЫВАЕТ, и почему — по факту, а не по обещанию:
    /// * ЛЕНТА §10 не пишется никогда: [`Running::certifying`] живёт только у наблюдателя. Цикл
    ///   её умеет, дверь к ней у действия не открыта;
    /// * СЛОВО О ЦЕЛИ не рождается никогда: `.act` недостижим из [`Speaking`], то есть цепочка со
    ///   свёрткой до этого терминала не доходит.
    ///
    /// Обе двери закрыты решением о ПРОДУКТЕ, а не свойством цикла, и открыть их — отдельный
    /// разговор, не попутная правка.
    pub fn run(self) -> Report {
        let Acting { detecting, react } = self;
        drive::<C, T, _, H>(detecting, false, &mut Do(react))
    }
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
/// потребительскую цепочку не вписан, потому содержимое отклика здесь пусто.
type Recorded<C, T> = Tape<Wide<<T as Transport>::Wire, <C as Bordered>::Edge>, Whose, ()>;

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
/// Зеркало живой петли, и в этом весь смысл: те же двери ([`FlowTable::process`] на пакет,
/// [`FlowTable::each`] на букву без адреса, свёртка на границе узла), но вход берётся из ЛЕНТЫ, а
/// не из носителя и часов. Что расходится — то и есть скрытый вход машины (§10).
///
/// Реакции потребителя здесь не зовутся вовсе: они трогают мир, а переигровка его не трогает
/// (§9.4). Наружу идут ИСХОДЫ — их и сверяет закон.
///
/// Параметр — ШИРОКОЕ СЛОВО целиком, не транспорт: транспорт тут не при чём, лента уже разобрана.
fn replay<W: Clone + 'static>(
    seeds: &[Box<dyn Probe<W>>],
    fold: Option<&Fold>,
    idle: Duration,
    mode: Mode,
    letters: &[TapeLetter<W, Whose, ()>],
) -> Vec<Said> {
    // Живой режим сюда не приходит: пере-подача — всегда переигровка. Придёт — упадём в отладке,
    // а не соврём тихо вердиктом, добытым касанием мира.
    debug_assert_eq!(mode, Mode::Replay, "переигровка идёт только в Replay");

    let templates: Vec<Box<dyn Probe<W>>> = seeds.iter().map(|probe| probe.clone_box()).collect();
    let mut table = FlowTable::<Probes<W>, Flow>::new(idle, move |_flow| {
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
        match to {
            To::One(whose) => {
                let DetectorEvent::Packet { input, at } = event else {
                    // Адресованной может быть только буква с ключом: прочие сочетания лента не
                    // рождает — их пишет тот же код, что читает.
                    continue;
                };
                let (signals, ()) = table.process(whose.flow, input, *at);
                for signal in &signals {
                    said.push(Said::OfConversation(label(&whose.target), signal.clone()));
                    layer.saw(whose.target.clone(), whose.flow, signal.clone(), *at);
                }
                targets.insert(whose.flow, whose.target.clone());
            }
            To::Each => {
                let at = event.at();
                for (flow, (signals, ())) in table.each(event.clone()) {
                    if let Some(key) = targets.get(&flow) {
                        for signal in &signals {
                            said.push(Said::OfConversation(label(key), signal.clone()));
                            layer.saw(key.clone(), flow, signal.clone(), at);
                        }
                    }
                }
                // Слово о цели рождается на границе УЗЛА — там же, где в живом прогоне.
                if matches!(event, DetectorEvent::Tick { .. }) {
                    if let Some(fold) = fold {
                        for (target, voice) in voiced(&mut layer, fold, idle, at) {
                            said.push(Said::OfTarget(target, voice));
                        }
                    }
                }
            }
            To::Nobody => {}
        }
    }
    said
}

/// Шаг СЕТКИ — как часто закрывается окно, по которому судят приборы. Не «как часто будим»: сроком
/// сна распоряжается носитель ([`Serves::serve`]), а сетка — предмет наблюдения, и её шаг не
/// зависит от того, чем и сколько носитель спит.
const TICK: Duration = Duration::from_millis(200);

/// Нижний предел срока эвикта ключа: даже беспороговым приборам нужно пережить типичный разговор.
const MIN_IDLE: Duration = Duration::from_secs(10);

/// ВЕДУЩИЙ ЦИКЛ — один на оба терминала. Возвращается исходом настройки либо концом источника;
/// живой носитель конца не обещает, и на боевой очереди цикл работает, пока жив процесс.
///
/// Устройство: носитель обслуживает шов ([`Serves::serve`]) до СЛЕДУЮЩЕГО УЗЛА сетки, а всё, что
/// он сказал, шов ([`Interleave`]) переводит в буквы и отдаёт [`Alive::walk`]. Прежде цикл гонял
/// ПАЧКУ пакетов, а тик смотрел после неё — и пакет, перешагнувший узел, доходил до прибора раньше
/// самого узла: детектор видел его раньше закрытия окна, в которое пакет не попал, и относил его
/// байты не к тому окну (§8, дословно).
///
/// МОМЕНТ БЕЗОТВЕТНОГО ИСХОДА — СРОК, о котором просили, а не показание часов. Носитель обязался не
/// возвращаться раньше него; значит срок наступил, и узел, назначенный на него, наступил ровно на
/// сетке. Взятый заново `Instant::now()` был бы моментом, когда нам СЛУЧИЛОСЬ вернуться — он
/// позже узла на величину планировщика и о наблюдении не говорит ничего. Оттого же носитель вправе
/// держать поддельные часы (§8: время есть буква входа, подделать её законно) — и бумажный носитель
/// в `tests/driver.rs` ими и держится, не гоня реальную секунду.
///
/// Цена названа: носитель, обязательство нарушивший, гонит сетку впереди СВОИХ часов — узлов
/// выходит больше, чем у него прошло времени. Это цена нарушителя, не цикла, и на боевой очереди её
/// не бывает: там закон срока исполняется единственным сном внутри `serve`.
///
/// ДЫРА приходит С РАБОТОЙ, то есть раньше срока (носитель её не досыпает): момент — ниже, там, где
/// решает `МОМЕНТ У КАЖДОГО ИСХОДА ОТ НОСИТЕЛЯ`. Момента потери не существует нигде — ядро выбросило
/// сообщения раньше, чем мы позвали приём, и `ENOBUFS` не несёт ни числа потерянных, ни времени.
///
/// ОТКАЗ ТЕРМИНАЛА (`Answered(Err)`) цикл печатает и идёт дальше. Цена у этого ДВОЙНАЯ, и обе
/// половины дорогие:
/// * ядро всё ещё ДЕРЖИТ пакет — мы не ответили удержанному, и разговор стоит, пока очередь не
///   выкинет его по своему сроку;
/// * памятка не уехала, и это не задержка, а ПОВТОР ПОКАЗАНИЯ: фаза кодирует не только положение
///   в вычислении, но и факт «уже сказали» (гейт молчания `Confirmed`/`Released` в
///   `instrument/edge_detect.rs`), а из счётчиков края этот факт не выводится ничем. Следующий
///   пакет прочтёт старую фазу при прежних условиях и выдаст показание второй раз — для `.detect`
///   это дубль в отчёте, для `.act(sever)` второй RST по уже оборванному разговору.
///
/// Повтора вердикта здесь нет НАРОЧНО: сколько раз, с какой паузой и что при исчерпании — решение,
/// которое принимают с замером частоты отказов, а замера нет.
fn drive<C, T, V, H: MarkHome>(chain: Detecting<C, T, H>, certify: bool, voice: &mut V) -> Report
where
    C: Bordered,
    C::Carrier: CanHold + CanRemember,
    // `Bordered::Edge` И край, что отдаёт `carrier.serve(...)`, — ОДИН тип по определению
    // блáнкетного `impl Bordered` (`type Edge = <C::Carrier as Serves>::Edge`), но связаны два
    // ассоциированных пути, и без явного тождества здесь компилятор их не отождествит — только
    // внутри самого `impl`, где равенство и записано, а не в постороннем `drive`.
    C::Carrier: Serves<Edge = <C as Bordered>::Edge>,
    <C::Carrier as Terminal>::Refusal: std::fmt::Debug,
    T: Transport,
    V: Voice<C::Carrier>,
{
    let Detecting {
        carrier: recipe,
        park,
        longest,
        about,
        ..
    } = chain;
    let name = recipe.name();
    // Носитель открывает СЕБЯ: свои предпосылки, свои сокеты. Цикл о них не знает и знать не может
    // — предпосылка носителя есть дело носителя (у WinDivert она другая).
    let mut carrier = match recipe.open() {
        Ok(carrier) => carrier,
        Err(Cause(why)) => return Report::not_started(name, why),
    };

    let idle = longest.saturating_mul(2).max(MIN_IDLE);
    // Семя семьи: те же шаблоны, из которых движок сеет машины, нужны и переигровке — она обязана
    // начать с ТОГО ЖЕ состояния, иначе сверяла бы две разные машины.
    let seeds: Vec<Box<dyn Probe<Wide<T::Wire, C::Edge>>>> = park
        .per_flow
        .iter()
        .map(|probe| probe.clone_box())
        .collect();
    let templates = park.per_flow;
    let mut alive: Alive<C, T> = Alive {
        table: FlowTable::new(idle, move |_flow| {
            Probes(templates.iter().map(|probe| probe.clone_box()).collect())
        }),
        // Приборы КРАЯ живут одним экземпляром на весь движок: их состояние не здесь, а в марке
        // носителя, и копия на ключ была бы копией пустоты.
        at_edge: park.at_edge,
        layer: Layer::new(),
        targets: HashMap::new(),
        tape: Tape::new(),
        certify,
        about,
        idle,
    };
    let mut state = T::State::default();
    // Сетка отмеряется от ПЕРВОГО НАБЛЮДЁННОГО момента, а не от часов цикла. Часы цикла и часы
    // носителя — разные эпохи (записанный провод, стенд, чужая ОС), и сетка, начатая нашими, на
    // первом же пакете носителя из другой эпохи выдала бы миллионы узлов разом: прошлое зажимает
    // шов (`at.max(last)`), будущее не зажимает ничто. До первого наблюдения мерить нечего — и
    // адресовать узлы тоже некому: живых машин ещё нет.
    let mut seam: Option<Interleave> = None;

    loop {
        // О КОНЦЕ СПРАШИВАЮТ ПРЕЖДЕ, ЧЕМ ПРОСИТЬ РАБОТУ. Носитель, у которого её больше не будет,
        // иначе обязан был бы выдумать тишину до срока — и цикл выдал бы узел, которого в его
        // источнике нет. А тишина, которую носитель честно выдержал, наоборот, обязана дойти
        // узлами: спроси о конце ПОСЛЕ неё — и последний узел пропал бы ровно тогда, когда срок
        // тишины совпал с концом сценария. Живая очередь сюда не приходит никогда: `exhausted` у
        // неё ложь по построению — ядро конца не обещает.
        if carrier.exhausted() {
            return Report::finished(name);
        }
        // Срок — не узел, а ПРОСЬБА к носителю: столько ждать, если работы нет. Оттого до первой
        // буквы он берётся у часов цикла, и это законно: часы цикла знают, сколько ждать, и не
        // знают, что наблюдено.
        let until = match &seam {
            Some(seam) => seam.next_node().unwrap_or_else(|| Instant::now() + TICK),
            None => Instant::now() + TICK,
        };
        let mut effects: SmallVec<[Effect; 2]> = SmallVec::new();
        let mut crossed: Option<Instant> = None;

        let outcome = carrier.serve(until, |held, edge| {
            let at = held.at();
            let seen = C::shown(held);
            // Марка — то, что край УЖЕ хранит: памятка ляжет в неё read-modify-write, чужие биты
            // целы. Края нет — писать не во что, и ноль тут значит «нечего перезаписывать».
            let mark = edge.as_ref().map(EdgeView::mark).unwrap_or(0);
            let grid = seam.get_or_insert_with(|| Interleave::started(at, TICK));
            let (moved, letters, whose) = match T::observe(&mut state, parse::read(seen, T::PORT)) {
                Observation::Seen(observed) => {
                    let (moved, letters) = grid.saw((observed.wire, edge), at);
                    (moved, letters, Some((observed.flow, observed.key)))
                }
                // Кадр БЫЛ, а прочесть его не удалось — третья дверь шва, не тишина. Разница
                // видимая: `idle` отдал бы одни узлы, и приборы, судящие по ОТСУТСТВИЮ, сочли бы
                // окно свободным от пропажи; `unread` кладёт в ленту `Opaque { why }`, и на
                // прячущей букве они слепнут (`DetectorEvent::hides_observation`). Момент кадра —
                // не срок: обрезанный кадр приходит С РАБОТОЙ, раньше узла.
                Observation::Unread(why) => {
                    let (moved, letters) = grid.unread(why, at);
                    (moved, letters, None)
                }
                // Не наш кадр — но момент его прихода СЕТКУ ДВИГАЕТ: иначе поток чужого трафика
                // выглядел бы тишиной, и приборы молчания подтверждали бы дроп на живой машине.
                Observation::Foreign => {
                    let (moved, letters) = grid.idle(at);
                    (moved, letters, None)
                }
            };
            *grid = moved;
            let (memo, node) = alive.walk(letters, whose, seen, voice, &mut effects);
            crossed = node;
            // Слово носителю: пакет идёт как шёл, а память — ТЕМ ЖЕ словом (§5: «отпустить и
            // запомнить» неделимо). Разбирать это слово в вердикт — дело носителя: фасад, писавший
            // разбор своей рукой, держал вторую копию таблицы, расходившуюся молча.
            match memo {
                Some(memo) => <C::Carrier as CanRemember>::remember(memo.apply_to(mark), true),
                None => <C::Carrier as CanHold>::release(),
            }
        });

        // Ответ уже прошёл сквозь приборы внутри решения; безответный исход рождает буквы здесь, и
        // рождает их ОДНА дверь шва на исход — гоняет же их тот же `walk`, что и пакет.
        //
        // МОМЕНТ У КАЖДОГО ИСХОДА ОТ НОСИТЕЛЯ: ответ несёт его в `Held::at`, дыра — в самом исходе
        // (`Served::Torn`), тишина — сроком, о котором мы просили и который носитель обязался
        // выждать. Второго владельца часов у цикла нет.
        let sown = match outcome {
            Served::Answered(Ok(_)) => None,
            Served::Answered(Err(refused)) => {
                report!("вердикт не ушёл: {:?}", refused.why);
                None
            }
            Served::Torn(at) => Some(
                seam.get_or_insert_with(|| Interleave::started(at, TICK))
                    .torn(at),
            ),
            // Тишина ДО первого наблюдения сетки не заводит: мерить нечего, и адресовать узлы
            // некому — живых машин ещё нет.
            Served::Idle | Served::Blind => seam.as_mut().map(|grid| grid.idle(until)),
        };
        if let Some((moved, letters)) = sown {
            seam = Some(moved);
            let (_memo, node) = alive.walk(letters, None, &[], voice, &mut effects);
            crossed = node;
        }

        voice.does(&mut carrier, effects);

        // Уборка на границе узла: слово о цели сказано раньше, среди букв (`Alive::walk`).
        if crossed.is_some() {
            alive.forget_evicted();
            alive.certified(&seeds);
        }
    }
}

/// ЖИВОЕ СОСТОЯНИЕ ПРОГОНА — всё, чего касается буква. Отдельной вещью, а не россыпью локальных
/// переменных: букву гоняет ОДНА функция ([`Alive::walk`]), и её девять доводов были бы девятью
/// местами, где их можно передать не в том порядке.
struct Alive<C: Bordered, T: Transport> {
    /// ПРОВОДНЫЕ приборы: копия семьи на ключ, состояние в юзерспейсе.
    table: FlowTable<Probes<Wide<T::Wire, C::Edge>>, Flow>,
    /// КРАЕВЫЕ: один экземпляр на движок, состояние в марке носителя.
    at_edge: Vec<Box<dyn EdgeProbe<Wide<T::Wire, C::Edge>>>>,
    /// Слова разговоров, разложенные по цели: из них рождается слово О ЦЕЛИ.
    layer: Layer<Conversation, Target, Distress>,
    /// Ключ цели на разговор — для сигналов, рождённых узлом сетки (у узла пакета с личностью нет).
    /// Именно КЛЮЧ, а не ярлык: тег `Named`/`Unnamed` нужен слою, а ярлык из ключа выводится.
    targets: HashMap<Flow, TargetKey<Box<str>>>,
    /// Окно ленты: пишется, только когда закон предъявляется — даром лента стоила бы клона слова
    /// провода на каждый пакет.
    tape: Recorded<C, T>,
    certify: bool,
    /// Свёртка слов разговоров в слово о ЦЕЛИ и реакция на него. Живёт ЗДЕСЬ, а не в цикле, потому
    /// что зовётся на закрытии узла — среди букв, а не после них.
    about: Option<(Fold, TargetVoice)>,
    /// Срок, после которого затихший разговор снимается: им же судит и слой.
    idle: Duration,
}

impl<C: Bordered, T: Transport> Alive<C, T> {
    /// ПРОГНАТЬ БУКВЫ ЧЕРЕЗ ПРИБОРЫ. Отдельной функцией, а не телом ветки: буквы приходят из
    /// ЧЕТЫРЁХ мест (пакет, узел сетки, дыра, простой), и четыре копии этого разошлись бы молча —
    /// ровно так `.act` и остался без ленты, дыры и слова о цели.
    ///
    /// АДРЕС выводится из `whose`, а не из ветки цикла: пакет идёт машине СВОЕГО разговора, всё
    /// прочее — каждой живой. У дыры адреса нет по существу (докблок [`FlowTable`] называет
    /// причину), у узла сетки — потому что у времени собеседника не бывает.
    ///
    /// Краевые приборы получают только ПАКЕТ: их предмет — состояние разговора в марке, а марка
    /// приезжает с пакетом; и слово, сказанное ими на узле, некому было бы адресовать.
    ///
    /// Наружу — памятка (её кладёт домой носитель тем же словом, что и вердикт) и момент
    /// ПОСЛЕДНЕГО закрытого узла, если он тут был: по нему цикл судит, пора ли говорить о цели.
    fn walk<V: Voice<C::Carrier>>(
        &mut self,
        letters: Vec<DetectorEvent<Wide<T::Wire, C::Edge>>>,
        whose: Option<(Flow, TargetKey<Box<str>>)>,
        seen: &[u8],
        voice: &mut V,
        effects: &mut SmallVec<[Effect; 2]>,
    ) -> (Option<Memo>, Option<Instant>) {
        let mut memo: Option<Memo> = None;
        let mut crossed: Option<Instant> = None;
        for letter in letters {
            let at = letter.at();
            // УЛИКА ЕДЕТ ВМЕСТЕ С АДРЕСОМ. Байты — только у буквы, у которой есть чей: узел сетки и
            // дыра адресованы КАЖДОЙ живой машине, и дай им байты пакета этого оборота — акт,
            // рождённый словом ЧУЖОГО разговора, оборвал бы разговор, привёзший пакет. Тот не
            // бедствовал вовсе, а слово необратимо (§1). Прежде закон держался тем, что штатные
            // приборы на узле молчат, — то есть совпадением; `own(…)` его нарушал.
            let (said, evidence): (
                Vec<(TargetKey<Box<str>>, Flow, SmallVec<[Distress; 2]>)>,
                &[u8],
            ) = match (&letter, &whose) {
                (DetectorEvent::Packet { input, .. }, Some((flow, key))) => {
                    self.recorded(
                        To::One(Whose {
                            flow: *flow,
                            target: key.clone(),
                        }),
                        &letter,
                    );
                    let (mut signals, ()) = self.table.process(*flow, input, at);
                    for probe in self.at_edge.iter_mut() {
                        let (remembered, spoken) = probe.observe(&letter);
                        // Памятка одна на пакет: марка одна, записать в неё можно ровно одно
                        // слово. Двух краевых приборов в цепочке ТИП НЕ ЗАПРЕЩАЕТ (`.detect`
                        // их просто копит) — тогда побеждает сказавший последним. Цена
                        // названа, а не спрятана: ни одна цепочка парка двух краевых сегодня
                        // не ставит, а гейт на это — отдельное решение, не попутное.
                        memo = remembered.or(memo);
                        signals.extend(spoken);
                    }
                    self.targets.insert(*flow, key.clone());
                    (vec![(key.clone(), *flow, signals)], seen)
                }
                // Буква без адреса — каждой живой машине. В ленту она ложится РАЗ, а фанаут
                // делает тот, кто её читает: перегенерируй её на переигровке — и та позвала бы
                // часы, то есть впустила бы в машину скрытый вход, который сама и проверяет.
                _ => {
                    self.recorded(To::Each, &letter);
                    let heard = self
                        .table
                        .each(letter.clone())
                        .into_iter()
                        .filter_map(|(flow, (signals, ()))| {
                            self.targets
                                .get(&flow)
                                .map(|key| (key.clone(), flow, signals))
                        })
                        .collect();
                    (heard, &[][..])
                }
            };
            for (key, flow, signals) in said {
                let named = label(&key);
                for signal in signals {
                    effects.extend(voice.hears(&named, signal.clone(), evidence));
                    // Слой копится РАДИ копредела и больше ни для чего: нет свёртки — некому его
                    // читать, и наполнять его значило бы платить за слово, которое не родится.
                    if self.about.is_some() {
                        self.layer.saw(key.clone(), flow, signal, at);
                    }
                }
            }
            // Слово О ЦЕЛИ — на КАЖДОМ закрытом узле, здесь же, где буквы. Не в конце оборота:
            // пакет штатно перешагивает несколько узлов, и слово, сказанное раз за оборот, зависело
            // бы от того, как носитель сбил работу в пачки, — то есть от входа вне алфавита машины,
            // ровно того, что ловит §10. Зеркало переигровки (`replay`) зовёт свёртку так же.
            if matches!(letter, DetectorEvent::Tick { .. }) {
                crossed = Some(at);
                self.spoke_of_targets(at);
            }
        }
        (memo, crossed)
    }

    /// Свести слова разговоров в слово о ЦЕЛИ и сказать его. Нет свёртки — нет и слова: копредел
    /// объявляет потребитель (`.about`), а не движок.
    fn spoke_of_targets(&mut self, at: Instant) {
        let Alive {
            layer, about, idle, ..
        } = self;
        let Some((fold, say)) = about else {
            return;
        };
        for (target, said) in voiced(layer, fold, *idle, at) {
            say(&target, said);
        }
    }

    /// Записать букву в ленту — с адресом, который знает только тот, кто её родил: позже его взять
    /// неоткуда, словарь провода потока не несёт. Одной дверью на все четыре буквы: два места
    /// записи разошлись бы, и первым разошедшимся оказалась бы дыра, которую и записывать-то стали
    /// только сегодня.
    fn recorded(&mut self, to: To<Whose>, letter: &DetectorEvent<Wide<T::Wire, C::Edge>>) {
        if self.certify {
            self.tape.record([TapeLetter::Event {
                to,
                event: letter.clone(),
            }]);
        }
    }

    /// Имя уходит вместе с ключом: зеркалим эвикт таблицы, чтобы карта не росла.
    fn forget_evicted(&mut self) {
        let Alive { targets, table, .. } = self;
        targets.retain(|flow, _| table.get(flow).is_some());
    }

    /// ВОСЬМОЙ ЗАКОН на живой ленте (§10, §12.3): окно набралось — пере-подаём его свежей семье
    /// дважды и сверяем сказанное. Свидетель предъявляется тут же: молча держать закон значит не
    /// держать его вовсе.
    fn certified(&mut self, seeds: &[Box<dyn Probe<Wide<T::Wire, C::Edge>>>]) {
        if !self.certify || self.tape.len() < TAPE_WINDOW {
            return;
        }
        let fold = self.about.as_ref().map(|(fold, _say)| fold);
        let idle = self.idle;
        let verdict = replays(&self.tape, |mode, letters| {
            replay::<Wide<T::Wire, C::Edge>>(seeds, fold, idle, mode, letters)
        });
        match verdict {
            Replayed::Reproduced => {
                report!("§10: окно из {} букв воспроизведено", self.tape.len())
            }
            Replayed::Unstable { at } => report!(
                "§10 НАРУШЕН: прогоны разошлись на исходе {at} — у машины есть вход вне её алфавита"
            ),
            Replayed::NoTape => report!("§10: судить не о чем — лента пуста"),
            // Окно из одних узлов сетки без живых машин: согласие двух молчаний свидетельством не
            // считается — под ним прошла бы любая порча.
            Replayed::Silent => report!(
                "§10: окно из {} букв прошло молча — машине нечего было сказать, свидетельства нет",
                self.tape.len()
            ),
        }
        // Окно закрыто: следующее пишется с чистого места, иначе лента росла бы вечно.
        self.tape = Tape::new();
    }
}

/// Исход движка. Два и только два: настройка не состоялась либо источник кончился. Работающий цикл
/// его не возвращает — на боевой очереди он не кончается вовсе.
pub struct Report {
    name: String,
    why: Option<String>,
}

impl Report {
    fn not_started(name: String, why: String) -> Report {
        Report {
            name,
            why: Some(why),
        }
    }

    /// Носитель сказал, что работы больше не будет никогда, и цикл вышел. Отдельно от «не
    /// открылся» (§7: «не смотрели» ≠ «смотрели и кончилось»).
    fn finished(name: String) -> Report {
        Report { name, why: None }
    }

    /// Почему запуск не состоялся; `None` — состоялся. Значение, а не печать: тот же закон, по
    /// которому `Refused` вытеснил `let _ =` — отказ мира есть знание.
    pub fn why(&self) -> Option<&str> {
        self.why.as_deref()
    }
}

impl std::process::Termination for Report {
    fn report(self) -> std::process::ExitCode {
        match self.why {
            None => std::process::ExitCode::SUCCESS,
            Some(why) => {
                eprintln!("[reflex] {} не открылся: {why}", self.name);
                std::process::ExitCode::FAILURE
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Край, ничего не ведущий: стенды ниже проверяют ПЕРЕИГРОВКУ, а не край, и настоящий занял бы
    /// в них место предмета. Свой, а не носителя: тест фасада, знающий тип конкретного носителя,
    /// проверял бы заодно и его — а фасад ровно тем и ценен, что носителя не знает.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Blank;

    impl reflex_core::edge::EdgeView for Blank {
        fn down_packets(&self) -> Option<u64> {
            None
        }
        fn up_packets(&self) -> Option<u64> {
            None
        }
        fn down_bytes(&self) -> Option<u64> {
            None
        }
        fn up_bytes(&self) -> Option<u64> {
            None
        }
        fn idle(&self) -> Option<Duration> {
            None
        }
        fn age(&self) -> Option<Duration> {
            None
        }
        fn mark(&self) -> u32 {
            0
        }
    }

    /// Широкое слово стендов: провод соединения над пустым краем.
    type Word = Wide<Reading, Blank>;

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

    impl Probe<Word> for Steady {
        fn observe(&mut self, event: &DetectorEvent<Word>) -> SmallVec<[Distress; 2]> {
            match event {
                DetectorEvent::Packet { .. } => smallvec![Distress::NoBytes],
                _ => smallvec![],
            }
        }

        fn clone_box(&self) -> Box<dyn Probe<Word>> {
            Box::new(self.clone())
        }
    }

    /// Прибор со СКРЫТЫМ входом: величину берёт из счётчика, живущего вне его состояния. Ровно то,
    /// что восьмой закон обязан ловить, — машина читает то, чего нет в её алфавите.
    #[derive(Clone)]
    struct Peeking;

    static PEEKED: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    impl Probe<Word> for Peeking {
        fn observe(&mut self, event: &DetectorEvent<Word>) -> SmallVec<[Distress; 2]> {
            match event {
                DetectorEvent::Packet { .. } => {
                    let ms = PEEKED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    smallvec![Distress::Silence { ms }]
                }
                _ => smallvec![],
            }
        }

        fn clone_box(&self) -> Box<dyn Probe<Word>> {
            Box::new(self.clone())
        }
    }

    /// Окно ленты из двух разговоров одной цели и узла сетки между ними.
    fn window(start: Instant) -> Tape<Word, Whose, ()> {
        let target = TargetKey::Named("rutracker.org".into());
        let mut tape: Tape<Word, Whose, ()> = Tape::new();
        for (n, offset) in [(1u32, 0u64), (2, 10)] {
            tape.record([TapeLetter::Event {
                to: To::One(Whose {
                    flow: flow(n),
                    target: target.clone(),
                }),
                event: DetectorEvent::Packet {
                    // Край в записи есть, но пуст: стенд проверяет ПЕРЕИГРОВКУ, а не край.
                    input: (Reading::Tcp(SeenTcp::sent(100)), None),
                    at: start + Duration::from_millis(offset),
                },
            }]);
        }
        tape.record([TapeLetter::Event {
            to: To::Each,
            event: DetectorEvent::Tick {
                // Номер УЗЛА, а не ноль: первый узел двухсотмиллисекундной сетки от `start`.
                // Подделать его нулём значило бы записать в ленту сетку, которой нет, — тот же
                // довод, что снял ноль из `FlowTable`.
                node: 1,
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
        let seeds: Vec<Box<dyn Probe<Word>>> = vec![Box::new(Steady)];

        let verdict = replays(&tape, |mode, letters| {
            replay::<Word>(&seeds, None, Duration::from_secs(10), mode, letters)
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
        let seeds: Vec<Box<dyn Probe<Word>>> = vec![Box::new(Peeking)];

        let verdict = replays(&tape, |mode, letters| {
            replay::<Word>(&seeds, None, Duration::from_secs(10), mode, letters)
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
        let seeds: Vec<Box<dyn Probe<Word>>> = vec![Box::new(Steady)];
        let fold: Fold = Box::new(|words: &[&Distress]| {
            words
                .iter()
                .all(|distress| matches!(distress, Distress::NoBytes))
                .then_some(Distress::NoBytes)
        });

        let said = replay::<Word>(
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
            replays(&tape, |mode, letters| replay::<Word>(
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
