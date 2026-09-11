// Обещание имени в докблоке ([`Name`]) держит компилятор, не читатель: битая ссылка — ошибка сборки
// документации, а не молчаливое предупреждение, которое ловят люди постфактум. Ссылка `Edged` тут
// была ровно таким случаем (замечена 10.09.2026, тем же днём, что и `own_at_edge` рядом) — деny
// делает шестой и седьмой такой дрейф последним.
#![deny(rustdoc::broken_intra_doc_links)]

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

use std::collections::{HashMap, VecDeque};
use std::marker::PhantomData;
use std::time::{Duration, Instant};

use reflex_core::backend::Sink;
use reflex_core::capability::{CanAsk, CanHold, CanInject, CanRemember};
use reflex_core::certify::replays::replays;
/// Вердикт восьмого закона (§10) — публичен, а не внутреннее имя: он стоит в подписи
/// [`Report::certified`], и без него исход прогона нельзя ни назвать, ни разобрать, не притащив
/// `reflex-core` второй зависимостью. Дверь у фасада одна — значит и типы её подписи проходят
/// через неё.
pub use reflex_core::certify::replays::Replayed;
use reflex_core::colimit::Layer;
use reflex_core::word::Word;
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
use reflex_engine::parse::{self};
use reflex_engine::row::{host_of, keyed, Naming, TargetKey};
use reflex_engine::talk::Talks;
use reflex_engine::Addr;
/// АДРЕС РАЗГОВОРА — публичен, потому что стоит публичным полем в [`Whom`] и [`Note`].
///
/// Реэкспорт, а не `use`: без него потребитель, взявшийся различать разговоры одной цели, обязан
/// назвать тип, которого фасад ему не дал, — то есть взять вторую зависимость (`reflex-engine`)
/// ради имени поля, уже лежащего у него в руках. Это ломало бы закон фасада «потребитель зависит
/// от ОДНОГО крейта» тише всего: цепочка собирается, а `let _: ??? = whom.flow` написать нечем.
pub use reflex_engine::Flow;
use reflex_instrument::edge::{Layout, Memo};
use reflex_instrument::edge_detect::EdgeSilence;
use reflex_instrument::poison::DnsPoisonInstrument;
use reflex_instrument::detect::{ChokedInstrument, RstInstrument, ThrottledInstrument};
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
pub mod pcap;
// ТРАНСПОРТ QUIC — третий рядом с TCP и UDP. За фичей: тянет `ring`, см. манифест.
#[cfg(feature = "quic")]
mod quic;
#[cfg(feature = "quic")]
pub use quic::{Quic, QuicState};
// СОЧИНЁННЫЙ ПРОВОД — третий носитель: сценарий вместо мира. В умолчании, см. манифест.
#[cfg(feature = "scenario")]
pub mod scenario;
// ЗАМЫКАНИЕ КОНТУРА — черновая дверь за фичей, каноном не объявленная. Цена в манифесте.
#[cfg(feature = "telling")]
pub mod telling;
#[cfg(unix)]
pub use nfqueue::{LocalNfqueue, Nfqueue, NfqueueCarrier, INJECT_MARK};
/// Дверь записи стоит в КОРНЕ рядом с [`engine`]: `reflex::pcap("файл")`. Имя делят модуль и
/// функция — Rust держит их в разных пространствах, и это ровно тот случай, ради которого
/// пространства и разведены: предмет один, а `reflex::pcap::Recording` рядом с `reflex::pcap(…)`
/// читается как одно имя в двух ролях, а не как два разных.
pub use pcap::{pcap, Recording};

/// Причина, по которой кадр не прочитан. Реэкспорт, а не внутреннее имя: она стоит в подписи
/// [`Transport::observe`], и без неё свой транспорт снаружи не написать — а `Truncated` из неё
/// решает, ослепнут приборы на этой букве или нет (`DetectorEvent::hides_observation`).
pub use reflex_core::parse::Unread;

/// Разобранный кадр — реэкспорт по той же причине, что и [`Unread`]: он стоит в подписи
/// [`Transport::observe`], и без него свой транспорт снаружи НЕ НАПИСАТЬ. Трейт при этом публичен —
/// то есть дверь была открыта, а ключ от неё лежал внутри. Нашлось при попытке поверить свой же
/// транспорт: тест не мог назвать тип, который трейт требует.
pub use reflex_engine::parse::{Datagram, Read};


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
/// носитель: несостоявшийся запуск обязан быть значением (`Report::not_started`, приватный
/// конструктор — не ссылка: значение видит потребитель, конструктор не часть контракта), а не
/// паникой на первой строке потребительской цепочки.
pub fn engine<C: IntoCarrier>(carrier: C) -> Engine<C> {
    Engine { carrier }
}

// ─── Транспорт: ось `.from` ───────────────────────────────────────────────────────────────────

/// Наблюдение из кадра: ключ разговора, имя цели (для реакции) и широкое слово провода.
///
/// Поля ПУБЛИЧНЫ, и это не послабление: `Observed` есть ВЫХОД [`Transport::observe`], а трейт
/// публичен — с приватными полями его нельзя было реализовать снаружи вовсе, то есть ось `.from`
/// объявлялась расширяемой и расширяться не давала. Нашлось при поверке собственного транспорта:
/// тест не мог ни построить наблюдение, ни прочесть построенное.
pub struct Observed<W> {
    pub flow: Flow,
    /// Ключ цели — расслоение §4 (`Named | Unnamed`). Им цель ключуется в слое; ярлык для человека
    /// получается из него [`label`], а не наоборот: обратный ход терял бы тег.
    pub key: TargetKey<Box<str>>,
    pub wire: W,
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

/// Детектор СБРОСА: путь ломают снаружи. Ось «отдала ли цель байт до сброса» отделяет перехват от
/// законного прощания, и различает их сам прибор — двери на это не нужно.
///
/// Дверь заведена 11.09.2026, прибор существовал задолго до неё. Что до потребителя он не доходил,
/// нашлось ПРОГОНОМ у потребителя, а не чтением у нас: боевая цепочка, собранная из всего, что
/// предлагал парк, молчала на записи, где сброс ЕСТЬ. Слово `Distress::Rst` при этом в словаре
/// стояло — то есть фасад умел про сброс СКАЗАТЬ и не умел его УВИДЕТЬ, а `match` у потребителя
/// собирался с веткой, которой некому было сработать.
pub struct Rst;

impl Rst {
    /// Сброс, пришедший на разговор.
    pub fn seen() -> Rst {
        Rst
    }
}

/// Детектор ТРОТТЛИНГА: скорость ниже доказанной. Единственный в парке, чьё показание — ВЕЛИЧИНА
/// (`Distress::Throttled { bps }`), а не факт: «столько байт в секунду против стольких доказанных».
///
/// `window` — на чём мерить скорость. Окно живёт здесь, а не константой прибора, потому что цена
/// ошибки несимметрична: узкое окно кричит на всякой паузе TCP, широкое просыпает медленную
/// удавку. Кто мерит — тот и знает свой трафик.
pub struct Throttled {
    window: Duration,
}

impl Throttled {
    /// Окно, на котором считается скорость.
    pub fn over(window: Duration) -> Throttled {
        Throttled { window }
    }
}

/// Детектор ЗАХЛЁБЫВАНИЯ: клиент просит, цель не отдаёт, планки не доказывала.
///
/// От [`Silence`] отличается требованием ДОКАЗАННОГО СПРОСА — без просьбы молчание законно, и
/// молчащий сервер, которого никто не спрашивал, здесь не бедствует. Оттого и два довода:
/// `ceiling` — планка, которую цель когда-то показала (ниже неё есть о чём говорить), `after` —
/// сколько ждать, прежде чем назвать это бедой.
pub struct Choked {
    ceiling: u64,
    after: Duration,
}

impl Choked {
    /// Планка в байтах в секунду, которую цель доказала, и терпение до вердикта.
    pub fn after(ceiling: u64, after: Duration) -> Choked {
        Choked { ceiling, after }
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
pub trait Probe<W, S>: Send {
    /// Слова прибора за этот шаг (пусто — сказать нечего). `S` — СЛОВАРЬ ЦЕПОЧКИ: парк говорит
    /// `Distress`, чужой прибор — своё, и второе не обязано выражаться через первое.
    fn observe(&mut self, event: &DetectorEvent<W>) -> SmallVec<[S; 2]>;
    /// Свежая копия шаблона — `FlowTable` заводит прибор на каждый ключ.
    fn clone_box(&self) -> Box<dyn Probe<W, S>>;
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

impl<W, N, M, S, P> Probe<W, S> for Lift<M, N>
where
    W: 'static,
    N: Reads<W> + 'static,
    S: From<P> + 'static,
    P: 'static,
    M: Mealy<In = DetectorEvent<N>, Out = SmallVec<[P; 2]>> + Copy + Send + 'static,
{
    fn observe(&mut self, event: &DetectorEvent<W>) -> SmallVec<[S; 2]> {
        match narrow::<W, N>(event) {
            Some(event) => {
                let (machine, signals, _log) = self.machine.step(event);
                self.machine = machine;
                signals.into_iter().map(S::from).collect()
            }
            None => SmallVec::new(),
        }
    }

    fn clone_box(&self) -> Box<dyn Probe<W, S>> {
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
pub trait EdgeProbe<W, S>: Send {
    fn observe(&mut self, event: &DetectorEvent<W>) -> (Option<Memo>, SmallVec<[S; 2]>);
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
pub enum Placed<W, S> {
    /// По разговору: копия шаблона на ключ, тики, состояние в юзерспейсе.
    PerFlow(Box<dyn Probe<W, S>>),
    /// На крае: один экземпляр, состояние в марке ядра, тиков не просит.
    AtEdge(Box<dyn EdgeProbe<W, S>>),
}

/// Подъём КРАЕВОЙ машины в прибор края: сужение то же (§4, [`Reads`]), но выход двойной — беда и
/// памятка. Копии на ключ не делает: экземпляр один, состояние в марке.
struct AtEdge<M, N> {
    machine: M,
    alphabet: PhantomData<fn() -> N>,
}

impl<W, N, M, S, P> EdgeProbe<W, S> for AtEdge<M, N>
where
    W: 'static,
    N: Reads<W> + 'static,
    S: From<P> + 'static,
    P: 'static,
    M: Mealy<In = DetectorEvent<N>, Out = (Option<Memo>, SmallVec<[P; 2]>)> + Copy + Send + 'static,
{
    fn observe(&mut self, event: &DetectorEvent<W>) -> (Option<Memo>, SmallVec<[S; 2]>) {
        match narrow::<W, N>(event) {
            Some(event) => {
                let (machine, (memo, said), _log) = self.machine.step(event);
                self.machine = machine;
                (memo, said.into_iter().map(S::from).collect())
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
    /// Слово, которым говорит ЭТОТ прибор. Парк говорит `Distress`, чужой прибор — своё; цепочка
    /// принимает первое как свой словарь, а следующие поднимает в него через `From`.
    type Word;

    /// Пишет ли прибор марку. Объявляет САМ прибор, как и дом (`place`).
    type Home: MarkHome;

    /// Куда прибор встаёт. `layout` — раскладка НАШИХ битов марки, параметр цепочки: краевой прибор
    /// пишет под ней состояние, проводной её не смотрит. Отдаётся всем, потому что дом объявляет
    /// прибор, а не спрашивающий: спроси фасад «краевой ли ты» отдельным методом — и ответ разошёлся
    /// бы с тем, что прибор вернул.
    #[doc(hidden)]
    fn place(self, layout: Layout) -> Placed<W, Self::Word>;
    /// Временно́е окно прибора (ноль у беспороговых) — по нему движок выбирает срок эвикта ключа.
    #[doc(hidden)]
    fn window(&self) -> Duration {
        Duration::ZERO
    }
}

/// Собрать прибор-машину в лифт над `W`.
fn lift<W, N, M, S, P>(machine: M) -> Box<dyn Probe<W, S>>
where
    W: 'static,
    N: Reads<W> + 'static,
    S: From<P> + 'static,
    P: 'static,
    M: Mealy<In = DetectorEvent<N>, Out = SmallVec<[P; 2]>> + Copy + Send + 'static,
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
    type Word = Distress;
    type Home = MarkWriter;
    fn place(self, layout: Layout) -> Placed<Wide<Reading, E>, Distress> {
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
    type Word = Distress;
    type Home = MarkSilent;
    fn place(self, _layout: Layout) -> Placed<Wide<Reading, E>, Distress> {
        Placed::PerFlow(lift::<Wide<Reading, E>, Seen, _, Distress, Distress>(
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
    type Word = Distress;
    type Home = MarkWriter;
    fn place(self, layout: Layout) -> Placed<Wide<Reading, E>, Distress> {
        Placed::AtEdge(Box::new(AtEdge {
            machine: EdgeSilence::<E>::new(BLACKHOLE_WINDOW, layout),
            alphabet: PhantomData,
        }))
    }
    fn window(&self) -> Duration {
        BLACKHOLE_WINDOW
    }
}

/// Сброс живёт В ПРОВОДЕ: улика — флаг `RST` в заголовке, а счётчики края флагов не хранят.
impl<E: Clone + 'static> IntoProbe<Wide<Reading, E>> for Rst {
    type Word = Distress;
    type Home = MarkSilent;
    fn place(self, _layout: Layout) -> Placed<Wide<Reading, E>, Distress> {
        Placed::PerFlow(lift::<Wide<Reading, E>, SeenTcp, _, Distress, Distress>(
            RstInstrument::new(),
        ))
    }
}

/// Троттлинг живёт В ПРОВОДЕ: показание — величина, считанная по окну, и окно это НАШЕ, а не
/// ядерное. Край даёт байты нарастающим итогом, но не помнит, сколько их было окно назад.
impl<E: Clone + 'static> IntoProbe<Wide<Reading, E>> for Throttled {
    type Word = Distress;
    type Home = MarkSilent;
    fn place(self, _layout: Layout) -> Placed<Wide<Reading, E>, Distress> {
        Placed::PerFlow(lift::<Wide<Reading, E>, SeenTcp, _, Distress, Distress>(
            ThrottledInstrument::over(self.window),
        ))
    }
    fn window(&self) -> Duration {
        self.window
    }
}

/// Захлёбывание живёт В ПРОВОДЕ по той же причине, что и троттлинг: предмет — СПРОС клиента против
/// отдачи цели, а спрос виден просьбами в проводе, не счётчиком края.
impl<E: Clone + 'static> IntoProbe<Wide<Reading, E>> for Choked {
    type Word = Distress;
    type Home = MarkSilent;
    fn place(self, _layout: Layout) -> Placed<Wide<Reading, E>, Distress> {
        Placed::PerFlow(lift::<Wide<Reading, E>, Seen, _, Distress, Distress>(
            ChokedInstrument::after(self.ceiling, self.after),
        ))
    }
    fn window(&self) -> Duration {
        self.after
    }
}

/// Отравление DNS — В ПРОВОДЕ: предмет его СОДЕРЖИМОЕ ответа (инжект `NXDOMAIN`), а край
/// содержимого не читает вовсе.
impl<E: Clone + 'static> IntoProbe<Wide<DnsMessage, E>> for DnsPoison {
    type Word = Distress;
    type Home = MarkSilent;
    fn place(self, _layout: Layout) -> Placed<Wide<DnsMessage, E>, Distress> {
        Placed::PerFlow(lift::<Wide<DnsMessage, E>, DnsMessage, _, Distress, Distress>(
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
pub fn own<N, M, S>(machine: M) -> Own<M, N>
where
    M: Mealy<In = DetectorEvent<N>, Out = SmallVec<[S; 2]>> + Copy + Send + 'static,
{
    Own {
        machine,
        alphabet: PhantomData,
    }
}

/// Свой прибор живёт ПО РАЗГОВОРУ: он держит состояние в себе, движок сеет копию на ключ. Читать
/// [`reflex_instrument::edge_word::Edged`] эта дверь не умеет — машина получает то, что видит
/// `Mealy`, и только. Вторая дверь для чтения края (черновое имя было `own_at_edge`) не построена;
/// называть несуществующее имя ссылкой — ровно та ошибка докблока, от которой чинит эта правка.
impl<W, N, M, S> IntoProbe<W> for Own<M, N>
where
    W: 'static,
    N: Reads<W> + 'static,
    S: 'static,
    M: Mealy<In = DetectorEvent<N>, Out = SmallVec<[S; 2]>> + Copy + Send + 'static,
{
    type Home = MarkSilent;
    type Word = S;
    fn place(self, _layout: Layout) -> Placed<W, S> {
        Placed::PerFlow(lift::<W, N, M, S, S>(self.machine))
    }
}

/// Поднять слово прибора в словарь цепочки. Нужна отдельная обёртка, а не `From` на месте: прибор
/// уже упакован в `Box<dyn Probe>`, и его слово не переписать иначе как ещё одним слоем.
struct Raise<P>(P);

impl<W, S, Q> Probe<W, S> for Raise<Box<dyn Probe<W, Q>>>
where
    S: From<Q> + 'static,
    Q: 'static,
    W: 'static,
{
    fn observe(&mut self, event: &DetectorEvent<W>) -> SmallVec<[S; 2]> {
        self.0.observe(event).into_iter().map(S::from).collect()
    }

    fn clone_box(&self) -> Box<dyn Probe<W, S>> {
        Box::new(Raise::<Box<dyn Probe<W, Q>>>(self.0.clone_box()))
    }
}

impl<W, S, Q> EdgeProbe<W, S> for Raise<Box<dyn EdgeProbe<W, Q>>>
where
    S: From<Q> + 'static,
    Q: 'static,
    W: 'static,
{
    fn observe(&mut self, event: &DetectorEvent<W>) -> (Option<Memo>, SmallVec<[S; 2]>) {
        let (memo, said) = self.0.observe(event);
        (memo, said.into_iter().map(S::from).collect())
    }
}

/// Приборы разговора, гоняемые ВМЕСТЕ над одним словом провода. Пакет и тик фанаутятся в каждый,
/// слова сливаются в ОДИН словарь цепочки `S`: парк вкладывается в него через `From`, чужой прибор
/// говорит на нём прямо. Один словарь — потому что одна `FlowTable`, один слой целей и одна
/// свёртка; два словаря порвали бы их надвое.
struct Probes<W, S>(Vec<Box<dyn Probe<W, S>>>);

impl<W: Clone + 'static, S: Word + 'static> Mealy for Probes<W, S> {
    type In = DetectorEvent<W>;
    type Out = SmallVec<[S; 2]>;
    type Log = ();

    fn step(mut self, event: Self::In) -> (Self, Self::Out, ()) {
        let mut said: SmallVec<[S; 2]> = SmallVec::new();
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
    pub fn detect<P>(self, detector: P) -> Detecting<C, T, P::Home, P::Word>
    where
        P: IntoProbe<Wide<T::Wire, C::Edge>>,
        P::Word: 'static,
    {
        let mut park = Park::new();
        let longest = detector.window();
        park.add(detector.place(self.carrier.layout()));
        Detecting {
            home: PhantomData,
            carrier: self.carrier,
            park,
            longest,
            about: None,
            #[cfg(feature = "telling")]
            telling: None,
            transport: PhantomData,
        }
    }
}

/// Свёртка слов о разговорах в слово о ЦЕЛИ — приходит от потребителя ЗНАЧЕНИЕМ, как приходит свой
/// автомат в `own(…)`. Какое слово рождается («молчат все», «молчит доля», «молчит хоть один») —
/// описание угрозы, а не механики: фреймворк называет копредел, не угрозу.
///
/// Свёртка видит МНОЖЕСТВО последних слов: порядок ей не показан, кратность сняло хранилище.
/// Свёртка слов разговоров в слово о цели. Словарь тот же `S`: копредел (§4) живёт над
/// ОБЛАСТЬЮ, а не над словом, и смена словаря его не касается.
pub type Fold<S = Distress> = Box<dyn Fn(&[&S]) -> Option<S> + Send>;

/// Реакция на слово о ЦЕЛИ. Отдельна от реакции на слово о разговоре: области разные, и §5 держит
/// их раздельно типом.
pub type TargetVoice<S = Distress> = Box<dyn FnMut(&str, Voiced<S>) + Send>;

/// Приборы цепочки, разложенные ПО ДОМУ состояния. Два списка, а не один с тегом: петля гонит их
/// по-разному, и «род» тут не пометка, а разная механика — проводные сеются по ключу и будятся
/// тиками, краевой живёт одним экземпляром и пишет марку.
struct Park<W, S> {
    per_flow: Vec<Box<dyn Probe<W, S>>>,
    at_edge: Vec<Box<dyn EdgeProbe<W, S>>>,
}

impl<W, S> Park<W, S> {
    fn new() -> Park<W, S> {
        Park {
            per_flow: Vec::new(),
            at_edge: Vec::new(),
        }
    }

    /// Поставить прибор в его дом — тот, который он сам назвал, подняв его слово в словарь
    /// цепочки. Подъём тут, а не у прибора: прибор говорит СВОЁ, цепочка сводит сказанное к одному.
    fn add<Q: 'static>(&mut self, placed: Placed<W, Q>)
    where
        S: From<Q> + 'static,
        W: 'static,
    {
        match placed {
            Placed::PerFlow(probe) => self
                .per_flow
                .push(Box::new(Raise::<Box<dyn Probe<W, Q>>>(probe))),
            Placed::AtEdge(probe) => self
                .at_edge
                .push(Box::new(Raise::<Box<dyn EdgeProbe<W, Q>>>(probe))),
        }
    }
}

/// Детекторы копятся — можно добавить ещё или перейти к реакции.
pub struct Detecting<C: Bordered, T: Transport, H: MarkHome = MarkSilent, S = Distress> {
    home: PhantomData<fn() -> H>,
    carrier: C,
    park: Park<Wide<T::Wire, C::Edge>, S>,
    longest: Duration,
    about: Option<(Fold<S>, TargetVoice<S>)>,
    /// Ручка внеполосной двери, если её просили. `None` — не просили: контур разомкнут, и это
    /// обычное состояние наблюдателя.
    #[cfg(feature = "telling")]
    telling: Option<crate::telling::Telling>,
    transport: PhantomData<fn() -> T>,
}

impl<C: Bordered, T: Transport, H: MarkHome, S> Detecting<C, T, H, S> {
    /// Тело установки, общее обеим дверям: дом меняется ТИПОМ, работа одна.
    fn add<P, H2: MarkHome>(mut self, detector: P) -> Detecting<C, T, H2, S>
    where
        P: IntoProbe<Wide<T::Wire, C::Edge>>,
        S: From<P::Word> + 'static,
        P::Word: 'static,
    {
        self.longest = self.longest.max(detector.window());
        let placed = detector.place(self.carrier.layout());
        self.park.add(placed);
        Detecting {
            home: PhantomData,
            carrier: self.carrier,
            park: self.park,
            longest: self.longest,
            about: self.about,
            #[cfg(feature = "telling")]
            telling: self.telling,
            transport: PhantomData,
        }
    }

    /// ДВЕРЬ ВНЕПОЛОСНОГО ЗНАНИЯ (черновая, за фичей `telling`). Ручка копируется и уезжает в
    /// чужую нить; движок раз в оборот забирает положенное и кладёт решение в дом КЛЮЧА, откуда
    /// оно читается вердиктом СЛЕДУЮЩИХ пакетов той же цели.
    ///
    /// Область марки под решение объявляется потребителем и обязана НЕ ПЕРЕСЕКАТЬСЯ с областью
    /// приборов — проверка стоит здесь, при постройке, а не на первой записи: пересечение значило
    /// бы, что два писателя затирают друг друга, и узналось бы это поведением сети.
    #[cfg(feature = "telling")]
    pub fn telling(mut self, telling: crate::telling::Telling) -> Detecting<C, T, H, S> {
        self.telling = Some(telling);
        self
    }
}

impl<C: Bordered, T: Transport, S> Detecting<C, T, MarkSilent, S> {
    /// Ещё прибор поверх — они гоняются ВМЕСТЕ над одним проводом. Писателя марки пока нет, потому
    /// принимается ЛЮБОЙ прибор; его дом становится домом цепочки.
    pub fn detect<P>(self, detector: P) -> Detecting<C, T, P::Home, S>
    where
        P: IntoProbe<Wide<T::Wire, C::Edge>>,
        S: From<P::Word> + 'static,
        P::Word: 'static,
    {
        self.add::<P, P::Home>(detector)
    }
}

impl<C: Bordered, T: Transport, S> Detecting<C, T, MarkWriter, S> {
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
    pub fn detect<P>(self, detector: P) -> Detecting<C, T, MarkWriter, S>
    where
        P: IntoProbe<Wide<T::Wire, C::Edge>, Home = MarkSilent>,
        S: From<P::Word> + 'static,
        P::Word: 'static,
    {
        self.add::<P, MarkWriter>(detector)
    }
}

impl<C: Bordered, T: Transport, H: MarkHome, S> Detecting<C, T, H, S> {
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
        fold: impl Fn(&[&S]) -> Option<S> + Send + 'static,
    ) -> Folding<C, T, H, S> {
        Folding {
            detecting: self,
            fold: Box::new(fold),
        }
    }

    /// НАБЛЮДАТЬ: реакция на срабатывание, без вмешательства. `target` — имя цели, `distress` — что
    /// случилось. Пакет идёт как шёл.
    pub fn on<F: FnMut(&str, S)>(self, react: F) -> Running<C, T, ByName<F>, H, S> {
        Running {
            detecting: self,
            react: ByName(react),
            certify: false,
        }
    }

    /// НАБЛЮДАТЬ С АДРЕСОМ: реакция получает [`Whom`] — имя цели И ключ разговора.
    ///
    /// Отдельная дверь, а не второй способ звать `.on`: вывод типов у замыканий без аннотаций
    /// требует, чтобы подпись была известна из сигнатуры метода. Две двери здесь не два закона, а
    /// два ОБЪЁМА одного адреса: кому довольно имени цели — `.on`, кому нужно различать разговоры
    /// одной цели — `.on_addressed`.
    pub fn on_addressed<F: FnMut(Whom<'_>, S)>(
        self,
        react: F,
    ) -> Running<C, T, Addressed<F>, H, S> {
        Running {
            detecting: self,
            react: Addressed(react),
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
    pub fn act<F: FnMut(&str, S) -> Act<C::Carrier>>(self, react: F) -> Acting<C, T, F, H, S>
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
fn voiced<S: Word + Clone>(
    layer: &mut Layer<Conversation, Target, S>,
    fold: &Fold<S>,
    idle: Duration,
    now: Instant,
) -> Vec<(String, Voiced<S>)> {
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
pub struct Folding<C: Bordered, T: Transport, H: MarkHome = MarkSilent, S = Distress> {
    detecting: Detecting<C, T, H, S>,
    fold: Fold<S>,
}

impl<C: Bordered, T: Transport, H: MarkHome, S> Folding<C, T, H, S> {
    /// Что делать со словом о ЦЕЛИ. Дверь отдельная от [`Detecting::on`], потому что область другая:
    /// беда разговора и беда цели — слова разных слоёв, и §5 не складывает их законом пары. Спустить
    /// слово о цели к разговору тоже нельзя — это отменило бы только что сделанную агрегацию.
    pub fn on_target<G: FnMut(&str, Voiced<S>) + Send + 'static>(
        self,
        react: G,
    ) -> Speaking<C, T, H, S> {
        Speaking {
            detecting: Detecting {
                about: Some((self.fold, Box::new(react) as TargetVoice<S>)),
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
pub struct Speaking<C: Bordered, T: Transport, H: MarkHome = MarkSilent, S = Distress> {
    detecting: Detecting<C, T, H, S>,
}

impl<C: Bordered, T: Transport, S> Speaking<C, T, MarkSilent, S> {
    /// Ещё прибор поверх — как в [`Detecting::detect`]: копредел не закрывает набор приборов.
    pub fn detect<P>(self, detector: P) -> Speaking<C, T, P::Home, S>
    where
        P: IntoProbe<Wide<T::Wire, C::Edge>>,
        S: From<P::Word> + 'static,
        P::Word: 'static,
    {
        Speaking {
            detecting: self.detecting.detect(detector),
        }
    }
}

impl<C: Bordered, T: Transport, S> Speaking<C, T, MarkWriter, S> {
    /// Писатель марки уже стоит — принимается только прибор, её не пишущий (см. `Detecting`).
    pub fn detect<P>(self, detector: P) -> Speaking<C, T, MarkWriter, S>
    where
        P: IntoProbe<Wide<T::Wire, C::Edge>, Home = MarkSilent>,
        S: From<P::Word> + 'static,
        P::Word: 'static,
    {
        Speaking {
            detecting: self.detecting.detect(detector),
        }
    }
}

impl<C: Bordered, T: Transport, H: MarkHome, S> Speaking<C, T, H, S> {
    /// НАБЛЮДАТЬ слова о РАЗГОВОРАХ — вторая дверь пары. Слова о цели уже адресованы `.on_target`.
    pub fn on<F: FnMut(&str, S)>(self, react: F) -> Running<C, T, ByName<F>, H, S> {
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
trait Voice<K, S> {
    /// Слово услышано — чем цепочка обещает тронуть мир. Пусто у наблюдателя.
    fn hears(&mut self, whom: Whom<'_>, word: S, seen: &[u8]) -> SmallVec<[Effect; 2]>;
    /// Исполнить обещанное носителем. У наблюдателя обещаний не бывает — тело пусто по построению.
    fn does(&mut self, carrier: &mut K, effects: SmallVec<[Effect; 2]>);
}

/// КОМУ адресовано слово — всё, что фасад знает о его авторе.
///
/// Имя цели было наружу всегда; ключ РАЗГОВОРА — нет, и это была дыра: слово принадлежит
/// разговору (§4), а наружу выходило, потеряв его адрес. Потребитель, которому нужно различать
/// разговоры одной цели, восстанавливал адрес в обход конструкции — стоком мимо алфавита, то есть
/// нарушением §2 (замер: слушатель канала над сканилкой стратегий, 10.09).
///
/// Края здесь НЕТ намеренно. Он носитель-зависим (`CtEdge` против `LocalEdge`), и отдать его
/// типом значило бы вернуть потребителю знание о носителе — ровно то, что выселялось всей веткой.
/// Что из края выводимо и переносимо, прибор кладёт в СВОЁ СЛОВО: с тех пор как словарь стал
/// потребительским, это законно и адреса не требует.
#[derive(Debug, Clone, Copy)]
pub struct Whom<'a> {
    /// Имя цели — то же, что приходило первым аргументом прежде.
    pub target: &'a str,
    /// Ключ разговора: пятёрка, которой он опознан.
    pub flow: Flow,
}

/// Как реакция принимает адрес. Два способа, и оба — одна дверь `.on`: `|target, слово|` берёт
/// только имя (так писали всегда, и примеры не изменились ни строкой), `addressed(|whom, слово|)`
/// берёт адрес целиком.
///
/// Через обёртку, а не через второй метод: предмет один — «реакция на слово», и заводить ему две
/// двери значило бы развести один закон надвое (тот же довод, что у `Placed`: род объявляет
/// прибор, а не спрашивающий).
pub trait Reaction<S> {
    fn call(&mut self, whom: Whom<'_>, word: S);
}

/// Реакция по ИМЕНИ — как писали всегда. Обёртка, а не blanket-`impl` по `FnMut`: blanket ломает
/// вывод типов у замыканий без аннотаций, и `.on(|target, distress| …)` в примерах перестал бы
/// собираться. Обёртку ставит сам `.on`, потребителю она не видна.
pub struct ByName<F>(F);

impl<S, F: FnMut(&str, S)> Reaction<S> for ByName<F> {
    fn call(&mut self, whom: Whom<'_>, word: S) {
        (self.0)(whom.target, word)
    }
}

/// Обёртка для реакции, которой нужен АДРЕС, а не только имя. Ставит её `.on_addressed`.
pub struct Addressed<F>(F);

impl<S, F: FnMut(Whom<'_>, S)> Reaction<S> for Addressed<F> {
    fn call(&mut self, whom: Whom<'_>, word: S) {
        (self.0)(whom, word)
    }
}

/// СМОТРЕТЬ: реакция потребителя, мира не касающаяся.
struct Watch<F>(F);

impl<K, S, F: Reaction<S>> Voice<K, S> for Watch<F> {
    fn hears(&mut self, whom: Whom<'_>, word: S, _seen: &[u8]) -> SmallVec<[Effect; 2]> {
        self.0.call(whom, word);
        SmallVec::new()
    }

    fn does(&mut self, _carrier: &mut K, _effects: SmallVec<[Effect; 2]>) {}
}

/// ДЕЙСТВОВАТЬ: реакция возвращает акт, [`emit`] переводит его в слово носителю и команды миру,
/// исполняет их цикл — и в переигровке не исполняет, тем лента и остаётся переигрываемой (§10).
struct Do<F>(F);

impl<K, S, F> Voice<K, S> for Do<F>
where
    K: CanHold + CanInject,
    K::Error: std::fmt::Debug,
    F: FnMut(&str, S) -> Act<K>,
{
    fn hears(&mut self, whom: Whom<'_>, word: S, seen: &[u8]) -> SmallVec<[Effect; 2]> {
        let (_word, effects) = emit::<K>((self.0)(whom.target, word), seen);
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
pub struct Running<C: Bordered, T: Transport, F, H: MarkHome = MarkSilent, S = Distress> {
    detecting: Detecting<C, T, H, S>,
    react: F,
    /// Предъявлять ли восьмой закон на живой ленте — [`Running::certifying`].
    certify: bool,
}

impl<C, T, F, H: MarkHome, S: Word + Clone + PartialEq + 'static> Running<C, T, F, H, S>
where
    C: Bordered,
    C::Carrier: CanHold + CanRemember,
    // См. докблок `drive`: тождество ассоциированных путей края нужно явным, иначе `drive::<C,…>`
    // ниже не соберётся — компилятор не отождествляет их через сторонний `impl Bordered`.
    C::Carrier: Serves<Edge = <C as Bordered>::Edge>,
    <C::Carrier as Terminal>::Refusal: std::fmt::Debug,
    T: Transport,
    F: Reaction<S>,
{
    /// НАБЛЮДАТЬ. Ведущий цикл один на оба терминала — см. докблок приватной `drive` рядом в этом
    /// файле; отсюда в него едет голос приватной `Watch`, мира не касающийся (обе не ссылки — имена
    /// не экспортированы намеренно, цикл не часть публичного контракта).
    pub fn run(self) -> Report {
        let Running {
            detecting,
            react,
            certify,
        } = self;
        drive::<C, T, _, H, S>(detecting, certify, &mut Watch(react))
    }

    /// Предъявлять восьмой закон (§10) на СВОЕЙ ленте: движок пишет окно наблюдений и, набрав его,
    /// пере-подаёт свежей семье машин дважды — сверяя не ленту, а сказанное.
    ///
    /// Дверь отдельная и по умолчанию закрытая: запись стоит клона слова провода на каждый пакет, и
    /// платить её тем, кто закона не просит, незачем. Кто просит — получает свидетельство на СВОЁМ
    /// трафике, а не на выдуманном стенде: это и отличает предъявимость от обещания.
    pub fn certifying(mut self) -> Running<C, T, F, H, S> {
        self.certify = true;
        self
    }
}

/// ПОКАЗАНИЕ, ВЫШЕДШЕЕ НАРУЖУ ЗНАЧЕНИЕМ. То же, что получает реакция `.on_addressed`, но не в
/// замыкании, а вещью, которой потребитель распоряжается сам.
///
/// Адрес здесь ВЛАДЕЮЩИЙ, в отличие от [`Whom`]: заимствованное имя жило ровно один вызов реакции,
/// а показание-значение переживает свой оборот по определению — иначе его нельзя было бы сложить,
/// отправить или сравнить, то есть незачем было бы отдавать. Цена — одна короткая аллокация на
/// показание, и она не на пакет: показания редки, на то они и показания.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note<S = Distress> {
    /// Имя цели — то же, что приходит первым доводом в `.on`.
    pub target: Box<str>,
    /// Ключ разговора: пятёрка, которой он опознан.
    pub flow: Flow,
    /// Что сказала машина.
    pub word: S,
}

/// ГОЛОС, КЛАДУЩИЙ ПОКАЗАНИЯ В ОЧЕРЕДЬ, — тот же [`Voice`], которым говорят `.on` и `.act`.
///
/// Обещаний миру не даёт (`does` пуст по построению, как у наблюдателя): показание-значение есть
/// НАБЛЮДЕНИЕ, и дать ему трогать носителя значило бы завести действие в обход гейта §9.1.
struct Collecting<'q, S>(&'q mut VecDeque<Note<S>>);

impl<K, S> Voice<K, S> for Collecting<'_, S> {
    fn hears(&mut self, whom: Whom<'_>, word: S, _seen: &[u8]) -> SmallVec<[Effect; 2]> {
        self.0.push_back(Note {
            target: whom.target.into(),
            flow: whom.flow,
            word,
        });
        SmallVec::new()
    }

    fn does(&mut self, _carrier: &mut K, _effects: SmallVec<[Effect; 2]>) {}
}

/// ПРОГОН КАК ЗНАЧЕНИЕ: показания идут вбок, наружу, по одному.
///
/// ```no_run
/// use reflex::*;
///
/// fn main() -> Result<(), Report> {
///     let notes = engine(Nfqueue::queue(200))
///         .from(Tcp)
///         .extract(Sni)
///         .detect(Silence::after(secs(5)))
///         .heard()?;
///
///     for note in notes {
///         report!("{}: {:?}", note.target, note.word);
///     }
///     Ok(())
/// }
/// ```
///
/// `no_run`, а не `ignore`: собрать образец компилятор обязан (иначе докблок обещал бы синтаксис,
/// которого нет), а запускать его негде — живой очереди в доктесте не бывает.
///
/// # Почему `Iterator`, а не `Stream`
///
/// Потому что рантайма у потребителя НЕТ и не требуется, и это замер, а не выбор вкуса: оба
/// прежних терминала — `fn run(self) -> Report`, синхронные, и `.await` в этом крейте ровно ноль.
/// Отдать `Stream` значило бы обязать всякого, кому нужны показания, взять асинхронный рантайм
/// ради цикла, который и так крутится в его собственном потоке. `Stream` над `Iterator` строится
/// одной строкой тем, у кого рантайм уже есть; обратно — не строится ничем.
///
/// Математически это одно и то же: развёртка коалгебры (§1). Шаг `S × In → S × Out` обрывист сам
/// по себе, и непрерывным его делало не устройство закона, а то, что состояние прогона лежало в
/// кадре стека (`Turning`, приватный оборот цикла).
///
/// # Конец
///
/// `None` значит, что носитель сказал: работы больше не будет НИКОГДА. Отдельного `Report` к этому
/// не прилагается нарочно — `Report::finished` не несёт ничего, кроме имени носителя, а его
/// потребитель написал своей рукой строкой выше. Несостоявшийся ЗАПУСК — другое дело, и он приходит
/// значением: `heard()` отдаёт `Err(Report)`, не пустой итератор (§7: «не смотрели» ≠ «смотрели и
/// кончилось»). На живой очереди `None` не приходит никогда: ядро конца не обещает.
///
/// # Чего эта дверь НЕ умеет — по факту, а не по обещанию
///
/// * ДЕЙСТВОВАТЬ. Показание-значение наблюдает; кому нужен `Act`, тому `.act`, и это не сужение
///   удобства, а гейт §9.1: акт требует способности носителя В ТОЧКЕ СОЗДАНИЯ, а у показания,
///   уехавшего к потребителю, носителя уже нет.
/// * СЛОВО О ЦЕЛИ. Копредел по слою живёт за `.about(…).on_target(…)`, и сюда не доходит: у
///   `Heard` нет свёртки. Открыть — отдельный разговор, не попутная правка.
/// * ПРЕДЪЯВЛЯТЬ §10 (`certifying`). Лента пишется у наблюдателя с реакцией; здесь дверь к ней не
///   открыта.
pub struct Heard<C: Bordered, T: Transport, S = Distress> {
    turning: Turning<C, T, S>,
    /// Один оборот рождает НЕСКОЛЬКО показаний (буквы узла адресованы каждой живой машине), а
    /// итератор отдаёт по одному: очередь и есть эта разница.
    said: VecDeque<Note<S>>,
}

impl<C, T, S> Iterator for Heard<C, T, S>
where
    C: Bordered,
    C::Carrier: CanHold + CanRemember,
    C::Carrier: Serves<Edge = <C as Bordered>::Edge>,
    <C::Carrier as Terminal>::Refusal: std::fmt::Debug,
    T: Transport,
    S: Word + Clone + PartialEq + 'static,
{
    type Item = Note<S>;

    fn next(&mut self) -> Option<Note<S>> {
        loop {
            if let Some(note) = self.said.pop_front() {
                return Some(note);
            }
            // Оборот мог не сказать ничего (тишина, чужой кадр, узел без слова) — тогда крутим
            // дальше. Цикл здесь не «ожидание»: срок выдерживает НОСИТЕЛЬ внутри `serve`, а не мы
            // опросом. Тот же закон срока, что и у `.on`, — один оборот, один сон.
            if !self.turning.pump(&mut Collecting(&mut self.said)) {
                return None;
            }
        }
    }
}

impl<C, T, H: MarkHome, S> Detecting<C, T, H, S>
where
    C: Bordered,
    C::Carrier: CanHold + CanRemember,
    C::Carrier: Serves<Edge = <C as Bordered>::Edge>,
    <C::Carrier as Terminal>::Refusal: std::fmt::Debug,
    T: Transport,
    S: Word + Clone + PartialEq + 'static,
{
    /// ПОКАЗАНИЯ ЗНАЧЕНИЕМ — терминал без замыкания: выражение и есть поток показаний.
    ///
    /// Третья дверь наблюдения рядом с `.on` и `.on_addressed`, а не вместо них. Предмет у всех
    /// трёх один — «что сказала машина», — и различаются они лишь тем, КОМУ принадлежит цикл: у
    /// первых двух фреймворку (он зовёт реакцию), у этой потребителю (он тянет показания). Кому
    /// довольно реакции, тот не платит ничем: `.on` не изменился ни строкой.
    ///
    /// `Err(Report)` — носитель не открылся; см. [`Heard`] о том, почему конец прогона `Report`а не
    /// несёт.
    pub fn heard(self) -> Result<Heard<C, T, S>, Report> {
        Ok(Heard {
            turning: Turning::begun(self, false)?,
            said: VecDeque::new(),
        })
    }
}

/// Цепочка с ДЕЙСТВИЕМ собрана — готова к запуску.
pub struct Acting<C: Bordered, T: Transport, F, H: MarkHome = MarkSilent, S = Distress> {
    detecting: Detecting<C, T, H, S>,
    react: F,
}

impl<C, T, F, H: MarkHome, S: Word + Clone + PartialEq + 'static> Acting<C, T, F, H, S>
where
    C: Bordered,
    C::Carrier: CanHold + CanRemember + CanInject,
    // См. докблок `drive`: тождество ассоциированных путей края нужно явным, иначе `drive::<C,…>`
    // ниже не соберётся — компилятор не отождествляет их через сторонний `impl Bordered`.
    C::Carrier: Serves<Edge = <C as Bordered>::Edge>,
    <C::Carrier as Terminal>::Refusal: std::fmt::Debug,
    <C::Carrier as Sink>::Error: std::fmt::Debug,
    T: Transport,
    F: FnMut(&str, S) -> Act<C::Carrier>,
{
    /// ДЕЙСТВОВАТЬ. Тот же ведущий цикл, что и у `.on` (приватная `drive`, не ссылка — см. выше), —
    /// отличается только голосом `Do`: он переводит акт в команды и отдаёт их СТОКУ НОСИТЕЛЯ.
    /// Узлы сетки, дыра и памятка
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
        drive::<C, T, _, H, S>(detecting, false, &mut Do(react))
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
pub enum Said<S = Distress> {
    /// Слово разговора, названное именем цели (так его видит `.on`). Словарь — цепочкин: сверка
    /// восьмого закона требует РАВЕНСТВА слов, и потому слово остаётся словом, а не превращается в
    /// текст. Отпечаток для сравнения и текст для человека — разные вещи.
    OfConversation(String, S),
    /// Слово о цели — итог свёртки (так его видит `.on_target`).
    OfTarget(String, Voiced<S>),
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
fn replay<W: Clone + 'static, S: Word + Clone + PartialEq + 'static>(
    seeds: &[Box<dyn Probe<W, S>>],
    fold: Option<&Fold<S>>,
    idle: Duration,
    mode: Mode,
    letters: &[TapeLetter<W, Whose, ()>],
) -> Vec<Said<S>> {
    // Живой режим сюда не приходит: пере-подача — всегда переигровка. Придёт — упадём в отладке,
    // а не соврём тихо вердиктом, добытым касанием мира.
    debug_assert_eq!(mode, Mode::Replay, "переигровка идёт только в Replay");

    let templates: Vec<Box<dyn Probe<W, S>>> =
        seeds.iter().map(|probe| probe.clone_box()).collect();
    let mut table = FlowTable::<Probes<W, S>, Flow>::new(idle, move |_flow| {
        Probes(templates.iter().map(|probe| probe.clone_box()).collect())
    });
    let mut targets: HashMap<Flow, TargetKey<Box<str>>> = HashMap::new();
    let mut layer: Layer<Conversation, Target, S> = Layer::new();
    let mut said: Vec<Said<S>> = Vec::new();

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
fn drive<C, T, V, H: MarkHome, S>(
    chain: Detecting<C, T, H, S>,
    certify: bool,
    voice: &mut V,
) -> Report
where
    C: Bordered,
    C::Carrier: CanHold + CanRemember,
    // `Bordered::Edge` И край, что отдаёт `carrier.serve(...)`, — ОДИН тип по определению
    // блáнкетного `impl Bordered` (`type Edge = <C::Carrier as Serves>::Edge`), но связаны два
    // ассоциированных пути, и без явного тождества здесь компилятор их не отождествит — только
    // внутри самого `impl`, где равенство и записано, а не в постороннем месте.
    C::Carrier: Serves<Edge = <C as Bordered>::Edge>,
    <C::Carrier as Terminal>::Refusal: std::fmt::Debug,
    T: Transport,
    V: Voice<C::Carrier, S>,
    S: Word + Clone + PartialEq + 'static,
{
    let mut turning = match Turning::begun(chain, certify) {
        Ok(turning) => turning,
        Err(report) => return report,
    };
    while turning.pump(voice) {}
    Report::finished(turning.name, turning.certified)
}

/// ПРОГОН, ОСТАНОВЛЕННЫЙ МЕЖДУ ОБОРОТАМИ.
///
/// Прежде это были локальные переменные внутри `loop` — и потому прогон существовал только пока
/// цикл крутится. Ведущих цикла от этого не стало два: он ОДИН, здесь, и `drive` лишь повторяет его
/// оборот, пока носитель не скажет, что работы больше не будет. Зато оборот стал ПРЕДЪЯВИМЫМ
/// снаружи, и на нём стоит [`Heard`] — дверь, отдающая показания значением.
///
/// Ровно ту же вещь говорит §1: шаг машины есть `S × In → S × Out`, и он ВСЕГДА был обрывист.
/// Непрерывным его делал не закон, а то, что состояние лежало в кадре стека.
struct Turning<C: Bordered, T: Transport, S> {
    /// Носитель отдельным полем от всего прочего НЕ по вкусу, а по необходимости: `serve` берёт
    /// его `&mut` и в замыкании держит `&mut` на соседей. Разъятые поля компилятор различает,
    /// разъятые через `self` методы — нет.
    carrier: C::Carrier,
    alive: Alive<C, T, S>,
    state: T::State,
    seam: Option<Interleave>,
    seeds: Vec<Box<dyn Probe<Wide<T::Wire, C::Edge>, S>>>,
    /// Имя носителя — для [`Report`]. Живёт здесь, потому что открывший носителя рецепт съеден.
    name: String,
    /// Чем кончилось свидетельство §10, если его просили. Живёт на обороте, а не в `Alive`: это
    /// исход ПРОГОНА, и уходит он в [`Report`], когда источник кончился.
    certified: Option<Replayed>,
    /// Внеполосная дверь и ДОМ РЕШЕНИЙ ПО КЛЮЧУ. Дом здесь, а не в `Alive`: решение не наблюдение
    /// и приборам не достаётся — оно живёт до вердикта и читается им.
    #[cfg(feature = "telling")]
    telling: Option<(crate::telling::Telling, HashMap<String, reflex_core::mark::Marked>)>,
}

impl<C, T, S> Turning<C, T, S>
where
    C: Bordered,
    C::Carrier: CanHold + CanRemember,
    // `Bordered::Edge` И край, что отдаёт `carrier.serve(...)`, — ОДИН тип по определению
    // блáнкетного `impl Bordered` (`type Edge = <C::Carrier as Serves>::Edge`), но связаны два
    // ассоциированных пути, и без явного тождества здесь компилятор их не отождествит — только
    // внутри самого `impl`, где равенство и записано, а не в постороннем месте.
    C::Carrier: Serves<Edge = <C as Bordered>::Edge>,
    <C::Carrier as Terminal>::Refusal: std::fmt::Debug,
    T: Transport,
    S: Word + Clone + PartialEq + 'static,
{
    /// ОТКРЫТЬ НОСИТЕЛЯ И ПОСЕЯТЬ СЕМЬЮ. Отказ открытия — значение (§7), не паника: `Err` несёт
    /// готовый [`Report`], потому что несостоявшийся запуск есть знание, а не отсутствие его.
    fn begun<H: MarkHome>(chain: Detecting<C, T, H, S>, certify: bool) -> Result<Self, Report> {
        let Detecting {
            carrier: recipe,
            park,
            longest,
            about,
            #[cfg(feature = "telling")]
            telling,
            ..
        } = chain;
        let name = recipe.name();
        // НЕПЕРЕСЕЧЕНИЕ ОБЛАСТЕЙ — ПРИ ПОСТРОЙКЕ, не при первой записи. Пересекись область решений
        // с областью приборов, и два писателя затирали бы друг друга: фаза прибора читалась бы как
        // чужая, решение — как испорченное, и заметно это стало бы по поведению сети, а не по
        // красному тесту. Отказ здесь — ЗНАЧЕНИЕ (`Report`), как и всякий несостоявшийся запуск.
        #[cfg(feature = "telling")]
        if let Some(handle) = telling.as_ref() {
            let ours = reflex_core::mark::Region::new(recipe.layout().mask());
            if ours.is_some_and(|ours| handle.region().overlaps(&ours)) {
                return Err(Report::not_started(
                    name,
                    format!(
                        "область решений 0x{:08X} пересекается с областью приборов 0x{:08X}: \
                         два писателя затирали бы друг друга",
                        handle.region().mask(),
                        recipe.layout().mask()
                    ),
                ));
            }
        }
        // Носитель открывает СЕБЯ: свои предпосылки, свои сокеты. Цикл о них не знает и знать не может
        // — предпосылка носителя есть дело носителя (у WinDivert она другая).
        let carrier = match recipe.open() {
            Ok(carrier) => carrier,
            Err(Cause(why)) => return Err(Report::not_started(name, why)),
        };

        let idle = longest.saturating_mul(2).max(MIN_IDLE);
        // Семя семьи: те же шаблоны, из которых движок сеет машины, нужны и переигровке — она обязана
        // начать с ТОГО ЖЕ состояния, иначе сверяла бы две разные машины.
        let seeds: Vec<Box<dyn Probe<Wide<T::Wire, C::Edge>, S>>> = park
            .per_flow
            .iter()
            .map(|probe| probe.clone_box())
            .collect();
        let templates = park.per_flow;
        let alive: Alive<C, T, S> = Alive {
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
        let state = T::State::default();
        // Сетка отмеряется от ПЕРВОГО НАБЛЮДЁННОГО момента, а не от часов цикла. Часы цикла и часы
        // носителя — разные эпохи (записанный провод, стенд, чужая ОС), и сетка, начатая нашими, на
        // первом же пакете носителя из другой эпохи выдала бы миллионы узлов разом: прошлое зажимает
        // шов (`at.max(last)`), будущее не зажимает ничто. До первого наблюдения мерить нечего — и
        // адресовать узлы тоже некому: живых машин ещё нет.
        let seam: Option<Interleave> = None;

        Ok(Turning {
            carrier,
            alive,
            state,
            seam,
            seeds,
            name,
            certified: None,
            #[cfg(feature = "telling")]
            telling: telling.map(|handle| (handle, HashMap::new())),
        })
    }

    /// ОДИН ОБОРОТ ВЕДУЩЕГО ЦИКЛА. `false` — носитель сказал, что работы больше не будет никогда.
    ///
    /// Всё, что было телом `loop`, — здесь дословно, и это важнее удобства: два тела разошлись бы
    /// молча, как уже разошлись однажды ведущие циклы наблюдения и действия (см. докблок
    /// [`Acting::run`]).
    fn pump<V: Voice<C::Carrier, S>>(&mut self, voice: &mut V) -> bool {
        // О КОНЦЕ СПРАШИВАЮТ ПРЕЖДЕ, ЧЕМ ПРОСИТЬ РАБОТУ — довод ниже, в теле.
        if self.carrier.exhausted() {
            // Источник кончился — судим по набранному окну, даже неполному. Иначе на КОНЕЧНОМ
            // носителе закон молчал бы обо всём прогоне, и молчание читалось бы как согласие.
            self.certified = self.alive.certified(&self.seeds, true).or(self.certified.take());
            return false;
        }
        // ВНЕПОЛОСНОЕ ЗНАНИЕ ЗАБИРАЕТСЯ ПЕРЕД РАБОТОЙ, а не после: решение, положенное автором до
        // прихода пакета, обязано быть учтено ЭТИМ пакетом, а не следующим. Сетку положенное не
        // двигает — оно не наблюдение провода, и узел, рождённый чужим решением, был бы скрытым
        // входом для приборов молчания (см. докблок `telling`: место на ленте — следующий срез).
        #[cfg(feature = "telling")]
        if let Some((handle, decisions)) = self.telling.as_mut() {
            for told in handle.drain() {
                decisions.insert(told.target, told.decided);
            }
        }
        let Turning {
            carrier,
            alive,
            state,
            seam,
            seeds,
            ..
        } = self;
        // Дом решений — только на чтение внутри решения о вердикте.
        #[cfg(feature = "telling")]
        let decisions = self.telling.as_ref().map(|(_handle, decisions)| decisions);
    // О КОНЦЕ СПРАШИВАЮТ ПРЕЖДЕ, ЧЕМ ПРОСИТЬ РАБОТУ. Носитель, у которого её больше не будет,
    // иначе обязан был бы выдумать тишину до срока — и цикл выдал бы узел, которого в его
    // источнике нет. А тишина, которую носитель честно выдержал, наоборот, обязана дойти
    // узлами: спроси о конце ПОСЛЕ неё — и последний узел пропал бы ровно тогда, когда срок
    // тишины совпал с концом сценария. Живая очередь сюда не приходит никогда: `exhausted` у
    // неё ложь по построению — ядро конца не обещает.
        // Срок — не узел, а ПРОСЬБА к носителю: столько ждать, если работы нет. Оттого до первой
    // буквы он берётся у часов цикла, и это законно: часы цикла знают, сколько ждать, и не
    // знают, что наблюдено.
    let until = match &*seam {
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
        let (moved, letters, whose) = match T::observe(state, parse::read(seen, T::PORT)) {
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
        // Ярлык цели снимается ДО того, как `whose` уедет в раздачу: решение адресовано ключу, а
        // владение ключом уходит вместе с буквой.
        #[cfg(feature = "telling")]
        let decided: Option<reflex_core::mark::Marked> = decisions.and_then(|decisions| {
            whose
                .as_ref()
                .and_then(|(_flow, key)| decisions.get(&label(key)).copied())
        });
        #[cfg(not(feature = "telling"))]
        let decided: Option<reflex_core::mark::Marked> = None;
        let (memo, node) = alive.walk(letters, whose, seen, voice, &mut effects);
        crossed = node;
        // Слово носителю: пакет идёт как шёл, а память — ТЕМ ЖЕ словом (§5: «отпустить и
        // запомнить» неделимо). Разбирать это слово в вердикт — дело носителя: фасад, писавший
        // разбор своей рукой, держал вторую копию таблицы, расходившуюся молча.
        // Памятка прибора и решение потребителя живут в РАЗНЫХ областях марки и ложатся ОДНИМ
        // словом — тем же, каким пакет отпускается. Разведи их по двум путям, и вернулась бы та
        // болезнь, от которой уходили: «ответили, но не запомнили» (§5, «отпустить и запомнить»
        // неделимо). Порядок наложений безразличен ровно потому, что области не пересекаются —
        // и это проверено при постройке, а не здесь, на горячем пути.
        match (memo, decided) {
            (Some(memo), Some(decided)) => <C::Carrier as CanRemember>::remember(
                decided.apply_to(memo.apply_to(mark)),
                true,
            ),
            (Some(memo), None) => <C::Carrier as CanRemember>::remember(memo.apply_to(mark), true),
            (None, Some(decided)) => {
                <C::Carrier as CanRemember>::remember(decided.apply_to(mark), true)
            }
            (None, None) => <C::Carrier as CanHold>::release(),
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
        *seam = Some(moved);
        let (_memo, node) = alive.walk(letters, None, &[], voice, &mut effects);
        crossed = node;
    }

    voice.does(carrier, effects);

    // Уборка на границе узла: слово о цели сказано раньше, среди букв (`Alive::walk`).
    if crossed.is_some() {
        alive.forget_evicted();
        alive.certified(seeds, false);
    }
        true
    }
}


/// ЖИВОЕ СОСТОЯНИЕ ПРОГОНА — всё, чего касается буква. Отдельной вещью, а не россыпью локальных
/// переменных: букву гоняет ОДНА функция ([`Alive::walk`]), и её девять доводов были бы девятью
/// местами, где их можно передать не в том порядке.
struct Alive<C: Bordered, T: Transport, S> {
    /// ПРОВОДНЫЕ приборы: копия семьи на ключ, состояние в юзерспейсе.
    table: FlowTable<Probes<Wide<T::Wire, C::Edge>, S>, Flow>,
    /// КРАЕВЫЕ: один экземпляр на движок, состояние в марке носителя.
    at_edge: Vec<Box<dyn EdgeProbe<Wide<T::Wire, C::Edge>, S>>>,
    /// Слова разговоров, разложенные по цели: из них рождается слово О ЦЕЛИ.
    layer: Layer<Conversation, Target, S>,
    /// Ключ цели на разговор — для сигналов, рождённых узлом сетки (у узла пакета с личностью нет).
    /// Именно КЛЮЧ, а не ярлык: тег `Named`/`Unnamed` нужен слою, а ярлык из ключа выводится.
    targets: HashMap<Flow, TargetKey<Box<str>>>,
    /// Окно ленты: пишется, только когда закон предъявляется — даром лента стоила бы клона слова
    /// провода на каждый пакет.
    tape: Recorded<C, T>,
    certify: bool,
    /// Свёртка слов разговоров в слово о ЦЕЛИ и реакция на него. Живёт ЗДЕСЬ, а не в цикле, потому
    /// что зовётся на закрытии узла — среди букв, а не после них.
    about: Option<(Fold<S>, TargetVoice<S>)>,
    /// Срок, после которого затихший разговор снимается: им же судит и слой.
    idle: Duration,
}

impl<C: Bordered, T: Transport, S: Word + Clone + PartialEq + 'static> Alive<C, T, S> {
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
    fn walk<V: Voice<C::Carrier, S>>(
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
                Vec<(TargetKey<Box<str>>, Flow, SmallVec<[S; 2]>)>,
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
                // ПАКЕТ БЕЗ АДРЕСА — НИКОМУ, и это единственное место, где он рождается. Сегодня
                // такая пара не возникает: `whose` заполняется ровно там, где буква пакета и
                // рождается (`Observation::Seen`), а непонятое и чужое дают `Opaque`/`Tick`. Но
                // ТИП этого не обещает, и ветвь стоит здесь не ради полноты формы: раздай её
                // «каждой машине» по общему правилу — и байты пакета уехали бы уликой чужим
                // разговорам, то есть акт, рождённый чужим словом, оборвал бы непричастного (тот
                // самый закон, что назван абзацем выше). Лента при этом не молчит: буква была, и
                // `To::Nobody` говорит, что она не досталась никому (§7 — незнание обитаемо).
                (DetectorEvent::Packet { .. }, None) => {
                    self.recorded(To::Nobody, &letter);
                    (Vec::new(), &[][..])
                }
                // Буква без адреса — каждой живой машине. В ленту она ложится РАЗ, а фанаут
                // делает тот, кто её читает: перегенерируй её на переигровке — и та позвала бы
                // часы, то есть впустила бы в машину скрытый вход, который сама и проверяет.
                //
                // ЗАГЛУШКИ `_` ЗДЕСЬ НЕТ НАРОЧНО. Появится в алфавите пятая буква — компилятор
                // приведёт автора СЮДА, к вопросу «кому она адресована», вместо того чтобы дать
                // ей молча уехать всем. Дыра (`Torn`) и непонятое (`Opaque`) едут каждому именно
                // потому, что чьё наблюдение пропало — неизвестно: ослепнуть обязаны все, кто
                // судит по отсутствию, а не никто.
                (DetectorEvent::Tick { .. }, _)
                | (DetectorEvent::Opaque { .. }, _)
                | (DetectorEvent::Torn { .. }, _) => {
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
                    effects.extend(voice.hears(
                        Whom {
                            target: &named,
                            flow,
                        },
                        signal.clone(),
                        evidence,
                    ));
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
    /// `closing` — источник кончился, и другого окна не будет. Тогда судим по тому, что набрано:
    /// на КОНЕЧНОМ носителе (запись) полное окно может не собраться никогда, и закон, ждущий
    /// шестидесяти четырёх букв, промолчал бы обо всём файле — ни вердикта, ни «свидетельства
    /// нет». Молчание о собственной предъявимости хуже отказа: отказ назван клеткой (`NoTape`,
    /// `Silent`), а молчание неотличимо от «всё в порядке».
    fn certified(
        &mut self,
        seeds: &[Box<dyn Probe<Wide<T::Wire, C::Edge>, S>>],
        closing: bool,
    ) -> Option<Replayed> {
        if !self.certify || (self.tape.len() < TAPE_WINDOW && !closing) {
            return None;
        }
        let fold = self.about.as_ref().map(|(fold, _say)| fold);
        let idle = self.idle;
        let verdict = replays(&self.tape, |mode, letters| {
            replay::<Wide<T::Wire, C::Edge>, S>(seeds, fold, idle, mode, letters)
        });
        match &verdict {
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
        Some(verdict)
    }
}

/// Исход движка. Два и только два: настройка не состоялась либо источник кончился. Работающий цикл
/// его не возвращает — на боевой очереди он не кончается вовсе.
///
/// `Debug` не для печати в лог, а потому что исход стал ЛЕВОЙ ЧАСТЬЮ `Result` (`Detecting::heard`):
/// значение, которое нельзя предъявить, наполовину не значение — `?` его пропустит, а `.expect` в
/// тесте не соберётся. Второй случай пришёл в тот же день с другой стороны: прогон записи отдаёт
/// `Report`, и упавший тест не мог сказать, ПОЧЕМУ движок не открылся.
#[derive(Debug)]
pub struct Report {
    name: String,
    why: Option<String>,
    /// Чем кончилось свидетельство §10 — `None`, если его не просили ([`Running::certifying`]).
    /// ЗНАЧЕНИЕМ, а не строкой в логе: закон, который нельзя предъявить вызывающему, проверяется
    /// только глазами человека, читающего вывод, — то есть не проверяется.
    certified: Option<Replayed>,
}

impl Report {
    fn not_started(name: String, why: String) -> Report {
        Report {
            name,
            why: Some(why),
            certified: None,
        }
    }

    /// Носитель сказал, что работы больше не будет никогда, и цикл вышел. Отдельно от «не
    /// открылся» (§7: «не смотрели» ≠ «смотрели и кончилось»).
    fn finished(name: String, certified: Option<Replayed>) -> Report {
        Report {
            name,
            why: None,
            certified,
        }
    }

    /// Чем кончилось свидетельство восьмого закона (§10). `None` — не просили: клетка «не
    /// смотрели» отдельно от всякого вердикта (§7).
    pub fn certified(&self) -> Option<&Replayed> {
        self.certified.as_ref()
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

    impl Probe<Word, Distress> for Steady {
        fn observe(&mut self, event: &DetectorEvent<Word>) -> SmallVec<[Distress; 2]> {
            match event {
                DetectorEvent::Packet { .. } => smallvec![Distress::NoBytes],
                DetectorEvent::Tick { .. }
                | DetectorEvent::Opaque { .. }
                | DetectorEvent::Torn { .. } => smallvec![],
            }
        }

        fn clone_box(&self) -> Box<dyn Probe<Word, Distress>> {
            Box::new(self.clone())
        }
    }

    /// Прибор со СКРЫТЫМ входом: величину берёт из счётчика, живущего вне его состояния. Ровно то,
    /// что восьмой закон обязан ловить, — машина читает то, чего нет в её алфавите.
    #[derive(Clone)]
    struct Peeking;

    static PEEKED: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    impl Probe<Word, Distress> for Peeking {
        fn observe(&mut self, event: &DetectorEvent<Word>) -> SmallVec<[Distress; 2]> {
            match event {
                DetectorEvent::Packet { .. } => {
                    let ms = PEEKED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    smallvec![Distress::Silence { ms }]
                }
                DetectorEvent::Tick { .. }
                | DetectorEvent::Opaque { .. }
                | DetectorEvent::Torn { .. } => smallvec![],
            }
        }

        fn clone_box(&self) -> Box<dyn Probe<Word, Distress>> {
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
        let seeds: Vec<Box<dyn Probe<Word, Distress>>> = vec![Box::new(Steady)];

        let verdict = replays(&tape, |mode, letters| {
            replay::<Word, Distress>(&seeds, None, Duration::from_secs(10), mode, letters)
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
        let seeds: Vec<Box<dyn Probe<Word, Distress>>> = vec![Box::new(Peeking)];

        let verdict = replays(&tape, |mode, letters| {
            replay::<Word, Distress>(&seeds, None, Duration::from_secs(10), mode, letters)
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
        let seeds: Vec<Box<dyn Probe<Word, Distress>>> = vec![Box::new(Steady)];
        let fold: Fold = Box::new(|words: &[&Distress]| {
            words
                .iter()
                .all(|distress| matches!(distress, Distress::NoBytes))
                .then_some(Distress::NoBytes)
        });

        let said = replay::<Word, Distress>(
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
            replays(&tape, |mode, letters| replay::<Word, Distress>(
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
