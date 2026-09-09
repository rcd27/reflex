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
//!             Distress::Rst | Distress::Throttled { .. } | Distress::Blackhole { .. } => {}
//!         })
//!         .run()
//! }
//! ```
//!
//! Ни `Plane`, ни `Interleave`, ни `DetectorEvent`, ни `parse` наружу не торчат: цепочка
//! разворачивается в алгебру движка (`разбор провода → приборы на ключ → реакция`) внутри [`run`].
//! Приборы КОМПОНУЮТСЯ: `.detect(A).detect(B)` гоняет оба над одним проводом, реакция получает их
//! общий алфавит [`Distress`]. Склейку сигналов в вывод (подозрение → подтверждение) пишет
//! потребитель — фреймворк описывает МИР, лечение живёт у него.
//!
//! [`run`]: Running::run

use std::collections::HashMap;
use std::time::{Duration, Instant};

use reflex_core::flow_table::FlowTable;
use reflex_core::mealy::Mealy;
use reflex_core::serves::Served;
use reflex_core::tls;
use reflex_core::DetectorEvent;
use reflex_core::Reads;
use reflex_core::Serves;
use reflex_engine::row::{host_of, keyed, Naming, TargetKey};
use reflex_engine::{Addr, FlowKey};
use reflex_engine_nfq::parse::{self, Read, SERVER_PORT};
use reflex_engine_nfq::talk::Talks;
use reflex_instrument::detect::{SilenceInstrument, SynDropInstrument};
use reflex_instrument::retransmit::RetransmitInstrument;
use reflex_instrument::wire::{Reading, Seen, SeenTcp};
use reflex_linux::nfqueue::{Answer, NfqueueBackend};
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

/// Транспорт разговоров, за которым смотрим. Пока — только TCP.
pub struct Tcp;

/// Чем ключуется цель: именем из `ClientHello`, а при его ОТСУТСТВИИ — адресом. Отсутствие имени
/// не теряется (MTProto/Телеграм, коннект по чистому IP, ECH — имени нет вовсе): такая цель
/// опознаётся по IP, а не пропадает молча. Это расслоение движка (`TargetKey::Named | Unnamed`,
/// канон §4): имя — верхний слой, адрес — нижний, и слово всегда есть.
pub struct Sni;

/// Личность цели разговора, копимая по ходу: адрес известен с первого пакета, имя — если пришло
/// приветствие с SNI. Отсюда рождается [`TargetKey`] цели.
struct Ident {
    dst: Addr,
    naming: Naming<Box<str>>,
}

impl Ident {
    /// Как назвать цель человеку: имя, если оно есть; иначе адрес. `keyed` — то же расслоение, каким
    /// цель ключует движок (`host_of` — точный адрес: какой именно сервер, не сеть).
    fn target(&self) -> String {
        match keyed(self.naming.clone(), self.dst, host_of) {
            TargetKey::Named(name) => name.to_string(),
            TargetKey::Unnamed(addr) => addr.to_string(),
        }
    }
}

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

/// Детектор тихого дропа по ПОВТОРУ клиента: просьба ушла, ответа нет, ядро клиента ретрансмитит —
/// самая ранняя улика (порог — RTO клиента под реальный RTT, не наш тик). Подозрение, не приговор:
/// обычная сетевая потеря даёт тот же повтор, потому автора не называем.
pub struct Retransmit;

impl Retransmit {
    /// Повтор без ответа цели.
    pub fn unanswered() -> Retransmit {
        Retransmit
    }
}

/// Детектор IP-blackhole: `SYN` ушёл, `SYN+ACK` не пришёл, клиент повторяет `SYN` — блок по адресу,
/// соединение не состоялось вовсе. Читает `SeenTcp` (не `Seen`): это ОТДЕЛЬНЫЙ пайп, через
/// `Silence`/`Retransmit` его не выразить — там соединение уже открыто, здесь его нет.
pub struct SynDrop;

impl SynDrop {
    /// Адрес недостижим: повтор стука без рукопожатия.
    pub fn unreachable() -> SynDrop {
        SynDrop
    }
}

/// Настроенный прибор — то, что кладут в `.detect(…)`. Внутренний тип: наружу торчат `Silence`
/// и `Retransmit`, а не он (скрыт из доков, потребитель его не называет).
#[doc(hidden)]
#[derive(Clone, Copy)]
pub enum Probe {
    Retransmit(RetransmitInstrument),
    Silence(SilenceInstrument),
    SynDrop(SynDropInstrument),
}

/// Сузить широкое событие провода до алфавита прибора (канон §4, `Reads`). Пакет — по букве прибора
/// (`None` — буква не его, шаг пропускается); тик и непонятое идут всем. Так разноалфавитные приборы
/// (`Seen`-тишина и `SeenTcp`-blackhole) встают в одну дверь.
fn narrow<N: Reads<Reading>>(event: &DetectorEvent<Reading>) -> Option<DetectorEvent<N>> {
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

impl Probe {
    /// Один шаг прибора над широким событием: прибор сам сужает его до своего алфавита. Лог
    /// отбрасываем — наружу идёт только слово беды.
    fn step(self, event: &DetectorEvent<Reading>) -> (Probe, SmallVec<[Distress; 2]>) {
        match self {
            Probe::Retransmit(machine) => match narrow::<Seen>(event) {
                Some(event) => {
                    let (machine, signals, ()) = machine.step(event);
                    (Probe::Retransmit(machine), signals)
                }
                None => (Probe::Retransmit(machine), SmallVec::new()),
            },
            Probe::Silence(machine) => match narrow::<Seen>(event) {
                Some(event) => {
                    let (machine, signals, _log) = machine.step(event);
                    (Probe::Silence(machine), signals)
                }
                None => (Probe::Silence(machine), SmallVec::new()),
            },
            Probe::SynDrop(machine) => match narrow::<SeenTcp>(event) {
                Some(event) => {
                    let (machine, signals, ()) = machine.step(event);
                    (Probe::SynDrop(machine), signals)
                }
                None => (Probe::SynDrop(machine), SmallVec::new()),
            },
        }
    }
}

/// Прибор, кладущийся в `.detect(…)`. Реализуют `Silence` и `Retransmit`.
pub trait IntoProbe {
    #[doc(hidden)]
    fn into_probe(self) -> Probe;
    /// Временно́е окно прибора (ноль у беспороговых) — по нему движок выбирает срок эвикта ключа.
    #[doc(hidden)]
    fn window(&self) -> Duration {
        Duration::ZERO
    }
}

impl IntoProbe for Silence {
    fn into_probe(self) -> Probe {
        Probe::Silence(SilenceInstrument::after(self.after))
    }
    fn window(&self) -> Duration {
        self.after
    }
}

impl IntoProbe for Retransmit {
    fn into_probe(self) -> Probe {
        Probe::Retransmit(RetransmitInstrument::new())
    }
}

impl IntoProbe for SynDrop {
    fn into_probe(self) -> Probe {
        Probe::SynDrop(SynDropInstrument::new())
    }
}

/// Приборы разговора, гоняемые ВМЕСТЕ над одним проводом. Композиция: пакет и тик фанаутятся в
/// каждый, слова беды сливаются в один алфавит [`Distress`]. Это `alongside` парка, свёрнутый в
/// список одинакового входа/выхода.
#[derive(Clone)]
struct Probes(Vec<Probe>);

impl Mealy for Probes {
    type In = DetectorEvent<Reading>;
    type Out = SmallVec<[Distress; 2]>;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        let mut said: SmallVec<[Distress; 2]> = SmallVec::new();
        let stepped = self
            .0
            .into_iter()
            .map(|probe| {
                let (probe, signals) = probe.step(&event);
                said.extend(signals);
                probe
            })
            .collect();
        (Probes(stepped), said, ())
    }
}

/// Движок над носителем — ждёт выбора транспорта.
pub struct Engine {
    queue: u16,
}

impl Engine {
    /// Поток разговоров этого транспорта.
    pub fn from(self, _transport: Tcp) -> Watching {
        Watching { queue: self.queue }
    }
}

/// Транспорт выбран — ждёт ключа разговора.
pub struct Watching {
    queue: u16,
}

impl Watching {
    /// Чем ключуется разговор.
    pub fn extract(self, _key: Sni) -> Keyed {
        Keyed { queue: self.queue }
    }
}

/// Ключ выбран — ждёт хотя бы одного детектора.
pub struct Keyed {
    queue: u16,
}

impl Keyed {
    /// Установить первый детектор. Дальше можно `.detect(…)` ещё — они гоняются вместе.
    pub fn detect(self, detector: impl IntoProbe) -> Detecting {
        Detecting {
            queue: self.queue,
            longest: detector.window(),
            probes: vec![detector.into_probe()],
        }
    }
}

/// Детекторы копятся — можно добавить ещё или перейти к реакции.
pub struct Detecting {
    queue: u16,
    probes: Vec<Probe>,
    longest: Duration,
}

impl Detecting {
    /// Установить ещё один детектор поверх — они гоняются ВМЕСТЕ над одним проводом.
    pub fn detect(mut self, detector: impl IntoProbe) -> Detecting {
        self.longest = self.longest.max(detector.window());
        self.probes.push(detector.into_probe());
        self
    }

    /// Что делать на срабатывание любого прибора. `target` — имя цели, `distress` — что случилось.
    pub fn on<F: FnMut(&str, Distress)>(self, react: F) -> Running<F> {
        Running {
            queue: self.queue,
            probes: self.probes,
            longest: self.longest,
            react,
        }
    }
}

/// Цепочка собрана — готова к запуску.
pub struct Running<F> {
    queue: u16,
    probes: Vec<Probe>,
    longest: Duration,
    react: F,
}

/// Как часто движок будит приборы в тишине. Молчание видно только тиком — без него окно тишины не
/// закрылось бы. Меньше окна детектора; выбрано, не замерено.
const TICK: Duration = Duration::from_millis(200);

/// Сколько ждать на пустой очереди, прежде чем вернуться к тику. Ожидание ведёт цикл, не бэкенд.
const POLL_MS: i32 = 100;

/// Нижний предел срока эвикта ключа: даже беспороговым приборам (повтор) нужно пережить типичный
/// разговор.
const MIN_IDLE: Duration = Duration::from_secs(10);

impl<F: FnMut(&str, Distress)> Running<F> {
    /// Ведущий цикл. Возвращается только исходом настройки (`Report`) — работает, пока жив процесс.
    ///
    /// Внутри: разбор провода (`parse`) → память разговора (`Talks`) → приборы на ключ
    /// ([`FlowTable`] над [`Probes`]) с фанаутом тиков и эвиктом по простою → реакция на общий
    /// алфавит [`Distress`]. Пакет пропускается как есть (`Answer::Pass`): use-case наблюдает.
    pub fn run(mut self) -> Report {
        let mut backend = match NfqueueBackend::open(self.queue) {
            Ok(backend) => backend,
            Err(why) => return Report::not_started(self.queue, why),
        };

        // Ключ живёт до эвикта дольше самого долгого окна: снятый раньше потерял бы его беду.
        let idle = self.longest.saturating_mul(2).max(MIN_IDLE);
        let probes = self.probes;
        let mut table =
            FlowTable::<Probes, FlowKey>::new(idle, move |_flow| Probes(probes.clone()));
        let mut talks = Talks::new();
        // Личность цели живёт вне приборов: они мерят провод, а `extract(Sni)` копит имя+адрес.
        let mut idents: HashMap<FlowKey, Ident> = HashMap::new();
        let mut last_tick = Instant::now();

        loop {
            let now = Instant::now();

            let outcome = {
                let table = &mut table;
                let talks = &mut talks;
                let idents = &mut idents;
                let react = &mut self.react;
                backend.serve(|held| {
                    if let Read::Tcp(wire) = parse::read(held.seen(), SERVER_PORT) {
                        // Личность копится: адрес с первого пакета, имя — если пришло приветствие.
                        // Отсутствие SNI не теряется — цель опознаётся по адресу (Телега/чистый IP).
                        let ident = idents.entry(wire.flow).or_insert(Ident {
                            dst: wire.dst,
                            naming: Naming::Awaited,
                        });
                        if let Some(sni) = tls::extract_sni(wire.payload) {
                            ident.naming = Naming::Spoken(sni.into());
                        }
                        // Провод → ШИРОКИЙ словарь; каждый прибор сузит его до своего алфавита
                        // (`Seen` — тишина/повтор, `SeenTcp` — blackhole). Кормим широким, не узким.
                        if let Some(tcp) = talks.read(&wire) {
                            let reading = Reading::Tcp(tcp);
                            let (signals, ()) = table.process(wire.flow, &reading, now);
                            fire(react, idents, wire.flow, &signals);
                        }
                    }
                    // Наблюдаем, не вмешиваемся: пакет идёт как шёл.
                    Answer::Pass
                })
            };

            match outcome {
                Served::Answered(_) => {}
                // Пусто — подождём на дескрипторе, чтобы не жечь процессор пустым циклом.
                Served::Idle => {
                    let _ = backend.wait(POLL_MS);
                }
                // Ждать не на чем — короткий сон, чтобы не крутиться вслепую.
                Served::Blind => std::thread::sleep(Duration::from_millis(1)),
            }

            // Тик будит приборы в тишине — там рождается подтверждение по окну тишины.
            if now.duration_since(last_tick) >= TICK {
                last_tick = now;
                for (flow, (signals, ())) in table.tick(now) {
                    fire(&mut self.react, &idents, flow, &signals);
                }
                // Личность уходит вместе с ключом: эвикт таблицы по простою, зеркалим его, чтобы
                // карта личностей не росла с числом ВИДЕННЫХ разговоров.
                idents.retain(|flow, _| table.get(flow).is_some());
            }
        }
    }
}

/// Отдать слова беды реакции по личности цели. Личность есть ВСЕГДА (имя или адрес), потому
/// безымянная цель — Телеграм, чистый IP — не теряется. Что делать с каждым словом — решает потребитель.
fn fire<F: FnMut(&str, Distress)>(
    react: &mut F,
    idents: &HashMap<FlowKey, Ident>,
    flow: FlowKey,
    signals: &[Distress],
) {
    if let Some(ident) = idents.get(&flow) {
        let target = ident.target();
        for signal in signals {
            react(&target, signal.clone());
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

    /// `extract(Sni)` не теряет безымянную цель: нет имени — личность по адресу. Телеграм, коннект
    /// по чистому IP, ECH — у всех имени нет, и все опознаются по IP, а не пропадают молча.
    #[test]
    fn target_falls_back_to_address_when_there_is_no_name() {
        let awaited = Ident {
            dst: Addr(0x0A00_0001),
            naming: Naming::Awaited,
        };
        assert_eq!(
            awaited.target(),
            "10.0.0.1",
            "приветствия не было — по адресу"
        );

        let silent = Ident {
            dst: Addr(0x0A00_0001),
            naming: Naming::Silent,
        };
        assert_eq!(
            silent.target(),
            "10.0.0.1",
            "приветствие без имени (ECH/не-TLS) — тоже по адресу"
        );

        let named = Ident {
            dst: Addr(0x0A00_0001),
            naming: Naming::Spoken("rutracker.org".into()),
        };
        assert_eq!(named.target(), "rutracker.org", "имя есть — по имени");
    }
}
