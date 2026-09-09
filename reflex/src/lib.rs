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
//!             Distress::Rst | Distress::Throttled { .. } => {}
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
use reflex_core::Serves;
use reflex_engine::FlowKey;
use reflex_engine_nfq::parse::{self, Read, SERVER_PORT};
use reflex_engine_nfq::talk::Talks;
use reflex_instrument::detect::SilenceInstrument;
use reflex_instrument::retransmit::RetransmitInstrument;
use reflex_instrument::wire::{Reading, Seen};
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

/// Чем ключуется разговор. Пока — именем цели из `ClientHello`.
pub struct Sni;

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

/// Настроенный прибор — то, что кладут в `.detect(…)`. Внутренний тип: наружу торчат `Silence`
/// и `Retransmit`, а не он (скрыт из доков, потребитель его не называет).
#[doc(hidden)]
#[derive(Clone, Copy)]
pub enum Probe {
    Retransmit(RetransmitInstrument),
    Silence(SilenceInstrument),
}

impl Probe {
    /// Один шаг прибора; лог отбрасываем — наружу идёт только слово беды.
    fn step(self, event: DetectorEvent<Seen>) -> (Probe, SmallVec<[Distress; 2]>) {
        match self {
            Probe::Retransmit(machine) => {
                let (machine, signals, ()) = machine.step(event);
                (Probe::Retransmit(machine), signals)
            }
            Probe::Silence(machine) => {
                let (machine, signals, _log) = machine.step(event);
                (Probe::Silence(machine), signals)
            }
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

/// Приборы разговора, гоняемые ВМЕСТЕ над одним проводом. Композиция: пакет и тик фанаутятся в
/// каждый, слова беды сливаются в один алфавит [`Distress`]. Это `alongside` парка, свёрнутый в
/// список одинакового входа/выхода.
#[derive(Clone)]
struct Probes(Vec<Probe>);

impl Mealy for Probes {
    type In = DetectorEvent<Seen>;
    type Out = SmallVec<[Distress; 2]>;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        let mut said: SmallVec<[Distress; 2]> = SmallVec::new();
        let stepped = self
            .0
            .into_iter()
            .map(|probe| {
                let (probe, signals) = probe.step(event.clone());
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
        // Имя цели живёт вне приборов: они мерят провод, имя добывается из `ClientHello`.
        let mut names: HashMap<FlowKey, String> = HashMap::new();
        let mut last_tick = Instant::now();

        loop {
            let now = Instant::now();

            let outcome = {
                let table = &mut table;
                let talks = &mut talks;
                let names = &mut names;
                let react = &mut self.react;
                backend.serve(|held| {
                    if let Read::Tcp(wire) = parse::read(held.seen(), SERVER_PORT) {
                        // Имя цели — из приветствия, если оно в этом пакете.
                        if let Some(name) = tls::extract_sni(wire.payload) {
                            names.insert(wire.flow, name);
                        }
                        // Провод → буква приборов; TCP-специфичные улики (SYN/RST) сюда не идут —
                        // `anywhere` их отсеивает.
                        if let Some(seen) = talks
                            .read(&wire)
                            .and_then(|tcp| Reading::Tcp(tcp).anywhere())
                        {
                            let (signals, ()) = table.process(wire.flow, &seen, now);
                            fire(react, names, wire.flow, &signals);
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
                    fire(&mut self.react, &names, flow, &signals);
                }
            }
        }
    }
}

/// Отдать слова беды реакции. Зовём по имени цели; безымянный разговор молчим — `extract(Sni)`
/// обещал ключ, а без имени вести цель нечем. Что делать с каждым словом — решает потребитель.
fn fire<F: FnMut(&str, Distress)>(
    react: &mut F,
    names: &HashMap<FlowKey, String>,
    flow: FlowKey,
    signals: &[Distress],
) {
    if let Some(name) = names.get(&flow) {
        for signal in signals {
            react(name, signal.clone());
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
