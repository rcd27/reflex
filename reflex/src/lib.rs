//! `reflex` — единственная дверь фреймворка. Потребитель пишет цепочку и больше ничего не знает:
//!
//! ```no_run
//! use reflex::*;
//!
//! fn main() -> Report {
//!     engine(Nfqueue::queue(200))
//!         .from(Tcp)
//!         .extract(Sni)
//!         .detect(Silence::after(secs(5)))
//!         .on(|target, silence| report!("тихий дроп: {target} молчит {}мс", silence.ms))
//!         .run()
//! }
//! ```
//!
//! Ни `Plane`, ни `Interleave`, ни `DetectorEvent`, ни `parse` наружу не торчат: цепочка
//! разворачивается в алгебру движка (`разбор провода → детектор на ключ → реакция`) внутри [`run`].
//! Это фасад одной итерации example-driven разработки: наружу выведено ровно то, что нужно
//! use-case'у `detect-silent-drop`; поверхность растёт от следующих примеров, а не от догадок.
//!
//! [`run`]: Running::run

use std::collections::HashMap;
use std::time::{Duration, Instant};

use reflex_core::flow_table::FlowTable;
use reflex_core::serves::Served;
use reflex_core::tls;
use reflex_core::Serves;
use reflex_engine::FlowKey;
use reflex_engine_nfq::parse::{self, Read, SERVER_PORT};
use reflex_engine_nfq::talk::Talks;
use reflex_instrument::detect::{Measured, SilenceInstrument};
use reflex_instrument::distress::Distress;
use reflex_instrument::wire::Reading;
use reflex_linux::nfqueue::{Answer, NfqueueBackend};

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

/// Детектор тихого дропа: цель молчит дольше окна `after`.
pub struct Silence {
    after: Duration,
}

impl Silence {
    /// Сколько молчания терпим, прежде чем назвать это тихим дропом.
    pub fn after(after: Duration) -> Silence {
        Silence { after }
    }
}

/// Что случилось: цель молчит столько-то миллисекунд.
pub struct Silenced {
    pub ms: u32,
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

/// Ключ выбран — ждёт детектора.
pub struct Keyed {
    queue: u16,
}

impl Keyed {
    /// Установить детектор.
    pub fn detect(self, silence: Silence) -> Detecting {
        Detecting {
            queue: self.queue,
            after: silence.after,
        }
    }
}

/// Детектор установлен — ждёт реакции.
pub struct Detecting {
    queue: u16,
    after: Duration,
}

impl Detecting {
    /// Что делать при срабатывании. `target` — имя цели, `silence` — сколько она молчит.
    pub fn on<F: FnMut(&str, Silenced)>(self, react: F) -> Running<F> {
        Running {
            queue: self.queue,
            after: self.after,
            react,
        }
    }
}

/// Цепочка собрана — готова к запуску.
pub struct Running<F> {
    queue: u16,
    after: Duration,
    react: F,
}

/// Как часто движок будит детекторы в тишине. Молчание видно только тиком — без него тихий дроп
/// заметился бы лишь на следующем пакете, которого нет. Меньше окна детектора; выбрано, не замерено.
const TICK: Duration = Duration::from_millis(200);

/// Сколько ждать на пустой очереди, прежде чем вернуться к тику. Ожидание ведёт цикл, не бэкенд.
const POLL_MS: i32 = 100;

impl<F: FnMut(&str, Silenced)> Running<F> {
    /// Ведущий цикл. Возвращается только исходом настройки (`Report`) — работает, пока жив процесс.
    ///
    /// Внутри: разбор провода (`parse`) → память разговора (`Talks`) → детектор на ключ
    /// (`FlowTable<SilenceInstrument>`) с фанаутом тиков и эвиктом по простою → реакция. Пакет
    /// пропускается как есть (`Answer::Pass`): этот use-case наблюдает, а не вмешивается.
    pub fn run(mut self) -> Report {
        let mut backend = match NfqueueBackend::open(self.queue) {
            Ok(backend) => backend,
            Err(why) => return Report::not_started(self.queue, why),
        };

        let after = self.after;
        // Ключ молчит до эвикта вдвое дольше окна: снятый раньше потерял бы беду последнего окна.
        let mut table =
            FlowTable::<SilenceInstrument, FlowKey>::new(after.saturating_mul(2), move |_flow| {
                SilenceInstrument::after(after)
            });
        let mut talks = Talks::new();
        // Имя цели живёт вне детектора: он мерит молчание, имя добывается из `ClientHello`.
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
                    match parse::read(held.seen(), SERVER_PORT) {
                        Read::Tcp(wire) => {
                            // Имя цели — из приветствия, если оно в этом пакете.
                            if let Some(name) = tls::extract_sni(wire.payload) {
                                names.insert(wire.flow, name);
                            }
                            // Провод → буква детектора; TCP-специфичные улики (SYN/RST) детектор
                            // тишины не читает — `anywhere` их отсеивает.
                            if let Some(seen) = talks
                                .read(&wire)
                                .and_then(|tcp| Reading::Tcp(tcp).anywhere())
                            {
                                let (signals, log) = table.process(wire.flow, &seen, now);
                                fire(react, names, wire.flow, &signals, log);
                            }
                        }
                        Read::Udp(_)
                        | Read::NotIpv4
                        | Read::NotOurProtocol
                        | Read::NotOurPort
                        | Read::Truncated => {}
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

            // Тик будит детекторы в тишине — именно тут и рождается сигнал о тихом дропе.
            if now.duration_since(last_tick) >= TICK {
                last_tick = now;
                for (flow, (signals, log)) in table.tick(now) {
                    fire(&mut self.react, &names, flow, &signals, log);
                }
            }
        }
    }
}

/// Перевести беды детектора в реакцию. Тишину зовём по имени цели; безымянный разговор молчим —
/// `extract(Sni)` обещал ключ, а без имени вести цель нечем. Прочие беды (`Rst`, троттлинг, повтор)
/// этому use-case'у не адресованы — детектор тишины их и не эмитит.
fn fire<F: FnMut(&str, Silenced)>(
    react: &mut F,
    names: &HashMap<FlowKey, String>,
    flow: FlowKey,
    signals: &[Distress],
    log: Option<Measured>,
) {
    for signal in signals {
        let ms = match signal {
            Distress::Silence { ms } => *ms,
            // Цель не ответила вовсе — молчание с самого начала; длину берём из показания.
            Distress::NoBytes => log.map(|measured| measured.since_ms).unwrap_or(0),
            Distress::Rst | Distress::Throttled { .. } | Distress::Retransmit { .. } => continue,
        };
        if let Some(name) = names.get(&flow) {
            react(name, Silenced { ms });
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
