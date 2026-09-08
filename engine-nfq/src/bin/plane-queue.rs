use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use reflex_core::command::InjectablePacket;
use reflex_engine::watch::Watch;
use reflex_engine::{Act, Addr, Basis, Interest, Mark, Noticed, Programme, Tick};
use reflex_engine_nfq::parse::{read, Read, SERVER_PORT};
use reflex_engine_nfq::plane::Plane;
use reflex_linux::nfqueue::{Answer, NfqHandler, NfqPacket, NfqPipeline};

const INJECT_MARK: u32 = 0xBB;
/// Шаг собственных часов плоскости. Сто миллисекунд взято от соседей (отчётчик и снимок тикают тем
/// же шагом), не замерено: реже — потеря цели заметится позже на шаг, чаще — тред берёт лок без нужды.
const PULSE: Duration = Duration::from_millis(100);
/// Шаг снимка для показа. Реже часов намеренно: снимок стоит дампа conntrack (сисколл плюс разбор
/// netlink), человек за таблицей не читает быстрее секунды. Взято от терпения читателя, не замерено.
const SNAPSHOT_EVERY: Duration = Duration::from_secs(1);
/// Метка ноги, которую ядро увидит на членах множества.
const MARK_LEG: u32 = 0xCC;
/// Имя множества в таблице стенда.
struct Shell {
    plane: Arc<Mutex<Plane>>,
    /// Сколько разговоров выпущено из горячего пути. Считается ПАКЕТАМИ, на которых выпуск состоялся:
    /// верхняя граница дороги в userspace, которую перестанем платить; сверяется со счётчиком ядра.
    released: Arc<AtomicU64>,
    started: Instant,
    slowest_ns: Arc<AtomicU64>,
    total_ns: Arc<AtomicU64>,
    seen: Arc<AtomicU64>,
    unparsed: Arc<AtomicU64>,
    fresh_ns: Arc<AtomicU64>,
    fresh_n: Arc<AtomicU64>,
    running_ns: Arc<AtomicU64>,
    running_n: Arc<AtomicU64>,
}

impl NfqHandler for Shell {
    fn handle(&mut self, packet: &NfqPacket) -> (Answer, Vec<InjectablePacket>) {
        let entered = Instant::now();
        let injects: Vec<InjectablePacket> = Vec::new();
        let mut opened = false;
        self.seen.fetch_add(1, Ordering::Relaxed);
        let now = Tick(self.started.elapsed().as_nanos() as u64);

        let verdict = match read(&packet.payload, SERVER_PORT) {
            Read::Tcp(wire) => match self.plane.lock() {
                Err(_poisoned) => Answer::Pass,
                Ok(mut held) => {
                    held.offer();
                    let fed = held.feed(wire, now);
                    opened = fed.opened;
                    // Выпуск решает закон, а не оболочка — и это выражено: решение приезжает готовым
                    // (прежде оболочка сводила личность с вердиктом сама и могла взять чужой флоу).
                    match (fed.act, fed.watch) {
                        (_taken, Watch::Release(mark)) => {
                            self.released.fetch_add(1, Ordering::Relaxed);
                            Answer::Marked(mark.0)
                        }
                        (Act::Pass, Watch::Hold) => Answer::Pass,
                        (Act::Drop, Watch::Hold) => Answer::Stop,
                        // Метка уходит вердиктом. Прежде здесь `Accept`, а адрес поднимался в
                        // множество ядра отдельным ходом — снят (`df7b3e78`) за применение знания
                        // ПО АДРЕСУ.
                        (Act::Marked(mark), Watch::Hold) => Answer::Marked(mark.0),
                        // Обрыв пока не исполняется на проводе (#318): закон построен в плоскости
                        // (`step`), но послать клиенту сброс нужна инъекция (TCP-RST с seq из
                        // состояния), а не вердикт. `Drop` клиенту не говорит ничего — человек ждёт
                        // до таймаута. Пропускаем и СЧИТАЕМ: неисполненный приказ — величина, не тишина.
                        (Act::Sever, Watch::Hold) => {
                            held.note_unapplied("Sever");
                            Answer::Pass
                        }
                    }
                }
            },
            // Датаграммы через эту очередь не идут: правило заворачивает только соединения.
            // Пришедшая сюда значит, что правило разошлось с оболочкой — считать её «неразобранной»
            // верно (разобрать умеем, а ждать не ждали).
            Read::Udp(_)
            | Read::Truncated
            | Read::NotIpv4
            | Read::NotOurProtocol
            | Read::NotOurPort => {
                self.unparsed.fetch_add(1, Ordering::Relaxed);
                match self.plane.lock() {
                    Err(_poisoned) => (),
                    Ok(mut held) => held.note_unparsed(),
                }
                Answer::Pass
            }
        };

        let spent = entered.elapsed().as_nanos() as u64;
        // Цена разделена по роду работы: новый разговор заводит курсор и цель (две вставки),
        // продолжение только ищет. Смешав, померим состав трафика, а не плоскость.
        match opened {
            true => {
                self.fresh_ns.fetch_add(spent, Ordering::Relaxed);
                self.fresh_n.fetch_add(1, Ordering::Relaxed);
            }
            false => {
                self.running_ns.fetch_add(spent, Ordering::Relaxed);
                self.running_n.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.total_ns.fetch_add(spent, Ordering::Relaxed);
        self.slowest_ns.fetch_max(spent, Ordering::Relaxed);
        (verdict, injects)
    }
}

/// Имя наблюдения берётся у типа, не считается здесь во второй раз (прежде свой перевод русскими
/// словами расходился бы с реестром событий в первый же день, когда у наблюдения появилась новая
/// буква). Слова двух областей — каждое своим держателем имени: наблюдения разговора паспортом,
/// потеря цели самим типом.
fn named(told: &Noticed) -> &'static str {
    match told {
        Noticed::Talk(sighting) => {
            <reflex_engine::SightingInstrument as reflex_instrument::Instrument>::name(sighting)
        }
        Noticed::Loss(_lost) => reflex_engine::Lost::EVENT,
    }
}

/// Сужение для замера: имя как есть. Целей с именами этот прибор не наблюдает.
fn as_seen(host: &str) -> &str {
    host
}

fn report(plane: &Arc<Mutex<Plane>>, seen: &AtomicU64, total: &AtomicU64, worst: &AtomicU64) {
    match plane.lock() {
        Err(_poisoned) => eprintln!("[плоскость] состояние отравлено"),
        Ok(mut held) => {
            let told = held.drain();
            let counted = told.iter().fold(
                std::collections::BTreeMap::<&'static str, u64>::new(),
                |mut tally, noted| {
                    *tally.entry(named(&noted.what)).or_insert(0) += 1;
                    tally
                },
            );
            let tally = held.tally();
            let packets = seen.load(Ordering::Relaxed).max(1);
            eprintln!(
                "[плоскость] пакетов {} · вверх {} Б · вниз {} Б · флоу открыто {} · курсоров {} · целей {}",
                tally.packets, tally.up_bytes, tally.down_bytes, tally.flows_opened,
                held.pressure().held, held.targets_held(),
            );
            eprintln!(
                "[канал]     за 1 с {} Б · потолок ковша {} Б · вердикт: средний {} нс, худший {} нс",
                held.channel(7).bytes,
                held.ceiling().bytes,
                total.load(Ordering::Relaxed) / packets,
                worst.load(Ordering::Relaxed),
            );
            eprintln!(
                "[наблюдения] {} · потеряно {} · вытеснено курсоров {} / целей {}",
                counted
                    .iter()
                    .map(|(what, n)| format!("{what} {n}"))
                    .collect::<Vec<String>>()
                    .join(" · "),
                held.dropped_sightings(),
                held.pressure().evicted,
                held.evicted_targets(),
            );
            let names = held.names();
            match names.is_empty() {
                true => (),
                false => eprintln!(
                    "[имена]     {} · без имени {}",
                    names
                        .iter()
                        .map(|(name, n)| format!("{name}×{n}"))
                        .collect::<Vec<String>>()
                        .join(" · "),
                    held.unnamed_hellos(),
                ),
            }
            let unapplied = held.unapplied();
            match unapplied.is_empty() {
                true => (),
                false => eprintln!(
                    "[НЕ ПРИМЕНЕНО] {}",
                    unapplied
                        .iter()
                        .map(|(what, n)| format!("{what} {n}"))
                        .collect::<Vec<String>>()
                        .join(" · ")
                ),
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let queue: u16 = match args.first().map(|first| first.parse::<u16>()) {
        Some(Ok(parsed)) => parsed,
        None => {
            eprintln!("нужно: plane-queue <очередь>");
            std::process::exit(2);
        }
        Some(Err(_bad)) => {
            eprintln!("нужно: plane-queue <очередь>");
            std::process::exit(2);
        }
    };

    // Что вести ногой — задаётся снаружи: знание о среде край не выдумывает. Пусто — плоскость
    // никого не метит (законный вырожденный случай, не отказ).
    let leg = std::env::var("PLANE_MARK").unwrap_or_default();
    // Прибор цены цели знает только адреса: засев синтетический, имён на проводе нет. Оттого сужение
    // — тождество, и это сказано: предмет здесь таблица, а не ключ.
    let plane = Arc::new(Mutex::new(Plane::new(Programme::Pass, as_seen)));
    // Разбор, который молча отбрасывает, врёт: оболочка печатала «помечаем 2606:...» и не метила
    // никого (getent отдал IPv6, а плоскость знает четыре байта, #299). Теперь отказ ГРОМКИЙ.
    leg.split(',')
        .filter(|piece| !piece.trim().is_empty())
        .filter_map(|piece| match piece.trim().parse::<std::net::Ipv4Addr>() {
            Ok(parsed) => Some(parsed),
            Err(_not_v4) => {
                eprintln!(
                    "[нога] «{}» НЕ РАЗОБРАН как IPv4 — не помечен",
                    piece.trim()
                );
                None
            }
        })
        .for_each(|address| match plane.lock() {
            Err(_poisoned) => (),
            Ok(mut held) => held.teach_unnamed(
                Addr(u32::from(address)),
                Programme::Mark(Mark(MARK_LEG)),
                Basis::Measured,
                Interest::Watching,
            ),
        });
    // Засев знания для замера (#300): цена на пакет обязана быть O(1) по ОБЪЁМУ знания, проверить
    // можно лишь сравнив прогоны с разной таблицей. Адреса синтетические, трафика нет — предмет
    // замера таблица, а не цели.
    let seeded: u32 = std::env::var("PLANE_SEED")
        .ok()
        .and_then(|given| given.parse().ok())
        .unwrap_or(0);
    (0..seeded).for_each(|i| match plane.lock() {
        Err(_poisoned) => (),
        // Засеву наблюдение не нужно: трафика к этим адресам нет.
        Ok(mut held) => held.teach_unnamed(
            Addr(0x0A00_0000 + i),
            Programme::Mark(Mark(MARK_LEG)),
            Basis::Seeded,
            Interest::Idle,
        ),
    });
    match seeded {
        0 => (),
        many => eprintln!("[засев] знание о {many} целях"),
    }

    eprintln!(
        "[нога] помечаем: {}",
        match leg.is_empty() {
            true => "никого".to_string(),
            false => leg.clone(),
        }
    );
    // Начало отсчёта одно на всех, заводится здесь, не внутри обработчика: время у пакетов и у тика
    // обязаны идти по одной шкале, иначе горизонт тишины меряется чужой.
    let started = Instant::now();
    let seen = Arc::new(AtomicU64::new(0));
    let total_ns = Arc::new(AtomicU64::new(0));
    let slowest_ns = Arc::new(AtomicU64::new(0));
    let unparsed = Arc::new(AtomicU64::new(0));
    let fresh_ns = Arc::new(AtomicU64::new(0));
    let fresh_n = Arc::new(AtomicU64::new(0));
    let running_ns = Arc::new(AtomicU64::new(0));
    let running_n = Arc::new(AtomicU64::new(0));

    let watched = (
        plane.clone(),
        seen.clone(),
        total_ns.clone(),
        slowest_ns.clone(),
    );
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(2));
        report(&watched.0, &watched.1, &watched.2, &watched.3);
    });

    // Время идёт, даже когда пакетов нет (#323). Прежде плоскость двигалась только чужим пакетом, и
    // всё, что судит о тишине, в тишине не срабатывало — а мёртвая нога умирает, когда трафика нет.
    // Этот тред — недостающая половина: ничего не наблюдает, лишь сообщает, что время прошло. Часы
    // берутся примитивом, не пишутся заново (замер нашёл 17 мест, порождавших время самостоятельно).
    let ticked = (plane.clone(), started);
    std::thread::spawn(move || {
        use reflex_core::clock::Beats;
        reflex_core::clock::OsClock
            .beats(PULSE)
            .for_each(|_at| match ticked.0.lock() {
                Err(_poisoned) => (),
                Ok(mut held) => {
                    // Момент от того же начала, что и у пакетов: две шкалы на одном состоянии
                    // разошлись бы, горизонт тишины считался бы по чужой.
                    let told = held.tick(Tick(started.elapsed().as_nanos() as u64));
                    told.into_iter()
                        .for_each(|noted| println!("{}", named(&noted.what)));
                }
            });
    });

    // Снимок строки (цель × узел) — живым процессом, а не тестом (#320): `record()` звался только из
    // `tests/record.rs`, ни один живой процесс строку не строил, показ рисовал макет. Читает ядро
    // этот тред, а не горячий путь: дамп conntrack — сисколл и разбор netlink, цена не на пакете.
    let snapped = (plane.clone(), started);
    let where_snapshot =
        std::env::var("PLANE_SNAPSHOT").unwrap_or_else(|_| "/tmp/plane-queue.snapshot".into());
    std::thread::spawn(move || {
        use reflex_core::clock::Beats;
        reflex_core::clock::OsClock
            .beats(SNAPSHOT_EVERY)
            .for_each(|_at| {
                // Дамп берётся ДО лока: netlink-обмен занимает миллисекунды, держать на них лок
                // плоскости значило бы платить временем горячего пути за работу показа.
                let seen = match reflex_linux::conntrack::Dump::open() {
                    Err(_no_netlink) => Vec::new(),
                    Ok(dump) => dump.entries().unwrap_or_default(),
                };
                match snapped.0.lock() {
                    Err(_poisoned) => (),
                    Ok(held) => {
                        let snapshot = reflex_engine_nfq::record::as_lines(
                            &reflex_engine_nfq::record::record(&held, &seen, SERVER_PORT),
                            Tick(snapped.1.elapsed().as_nanos() as u64),
                        );
                        // Перезапись целиком: снимок есть СОСТОЯНИЕ, а не журнал. Дописывание
                        // заставило бы читателя искать конец и однажды прочесть половину.
                        let _ = std::fs::write(&where_snapshot, snapshot);
                    }
                }
            });
    });

    let snapshotted = plane.clone();
    let handled = seen.clone();
    let costs = (
        fresh_ns.clone(),
        fresh_n.clone(),
        running_ns.clone(),
        running_n.clone(),
    );
    let released = Arc::new(AtomicU64::new(0));
    let released_told = released.clone();
    let where_to = std::env::var("PLANE_STATE").unwrap_or_else(|_| "/tmp/plane-queue.state".into());
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(100));
        match snapshotted.lock() {
            Err(_poisoned) => (),
            Ok(held) => {
                // По меткам, а не суммой: метки ведут в разные места, сумма по ним не сверяется ни с
                // одним счётчиком ядра — сверяется величина ПО СВОЕЙ метке. Имена в состояние, а не
                // только в журнал: журнал печатает по таймеру, стенд спрашивает «видели ли», а
                // получает «печатали ли с тех пор» (так `lift-leak.sh` объявил красным исправное).
                let names = held
                    .names()
                    .iter()
                    .map(|(name, seen)| format!("name:{name}={seen}"))
                    .collect::<Vec<String>>()
                    .join(" ");
                let marks = held
                    .marked_packets()
                    .iter()
                    .map(|(mark, packets)| format!("mark_{mark:x}={packets}"))
                    .collect::<Vec<String>>()
                    .join(" ");
                let line = format!(
                    "fresh_ns={} fresh_n={} running_ns={} running_n={} handled={} released={} {} {} {}",
                    costs.0.load(Ordering::Relaxed),
                    costs.1.load(Ordering::Relaxed),
                    costs.2.load(Ordering::Relaxed),
                    costs.3.load(Ordering::Relaxed),
                    handled.load(Ordering::Relaxed),
                    released_told.load(Ordering::Relaxed),
                    held.snapshot(),
                    marks,
                    names
                );
                let _ = std::fs::write(&where_to, line);
            }
        }
    });

    eprintln!(
        "plane-queue: очередь={queue}, метка={INJECT_MARK:#x}\n\
         ВНИМАНИЕ: очередь без слушателя дропает весь трафик netns — правила снимайте ПЕРВЫМИ."
    );

    let shell = Shell {
        plane: plane.clone(),
        released: released.clone(),
        started,
        slowest_ns: slowest_ns.clone(),
        total_ns: total_ns.clone(),
        seen: seen.clone(),
        unparsed,
        fresh_ns: fresh_ns.clone(),
        fresh_n: fresh_n.clone(),
        running_ns: running_ns.clone(),
        running_n: running_n.clone(),
    };

    match NfqPipeline::bind(queue, INJECT_MARK, shell) {
        Err(why) => {
            eprintln!("очередь {queue} не открыта: {why}");
            std::process::exit(1);
        }
        Ok(mut pipeline) => {
            let ticking = pipeline.counts_handle();
            let where_to =
                std::env::var("PLANE_PIPE").unwrap_or_else(|_| "/tmp/plane-queue.pipe".to_string());
            std::thread::spawn(move || loop {
                std::thread::sleep(Duration::from_millis(100));
                let counts = ticking.snapshot();
                let _ = std::fs::write(
                    &where_to,
                    format!(
                        "received={} mark_skipped={} handed={} again={} failed={} blind={}\n",
                        counts.received,
                        counts.mark_skipped,
                        counts.handed,
                        counts.again,
                        counts.failed,
                        counts.blind
                    ),
                );
            });
            let deadline = std::env::var("PLANE_SECONDS")
                .ok()
                .and_then(|given| given.parse::<u64>().ok())
                .unwrap_or(3600);
            let until = Instant::now() + Duration::from_secs(deadline);
            let outcome = pipeline.run_while(|| Instant::now() < until);
            let counts = pipeline.counts();
            eprintln!(
                "[пайп] принято {} · замкнуто по метке {} · отдано обработчику {} · пусто {} · ошибок {}",
                counts.received, counts.mark_skipped, counts.handed, counts.again, counts.failed
            );
            match outcome {
                Ok(()) => eprintln!("очередь закрыта"),
                Err(why) => {
                    eprintln!("очередь упала: {why}");
                    std::process::exit(1);
                }
            }
        }
    }
    report(&plane, &seen, &total_ns, &slowest_ns);
}
