use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use reflex_engine::watch::Watch;
use reflex_engine::{Act, Addr, Basis, Interest, Mark, Noticed, Programme, Tick};
use reflex_engine_nfq::parse::{read, Read, SERVER_PORT};
use reflex_engine_nfq::plane::Plane;
use reflex_core::command::InjectablePacket;
use reflex_linux::nfqueue::{NfqHandler, NfqPacket, NfqPipeline, NfqVerdict};

const INJECT_MARK: u32 = 0xBB;
/// ШАГ СОБСТВЕННЫХ ЧАСОВ ПЛОСКОСТИ.
///
/// Сто миллисекунд — не замер, и это названо: величина взята от соседей (отчётчик и снимок
/// состояния тикают тем же шагом), а не выведена из темпа предмета. Реже — и потеря цели
/// заметится позже на весь шаг; чаще — тред будет брать лок горячего пути без нужды. Мерить
/// нужно долю тиков, на которых что-то произошло; пока такого замера нет.
const PULSE: Duration = Duration::from_millis(100);
/// ШАГ СНИМКА ДЛЯ ПОКАЗА. Реже часов намеренно: снимок стоит дампа conntrack (сисколл плюс разбор
/// netlink), а человек за таблицей не читает быстрее секунды. Величина взята от терпения
/// читателя, а не замерена, — и это названо: мерить надо долю снимков, между которыми что-то
/// изменилось.
const SNAPSHOT_EVERY: Duration = Duration::from_secs(1);
/// Метка ноги, которую ядро увидит на членах множества.
const MARK_LEG: u32 = 0xCC;
/// Имя множества в таблице стенда.
struct Shell {
    plane: Arc<Mutex<Plane>>,
    /// СКОЛЬКО РАЗГОВОРОВ ВЫПУЩЕНО ИЗ ГОРЯЧЕГО ПУТИ. Считается ПАКЕТАМИ, на которых выпуск
    /// состоялся: это верхняя граница того, сколько дороги в userspace мы перестанем платить, и
    /// сверяется она со счётчиком ядра, а не подменяет его.
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
    fn handle(&mut self, packet: &NfqPacket) -> (NfqVerdict, Vec<InjectablePacket>) {
        let entered = Instant::now();
        let injects: Vec<InjectablePacket> = Vec::new();
        let mut opened = false;
        self.seen.fetch_add(1, Ordering::Relaxed);
        let now = Tick(self.started.elapsed().as_nanos() as u64);

        let verdict = match read(&packet.payload, SERVER_PORT) {
            Read::Tcp(wire) => match self.plane.lock() {
                Err(_poisoned) => NfqVerdict::Accept,
                Ok(mut held) => {
                    held.offer();
                    let fed = held.feed(wire, now);
                    opened = fed.opened;
                    // ВЫПУСК РЕШАЕТ ЗАКОН, А НЕ ОБОЛОЧКА — и теперь это ВЫРАЖЕНО: решение
                    // приезжает готовым. Прежде оболочка сводила личность с вердиктом сама и
                    // могла взять личность чужого флоу.
                    match (fed.act, fed.watch) {
                        (_taken, Watch::Release(mark)) => {
                            self.released.fetch_add(1, Ordering::Relaxed);
                            NfqVerdict::AcceptMarked(mark.0)
                        }
                        (Act::Pass, Watch::Hold) => NfqVerdict::Accept,
                        (Act::Drop, Watch::Hold) => NfqVerdict::Drop,
                        // МЕТКА УХОДИТ ВЕРДИКТОМ. Прежде здесь стоял `Accept`, а адрес поднимался
                        // в множество ядра отдельным ходом — механизм, снятый `df7b3e78` за то, что
                        // применял знание ПО АДРЕСУ. Стенд мерил его ещё сегодня утром, то есть
                        // проверял путь, которого в продукте больше нет.
                        (Act::Marked(mark), Watch::Hold) => NfqVerdict::AcceptMarked(mark.0),
                        // ОБРЫВ ПОКА НЕ ИСПОЛНЯЕТСЯ НА ПРОВОДЕ, И ЭТО НАЗВАНО ВСЛУХ (#318).
                        //
                        // Закон обрыва построен и доказан в плоскости (`step`), а вот послать
                        // клиенту сброс оболочка ещё не умеет: нужен собранный TCP-RST с seq из
                        // состояния разговора, то есть инъекция, а не вердикт. Молча ронять
                        // пакет нельзя — `Drop` не говорит клиенту ничего, и человек ждёт до
                        // своего таймаута ровно как без нас.
                        //
                        // Пропускаем и СЧИТАЕМ: неисполненный приказ обязан быть величиной, а не
                        // тишиной. Тем же прибором, что ловил неисполненный `Divert`.
                        (Act::Sever, Watch::Hold) => {
                            held.note_unapplied("Sever");
                            NfqVerdict::Accept
                        }
                    }
                }
            },
            // ДАТАГРАММЫ ЧЕРЕЗ ЭТУ ОЧЕРЕДЬ НЕ ИДУТ: правило заворачивает только соединения.
            // Пришедшая сюда датаграмма значит, что правило разошлось с оболочкой, и считать её
            // «неразобранной» верно — разобрать-то мы её умеем, а вот ждать не ждали.
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
                NfqVerdict::Accept
            }
        };

        let spent = entered.elapsed().as_nanos() as u64;
        // ЦЕНА РАЗДЕЛЕНА ПО РОДУ РАБОТЫ. Новый разговор заводит курсор и цель — две вставки в
        // карты; продолжение только ищет. Смешав их, мы померим состав трафика, а не плоскость.
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

/// ОТРАЖЕНИЕ РЕШЕНИЯ В ЯДРО. Адрес кладётся в `nft`-множество, и дальше заворачивает ЯДРО своими
/// правилами — плоскость таких пакетов больше не видит вовсе. Запуск `nft` на каждый адрес
/// законен потому, что адресов единицы и появляются они в темпе смены знания, а не пакета.

/// ИМЯ НАБЛЮДЕНИЯ БЕРЁТСЯ У ТИПА, а не считается здесь во второй раз.
///
/// Прежде тут стоял свой перевод русскими словами для журнала, а паспорт отдавал наружу одно имя
/// на все исходы. Два перевода одного предмета расходятся молча — и разошлись бы в первый же день,
/// когда у наблюдения появилась новая буква: журнал бы её назвал, реестр событий нет.
///
/// Слова двух областей названы каждое своим держателем имени: наблюдения разговора — паспортом
/// прибора, потеря цели — самим типом. Ни одно имя не написано здесь.
fn named(told: &Noticed) -> &'static str {
    match told {
        Noticed::Talk(sighting) => {
            <reflex_engine::SightingInstrument as reflex_instrument::Instrument>::name(sighting)
        }
        Noticed::Loss(_lost) => reflex_engine::Lost::EVENT,
    }
}

/// Сужение для замера: имя берётся как есть. Целей с именами этот прибор не наблюдает.
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

    // ЧТО ВЕСТИ НОГОЙ — задаётся снаружи: знание о среде край не выдумывает. Пусто — плоскость
    // никого не метит, и это законный вырожденный случай, а не отказ.
    let leg = std::env::var("PLANE_MARK").unwrap_or_default();
    // ПРИБОР ЦЕНЫ ЦЕЛИ ЗНАЕТ ТОЛЬКО АДРЕСА: засев синтетический, имён на проводе нет. Оттого
    // сужение — тождество, и это СКАЗАНО, а не умолчано: предмет здесь таблица, а не ключ.
    let plane = Arc::new(Mutex::new(Plane::new(Programme::Pass, as_seen)));
    // РАЗБОР, КОТОРЫЙ МОЛЧА ОТБРАСЫВАЕТ, ВРЁТ: оболочка печатала «помечаем 2606:...» и не метила
    // никого — `getent` отдал IPv6, а плоскость знает четыре байта (#299). Теперь отказ ГРОМКИЙ.
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
    // ЗАСЕВ ЗНАНИЯ ДЛЯ ЗАМЕРА (#300, утверждение 3). Цена на пакет обязана быть O(1) по ОБЪЁМУ
    // знания, и проверить это можно, лишь сравнив прогоны с разной таблицей. Адреса синтетические
    // и трафика к ним нет — предмет замера здесь ТАБЛИЦА, а не цели.
    let seeded: u32 = std::env::var("PLANE_SEED")
        .ok()
        .and_then(|given| given.parse().ok())
        .unwrap_or(0);
    (0..seeded).for_each(|i| match plane.lock() {
        Err(_poisoned) => (),
        // ЗАСЕВУ НАБЛЮДЕНИЕ НЕ НУЖНО: трафика к этим адресам нет, предмет замера — таблица.
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
    // НАЧАЛО ОТСЧЁТА ОДНО НА ВСЕХ, и заводится оно здесь, а не внутри обработчика: время у
    // пакетов и время у тика обязаны идти по одной шкале, иначе горизонт тишины меряется чужой.
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

    // ВРЕМЯ ИДЁТ, ДАЖЕ КОГДА ПАКЕТОВ НЕТ (#323).
    //
    // Прежде плоскость двигалась ТОЛЬКО чужим пакетом: `Tick` вычислялся внутри обработчика.
    // Значит всё, что судит о ТИШИНЕ, в тишине и не срабатывало — а мёртвая нога умирает ровно
    // тогда, когда трафика нет. Этот тред и есть недостающая половина: он ничего не наблюдает,
    // он лишь сообщает плоскости, что время прошло.
    //
    // ЧАСЫ БЕРУТСЯ ПРИМИТИВОМ, А НЕ ПИШУТСЯ ЗДЕСЬ ЗАНОВО. Замер 03.09 нашёл семнадцать мест,
    // порождавших время самостоятельно, в пяти формах; шестая встала бы сюда.
    let ticked = (plane.clone(), started);
    std::thread::spawn(move || {
        use reflex_core::clock::Beats;
        reflex_core::clock::OsClock
            .beats(PULSE)
            .for_each(|_at| match ticked.0.lock() {
                Err(_poisoned) => (),
                Ok(mut held) => {
                    // МОМЕНТ БЕРЁТСЯ ОТ ТОГО ЖЕ НАЧАЛА, что и у пакетов: две шкалы времени на
                    // одном состоянии разошлись бы, и горизонт тишины считался бы по чужой.
                    let told = held.tick(Tick(started.elapsed().as_nanos() as u64));
                    told.into_iter()
                        .for_each(|noted| println!("{}", named(&noted.what)));
                }
            });
    });

    // СНИМОК СТРОКИ (ЦЕЛЬ × УЗЕЛ) — ЖИВЫМ ПРОЦЕССОМ, А НЕ ТЕСТОМ (#320).
    //
    // `record()` до сегодня звался ТОЛЬКО из `tests/record.rs`: закон сборки строки существовал,
    // и ни один живой процесс её не строил. Показ при этом рисовал макет — то есть человек видел
    // не свою коробку, а наши выдумки. Ровно то, за что эпик и заведён: механизм построен,
    // читателя нет, и снаружи это неотличимо от работающего.
    //
    // ЧИТАЕТ ЯДРО ЭТОТ ТРЕД, А НЕ ГОРЯЧИЙ ПУТЬ: дамп conntrack — сисколл и разбор netlink, цена
    // которых не должна лежать на пакете человека. Темп снимка — свой, не трафика.
    let snapped = (plane.clone(), started);
    let where_snapshot =
        std::env::var("PLANE_SNAPSHOT").unwrap_or_else(|_| "/tmp/plane-queue.snapshot".into());
    std::thread::spawn(move || {
        use reflex_core::clock::Beats;
        reflex_core::clock::OsClock
            .beats(SNAPSHOT_EVERY)
            .for_each(|_at| {
                // ДАМП БЕРЁТСЯ ДО ЛОКА, а не под ним: netlink-обмен занимает миллисекунды, и
                // держать на них лок плоскости значило бы платить временем горячего пути за
                // работу показа.
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
                        // ПЕРЕЗАПИСЬ ЦЕЛИКОМ: снимок есть СОСТОЯНИЕ, а не журнал. Дописывание
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
                // ПО МЕТКАМ, А НЕ СУММОЙ: метки ведут в разные места, и сумма по ним не
                // сверяется ни с одним счётчиком ядра — сверяется величина ПО СВОЕЙ метке.
                // ИМЕНА В СОСТОЯНИЕ, А НЕ ТОЛЬКО В ЖУРНАЛ. Журнал печатает их по таймеру, и стенд,
                // читающий его, спрашивает «видели ли», а получает «печатали ли с тех пор». Так
                // `lift-leak.sh` объявил КРАСНЫМ исправный механизм.
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
