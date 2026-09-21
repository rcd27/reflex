//! ВЕДУЩИЙ ЦИКЛ на бумажном носителе — здесь и только здесь петля проверяется как петля.
//!
//! Зелёный парк тестов о ней не говорит ничего: оба регресса переезда — невидимый `SYN` и
//! блокирующий приём, останавливавший тики ровно тогда, когда наступало молчание, — нашли
//! стенды, а не прогон. Риск живёт в петле, значит и проверка обязана стоять в ней.
//!
//! Строки таблицы шва (`.superpowers/sdd/2026-09-10-carrier-functor/t8-seam-table.md`) названы у
//! каждого теста: таблицу писал тот, кто её не реализует, и покрытие сверяется по ней, а не по
//! памяти реализатора.

mod paper;

use std::time::Duration;

use paper::{
    alien, log, names, request, syn, taken, truncated, Crier, Letter, Paper, PaperAnswer, Recorder,
    Ticker,
};
use reflex::*;

/// ЧЕЙ ПУТЬ НЕСЁТ РАЗГОВОР — алфавит этой приёмки, объявленный один раз.
///
/// Марка `0x0300` сама по себе не значит ничего: биты обретают смысл только вместе с разметкой.
/// Объявив её здесь, приёмка читает край той же дверью, что и продукт.
enum Path {
    /// Разговор идёт путём, о котором приёмка и говорит.
    Ours,
    /// Любой другой путь, включая непомеченный.
    Other,
}

impl Meaning for Path {
    const REGION: Region = Region::declared(0xFFFF);

    /// Тотально и без wildcard: новое значение области не проскочит молча.
    fn read(value: u32) -> Path {
        match value {
            0x0300 => Path::Ours,
            0..=0x02FF | 0x0301..=u32::MAX => Path::Other,
        }
    }
}

/// Сколько узлов сетки укладывается в секунду тишины. ВЫЧИСЛЯЕТСЯ из [`TICK`] фасада, а не пишется
/// числом: своё число было бы вторым описанием одной величины и разошлось бы с первым молча.
const NODES_IN_A_SECOND: usize = (1000 / TICK.as_millis()) as usize;

/// Сколько раз имя встретилось среди дошедших букв.
fn how_many(seen: &[String], name: &str) -> usize {
    seen.iter().filter(|letter| *letter == name).count()
}

// ─── A. Молчание и часы ───────────────────────────────────────────────────────────────────────

/// A1. ТИШИНА ДОХОДИТ УЗЛАМИ. Здесь виден вчерашний блокирующий приём: он давал ноль букв вместо
/// пяти, и приборы молчания замирали ровно тогда, когда молчание наступало (§9.3).
#[test]
fn the_silence_of_a_live_conversation_arrives_as_nodes_of_the_grid() {
    let seen = log::<Letter>();
    let paper = Paper::new()
        .then_packet(request(40001))
        .silent_for(Duration::from_secs(1))
        .then_stop();

    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(Recorder::into(seen))
        .on(|_target, _distress| {})
        .run();

    assert_eq!(
        names(seen),
        ["packet", "tick", "tick", "tick", "tick", "tick"],
        "секунда тишины — пять узлов живой машине"
    );
}

/// A2. НАРУШИТЕЛЬ ЗАКОНА СРОКА цикл не ломает — но платит.
///
/// Момент безответного исхода цикл берёт у СРОКА, о котором просил, а не у часов (см. докблок
/// `Running::run`). Оттого носитель, вернувшийся раньше срока, гонит сетку впереди СВОИХ часов:
/// узлов выходит больше, чем у него прошло времени. Таблица шва ждала здесь «те же пять узлов за
/// много оборотов» — это верно для цикла, спрашивающего часы; наш берёт срок, и цена нарушения
/// выглядит иначе. Названа она здесь, а не замолчана.
#[test]
fn a_carrier_that_breaks_the_deadline_drives_the_grid_ahead_of_its_own_clock() {
    let honest = log::<Letter>();
    let hasty = log::<Letter>();
    let scenario = || {
        Paper::new()
            .then_packet(request(40001))
            .silent_for(Duration::from_secs(1))
            .then_stop()
    };

    let paper = scenario();
    let turns_honest = paper.turns();
    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(Recorder::into(honest))
        .on(|_, _| {})
        .run();

    let paper = scenario().hasty();
    let turns_hasty = paper.turns();
    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(Recorder::into(hasty))
        .on(|_, _| {})
        .run();

    let honest = names(honest);
    let hasty = names(hasty);
    assert_eq!(how_many(&honest, "tick"), NODES_IN_A_SECOND);
    assert!(
        how_many(&hasty, "tick") > NODES_IN_A_SECOND,
        "сетка ушла вперёд часов нарушителя: {hasty:?}"
    );
    assert!(
        turns_hasty.load(std::sync::atomic::Ordering::SeqCst)
            > turns_honest.load(std::sync::atomic::Ordering::SeqCst),
        "оборотов у нарушителя больше — это и есть сожжённое ядро"
    );
}

/// A3. СЛЕПОЙ НОСИТЕЛЬ ЧАСОВ НЕ ОСТАНАВЛИВАЕТ. `Blind` — «ждать не на чем», а не «времени нет»:
/// узлы наступают, и приборы молчания судят по ним же.
#[test]
fn the_blindness_of_the_carrier_does_not_stop_the_grid() {
    let seen = log::<Letter>();
    let paper = Paper::new()
        .then_packet(request(40001))
        .silent_for(Duration::from_secs(1))
        .then_stop()
        .blindfolded();

    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(Recorder::into(seen))
        .on(|_, _| {})
        .run();

    assert_eq!(how_many(&names(seen), "tick"), NODES_IN_A_SECOND);
}

/// A4. УЗЕЛ ЕЩЁ НЕ НАСТУПИЛ — пакет идёт один. Пустой список узлов есть законный выход сетки, и
/// пустая рассылка не обязана ни завести машину, ни тронуть слой.
#[test]
fn no_node_has_come_so_the_packet_goes_alone() {
    let seen = log::<Letter>();
    let paper = Paper::new()
        .silent_for(Duration::ZERO)
        .then_packet(request(40001))
        .then_stop();

    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(Recorder::into(seen))
        .on(|_, _| {})
        .run();

    assert_eq!(names(seen), ["packet"]);
}

// ─── B. Порядок букв ──────────────────────────────────────────────────────────────────────────

/// B1. ПЕРЕШАГНУТЫЕ УЗЛЫ ДОХОДЯТ ДО ПРИБОРА РАНЬШЕ ПАКЕТА. Гони фасад всю пачку, а тик смотри
/// после неё — детектор увидит пакет раньше закрытия окна, в которое пакет не попал, и отнесёт его
/// байты не к тому окну (§8, дословно).
///
/// Узлы здесь рождает САМ ПАКЕТ (`Interleave::saw`), а не тишина: носитель отдаёт его с моментом
/// за пятью узлами — так бывает, когда приборы медленнее сетки и срок прошёл до вызова. Возьми
/// сценарий с тишиной, и те же пять узлов пришли бы безответным исходом, а порядок внутри `saw`
/// остался бы непроверенным.
#[test]
fn the_nodes_a_packet_stepped_over_reach_the_instrument_before_it() {
    let seen = log::<Letter>();
    let paper = Paper::new()
        .then_packet(request(40001))
        .then_packet_after(Duration::from_secs(1), request(40001))
        .then_stop();

    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(Recorder::into(seen))
        .on(|_, _| {})
        .run();

    assert_eq!(
        names(seen),
        ["packet", "tick", "tick", "tick", "tick", "tick", "packet"],
        "узлы, которые пакет перешагнул, выходят ПЕРЕД ним"
    );
}

/// B2. ЧУЖОЙ КАДР ДВИГАЕТ СЕТКУ, но до приборов не доходит. Иначе поток чужого трафика выглядел бы
/// тишиной, и приборы молчания подтверждали бы дроп на живой машине.
///
/// Узлы и здесь рождает МОМЕНТ КАДРА, не тишина: тишины в сценарии нет вовсе, и потому пять узлов
/// могут прийти только от чужого кадра — иначе их не будет ни одного.
#[test]
fn a_foreign_frame_moves_the_grid_but_never_reaches_the_instruments() {
    let seen = log::<Letter>();
    let paper = Paper::new()
        .then_packet(request(40001))
        .then_packet_after(Duration::from_secs(1), alien())
        .then_stop();

    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(Recorder::into(seen))
        .on(|_, _| {})
        .run();

    assert_eq!(
        names(seen),
        ["packet", "tick", "tick", "tick", "tick", "tick"],
        "чужой кадр до прибора не дошёл, а узлы — дошли"
    );
}

/// B2½. ОБРЕЗАННЫЙ КАДР ДОХОДИТ ДО ПРИБОРОВ БУКВОЙ, А НЕ ТИШИНОЙ.
///
/// Половина закона Д7 была недостижима от носителя: `Transport::observe` отдавал `Option` и
/// схлопывал «не мой транспорт» с «кадр обрезан» в один `None`, а цикл отвечал на `None` вызовом
/// `Interleave::idle`. Следствия были два и оба тихие: буква `Opaque { why: Truncated }` через
/// фасад не рождалась НИ РАЗУ (работа пяти приборов по прячущей букве не срабатывала никогда), а
/// сам обрезанный кадр ДВИГАЛ часы тишины — то есть кадр, спрятавший ответ цели, работал
/// свидетельством её молчания.
///
/// Здесь оба следствия и проверяются: буква приходит, и приходит С ПРИЧИНОЙ. Пара этому тесту —
/// B2 (`a_foreign_frame_moves_the_grid_but_never_reaches_the_instruments`): без неё правка прошла бы и на «всякий
/// неразобранный кадр объявлять потерей», а тогда прибор слеп бы на чужом трафике — онемел зря.
///
/// Мутация: вернуть в `Tcp::observe` для `Read::Truncated` ответ `Observation::Foreign` — тест
/// краснеет, `opaque:Truncated` пропадает и остаётся один узел сетки на его месте.
#[test]
fn a_truncated_frame_arrives_as_a_letter_with_a_reason_and_not_as_silence() {
    let seen = log::<Letter>();
    let paper = Paper::new()
        .then_packet(request(40001))
        .then_packet_after(Duration::from_secs(1), truncated())
        .then_stop();

    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(Recorder::into(seen))
        .on(|_, _| {})
        .run();

    assert_eq!(
        names(seen),
        [
            "packet",
            "tick",
            "tick",
            "tick",
            "tick",
            "tick",
            "opaque:Truncated"
        ],
        "узлы вышли ПЕРЕД буквой потери, а сама потеря дошла до прибора названной"
    );
}

/// B3. УЗЛЫ ВЫХОДЯТ ПЕРЕД ДЫРОЙ — порядок держит конструкция шва, а не дисциплина зовущего.
#[test]
fn the_nodes_come_out_before_the_hole() {
    let seen = log::<Letter>();
    let paper = Paper::new()
        .then_packet(request(40001))
        .then_tear_after(Duration::from_secs(1))
        .then_stop();

    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(Recorder::into(seen))
        .on(|_, _| {})
        .run();

    assert_eq!(
        names(seen),
        ["packet", "tick", "tick", "tick", "tick", "tick", "torn"]
    );
}

/// B4. ДВА ПАКЕТА ОДНОГО ОКНА не разделяются узлом. Строка отрицательная: лишний узел здесь значил
/// бы, что узлы порождаются оборотом цикла, а не временем.
#[test]
fn two_packets_of_one_window_are_not_split_apart_by_a_node() {
    let seen = log::<Letter>();
    let paper = Paper::new()
        .then_packet(request(40001))
        .then_packet(request(40001))
        .then_stop();

    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(Recorder::into(seen))
        .on(|_, _| {})
        .run();

    assert_eq!(names(seen), ["packet", "packet"]);
}

// ─── C. Адрес буквы ───────────────────────────────────────────────────────────────────────────

/// C1. ПАКЕТ — ОДНОЙ МАШИНЕ, УЗЕЛ — КАЖДОЙ. Адрес выводится из того, чей это разговор, а не из
/// ветки цикла: два живых разговора дают на каждый узел по две буквы, а на пакет — одну.
#[test]
fn a_packet_goes_to_its_own_machine_and_a_node_goes_to_every_one() {
    let seen = log::<Letter>();
    let paper = Paper::new()
        .then_packet(request(40001))
        .then_packet(request(40002))
        .silent_for(Duration::from_secs(1))
        .then_stop();

    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(Recorder::into(seen))
        .on(|_, _| {})
        .run();

    let seen = names(seen);
    assert_eq!(how_many(&seen, "packet"), 2, "каждый пакет — одной машине");
    assert_eq!(
        how_many(&seen, "tick"),
        2 * NODES_IN_A_SECOND,
        "каждый узел — обеим живым машинам"
    );
}

/// C2. ДЫРА ДОХОДИТ ДО КАЖДОЙ ЖИВОЙ МАШИНЫ, как узел. Адреса у неё нет по существу: носитель
/// объявляет потерю на всю очередь, и приписать её одному разговору значило бы соврать об
/// остальных.
#[test]
fn a_hole_reaches_every_live_machine() {
    let seen = log::<Letter>();
    let paper = Paper::new()
        .then_packet(request(40001))
        .then_packet(request(40002))
        .then_tear()
        .then_stop();

    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(Recorder::into(seen))
        .on(|_, _| {})
        .run();

    assert_eq!(how_many(&names(seen), "torn"), 2);
}

/// C3. ДЫРА БЕЗ ЖИВЫХ МАШИН — ноль букв, и это не ошибка: непонятое некому адресовать. Рассылка по
/// пустой таблице не падает и машины «на всякий случай» не заводит.
#[test]
fn a_hole_with_no_live_machines_starts_no_machine() {
    let seen = log::<Letter>();
    let paper = Paper::new().then_tear().then_stop();

    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(Recorder::into(seen))
        .on(|_, _| {})
        .run();

    assert!(names(seen).is_empty(), "адресовать было некому");
}

// ─── D. Вердикт и памятка ─────────────────────────────────────────────────────────────────────

/// D1. МОЛЧАЩИЙ ПРИБОР ВСЁ РАВНО ОТПУСКАЕТ ПАКЕТ. «Отпустить» — тоже ответ: пакет без вердикта
/// висит в очереди ядра до её собственного срока.
#[test]
fn a_silent_instrument_still_releases_the_packet() {
    let seen = log::<Letter>();
    let paper = Paper::new().then_packet(request(40001)).then_stop();
    let applied = paper.applied();

    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(Recorder::into(seen))
        .on(|_, _| {})
        .run();

    assert_eq!(taken(applied), [PaperAnswer::Pass]);
}

/// D2. ПАМЯТКА ДОЕЗЖАЕТ ДО ТЕРМИНАЛА ОДНИМ СЛОВОМ С ВЕРДИКТОМ (§5: «отпустить и запомнить»
/// неделимо) — и доезжает ЧЕРЕЗ `Terminal::apply`, а не мимо него. Перепиши фасад таблицу
/// `Answer → (accept, state)` руками — она заживёт в двух копиях при зелёной сборке.
#[test]
fn the_remembering_reaches_the_terminal_in_one_word_with_the_verdict() {
    let paper = Paper::new().then_packet(syn(40001)).then_stop();
    let applied = paper.applied();

    // Пример краевого писателя памятки — `Silence`: `SynDrop` проводной и в марку не пишет.
    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(Silence::after(Duration::from_secs(1)))
        .on(|_, _| {})
        .run();

    assert!(
        matches!(
            taken(applied).as_slice(),
            [PaperAnswer::Remembered { accept: true, .. }]
        ),
        "{:?}",
        taken(applied)
    );
}

/// D1-бис. КРАЯ НЕТ — ПАМЯТКИ НЕТ, и марку не трогаем вовсе. Клетка §7: «не считали» — не «не
/// ответила»; выдумать фазу разговора, которого край ещё не видит, значило бы записать в носитель
/// знание, которого нет.
#[test]
fn without_an_edge_no_remembering_is_born() {
    let paper = Paper::new()
        .edging(None)
        .then_packet(syn(40001))
        .then_stop();
    let applied = paper.applied();

    // Краевой пример — `Silence`: `SynDrop` с 14.09.2026 проводной, и памятки не пишет вовсе.
    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(Silence::after(Duration::from_secs(1)))
        .on(|_, _| {})
        .run();

    assert_eq!(taken(applied), [PaperAnswer::Pass], "запоминать нечего");
}

/// D2-бис. ПОВТОР СТУКА БЕЗ РУКОПОЖАТИЯ ДОХОДИТ ДО ПРИБОРА ТОГО ЖЕ РАЗГОВОРА И НАЗЫВАЕТСЯ.
///
/// Прибор (`SynDropInstrument`) проверен в изоляции, фасад — только на одиночном стуке. Клетка
/// «второй `SYN` той же четвёрки через всю цепочку» не проверялась ничем — и ровно она немая на
/// живом носителе:
/// поле, 14.09.2026, 194 разговора дома к дата-центрам Телеграма в `SYN_SENT`, очередь ловушки
/// приняла 11 454 стука, ни одного `Blackhole`.
#[test]
fn a_repeated_syn_without_handshake_is_named_blackhole_through_the_facade() {
    let (said, heard) = std::sync::mpsc::sync_channel::<Distress>(8);
    let paper = Paper::new()
        .then_packet(syn(40001))
        .then_packet_after(Duration::from_secs(1), syn(40001))
        .then_stop();

    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(SynDrop::unreachable())
        .on(move |_target, distress| {
            let _sent = said.try_send(distress);
        })
        .run();

    let words: Vec<Distress> = heard.try_iter().collect();
    assert!(
        words
            .iter()
            .any(|word| matches!(word, Distress::Blackhole { .. })),
        "повтор SYN без рукопожатия прошёл фасад и не назван: {words:?}"
    );
}

/// D2-тер. ПОВТОР СТУКА НАЗЫВАЕТСЯ И БЕЗ КРАЯ — ТАК УСТРОЕНА МАШИНА.
///
/// Ядро боевой машины (OpenWrt 6.12.71) собрано без `CONFIG_NF_CONNTRACK_TIMESTAMP`: возраста потока у
/// края нет, а краевой `EdgeSilence` без возраста приговора не выносит никогда. На ловушке SYN это
/// давало немоту по построению — 11 454 стука к дата-центрам Телеграма, ни одного `Blackhole`
/// (14.09.2026). Повтор стука виден по НАШИМ часам, край ему не нужен.
#[test]
fn a_repeated_syn_without_an_edge_is_still_named_blackhole() {
    let (said, heard) = std::sync::mpsc::sync_channel::<Distress>(8);
    let paper = Paper::new()
        .edging(None)
        .then_packet(syn(40001))
        .then_packet_after(Duration::from_secs(1), syn(40001))
        .then_stop();

    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(SynDrop::unreachable())
        .on(move |_target, distress| {
            let _sent = said.try_send(distress);
        })
        .run();

    let words: Vec<Distress> = heard.try_iter().collect();
    assert!(
        words
            .iter()
            .any(|word| matches!(word, Distress::Blackhole { .. })),
        "без края повтор SYN не назван: {words:?}"
    );
}

/// D3. ОТКАЗ ВЕРДИКТА не отменяет прошедших букв: приборы уже посчитали пакет. Цена названа в
/// докблоке `Running::run` обеими половинами — здесь проверяется лишь то, что цикл жив и буквы не
/// потеряны.
#[test]
fn a_refused_verdict_does_not_cancel_the_letters_that_already_passed() {
    let seen = log::<Letter>();
    // Второй пакет ПОСЛЕ отказанного — иначе «цикл жив» не проверялось бы ничем: сценарий кончался
    // на отказе, и выход из петли по отказу выглядел бы точно так же, как продолжение.
    let paper = Paper::new()
        .then_packet(request(40001))
        .then_packet(request(40001))
        .then_stop()
        .refusing();

    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(Recorder::into(seen))
        .on(|_, _| {})
        .run();

    assert_eq!(
        names(seen),
        ["packet", "packet"],
        "буквы прошли до отказа, и отказ цикла не остановил"
    );
}

// ─── E. Конец и края ──────────────────────────────────────────────────────────────────────────

/// E1. УЗЛЫ ПОСЛЕ КОНЦА СЦЕНАРИЯ НЕ ВЫХОДЯТ — граница, а не недоделка. Часы носителя ушли на
/// секунду вперёд, но выдавать эти узлы некому: машина, которой они адресованы, больше не получит
/// ни одного пакета, а момент, в который нам случилось заметить конец, наблюдением не является.
#[test]
fn no_nodes_come_out_after_the_scenario_has_ended() {
    let seen = log::<Letter>();
    let paper = Paper::new()
        .then_packet(request(40001))
        .then_stop_after(Duration::from_secs(1));

    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(Recorder::into(seen))
        .on(|_, _| {})
        .run();

    assert_eq!(names(seen), ["packet"]);
}

/// E2. ДЫРА НЕСЁТ МОМЕНТ ОБНАРУЖЕНИЯ — и момент этот принадлежит НОСИТЕЛЮ, не часам цикла.
/// Потери момента не существует нигде: ядро выбросило сообщения раньше, чем мы позвали приём, и
/// `ENOBUFS` не несёт ни числа потерянных, ни времени. Обнаружение же знает ровно тот, кто
/// обнаружил, — и говорит его в самом исходе (`Served::Torn`).
///
/// Проверяется ВЕЛИЧИНОЙ, а не неравенством с последней буквой: то неравенство держал зажим шва
/// (`at.max(last)`) и оно было истинно при ЛЮБОМ поданном моменте, то есть не могло покраснеть.
#[test]
fn a_hole_carries_the_moment_of_the_carrier_and_not_the_clock_of_the_loop() {
    let seen = log::<Letter>();
    let paper = Paper::new()
        .then_packet(request(40001))
        .then_tear_after(Duration::from_secs(1))
        .then_stop();

    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(Recorder::into(seen))
        .on(|_, _| {})
        .run();

    let letters = taken(seen);
    let packet = letters.first().expect("пакет дошёл");
    let torn = letters.last().expect("дыра дошла");
    assert_eq!(torn.name, "torn");
    let waited = torn.at.duration_since(packet.at);
    assert!(
        waited >= Duration::from_secs(1) && waited < Duration::from_millis(1100),
        "дыра объявлена через секунду ПО ЧАСАМ НОСИТЕЛЯ, а не когда цикл заметил: {waited:?}"
    );
}

/// E3. НОСИТЕЛЬ НЕ ОТКРЫЛСЯ — цикл не начат, и это отдельный исход от «начат и ничего не увидел»
/// (§7: «не смотрели» ≠ «смотрели и пусто»).
#[test]
fn the_carrier_did_not_open_so_the_loop_never_started() {
    let seen = log::<Letter>();
    let paper = Paper::new()
        .then_packet(request(40001))
        .then_stop()
        .shut("нет базы таймаутов");

    let report = engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(Recorder::into(seen))
        .on(|_, _| {})
        .run();

    assert!(names(seen).is_empty(), "не смотрели вовсе");
    assert_eq!(report.why(), Some("нет базы таймаутов"));
}

// ─── Сверх таблицы: терминал ДЕЙСТВИЯ ─────────────────────────────────────────────────────────

/// `.act` ходит ТЕМ ЖЕ ЦИКЛОМ и отдаёт команду НОСИТЕЛЮ, а не своему сокету мимо него (§9.4).
/// Строки в таблице шва на это нет: свой цикл у действия проверять нечем, и потому он расходится
/// с наблюдающим молча — не знает ни ленты, ни дыры, ни слова о цели.
#[test]
fn a_sever_leaves_through_the_sink_of_the_carrier_and_not_past_it() {
    let paper = Paper::new().then_packet(request(40001)).then_stop();
    let injected = paper.injected();

    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(Crier::always())
        .act(|_, _| Act::sever())
        .run();

    assert_eq!(
        taken(injected).len(),
        1,
        "обрыв уехал командой в сток носителя"
    );
}

// ─── Правки по ревью: адрес улики, слово о цели, эпоха часов ──────────────────────────────────

/// УЛИКА ЕДЕТ ВМЕСТЕ С АДРЕСОМ. Слово, рождённое УЗЛОМ СЕТКИ, носителя не имеет — рвать ему нечем.
///
/// Гони `walk` все буквы оборота с байтами пакета, привезённого этим оборотом, — и узел,
/// разосланный КАЖДОЙ живой машине, получит улику ЧУЖОГО разговора: `Act::sever()` по слову
/// прибора B порвёт разговор A, который ни в чём не бедствовал. Штатными приборами недостижимо
/// (они на узле молчат), достижимо через `own(…)` — публичную дверь, которой мы хвалимся. Слово
/// необратимо, потому закон держит конструкция, а не молчание приборов.
#[test]
fn a_word_born_on_a_node_carries_no_evidence_and_has_nothing_to_sever_with() {
    let paper = Paper::new()
        .then_packet(request(40001))
        .then_packet_after(Duration::from_secs(1), request(40001))
        .then_stop();
    let injected = paper.injected();

    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(Ticker::always()) // кричит ТОЛЬКО на узле
        .act(|_, _| Act::sever())
        .run();

    assert!(
        taken(injected).is_empty(),
        "пять узлов сказали пять слов — и ни одно не оборвало чужой разговор"
    );
}

/// СЛОВО О ЦЕЛИ РОЖДАЕТСЯ НА КАЖДОМ ЗАКРЫТОМ УЗЛЕ, а не раз за оборот.
///
/// Пакет штатно перешагивает несколько узлов; зови свёртку раз за оборот — число слов о цели
/// зависело бы от того, как носитель сбил работу в пачки, то есть от входа вне алфавита машины.
/// Это ровно то, что ловит §10, и зеркало переигровки (`replay`) зовёт свёртку именно так.
#[test]
fn a_word_about_the_target_is_born_on_every_closed_node() {
    let said = log::<String>();
    let paper = Paper::new()
        .then_packet(request(40001))
        .then_packet_after(Duration::from_secs(1), request(40001))
        .then_stop();

    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(Ticker::always())
        .about(|words| words.first().map(|distress| (*distress).clone()))
        .on_target(move |target, _voiced| {
            said.lock()
                .expect("журнал не отравлен")
                .push(target.to_string())
        })
        .on(|_, _| {})
        .run();

    assert_eq!(
        taken(said).len(),
        NODES_IN_A_SECOND,
        "пять закрытых узлов — пять слов о цели"
    );
}

/// СЕТКА ОТМЕРЯЕТСЯ ОТ ПЕРВОГО НАБЛЮДЕНИЯ, а не от часов цикла.
///
/// Часы носителя и часы цикла — разные эпохи (записанный провод, стенд, чужая ОС). Носитель, чья
/// эпоха ПОЗАДИ нашей, ловит сетку от наших часов в зажим `at.max(last)`: все его моменты
/// схлопываются в момент запуска, сетка не двигается — и тишина перестаёт наблюдаться ровно тогда,
/// когда наступила. Тот же вчерашний регресс, только другой дорогой.
///
/// Обратная эпоха (носитель ВПЕРЕДИ) даёт залп узлов на первом наблюдении; до приборов он не
/// доходит — машин в этот момент ещё нет, — и стоит поэтому работы и мусора в ленте, а не ложных
/// показаний. Этим тестом он НЕ покрыт, и сказано об этом здесь, а не умолчано.
#[test]
fn the_grid_is_measured_from_the_first_observation_and_not_from_the_clock_of_the_loop() {
    let seen = log::<Letter>();
    let paper = Paper::new()
        .clock_behind(Duration::from_secs(60))
        .then_packet(request(40001))
        .silent_for(Duration::from_secs(1))
        .then_stop();

    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(Recorder::into(seen))
        .on(|_, _| {})
        .run();

    assert_eq!(
        how_many(&names(seen), "tick"),
        NODES_IN_A_SECOND,
        "секунда тишины носителя из прошлой эпохи — те же пять узлов"
    );
}

/// ПРЕДМЕТ: реакция ДЕЙСТВИЯ умеет взять адрес целиком — и решить по признаку ядра, а не по имени.
///
/// Асимметрия была такая: у наблюдения две формы одной двери (`.on(|target, слово|)` и
/// `.on_addressed(|whom, слово|)`), а у действия — только первая. Между тем именно действию адрес
/// нужнее: `Act::sever()` рвёт разговор, и рвать его надо по тому, ЧТО ядро говорит об этом
/// разговоре, а не по тому, как называется цель.
///
/// Заказано замером потребителя (19.09.2026): обрыв обязан случиться только на разговоре, идущем
/// под маркой лечения; беда на разговоре, идущем другим путём, — беда того пути, и рвать там
/// нечего. Признак (`Counted.mark`) приходит с каждой буквой и до реакции действия не доезжал.
///
/// Без этой двери потребителю оставалось держать свою карту «цель → план» и смотреть в неё — то
/// есть завести ВТОРОЙ источник правды о том, что ядро и так говорит на каждом пакете.
#[test]
fn an_acting_reaction_can_decide_by_the_mark_the_kernel_shows() {
    let severed = |mark: u32| -> usize {
        let paper = Paper::new()
            .edging(Some(paper::PaperEdge {
                mark,
                ..paper::PaperEdge::default()
            }))
            .then_packet(request(40001))
            .then_stop();
        let injected = paper.injected();

        engine(paper)
            .from(Tcp)
            .extract(Sni)
            .detect(Crier::always())
            .act_addressed(|whom: Whom<'_>, _distress: Distress| {
                // Признак берётся У ЯДРА там же, где принимается решение, и читается ОБЪЯВЛЕННЫМ
                // алфавитом: сырые биты значат разное смотря по разметке, и сравнивать их числом
                // значило бы завести здесь второй закон о марке.
                match whom.edge.map(|edge| edge.under::<Path>()) {
                    Some(Path::Ours) => Act::sever(),
                    Some(Path::Other) | None => Act::observe(),
                }
            })
            .run();

        taken(injected).len()
    };

    assert_eq!(
        severed(0x0300),
        1,
        "разговор под маркой лечения обязан быть оборван"
    );
    assert_eq!(
        severed(0x0400),
        0,
        "разговор под чужой маркой не наш предмет — рвать его нечем и незачем"
    );
}
