//! ВЕДУЩИЙ ЦИКЛ на бумажном носителе — первая его проверка в истории проекта.
//!
//! До этого файла петля не проверялась НИЧЕМ: оба регресса переезда (невидимый `SYN` и блокирующий
//! приём, останавливавший тики ровно тогда, когда наступало молчание) нашли боевые стенды, а 873
//! теста молчали. Проверка отсутствовала ровно там, где живёт риск.
//!
//! Строки таблицы шва (`.superpowers/sdd/2026-09-10-carrier-functor/t8-seam-table.md`) названы у
//! каждого теста: таблицу писал тот, кто её не реализует, и покрытие сверяется по ней, а не по
//! памяти реализатора.

mod paper;

use std::time::Duration;

use paper::{
    alien, log, names, request, syn, taken, Crier, Letter, Paper, PaperAnswer, Recorder, Ticker,
};
use reflex::*;

/// Сколько узлов сетки укладывается в секунду тишины: шаг сетки 200мс — величина фасада, тестам
/// она видна только следствием.
const NODES_IN_A_SECOND: usize = 5;

/// Сколько раз имя встретилось среди дошедших букв.
fn how_many(seen: &[String], name: &str) -> usize {
    seen.iter().filter(|letter| *letter == name).count()
}

// ─── A. Молчание и часы ───────────────────────────────────────────────────────────────────────

/// A1. ТИШИНА ДОХОДИТ УЗЛАМИ. Здесь виден вчерашний блокирующий приём: он давал ноль букв вместо
/// пяти, и приборы молчания замирали ровно тогда, когда молчание наступало (§9.3).
#[test]
fn тишина_живого_разговора_доходит_узлами_сетки() {
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
fn нарушитель_срока_гонит_сетку_впереди_своих_часов() {
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
fn слепота_носителя_не_останавливает_сетку() {
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
fn узел_не_наступил_пакет_идёт_один() {
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

/// B1. ПЕРЕШАГНУТЫЕ УЗЛЫ ДОХОДЯТ ДО ПРИБОРА РАНЬШЕ ПАКЕТА. Прежде фасад гонял всю пачку, потом
/// смотрел тик: детектор видел пакет раньше закрытия окна, в которое пакет не попал, и относил его
/// байты не к тому окну (§8, дословно).
///
/// Узлы здесь рождает САМ ПАКЕТ (`Interleave::saw`), а не тишина: носитель отдаёт его с моментом
/// за пятью узлами — так бывает, когда приборы медленнее сетки и срок прошёл до вызова. Возьми
/// сценарий с тишиной, и те же пять узлов пришли бы безответным исходом, а порядок внутри `saw`
/// остался бы непроверенным.
#[test]
fn перешагнутые_узлы_доходят_до_прибора_раньше_пакета() {
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
fn чужой_кадр_двигает_сетку_но_до_приборов_не_доходит() {
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

/// B3. УЗЛЫ ВЫХОДЯТ ПЕРЕД ДЫРОЙ — порядок держит конструкция шва, а не дисциплина зовущего.
#[test]
fn узлы_выходят_перед_дырой() {
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
fn два_пакета_одного_окна_не_разделяются_узлом() {
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
fn пакет_идёт_своей_машине_а_узел_каждой() {
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
fn дыра_доходит_до_каждой_живой_машины() {
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
fn дыра_без_живых_машин_не_заводит_машину() {
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
fn молчащий_прибор_всё_равно_отпускает_пакет() {
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
/// неделимо) — и доезжает ЧЕРЕЗ `Terminal::apply`, а не мимо него. Прежде фасад переписывал таблицу
/// `Answer → (accept, state)` руками, и таблица жила в двух копиях при зелёной сборке.
#[test]
fn памятка_доезжает_до_терминала_одним_словом_с_вердиктом() {
    let paper = Paper::new().then_packet(syn(40001)).then_stop();
    let applied = paper.applied();

    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(SynDrop::unreachable())
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
fn без_края_памятка_не_рождается() {
    let paper = Paper::new()
        .edging(None)
        .then_packet(syn(40001))
        .then_stop();
    let applied = paper.applied();

    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(SynDrop::unreachable())
        .on(|_, _| {})
        .run();

    assert_eq!(taken(applied), [PaperAnswer::Pass], "запоминать нечего");
}

/// D3. ОТКАЗ ВЕРДИКТА не отменяет прошедших букв: приборы уже посчитали пакет. Цена названа в
/// докблоке `Running::run` обеими половинами — здесь проверяется лишь то, что цикл жив и буквы не
/// потеряны.
#[test]
fn отказ_вердикта_не_отменяет_прошедших_букв() {
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
fn узлы_после_конца_сценария_не_выходят() {
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
fn дыра_несёт_момент_носителя_а_не_часы_цикла() {
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
fn носитель_не_открылся_цикл_не_начат() {
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
/// Строки в таблице шва нет: до сегодня у действия был свой цикл, и проверить его было нечем —
/// оттого он и разошёлся с наблюдающим (не знал ни ленты, ни дыры, ни слова о цели).
#[test]
fn обрыв_уезжает_стоком_носителя_а_не_мимо_него() {
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
/// Прежде `walk` гонял все буквы оборота с байтами пакета, привезённого этим оборотом: узел,
/// разосланный КАЖДОЙ живой машине, получал улику ЧУЖОГО разговора, и `Act::sever()` по слову
/// прибора B рвал разговор A, который ни в чём не бедствовал. Штатными приборами недостижимо (они
/// на узле молчат), достижимо через `own(…)` — публичную дверь, которой мы хвалимся. Слово
/// необратимо, потому закон держит конструкция, а не молчание приборов.
#[test]
fn слово_рождённое_узлом_не_несёт_улики_и_рвать_ему_нечем() {
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
fn слово_о_цели_рождается_на_каждом_закрытом_узле() {
    let сказано = log::<String>();
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
            сказано
                .lock()
                .expect("журнал не отравлен")
                .push(target.to_string())
        })
        .on(|_, _| {})
        .run();

    assert_eq!(
        taken(сказано).len(),
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
fn сетка_отмеряется_от_первого_наблюдения_а_не_от_часов_цикла() {
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
