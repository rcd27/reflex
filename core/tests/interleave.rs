//! СЛИЯНИЕ НАБЛЮДЕНИЙ И СЕТКИ В ОДИН ПОТОК — законы шва.
//!
//! Здесь время перестаёт быть сервисом и становится буквой входного алфавита: потребитель ниже по
//! течению не спрашивает часов вовсе, он читает буквы [`DetectorEvent`] и всё. У разобранного
//! (`saw`), непонятого (`unread`) и дыры (`torn`) — по своей двери, и все продвигают сетку одинаково.

use reflex_core::detector::DetectorEvent;
use reflex_core::interleave::Interleave;
use reflex_core::parse::Unread;
use std::time::{Duration, Instant};

const STEP: Duration = Duration::from_millis(100);

fn at(start: Instant, millis: u64) -> Instant {
    start + Duration::from_millis(millis)
}

/// Что за события вышли — в виде, который читается глазами.
fn shape<T>(events: &[DetectorEvent<T>], start: Instant) -> Vec<(char, u64)> {
    events
        .iter()
        .map(|event| {
            let millis = event.at().saturating_duration_since(start).as_millis() as u64;
            match event {
                DetectorEvent::Packet { .. } => ('p', millis),
                DetectorEvent::Tick { .. } => ('t', millis),
                DetectorEvent::Opaque { .. } => ('o', millis),
                // 'x' — дыра: 't' занято тиком, буква не пересекается с остальными.
                DetectorEvent::Torn { .. } => ('x', millis),
            }
        })
        .collect()
}

/// ПАКЕТ ВНУТРИ ОДНОГО ОКНА НЕ РОЖДАЕТ ТИКОВ.
#[test]
fn a_packet_inside_one_window_brings_no_ticks() {
    let start = Instant::now();
    let seam = Interleave::started(start, STEP);

    let (_seam, out) = seam.saw(1u8, at(start, 40));

    assert_eq!(shape(&out, start), vec![('p', 40)]);
}

/// УЗЛЫ СЕТКИ ВЫХОДЯТ ПЕРЕД ПАКЕТОМ, КОТОРЫЙ ИХ ПЕРЕШАГНУЛ, и в порядке времени.
///
/// Порядок существен: детектор, увидевший пакет раньше закрытия окна, в которое пакет не попал,
/// отнесёт его байты не к тому окну.
#[test]
fn the_nodes_a_packet_stepped_over_come_out_before_it() {
    let start = Instant::now();
    let seam = Interleave::started(start, STEP);

    let (_seam, out) = seam.saw(1u8, at(start, 250));

    assert_eq!(shape(&out, start), vec![('t', 100), ('t', 200), ('p', 250)]);
}

/// УЗЕЛ ВЫДАЁТСЯ РОВНО ОДИН РАЗ — сколько бы пакетов ни пришло следом.
#[test]
fn a_node_is_handed_out_exactly_once() {
    let start = Instant::now();
    let seam = Interleave::started(start, STEP);

    let (seam, first) = seam.saw(1u8, at(start, 150));
    let (seam, second) = seam.saw(2u8, at(start, 160));
    let (_seam, third) = seam.saw(3u8, at(start, 210));

    assert_eq!(shape(&first, start), vec![('t', 100), ('p', 150)]);
    assert_eq!(
        shape(&second, start),
        vec![('p', 160)],
        "узел 100 уже выдан"
    );
    assert_eq!(shape(&third, start), vec![('t', 200), ('p', 210)]);
}

/// НЕПОНЯТОЕ ДВИГАЕТ СЕТКУ ТЕМ ЖЕ СПОСОБОМ, ЧТО И ПАКЕТ — своя дверь, тот же закон.
///
/// Без этой двери поток из одних неразобранных наблюдений не продвигал бы сетку вовсе, и
/// молчание под таким трафиком было бы неотличимо от «наблюдений не было».
#[test]
fn an_unread_observation_steps_over_nodes_the_same_way_a_packet_does() {
    let start = Instant::now();
    let seam = Interleave::started(start, STEP);

    let (_seam, out) = seam.unread::<u8>(Unread::Truncated, at(start, 250));

    assert_eq!(shape(&out, start), vec![('t', 100), ('t', 200), ('o', 250)]);
}

/// УЗЕЛ, ПЕРЕШАГНУТЫЙ НЕПОНЯТЫМ, ВЫДАЁТСЯ РОВНО ОДИН РАЗ — как и у пакета, независимо от буквы,
/// которая пришла следом.
#[test]
fn a_node_is_not_handed_out_twice_across_different_letters() {
    let start = Instant::now();
    let seam = Interleave::started(start, STEP);

    let (seam, first) = seam.unread::<u8>(Unread::NotIpv4, at(start, 150));
    let (_seam, second) = seam.saw(1u8, at(start, 160));

    assert_eq!(shape(&first, start), vec![('t', 100), ('o', 150)]);
    assert_eq!(
        shape(&second, start),
        vec![('p', 160)],
        "узел 100 уже выдан непонятым — пакет его не повторяет"
    );
}

/// ТИШИНА ТОЖЕ НАБЛЮДЕНИЕ: будильник приносит наступившие узлы без единого пакета.
///
/// Ради этого шов и заводится. Пока трафик идёт, узлы ВЫЧИСЛЯЮТСЯ между пакетами и будильник не
/// нужен вовсе; он нужен ровно там, где событий нет, — то есть там, где приборы простоя и слепы.
#[test]
fn silence_still_produces_the_nodes_it_covered() {
    let start = Instant::now();
    let seam = Interleave::started(start, STEP);

    let (_seam, out) = seam.idle::<u8>(at(start, 320));

    assert_eq!(shape(&out, start), vec![('t', 100), ('t', 200), ('t', 300)]);
}

/// ВРЕМЯ НЕ ИДЁТ НАЗАД, ДАЖЕ ЕСЛИ ЕГО ПРИНЕСЛИ НАЗАД.
///
/// Провод переставляет пакеты, а очередь ядра отдаёт их не в порядке съёма. Событие с моментом
/// раньше уже выданного ломает всякий временной оператор ниже по течению — и ломает молча, потому
/// что тот вправе считать вход монотонным.
#[test]
fn a_packet_from_the_past_does_not_turn_time_backwards() {
    let start = Instant::now();
    let seam = Interleave::started(start, STEP);

    let (seam, _ahead) = seam.saw(1u8, at(start, 250));
    let (_seam, late) = seam.saw(2u8, at(start, 120));

    assert_eq!(
        shape(&late, start),
        vec![('p', 250)],
        "опоздавший пакет обязан выйти НЕ РАНЬШЕ последнего выданного момента"
    );
}

/// НОМЕР УЗЛА И МОМЕНТ — ОБА, А НЕ ОДИН ИЗ ДВУХ.
///
/// Номер даёт воспроизводимость: при переигровке он тот же, тогда как момент зависит от того,
/// когда прогон случился. Момент даёт сравнимость с чужими часами — с журналом ядра, с записью
/// провода, с отчётом человека.
///
/// Выбирать между ними значило бы терять одно из двух, а стоят они одно машинное слово.
#[test]
fn tick_carries_node_and_moment() {
    let start = Instant::now();
    let seam = Interleave::started(start, STEP);

    let (_, told) = seam.idle::<u8>(start + STEP * 3);

    let nodes: Vec<u64> = told
        .iter()
        .filter_map(|event| match event {
            DetectorEvent::Tick { node, .. } => Some(*node),
            DetectorEvent::Packet { .. }
            | DetectorEvent::Opaque { .. }
            | DetectorEvent::Torn { .. } => None,
        })
        .collect();

    assert_eq!(nodes, vec![1, 2, 3], "номера идут подряд от начала отсчёта");

    let moments: Vec<Instant> = told
        .iter()
        .filter_map(|event| match event {
            DetectorEvent::Tick { at, .. } => Some(*at),
            DetectorEvent::Packet { .. }
            | DetectorEvent::Opaque { .. }
            | DetectorEvent::Torn { .. } => None,
        })
        .collect();

    assert_eq!(
        moments,
        vec![start + STEP, start + STEP * 2, start + STEP * 3],
        "момент есть момент УЗЛА, а не момент выдачи"
    );
}

/// МОМЕНТЫ НЕУБЫВАЮТ ВО ВСЁМ ПОТОКЕ — сквозной закон, а не свойство одного вызова.
#[test]
fn moments_never_decrease_across_the_whole_stream() {
    let start = Instant::now();
    let arrivals = [40u64, 250, 120, 900, 30, 905];

    let (_seam, all) = arrivals.iter().fold(
        (Interleave::started(start, STEP), Vec::new()),
        |(seam, mut seen), millis| {
            let (seam, out) = seam.saw(1u8, at(start, *millis));
            seen.extend(out);
            (seam, seen)
        },
    );

    let moments: Vec<_> = all.iter().map(|event| event.at()).collect();
    assert!(
        moments.windows(2).all(|pair| pair[1] >= pair[0]),
        "поток отдал время, идущее назад: {:?}",
        shape(&all, start)
    );
}

/// Срок для носителя — момент СЛЕДУЮЩЕГО узла, отсчитанный от последнего выданного. Не «сейчас
/// плюс шаг»: тогда каждый пакет продлевал бы ожидание, и тик уезжал бы вправо тем сильнее, чем
/// плотнее трафик — часы приборов молчания зависели бы от трафика, что §8 запрещает.
#[test]
fn срок_есть_момент_следующего_узла() {
    let start = Instant::now();
    let every = Duration::from_millis(100);
    let seam = Interleave::started(start, every);

    assert_eq!(seam.next_node(), Some(start + Duration::from_millis(100)));

    let (seam, _) = seam.idle::<()>(start + Duration::from_millis(250));
    assert_eq!(seam.next_node(), Some(start + Duration::from_millis(300)));
}

/// Нулевой шаг — отсутствие сетки: узла не будет никогда. Два места описывают один закон — `next_node`
/// и `nodes_up_to` — и оба обязаны сказать одно: при нулевом шаге сетки нет, какая бы точка ни спросила.
#[test]
fn нулевой_шаг_даёт_отсутствие_сетки() {
    let start = Instant::now();
    let seam = Interleave::started(start, Duration::ZERO);

    assert_eq!(seam.next_node(), None, "узела нет, сетки нет");

    let (_seam, out) = seam.idle::<()>(start + Duration::from_secs(1));
    assert_eq!(shape(&out, start), vec![], "idle на нулевой сетке не выдаёт узлов");
}

// ─── ЧЕТВЁРТАЯ ДВЕРЬ: ОТКЛИК НА СПРОШЕННОЕ ──────────────────────────────────────────────────────
//
// До сегодня у неё не было ни вызова, ни прогона: закон написан, докблок продуман, способность не
// предъявлена ничем. Механизм, потреблённый ноль раз, стоит ноль — и хуже того, он выглядит
// готовым. Тесты ниже предъявляют ровно то, что докблок обещает.

use reflex_core::tape::TapeLetter;

/// Что вышло из двери отклика — породой и моментом.
fn tape_shape<T, K, C>(letters: &[TapeLetter<T, K, C>], start: Instant) -> Vec<(char, u64)> {
    letters
        .iter()
        .map(|letter| {
            let millis = letter.at().saturating_duration_since(start).as_millis() as u64;
            match letter {
                TapeLetter::Event { event, .. } => match event {
                    DetectorEvent::Tick { .. } => ('t', millis),
                    DetectorEvent::Packet { .. } => ('p', millis),
                    DetectorEvent::Opaque { .. } => ('o', millis),
                    DetectorEvent::Torn { .. } => ('x', millis),
                },
                // 'a' — отклик: он НЕ буква провода и в алфавит приборов не входит вовсе.
                TapeLetter::Answer(_) => ('a', millis),
            }
        })
        .collect()
}

/// ПРЕДМЕТ: узлы, которые отклик перешагнул, выходят ПЕРЕД ним. Порядок держит конструкция двери, а
/// не дисциплина зовущего, — ровно как у `saw`. Иначе лента перестала бы быть упорядоченной, и
/// переигровка сравнивала бы два разных входа.
#[test]
fn an_answer_lets_the_nodes_it_stepped_over_out_first() {
    let start = Instant::now();
    let seam = Interleave::started(start, STEP);

    let (_seam, letters) = seam.answered::<u8, &str, &str>("example.com", "заблокировано", at(start, 350));

    assert_eq!(
        tape_shape(&letters, start),
        vec![('t', 100), ('t', 200), ('t', 300), ('a', 350)],
        "три узла сетки обязаны выйти перед откликом, а отклик — последним"
    );
}

/// ОТКЛИК НЕСЁТ КЛЮЧ, И КЛЮЧ НЕСУЩИЙ: ответ приходит позже вопроса и сам по себе не говорит, чей
/// он. Без ключа драйверу осталось бы отдать его первой попавшейся машине либо всем — и то и другое
/// сделало бы ответ чужим наблюдением (§4).
#[test]
fn an_answer_carries_the_key_that_says_whose_it_is() {
    let start = Instant::now();
    let seam = Interleave::started(start, STEP);

    let (_seam, letters) = seam.answered::<u8, &str, u32>("rutracker.org", 42, at(start, 120));

    let letter = letters
        .iter()
        .find(|letter| matches!(letter, TapeLetter::Answer(_)))
        .expect("отклик обязан быть на ленте");

    let TapeLetter::Answer(answer) = letter else {
        unreachable!("только что нашли отклик")
    };
    assert_eq!(answer.key, "rutracker.org");
    assert_eq!(answer.input, 42);

    // Адрес спрашивают У БУКВЫ ЛЕНТЫ, а не у отклика: обе породы отвечают на один вопрос «твоё ли
    // это», и тем переигровка маршрутизирует их одинаково, не различая пород.
    assert!(letter.answers(&"rutracker.org"), "буква обязана узнавать свой ключ");
    assert!(!letter.answers(&"example.com"), "и не узнавать чужой");
}

/// ОТКЛИК ДВИГАЕТ СЕТКУ, НО НЕ ОТМЕНЯЕТ ТИШИНЫ ПРОВОДА, и это не тонкость, а предмет: цель, что
/// отвечает нашему контуру, пока провод молчит, — ЭТО И ЕСТЬ тихий дроп. Отодвинь отклик тишину, и
/// дропнутый поток, чей контур сказал «блок», выглядел бы НЕ-тихим — ровно наоборот правде.
///
/// Проверяется тем, что после отклика узлы продолжают идти от его момента: сетка сдвинулась,
/// а буквой провода отклик не стал (`seen()` его не отдаёт).
#[test]
fn an_answer_moves_the_grid_without_becoming_a_wire_letter() {
    let start = Instant::now();
    let seam = Interleave::started(start, STEP);

    let (seam, letters) = seam.answered::<u8, &str, &str>("example.com", "ответ", at(start, 250));
    assert!(
        letters.iter().all(|letter| match letter {
            TapeLetter::Answer(_) => letter.seen().is_none(),
            TapeLetter::Event { .. } => letter.seen().is_some(),
        }),
        "отклик буквой провода не является и приборам не достаётся"
    );

    let (_seam, after) = seam.idle::<u8>(at(start, 450));
    assert_eq!(
        shape(&after, start),
        vec![('t', 300), ('t', 400)],
        "сетка обязана продолжиться от момента отклика, а не от начала"
    );
}
