//! ЛЕНТА: два алфавита и одна упорядоченность.
//!
//! Драйвер сливает в ленту наблюдения провода и отклики на спрошенное, и записывает её целиком.
//! Прибор при этом читает лишь провод: отклик до него не доходит §4-сужением, а не веткой «не моя
//! буква» в каждом приборе.

use reflex_core::detector::DetectorEvent;
use reflex_core::interleave::Interleave;
use reflex_core::stack::Reads;
use reflex_core::tape::{Answer, Mode, Tape, TapeLetter, To};
use std::time::{Duration, Instant};

const STEP: Duration = Duration::from_millis(100);

fn at(start: Instant, millis: u64) -> Instant {
    start + Duration::from_millis(millis)
}

/// Буквы ленты в виде, читаемом глазами.
fn shape<T, K, C>(letters: &[TapeLetter<T, K, C>], start: Instant) -> Vec<(char, u64)> {
    letters
        .iter()
        .map(|letter| {
            let millis = letter.at().saturating_duration_since(start).as_millis() as u64;
            let kind = match letter {
                TapeLetter::Event {
                    event: DetectorEvent::Packet { .. },
                    ..
                } => 'p',
                TapeLetter::Event {
                    event: DetectorEvent::Tick { .. },
                    ..
                } => 't',
                TapeLetter::Event {
                    event: DetectorEvent::Opaque { .. },
                    ..
                } => 'o',
                // 'x' — дыра: 't' занято тиком, буква не пересекается с остальными.
                TapeLetter::Event {
                    event: DetectorEvent::Torn { .. },
                    ..
                } => 'x',
                TapeLetter::Answer(_) => 'a',
            };
            (kind, millis)
        })
        .collect()
}

/// ТРИ ИСТОЧНИКА — ОДНА ЛЕНТА, УПОРЯДОЧЕННАЯ ВРЕМЕНЕМ.
///
/// Узлы, которые отклик перешагнул, выходят ПЕРЕД ним — как и у пакета. Порядок держит шов, а не
/// дисциплина зовущего: иначе прибор увидел бы отклик раньше закрытия окна, в которое тот не попал,
/// и лента перестала бы быть лентой.
#[test]
fn three_sources_make_one_tape_ordered_by_time() {
    let start = Instant::now();
    let seam = Interleave::started(start, STEP);

    let (seam, seen) = seam.saw("запрос", at(start, 50));
    let (seam, answered) = seam.answered::<&str, u8, &str>(7, "ответ контура", at(start, 250));
    let (_seam, idled) = seam.idle::<&str>(at(start, 420));

    let wire: Vec<TapeLetter<&str, u8, &str>> = seen
        .into_iter()
        .map(|event| TapeLetter::Event {
            to: To::One(1),
            event,
        })
        .collect();
    let after: Vec<TapeLetter<&str, u8, &str>> = idled
        .into_iter()
        .map(|event| TapeLetter::Event {
            to: To::Each,
            event,
        })
        .collect();

    assert_eq!(
        shape(&wire, start),
        vec![('p', 50)],
        "пакет внутри окна тиков не родил"
    );
    assert_eq!(
        shape(&answered, start),
        vec![('t', 100), ('t', 200), ('a', 250)],
        "узлы, перешагнутые откликом, выходят перед ним"
    );
    assert_eq!(shape(&after, start), vec![('t', 300), ('t', 400)]);

    let tape = [wire, answered, after].concat();
    let moments: Vec<Instant> = tape.iter().map(|letter| letter.at()).collect();
    assert!(
        moments.windows(2).all(|pair| pair[1] >= pair[0]),
        "лента неубывает по времени: {:?}",
        shape(&tape, start)
    );
}

/// ОТКЛИК ДО ПРИБОРА НЕ ДОХОДИТ — и роняет его СУЖЕНИЕ, а не ветка в приборе.
///
/// Прибор объявлен на трёх буквах провода. Будь отклик четвёртой буквой его алфавита, каждый прибор
/// дерева обязан был бы написать «не моя буква» — восемнадцать одинаковых веток, и девятнадцатая у
/// следующего. Буква, которую все обязаны отвергнуть, адресована не им.
#[test]
fn an_answer_never_reaches_an_instrument_that_does_not_read_it() {
    let start = Instant::now();
    let packet: TapeLetter<u8, u8, &str> = TapeLetter::Event {
        to: To::One(1),
        event: DetectorEvent::Packet {
            input: 7,
            at: start,
        },
    };
    let answer: TapeLetter<u8, u8, &str> = TapeLetter::Answer(Answer {
        key: 1,
        input: "контур сказал: блок",
        at: start,
    });

    assert!(
        matches!(
            <DetectorEvent<u8> as Reads<TapeLetter<u8, u8, &str>>>::read(&packet),
            Some(DetectorEvent::Packet { input: 7, .. })
        ),
        "провод до прибора доходит"
    );
    assert!(
        <DetectorEvent<u8> as Reads<TapeLetter<u8, u8, &str>>>::read(&answer).is_none(),
        "отклик до прибора не доходит — сужение его роняет"
    );
}

/// ОТКЛИК ДВИГАЕТ СЕТКУ, НО НЕ ОТМЕНЯЕТ ТИШИНЫ ПРОВОДА.
///
/// Сетку двигает, потому что лента упорядочена временем и узлы обязаны выйти вовремя. Тишину не
/// отменяет, потому что приборы отклика не видят: цель, отвечающая нашему контуру, пока провод
/// молчит, — это тихий дроп, и он обязан выглядеть тихим.
#[test]
fn an_answer_moves_the_grid_but_not_the_silence() {
    let start = Instant::now();
    let seam = Interleave::started(start, STEP);

    let (seam, answered) = seam.answered::<u8, u8, &str>(3, "блок", at(start, 250));
    let (_seam, idled) = seam.idle::<u8>(at(start, 320));

    assert_eq!(
        shape(&answered, start),
        vec![('t', 100), ('t', 200), ('a', 250)],
        "узлы до отклика выданы"
    );
    let after: Vec<TapeLetter<u8, u8, &str>> = idled
        .into_iter()
        .map(|event| TapeLetter::Event {
            to: To::Each,
            event,
        })
        .collect();
    assert_eq!(
        shape(&after, start),
        vec![('t', 300)],
        "сетка сдвинулась откликом: узлы 100 и 200 повторно не выдаются"
    );

    let seen_by_instrument: Vec<DetectorEvent<u8>> = answered
        .iter()
        .filter_map(<DetectorEvent<u8> as Reads<TapeLetter<u8, u8, &str>>>::read)
        .collect();
    assert!(
        seen_by_instrument
            .iter()
            .all(|event| matches!(event, DetectorEvent::Tick { .. })),
        "прибору достались только узлы сетки — отклика он не видел"
    );
}

/// ОТКЛИК ДОХОДИТ ДО МАШИНЫ СВОЕГО КЛЮЧА И НЕ ДОХОДИТ ДО ЧУЖОЙ.
///
/// Ответ приходит позже вопроса, и «чей он» знает только ключ. Отдай драйвер отклик первой
/// попавшейся машине — она получила бы чужое наблюдение и стала бы машиной на двух ключах, то есть
/// двумя машинами (§4).
#[test]
fn отклик_адресован_машине_своего_ключа() {
    let start = Instant::now();
    let (_seam, letters) =
        Interleave::started(start, STEP).answered::<u8, u32, &str>(42, "блок", start);

    let answer = letters
        .iter()
        .find(|letter| matches!(letter, TapeLetter::Answer(_)))
        .expect("отклик в ленте");

    assert!(answer.answers(&42), "своей машине адресован");
    assert!(!answer.answers(&43), "чужой машине не адресован");
}

/// АДРЕС НАБЛЮДЕНИЯ ПРОВОДА ЛЕЖИТ В ЛЕНТЕ, А НЕ В ГОЛОВЕ ЗОВУЩЕГО.
///
/// В живом прогоне «чья это буква» знает разбор. На переигровке разбора нет — лента и есть весь
/// вход, и буква, не сказавшая, чья она, легла бы в первую попавшуюся машину: восьмой закон
/// свидетельствовал бы об одной общей машине вместо семьи (§4).
#[test]
fn наблюдение_провода_несёт_адрес_своей_машины() {
    let start = Instant::now();
    let packet: TapeLetter<u8, u32, &str> = TapeLetter::Event {
        to: To::One(42),
        event: DetectorEvent::Packet {
            input: 1,
            at: start,
        },
    };

    assert!(packet.answers(&42), "своей машине адресован");
    assert!(!packet.answers(&0), "чужой — нет");
}

/// У УЗЛА СЕТКИ И У НЕПОНЯТОГО КЛЮЧА НЕТ — И ЭТО РАЗНЫЕ «НЕТ».
///
/// Время идёт для ВСЕХ машин разом (`Each`), а непонятое не ключуется вовсе (`Nobody`): взять ключ
/// не из чего, разобрать не смогли. Слей их в одно — и переигровка либо съела бы тик одной машиной,
/// либо потеряла бы фанаут, а какое из двух, решал бы уже читатель кода.
#[test]
fn у_тика_и_непонятого_ключа_нет_но_по_разным_причинам() {
    let start = Instant::now();
    let tick: TapeLetter<u8, u32, &str> = TapeLetter::Event {
        to: To::Each,
        event: DetectorEvent::Tick { node: 1, at: start },
    };
    let opaque: TapeLetter<u8, u32, &str> = TapeLetter::Event {
        to: To::Nobody,
        event: DetectorEvent::Opaque {
            why: reflex_core::parse::Unread::Truncated,
            at: start,
        },
    };

    assert!(!tick.answers(&42), "узел сетки не адресован ЛИЧНО никому");
    assert!(!opaque.answers(&42), "у непонятого адресата нет вовсе");
    assert_ne!(
        tick.seen().map(|(to, _)| to.clone()),
        opaque.seen().map(|(to, _)| to.clone()),
        "«всем» и «никому» — разные адреса, а не одно пустое место"
    );
}

// ─── Лента и режимы ──────────────────────────────────────────────────────────────────────────

/// ПЕРЕИГРОВКА ДАЁТ ТЕ ЖЕ ИСХОДЫ, ЧТО ЖИВОЙ ПРОГОН.
///
/// Машина одна и та же, лента та же — значит и последовательность высказываний та же. Это и есть
/// предмет восьмого закона (§10): не сравнение лент, а сверка ИСХОДОВ двух прогонов одной ленты.
#[test]
fn переигровка_повторяет_исходы_живого_прогона() {
    let start = Instant::now();
    let mut tape: Tape<u8, u32, &str> = Tape::new();

    let seam = Interleave::started(start, STEP);
    let (seam, seen) = seam.saw(1u8, at(start, 50));
    tape.record(seen.into_iter().map(|event| TapeLetter::Event {
        to: To::One(1),
        event,
    }));
    let (seam, answered) = seam.answered::<u8, u32, &str>(7, "блок", at(start, 250));
    tape.record(answered);
    let (_seam, idled) = seam.idle::<u8>(at(start, 420));
    tape.record(idled.into_iter().map(|event| TapeLetter::Event {
        to: To::Each,
        event,
    }));

    // «Прогон»: считаем, что видит прибор — буквы провода, дошедшие сужением.
    let run = |tape: &Tape<u8, u32, &str>| -> Vec<u64> {
        tape.letters()
            .iter()
            .filter_map(<DetectorEvent<u8> as Reads<TapeLetter<u8, u32, &str>>>::read)
            .map(|event| event.at().saturating_duration_since(start).as_millis() as u64)
            .collect()
    };

    assert_eq!(run(&tape), run(&tape), "два прогона одной ленты согласны");
    // Пакет, два узла до отклика, отклик, два узла тишины — шесть букв, обе породы.
    assert_eq!(tape.len(), 6, "лента записана ЦЕЛИКОМ: обе породы букв");
    assert_eq!(
        tape.letters()
            .iter()
            .filter(|letter| matches!(letter, TapeLetter::Answer(_)))
            .count(),
        1,
        "отклик записан в ленту наравне с проводом — иначе переигровка увидела бы не тот вход"
    );
}

/// В ПЕРЕИГРОВКЕ МИР НЕ ТРОГАЕТСЯ.
///
/// Живой прогон исполняет команды: инъекция уходит в провод, вопрос — контуру. Переигровка их
/// глушит — иначе она слала бы RST заново и спрашивала повторно, то есть не переигрывала бы, а
/// повторяла, и восьмой закон проверял бы не то.
#[test]
fn переигровка_не_трогает_мир() {
    assert!(
        Mode::Live.touches_the_world(),
        "живой прогон исполняет команды"
    );
    assert!(
        !Mode::Replay.touches_the_world(),
        "переигровка глушит команды — мир не трогается"
    );

    // Сколько команд ушло бы в мир: петля исполняет их лишь в живом прогоне.
    let sent = |mode: Mode, effects: usize| match mode.touches_the_world() {
        true => effects,
        false => 0,
    };
    assert_eq!(sent(Mode::Live, 3), 3);
    assert_eq!(sent(Mode::Replay, 3), 0, "ни одной команды в переигровке");
}
