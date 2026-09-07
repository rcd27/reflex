//! ПОКАЗАНИЕ НЕСЁТ ЗНАЧЕНИЯ, КОТОРЫМИ ШАГ РАБОТАЛ, А НЕ ОПИСАНИЕ ИХ.
//!
//! Значение не может разойтись с собой; строка может. Прибор тишины решает по трём величинам —
//! сколько молчали, сколько байт пришло и ждёт ли человек прямо сейчас, — и ровно они обязаны
//! выйти показанием, иначе решение непредъявимо: чтобы понять его, придётся лезть внутрь машины.
//!
//! Здесь же проверяется закон забывания: показания не читаются никем, значит снятие их не меняет
//! НИ ОДНОГО слова. Это не обещание докблока, а проверка.
use std::fmt::Debug;
use std::time::{Duration, Instant};

use reflex_core::step::{Step, StepExt};
use reflex_core::DetectorEvent;
use reflex_instrument::agreement::{Agreement, AgreementInstrument};
use reflex_instrument::detect::SilenceInstrument;
use reflex_instrument::drift::{HistoryInstrument, Shift};
use reflex_instrument::wire::Seen;
use smallvec::SmallVec;

const PATIENCE: Duration = Duration::from_millis(1_500);

/// СЦЕНАРИЙ ВСТАВШЕГО ПОТОКА: байты были и кончились, пока их ждут.
///
/// Взят дословно из поверки прибора, живущей рядом с ним: цель отдала четыре килобайта, клиент
/// попросил ещё, дальше две секунды тишины при терпении в полторы.
fn a_stalled_stream(start: Instant) -> Vec<DetectorEvent<Seen>> {
    vec![
        (Some(Seen::Received { count: 4_096 }), 0u64),
        (Some(Seen::Sent { count: 100 }), 10),
        (None, 2_000),
    ]
    .into_iter()
    .map(|(seen, after_ms)| {
        let at = start + Duration::from_millis(after_ms);
        match seen {
            Some(seen) => DetectorEvent::Packet { input: seen, at },
            None => DetectorEvent::Tick { node: after_ms, at },
        }
    })
    .collect()
}

/// Прогнать машину по входам и собрать ТОЛЬКО слова.
fn words<M>(machine: M, inputs: Vec<M::From>) -> Vec<M::To>
where
    M: Step,
    M::To: Debug + PartialEq,
{
    let mut machine = machine;
    let mut said = Vec::new();
    for input in inputs {
        let (next, word, _) = machine.step(input);
        machine = next;
        said.push(word);
    }
    said
}

#[test]
fn nothing_measured_before_the_first_observation() {
    let start = Instant::now();
    let (_, _, noted) = SilenceInstrument::after(PATIENCE).step(DetectorEvent::Tick {
        node: 1,
        at: start + PATIENCE,
    });
    assert_eq!(
        noted, None,
        "мерить не от чего: наблюдений ещё не было, и показание пусто"
    );
}

#[test]
fn the_measurement_leaves_as_a_value() {
    let start = Instant::now();
    let noted: Vec<_> = a_stalled_stream(start)
        .into_iter()
        .scan(SilenceInstrument::after(PATIENCE), |machine, event| {
            let (next, _, noted) = (*machine).step(event);
            *machine = next;
            Some(noted)
        })
        .flatten()
        .collect();

    let last = noted.last().expect("прибор обязан отметить, чем мерил");
    assert_eq!(
        last.bytes, 4_096,
        "показание несёт ЗНАЧЕНИЕ, которым решали"
    );
    assert!(last.awaiting, "и ось, без которой решение необъяснимо");
}

#[test]
fn forgetting_the_notes_changes_no_word() {
    let start = Instant::now();

    let with_notes = words(SilenceInstrument::after(PATIENCE), a_stalled_stream(start));
    let without = words(
        SilenceInstrument::after(PATIENCE).mute(),
        a_stalled_stream(start),
    );

    assert_eq!(
        with_notes, without,
        "показания не читаются никем — значит снятие их не меняет ни одного слова"
    );
}

/// НЕТ ОБЛАСТИ — ПОКАЗАНИЕ, И ЭТО СТОИТ В ПОДПИСИ, А НЕ В ПРОЗЕ.
///
/// Сверка приказа с исполнением и сравнение прогона с рядом не адресованы ни пакету, ни разговору,
/// ни цели: их ждёт человек, читающий отчёт, — а он стоит ЗА границей цепочки, там же, куда
/// уходят показания. Значит соседу по стрелке эти приборы говорят пустое слово, и вся их речь идёт
/// вбок.
///
/// Проверяет компилятор: границы `To = ()` и `Notes = SmallVec<[S; 2]>` утверждают ровно это.
#[test]
fn an_instrument_without_a_region_speaks_sideways() {
    fn speaks_sideways<M, S>()
    where
        M: Step<To = (), Notes = SmallVec<[S; 2]>>,
    {
    }

    speaks_sideways::<AgreementInstrument, Agreement>();
    speaks_sideways::<HistoryInstrument, Shift>();
}
