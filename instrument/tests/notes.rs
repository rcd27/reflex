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

use reflex_core::mealy::{Mealy, MealyExt};
use reflex_core::DetectorEvent;
use reflex_instrument::agreement::{Agreement, AgreementInstrument};
use reflex_instrument::detect::{Measured, SilenceInstrument, Watch};
use reflex_instrument::distress::Distress;
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
fn words<M>(machine: M, inputs: Vec<M::In>) -> Vec<M::Out>
where
    M: Mealy,
    M::Out: Debug + PartialEq,
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
/// Проверяет компилятор: границы `Out = ()` и `Log = SmallVec<[S; 2]>` утверждают ровно это.
#[test]
fn an_instrument_without_a_region_speaks_sideways() {
    fn speaks_sideways<M, S>()
    where
        M: Mealy<Out = (), Log = SmallVec<[S; 2]>>,
    {
    }

    speaks_sideways::<AgreementInstrument, Agreement>();
    speaks_sideways::<HistoryInstrument, Shift>();
}

/// ПУСТОЕ СЛОВО ПРИ ИСТЁКШЕМ ПОРОГЕ РАЗБИРАЕТСЯ ЧЕТВЁРТОЙ ОСЬЮ, А НЕ ДОГАДКОЙ.
///
/// Прибор молчит на тике, отстоящем от последнего события дальше терпения, ровно по трём разным
/// причинам: повода нет (байты пришли и никто не ждёт), уже пожаловались, разговор кончился.
/// Лечение у каждой своё, а первые три оси показания у двух последних СОВПАДАЮТ БУКВА В БУКВУ —
/// различает их одна четвёртая.
#[test]
fn the_watch_axis_tells_the_three_silences_apart() {
    let start = Instant::now();
    let at = |after_ms: u64| start + Duration::from_millis(after_ms);
    let tick = |machine: SilenceInstrument,
                after_ms: u64|
     -> (SilenceInstrument, SmallVec<[Distress; 2]>, Option<Measured>) {
        let (next, word, noted) = machine.step(DetectorEvent::Tick {
            node: after_ms,
            at: at(after_ms),
        });
        (next, word, noted)
    };
    let packet = |machine: SilenceInstrument, seen: Seen, after_ms: u64| -> SilenceInstrument {
        let (next, _word, _noted) = machine.step(DetectorEvent::Packet {
            input: seen,
            at: at(after_ms),
        });
        next
    };
    // Часы заводит ПЕРВЫЙ ТИК, и только потом приходит наблюдение.
    let wound = |seen: Seen| packet(tick(SilenceInstrument::after(PATIENCE), 0).0, seen, 10);

    // ПОВОДА НЕТ: цель отдала байты, и никто не ждёт продолжения.
    let (_, calm, no_reason) = tick(wound(Seen::Received { count: 4_096 }), 4_000);
    let no_reason = no_reason.expect("часы заведены — мерить есть от чего");
    assert!(calm.is_empty(), "молчащей беды здесь нет");
    assert_eq!(
        no_reason.watch,
        Watch::Open,
        "смотрим и готовы пожаловаться"
    );

    // УЖЕ ПОЖАЛОВАЛИСЬ: тик за порогом дал беду, следующий молчит по другой причине.
    let (fired, complaint, _) = tick(wound(Seen::Sent { count: 100 }), 2_000);
    assert!(
        !complaint.is_empty(),
        "порог истёк — беда обязана прозвучать"
    );
    let (_, silent, after_the_complaint) = tick(fired, 4_000);
    assert!(silent.is_empty(), "второй раз о том же не жалуемся");
    let after_the_complaint = after_the_complaint.expect("часы идут и после жалобы");

    // РАЗГОВОР КОНЧЕН: молчание попрощавшегося уликой не является.
    let closed = packet(
        wound(Seen::Sent { count: 100 }),
        Seen::Closed { by_client: false },
        10,
    );
    let (_, mute, after_the_farewell) = tick(closed, 4_000);
    assert!(mute.is_empty(), "цель попрощалась — молчание её не улика");
    let after_the_farewell = after_the_farewell.expect("часы идут и после прощания");

    // ТРИ ПОКАЗАНИЯ, И ДВА ИЗ НИХ РАСХОДЯТСЯ РОВНО ОДНОЙ ОСЬЮ.
    assert_eq!(
        after_the_complaint,
        Measured {
            watch: Watch::Fired,
            ..after_the_farewell
        },
        "«уже сказали» и «разговор кончился» различает одна четвёртая ось"
    );
    assert_eq!(after_the_farewell.watch, Watch::Ended);
    assert_ne!(no_reason.watch, after_the_complaint.watch);
}

// ─── ПАРА ПОМОЩНИКОВ ПОВЕРКИ: СЛОВО И ПОКАЗАНИЕ ────────────────────────────────────────────────

/// ПРЕДМЕТ: `says` спрашивает СЛОВО, `heard` — ПОКАЗАНИЕ, и у прибора без адресата слова есть
/// только второе. Помощник, вернувший пустоту там, где спросили не тот предмет, неотличим от
/// прибора, которому нечего сказать, — потому пара и названа парой.
///
/// Заведено по замеру потребителя: пять его приборов не поверялись `says` вовсе, и он написал свою
/// обёртку. Своя обёртка у каждого поверяющего — это два способа поверки, расходящиеся молча.
#[test]
fn слово_и_показание_спрашиваются_разными_помощниками() {
    use reflex_instrument::agreement::{Agreement, AgreementInstrument};
    use reflex_instrument::{heard, says};

    // Мы пометили 7 разговоров, ядро подтверждает 7 — согласие.
    let observation = (7u64, Some(7u64));

    // Слова у этого прибора нет ПО ПОСТРОЕНИЮ: у сверки нет области, её ждёт человек за границей
    // цепочки. `says` честно отдаёт `()` — и ровно потому им этот прибор не поверяется.
    let word: () = says(AgreementInstrument, observation);
    assert_eq!(word, (), "слова у прибора без адресата нет");

    let reading = heard(AgreementInstrument, observation);
    assert_eq!(
        reading.as_slice(),
        [Agreement::Agreed { both: 7 }],
        "показание обязано нести величины, которыми прибор работал"
    );
}
