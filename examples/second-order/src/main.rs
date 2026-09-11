//! # Приборы ВТОРОГО ПОРЯДКА: ряд строит потребитель, прибор судит
//!
//! Часть приборов парка ест не провод, а ПРОИЗВОДНУЮ от провода: просадка (`SagInstrument`) читает
//! ряд скоростей по окнам, темп (`PaceInstrument`) — длительность ожидания. В цепочку такие не
//! встают и встать не могут: `.detect(…)` кормит буквами провода, а ряда на проводе нет — его
//! кто-то должен построить.
//!
//! Пример показывает, КТО и ЗА СКОЛЬКО. Не «как обойти ограничение»: это замер перед решением —
//! ступень агрегации нужна фреймворку или хватает двадцати строк у потребителя.
//!
//! ## Чем это возможно
//!
//! Третья дверь наблюдения (`heard()`) отдаёт показания ЗНАЧЕНИЕМ, и у каждого есть три вещи,
//! которых хватает для ряда: момент наблюдения (§8 — тот, что нёс носитель, а не наши часы),
//! величины края и адрес. Возьми потребитель свои часы — на записи ряд схлопнулся бы в точку:
//! семь секунд провода проходят за микросекунды прогона.
//!
//! ## Запуск
//!
//! ```sh
//! cargo run -p second-order -- reflex/tests/fixtures/long-hello.pcap
//! ```

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use reflex::*;
use reflex_instrument::sag::{Sag, SagInstrument};

/// Окно ряда. Секунда, как и просит паспорт прибора (`CADENCE = Own { step_ms: 1000 }`): окно
/// короче пачки дало бы нули между пачками, и просадка почудилась бы на здоровой закачке.
const WINDOW: Duration = Duration::from_secs(1);

/// Прибор, говорящий на каждом пакете. Нужен затем, что показания рождаются СЛОВАМИ: нет слова —
/// нет и показания, а нам нужен поток наблюдений, а не поток бед.
#[derive(Clone, Copy, Default)]
struct Every;

impl Mealy for Every {
    type In = DetectorEvent<Seen>;
    type Out = SmallVec<[Distress; 2]>;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        match event {
            DetectorEvent::Packet { .. } => (self, smallvec![Distress::NoBytes], ()),
            DetectorEvent::Tick { .. } | DetectorEvent::Opaque { .. } | DetectorEvent::Torn { .. } => {
                (self, SmallVec::new(), ())
            }
        }
    }
}

/// СТУПЕНЬ АГРЕГАЦИИ ЦЕЛИКОМ — вот столько она стоит потребителю.
///
/// Байты вниз — величина НАКОПЛЕННАЯ (край считает с начала разговора), а прибору нужна СКОРОСТЬ.
/// Разность соседних окон и есть скорость; взять сами накопления значило бы кормить прибор
/// монотонно растущим рядом, в котором просадки не бывает по построению.
fn series(notes: impl Iterator<Item = Note>, since: Instant) -> BTreeMap<Box<str>, Vec<u64>> {
    let mut windows: BTreeMap<Box<str>, BTreeMap<u64, u64>> = BTreeMap::new();
    for note in notes {
        // Край сняли не на всякой букве: у слова, рождённого узлом сетки, его нет (§7 — «не
        // сняли» ≠ «нули»). Такое показание ряд не двигает вовсе.
        let Some(bytes) = note.edge.and_then(|edge| edge.down_bytes) else {
            continue;
        };
        let window = note.at.saturating_duration_since(since).as_millis() as u64
            / WINDOW.as_millis() as u64;
        // Внутри окна берём ПОСЛЕДНЕЕ накопление: оно и есть «сколько прошло к концу окна».
        windows
            .entry(note.target.clone())
            .or_default()
            .insert(window, bytes);
    }

    windows
        .into_iter()
        .map(|(target, marks)| {
            let counted: Vec<u64> = marks.values().copied().collect();
            // Скорость окна — прирост накопления. Первое окно приростом не считается: не с чем
            // сравнивать, и подставить ноль значило бы выдумать простой в начале разговора.
            let rates = counted
                .windows(2)
                .map(|pair| pair[1].saturating_sub(pair[0]))
                .collect();
            (target, rates)
        })
        .collect()
}

/// Исход — `ExitCode`, а не `Report`, и это не мелочь формы: у двери показаний нет «конца
/// прогона» как значения. Несостоявшийся ЗАПУСК приезжает `Report`ом (`heard()` отдаёт `Err`), а
/// удавшийся кончается тем, что итератор иссяк, — и отчитываться тут не о чем, кроме собственной
/// работы потребителя. Оттого и `Termination` зовётся руками на одной ветке из двух.
fn main() -> std::process::ExitCode {
    use std::process::Termination;

    let path = std::env::args().nth(1).unwrap_or_default();
    let started = Instant::now();

    let notes = match pcap(&path)
        .from(Tcp)
        .extract(Sni)
        .detect(own(Every))
        .heard()
    {
        Err(report) => return report.report(),
        Ok(notes) => notes,
    };

    let rows = series(notes, started);
    for (target, rates) in &rows {
        report!("{target}: ряд по окнам {rates:?}");
        // Прибор второго порядка судит ряд ОДНИМ шагом: состояния у него нет, весь предмет во
        // входе. Оттого он и не встаёт в цепочку — цепочка кормит буквами, а не рядами.
        let (_instrument, said, ()) =
            SagInstrument.step(DetectorEvent::packet_now(rates.clone()));
        match said.first() {
            None => report!("  просадки нет (либо ряд короче четырёх окон — прибор слеп, не пуст)"),
            Some(Sag {
                at_window,
                before_bps,
                after_bps,
            }) => report!("  ПРОСАДКА на окне {at_window}: было {before_bps} Б/с, стало {after_bps}"),
        }
    }

    report!(
        "показаний сведено в {} целей за {:?} прогона",
        rows.len(),
        started.elapsed()
    );
    std::process::ExitCode::SUCCESS
}
