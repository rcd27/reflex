//! ЗАМКНУТЫЙ КОНТУР: решение, принятое ВНЕ ПОЛОСЫ, читается на горячем пути.
//!
//! Предмет теста ровно один и он не про удобство двери: **последствие обязано пережить разговор**.
//! Буква, легшая в дом ключа и не влияющая на вердикт СЛЕДУЮЩЕГО пакета этой цели, не стоит
//! ничего — расследование идёт секундами, а разговор, по которому решали, к тому времени кончился.
//!
//! Проверяется прогоном по бумажному носителю: он тот же `Serves`, та же линейность владения, что
//! у очереди ядра, и он ЗАПИСЫВАЕТ вердикт — потому сказать «решение доехало» можно значением, а
//! не верой.

#![cfg(feature = "telling")]

mod paper;

use paper::{log, request, taken, Paper, PaperAnswer};
use reflex::telling::Telling;
use reflex::*;
use reflex_core::mark::{Marked, Region};

/// Прибор, говорящий на КАЖДОМ пакете: предмет теста — доезд решения до вердикта, а не то, при
/// каких условиях парковый прибор высказывается. Возьми я `Silence`, тест проверял бы его пороги.
#[derive(Clone, Copy, Default)]
struct Always;

impl Mealy for Always {
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

/// Область решений — четыре бита, заведомо не пересекающиеся с областью приборов
/// (`Layout::preset()` занимает 0x0FFF_E000).
fn leg() -> Region {
    Region::new(0x0000_0F00).expect("связная область")
}

/// Что носитель записал в марку каждым вердиктом.
fn marks(applied: &[PaperAnswer]) -> Vec<u32> {
    applied
        .iter()
        .filter_map(|answer| match answer {
            PaperAnswer::Remembered { state, .. } => Some(*state),
            _ => None,
        })
        .collect()
}

/// ПРЕДМЕТ: решение, положенное между пакетами, доезжает до вердикта СЛЕДУЮЩЕГО пакета той же цели
/// — и не задним числом до предыдущего.
#[test]
fn решение_читается_вердиктом_следующего_пакета_той_же_цели() {
    let heard = log::<Distress>();
    let telling = Telling::over(leg());
    let posting = telling.clone();

    // Носитель отдаёт два пакета одного разговора. Между ними реакция кладёт решение — то есть
    // ровно так, как это делает медленный контур: узнал, сказал, и знание обязано остаться.
    let paper = Paper::new()
        .then_packet(request(40001))
        .then_packet(request(40001))
        .then_stop();
    let applied = paper.applied();

    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(own(Always))
        .telling(telling)
        .on(move |target: &str, distress| {
            heard.lock().expect("слышно").push(distress);
            // Решение кладётся ИЗ РЕАКЦИИ здесь только ради краткости теста: дверь не знает, кто
            // её позвал, и та же ручка работает из чужой нити (`heard()`), где цикл — потребителя.
            assert!(posting.tell(target, 0b1010), "решение обязано влезть в область");
        })
        .run();

    let applied = taken(applied);
    let written = marks(&applied);

    // ДО решения носитель просто ОТПУСКАЕТ пакет: помнить нечего — ни памятки прибора, ни решения.
    // Это не мелочь формы: «отпустить» и «отпустить, запомнив ноль» — разные слова, и второе
    // затёрло бы чужие биты нулём там, где мы вообще ничего не решали.
    assert_eq!(
        applied.first(),
        Some(&PaperAnswer::Pass),
        "первый пакет вынесен до решения — вердикт обязан быть простым пропуском; \
         записано: {applied:?}"
    );

    assert_eq!(
        written.len(),
        1,
        "запомненный вердикт ровно один — тот, что после решения: {applied:?}"
    );
    assert_eq!(
        Marked::read(&leg(), written[0]),
        0b1010,
        "вердикт СЛЕДУЮЩЕГО пакета обязан нести решение: оно пережило разговор, по которому решали"
    );

    let decided = leg().holding(0b1010).expect("влезает");
    assert_eq!(
        decided.apply_to(0) & !leg().mask(),
        0,
        "решение живёт ТОЛЬКО в своей области — чужие биты не трогает"
    );
}

/// Половина вторая: пересечение областей — ОТКАЗ ЗАПУСКА, а не тихая порча. Два писателя по одним
/// битам затирали бы друг друга, и заметно это стало бы по поведению сети, а не по красному тесту.
#[test]
fn пересечение_областей_не_даёт_движку_подняться() {
    // 0x0FFF_E000 — область приборов у раскладки по умолчанию; берём её бит.
    let overlapping = Region::new(0x0FFF_E000).expect("связная область");

    let report = engine(Paper::new().then_stop())
        .from(Tcp)
        .extract(Sni)
        .detect(own(Always))
        .telling(Telling::over(overlapping))
        .on(|_target: &str, _distress: Distress| {})
        .run();

    let why = report.why().unwrap_or_default();
    assert!(
        why.contains("пересекается"),
        "отказ обязан назвать причину пересечения; сказано: {why:?}"
    );
}

/// И третья: значение, не влезающее в объявленную область, НЕ КЛАДЁТСЯ. Обрежь его молча — «нога
/// 5» стала бы «ногой 1», и узналось бы это по маршруту, а не по отказу.
#[test]
fn значение_шире_области_не_кладётся_вовсе() {
    let telling = Telling::over(leg());

    assert!(telling.tell("example.com", 0b1111), "четыре бита влезают");
    assert!(
        !telling.tell("example.com", 0b1_0000),
        "пятый бит — отказ, а не обрезание"
    );
}
