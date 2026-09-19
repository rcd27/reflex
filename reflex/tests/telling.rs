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

use paper::{dns_query, log, request, taken, Paper, PaperAnswer};
use reflex::telling::{Known, Telling, Unknowable};
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
            DetectorEvent::Tick { .. }
            | DetectorEvent::Opaque { .. }
            | DetectorEvent::Torn { .. } => (self, SmallVec::new(), ()),
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
fn a_decision_is_read_by_the_verdict_of_the_next_packet_of_the_same_target() {
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
            assert!(
                posting.tell(target, 0b1010),
                "решение обязано влезть в область"
            );
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
fn overlapping_regions_do_not_let_the_engine_come_up() {
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

/// ЧЕТВЁРТАЯ, И ОНА ПРО ЧИСЛО ЧИТАТЕЛЕЙ: решение достаётся КАЖДОЙ цепочке, а не первой спросившей.
///
/// # Чем оплачено (живой стенд, 12.09.2026)
///
/// Продукт крутит две цепочки над одним знанием — TCP и QUIC, — и каждой отдана КОПИЯ ручки.
/// Копия по докблоку значит «ручек сколько угодно, дверь одна», и про писателей это верно. Про
/// читателей не было сказано ничего, а `drain` забирает очередь ЦЕЛИКОМ: письмо доставалось той
/// цепочке, чей оборот случился раньше, и второй не доставалось НИКОГДА.
///
/// Наблюдалось это не как потеря, а как «лечение через раз»: марка решения доезжала до `SYN` в
/// 8 случаях из 111 (счётчики ядра, `rutracker.org`), потому что QUIC-нить крутится по тику и без
/// трафика — и вычерпывала письма у TCP-цепочки, которой они и были нужны.
#[test]
fn a_decision_reaches_every_chain_not_only_the_first_asker() {
    let telling = Telling::over(leg());

    // ПОРЯДОК ТОТ ЖЕ, ЧТО У ПРОДУКТА: сперва поднимаются ОБЕ цепочки, и лишь потом расследование
    // кладёт решение из своей нити. Положи его раньше — тест спрашивал бы про долг перед ещё не
    // существующим читателем, а это другой вопрос.
    let chain = |paper: Paper, handle: Telling| {
        engine(paper)
            .from(Tcp)
            .extract(Sni)
            .detect(own(Always))
            .telling(handle)
            .heard()
            .expect("бумажная цепочка поднимается")
    };

    let paper_tcp = Paper::new().then_packet(request(40001)).then_stop();
    let applied_tcp = paper_tcp.applied();
    let tcp_chain = chain(paper_tcp, telling.clone());

    let paper_quic = Paper::new().then_packet(request(40001)).then_stop();
    let applied_quic = paper_quic.applied();
    let quic_chain = chain(paper_quic, telling.clone());

    assert!(
        telling.tell("93.184.216.34", 0b1010),
        "решение влезает в область"
    );

    tcp_chain.for_each(drop);
    quic_chain.for_each(drop);

    let tcp = marks(&taken(applied_tcp));
    let quic = marks(&taken(applied_quic));

    let read = |written: Vec<u32>| {
        written
            .iter()
            .map(|mark| Marked::read(&leg(), *mark))
            .collect::<Vec<_>>()
    };

    assert_eq!(
        read(tcp),
        vec![0b1010],
        "первая цепочка обязана прочесть решение"
    );
    assert_eq!(
        read(quic),
        vec![0b1010],
        "ВТОРАЯ цепочка обязана прочесть ТО ЖЕ решение: у знания один владелец, \
         а читателей столько, сколько цепочек — иначе лечение работает через раз"
    );
}

/// И третья: значение, не влезающее в объявленную область, НЕ КЛАДЁТСЯ. Обрежь его молча — «нога
/// 5» стала бы «ногой 1», и узналось бы это по маршруту, а не по отказу.
#[test]
fn a_value_wider_than_its_region_is_not_written_at_all() {
    let telling = Telling::over(leg());

    assert!(telling.tell("example.com", 0b1111), "четыре бита влезают");
    assert!(
        !telling.tell("example.com", 0b1_0000),
        "пятый бит — отказ, а не обрезание"
    );
}

// ─── ИЗВЕСТНОЕ ЗАРАНЕЕ ─────────────────────────────────────────────────────────────────

const STRAIGHT: u32 = 0b0001;
const CONTOUR: u32 = 0b1100;

fn priors() -> Telling {
    Telling::over(leg())
        .knowing(Known::suffixes(["gosuslugi.ru", "yandex.ru"]).marked(STRAIGHT))
        .and_then(|telling| {
            telling.knowing(Known::suffixes(["chatgpt.com", "music.yandex.ru"]).marked(CONTOUR))
        })
        .expect("прайоры помещаются в область и не спорят друг с другом")
}

/// Цепочка имён, как у продукта: ключ — имя из вопроса, и марка ложится на сам вопрос.
fn asked(telling: Telling, name: &str) -> Vec<u32> {
    let paper = Paper::new().then_packet(dns_query(40001, name)).then_stop();
    let applied = paper.applied();
    engine(paper)
        .from(Udp)
        .extract(Sni)
        .detect(Resolve::names())
        .telling(telling)
        .heard()
        .expect("бумажная цепочка поднимается")
        .for_each(drop);
    read(marks(&taken(applied)))
}

fn read(written: Vec<u32>) -> Vec<u32> {
    written
        .iter()
        .map(|mark| Marked::read(&leg(), *mark))
        .collect()
}

#[test]
fn a_known_name_is_led_from_its_very_first_packet() {
    assert_eq!(asked(priors(), "ab.chatgpt.com"), vec![CONTOUR]);
    assert_eq!(asked(priors(), "www.gosuslugi.ru"), vec![STRAIGHT]);
}

#[test]
fn a_suffix_covers_its_subdomains_and_not_its_lookalikes() {
    let priors = priors();

    assert_eq!(priors.known("gosuslugi.ru"), Some(STRAIGHT));
    assert_eq!(priors.known("lk.gosuslugi.ru"), Some(STRAIGHT));
    assert_eq!(priors.known("notgosuslugi.ru"), None);
    assert_eq!(priors.known("gosuslugi.ru.example.com"), None);
}

#[test]
fn the_longest_suffix_decides() {
    let priors = priors();

    assert_eq!(priors.known("mail.yandex.ru"), Some(STRAIGHT));
    assert_eq!(priors.known("api.music.yandex.ru"), Some(CONTOUR));
}

#[test]
fn what_is_known_does_not_yield_to_what_is_told() {
    let priors = priors();

    assert!(!priors.tell("www.gosuslugi.ru", CONTOUR));
    assert_eq!(asked(priors, "www.gosuslugi.ru"), vec![STRAIGHT]);
}

#[test]
fn an_address_answered_for_a_known_name_is_known_too() {
    let priors = priors();
    let paper = Paper::new().then_packet(request(40001)).then_stop();
    let applied = paper.applied();
    let chain = engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(own(Always))
        .telling(priors.clone())
        .heard()
        .expect("бумажная цепочка поднимается");

    assert!(priors.tell("93.184.216.34", CONTOUR));
    assert_eq!(
        priors.bind("93.184.216.34", "www.gosuslugi.ru"),
        Some(STRAIGHT)
    );
    assert!(!priors.tell("93.184.216.34", CONTOUR));
    chain.for_each(drop);

    assert_eq!(priors.known("93.184.216.34"), Some(STRAIGHT));
    assert_eq!(read(marks(&taken(applied))), vec![STRAIGHT]);
}

#[test]
fn an_address_shared_by_two_known_names_follows_the_first_declared() {
    let priors = priors();

    assert_eq!(priors.bind("104.18.32.47", "chatgpt.com"), Some(CONTOUR));
    assert_eq!(priors.bind("104.18.32.47", "gosuslugi.ru"), Some(STRAIGHT));
    assert_eq!(priors.bind("104.18.32.47", "chatgpt.com"), Some(STRAIGHT));
    assert_eq!(priors.known("104.18.32.47"), Some(STRAIGHT));
}

#[test]
fn an_address_of_an_unknown_name_stays_unknown() {
    let priors = priors();

    assert_eq!(priors.bind("93.184.216.34", "example.com"), None);
    assert_eq!(priors.known("93.184.216.34"), None);
    assert!(priors.tell("93.184.216.34", CONTOUR));
}

#[test]
fn a_prior_wider_than_the_region_is_refused() {
    let refused = Telling::over(leg()).knowing(Known::suffixes(["chatgpt.com"]).marked(0b1_0000));

    assert!(matches!(refused, Err(Unknowable::Unheld(0b1_0000))));
}

#[test]
fn one_name_cannot_be_known_two_ways() {
    let refused = Telling::over(leg())
        .knowing(Known::suffixes(["yandex.ru"]).marked(STRAIGHT))
        .and_then(|telling| telling.knowing(Known::suffixes(["yandex.ru"]).marked(CONTOUR)));

    assert!(matches!(refused, Err(Unknowable::Twice(name)) if name == "yandex.ru"));
}

/// ПРЕДМЕТ: внеполосное решение доезжает и у цепочки СО СВЁРТКОЙ.
///
/// Дверь `telling` стояла только до `.about`, и пайпу с копределом была недоступна — при том, что
/// решают именно о ЦЕЛИ, то есть о той области, ради которой копредел и заведён. Закон проверяет не
/// собираемость (она обманчива), а ДОЕЗД: вердикт следующего пакета обязан нести решение.
#[test]
fn a_decision_reaches_the_verdict_of_a_folded_chain_too() {
    let telling = Telling::over(leg());
    let posting = telling.clone();

    let paper = Paper::new()
        .then_packet(request(40001))
        .then_packet(request(40001))
        .then_stop();
    let applied = paper.applied();

    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(own(Always))
        .about(|words| words.first().map(|word| (*word).clone()))
        .on_target(|_target, _voiced| {})
        .telling(telling)
        .on(move |target: &str, _distress: Distress| {
            assert!(
                posting.tell(target, 0b1010),
                "решение обязано влезть в область"
            );
        })
        .run();

    let written = marks(&taken(applied));
    assert_eq!(
        written.len(),
        1,
        "запомненный вердикт ровно один — тот, что после решения"
    );
    assert_eq!(
        Marked::read(&leg(), written[0]),
        0b1010,
        "решение обязано доезжать до вердикта и у свёрнутой цепочки"
    );
}
