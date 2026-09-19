//! ПАМЯТЬ РАЗБОРА ЖИВЁТ НЕ ДОЛЬШЕ РАЗГОВОРА — прогоном через настоящую цепочку, а не чтением.
//!
//! Закон был написан и не исполнялся: `Talks::forget` существовал, и звал его только юнит-тест в
//! собственном файле. Вызовы БЫЛИ и потеряны при переносе — `git log -S "talks.forget"` даёт их в
//! `reflex-engine-nfq`, снесённом 10.09.2026 (`5406330`), а новый цикл фасада их не подобрал.
//! Ценой был рост карт разбора числом ВИДЕННЫХ четвёрок: замер потребителя 18.09.2026 — около
//! 0,8 КБ на четвёрку, монотонно и невозвращаемо, сутками на живых машинах.
//!
//! Витнес устроен ЧУЖИМ ТРАНСПОРТОМ, а не заглядыванием внутрь: `Watched` стоит в той же двери
//! (`.from(..)`), что и `Tcp`, делает ту же работу и ЗАПИСЫВАЕТ, о ком цикл велел забыть. Так
//! проверяется не поле структуры, а обязанность двери — то, что увидит и всякий, кто напишет свой
//! транспорт.

use std::sync::mpsc;
use std::sync::Mutex;
use std::time::Duration;

use reflex::scenario::{request, Paper};
use reflex::*;

/// О ком цикл велел забыть. Статикой, потому что `Transport::forget` — функция типа, а не метода:
/// состояние ей дают, а собственной памяти у неё нет. Тест один в процессе, гонки нет.
static FORGOTTEN: Mutex<Vec<u16>> = Mutex::new(Vec::new());

/// Тот же транспорт, что `Tcp`, плюс запись об уходе. Делегирует ВСЁ: отличие в одном — он
/// свидетельствует.
struct Watched;

impl Transport for Watched {
    type Wire = <Tcp as Transport>::Wire;
    const PORT: u16 = <Tcp as Transport>::PORT;
    type State = <Tcp as Transport>::State;

    fn observe(state: &mut Self::State, read: Read<'_>) -> Observation<Self::Wire> {
        Tcp::observe(state, read)
    }

    fn forget(state: &mut Self::State, flow: &Flow) {
        FORGOTTEN
            .lock()
            .expect("запись об уходе")
            .push(flow.src.port());
        Tcp::forget(state, flow);
    }
}

/// СРОК — второй рубеж уборки (§12.6). Разговор, замолчавший дольше порога, снимается таблицей, и
/// транспорт обязан узнать об этом: иначе его карты помнят четвёрку, которой для движка уже нет.
///
/// Порог здесь не выдуман: `idle` цепочки есть удвоенное окно самого долгого прибора, но не меньше
/// десяти секунд. Прибор молчания ждёт пять — значит порог десять, и тридцать секунд сценарной
/// тишины его заведомо перешагивают.
#[test]
fn the_loop_tells_the_transport_about_a_conversation_that_went_quiet() {
    FORGOTTEN.lock().expect("чисто").clear();

    let paper = Paper::new()
        .then_packet(request(40001))
        // Разговор 40001 замолкает и уходит по сроку; разговор 40002 после него КРУТИТ ЦИКЛ, чтобы
        // узел сетки закрылся и уборка случилась: снятие делает горячий путь, объявление читают на
        // узле.
        .silent_for(Duration::from_secs(30))
        .then_packet(request(40002))
        .silent_for(Duration::from_secs(1))
        .then_stop();

    let report = engine(paper)
        .from(Watched)
        .extract(Sni)
        .detect(Silence::after(secs(5)))
        .on(|_target, _distress| {})
        .run();

    let forgotten = FORGOTTEN.lock().expect("итог").clone();
    assert!(
        forgotten.contains(&40001),
        "разговор снят по сроку — транспорт обязан был узнать; узнал о: {forgotten:?} ({report:?})"
    );
}

/// Та же дверь, тот же зов — но у транспорта БЕЗ памяти по разговору забывать нечего, и пустое
/// тело `Udp::forget` законно. Проверка держит границу: «нечего забыть» не должно превратиться в
/// «зова не было» — тогда следующий транспорт с памятью унаследовал бы утечку молча.
#[test]
fn a_transport_without_per_conversation_memory_still_gets_told() {
    // `Udp::forget` ничего не делает и ничего не возвращает: свидетельствовать тут можно только
    // тем, что цепочка на нём СОБИРАЕТСЯ и проходит прогон. Сборка и есть доказательство: не будь
    // зова в трейте, эта цепочка не отличалась бы от прежней ничем.
    let paper = Paper::new().then_stop();
    let report = engine(paper)
        .from(Udp)
        .extract(Sni)
        .detect(DnsPoison::injected())
        .on(|_target, _distress| {})
        .run();
    assert!(
        format!("{report:?}").contains("Report"),
        "прогон состоялся значением, а не паникой"
    );
}

/// ЖИВОЙ СЧЁТ УТРАТЫ — то, чего у боевого пути не было вовсе.
///
/// `Report::forgotten` считает утрату по потолку значением, но боевой прогон `Report`а не отдаёт
/// НИКОГДА: он не кончается по построению, а `.heard()` возвращает его лишь на ветви «носитель не
/// открылся». Объявление уходило потребителю, которого там нет. Порт [`Detecting::parting`] отдаёт
/// уход ВО ВРЕМЯ прогона и с причиной — по ней видно, сняли мёртвое или живое.
#[test]
fn partings_are_told_while_the_run_is_still_going() {
    let (tx, rx) = mpsc::sync_channel(64);

    let paper = Paper::new()
        .then_packet(request(40011))
        .silent_for(Duration::from_secs(30))
        .then_packet(request(40012))
        .silent_for(Duration::from_secs(1))
        .then_stop();

    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(Silence::after(secs(5)))
        .parting(Tap::new(tx))
        .on(|_target, _distress| {})
        .run();

    let told: Vec<Parted> = rx.try_iter().collect();
    assert!(
        told.iter().any(|parted| parted.flow.src.port() == 40011),
        "разговор ушёл по сроку — порт обязан был о нём сказать; сказано: {told:?}"
    );
    assert!(
        told.iter().all(|parted| parted.why == Departure::Idle),
        "и сказать ПРИЧИНУ: здесь снимали мёртвое, потолок ни при чём — {told:?}"
    );
}
