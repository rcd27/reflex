//! ЗАКОН КАЛИТКИ: ЧТО ПОРОДИЛ МИР — ВИДНО НАБЛЮДАТЕЛЮ, И ПРИТОМ ВСЁ.
//!
//! # Чем этот закон отличается от закона инъекции
//!
//! РОЛИ ПЕРЕВЁРНУТЫ. Там подопытный отправлял, а свидетельствовал тот, до кого должно было дойти;
//! здесь подопытный НАБЛЮДАЕТ, а свидетельствует тот, кто породил трафик. Вместе с ролями меняется
//! и то, что делает прогон недействительным: у инъекции — молчащий прибор, здесь — молчащий мир.
//!
//! # Что типом невыразимо
//!
//! `CanObserve` требует [`Source`](reflex_core::backend::Source) — заявить «умею наблюдать», не
//! отдавая потока, нельзя. Но вторая половина смысла, «НЕ ВМЕШИВАЯСЬ», типом не выражается вовсе:
//! наблюдатель, роняющий каждый второй пакет, синтаксически неотличим от честного. Ловится это
//! только СЧЁТОМ — и потому закону нужен независимый ответ на вопрос «сколько ушло».
//!
//! Мир здесь ПАМЯТНЫЙ, и проверки сертифицируют САМ ЗАКОН. Настоящее свидетельство даёт живое
//! устройство, где число ушедших кадров берётся у счётчика ядра — прибора иной природы, чем и
//! наблюдатель, и libpcap.

use futures::stream;
use reflex_core::backend::Source;
use reflex_core::capability::CanObserve;
use reflex_core::certify::observation::{observes, watching, Broken, Invalid, Origin};
use reflex_core::certify::Verdict;

const NONCE: &[u8] = b"nonce-obs-7c";

/// НАБЛЮДАТЕЛЬ, ОТДАЮЩИЙ РОВНО ТО, ЧТО ЕМУ ПОКАЗАЛИ.
///
/// Поток задаётся списком: памятный мир не умеет ронять пакеты сам, и всякая потеря здесь —
/// НАМЕРЕННАЯ, то есть проверяемая.
struct Watcher(Vec<Vec<u8>>);

impl Source for Watcher {
    type Packet = Vec<u8>;
    type Packets<'a>
        = stream::Iter<std::vec::IntoIter<Vec<u8>>>
    where
        Self: 'a;

    fn packets(&mut self) -> Self::Packets<'_> {
        stream::iter(std::mem::take(&mut self.0))
    }
}

impl CanObserve for Watcher {}

/// МИР, КОТОРЫЙ ЗНАЕТ, СКОЛЬКО ПОРОДИЛ. В памятном мире это число; на живом устройстве —
/// разность счётчиков ядра до и после.
struct World(usize);

impl Origin for World {
    fn emit(&mut self, _nonce: &[u8]) -> usize {
        self.0
    }
}

fn frames(count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|n| {
            b"\x88\xb5"
                .iter()
                .copied()
                .chain(NONCE.iter().copied())
                .chain([n as u8])
                .collect()
        })
        .collect()
}

/// ЧЕСТНЫЙ НАБЛЮДАТЕЛЬ ЗАКОН ДЕРЖИТ.
#[tokio::test]
async fn a_watcher_that_sees_everything_holds_the_law() {
    let mut dut = Watcher(frames(5));
    let mut world = World(5);

    let outcome = observes(&mut world, NONCE, watching(&mut dut)).await;

    assert_eq!(outcome, Verdict::Held);
}

/// РОНЯЮЩИЙ — НЕ ДЕРЖИТ, И ЭТО ГЛАВНАЯ ПРОВЕРКА ФАЙЛА.
///
/// Типом такой наблюдатель безупречен: `Source` реализован, поток отдаётся. Ровно то, что типы
/// поймать не могут, — и ловится оно СЧЁТОМ, а не наличием.
#[tokio::test]
async fn a_watcher_that_drops_packets_is_caught() {
    let mut dut = Watcher(frames(2));
    let mut world = World(5);

    let outcome = observes(&mut world, NONCE, watching(&mut dut)).await;

    assert_eq!(outcome, Verdict::Broken(Broken::Lost { sent: 5, seen: 2 }));
}

/// ДВОЯЩИЙ — ТОЖЕ НЕ ДЕРЖИТ, И ЭТО ДРУГАЯ БЕДА С ДРУГОЙ ПОЧИНКОЙ.
///
/// Потеря и дубль — не оттенки друг друга: первая лечится в приёме, второй в разметке. Слить их в
/// одно «число не сошлось» значило бы отнять у читателя то единственное, по чему их различают.
#[tokio::test]
async fn a_watcher_that_doubles_packets_is_caught_too() {
    let mut dut = Watcher(frames(7));
    let mut world = World(5);

    let outcome = observes(&mut world, NONCE, watching(&mut dut)).await;

    assert_eq!(
        outcome,
        Verdict::Broken(Broken::Duplicated { sent: 5, seen: 7 })
    );
}

/// МОЛЧАЩИЙ МИР НЕ ДАЁТ ВЕРДИКТА ВОВСЕ.
///
/// Наблюдателю, которому нечего было видеть, нельзя предъявить, что он не увидел. Это зеркало
/// `WitnessSilent` из закона инъекции: там молчал прибор, здесь молчит мир, и оба раза беда —
/// стенда, а не подопытного.
#[tokio::test]
async fn a_silent_world_yields_no_verdict() {
    let mut dut = Watcher(frames(0));
    let mut world = World(0);

    let outcome = observes(&mut world, NONCE, watching(&mut dut)).await;

    assert_eq!(outcome, Verdict::Invalid(Invalid::WorldSilent));
}

/// ЧУЖОЙ ТРАФИК НЕ ЗАСЧИТЫВАЕТСЯ — НИ ЗА, НИ ПРОТИВ.
///
/// Наблюдатель видит и посторонние кадры; считай закон всё подряд — честный наблюдатель в живом
/// сегменте немедленно стал бы «двоящим». Нонс отвечает на вопрос «сколько НАШИХ он увидел».
#[tokio::test]
async fn someone_elses_traffic_changes_nothing() {
    let noisy = frames(5)
        .into_iter()
        .chain([
            b"chatter from a neighbour".to_vec(),
            b"arp who-has".to_vec(),
        ])
        .collect();
    let mut dut = Watcher(noisy);
    let mut world = World(5);

    let outcome = observes(&mut world, NONCE, watching(&mut dut)).await;

    assert_eq!(outcome, Verdict::Held);
}
