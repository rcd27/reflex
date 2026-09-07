//! У ДВЕРИ ШВА ЕСТЬ КОРМЯЩИЙ: НАСТОЯЩИЙ РАЗБОР ПРОВОДА ПИТАЕТ `Sensed::Unread`.
//!
//! Одним прогоном проверяется закон, а не факт о том, что где лежит: край читает байты РОВНО ОДИН
//! РАЗ; через шов ([`reflex_core::interleave::Interleave::unread`],
//! [`reflex_runtime::timed::on_grid`]) едет РАЗОБРАННАЯ БУКВА, а не байты; счётчик непонятого стоит
//! ЗВЕНОМ ЦЕПОЧКИ (`Step`), а не счётчиком в краю до канала; причина отказа едет ЗНАЧЕНИЕМ, потому
//! что «не наш протокол» законно и вечно, а «обрезан» есть потеря и чинится настройкой съёма —
//! слитые в одно число, эти два отказа стали бы неразличимы; и сетка идёт одним и тем же способом
//! что на разобранном, что на непонятом трафике.
//!
//! # Где проходит граница «читает байты / читает разобранное»
//!
//! Ровно на вызове [`framed_once`] внутри [`observe`] — единственном месте всего файла, где на
//! вход приходит `&[u8]`. Всё, что происходит после него (`Framed::unread()`, [`Letter`],
//! [`Unread`], [`DetectorEvent`], [`Tally`]), работает с РЕЗУЛЬТАТОМ разбора. Что за этим краем
//! байтов больше нет, доказывают три независимые вещи, а не расположение кода: счётчик вызовов
//! [`PARSE_CALLS`] (прогон, а не обещание — раздел 1 ниже), тип [`Letter`] — без `&[u8]` внутри и
//! потому `'static`, тогда как [`Framed`] несёт время жизни байтов (раздел 2), и то, что дальше по
//! течению ни один тип, включая [`Tally`], не знает о существовании среза байтов вовсе.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use futures::StreamExt;
use reflex_core::clock::TestClock;
use reflex_core::detector::{DetectorEvent, Sensed};
use reflex_core::parse::Unread;
use reflex_core::step::{Step, StepExt};
use reflex_engine_nfq::parse::{framed, Framed, SERVER_PORT};
use reflex_runtime::timed::on_grid;

const CLIENT: u32 = 0xC0A8_0164;
const SERVER: u32 = 0x8EFA_BD0E;

/// ПОСТРОЕНИЕ TCP-КАДРА — байты кладутся ровно так, как их ждёт разбор очереди: тот порядок
/// полей и те смещения. Кадр, собранный иначе, не доказывал бы ничего о разборе, которым живёт
/// очередь, — он проверял бы выдумку.
fn frame(
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    flags: u8,
    body: &[u8],
) -> Vec<u8> {
    let total = (40 + body.len()) as u16;
    [
        &[0x45u8, 0x00][..],
        &total.to_be_bytes(),
        &[0x00, 0x01, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00],
        &src_ip.to_be_bytes(),
        &dst_ip.to_be_bytes(),
        &src_port.to_be_bytes(),
        &dst_port.to_be_bytes(),
        &[0, 0, 0, 1, 0, 0, 0, 1],
        &[0x50, flags, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00],
        body,
    ]
    .concat()
}

/// ПОСТРОЕНИЕ UDP-КАДРА — тот же источник и тот же приём, что у [`frame`].
fn udp_frame(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, body: &[u8]) -> Vec<u8> {
    let payload = (8 + body.len()) as u16;
    [
        &[0x45u8, 0x00][..],
        &(20 + payload).to_be_bytes(),
        &[0x00, 0x01, 0x40, 0x00, 0x40, 17, 0x00, 0x00],
        &src_ip.to_be_bytes(),
        &dst_ip.to_be_bytes(),
        &src_port.to_be_bytes(),
        &dst_port.to_be_bytes(),
        &payload.to_be_bytes(),
        &[0x00, 0x00],
        body,
    ]
    .concat()
}

/// БУКВА, ДОЕЗЖАЮЩАЯ ЧЕРЕЗ ШОВ, — РЕЗУЛЬТАТ РАЗБОРА, А НЕ СРЕЗ БАЙТОВ.
///
/// У типа нет ни `&[u8]`, ни времени жизни вовсе: значение живёт само по себе, дольше кадра, из
/// которого получено. Это не соглашение — компилятор проверяет его ниже, у [`STATIC_PROOF`]:
/// понеси `Letter` чужое время жизни (как несёт его [`Framed`]), сборка такой проверки откажет.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Letter {
    Tcp { dst_ip: u32 },
    Udp { dst_ip: u32 },
}

impl From<Framed<'_>> for Letter {
    /// Вызывается ровно там, где [`Framed::unread`] уже сказал `None` — то есть на `Tcp`/`Udp`.
    /// Остальные варианты перечислены поимённо, не хвостом: полноту здесь сторожит компилятор так
    /// же, как её сторожит буква алфавита детектора.
    fn from(framed: Framed<'_>) -> Self {
        match framed {
            Framed::Tcp(segment) => Letter::Tcp {
                dst_ip: segment.header.ends.dst_ip,
            },
            Framed::Udp(payload) => Letter::Udp {
                dst_ip: payload.ends.dst_ip,
            },
            Framed::NotIpv4 | Framed::NotOurProtocol | Framed::Truncated => {
                unreachable!("вызывающий обязан проверить Framed::unread() перед From::from")
            }
        }
    }
}

/// ПРОВЕРКА ПО ТИПУ, ЧТО ЧЕРЕЗ ШОВ ЕДЕТ БУКВА: `Letter` не хранит заимствования, значит `'static`.
/// Не компилируется — не буква через шов летит, а нечто, что помнит про исходные байты.
const STATIC_PROOF: fn() = || {
    fn is_owned<T: 'static>() {}
    is_owned::<Letter>();
};

/// СЧЁТЧИК ВЫЗОВОВ РАЗБОРА — свидетель того, что байты каждого кадра читаются РОВНО ОДИН РАЗ.
/// Не продуктовый код: обычный `parse::framed` вызывался бы без счётчика. Он существует затем,
/// чтобы утверждение «разбор один» было прогоном, а не обещанием в докблоке.
static PARSE_CALLS: AtomicUsize = AtomicUsize::new(0);

fn framed_once(frame: &[u8]) -> Framed<'_> {
    PARSE_CALLS.fetch_add(1, Ordering::SeqCst);
    framed(frame)
}

/// ГРАНИЦА КРАЯ: единственная функция файла, принимающая `&[u8]`. Дальше — только результат
/// разбора. `Framed::unread()` решает, какую дверь шва открыть: `None` — `Sensed::Seen`,
/// `Some(why)` — `Sensed::Unread(why)`.
fn observe(bytes: &[u8], at: Instant) -> (Sensed<Letter>, Instant) {
    let framed = framed_once(bytes);
    let sensed = match framed.unread() {
        Some(why) => Sensed::Unread(why),
        None => Sensed::Seen(Letter::from(framed)),
    };
    (sensed, at)
}

fn at(began: Instant, millis: u64) -> Instant {
    began + Duration::from_millis(millis)
}

/// СЧЁТЧИК НЕПОНЯТОГО КАК ЗВЕНО ЦЕПОЧКИ (`Step`), А НЕ СЧЁТЧИК В КРАЮ ДО КАНАЛА.
///
/// Питается тем же `DetectorEvent`, каким живёт всякий детектор фундамента, и стыкуется тем же
/// комбинатором ([`StepExt::over`]), каким стыкуется всякий шаг. Показание — обычный выход шага,
/// а не что-то, добытое сбоку.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Tally {
    packets: u32,
    opaque: u32,
}

/// ОБЛАСТЬ ЗАКОННОГО СТЕНДА.
///
/// Объявляется здесь, а не в фундаменте: закон обязан быть выразим для того, кто заводит свою
/// область снаружи, и стенд — законный заводящий.
struct Bench;
impl reflex_core::word::Region for Bench {}

/// Счёт стенда адресован стенду: ни пакету, ни разговору, ни цели он ничего не говорит.
impl reflex_core::word::Word for Tally {
    type Of = Bench;
}

impl Step for Tally {
    type From = DetectorEvent<Letter>;
    type To = Tally;

    fn step(self, event: Self::From) -> (Self, Self::To) {
        let next = match event {
            DetectorEvent::Packet { .. } => Tally {
                packets: self.packets + 1,
                ..self
            },
            DetectorEvent::Opaque { .. } => Tally {
                opaque: self.opaque + 1,
                ..self
            },
            DetectorEvent::Tick { .. } => self,
        };
        (next, next)
    }
}

/// ПЯТЬ УТВЕРЖДЕНИЙ ЗАДАЧИ 4′, ОДНИМ ПРОГОНОМ.
///
/// Кадры настоящие (способ построения — из тестов `engine-nfq`), сетка настоящая
/// (`reflex_runtime::timed::on_grid` на [`TestClock`]), счётчик — настоящее звено `Step`.
#[tokio::test]
async fn a_feeder_exists_the_seam_carries_opaque_traffic_end_to_end() {
    STATIC_PROOF();

    let clock = TestClock::new();
    let began = clock.began();
    let every = Duration::from_millis(100);

    // Пять кадров, поровну разобранных и непонятых, по одному на каждый узел сетки 100..500 мс.
    let good_tcp = frame(CLIENT, SERVER, 51000, SERVER_PORT, 0x02, b"");
    let not_ipv4 = [0x60u8];
    let good_udp = udp_frame(CLIENT, SERVER, 51000, SERVER_PORT, b"initial");
    // Ни TCP, ни UDP: протокол ICMP там, где обычно стоит TCP.
    let not_our_protocol = [&frame(CLIENT, SERVER, 1, 2, 0, b"")[..9], &[1u8][..]].concat();
    // TCP-кадр, обрезанный внутри IP-заголовка, до поля протокола выше.
    let full = frame(CLIENT, SERVER, 51000, SERVER_PORT, 0x18, b"hello");
    let truncated = full[..14].to_vec();

    let observations = vec![
        observe(&good_tcp, at(began, 100)),
        observe(&not_ipv4, at(began, 200)),
        observe(&good_udp, at(began, 300)),
        observe(&not_our_protocol, at(began, 400)),
        observe(&truncated, at(began, 500)),
    ];

    // === 1. Разбор один и он в краю. ===
    // Пять кадров — пять вызовов `parse::framed`. Второго разбора для передачи причины отказа
    // дальше не потребовалось: `Framed::unread()` в `observe` берёт её из уже разобранного значения.
    assert_eq!(
        PARSE_CALLS.load(Ordering::SeqCst),
        5,
        "байты каждого кадра читаются ровно один раз"
    );

    let events: Vec<DetectorEvent<Letter>> =
        on_grid(futures::stream::iter(observations), clock, began, every)
            .collect()
            .await;

    // Шов не читает содержимое наблюдения — прогон через него не должен разобрать байты снова.
    assert_eq!(
        PARSE_CALLS.load(Ordering::SeqCst),
        5,
        "шов и цепочка ниже него не разбирают байты повторно"
    );

    // === 4. Причина доезжает значением. ===
    let reasons: Vec<Unread> = events
        .iter()
        .filter_map(|event| match event {
            DetectorEvent::Opaque { why, .. } => Some(*why),
            DetectorEvent::Packet { .. } | DetectorEvent::Tick { .. } => None,
        })
        .collect();
    assert_eq!(
        reasons,
        vec![Unread::NotIpv4, Unread::NotOurProtocol, Unread::Truncated],
        "три разных отказа разбора различимы на дальнем конце шва по значению, а не слиты в один счётчик"
    );

    // === 2. Через шов едет БУКВА, а не байты. ===
    let letters: Vec<Letter> = events
        .iter()
        .filter_map(|event| match event {
            DetectorEvent::Packet { input, .. } => Some(*input),
            DetectorEvent::Opaque { .. } | DetectorEvent::Tick { .. } => None,
        })
        .collect();
    assert_eq!(
        letters,
        vec![
            Letter::Tcp { dst_ip: SERVER },
            Letter::Udp { dst_ip: SERVER }
        ],
        "на дальнем конце — разобранное поле заголовка, а не байты кадра"
    );

    // === 5. Сетка идёт и на непонятом трафике так же, как на разобранном. ===
    let ticks: Vec<u64> = events
        .iter()
        .filter_map(|event| match event {
            DetectorEvent::Tick { node, .. } => Some(*node),
            DetectorEvent::Packet { .. } | DetectorEvent::Opaque { .. } => None,
        })
        .collect();
    assert_eq!(
        ticks,
        vec![1, 2, 3, 4, 5],
        "перед каждым из пяти наблюдений — разобранным и непонятым вперемешку — сетка выдаёт свой узел"
    );

    // === 3. Счётчик непонятого — звено цепочки, а не счётчик в краю до канала. ===
    let tallies: Vec<Tally> = Tally::default()
        .over(futures::stream::iter(events))
        .collect()
        .await;
    let last = *tallies
        .last()
        .expect("десять событий (пять узлов и пять наблюдений) обязаны дать десять показаний");
    assert_eq!(
        last,
        Tally {
            packets: 2,
            opaque: 3
        },
        "звено-счётчик держит и разобранное, и непонятое в одном показании обычного шага"
    );
}
