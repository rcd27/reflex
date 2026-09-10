//! Край в юзерспейсе: то же, что ведёт ядро, но своим счётом. Предел назван прямо — возраст
//! разговора, начавшегося ДО запуска, неизвестен, и `age()` отдаёт `None`, а не ноль.
//!
//! `Paper` здесь — не бумажный носитель `reflex/tests/paper` (тот живёт в другом крейте и тащит
//! `IntoCarrier`/`Layout`, которых у `core` нет): минимальный `Serves`, ровно тех прав, что нужны
//! `Local`, чтобы `Local::<Paper>::remember(…)` и полный шов `serve` вообще собрались.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::rc::Rc;
use std::time::Instant;

use reflex_core::capability::{CanHold, CanRefuse, CanRemember};
use reflex_core::edge::EdgeView;
use reflex_core::held::{Answered, Delivered, Held, Observed, Refused, Terminal};
use reflex_core::local::{Answer, Local, LocalEdge};
use reflex_core::serves::Served;
use reflex_core::types::{Flow, Protocol};
use reflex_core::Serves;

// ─── Минимальный носитель ─────────────────────────────────────────────────────────────────────

struct Envelope(Vec<u8>);

impl Observed for Envelope {
    fn payload(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PaperAnswer {
    Pass,
    Stop,
}

/// Носитель без дома: пакет отдаёт как есть, помнить не умеет — ровно то, чем является ядерная
/// очередь без conntrack (форма, которую получит `WinDivert`). `applied` — журнал того, каким
/// C-словом ушёл вердикт: единственный способ тесту увидеть, что `Local` в самом деле перевёл
/// решение в чужой словарь, а не пропустил всё молчанием.
struct Paper {
    queue: VecDeque<Vec<u8>>,
    applied: Rc<RefCell<Vec<PaperAnswer>>>,
}

impl Paper {
    fn new() -> Paper {
        Paper {
            queue: VecDeque::new(),
            applied: Rc::new(RefCell::new(Vec::new())),
        }
    }

    fn with_packet(bytes: Vec<u8>) -> Paper {
        let mut paper = Paper::new();
        paper.queue.push_back(bytes);
        paper
    }

    fn applied(&self) -> Rc<RefCell<Vec<PaperAnswer>>> {
        Rc::clone(&self.applied)
    }
}

impl Terminal for Paper {
    type Carrier = Envelope;
    type Answer = PaperAnswer;
    type Refusal = ();

    fn apply(
        &mut self,
        answered: Answered<Envelope, PaperAnswer>,
    ) -> Result<Delivered<PaperAnswer>, Refused<PaperAnswer, ()>> {
        self.applied.borrow_mut().push(answered.answer);
        Ok(Delivered {
            at: answered.at,
            answer: answered.answer,
        })
    }
}

impl CanHold for Paper {
    fn release() -> PaperAnswer {
        PaperAnswer::Pass
    }
}

impl CanRefuse for Paper {
    fn refuse() -> PaperAnswer {
        PaperAnswer::Stop
    }
}

impl Serves for Paper {
    // `LocalEdge` — не потому, что `Paper` считает: она НЕ ведёт края вовсе (ровно то, чем
    // является ядерная очередь без conntrack) и всегда отдаёт `None`. Тип взят готовый
    // (`core::local::LocalEdge`), а не заведён новый ради подписи — тем же типом, что и
    // `Local::Edge`, это заодно делает мутацию «подать чужой край вместо своего» ПРЕДСТАВИМОЙ:
    // оба варианта одного типа, компилятор их не различит, различит только тест.
    type Edge = LocalEdge;

    fn serve<F>(
        &mut self,
        until: Instant,
        decide: F,
    ) -> Served<Delivered<PaperAnswer>, Refused<PaperAnswer, ()>>
    where
        F: FnOnce(&Held<Envelope>, Option<LocalEdge>) -> PaperAnswer,
    {
        match self.queue.pop_front() {
            Some(bytes) => {
                let held = Held::new(Envelope(bytes), Instant::now());
                let answer = decide(&held, None);
                Served::Answered(self.apply(held.answered(answer)))
            }
            None => {
                std::thread::sleep(until.saturating_duration_since(Instant::now()));
                Served::Idle
            }
        }
    }
}

// ─── Кадры ────────────────────────────────────────────────────────────────────────────────────

const SRC_PORT: u16 = 55555;
const DST_PORT: u16 = 443;

/// Тот же разговор, что кладут кадры ниже — ключ, которым тест читает дом напрямую, минуя разбор.
fn flow() -> Flow {
    Flow {
        src: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 2).into(), SRC_PORT),
        dst: SocketAddr::new(Ipv4Addr::new(93, 184, 216, 34).into(), DST_PORT),
        protocol: Protocol::Tcp,
    }
}

/// Минимальный кадр IPv4+TCP заданной ДЛИНЫ (L3+L4+нагрузка) — ровно то, что очередь ядра кладёт
/// в руки: без Ethernet. Длина, не нагрузка, — предмет теста «местный_край_считает_кадры».
fn frame_of_len(flags: u8, total: usize) -> Vec<u8> {
    assert!(total >= 40, "меньше заголовков IPv4+TCP не бывает");
    let mut packet = vec![0u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[9] = 6; // TCP
    packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
    packet[16..20].copy_from_slice(&[93, 184, 216, 34]);
    packet[20..22].copy_from_slice(&SRC_PORT.to_be_bytes());
    packet[22..24].copy_from_slice(&DST_PORT.to_be_bytes());
    packet[32] = 5 << 4;
    packet[33] = flags;
    packet[34..36].copy_from_slice(&64240u16.to_be_bytes());
    packet
}

/// Кадр заданной длины, идущий ВНИЗ (клиент → цель), с `ACK` — не `SYN`.
fn a_frame_of(total: usize) -> Vec<u8> {
    frame_of_len(0x10, total)
}

/// Разговор, начатый ДО нас: клиент прислал `ACK` без `SYN` в нашем поле зрения.
fn a_mid_stream_ack() -> Vec<u8> {
    frame_of_len(0x10, 40)
}

/// Стук клиента: `SYN` к цели — единственный кадр, заводящий `opened`.
fn a_syn() -> Vec<u8> {
    frame_of_len(0x02, 40)
}

// ─── Тесты по брифу ───────────────────────────────────────────────────────────────────────────

/// Счёт ведётся в КАДРАХ — так велит закон `EdgeView` (Д6). Считай `Local` нагрузку, порог
/// «клиент отдал запрос» завысился бы на заголовок каждого пакета.
#[test]
fn местный_край_считает_кадры() {
    let mut local = Local::new(Paper::new());
    local.saw_down(a_frame_of(1500));
    local.saw_down(a_frame_of(1500));

    let edge = local.edge_of(flow()).expect("разговор заведён");
    assert_eq!(edge.down_packets(), Some(2));
    assert_eq!(edge.down_bytes(), Some(3000));
}

/// Возраст потока, начатого до нас, неизвестен. `None`, а не ноль: ноль означал бы «только что
/// открылся», и прибор тишины подтвердил бы дроп на живом разговоре. Это предел НОСИТЕЛЯ, не закона.
#[test]
fn возраст_потока_начатого_до_нас_неизвестен() {
    let mut local = Local::new(Paper::new());
    local.saw_down(a_mid_stream_ack()); // не SYN: начала мы не видели

    assert_eq!(local.edge_of(flow()).unwrap().age(), None);
}

/// Памятка ложится домой ТЕМ ЖЕ словом, что и вердикт, и читается обратно маркой — интерфейс тот
/// же, что у ct_mark. Куда легли 32 бита, фасад не знает и знать не должен.
#[test]
fn памятка_ложится_домой_и_читается_маркой() {
    let mut local = Local::new(Paper::new());
    local.saw_down(a_syn());
    local.apply_answer(flow(), Local::<Paper>::remember(0xABCD, true));

    assert_eq!(local.edge_of(flow()).unwrap().mark(), 0xABCD);
}

// ─── Дополнительные тесты (не из брифа): полный шов Serves/Terminal ─────────────────────────────

/// Разговор, у которого `SYN` в поле зрения БЫЛ, получает возраст: `Some`. Пара к
/// «возраст_потока_начатого_до_нас_неизвестен» — показывает, что там `None` не заглушка на каждый
/// случай, а честный ответ ровно там, где начала не видели.
#[test]
fn возраст_потока_с_увиденным_syn_известен() {
    let mut local = Local::new(Paper::new());
    local.saw_down(a_syn());

    assert!(local.edge_of(flow()).unwrap().age().is_some());
}

/// Полный шов: `Local` встаёт декоратором над `Serves` и сам считает кадр, приходящий С НОСИТЕЛЯ —
/// не только через ручной `saw_down`. Направление читается из адресов кадра (клиент → цель), а не
/// объявляется вызывающим: в бою `serve` получает пакет с носителя, а не тестовую пометку.
#[test]
fn serve_считает_кадр_и_кладёт_память_в_дом() {
    let mut local = Local::new(Paper::with_packet(a_syn()));

    let outcome = local.serve(Instant::now(), |_held, _edge| {
        Local::<Paper>::remember(7, true)
    });

    assert!(
        matches!(outcome, Served::Answered(Ok(_))),
        "ответ доставлен"
    );
    let edge = local
        .edge_of(flow())
        .expect("разговор заведён приходом пакета");
    assert_eq!(edge.down_packets(), Some(1));
    assert_eq!(edge.mark(), 7);
}

/// Отказ (`Answer::Stop`) доходит до носителя ЕГО словом отказа, не словом пропуска: гейт `Local`
/// в самом деле разбирает решение и переводит его в чужой словарь, а не пропускает всё молчанием.
#[test]
fn serve_переводит_отказ_в_c_слово_отказа() {
    let paper = Paper::with_packet(a_syn());
    let applied = paper.applied();
    let mut local = Local::new(paper);

    let _ = local.serve(Instant::now(), |_held, _edge| Answer::Stop);

    assert_eq!(*applied.borrow(), vec![PaperAnswer::Stop]);
}

/// ГЛАВНЫЙ ТЕСТ ПОДМЕНЫ (задача 10½): `Local::serve` обязан подать решению СВОЙ край, а не тот,
/// что вернул бы обёрнутый носитель. `Paper` края не ведёт вовсе — её `Serves::serve` всегда
/// отдаёт `None` (см. `impl Serves for Paper`). Если бы `Local` пересылал ЭТОТ `None` решению
/// вместо построения своего — весь смысл декоратора (докблок `core::local`: «Local — форма...
/// которая наконец подставляет свой Edging») был бы фикцией, недоказанной ни одним тестом.
///
/// Мутация: заменить `own_edge` на `_their_edge` в `Local::Serves::serve` (типы совпадают —
/// `Paper::Edge = LocalEdge`, мутация ПРОЙДЁТ компилятор) — `seen` станет `None`, и `expect` ниже
/// покраснеет.
#[test]
fn serve_подаёт_свой_край_а_не_обёрнутого() {
    let mut local = Local::new(Paper::with_packet(a_syn()));
    let mut seen: Option<LocalEdge> = None;

    let _ = local.serve(Instant::now(), |_held, edge| {
        seen = edge;
        Answer::Pass
    });

    let edge = seen.expect(
        "Local обязан подать decide СВОЙ край; обёрнутая Paper края не ведёт и вернула бы None",
    );
    assert_eq!(
        edge.down_packets(),
        Some(1),
        "свой счёт увидел этот же кадр"
    );
}
