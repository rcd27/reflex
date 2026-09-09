//! Приборы края читают ЯДЕРНЫЕ величины (через `EdgeView`) и марку, состояния в юзерспейсе не держат.
//! Носитель здесь — локальный `TestEdge` (не conntrack): прибор о носителе не знает по построению.
//!
//! Закон ПАКЕТНЫЙ (`up.packets` 0/1/≥2), порог — по ВОЗРАСТУ потока: два наблюдения умещаются в burst
//! рукопожатия ДО ответа, и лишь возраст отличает «ещё не ответила» от «уже не ответит» (см. докблок
//! `edge_detect`). Тесты гоняют поток пакет за пакетом, перенося фазу через марку — `mark_after`
//! применяет памятку, как это сделал бы носитель на вердикте.

use std::time::Duration;

use reflex_core::edge::EdgeView;
use reflex_core::mealy::Mealy;
use reflex_core::DetectorEvent;
use reflex_instrument::distress::Distress;
use reflex_instrument::edge::{Layout, Memo, Phase};
use reflex_instrument::edge_detect::{EdgeSilence, Verdict};
use reflex_instrument::edge_word::Edged;
use reflex_instrument::wire::Seen;

/// Окно возраста прибора в тестах — секунда. «Молод» — младше, «стар» — старше.
const WINDOW: Duration = Duration::from_secs(1);

fn layout() -> Layout {
    Layout::new(0x0FFF_E000, 0b101).expect("15-битная маска, ненулевой тег")
}

fn silence() -> EdgeSilence<TestEdge> {
    EdgeSilence::new(WINDOW, layout())
}

/// Носитель края для теста — величины кладём прямо, conntrack не при чём.
#[derive(Clone)]
struct TestEdge {
    down_pk: Option<u64>,
    up_pk: Option<u64>,
    down_by: Option<u64>,
    up_by: Option<u64>,
    age: Option<Duration>,
    mark: u32,
}

impl EdgeView for TestEdge {
    fn down_packets(&self) -> Option<u64> {
        self.down_pk
    }
    fn up_packets(&self) -> Option<u64> {
        self.up_pk
    }
    fn down_bytes(&self) -> Option<u64> {
        self.down_by
    }
    fn up_bytes(&self) -> Option<u64> {
        self.up_by
    }
    fn idle(&self) -> Option<Duration> {
        None
    }
    fn age(&self) -> Option<Duration> {
        self.age
    }
    fn mark(&self) -> u32 {
        self.mark
    }
}

/// Наблюдение: пакеты (down/up), байты (down/up), возраст в секундах. Марка — 0 (нетронуто).
fn edge(down_pk: u64, up_pk: u64, down_by: u64, up_by: u64, age_s: u64) -> TestEdge {
    TestEdge {
        down_pk: Some(down_pk),
        up_pk: Some(up_pk),
        down_by: Some(down_by),
        up_by: Some(up_by),
        age: Some(Duration::from_secs(age_s)),
        mark: 0,
    }
}

/// Клиент отдал запрос: три пакета, 400 байт (400 − 3×60 = 220 > 100). `up_pk` и возраст — параметры.
fn with_request(up_pk: u64, age_s: u64) -> TestEdge {
    edge(3, up_pk, 400, 60, age_s)
}

fn with_mark(mut edge: TestEdge, mark: u32) -> TestEdge {
    edge.mark = mark;
    edge
}

fn packet(edge: TestEdge) -> DetectorEvent<Edged<Seen, Option<TestEdge>>> {
    DetectorEvent::packet_now(Edged {
        narrow: Seen::Received { count: 1 },
        edge: Some(edge),
    })
}

/// Один шаг: вернуть находки и МАРКУ после (памятка применена, как сделал бы носитель на вердикте).
fn mark_after(silence: EdgeSilence<TestEdge>, edge: TestEdge) -> (u32, Verdict) {
    let mark = edge.mark;
    let (_next, verdict, ()) = silence.step(packet(edge));
    let next_mark = verdict.0.map_or(mark, |memo| memo.apply_to(mark));
    (next_mark, verdict)
}

fn said(verdict: &Verdict) -> &[Distress] {
    &verdict.1
}

/// Первое наблюдение молчания — лишь подозрение: беды нет, фаза уехала в марку. Порог держит возраст.
#[test]
fn the_first_sight_of_silence_only_suspects() {
    let (mark, verdict) = mark_after(silence(), with_request(1, 0));
    assert!(said(&verdict).is_empty(), "первый пакет не жалуется");
    assert_ne!(mark, 0, "но подозрение уехало в марку");
}

/// Молодой молчащий поток НЕ подтверждается — живой сервер ответит с запозданием на RTT, а два
/// наблюдения умещаются в burst рукопожатия до ответа. Это и был ложняк на чистом vk.
#[test]
fn a_young_silent_target_is_not_yet_confirmed() {
    let s = silence();
    // Возраст 0: только `SYN+ACK`, клиент отдал запрос — но рано судить.
    let (mark, first) = mark_after(s, with_request(1, 0));
    assert!(said(&first).is_empty(), "первое — подозрение");
    // Всё ещё молод (возраст 0 < окно): цель могла просто не успеть ответить.
    let (_mark, second) = mark_after(s, with_mark(with_request(1, 0), mark));
    assert!(
        said(&second).is_empty(),
        "возраст мал — не дроп, а ещё не ответ"
    );
}

/// Цель прислала только `SYN+ACK` и молчит ДОЛЬШЕ окна возраста — тихий дроп: `NoBytes`.
#[test]
fn a_synack_only_target_past_the_window_is_no_bytes() {
    let s = silence();
    let (mark, first) = mark_after(s, with_request(1, 0));
    assert!(said(&first).is_empty(), "первое — подозрение");
    // Возраст 2 с > окно 1 с, up_pk замер на 1, клиент отдал запрос — цель уже не ответит.
    let (_mark, second) = mark_after(s, with_mark(with_request(1, 2), mark));
    assert!(
        said(&second).contains(&Distress::NoBytes),
        "молчит дольше окна — тихий дроп"
    );
}

/// `SYN+ACK` не пришёл вовсе и возраст перешагнул окно — `Blackhole`, а не `NoBytes`.
#[test]
fn a_synack_never_arrived_past_the_window_is_blackhole() {
    let s = silence();
    let (mark, _first) = mark_after(s, edge(1, 0, 60, 0, 0));
    let (_mark, second) = mark_after(s, with_mark(edge(2, 0, 120, 0, 2), mark));
    assert!(
        said(&second)
            .iter()
            .any(|distress| matches!(distress, Distress::Blackhole { .. })),
        "нет `SYN+ACK` — не открытое молчит, а несостоявшееся"
    );
    assert!(!said(&second).contains(&Distress::NoBytes));
}

/// Клиент так и не отдал запрос — не беда даже за окном: `client_spoke` сторожит и в подтверждении.
/// Путь входит через `no_synack`, потом `SYN+ACK` — но дропать нечего.
#[test]
fn a_synack_only_without_a_request_stays_silent() {
    let s = silence();
    let (mark, _first) = mark_after(s, edge(1, 0, 60, 0, 0));
    let (mark, second) = mark_after(s, with_mark(edge(1, 1, 60, 0, 1), mark));
    assert!(said(&second).is_empty());
    // Возраст за окном (3 с), up_pk замер на 1, но запроса нет → НЕ `NoBytes`.
    let (_mark, third) = mark_after(s, with_mark(edge(1, 1, 60, 0, 3), mark));
    assert!(
        said(&third).is_empty(),
        "нет запроса — нечему быть дропнутым"
    );
}

/// Цель прислала пакет сверх `SYN+ACK` (up_pk≥2) — жива: `Released`, НЕ `Confirmed`, и возраст тут ни
/// при чём. Порог живости — ровно «≥2»: марка обязана нести `Released`, не подозрение.
#[test]
fn a_target_that_moves_past_synack_is_released() {
    let s = silence();
    let (mark, first) = mark_after(s, with_request(1, 0));
    assert!(said(&first).is_empty());
    // Даже при возрасте за окном движение пакета отпускает поток.
    let (mark, second) = mark_after(s, with_mark(with_request(2, 5), mark));
    assert!(said(&second).is_empty(), "цель шевельнулась пакетом — жива");
    assert_eq!(
        mark,
        Memo::new(layout(), Phase::Released, 2).apply_to(0),
        "порог живости — один пакет сверх `SYN+ACK`, поток отпущен"
    );
}

/// Цель заведомо жива (много ответных пакетов) — ни подозрения, ни тишины даже на первом наблюдении.
#[test]
fn an_answered_flow_is_not_a_silent_drop() {
    let (_mark, verdict) = mark_after(silence(), with_request(5, 3));
    assert!(said(&verdict).is_empty(), "цель отвечает — беды нет");
}

/// `None` (край не считает, acct off) не даёт судить: беды не объявляем ни на одном наблюдении.
#[test]
fn unknown_counters_are_not_a_silent_drop() {
    let s = silence();
    let blind = TestEdge {
        down_pk: None,
        up_pk: None,
        down_by: None,
        up_by: None,
        age: None,
        mark: 0,
    };
    let (mark, first) = mark_after(s, blind.clone());
    assert!(said(&first).is_empty(), "не считали — не тишина");
    let (_mark, second) = mark_after(s, with_mark(blind, mark));
    assert!(said(&second).is_empty(), "и на втором наблюдении молчим");
}

/// Сказанное однажды не повторяется: фаза `Confirmed` лежит в марке, второй пакет её оттуда читает.
#[test]
fn a_told_flow_stays_silent_on_the_next_packet() {
    let told = Memo::new(layout(), Phase::Confirmed, 1).apply_to(0);
    let (_mark, verdict) = mark_after(silence(), with_mark(with_request(1, 5), told));
    assert!(said(&verdict).is_empty(), "повторно не жалуемся");
}

/// Ожившая цель под `Released` тоже молчит — терминал: обратно в подозрение не возвращаемся.
#[test]
fn a_released_flow_stays_silent() {
    let released = Memo::new(layout(), Phase::Released, 3).apply_to(0);
    let (_mark, verdict) = mark_after(silence(), with_mark(with_request(1, 9), released));
    assert!(said(&verdict).is_empty(), "`Released` терминален");
}

/// Прибор состояния не держит: два шага из одного значения дают один и тот же исход.
#[test]
fn the_instrument_is_stateless() {
    let s = silence();
    let (_m1, first) = mark_after(s, with_request(1, 0));
    let (_m2, second) = mark_after(s, with_request(1, 0));
    assert_eq!(
        said(&first),
        said(&second),
        "исход зависит от края, не от прожитого"
    );
}

/// По нашим битам писал другой — буква `Diverged`, не тишина; его биты НЕ трогаем (памятка `None`).
#[test]
fn a_foreign_writer_is_observed_and_left_alone() {
    let alien = 0x0055_0000;
    let (_mark, verdict) = mark_after(silence(), with_mark(with_request(1, 2), alien));
    assert!(said(&verdict)
        .iter()
        .any(|distress| matches!(distress, Distress::Diverged { .. })));
    assert!(verdict.0.is_none(), "чужие биты не затираем");
}

/// КРАЯ НЕТ — СУДИТЬ НЕ О ЧЕМ, И ПАМЯТКИ НЕТ.
///
/// Пакет, которого ядро ещё не завело в conntrack (первый `SYN` вне таблицы), вида не имеет. Это
/// «не считали», а не «цель не ответила»: скажи прибор что-нибудь здесь — он высказался бы о
/// разговоре, которого край не видит. И памятки быть не может: писать фазу в марку по незнанию
/// значит выдумать состояние.
#[test]
fn без_края_прибор_молчит_и_ничего_не_помнит() {
    let silence: EdgeSilence<TestEdge> = EdgeSilence::new(WINDOW, layout());

    let (_next, (memo, said), ()) = silence.step(DetectorEvent::packet_now(Edged {
        narrow: Seen::Received { count: 1 },
        edge: None::<TestEdge>,
    }));

    assert!(said.is_empty(), "без края сказать нечего");
    assert!(
        memo.is_none(),
        "без края нечего и помнить — фаза не выдумывается"
    );
}
