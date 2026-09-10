//! `timeout` БЕЗ ЧАСОВ — и с двумя сроками, которые нельзя путать.
//!
//! Смешение «предмет замолчал» и «мы перестали ждать» лживо приписывает миру наше собственное
//! нетерпение: два независимых срока обязаны остаться двумя, а не слиться в один по имени
//! удобства.

use reflex_core::detector::DetectorEvent;
use reflex_core::mealy::Mealy;
use reflex_core::parse::Unread;
use reflex_core::timeout::{Deadline, Expiry, Timeout};
use reflex_core::word::{Base, Word};
use std::time::{Duration, Instant};

/// ОБЛАСТЬ ЗАКОННОГО СТЕНДА.
///
/// Объявляется здесь, а не в фундаменте: закон обязан быть выразим для того, кто заводит свою
/// область снаружи, и стенд — законный заводящий.
struct Bench;
impl Base for Bench {
    type Fibre = ();
}

/// ПРЕДМЕТ, ЗА КОТОРЫМ СМОТРИТ ОПЕРАТОР. Своё имя, а не голое число: срок наследует АДРЕС
/// предмета, и предмет обязан его иметь.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Watched(i32);

impl Word for Watched {
    type Of = Bench;
}

/// Срок, названный предмету стенда.
fn idle() -> Deadline<Watched> {
    Deadline::of(Expiry::Idle)
}

/// Потолок ожидания, названный предмету стенда.
fn ceiling() -> Deadline<Watched> {
    Deadline::of(Expiry::Ceiling)
}

const IDLE: Duration = Duration::from_millis(300);
const CEILING: Duration = Duration::from_millis(1_000);

fn run(events: Vec<DetectorEvent<Watched>>) -> Vec<Deadline<Watched>> {
    events
        .into_iter()
        .fold(
            (Timeout::new(IDLE, CEILING), Vec::new()),
            |(detector, mut seen), event| {
                let (detector, signals, ()) = detector.step(event);
                seen.extend(signals);
                (detector, seen)
            },
        )
        .1
}

fn packet(t: Instant, millis: u64) -> DetectorEvent<Watched> {
    DetectorEvent::Packet {
        input: Watched(1),
        at: t + Duration::from_millis(millis),
    }
}

fn tick(t: Instant, millis: u64) -> DetectorEvent<Watched> {
    DetectorEvent::Tick {
        node: millis,
        at: t + Duration::from_millis(millis),
    }
}

/// ТИШИНА ДОЛЬШЕ ПОРОГА — `Idle`.
#[test]
fn silence_longer_than_the_threshold_is_idle() {
    let t = Instant::now();

    assert_eq!(
        run(vec![packet(t, 0), tick(t, 200), tick(t, 400)]),
        vec![idle()]
    );
}

/// ВСЯКОЕ СОБЫТИЕ ОТОДВИГАЕТ ТИШИНУ.
#[test]
fn any_event_pushes_the_silence_threshold_back() {
    let t = Instant::now();

    assert_eq!(
        run(vec![
            packet(t, 0),
            tick(t, 200),
            packet(t, 250),
            tick(t, 400),
            tick(t, 500),
        ]),
        Vec::<Deadline<Watched>>::new(),
        "к 500 мс с последнего события прошло 250 — тишины ещё нет"
    );
}

/// ПОТОЛОК ЕСТЬ УТВЕРЖДЕНИЕ О НАС: он наступает, ДАЖЕ ЕСЛИ события идут.
///
/// Это главное различие двух сроков. `Idle` говорит «предмет замолчал», `Ceiling` — «мы перестали
/// ждать». Слить их значило бы объявить своё нетерпение свойством мира.
#[test]
fn the_ceiling_fires_even_while_events_keep_arriving() {
    let t = Instant::now();

    assert_eq!(
        run(vec![
            packet(t, 0),
            packet(t, 200),
            packet(t, 400),
            packet(t, 600),
            packet(t, 800),
            packet(t, 1_000),
            tick(t, 1_050),
        ]),
        vec![ceiling()],
        "события шли без перерыва — значит это не про них, а про нас"
    );
}

/// ВЫИГРЫВАЕТ ТОТ СРОК, ЧЕЙ МОМЕНТ НАСТУПИЛ РАНЬШЕ, а не тот, что проверен первым.
///
/// Иначе порядок проверок в коде становился бы скрытым правилом, и при потолке короче тишины
/// прибор врал бы о причине.
#[test]
fn whichever_threshold_is_crossed_first_wins() {
    let t = Instant::now();
    let sooner_ceiling = Timeout::new(Duration::from_millis(900), Duration::from_millis(100));

    let (_detector, out) = [packet(t, 0), tick(t, 950)].into_iter().fold(
        (sooner_ceiling, Vec::new()),
        |(detector, mut seen), event| {
            let (detector, signals, ()) = detector.step(event);
            seen.extend(signals);
            (detector, seen)
        },
    );

    assert_eq!(
        out,
        vec![ceiling()],
        "потолок в 100 мс наступил раньше тишины в 900 — он и назван"
    );
}

/// ГОВОРИТ ОДИН РАЗ, А НОВОЕ СОБЫТИЕ ЗАВОДИТ СРОК ЗАНОВО.
///
/// Поток, замерший дважды, обязан дать два высказывания: это два разных простоя, а не один
/// длинный. Повтор же о том же простое был бы шумом.
#[test]
fn it_speaks_once_per_arming_and_a_new_event_arms_it_again() {
    let t = Instant::now();

    assert_eq!(
        run(vec![
            packet(t, 0),
            tick(t, 400),
            tick(t, 500),
            tick(t, 600),
            packet(t, 700),
            tick(t, 1_100),
        ]),
        vec![idle(), idle()],
        "два простоя — два высказывания, и ни одного лишнего между ними"
    );
}

/// ПОКА НИЧЕГО НЕ ПРИХОДИЛО, СРОКА НЕТ. Нельзя истечь тому, что не начиналось.
#[test]
fn nothing_ever_seen_means_nothing_to_expire() {
    let t = Instant::now();

    assert_eq!(
        run(vec![tick(t, 500), tick(t, 5_000)]),
        Vec::<Deadline<Watched>>::new()
    );
}

/// ДЫРА НЕ ДЕЛАЕТ ИЗ ГОВОРИВШЕГО ПРЕДМЕТА ЗАМОЛЧАВШИЙ.
///
/// `Idle` есть вывод О МИРЕ, и выводится он из ОТСУТСТВИЯ наблюдений в окне. Дыра означает, что
/// отсутствие не установлено: наблюдения были и до нас не дошли. Сказать `Idle` по такому окну —
/// приписать миру собственную слепоту (§7, Д7).
#[test]
fn a_tear_does_not_turn_a_speaking_subject_into_a_silent_one() {
    let t = Instant::now();

    assert_eq!(
        run(vec![
            packet(t, 0),
            DetectorEvent::Torn {
                at: t + Duration::from_millis(200)
            },
            tick(t, 400),
        ]),
        vec![],
        "наблюдение в 200мс могло быть — окно с дырой о тишине не свидетельствует"
    );
}

/// НАШЕ НЕТЕРПЕНИЕ ДЫРОЙ НЕ ПОДДЕЛЫВАЕТСЯ.
///
/// `Ceiling` говорит О НАС: сколько ждём мы. Утверждение о себе не выводится из наблюдений мира
/// вовсе, и подделать его пропажей чужих байт нельзя — гасить его значило бы разучиться
/// останавливаться.
#[test]
fn a_tear_does_not_touch_our_own_patience() {
    let t = Instant::now();

    assert_eq!(
        run(vec![
            packet(t, 0),
            DetectorEvent::Torn {
                at: t + Duration::from_millis(100)
            },
            tick(t, 1_100),
        ]),
        vec![ceiling()],
        "предмет может быть жив, но ждать мы перестали — это про нас"
    );
}

/// ЗРЕНИЕ ВОЗВРАЩАЕТ НАБЛЮДЕНИЕ, А НЕ ВРЕМЯ.
#[test]
fn an_observation_after_the_tear_restores_the_verdict_about_the_world() {
    let t = Instant::now();

    assert_eq!(
        run(vec![
            packet(t, 0),
            DetectorEvent::Torn {
                at: t + Duration::from_millis(100)
            },
            packet(t, 200),
            tick(t, 400),
            tick(t, 600),
        ]),
        vec![idle()],
        "окно от нового наблюдения свободно от дыры — прибор обязан снова судить о мире"
    );
}

/// ОБРЕЗАННЫЙ КАДР ПРЯЧЕТ НАБЛЮДЕНИЕ ТАК ЖЕ, КАК ДЫРА.
///
/// `Opaque { why: Truncated }` — кадр БЫЛ и мог нести ответ цели; прочесть его не удалось. Окно с
/// ним об отсутствии наблюдений не свидетельствует, и `Idle` («предмет замолчал» — утверждение О
/// МИРЕ) по такому окну приписал бы миру нашу слепоту.
///
/// Проверяет ПОРЯДОК АРМОВ в `Timeout::step`, а не только критерий: разбор по имени
/// (`DetectorEvent::Opaque { .. }`) стоял ВЫШЕ гарда `hides_observation()`, и гард видел одну лишь
/// `Torn`. Мутация — вернуть арм `Opaque` наверх; тест краснеет, `a_tear_…` остаётся зелёным.
#[test]
fn a_truncated_frame_hides_the_verdict_about_the_world() {
    let t = Instant::now();

    assert_eq!(
        run(vec![
            packet(t, 0),
            DetectorEvent::Opaque {
                why: Unread::Truncated,
                at: t + Duration::from_millis(200),
            },
            tick(t, 400),
        ]),
        vec![],
        "наблюдение в 200мс могло быть — окно с обрезанным кадром о тишине не свидетельствует"
    );
}

/// ЧУЖОЙ ПРОТОКОЛ ЗРЕНИЯ НЕ ОТНИМАЕТ.
///
/// Вторая половина того же закона, без которой первая прошла бы и на «гасим всякое `Opaque`»:
/// `NotIpv4`/`NotOurProtocol` — законное и вечное свойство чужого трафика, ответом в НАШЕМ
/// разговоре такой кадр быть не мог. Ослепнуть на нём значило бы онеметь зря.
#[test]
fn an_alien_protocol_does_not_blind_the_verdict_about_the_world() {
    let t = Instant::now();

    assert_eq!(
        run(vec![
            packet(t, 0),
            DetectorEvent::Opaque {
                why: Unread::NotOurProtocol,
                at: t + Duration::from_millis(200),
            },
            tick(t, 400),
        ]),
        vec![idle()],
        "чужой протокол ответом быть не мог — окно осталось свободным от пропажи"
    );
}
