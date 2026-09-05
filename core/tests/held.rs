//! НАБЛЮДЕНИЕ, НЕСУЩЕЕ ПРАВО ОТВЕТИТЬ — законы того, что ничего не съедается.
//!
//! Невод 1 отстрелил здесь ногу дважды, и обе видно в его коде: вердикт был ВЫЗОВОМ
//! (`accept_marked(msg, mark)`), то есть не значением — записать, сравнить и развернуть назад его
//! нельзя; а след расследования уезжал спанами OTLP, и его собственный док признаётся, что без
//! `OTEL_EXPORTER_OTLP_ENDPOINT` «спаны молча гасятся». Обе беды одного рода: сведения покидали
//! значение.

use reflex_core::held::{Held, Unanswered};
use std::time::{Duration, Instant};

/// Носитель права ответа. В бою это сообщение ядра; здесь — расписка, по которой видно, чем
/// ответили и ответили ли вообще.
#[derive(Debug, Clone, Default)]
struct Slip(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl Slip {
    fn said(&self) -> Vec<String> {
        match self.0.lock() {
            Err(_poisoned) => Vec::new(),
            Ok(said) => said.clone(),
        }
    }
}

impl reflex_core::held::Carrier for Slip {
    fn answer(self, with: &str) {
        match self.0.lock() {
            Err(_poisoned) => (),
            Ok(mut said) => said.push(with.to_string()),
        }
    }
}

/// НАБЛЮДЕНИЕ ЧИТАЕТСЯ СКОЛЬКО УГОДНО РАЗ. Ответ не отнимает у дела его предмет.
#[test]
fn what_was_seen_can_be_read_again_and_again() {
    let held = Held::new(Slip::default(), vec![1u8, 2, 3], Instant::now());

    assert_eq!(held.seen(), &[1, 2, 3]);
    assert_eq!(held.seen(), &[1, 2, 3], "чтение не съедает наблюдение");
    assert_eq!(held.seen().len(), 3);
}

/// ОТВЕТ ОСТАВЛЯЕТ ЗАПИСЬ, А НЕ ИСЧЕЗАЕТ. Вердикт — значение, и после него дело остаётся делом.
#[test]
fn answering_leaves_a_record_instead_of_consuming_the_case() {
    let slip = Slip::default();
    let at = Instant::now();
    let held = Held::new(slip.clone(), vec![7u8], at);

    let answered = held.answered("marked(3)");

    assert_eq!(slip.said(), vec!["marked(3)"], "ответ дошёл до носителя");
    assert_eq!(answered.seen, vec![7], "предмет пережил ответ");
    assert_eq!(answered.at, at, "и момент тоже");
    assert_eq!(answered.answer, "marked(3)", "и сам ответ стал записью");
}

/// ЗАБЫТЫЙ ОТВЕТ НЕВОЗМОЖЕН: деструктор отвечает пропуском.
///
/// Семантика та же, что у `TrafficGuard` («мёртвый страж ⟹ трафик идёт»): непринятое решение не
/// должно останавливать чужой трафик. Но молчаливым это быть не может — см. следующий закон.
#[test]
fn a_forgotten_answer_is_impossible_the_drop_lets_traffic_through() {
    let slip = Slip::default();

    drop(Held::new(slip.clone(), vec![1u8], Instant::now()));

    assert_eq!(slip.said(), vec![Unanswered::PASSED_BY_DROP]);
}

/// И ЭТО ФАКТ О НАС, А НЕ О МИРЕ. Отпущенное деструктором обязано быть отличимо от отпущенного
/// решением — иначе «мы забыли» читается как «мы решили пропустить».
#[test]
fn what_the_destructor_let_through_is_not_the_same_word_as_a_decision_to_pass() {
    let by_decision = Slip::default();
    let by_forgetting = Slip::default();

    Held::new(by_decision.clone(), vec![1u8], Instant::now()).answered("pass");
    drop(Held::new(by_forgetting.clone(), vec![1u8], Instant::now()));

    assert_ne!(
        by_decision.said(),
        by_forgetting.said(),
        "решение пропустить и забытый вердикт обязаны звучать по-разному"
    );
}

/// ОТВЕТ ОДИН. Ответив, дело нельзя ответить снова — по построению, а не по договорённости.
///
/// Проверяется компиляцией: `answered` берёт `self`, и второй вызов не соберётся.
#[test]
fn a_case_is_answered_once() {
    let slip = Slip::default();
    let held = Held::new(slip.clone(), vec![1u8], Instant::now());

    let _answered = held.answered("pass");
    // held.answered("drop"); ← не соберётся: наблюдение уже отдано ответу

    assert_eq!(slip.said().len(), 1, "носитель услышал ровно один ответ");
}

/// МОМЕНТ НАБЛЮДЕНИЯ ПЕРЕЖИВАЕТ ВСЁ. Без него дело нельзя поставить на ленту времени, а
/// расследование только по ней и разворачивается назад.
#[test]
fn the_moment_of_observation_survives_the_whole_journey() {
    let at = Instant::now() - Duration::from_secs(5);
    let answered = Held::new(Slip::default(), vec![9u8], at).answered("drop");

    assert_eq!(answered.at, at);
}
