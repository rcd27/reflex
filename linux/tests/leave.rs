//! ПРОСЬБА УЙТИ, УСЛЫШАННАЯ СИНХРОННО (`reflex_linux::leave`).
//!
//! Сигнал шлётся `raise` — ЭТОЙ нити, а не процессу: приёмки крутятся нитями одного процесса, и
//! сигнал процессу достался бы соседней нити, которая его не блокирует, — умер бы весь прогон.

use reflex_linux::leave::{Leaving, Plea};

/// Просьбы не было — ответ «нет», и оборот не ждёт.
#[test]
fn without_a_plea_the_question_answers_nothing_at_once() {
    let Ok(leaving) = Leaving::blocked() else {
        panic!("сигналы обязаны заблокироваться")
    };

    let started = std::time::Instant::now();
    assert_eq!(leaving.asked(), None, "просьбы не было");
    assert!(
        started.elapsed() < std::time::Duration::from_millis(50),
        "вопрос не ждёт: {:?}",
        started.elapsed()
    );
}

/// `SIGTERM` не убивает процесс, а ждёт вопроса — и приходит ответом.
#[test]
fn a_terminate_waits_to_be_asked_instead_of_killing() {
    let Ok(leaving) = Leaving::blocked() else {
        panic!("сигналы обязаны заблокироваться")
    };

    // Жив после сигнала — значит, он заблокирован; иначе действие по умолчанию убило бы прогон.
    let raised = unsafe { libc::raise(libc::SIGTERM) };
    assert_eq!(raised, 0, "сигнал обязан уйти");

    assert_eq!(leaving.asked(), Some(Plea::Terminate), "просьба услышана");
    assert_eq!(leaving.asked(), None, "и услышана один раз");
}

/// Все три штатные просьбы — те же, что у асинхронной двери `reflex-runtime::shutdown_signal`.
#[test]
fn every_ordinary_plea_is_heard_by_its_name() {
    let Ok(leaving) = Leaving::blocked() else {
        panic!("сигналы обязаны заблокироваться")
    };

    let heard: Vec<Option<Plea>> = [libc::SIGINT, libc::SIGHUP]
        .iter()
        .map(|signal| {
            let _raised = unsafe { libc::raise(*signal) };
            leaving.asked()
        })
        .collect();

    assert_eq!(heard, vec![Some(Plea::Interrupt), Some(Plea::Hangup)]);
}
