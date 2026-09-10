//! ЗАКОНЫ ЛЕСТНИЦЫ ПРОБ. Вторая ось: `core` держит шаг, `runtime` держит конкурентность.
//!
//! Проверяется здесь не «работает ли перебор» — перебор работает всегда. Проверяется то, ради чего
//! оператор вообще заведён в фундаменте: что ОТЧЁТ НЕ ЛЖЁТ. Цикл с `break`, написанный у себя,
//! перебор тоже сделает — и потеряет закон останова при первой правке соседней строки, молча.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use reflex_runtime::ladder::{climb, Climbing, Tried};

/// ПРЕДМЕТ: до остановки ВКЛЮЧИТЕЛЬНО. Ступень остановки в отчёте, а не отброшена вместе с ней;
/// то, до чего не дошли, названо `NotRun`, а не приговором кандидату.
#[tokio::test]
async fn the_rung_that_halts_the_climb_stays_in_the_report() {
    let climbed = climb(vec![1, 2, 3, 4, 5], 1, |candidate: i32| async move {
        Ok(match candidate == 2 {
            true => (format!("взяло {candidate}"), Climbing::Halt),
            false => (format!("не взяло {candidate}"), Climbing::Onward),
        })
    })
    .await;

    assert_eq!(
        climbed.halted().map(|(key, what)| (*key, what.clone())),
        Some((2, "взяло 2".to_string())),
        "ступень остановки обязана остаться в отчёте"
    );
    assert_eq!(
        climbed.tried[0].1,
        Tried::Established {
            what: "не взяло 1".to_string(),
            then: Climbing::Onward
        },
        "проба состоялась и УСТАНОВИЛА своё — знание не выбрасывается"
    );
    assert_eq!(
        climbed.tried[2].1,
        Tried::NotRun,
        "до третьего не дошли — это НЕЗНАНИЕ, а не приговор кандидату"
    );
    assert_eq!(
        climbed.unestablished(),
        3,
        "цена остановки названа числом: о трёх кандидатах не установлено ничего"
    );
}

/// ПРЕДМЕТ: «мир отказал» ≠ «кандидат не годится». Слей их — и отчёт скажет «перебрали пятерых, не
/// нашли», хотя двое не состоялись вовсе, и их надо пробовать заново.
#[tokio::test]
async fn a_refusal_of_the_world_is_not_a_verdict_on_the_candidate() {
    let climbed = climb(vec!["a", "b", "c"], 3, |candidate: &str| async move {
        match candidate {
            "b" => Err("сокет не открылся".to_string()),
            _ => Ok(("не взяло", Climbing::Onward)),
        }
    })
    .await;

    assert!(climbed.tried[0].1.established());
    assert_eq!(
        climbed.tried[1].1,
        Tried::Refused("сокет не открылся".to_string()),
        "отказ мира обязан нести причину, а не схлопываться в «не годен»"
    );
    assert!(
        !climbed.tried[1].1.established(),
        "об этом кандидате не установлено НИЧЕГО"
    );
    assert!(
        climbed.tried[0].1.established(),
        "а об этом — установлено, что не годится"
    );
}

/// ПРЕДМЕТ: отчёт ПОЛОН по построению — строк ровно столько, сколько кандидатов подавали. Отчёт, из
/// которого выпадают незапущенные, читается как «перебрали всё».
#[tokio::test]
async fn every_candidate_is_named_in_the_report() {
    let candidates: Vec<u8> = (0..20).collect();
    let climbed = climb(candidates.clone(), 4, |candidate: u8| async move {
        Ok(match candidate == 3 {
            true => (candidate, Climbing::Halt),
            false => (candidate, Climbing::Onward),
        })
    })
    .await;

    assert_eq!(climbed.tried.len(), candidates.len());
    let named: Vec<u8> = climbed.tried.iter().map(|(key, _)| *key).collect();
    assert_eq!(named, candidates, "и в порядке ПОДАЧИ, а не завершения");
}

/// ПРЕДМЕТ: ширина держится. Не «примерно столько» — в полёте НЕ БОЛЕЕ `width` проб одновременно,
/// и меряется это счётчиком, а не верой: лестница, ходящая шире просимого, кладёт цель, ради
/// щажения которой ширину и задавали.
#[tokio::test]
async fn the_width_of_the_climb_is_never_exceeded() {
    let flying = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let (counting, watching) = (Arc::clone(&flying), Arc::clone(&peak));

    let climbed = climb((0..12).collect::<Vec<u8>>(), 3, move |_candidate: u8| {
        let flying = Arc::clone(&counting);
        let peak = Arc::clone(&watching);
        async move {
            let now = flying.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(5)).await;
            flying.fetch_sub(1, Ordering::SeqCst);
            Ok(((), Climbing::Onward))
        }
    })
    .await;

    assert_eq!(climbed.tried.len(), 12);
    assert_eq!(
        peak.load(Ordering::SeqCst),
        3,
        "в полёте обязано быть ровно три — не меньше (иначе ширина не работает) и не больше"
    );
}

/// ПРЕДМЕТ: остановка — ПО ПОРЯДКУ ПОДАЧИ, а не по времени ответа. Здесь второй кандидат отвечает
/// быстрее первого, и оба велят встать; лестница обязана отдать ПЕРВОГО, иначе один и тот же вход
/// давал бы разный ответ в зависимости от темпа сети — то есть перестал бы быть входом.
#[tokio::test]
async fn the_halt_is_the_first_by_order_not_by_speed() {
    let climbed = climb(vec![10u64, 20u64], 2, |candidate: u64| async move {
        // Первый отвечает медленнее второго вдвое.
        let delay = match candidate {
            10 => 40,
            _ => 5,
        };
        tokio::time::sleep(Duration::from_millis(delay)).await;
        Ok((candidate, Climbing::Halt))
    })
    .await;

    assert_eq!(
        climbed.halted().map(|(key, _)| *key),
        Some(10),
        "медленный, но первый — он и есть ответ"
    );
    assert!(
        climbed.tried[1].1.established(),
        "второй тоже состоялся — выбрасывать его исход значило бы отчитаться «не запускали» о \
         том, что запускали"
    );
}

/// ПРЕДМЕТ ДВУХ ОСЕЙ, ради которого форма и менялась: успех НЕ ВСЕГДА конец поиска, а остановка НЕ
/// ВСЕГДА успех.
///
/// Первый кандидат берёт цель, но с повторами — знание установлено, искать чище стоит, перебор
/// идёт дальше. Второй устанавливает, что цель не берётся ничем: перебор встаёт, и это ПРИГОВОР
/// ЦЕЛИ, а не находка. Слей эти оси в одну — и «встал» пришлось бы объявить «нашли», то есть
/// соврать ровно там, где отчёт и читают.
#[tokio::test]
async fn success_does_not_always_halt_and_a_halt_is_not_always_success() {
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Found {
        TakesWithRetries,
        Unreachable,
    }

    let climbed = climb(vec!["повторами", "никак"], 1, |candidate: &str| async move {
        Ok(match candidate {
            "повторами" => (Found::TakesWithRetries, Climbing::Onward),
            _ => (Found::Unreachable, Climbing::Halt),
        })
    })
    .await;

    assert_eq!(
        climbed.tried[0].1,
        Tried::Established {
            what: Found::TakesWithRetries,
            then: Climbing::Onward
        },
        "успех, на котором перебор продолжается, обязан быть выразим"
    );
    assert_eq!(
        climbed.halted().map(|(_, what)| what.clone()),
        Some(Found::Unreachable),
        "остановка обязана быть выразима БЕЗ объявления кандидата годным"
    );
}

/// ПРЕДМЕТ: лестница НЕ ТРЕБУЕТ потокобезопасности, которой не пользуется.
///
/// Оснастка здесь однопоточна ПО ПОСТРОЕНИЮ: провод — `Rc<dyn Fn>`, счётчик проб — `Cell<usize>`.
/// Ни то ни другое не `Send`, и не по лени: у сценария один поток, и синхронизация в нём есть
/// плата за то, чего не происходит. Замер потребителя, ради которого границы и сняты: восемь
/// историй поля, в каждой свой провод.
///
/// Тест держит отсутствие границ ПРОГОНОМ: верни в подпись `Send`/`Sync`/`'static` — он не
/// соберётся. Докблок такого не удержал бы.
#[tokio::test]
async fn a_single_threaded_probe_needs_no_send() {
    use std::cell::Cell;
    use std::rc::Rc;

    let tried = Rc::new(Cell::new(0usize));
    let wire: Rc<dyn Fn(u8) -> bool> = Rc::new(|candidate: u8| candidate == 2);

    let counting = Rc::clone(&tried);
    let climbed = climb(vec![1u8, 2, 3], 1, move |candidate: u8| {
        let wire = Rc::clone(&wire);
        let counting = Rc::clone(&counting);
        async move {
            counting.set(counting.get() + 1);
            Ok(match wire(candidate) {
                true => ("взяло", Climbing::Halt),
                false => ("не взяло", Climbing::Onward),
            })
        }
    })
    .await;

    assert_eq!(climbed.halted().map(|(key, _)| *key), Some(2));
    assert_eq!(
        tried.get(),
        2,
        "до третьего не дошли — счётчик однопоточной оснастки это и показывает"
    );
    assert_eq!(climbed.tried[2].1, Tried::NotRun);
}
