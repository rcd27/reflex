//! ЗАКОНЫ ЛЕСТНИЦЫ ПРОБ. Вторая ось: `core` держит шаг, `runtime` держит конкурентность.
//!
//! Проверяется здесь не «работает ли перебор» — перебор работает всегда. Проверяется то, ради чего
//! оператор вообще заведён в фундаменте: что ОТЧЁТ НЕ ЛЖЁТ. Цикл с `break`, написанный у себя,
//! перебор тоже сделает — и потеряет закон останова при первой правке соседней строки, молча.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use reflex_runtime::ladder::{climb, Tried};

/// ПРЕДМЕТ: до первой годной ВКЛЮЧИТЕЛЬНО. Годная в отчёте, а не отброшена вместе с остановкой;
/// то, до чего не дошли, названо `NotRun`, а не «не годится».
#[tokio::test]
async fn the_first_good_rung_stops_the_climb_and_stays_in_the_report() {
    let climbed = climb(vec![1, 2, 3, 4, 5], 1, |candidate: i32| async move {
        Ok((candidate == 2).then_some(format!("годен {candidate}")))
    })
    .await;

    assert_eq!(
        climbed.good().map(|(key, good)| (*key, good.clone())),
        Some((2, "годен 2".to_string())),
        "годная обязана остаться в отчёте"
    );
    assert_eq!(climbed.tried[0].1, Tried::Bad, "первый пробовали — не годен");
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
            _ => Ok(None::<()>),
        }
    })
    .await;

    assert_eq!(climbed.tried[0].1, Tried::Bad);
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
        Ok((candidate == 3).then_some(candidate))
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
            Ok(None::<()>)
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

/// ПРЕДМЕТ: первая годная — ПО ПОРЯДКУ ПОДАЧИ, а не по времени ответа. Здесь второй кандидат
/// отвечает быстрее первого, и оба годны; лестница обязана отдать ПЕРВОГО, иначе один и тот же вход
/// давал бы разный ответ в зависимости от темпа сети — то есть перестал бы быть входом.
#[tokio::test]
async fn the_good_one_is_the_first_by_order_not_by_speed() {
    let climbed = climb(vec![10u64, 20u64], 2, |candidate: u64| async move {
        // Первый отвечает медленнее второго вдвое.
        let delay = match candidate {
            10 => 40,
            _ => 5,
        };
        tokio::time::sleep(Duration::from_millis(delay)).await;
        Ok(Some(candidate))
    })
    .await;

    assert_eq!(
        climbed.good().map(|(key, _)| *key),
        Some(10),
        "медленный, но первый — он и есть ответ"
    );
    assert!(
        matches!(climbed.tried[1].1, Tried::Good(_)),
        "второй тоже состоялся и годен — выбрасывать его исход значило бы отчитаться «не \
         запускали» о том, что запускали"
    );
}
