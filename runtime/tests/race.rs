//! ГОНКА (#355): ступенчатый старт, первая удача побеждает, срок общий. Время — tokio на паузе.
use reflex_runtime::race::{race, Attempt};
use std::time::Duration;

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// Первая удача снимает остальных, и отчёт называет каждого кандидата своим исходом.
#[tokio::test(start_paused = true)]
async fn the_first_success_wins_and_the_rest_are_abandoned() {
    let raced = race(
        vec![1000u64, 100, 50],
        ms(500),
        3,
        ms(4500),
        |wait| async move {
            tokio::time::sleep(ms(wait)).await;
            Ok::<u64, String>(wait)
        },
    )
    .await;
    // 1000 стартует в 0 и кончил бы в 1000; 100 стартует в 500 и кончает в 600 — раньше всех.
    assert_eq!(raced.won, Some((100, 100)));
    assert_eq!(raced.tried[0], (1000, Attempt::Abandoned));
    assert_eq!(raced.tried[1], (100, Attempt::Won));
    // 50 стартовал бы в 1000 — гонка кончилась в 600, его не запускали.
    assert_eq!(raced.tried[2], (50, Attempt::NotRun));
}

/// Отказ не ждёт ступени: следующий кандидат идёт сразу, иначе потерянный SYN съедает бюджет.
#[tokio::test(start_paused = true)]
async fn a_refusal_starts_the_next_candidate_at_once() {
    let started = std::sync::Mutex::new(Vec::new());
    let t0 = tokio::time::Instant::now();
    let raced = race(vec![0u8, 1], ms(500), 3, ms(4500), |k| {
        started.lock().map(|mut s| s.push((k, t0.elapsed()))).ok();
        async move {
            match k {
                0 => Err("RST".to_string()),
                _ => Ok(k),
            }
        }
    })
    .await;
    assert_eq!(raced.won, Some((1, 1)));
    let when = started.lock().map(|s| s.clone()).unwrap_or_default();
    assert_eq!(when[1].1, ms(0), "после отказа ступень не ждут");
}

/// Срок общий: никто не успел — победителя нет, все в полёте брошены, незапущенные названы.
#[tokio::test(start_paused = true)]
async fn the_deadline_ends_the_race_without_a_winner() {
    let raced = race(
        vec![10_000u64, 10_000, 10_000, 10_000],
        ms(500),
        3,
        ms(1200),
        |wait| async move {
            tokio::time::sleep(ms(wait)).await;
            Ok::<u64, String>(wait)
        },
    )
    .await;
    assert_eq!(raced.won, None);
    let kinds: Vec<&Attempt> = raced.tried.iter().map(|(_, a)| a).collect();
    assert_eq!(
        kinds,
        vec![
            &Attempt::Abandoned,
            &Attempt::Abandoned,
            &Attempt::Abandoned,
            &Attempt::NotRun
        ]
    );
}

/// Ширина держит число одновременных попыток.
#[tokio::test(start_paused = true)]
async fn no_more_than_width_attempts_fly_at_once() {
    let flying = std::sync::atomic::AtomicUsize::new(0);
    let peak = std::sync::atomic::AtomicUsize::new(0);
    let _ = race(vec![(); 6], ms(10), 2, ms(4500), |_| {
        let now = flying.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        peak.fetch_max(now, std::sync::atomic::Ordering::SeqCst);
        let flying = &flying;
        async move {
            tokio::time::sleep(ms(100)).await;
            flying.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            Err::<(), String>("нет".into())
        }
    })
    .await;
    assert_eq!(peak.load(std::sync::atomic::Ordering::SeqCst), 2);
}
