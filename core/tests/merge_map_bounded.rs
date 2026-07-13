//! Тесты `merge_map_bounded` — проекция молекулы `FlowPermit` (nevod/model/molecule).
//!
//! Оператор = bounded-flatMap / mergeMap(Cap): стрим айтемов → по future на айтем, но
//! одновременно живых future НЕ больше `cap`. Слот в пуле = permit; завершение future =
//! возврат permit (RAII). Прямые инварианты модели:
//!   - `BoundedInflight`: inflight <= Cap (закон — рабочий набор связан с константой);
//!   - non-vacuity (reach): пул РЕАЛЬНО наполняется до Cap (иначе потолок вакуумен).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use futures::StreamExt;
use reflex_core::ReflexExt;

/// Счётчик живых future: инкремент на старте, декремент на завершении, пик — свидетель потолка.
#[derive(Clone, Default)]
struct Inflight {
    live: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}

impl Inflight {
    /// Вход в future: +1 живых, обновить пик. Возврат — RAII-гард, который на Drop делает -1.
    fn enter(&self) -> InflightGuard {
        let now = self.live.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        InflightGuard {
            live: self.live.clone(),
        }
    }
    fn peak(&self) -> usize {
        self.peak.load(Ordering::SeqCst)
    }
}

struct InflightGuard {
    live: Arc<AtomicUsize>,
}
impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

/// ЗАКОН `BoundedInflight` + non-vacuity: N айтемов > cap, живых одновременно ровно cap,
/// НИКОГДА не больше. Пул наполняется до потолка (reach), но не пробивает его (safety).
#[tokio::test]
async fn never_exceeds_cap_and_fills_to_cap() {
    let inflight = Inflight::default();
    let cap = 3;
    let n = 10; // N > Cap — честный противник (иначе потолок не бьётся)

    let probe = inflight.clone();
    let mut results: Vec<usize> = futures::stream::iter(0..n)
        .merge_map_bounded(cap, move |x| {
            let probe = probe.clone();
            async move {
                let _permit = probe.enter();
                // Уступаем несколько раз — даём драйверу шанс допустить соседей до потолка.
                for _ in 0..4 {
                    tokio::task::yield_now().await;
                }
                x
            }
        })
        .collect()
        .await;

    // Safety (BoundedInflight): пик живых НЕ превысил потолок.
    assert!(
        inflight.peak() <= cap,
        "потолок пробит: пик={} > cap={}",
        inflight.peak(),
        cap
    );
    // Non-vacuity (reach): пул РЕАЛЬНО наполнился до потолка — GREEN не вхолостую.
    assert_eq!(inflight.peak(), cap, "пул не наполнился до потолка");

    // Полнота: все айтемы обработаны (порядок не гарантирован — mergeMap неупорядочен).
    results.sort_unstable();
    assert_eq!(results, (0..n).collect::<Vec<_>>());
}

/// Cap больше числа айтемов — пик = N (потолок не выдумывает лишних живых).
#[tokio::test]
async fn cap_above_n_peaks_at_n() {
    let inflight = Inflight::default();
    let cap = 100;
    let n = 4;

    let probe = inflight.clone();
    let results: Vec<usize> = futures::stream::iter(0..n)
        .merge_map_bounded(cap, move |x| {
            let probe = probe.clone();
            async move {
                let _permit = probe.enter();
                for _ in 0..4 {
                    tokio::task::yield_now().await;
                }
                x
            }
        })
        .collect()
        .await;

    assert_eq!(inflight.peak(), n, "пик должен упереться в N, не в cap");
    assert_eq!(results.len(), n);
}

/// Пустой источник — пустой выход, без паники.
#[tokio::test]
async fn empty_source() {
    let results: Vec<usize> = futures::stream::iter(Vec::<usize>::new())
        .merge_map_bounded(4, |x| async move { x })
        .collect()
        .await;
    assert!(results.is_empty());
}
