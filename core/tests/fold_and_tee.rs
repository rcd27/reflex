//! Тесты чистой свёртки и раздвоения потока.
//!
//! Оба оператора заведены под одно правило: доменную логику нельзя выразить неверно. `scan_state`
//! и `map` с побочным действием это правило нарушают — первый прячет мутацию за `&mut`, второй
//! прячет ветвление за именем отображения.

use futures::channel::mpsc;
use futures::{stream, StreamExt};
use reflex_core::ReflexExt;

/// Свёртка эмитит состояние ПОСЛЕ каждого шага — как `scan`, но чисто.
#[tokio::test]
async fn fold_emits_state_after_every_step() {
    let got: Vec<i32> = stream::iter([1, 2, 3])
        .fold_state(0, |acc, x| acc + x)
        .collect()
        .await;

    assert_eq!(got, vec![1, 3, 6]);
}

/// Состояние не теряется между шагами и не пересобирается заново.
#[tokio::test]
async fn fold_carries_state_across_steps() {
    let got: Vec<Vec<i32>> = stream::iter([1, 2])
        .fold_state(Vec::new(), |mut acc: Vec<i32>, x| {
            acc.push(x);
            acc
        })
        .collect()
        .await;

    assert_eq!(got, vec![vec![1], vec![1, 2]]);
}

/// Пустой источник не даёт ни одного состояния: семя эмитится не свёрткой, а тем, кто её
/// потребляет (`once(seed).chain(...)`). Различие существенно — на нём в неводе 2 потерялись бы
/// первые запросы.
#[tokio::test]
async fn fold_over_an_empty_source_emits_nothing() {
    let got: Vec<i32> = stream::iter(Vec::<i32>::new())
        .fold_state(42, |acc, x| acc + x)
        .collect()
        .await;

    assert!(got.is_empty());
}

/// ГЛАВНОЕ У `tee`: основной поток проходит ЦЕЛИКОМ, копия уходит в приёмник.
#[tokio::test]
async fn tee_passes_everything_through_and_copies_aside() {
    let (tx, rx) = mpsc::channel::<i32>(8);

    let main: Vec<i32> = stream::iter([1, 2, 3]).tee(tx).collect().await;
    assert_eq!(main, vec![1, 2, 3], "основной поток потерял элементы");

    let aside: Vec<i32> = rx.collect().await;
    assert_eq!(aside, vec![1, 2, 3], "копия не ушла в приёмник");
}

/// ОСНОВНОЙ ПОТОК НЕ ЖДЁТ ПРИЁМНИКА. Ёмкость меньше числа элементов — лишние копии теряются,
/// но полезная работа проходит вся. Обратное (ждать приёмника) означало бы, что побочная ветка
/// задерживает человека.
#[tokio::test]
async fn a_full_sink_does_not_hold_the_main_stream() {
    let (tx, rx) = mpsc::channel::<i32>(1);

    let main: Vec<i32> = stream::iter([1, 2, 3, 4, 5]).tee(tx).collect().await;
    assert_eq!(main, vec![1, 2, 3, 4, 5], "переполненный приёмник задержал поток");

    let aside: Vec<i32> = rx.collect().await;
    assert!(
        aside.len() < 5,
        "приёмник ёмкостью 1 принял всё — тест не проверяет переполнение: {aside:?}"
    );
}

/// КОНТРОЛЬ к предыдущему: при достаточной ёмкости не теряется ничего. Без него тест выше
/// зеленел бы и при `tee`, не отправляющем никогда.
#[tokio::test]
async fn a_roomy_sink_loses_nothing() {
    let (tx, rx) = mpsc::channel::<i32>(16);

    let _: Vec<i32> = stream::iter([1, 2, 3, 4, 5]).tee(tx).collect().await;
    let aside: Vec<i32> = rx.collect().await;

    assert_eq!(aside.len(), 5);
}
