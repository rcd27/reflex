//! ЦЕПОЧКА КАТЕГОРИИ РАБОТАЕТ, а не только компилируется (#295, срез 2).
//!
//! Типы-стадии запрещают бессмысленное — это проверяют `compile_fail` в самом модуле. Здесь
//! проверяется обратное: что законная цепочка не только собирается, но и ВЕЗЁТ значения.
//! Без этого теста стадии могли бы быть красивой обёрткой, теряющей данные.

use futures::{stream, StreamExt};
use reflex_core::category::Pipeline;

/// ПОЛНЫЙ ПУТЬ ПО ОБЪЕКТАМ: пакеты → сигналы → классификации → стратегии → команды.
#[tokio::test]
async fn the_whole_chain_carries_values_through_every_object() {
    let commands: Vec<Vec<u8>> = Pipeline::of_packets(stream::iter([1u8, 5, 9]))
        .map_signals(|byte| byte > 4)
        .classify(|big| match big {
            true => "крупный",
            false => "мелкий",
        })
        .react(|kind| format!("лечим {kind}"))
        .materialize(|plan| plan.into_bytes())
        .into_stream()
        .collect()
        .await;

    let read: Vec<String> = commands
        .into_iter()
        .map(|c| String::from_utf8(c).unwrap_or_default())
        .collect();

    assert_eq!(
        read,
        vec!["лечим мелкий", "лечим крупный", "лечим крупный"],
        "цепочка собралась, но значения по ней не доехали"
    );
}

/// ВЫХОД ИЗ КАТЕГОРИИ ЗАКОНЕН: `into_stream` отдаёт обычный поток.
///
/// Запирать поток внутри стадий значило бы требовать переписать под категорию всё, что и так
/// работает на `futures`. Категория добавляет закон, а не отнимает возможности.
#[tokio::test]
async fn leaving_the_category_is_allowed() {
    let doubled: Vec<u8> = Pipeline::of_packets(stream::iter([1u8, 2]))
        .into_stream()
        .map(|b| b * 2)
        .collect()
        .await;

    assert_eq!(doubled, vec![2, 4]);
}

/// `tap` ОПРЕДЕЛЁН НА ЛЮБОЙ СТАДИИ и стадию НЕ МЕНЯЕТ — единственный такой морфизм.
///
/// Проверяется и то, и другое: наблюдатель увидел значения, а цепочка после `tap` продолжается
/// так же, как без него. Если бы `tap` менял стадию, следующий морфизм не собрался бы.
#[tokio::test]
async fn tap_observes_without_changing_the_stage() {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEEN: AtomicU32 = AtomicU32::new(0);
    SEEN.store(0, Ordering::SeqCst);

    let out: Vec<&str> = Pipeline::of_packets(stream::iter([1u8, 7]))
        .tap(|b: &u8| {
            SEEN.fetch_add(*b as u32, Ordering::SeqCst);
        })
        .map_signals(|byte| byte > 4)
        .classify(|big| match big {
            true => "крупный",
            false => "мелкий",
        })
        .into_stream()
        .collect()
        .await;

    assert_eq!(out, vec!["мелкий", "крупный"], "поток изменён наблюдением");
    assert_eq!(
        SEEN.load(Ordering::SeqCst),
        8,
        "наблюдатель не увидел значений"
    );
}

/// КОМАНДЫ ДОЕЗЖАЮТ ДО ИНЪЕКТОРА, а не растворяются в терминальности.
///
/// Терминальность запрещает продолжать цепочку — это проверяют `compile_fail` в самом модуле. Здесь
/// обратное: что морфизм в `1` действительно ИСПОЛНЯЕТСЯ. Без этого теста `inject` мог бы быть
/// красивым способом выбросить поток.
#[tokio::test]
async fn injection_actually_emits_every_command() {
    use std::sync::atomic::{AtomicU32, Ordering};
    static EMITTED: AtomicU32 = AtomicU32::new(0);
    EMITTED.store(0, Ordering::SeqCst);

    let end = Pipeline::of_packets(stream::iter([1u8, 5, 9]))
        .map_signals(|byte| byte > 4)
        .classify(|big| match big {
            true => 100u32,
            false => 1,
        })
        .react(|weight| weight * 2)
        .materialize(|weight| weight + 1)
        .inject(|command: u32| {
            EMITTED.fetch_add(command, Ordering::SeqCst);
        })
        .drive()
        .await;

    assert_eq!(end, reflex_core::category::Terminal);
    assert_eq!(
        EMITTED.load(Ordering::SeqCst),
        3 + 201 + 201,
        "команды не доехали до инъектора"
    );
}
