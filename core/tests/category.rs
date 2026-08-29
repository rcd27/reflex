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

/// ДЕТЕКЦИЯ С СОСТОЯНИЕМ — морфизм, а не отдельный слой (#295).
///
/// Флагманский морфизм таблицы §5 приехал в категорию позже объектов: срез 2 честно отложил его,
/// а понадобился он в ту же минуту, когда продукт начал переезжать — первая же его ветвь есть
/// ровно `detect_per`.
#[tokio::test]
async fn stateful_detection_is_a_morphism() {
    use reflex_core::stream::Lifetime;
    use reflex_core::{Detector, DetectorEvent};
    use smallvec::{smallvec, SmallVec};

    #[derive(Debug, Clone, Copy, Default)]
    struct Counting(u8);
    impl Detector for Counting {
        type Input = u8;
        type Signal = u8;
        fn step(self, event: DetectorEvent<u8>) -> (Self, SmallVec<[u8; 2]>) {
            match event {
                DetectorEvent::Packet { .. } => (Counting(self.0 + 1), smallvec![]),
                DetectorEvent::Tick { .. } => (self, smallvec![self.0]),
            }
        }
    }

    let t0 = std::time::Instant::now();
    let seen: Vec<(u8, u8)> = Pipeline::of_packets(stream::iter([
        DetectorEvent::Packet { input: 1u8, at: t0 },
        DetectorEvent::Packet { input: 1u8, at: t0 },
        DetectorEvent::Tick { at: t0 },
    ]))
    .detect(
        |k: &u8| *k,
        Counting::default,
        Lifetime::UntilIdle(std::time::Duration::from_secs(60)),
    )
    .into_stream()
    .collect()
    .await;

    assert_eq!(seen, vec![(1u8, 2u8)], "детекция не досчитала: {seen:?}");
}

/// ЧАСТИЧНАЯ КЛАССИФИКАЦИЯ ОТСЕИВАЕТ — и это НАЗВАНО в имени морфизма.
///
/// Vision знает классификацию тотальную. Продукт показал, что в жизни она частична: не всякое
/// наблюдение становится делом. Спрятать отсев внутрь `classify` значило бы сделать тотальный
/// морфизм частичным молча.
#[tokio::test]
async fn partial_classification_drops_what_it_cannot_classify() {
    let out: Vec<&str> = Pipeline::of_signals(stream::iter([1u8, 7, 2, 9]))
        .classify_some(|signal| match signal > 4 {
            true => Some("крупный"),
            false => None,
        })
        .into_stream()
        .collect()
        .await;

    assert_eq!(
        out,
        vec!["крупный", "крупный"],
        "частичная классификация пропустила то, что классифицировать нечем: {out:?}"
    );
}

/// КОНТРОЛЬ: тотальная классификация НИЧЕГО не отсеивает.
///
/// Без него предыдущий тест зеленел бы и на реализации, где `classify_some` просто равен
/// `classify`, — а тогда частичность была бы именем без предмета.
#[tokio::test]
async fn total_classification_keeps_everything() {
    let out: Vec<bool> = Pipeline::of_signals(stream::iter([1u8, 7, 2, 9]))
        .classify(|signal| signal > 4)
        .into_stream()
        .collect()
        .await;

    assert_eq!(out.len(), 4, "тотальная классификация потеряла сигналы");
}
