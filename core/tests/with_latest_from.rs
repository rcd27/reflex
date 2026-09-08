use futures::StreamExt;
use reflex_core::ReflexExt;

#[tokio::test]
async fn with_latest_from_enriches_with_latest_value() {
    let source = futures::stream::iter(vec![1, 2, 3]);
    let config = futures::stream::iter(vec!["alpha"]);

    let result: Vec<String> = source
        .with_latest_from(config, "нет", |item, cfg| format!("{item}-{cfg}"))
        .collect()
        .await;

    // config emits "alpha" once, then all source items use it
    assert_eq!(result, vec!["1-alpha", "2-alpha", "3-alpha"]);
}

#[tokio::test]
async fn with_latest_from_uses_most_recent() {
    // config emits two values: the second should override the first
    let source = futures::stream::iter(vec![10, 20]);
    let config = futures::stream::iter(vec![100, 200]);

    let result: Vec<i32> = source
        .with_latest_from(config, 0, |item, cfg| item + cfg)
        .collect()
        .await;

    // with synchronous iterators, both config values are consumed
    // before source is polled, so latest = 200
    assert_eq!(result, vec![210, 220]);
}

#[tokio::test]
async fn with_latest_from_empty_source() {
    let source = futures::stream::iter(Vec::<i32>::new());
    let config = futures::stream::iter(vec![1, 2, 3]);

    let result: Vec<i32> = source
        .with_latest_from(config, 0, |item, cfg| item + cfg)
        .collect()
        .await;

    assert!(result.is_empty());
}

/// ЭЛЕМЕНТЫ НЕ ТЕРЯЮТСЯ, ПОКА ВТОРОЙ ПОТОК МОЛЧИТ (#295, срез 1).
///
/// # Чем это было
///
/// Оператор был ЧАСТИЧЕН: до первого значения `other` он молча выбрасывал элементы источника.
/// Домен определённости нигде не назывался — его описал ПОТРЕБИТЕЛЬ, в другом крейте:
///
/// > «`with_latest_from` из reflex ТЕРЯЕТ элемент, пока второй поток не выдал ни одного
/// > значения. Отсюда: поток знания обязан начинаться с семени, и семя есть условие
/// > работоспособности, а не оптимизация» — из практики потребителя
///
/// Костыль `once(default).chain(...)` стоял у обоих вызывающих. Теперь начальное значение —
/// часть сигнатуры, и обойти его нельзя.
///
/// # Что это значит для человека
///
/// В продукте источник — запросы человека, а `other` — накопленное знание. Потерянный элемент
/// здесь означает запрос, на который никто не ответил: первые обращения после старта коробки
/// уходили в никуда, пока не приедет первое знание.
#[tokio::test]
async fn nothing_is_lost_before_the_other_stream_speaks() {
    let quiet: Vec<u8> = Vec::new();

    let got: Vec<String> = futures::stream::iter([1, 2, 3])
        .with_latest_from(
            futures::stream::iter(quiet),
            0u8,
            |item: i32, latest: &u8| format!("{item}:{latest}"),
        )
        .collect()
        .await;

    assert_eq!(
        got,
        vec!["1:0", "2:0", "3:0"],
        "элементы потеряны, пока второй поток молчал: {got:?}"
    );
}

/// КОНТРОЛЬ: когда второй поток заговорил, берётся ЕГО значение, а не начальное.
///
/// Без него тест выше зеленел бы и на операторе, который игнорирует `other` вовсе.
#[tokio::test]
async fn the_latest_value_wins_over_the_initial_one() {
    let got: Vec<String> = futures::stream::iter([1, 2])
        .with_latest_from(
            futures::stream::iter([7u8]),
            0u8,
            |item: i32, latest: &u8| format!("{item}:{latest}"),
        )
        .collect()
        .await;

    assert!(
        got.iter().any(|s| s.ends_with(":7")),
        "начальное значение перекрыло пришедшее: {got:?}"
    );
}
