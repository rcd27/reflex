use futures::StreamExt;
use reflex_core::ReflexExt;

#[tokio::test]
async fn with_latest_from_enriches_with_latest_value() {
    let source = futures::stream::iter(vec![1, 2, 3]);
    let config = futures::stream::iter(vec!["alpha"]);

    let result: Vec<String> = source
        .with_latest_from(config, |item, cfg| format!("{item}-{cfg}"))
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
        .with_latest_from(config, |item, cfg| item + cfg)
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
        .with_latest_from(config, |item, cfg| item + cfg)
        .collect()
        .await;

    assert!(result.is_empty());
}
