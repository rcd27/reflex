use std::time::Duration;

use futures::StreamExt;
use reflex_core::ReflexExt;
use tokio::time;
use tokio_stream::wrappers::ReceiverStream;

#[tokio::test(start_paused = true)]
async fn debounce_suppresses_rapid_duplicates() {
    let (tx, rx) = tokio::sync::mpsc::channel::<&str>(16);

    let handle = tokio::spawn(async move {
        ReceiverStream::new(rx)
            .debounce(Duration::from_secs(1))
            .collect::<Vec<_>>()
            .await
    });

    // rapid burst: 3 items within 500ms
    tx.send("a").await.unwrap();
    time::advance(Duration::from_millis(200)).await;
    tx.send("b").await.unwrap();
    time::advance(Duration::from_millis(200)).await;
    tx.send("c").await.unwrap();

    // wait for debounce window to expire
    time::advance(Duration::from_secs(2)).await;

    drop(tx);
    let result = handle.await.unwrap();

    // only the last item in the burst should survive
    assert_eq!(result, vec!["c"]);
}

#[tokio::test(start_paused = true)]
async fn debounce_passes_spaced_items() {
    let (tx, rx) = tokio::sync::mpsc::channel::<i32>(16);

    let handle = tokio::spawn(async move {
        ReceiverStream::new(rx)
            .debounce(Duration::from_secs(1))
            .collect::<Vec<_>>()
            .await
    });

    // first item
    tx.send(1).await.unwrap();
    // yield to let spawned task poll and pick up the item
    tokio::task::yield_now().await;
    // advance past debounce window
    time::advance(Duration::from_secs(3)).await;
    // yield multiple times to let spawned task process the timer
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;

    // second item
    tx.send(2).await.unwrap();
    tokio::task::yield_now().await;
    time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;

    drop(tx);
    let result = handle.await.unwrap();

    assert_eq!(result, vec![1, 2]);
}

#[tokio::test]
async fn debounce_synchronous_stream() {
    // with a synchronous (iter) stream, all items arrive at once,
    // debounce keeps only the last
    let items = futures::stream::iter(vec![1, 2, 3, 4, 5]);

    let result: Vec<i32> = items
        .debounce(Duration::from_secs(1))
        .collect()
        .await;

    // source completes immediately, pending item is flushed
    assert_eq!(result, vec![5]);
}
