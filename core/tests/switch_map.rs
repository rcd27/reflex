use futures::StreamExt;
use reflex_core::ReflexExt;

#[tokio::test]
async fn switch_map_switches_to_latest_inner() {
    // outer stream emits 3 values
    // each maps to an inner stream of 2 items
    // switch_map should cancel previous inner on new outer
    let outer = futures::stream::iter(vec![10, 20, 30]);

    let result: Vec<i32> = outer
        .switch_map(|x| futures::stream::iter(vec![x + 1, x + 2]))
        .collect()
        .await;

    // switch_map cancels previous inner when new outer arrives.
    // outer=10 → inner [11,12] → emits 11, then outer=20 arrives → cancels 12
    // outer=20 → inner [21,22] → emits 21, then outer=30 arrives → cancels 22
    // outer=30 → inner [31,32] → emits both (last outer, no cancellation)
    assert_eq!(result, vec![11, 21, 31, 32]);
}

#[tokio::test]
async fn switch_map_empty_outer() {
    let outer = futures::stream::iter(Vec::<i32>::new());

    let result: Vec<i32> = outer
        .switch_map(|x| futures::stream::iter(vec![x]))
        .collect()
        .await;

    assert!(result.is_empty());
}

#[tokio::test]
async fn switch_map_empty_inner() {
    let outer = futures::stream::iter(vec![1, 2, 3]);

    let result: Vec<i32> = outer
        .switch_map(|_| futures::stream::empty::<i32>())
        .collect()
        .await;

    assert!(result.is_empty());
}

#[tokio::test]
async fn switch_map_transforms_type() {
    let outer = futures::stream::iter(vec![1, 2, 3]);

    let result: Vec<String> = outer
        .switch_map(|x| futures::stream::iter(vec![format!("item-{x}")]))
        .collect()
        .await;

    assert_eq!(result, vec!["item-1", "item-2", "item-3"]);
}
