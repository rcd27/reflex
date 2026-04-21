use futures::StreamExt;
use reflex_core::ReflexExt;
use tokio_stream::iter;

#[tokio::test]
async fn group_by_counts_per_key() {
    let items = vec!["a", "b", "a", "c", "b", "a"];
    let stream = iter(items);

    let results: Vec<(&str, usize)> = stream
        .group_by(
            |item: &&str| *item,
            || 0usize,
            |count, item| {
                *count += 1;
                Some((item, *count))
            },
        )
        .collect()
        .await;

    // a appears 3 times: (a,1), (a,2), (a,3)
    // b appears 2 times: (b,1), (b,2)
    // c appears 1 time:  (c,1)
    assert_eq!(results.len(), 6);
    let a_counts: Vec<usize> = results
        .iter()
        .filter(|(k, _)| *k == "a")
        .map(|(_, v)| *v)
        .collect();
    assert_eq!(a_counts, vec![1, 2, 3]);
    let b_counts: Vec<usize> = results
        .iter()
        .filter(|(k, _)| *k == "b")
        .map(|(_, v)| *v)
        .collect();
    assert_eq!(b_counts, vec![1, 2]);
}

#[tokio::test]
async fn group_by_filters_via_none() {
    let items = vec![1, 2, 3, 4, 5, 6];
    let stream = iter(items);

    // Only emit even numbers, grouped by modulo 3
    let results: Vec<i32> = stream
        .group_by(
            |item: &i32| *item % 3,
            || (),
            |_state, item| if item % 2 == 0 { Some(item) } else { None },
        )
        .collect()
        .await;

    assert_eq!(results, vec![2, 4, 6]);
}

#[tokio::test]
async fn group_by_empty_stream() {
    let stream = iter(Vec::<i32>::new());

    let results: Vec<i32> = stream
        .group_by(|item: &i32| *item, || (), |_, item| Some(item))
        .collect()
        .await;

    assert!(results.is_empty());
}

#[tokio::test]
async fn group_by_accumulates_state_per_key() {
    let items = vec![("x", 10), ("y", 20), ("x", 30), ("y", 5)];
    let stream = iter(items);

    // Accumulate sum per key, emit running total
    let results: Vec<(&str, i32)> = stream
        .group_by(
            |item: &(&str, i32)| item.0,
            || 0i32,
            |sum, (key, val)| {
                *sum += val;
                Some((key, *sum))
            },
        )
        .collect()
        .await;

    assert_eq!(results, vec![("x", 10), ("y", 20), ("x", 40), ("y", 25)]);
}
