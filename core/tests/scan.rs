use futures::StreamExt;
use reflex_core::ReflexExt;

#[tokio::test]
async fn scan_accumulates_state() {
    let items = futures::stream::iter(vec![1, 2, 3, 4, 5]);

    let result: Vec<i32> = items
        .scan_state(0, |state, item| {
            *state += item;
        })
        .collect()
        .await;

    // running sum: 1, 3, 6, 10, 15
    assert_eq!(result, vec![1, 3, 6, 10, 15]);
}

#[tokio::test]
async fn scan_emits_on_every_input() {
    let items = futures::stream::iter(vec!["a", "b", "c"]);

    let result: Vec<String> = items
        .scan_state(String::new(), |state, item| {
            if !state.is_empty() {
                state.push(',');
            }
            state.push_str(item);
        })
        .collect()
        .await;

    assert_eq!(result, vec!["a", "a,b", "a,b,c"]);
}

#[tokio::test]
async fn scan_empty_stream() {
    let items = futures::stream::iter(Vec::<i32>::new());

    let result: Vec<i32> = items
        .scan_state(0, |state, item| {
            *state += item;
        })
        .collect()
        .await;

    assert!(result.is_empty());
}
