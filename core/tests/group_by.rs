use futures::StreamExt;
use reflex_core::stream::Keys;
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
            // Ключей в тесте перечислимо мало.
            Keys::Finite,
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
            // Ключей в тесте перечислимо мало.
            Keys::Finite,
        )
        .collect()
        .await;

    assert_eq!(results, vec![2, 4, 6]);
}

#[tokio::test]
async fn group_by_empty_stream() {
    let stream = iter(Vec::<i32>::new());

    let results: Vec<i32> = stream
        .group_by(
            |item: &i32| *item,
            || (),
            |_, item| Some(item),
            Keys::Finite,
        )
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
            // Ключей в тесте перечислимо мало.
            Keys::Finite,
        )
        .collect()
        .await;

    assert_eq!(results, vec![("x", 10), ("y", 20), ("x", 40), ("y", 25)]);
}

/// СОСТОЯНИЙ ГРУПП НЕ БОЛЬШЕ НАЗВАННОГО ПРЕДЕЛА (#295, срез 1).
///
/// # Чем это было
///
/// `group_by` копил `HashMap<K, State>` без предела — ТА ЖЕ утечка, что вылечена в `detect_per`
/// (#294). Но там о ней хотя бы предупреждали в документации; здесь не было сказано ничего.
///
/// # Почему не «истечение по простою», как у соседа
///
/// У `group_by` НЕТ ЧАСОВ: он работает с обычным потоком, где время не приходит ни элементом, ни
/// тиком. Отмерить простой нечем — и вариант политики здесь другой по природе, а не по вкусу.
///
/// # Цена вытеснения названа
///
/// Вытесненная группа теряет накопленное: вернувшись, она начинает с нуля. Это ХУЖЕ, чем истечение
/// по простою, — уходит та, к которой дольше всего не обращались, а не та, что заведомо мертва. И
/// это честнее, чем расти без границы: у долгоживущего процесса второе кончается падением.
#[tokio::test]
async fn groups_do_not_outgrow_the_declared_ceiling() {
    // Ключи 1, 2, 3 при потолке 2: к моменту возврата единицы её состояние вытеснено.
    let seen: Vec<u32> = futures::stream::iter([1u8, 2, 3, 1])
        .group_by(
            |k: &u8| *k,
            || 0u32,
            |count: &mut u32, _item| {
                *count += 1;
                Some(*count)
            },
            Keys::AtMost(2),
        )
        .collect()
        .await;

    assert_eq!(
        seen.last(),
        Some(&1),
        "состояние вытесненной группы пережило вытеснение: {seen:?}"
    );
}

/// КОНТРОЛЬ: заявленная конечность чтится — состояния живут, сколько бы ключей ни пришло.
///
/// Без него тест выше зеленел бы и на операторе, который забывает состояние всегда, — а такой
/// оператор не группировка вовсе.
#[tokio::test]
async fn finite_keys_keep_their_state() {
    let seen: Vec<u32> = futures::stream::iter([1u8, 2, 3, 1])
        .group_by(
            |k: &u8| *k,
            || 0u32,
            |count: &mut u32, _item| {
                *count += 1;
                Some(*count)
            },
            Keys::Finite,
        )
        .collect()
        .await;

    assert_eq!(
        seen.last(),
        Some(&2),
        "заявленная конечность не почтена — состояние снято: {seen:?}"
    );
}
