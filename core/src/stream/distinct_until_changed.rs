//! `distinct_until_changed` — ПОТОК ЗНАЧЕНИЙ СТАНОВИТСЯ ПОТОКОМ ПЕРЕХОДОВ.
//!
//! # Зачем отдельный оператор
//!
//! Свидетельство о плагине добывается ОПРОСОМ: спросили счётчик ядра — получили `4096`, спросили
//! снова — снова `4096`. Значений много, событий одно: счётчик изменился. Потребителю нужно
//! второе, и превращать первое во второе вручную значит заводить у каждого потребителя своё
//! «а не то же ли самое пришло» — то есть N реализаций одного закона.
//!
//! # Что он даёт сверх экономии
//!
//! **Опрос перестаёт быть частью контракта.** Наблюдатель обязан рапортовать переходы своего
//! состояния, а не наблюдения — иначе частота отчётов привязывается к частоте опроса, и потолок
//! CPU становится вопросом того, как часто мы спрашиваем. С этим оператором спрашивать можно
//! сколько угодно: наружу выйдет ровно смена.
//!
//! **Оператор идемпотентен**: `d ∘ d = d`. Поток, уже прошедший через него, повторным
//! применением не меняется — свойство, которого нет ни у `filter`, ни у `dedup` по окну.
//!
//! # Первый элемент проходит ВСЕГДА
//!
//! Ему не с чем совпадать, и молчать о нём значило бы потерять начальное состояние: потребитель,
//! подключившийся к исправному плагину, не узнал бы о нём ничего до первой перемены. Ровно та
//! болезнь, что у `with_latest_from` без начального значения (#295).

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::Stream;
use pin_project_lite::pin_project;

pin_project! {
    pub struct DistinctUntilChangedStream<S, T> {
        #[pin]
        source: S,
        // Что видели в прошлый раз. `None` — не видели ничего, и первый элемент пройдёт.
        seen: Option<T>,
    }
}

impl<S, T> DistinctUntilChangedStream<S, T> {
    pub fn new(source: S) -> Self {
        Self { source, seen: None }
    }
}

impl<S> Stream for DistinctUntilChangedStream<S, S::Item>
where
    S: Stream,
    S::Item: PartialEq + Clone,
{
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // `let mut` здесь — идиома `pin_project` на границе опроса, та же, что у `switch_map` и
        // `merge_map_bounded`: без `as_mut` источник нельзя опросить дважды за один `poll`.
        // Мутация заперта в этой функции и наружу не видна: оператор остаётся чистым по входу.
        let mut this = self.project();

        loop {
            match this.source.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => match this.seen.as_ref() {
                    // ПОВТОР ГЛОТАЕТСЯ, И ИСТОЧНИК ОПРАШИВАЕТСЯ ДАЛЬШЕ, а не возвращается
                    // `Pending`: вернуть `Pending`, не оставив пробуждения, значит подвесить
                    // потребителя навсегда — потерянный waker, за который мы уже платили
                    // («три зелёных теста на виртуальных часах его не поймали»).
                    Some(before) if before == &item => continue,
                    _новое => {
                        *this.seen = Some(item.clone());
                        return Poll::Ready(Some(item));
                    }
                },
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext::ReflexExt;
    use futures::{stream, StreamExt};

    /// ПОВТОРЫ ГЛОТАЮТСЯ, ПЕРЕМЕНЫ ПРОХОДЯТ — включая возврат к прежнему значению.
    ///
    /// Возврат существен: `1,1,2,2,1` обязано дать `1,2,1`, а не `1,2`. Оператор помнит
    /// ПОСЛЕДНЕЕ, а не все виденные — иначе счётчик, сброшенный перезапуском плагина, молчал бы
    /// о том, что плагин перезапустился.
    #[tokio::test]
    async fn repeats_are_swallowed_and_a_return_to_a_former_value_is_a_change() {
        let seen: Vec<u8> = stream::iter([1, 1, 2, 2, 2, 1, 1, 3])
            .distinct_until_changed()
            .collect()
            .await;

        assert_eq!(seen, vec![1, 2, 1, 3]);
    }

    /// ПЕРВЫЙ ЭЛЕМЕНТ ПРОХОДИТ ВСЕГДА: ему не с чем совпадать.
    ///
    /// Контроль рядом: поток из одних повторов обязан дать РОВНО ОДИН элемент, а не ноль и не
    /// восемь. Без него «первый проходит» прошло бы и у оператора, пропускающего всё подряд.
    #[tokio::test]
    async fn the_first_value_always_passes_and_a_silent_source_yields_exactly_one() {
        let same: Vec<u8> = stream::iter([7, 7, 7, 7])
            .distinct_until_changed()
            .collect()
            .await;
        assert_eq!(same, vec![7]);

        let empty: Vec<u8> = stream::iter(Vec::<u8>::new())
            .distinct_until_changed()
            .collect()
            .await;
        assert!(empty.is_empty(), "пустой источник родил элемент из ничего");
    }

    /// ИДЕМПОТЕНТНОСТЬ: `d ∘ d = d`.
    ///
    /// Свойство не украшение: оно означает, что оператор можно ставить где угодно по цепочке, не
    /// сверяясь, не стоит ли он уже выше. Без него композиция потребовала бы знания о соседях.
    #[tokio::test]
    async fn applying_it_twice_changes_nothing() {
        let once: Vec<u8> = stream::iter([1, 1, 2, 3, 3])
            .distinct_until_changed()
            .collect()
            .await;
        let twice: Vec<u8> = stream::iter([1, 1, 2, 3, 3])
            .distinct_until_changed()
            .distinct_until_changed()
            .collect()
            .await;

        assert_eq!(once, twice);
        assert_eq!(once, vec![1, 2, 3]);
    }
}
