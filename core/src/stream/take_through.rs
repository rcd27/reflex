//! `take_through` — БЕРИ, ПОКА ПРЕДИКАТ ДЕРЖИТ, ВКЛЮЧАЯ ТУ, ЧТО ЕГО СНЯЛА.
//!
//! # Зачем отдельный оператор, когда есть `take_while`
//!
//! `take_while` роняет элемент, на котором предикат стал ложным, — и для ПОИСКА это ровно тот
//! элемент, ради которого поиск затевался. «Перебирай кандидатов, пока не найдётся годный»
//! кончается находкой, и потерять её значит остаться без ответа, потратив все пробы.
//!
//! Формулируя иначе: `take_while` выражает «пока условие держится», а поиск требует «до тех пор,
//! пока не случится». Второе не выводится из первого без потери последнего элемента.
//!
//! # Где применяется
//!
//! Подбор рабочей страты (`zond::search`): каталог перебирается сверху вниз, первая взявшая цель
//! останавливает перебор И является ответом. Тот же скелет у любой лестницы эскалации: пробуй
//! всё более дорогое, остановись на сработавшем, верни его.

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::Stream;
use pin_project_lite::pin_project;

pin_project! {
    pub struct TakeThroughStream<S, P> {
        #[pin]
        source: S,
        predicate: P,
        // Предикат уже снят — поток обязан кончиться, не трогая источник.
        done: bool,
    }
}

impl<S, P> TakeThroughStream<S, P> {
    pub fn new(source: S, predicate: P) -> Self {
        Self {
            source,
            predicate,
            done: false,
        }
    }
}

impl<S, P> Stream for TakeThroughStream<S, P>
where
    S: Stream,
    P: FnMut(&S::Item) -> bool,
{
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        match *this.done {
            // ИСТОЧНИК БОЛЬШЕ НЕ ОПРАШИВАЕТСЯ, и это не оптимизация: за каждым элементом здесь
            // стоит проба по сети, и лишний опрос есть лишний пакет.
            true => Poll::Ready(None),
            false => match this.source.poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    match (this.predicate)(&item) {
                        true => (),
                        // Элемент отдаём И на нём заканчиваемся — в этом вся разница с `take_while`.
                        false => *this.done = true,
                    }
                    Poll::Ready(Some(item))
                }
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{stream, StreamExt};

    /// ЭЛЕМЕНТ, СНЯВШИЙ ПРЕДИКАТ, ОСТАЁТСЯ. Это и есть весь смысл оператора: у `take_while`
    /// здесь было бы `[1, 2]`, то есть находка потеряна.
    #[test]
    fn the_element_that_broke_the_predicate_is_kept() {
        futures::executor::block_on(async {
            let got: Vec<i32> =
                TakeThroughStream::new(stream::iter([1, 2, 3, 4, 5]), |n: &i32| *n < 3)
                    .collect()
                    .await;
            assert_eq!(got, [1, 2, 3]);
        });
    }

    /// ПОСЛЕ ОСТАНОВКИ ИСТОЧНИК НЕ ОПРАШИВАЕТСЯ. За элементом стоит проба по сети — лишний опрос
    /// есть лишний пакет, и «поток кончился» обязано значить «больше не спрашиваем».
    #[test]
    fn the_source_is_not_polled_after_the_stop() {
        futures::executor::block_on(async {
            let polls = std::cell::Cell::new(0);
            let counted = stream::iter([1, 2, 3, 4, 5]).map(|n| {
                polls.set(polls.get() + 1);
                n
            });
            let got: Vec<i32> = TakeThroughStream::new(counted, |n: &i32| *n < 3)
                .collect()
                .await;
            assert_eq!(got, [1, 2, 3]);
            assert_eq!(polls.get(), 3, "источник опрошен лишний раз");
        });
    }

    /// ПРЕДИКАТ ДЕРЖИТ ВСЮ ДОРОГУ — отдаётся всё, и поток кончается вместе с источником.
    #[test]
    fn a_predicate_that_never_breaks_passes_everything() {
        futures::executor::block_on(async {
            let got: Vec<i32> = TakeThroughStream::new(stream::iter([1, 2, 3]), |_: &i32| true)
                .collect()
                .await;
            assert_eq!(got, [1, 2, 3]);
        });
    }

    /// ПУСТОЙ ИСТОЧНИК — ПУСТОЙ ВЫХОД, без обращения к предикату.
    #[test]
    fn an_empty_source_yields_nothing() {
        futures::executor::block_on(async {
            let got: Vec<i32> =
                TakeThroughStream::new(stream::iter(Vec::<i32>::new()), |_: &i32| {
                    panic!("предикат не смеет зваться на пустом источнике")
                })
                .collect()
                .await;
            assert!(got.is_empty());
        });
    }
}
