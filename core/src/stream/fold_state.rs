//! `fold_state` — свёртка потока в состояние, ЧИСТАЯ по построению.
//!
//! Отличие от [`scan_state`](crate::stream::ScanStream) не косметическое. Там шаг объявлен как
//! `FnMut(&mut State, Item)` — он возвращает `()`, а состояние правит через ссылку. В такой шаг
//! можно написать что угодно: прочитать глобал, сделать IO, забыть присвоить, — и тип не
//! возразит. Чистота остаётся соглашением.
//!
//! Здесь шаг есть `Fn(State, Item) -> State`. Два следствия, и оба даёт компилятор:
//!   * `Fn`, а не `FnMut` — мутировать захваченное окружение НЕЛЬЗЯ;
//!   * состояние приходит по значению и обязано быть возвращено — «забыть присвоить» не выйдет.
//!
//! ЦЕНА НАЗВАНА: состояние передаётся по значению на каждом шаге. Для больших состояний это
//! требует структурного разделения (persistent-структуры либо `Arc` на редко меняющуюся часть),
//! иначе свёртка окажется дороже мутации. Оператор этого не решает и решать не должен: как
//! устроено состояние — дело домена.

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::Stream;
use pin_project_lite::pin_project;

pin_project! {
    pub struct FoldStream<S, State, F> {
        #[pin]
        source: S,
        state: Option<State>,
        f: F,
    }
}

impl<S, State, F> FoldStream<S, State, F> {
    pub fn new(source: S, seed: State, f: F) -> Self {
        Self {
            source,
            state: Some(seed),
            f,
        }
    }
}

impl<S, State, F> Stream for FoldStream<S, State, F>
where
    S: Stream,
    State: Clone,
    F: Fn(State, S::Item) -> State,
{
    type Item = State;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        match this.source.poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(item)) => match this.state.take() {
                // Состояния нет — значит предыдущий шаг паниковал между take и записью.
                // Поток честно завершается, а не выдаёт полуправду.
                None => Poll::Ready(None),
                Some(state) => {
                    let next = (this.f)(state, item);
                    *this.state = Some(next.clone());
                    Poll::Ready(Some(next))
                }
            },
        }
    }
}
