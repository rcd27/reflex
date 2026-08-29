//! `group_by` — группировка по произвольному ключу с состоянием на группу.
//!
//! # Число групп ОГРАНИЧЕНО ЗАЯВЛЕНИЕМ, и промолчать нельзя (#295, срез 1)
//!
//! Оператор копил `HashMap<K, State>` без предела: ключ, о котором забыли, занимал память до конца
//! потока. Для потока соединений это утечка — та же, что вылечена в `detect_per` (#294), только о
//! ней здесь не было сказано НИЧЕГО.
//!
//! # Почему политика иная, чем у `detect_per`
//!
//! У `detect_per` есть часы: время приходит тиком, и состояние снимается по простою. У `group_by`
//! часов НЕТ — он работает с обычным потоком, где время не приходит ни элементом, ни тиком.
//! Отмерить простой нечем, и потому единственная честная граница — ЧИСЛО групп.
//!
//! Это различие по природе, а не по вкусу: одинаковая политика у двух операторов была бы ложью об
//! одном из них.

use std::collections::HashMap;
use std::hash::Hash;

/// СКОЛЬКО ГРУПП ДЕРЖИМ. Обязательный аргумент.
///
/// Вариант типа, а не `Option<usize>`: `None` читалось бы как «предела нет», то есть как
/// умолчание, — а предмет ровно в том, чтобы умолчания не было.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keys {
    /// КЛЮЧЕЙ КОНЕЧНОЕ ЧИСЛО — ноги, классы, состояния протокола. Расти памяти некуда, и
    /// состояния живут до конца потока законно. ЗАЯВЛЕНИЕ, а не молчание.
    Finite,
    /// КЛЮЧЕЙ НЕОГРАНИЧЕННО МНОГО — соединения, цели, сессии. Держим не более `n` групп; при
    /// переполнении уходит та, к которой дольше всего не обращались.
    ///
    /// ЦЕНА: вытесненная группа теряет накопленное и, вернувшись, начинает с нуля. Это хуже, чем
    /// истечение по простою у `detect_per` (уходит не заведомо мёртвая, а давняя), и честнее, чем
    /// рост без границы: у долгоживущего процесса второе кончается падением.
    AtMost(usize),
}
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::Stream;
use pin_project_lite::pin_project;

pin_project! {
    /// Groups items by key and applies a per-group operator.
    ///
    /// Each unique key gets its own state. The `init` closure creates initial state,
    /// `step` processes each item and may produce output. Results from all groups
    /// are flattened into a single output stream.
    ///
    /// Морфизм категории: `Stream<T> -> Stream<R>` с per-key state isolation.
    pub struct GroupByStream<S, K, State, KeyFn, Init, Step, R> {
        #[pin]
        source: S,
        key_fn: KeyFn,
        init: Init,
        step: Step,
        // Рядом с состоянием — ПОРЯДКОВЫЙ НОМЕР последнего обращения: им и только им решается,
        // кого вытеснять при переполнении.
        groups: HashMap<K, (State, u64)>,
        tick: u64,
        keys: Keys,
        _phantom: PhantomData<R>,
    }
}

impl<S, K, State, KeyFn, Init, Step, R> GroupByStream<S, K, State, KeyFn, Init, Step, R>
where
    K: Hash + Eq + Clone,
{
    pub fn new(source: S, key_fn: KeyFn, init: Init, step: Step, keys: Keys) -> Self {
        Self {
            source,
            key_fn,
            init,
            step,
            groups: HashMap::new(),
            tick: 0,
            keys,
            _phantom: PhantomData,
        }
    }
}

impl<S, T, K, State, KeyFn, Init, Step, R> Stream
    for GroupByStream<S, K, State, KeyFn, Init, Step, R>
where
    S: Stream<Item = T>,
    K: Hash + Eq + Clone,
    KeyFn: Fn(&T) -> K,
    Init: Fn() -> State,
    Step: FnMut(&mut State, T) -> Option<R>,
{
    type Item = R;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        match this.source.poll_next(cx) {
            Poll::Ready(Some(input)) => {
                let key = (this.key_fn)(&input);

                // ВЫТЕСНЕНИЕ ДО ВСТАВКИ, и только для НОВОГО ключа: группа, к которой обратились,
                // уходить не должна — иначе при потолке 1 всякий элемент стирал бы предыдущий.
                match (*this.keys, this.groups.contains_key(&key)) {
                    (Keys::AtMost(n), false) if this.groups.len() >= n => {
                        let oldest = this
                            .groups
                            .iter()
                            .min_by_key(|(_, (_, used))| *used)
                            .map(|(k, _)| k.clone());
                        match oldest {
                            None => (),
                            Some(k) => {
                                this.groups.remove(&k);
                            }
                        }
                    }
                    (Keys::AtMost(_), _) | (Keys::Finite, _) => (),
                }

                *this.tick += 1;
                let used = *this.tick;
                let entry = this
                    .groups
                    .entry(key)
                    .or_insert_with(|| ((this.init)(), used));
                entry.1 = used;
                let state = &mut entry.0;
                if let Some(result) = (this.step)(state, input) {
                    Poll::Ready(Some(result))
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
