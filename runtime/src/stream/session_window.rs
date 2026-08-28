//! ОКНО СЕССИИ — группировка по ключу с ЭМИССИЕЙ агрегата при закрытии окна по бездействию.
//!
//! ЗАЧЕМ ОТДЕЛЬНЫЙ ПРИМИТИВ, а не `group_by_flow` рядом. Тот при истечении делает `retain` и
//! состояние ВЫБРАСЫВАЕТ молча: для счётчика живых флоу это верно (считается только живое), для
//! сессии — фатально. Сессия и существует ради момента закрытия: пока она идёт, сказать о ней
//! нечего, а весь смысл — агрегат за целиком прошедший эпизод.
//!
//! Разделение обязанностей отсюда же: `step` НАКАПЛИВАЕТ и не эмитит ничего, `close` эмитит РОВНО
//! один раз. У `group_by_flow` эмитить может каждый шаг, и такой оператор не умеет сказать
//! «эпизод кончился» — а это единственное, что требуется здесь.
//!
//! ВЫТЕСНЕНИЕ ПО ПОТОЛКУ ТОЖЕ ЭМИТИТ. Соблазн — выкинуть старейшего молча (так делает сосед), и
//! это воспроизвело бы ту же потерю тише: под нагрузкой пропадали бы ровно длинные эпизоды, то
//! есть самые тяжёлые для человека. Вытесненная сессия обязана быть отдана — пусть неполной.

use std::collections::HashMap;
use std::hash::Hash;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::Stream;
use pin_project_lite::pin_project;
use tokio::time::{self, Instant, Interval};

/// Настройка жизненного цикла сессии.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Пауза бездействия, закрывающая сессию.
    pub idle: Duration,
    /// Потолок одновременно живых сессий. Старейшая вытесняется — С ЭМИССИЕЙ.
    pub max_sessions: usize,
    /// Как часто проверять истёкшие.
    pub sweep_interval: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            idle: Duration::from_secs(60),
            max_sessions: 4096,
            sweep_interval: Duration::from_secs(1),
        }
    }
}

/// ЧАСЫ — `tokio::time::Instant`, а НЕ `std::time`. Разница не косметическая: `tokio::time::pause()`
/// подменяет только своё время, и на std-часах окно по бездействию в тесте не закроется НИКОГДА —
/// оператор станет непроверяемым, а поведение «закрылось по тишине» непредъявимым. Сосед
/// `group_by_flow` держит `std::time::Instant` и потому своё истечение не тестирует ничем.
struct SessionEntry<State> {
    state: State,
    last_seen: Instant,
}

pin_project! {
    /// `Stream<T>` → `Stream<R>`: копит состояние на ключ, отдаёт агрегат при закрытии окна.
    pub struct SessionWindowStream<S, K, State, KeyFn, Init, Step, Close, R> {
        #[pin]
        source: S,
        config: SessionConfig,
        key_fn: KeyFn,
        init: Init,
        step: Step,
        close: Close,
        sessions: HashMap<K, SessionEntry<State>>,
        ready: Vec<R>,
        #[pin]
        sweep_tick: Interval,
        _phantom: PhantomData<R>,
    }
}

impl<S, K, State, KeyFn, Init, Step, Close, R>
    SessionWindowStream<S, K, State, KeyFn, Init, Step, Close, R>
{
    pub fn new(
        source: S,
        config: SessionConfig,
        key_fn: KeyFn,
        init: Init,
        step: Step,
        close: Close,
    ) -> Self {
        let sweep_interval = config.sweep_interval;
        Self {
            source,
            config,
            key_fn,
            init,
            step,
            close,
            sessions: HashMap::new(),
            ready: Vec::new(),
            sweep_tick: time::interval(sweep_interval),
            _phantom: PhantomData,
        }
    }
}

impl<S, T, K, State, KeyFn, Init, Step, Close, R> Stream
    for SessionWindowStream<S, K, State, KeyFn, Init, Step, Close, R>
where
    S: Stream<Item = T>,
    K: Eq + Hash + Clone,
    KeyFn: Fn(&T) -> K,
    Init: Fn() -> State,
    Step: FnMut(&mut State, T),
    Close: Fn(K, State) -> R,
{
    type Item = R;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        // Готовое отдаём прежде всего: агрегат, уже собранный прошлым проходом, не имеет права
        // ждать следующего события источника — сессия закрылась ТИШИНОЙ, событий больше не будет.
        if let Some(готовый) = this.ready.pop() {
            return Poll::Ready(Some(готовый));
        }

        if this.sweep_tick.as_mut().poll_tick(cx).is_ready() {
            let idle = this.config.idle;
            let now = Instant::now();
            let истёкшие = this
                .sessions
                .iter()
                .filter(|(_, entry)| now.duration_since(entry.last_seen) >= idle)
                .map(|(key, _)| key.clone())
                .collect::<Vec<_>>();
            let закрытые = истёкшие
                .into_iter()
                .filter_map(|key| {
                    this.sessions
                        .remove(&key)
                        .map(|entry| (this.close)(key, entry.state))
                })
                .collect::<Vec<_>>();
            this.ready.extend(закрытые);
            if let Some(готовый) = this.ready.pop() {
                return Poll::Ready(Some(готовый));
            }
        }

        match this.source.as_mut().poll_next(cx) {
            Poll::Ready(Some(input)) => {
                let key = (this.key_fn)(&input);
                let now = Instant::now();

                // Потолок достигнут и ключ НОВЫЙ — старейшая сессия уходит, но не молча.
                let потолок = this.config.max_sessions;
                let вытеснить =
                    match this.sessions.contains_key(&key) || this.sessions.len() < потолок {
                        true => None,
                        false => this
                            .sessions
                            .iter()
                            .min_by_key(|(_, entry)| entry.last_seen)
                            .map(|(старейший, _)| старейший.clone()),
                    };
                let вытесненный = вытеснить.and_then(|старейший| {
                    this.sessions
                        .remove(&старейший)
                        .map(|entry| (this.close)(старейший, entry.state))
                });
                this.ready.extend(вытесненный);

                let entry = this.sessions.entry(key).or_insert_with(|| SessionEntry {
                    state: (this.init)(),
                    last_seen: now,
                });
                entry.last_seen = now;
                (this.step)(&mut entry.state, input);

                match this.ready.pop() {
                    Some(готовый) => Poll::Ready(Some(готовый)),
                    None => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::UnboundedReceiverStream;

    /// Собрать поток-под-тест: ключ = первый элемент пары, состояние = сумма и счёт.
    fn под_тестом(
        rx: mpsc::UnboundedReceiver<(u8, u32)>,
        config: SessionConfig,
    ) -> impl Stream<Item = (u8, usize, u32)> {
        SessionWindowStream::new(
            UnboundedReceiverStream::new(rx),
            config,
            |item: &(u8, u32)| item.0,
            Vec::<u32>::new,
            |state: &mut Vec<u32>, item: (u8, u32)| state.push(item.1),
            |key: u8, state: Vec<u32>| (key, state.len(), state.iter().sum::<u32>()),
        )
    }

    /// ПРЕДМЕТ: сессия, замолчавшая дольше паузы, ОБЯЗАНА отдать агрегат. Сегодняшний сосед
    /// (`group_by_flow`) в этом месте молча выбрасывает состояние — и эпизод пропадает целиком.
    #[tokio::test(start_paused = true)]
    async fn замолчавшая_сессия_отдаёт_агрегат() {
        let (tx, rx) = mpsc::unbounded_channel();
        let поток = под_тестом(
            rx,
            SessionConfig {
                idle: Duration::from_secs(60),
                max_sessions: 16,
                sweep_interval: Duration::from_secs(1),
            },
        );
        tokio::pin!(поток);

        let _ = tx.send((1u8, 10u32));
        let _ = tx.send((1u8, 20u32));
        // Отправитель НАМЕРЕННО жив: закрытый источник дал бы второй путь к агрегату («поток
        // кончился — дозакрыть всё»), и тест перестал бы доказывать ровно бездействие.
        let _отправитель_жив = tx;

        // Ждём заведомо дольше паузы бездействия. `timeout` при `start_paused` двигает время сам,
        // и он же не даёт тесту ПОВИСНУТЬ, если агрегат не придёт вовсе.
        let агрегат = time::timeout(Duration::from_secs(300), поток.next())
            .await
            .ok()
            .flatten();

        assert_eq!(
            агрегат,
            Some((1u8, 2usize, 30u32)),
            "сессия молчала дольше паузы — агрегат за весь эпизод обязан приехать, а не пропасть"
        );
    }

    /// КОНТРОЛЬ к соседнему тесту, без которого тот вакуумен: реализация, эмитящая агрегат на
    /// КАЖДЫЙ проход, прошла бы его тоже. Живая сессия обязана МОЛЧАТЬ — иначе эпизод разорвётся
    /// на куски и `p95 по сессии` будет считаться по огрызкам, то есть врать в лучшую сторону.
    #[tokio::test(start_paused = true)]
    async fn живая_сессия_агрегата_не_отдаёт() {
        let (tx, rx) = mpsc::unbounded_channel();
        let поток = под_тестом(
            rx,
            SessionConfig {
                idle: Duration::from_secs(60),
                max_sessions: 16,
                sweep_interval: Duration::from_secs(1),
            },
        );
        tokio::pin!(поток);

        let _ = tx.send((1u8, 10u32));
        let _отправитель_жив = tx;

        // Ждём МЕНЬШЕ паузы бездействия: сессия ещё идёт, говорить о ней нечего.
        let преждевременный = time::timeout(Duration::from_secs(30), поток.next())
            .await
            .ok()
            .flatten();

        assert_eq!(
            преждевременный, None,
            "сессия ещё идёт — агрегат выдавать НЕЛЬЗЯ: эпизод не кончился"
        );
    }

    /// Вытеснение по потолку ОБЯЗАНО эмитить. Молчаливое вытеснение (так делает `group_by_flow`)
    /// теряет под нагрузкой ровно самые длинные эпизоды — то есть самые тяжёлые для человека, —
    /// и прибор начинает врать в лучшую сторону именно тогда, когда правда нужнее всего.
    #[tokio::test(start_paused = true)]
    async fn вытеснение_по_потолку_отдаёт_агрегат() {
        let (tx, rx) = mpsc::unbounded_channel();
        let поток = под_тестом(
            rx,
            SessionConfig {
                idle: Duration::from_secs(600),
                max_sessions: 2,
                sweep_interval: Duration::from_secs(1),
            },
        );
        tokio::pin!(поток);

        let _отправитель_жив = tx.clone();

        // События РАЗНЕСЕНЫ ВО ВРЕМЕНИ намеренно. При `pause()` все `Instant::now()` в одном
        // проходе равны, «старейший среди равных» выбирается порядком HashMap, и тест судил бы
        // монету. Секунда между ключами делает вытеснение LRU наблюдаемым, а не случайным.
        let _ = tx.send((1u8, 10u32));
        let первый = time::timeout(Duration::from_secs(1), поток.next())
            .await
            .ok()
            .flatten();
        let _ = tx.send((2u8, 20u32));
        let второй = time::timeout(Duration::from_secs(1), поток.next())
            .await
            .ok()
            .flatten();
        assert_eq!(
            (первый, второй),
            (None, None),
            "потолок ещё не достигнут — вытеснять некого"
        );

        let _ = tx.send((3u8, 30u32));
        // Пауза бездействия ЗАВЕДОМО не наступила (600 с против 30 с ожидания): единственная
        // законная причина агрегата здесь — вытеснение третьим ключом.
        let вытесненный = time::timeout(Duration::from_secs(30), поток.next())
            .await
            .ok()
            .flatten();

        assert_eq!(
            вытесненный,
            Some((1u8, 1usize, 10u32)),
            "третий ключ при потолке 2 вытесняет старейшего — и обязан отдать его эпизод, а не съесть"
        );
    }
}
