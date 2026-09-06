//! `detect_per` — прогон [`Detector`](crate::Detector) по потоку, с отдельным состоянием на ключ.
//!
//! # Зачем оператор, если есть `group_by`
//!
//! `group_by` ключует КАЖДЫЙ элемент и потому не умеет главного, что нужно детектору: `Tick`
//! обязан прийти ВО ВСЕ живые группы. Таймер — не событие одной цели, он событие времени, и
//! детектор тишины без него не сработает никогда (тишина есть отсутствие пакетов, а отсутствие
//! пакетов не порождает элементов потока).
//!
//! # Зачем оператор, если есть `over`
//!
//! [`over`](crate::step::StepExt::over) поднимает на поток ОДНУ машину: одно состояние на все
//! входы, каким бы ключом они ни различались. Детектору нужна СЕМЬЯ машин, ключёванная
//! разговором, — и вместе с ней рождение состояния на первом событии ключа, смерть по сроку и
//! доставка `Tick` во все живые сразу.
//!
//! ПРЕЖДЕ ЗДЕСЬ СРАВНИВАЛОСЬ С `drive` — драйвером снесённого диалекта реактора, — и доводы были
//! другие: «один эффект на переход» и «состояние `Copy`». Против шага они не работают: у `Step`
//! и выход, и состояние произвольны. Против ОДНОЙ машины работает то, что написано выше.
//!
//! # Что этот оператор ГАРАНТИРУЕТ
//!
//! * состояние заводится на ПЕРВОМ событии ключа и живёт, пока живёт поток;
//! * `Tick` доставляется каждому живому состоянию — в порядке ключей, детерминированно;
//! * ни один сигнал не теряется: они выдаются по одному, очередь опустошается прежде, чем
//!   опрашивается источник;
//! * детектор не дёргает часы сам — время приходит в событии, потому тесты воспроизводимы.
//!
//! # Политика жизни ключа НАЗЫВАЕТСЯ ВЫЗЫВАЮЩИМ, и промолчать нельзя
//!
//! Прежде здесь стояло предупреждение: «состояния не истекают… если ключей неограниченно много,
//! оператор не подходит», — и политика оставалась на совести потребителя. **Так не сработало.**
//! Первый же продуктовый вызов (`domain::pipe::alarms`) ключевал по 5-tuple соединения, то есть
//! нарушал названное условие, и это осталось незамеченным до #294: состояние каждого флоу жило
//! до конца процесса, а мёртвый флоу продолжал получать тики и получал улику в молчании,
//! набранную из пауз ЧУЖОГО трафика.
//!
//! Урок общий: **предупреждение в документации не защищает** — его читают, когда пишут оператор,
//! и не перечитывают, когда его применяют. Поэтому [`Lifetime`] стал обязательным аргументом:
//! забыть политику невозможно, а `Bounded` есть ЗАЯВЛЕНИЕ «ключей здесь конечное число», а не
//! умолчание.

use std::collections::{BTreeMap, VecDeque};
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::Stream;

use crate::detector::{Detector, DetectorEvent};
use std::time::{Duration, Instant};

/// СКОЛЬКО ЖИВЁТ СОСТОЯНИЕ КЛЮЧА. Обязательный аргумент [`DetectPer::new`].
///
/// Вариант типа, а не `Option<Duration>`: `None` читалось бы как «предела нет», то есть как
/// умолчание, — а предмет здесь ровно в том, чтобы умолчания не было.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifetime {
    /// КЛЮЧЕЙ КОНЕЧНОЕ ЧИСЛО — ноги, классы, порты. Состояние живёт до конца потока, и это
    /// законно: расти ему некуда.
    Bounded,
    /// КЛЮЧЕЙ НЕОГРАНИЧЕННО МНОГО — соединения, цели, сессии. Состояние снимается, когда по
    /// ключу не было НИ ОДНОГО события дольше срока.
    ///
    /// Срок берётся ЗАВЕДОМО БОЛЬШИМ, чем окна детекторов, которые в нём живут: снятое раньше
    /// времени состояние теряет беду, о которой детектор ещё не успел сказать.
    UntilIdle(Duration),
}

/// `Unpin` у источника требуется намеренно, вместо `pin_project`: поле с ассоциированным типом
/// (`VecDeque<(K, D::Signal)>`) макрос не разбирает. Ограничение необременительно — источники
/// событий его удовлетворяют, а взамен разбор структуры остаётся читаемым.
pub struct DetectPer<S, D, K, KeyFn, Factory>
where
    D: Detector,
{
    source: S,
    key_fn: KeyFn,
    factory: Factory,
    /// `BTreeMap`, а не `HashMap`: порядок доставки `Tick` обязан быть детерминированным,
    /// иначе тест, где два детектора сработали на один тик, зеленеет через раз.
    ///
    /// Рядом с детектором — момент ПОСЛЕДНЕГО события по ключу: без него нечем отмерить простой.
    states: BTreeMap<K, (D, Instant)>,
    pending: VecDeque<(K, D::Signal)>,
    lifetime: Lifetime,
}

impl<S, D, K, KeyFn, Factory> DetectPer<S, D, K, KeyFn, Factory>
where
    D: Detector,
{
    pub fn new(source: S, key_fn: KeyFn, factory: Factory, lifetime: Lifetime) -> Self {
        Self {
            source,
            key_fn,
            factory,
            states: BTreeMap::new(),
            pending: VecDeque::new(),
            lifetime,
        }
    }
}

impl<S, D, K, KeyFn, Factory> Stream for DetectPer<S, D, K, KeyFn, Factory>
where
    S: Stream<Item = DetectorEvent<D::Input>> + Unpin,
    D: Detector + Unpin,
    D::Input: Clone,
    D::Signal: Unpin,
    K: Ord + Clone + Unpin,
    KeyFn: Fn(&D::Input) -> K + Unpin,
    Factory: Fn() -> D + Unpin,
{
    type Item = (K, D::Signal);

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            // Сначала отдаём накопленное: сигнал, произведённый шагом, не может быть потерян
            // из-за того, что источник завершился следом.
            match this.pending.pop_front() {
                Some(signal) => return Poll::Ready(Some(signal)),
                None => (),
            }

            match Pin::new(&mut this.source).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(None),

                // ПАКЕТ — в состояние своего ключа.
                Poll::Ready(Some(DetectorEvent::Packet { input, at })) => {
                    let key = (this.key_fn)(&input);
                    let detector = match this.states.remove(&key) {
                        Some((existing, _)) => existing,
                        None => (this.factory)(),
                    };
                    let (next, signals) = detector.step(DetectorEvent::Packet { input, at });
                    this.states.insert(key.clone(), (next, at));
                    signals
                        .into_iter()
                        .for_each(|signal| this.pending.push_back((key.clone(), signal)));
                }

                // ТИК — во все живые состояния. Это и есть причина существования оператора.
                Poll::Ready(Some(DetectorEvent::Tick { at })) => {
                    let keys: Vec<K> = this.states.keys().cloned().collect();
                    keys.into_iter().for_each(|key| {
                        match this.states.remove(&key) {
                            None => (),
                            Some((detector, seen_at)) => {
                                // ТИК ДОСТАВЛЯЕТСЯ ПРЕЖДЕ, ЧЕМ РЕШАЕТСЯ СУДЬБА КЛЮЧА: снять
                                // состояние, не дав ему сказать последнее слово, значит потерять
                                // беду, о которой детектор уже знал.
                                let (next, signals) = detector.step(DetectorEvent::Tick { at });
                                let idle = at.saturating_duration_since(seen_at);
                                match this.lifetime {
                                    Lifetime::UntilIdle(limit) if idle >= limit => (),
                                    Lifetime::UntilIdle(_) | Lifetime::Bounded => {
                                        this.states.insert(key.clone(), (next, seen_at));
                                    }
                                }
                                signals.into_iter().for_each(|signal| {
                                    this.pending.push_back((key.clone(), signal))
                                });
                            }
                        };
                    });
                }
            }
        }
    }
}
