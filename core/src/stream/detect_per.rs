//! `detect_per` — прогон [`Detector`](crate::Detector) по потоку, с отдельным состоянием на ключ.
//!
//! # Зачем оператор, если есть `group_by`
//!
//! `group_by` ключует КАЖДЫЙ элемент и потому не умеет главного, что нужно детектору: `Tick`
//! обязан прийти ВО ВСЕ живые группы. Таймер — не событие одной цели, он событие времени, и
//! детектор тишины без него не сработает никогда (тишина есть отсутствие пакетов, а отсутствие
//! пакетов не порождает элементов потока).
//!
//! # Зачем оператор, если есть `drive`
//!
//! `drive` прогоняет [`Reactor`](crate::Reactor): один эффект на переход, состояние `Copy`.
//! Детектор устроен иначе — `SmallVec` сигналов на шаг (их может быть ноль, один или два) и
//! состояние произвольного размера. Гонять детектор через реактор значит терять сигналы.
//!
//! # Что этот оператор ГАРАНТИРУЕТ
//!
//! * состояние заводится на ПЕРВОМ событии ключа и живёт, пока живёт поток;
//! * `Tick` доставляется каждому живому состоянию — в порядке ключей, детерминированно;
//! * ни один сигнал не теряется: они выдаются по одному, очередь опустошается прежде, чем
//!   опрашивается источник;
//! * детектор не дёргает часы сам — время приходит в событии, потому тесты воспроизводимы.
//!
//! # Чего он НЕ делает
//!
//! Состояния не истекают: ключ, о котором забыли, занимает память до конца потока. Для потока
//! соединений это утечка, и лечится она либо истечением по времени, либо внешним снятием ключа.
//! Здесь не сделано намеренно — политика жизни ключа принадлежит потребителю, а не оператору,
//! и угадывать её означало бы навязать одну всем. Потребителю: если ключей неограниченно много,
//! оператор не подходит.

use std::collections::{BTreeMap, VecDeque};
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::Stream;

use crate::detector::{Detector, DetectorEvent};

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
    states: BTreeMap<K, D>,
    pending: VecDeque<(K, D::Signal)>,
}

impl<S, D, K, KeyFn, Factory> DetectPer<S, D, K, KeyFn, Factory>
where
    D: Detector,
{
    pub fn new(source: S, key_fn: KeyFn, factory: Factory) -> Self {
        Self {
            source,
            key_fn,
            factory,
            states: BTreeMap::new(),
            pending: VecDeque::new(),
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
                        Some(existing) => existing,
                        None => (this.factory)(),
                    };
                    let (next, signals) = detector.step(DetectorEvent::Packet { input, at });
                    this.states.insert(key.clone(), next);
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
                            Some(detector) => {
                                let (next, signals) = detector.step(DetectorEvent::Tick { at });
                                this.states.insert(key.clone(), next);
                                signals
                                    .into_iter()
                                    .for_each(|signal| this.pending.push_back((key.clone(), signal)));
                            }
                        };
                    });
                }
            }
        }
    }
}
