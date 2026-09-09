//! Приборы на величинах КРАЯ, без собственного состояния. Прибор о носителе не знает — читает
//! `EdgeView` (conntrack, карта eBPF, чужая ОС) и марку под своей `Layout`. Собственное `S`
//! вырождено: исход зависит от края и марки, не от прожитого (§ спеки — состояние в ядре).
//!
//! База таймаута прибору НЕ нужна: `idle` край отдаёт готовой величиной (`V::idle`). Оттого
//! `EdgeSilence::new(after, layout)` базы не принимает — она живёт у носителя (`CtEdge`).

use std::marker::PhantomData;
use std::time::Duration;

use reflex_core::edge::EdgeView;
use reflex_core::mealy::Mealy;
use reflex_core::DetectorEvent;
use smallvec::{smallvec, SmallVec};

use crate::distress::Distress;
use crate::edge::{Layout, Memo, Phase, Recall};
use crate::edge_word::Edged;
use crate::wire::Seen;

/// Тишина по величинам края. Ловит РОВНО два случая, и это предел `idle`:
/// * «цель не ответила вовсе» — `up_packets == Some(0)` (счётчик ядра, `NoBytes`);
/// * «поток простаивает целиком» — `idle >= after`.
///
/// Третий случай — «замолчала посреди разговора при активном клиенте» — на `idle` НЕВЫРАЗИМ: ядро
/// освежает таймаут на ЛЮБОМ пакете (`__nf_ct_refresh_acct`), включая повтор клиента, потому `idle`
/// у такого потока близок к нулю. Он выражается неподвижностью `up` при растущем `down` — то есть
/// прибором ПОВТОРА, где оттиск памятки и становится точкой отсчёта. Оттиск здесь пишется (памятка
/// одна на приборы), но решения по нему `EdgeSilence` не принимает — читает его повтор.
///
/// Фазу и оттиск читает/пишет через марку — состояния в юзерспейсе не держит.
pub struct EdgeSilence<V> {
    after: Duration,
    layout: Layout,
    edge: PhantomData<fn() -> V>,
}

// Copy/Clone без `V`-бонда: носитель в фантоме, экземпляр от `V` не зависит.
impl<V> Clone for EdgeSilence<V> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<V> Copy for EdgeSilence<V> {}

/// Оттиск — младшие 8 бит счётчика ответов на момент постановки фазы. `None` (край не считает) даёт
/// 0: сравнивать оттиск всё равно не с чем, а фаза важнее.
fn imprint_of(up: Option<u64>) -> u8 {
    (up.unwrap_or(0) & 0xFF) as u8
}

impl<V: EdgeView> EdgeSilence<V> {
    pub fn new(after: Duration, layout: Layout) -> EdgeSilence<V> {
        EdgeSilence {
            after,
            layout,
            edge: PhantomData,
        }
    }

    /// Памятка: фаза и оттиск ставятся ОДНИМ конструктором — разнести (записать фазу, не обновив
    /// точку отсчёта) нельзя, иначе подозрение смотрело бы в прошлое.
    fn memo(&self, phase: Phase, up: Option<u64>) -> Memo {
        Memo::new(self.layout, phase, imprint_of(up))
    }
}

impl<V: EdgeView> Mealy for EdgeSilence<V> {
    type In = DetectorEvent<Edged<Seen, V>>;
    type Out = SmallVec<[(Distress, Memo); 2]>;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        // Прибор края работает по букве `Packet`: тик марки прочесть не может (ct-вид едет с пакетом).
        let edge = match &event {
            DetectorEvent::Packet { input, .. } => &input.edge,
            DetectorEvent::Tick { .. } | DetectorEvent::Opaque { .. } => {
                return (self, SmallVec::new(), ());
            }
        };
        let up = edge.up_packets();

        let out: SmallVec<[(Distress, Memo); 2]> = match self.layout.read(edge.mark()) {
            // Чужой писатель (тег не наш, слово непустое) — находка, не тишина.
            Recall::Foreign { theirs } if theirs != 0 => {
                smallvec![(Distress::Diverged { theirs }, self.memo(Phase::Suspected, up))]
            }
            // Наша фаза или нетронутый поток (`theirs == 0`).
            recall => {
                let phase = match recall {
                    Recall::Ours(memo) => memo.phase,
                    Recall::Foreign { .. } => Phase::Quiet,
                };
                match phase {
                    // Уже сказали — повторно не жалуемся (фаза лежит в марке).
                    Phase::Confirmed | Phase::Released => SmallVec::new(),
                    Phase::Quiet | Phase::Suspected => {
                        if up == Some(0) {
                            // Цель не ответила ВОВСЕ — `Some(0)`, не `None` (иначе ложь при acct off).
                            smallvec![(Distress::NoBytes, self.memo(Phase::Confirmed, up))]
                        } else if edge.idle().is_some_and(|idle| idle >= self.after) {
                            let ms = edge.idle().map_or(0, |idle| idle.as_millis() as u32);
                            smallvec![(Distress::Silence { ms }, self.memo(Phase::Confirmed, up))]
                        } else {
                            SmallVec::new()
                        }
                    }
                }
            }
        };
        (self, out, ())
    }
}
