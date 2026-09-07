use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures::Stream;
use pin_project_lite::pin_project;
use smallvec::SmallVec;
use tokio::time::{self, Interval};

use reflex_core::step::Step;
use reflex_core::DetectorEvent;

pin_project! {
    pub struct DetectStream<S, D, Sig> {
        #[pin]
        source: S,
        detector: Option<D>,
        buffer: VecDeque<Sig>,
        #[pin]
        tick: Interval,
        // НАЧАЛО СЕТКИ, ЕЁ ШАГ И ПОСЛЕДНИЙ УЖЕ УЧТЁННЫЙ МОМЕНТ.
        //
        // Пробуждение `tick` говорит ровно одно: «пора посмотреть». Какие узлы сетки НАСТУПИЛИ с
        // прошлого взгляда и как они пронумерованы, называет [`reflex_core::grid::nodes_between`]
        // на моменте КАЖДОГО узла — тем же способом, каким это уже делают [`crate::interleave`] и
        // `reflex_core::pcap::on_grid`. Считать номер от момента пробуждения (`grid::due(began,
        // now, every)`) значило бы под каждым отдельным пробуждением получать номер ПОСЛЕДНЕГО
        // наступившего узла, а пропущенные между двумя пробуждениями — терять молча: три
        // пробуждения подряд почти в одну точку дали бы три одинаковых номера там, где сетка
        // называет три РАЗНЫХ подряд идущих узла.
        began: Instant,
        last: Instant,
        every: Duration,
    }
}

impl<S, D, Sig> DetectStream<S, D, Sig> {
    pub fn new(source: S, detector: D, tick_interval: Duration) -> Self {
        let began = Instant::now();
        Self {
            source,
            detector: Some(detector),
            buffer: VecDeque::new(),
            tick: time::interval(tick_interval),
            began,
            last: began,
            every: tick_interval,
        }
    }
}

impl<S, D, Sig> Stream for DetectStream<S, D, Sig>
where
    S: Stream,
    D: Step<From = DetectorEvent<S::Item>, To = SmallVec<[Sig; 2]>>,
{
    type Item = Sig;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        // 1. Drain buffered signals first
        if let Some(signal) = this.buffer.pop_front() {
            return Poll::Ready(Some(signal));
        }

        // 2. Try tick
        if let Some(mut detector) = this.detector.take() {
            if this.tick.as_mut().poll_tick(cx).is_ready() {
                let now = Instant::now();
                // УЗЛЫ БЕРУТСЯ ПО ЗАКОНУ СЕТКИ НА ИХ СОБСТВЕННОМ МОМЕНТЕ, а не на моменте
                // пробуждения: пробуждение под дрейфом может опоздать на несколько шагов сразу, и
                // тогда `nodes_between` отдаёт их ВСЕ по порядку, а не один слипшийся номер.
                let nodes: Vec<Instant> =
                    reflex_core::grid::nodes_between(*this.began, *this.last, now, *this.every)
                        .collect();
                for at in nodes {
                    let node = reflex_core::grid::due(*this.began, at, *this.every);
                    let (next_detector, signals) = detector.step(DetectorEvent::Tick { node, at });
                    detector = next_detector;
                    for signal in signals {
                        this.buffer.push_back(signal);
                    }
                }
                *this.last = now;
                *this.detector = Some(detector);
                if let Some(signal) = this.buffer.pop_front() {
                    return Poll::Ready(Some(signal));
                }
            } else {
                *this.detector = Some(detector);
            }
        }

        // 3. Poll source
        match this.source.as_mut().poll_next(cx) {
            Poll::Ready(Some(input)) => {
                if let Some(detector) = this.detector.take() {
                    let at = Instant::now();
                    let (new_detector, signals) =
                        detector.step(DetectorEvent::Packet { input, at });
                    *this.detector = Some(new_detector);
                    for signal in signals {
                        this.buffer.push_back(signal);
                    }
                }
                if let Some(signal) = this.buffer.pop_front() {
                    Poll::Ready(Some(signal))
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
