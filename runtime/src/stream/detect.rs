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

/// МОМЕНТ ПО ЧАСАМ РАНТАЙМА — ЕДИНСТВЕННАЯ ЛИНЕЙКА ВРЕМЕНИ ЭТОГО ОПЕРАТОРА (Ruling 20).
///
/// Будильник оператор берёт у рантайма, значит и всякий момент, который он ставит в событие или
/// кладёт в сетку, обязан приходить оттуда же. Две линейки в одном операторе расходятся МОЛЧА:
/// под управляемым временем будильник отстреливается по виртуальной, а системных наносекунд между
/// двумя пробуждениями почти не проходит — узлов не наступает ни одного, тик не рождается вовсе, и
/// у потребителя это выглядит зависанием до внешнего таймаута, а не отказом. Под обычным рантаймом
/// эти часы и есть системные, так что цена закона — ноль.
fn now() -> Instant {
    time::Instant::now().into_std()
}

pin_project! {
    pub struct DetectStream<S, D, Sig> {
        #[pin]
        source: S,
        detector: Option<D>,
        buffer: VecDeque<Sig>,
        #[pin]
        tick: Interval,
        // НАЧАЛО СЕТКИ, ЕЁ ШАГ И ПОСЛЕДНИЙ УЖЕ УЧТЁННЫЙ МОМЕНТ — всё по часам рантайма.
        //
        // Пробуждение `tick` говорит ровно одно: «пора посмотреть». Какие узлы сетки НАСТУПИЛИ с
        // прошлого взгляда и как они пронумерованы, называет [`reflex_core::grid::nodes_between`]
        // на моменте КАЖДОГО узла. Считать номер от момента пробуждения значило бы под каждым
        // отдельным пробуждением получать номер ПОСЛЕДНЕГО наступившего узла, а пропущенные между
        // двумя пробуждениями — терять молча: три пробуждения подряд почти в одну точку дали бы
        // три одинаковых номера там, где сетка называет три РАЗНЫХ подряд идущих узла.
        //
        // НОМЕР УЗЛА СРАВНИМ ТОЛЬКО ВНУТРИ ОДНОГО ЭКЗЕМПЛЯРА: `began` снимается при постройке и
        // наружу не выходит, то есть у каждого потока своё начало отсчёта. Тот же номер при
        // переигровке даёт лишь сетка, чьё начало задано СНАРУЖИ; здесь сетка начинается там, где
        // начался поток, и номера двух потоков между собой не сравнимы.
        began: Instant,
        last: Instant,
        every: Duration,
    }
}

impl<S, D, Sig> DetectStream<S, D, Sig> {
    pub fn new(source: S, detector: D, tick_interval: Duration) -> Self {
        // НАЧАЛО СЕТКИ СНИМАЕТСЯ ДО ПОСТРОЙКИ ТАЙМЕРА: первый узел таймера приходится на момент
        // его создания, и `began`, снятый после, оказался бы ПОЗЖЕ первого узла — сетка начала бы
        // счёт с отрицательного расстояния.
        let began = now();
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

    /// # ЗАКОН (Ruling 14): `Pending` — ТОЛЬКО ПОСЛЕ ТОГО, КАК ОБА ИСТОЧНИКА ПРОБУЖДЕНИЯ ОПРОШЕНЫ
    /// ДО `Pending`.
    ///
    /// Таймер, вернувший `Ready`, не регистрирует будильник на следующий узел САМ СОБОЙ — это
    /// делает СЛЕДУЮЩИЙ вызов `poll_tick`, вернувший `Pending`. Опросить его один раз и уйти к
    /// источнику, не опросив снова, значит вернуть `Pending`, не попросив разбудить нас: поток
    /// засыпает, и будить его больше некому, кроме чужого таймера снаружи. Больнее всего это в
    /// тишине — там, ради чего тик и заведён.
    ///
    /// # ЗАКОН (Ruling 20): МОМЕНТ УЗЛА БЕРЁТСЯ С ЛИНЕЙКИ БУДИЛЬНИКА
    ///
    /// `poll_tick` отдаёт момент сработавшего узла по часам рантайма — сетка считается от него и
    /// от `began`, снятого теми же часами. Спросить момент у системных часов значило бы держать в
    /// одном операторе две линейки; чем это кончается, сказано у `now`.
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        // 1. Drain buffered signals first
        if let Some(signal) = this.buffer.pop_front() {
            return Poll::Ready(Some(signal));
        }

        // 2. Опросить тик ДО `Pending` — цикл, а не одиночный вызов (закон см. в докстроке метода).
        if let Some(mut detector) = this.detector.take() {
            let mut woke: Option<Instant> = None;
            while let Poll::Ready(fired) = this.tick.as_mut().poll_tick(cx) {
                woke = Some(fired.into_std());
            }
            if let Some(upto) = woke {
                // УЗЛЫ БЕРУТСЯ ПО ЗАКОНУ СЕТКИ НА ИХ СОБСТВЕННОМ МОМЕНТЕ, а не на моменте
                // пробуждения: пробуждение под дрейфом может опоздать на несколько шагов сразу, и
                // тогда `nodes_between` отдаёт их ВСЕ по порядку, а не один слипшийся номер.
                let nodes: Vec<Instant> =
                    reflex_core::grid::nodes_between(*this.began, *this.last, upto, *this.every)
                        .collect();
                for at in nodes {
                    let node = reflex_core::grid::due(*this.began, at, *this.every);
                    let (next_detector, signals, _notes) =
                        detector.step(DetectorEvent::Tick { node, at });
                    detector = next_detector;
                    for signal in signals {
                        this.buffer.push_back(signal);
                    }
                }
                *this.last = upto;
            }
            *this.detector = Some(detector);
            if let Some(signal) = this.buffer.pop_front() {
                return Poll::Ready(Some(signal));
            }
        }

        // 3. Poll source
        match this.source.as_mut().poll_next(cx) {
            Poll::Ready(Some(input)) => {
                if let Some(detector) = this.detector.take() {
                    let at = now();
                    let (new_detector, signals, _notes) =
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
