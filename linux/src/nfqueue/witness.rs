//! Реактивный byte-witness над NFQ-пайплайном (general-purpose: reflex-подложка, НЕ домен).
//! `WireHandler`-декоратор: шлёт КАЖДЫЙ пакет как сегмент в owned-актор, гоняющий per-flow
//! [`FlowTable`] (реактивный примитив reflex) + независимый тик-тред → эмитит АТРИБУТИРОВАННЫЙ
//! сигнал детектора через [`Tap`]. Заменяет hand-rolled тред-драйверы в потребителях (Rule:
//! примитив живёт в reflex, не переизобретается в домене).
//!
//! Rule 10 (owned state в driver-треде + канал, не `Arc<Mutex>`): `FlowTable` живёт в ЕДИНСТВЕННОМ
//! акторе; сегменты и тики сходятся туда каналом. Тик — НЕЗАВИСИМ от пакетов (отдельный тред):
//! простойный поток (нет пакетов) всё равно закрывает окно → детектор даёт сигнал (иначе «встал»
//! невидим). Часы на краю (Rule 1): `Instant::now()` стампится при отправке события. Прозрачен к
//! вердикту: делегирует внутреннему хендлеру, свидетеля лишь НАБЛЮДАЕТ.

use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use reflex_core::command::InjectablePacket;
use reflex_core::detector::Detector;
use reflex_core::flow_table::FlowTable;
use reflex_core::types::{Flow, TcpOptions, TcpSegment};
use reflex_core::Tap;

use super::pipeline::NfqVerdict;
use super::typed::{WireHandler, WirePacket};

enum WitnessEvent {
    Segment(TcpSegment, Instant),
    Tick(Instant),
}

/// Декоратор: наблюдает byte-witness per-flow над NFQ-потоком, делегирует технику `H`. Актор и
/// тикер спавнятся в [`new`](Self::new); `on` лишь шлёт сегмент (fire-and-forget) и делегирует.
pub struct FlowWitness<H> {
    inner: H,
    tx: mpsc::Sender<WitnessEvent>,
}

impl<H> FlowWitness<H> {
    /// `make_detector` строит per-flow детектор (напр. байт-здоровье с окном); `tick` — период
    /// тика (закрытие окон простойных потоков); `tap` — сток атрибутированных сигналов.
    pub fn new<D>(
        inner: H,
        make_detector: impl Fn(Flow) -> D + Send + 'static,
        tick: Duration,
        tap: Tap<(Flow, D::Signal)>,
    ) -> Self
    where
        D: Detector<Input = TcpSegment> + Send + 'static,
        D::Signal: Send + 'static,
    {
        let (tx, rx) = mpsc::channel::<WitnessEvent>();

        // Тик-тред: закрывает окна независимо от прихода пакетов.
        let tick_tx = tx.clone();
        thread::spawn(move || loop {
            thread::sleep(tick);
            if tick_tx.send(WitnessEvent::Tick(Instant::now())).is_err() {
                break; // актор ушёл
            }
        });

        // Актор: единоличный владелец `FlowTable` (Rule 10), сворачивает события, эмитит в `tap`.
        thread::spawn(move || {
            let mut table = FlowTable::new(make_detector);
            for ev in rx {
                match ev {
                    WitnessEvent::Segment(seg, at) => {
                        let flow = seg.flow.clone();
                        for sig in table.process(&seg, at) {
                            tap.emit((flow.clone(), sig));
                        }
                    }
                    WitnessEvent::Tick(at) => {
                        for attributed in table.tick_attributed(at) {
                            tap.emit(attributed);
                        }
                    }
                }
            }
        });

        Self { inner, tx }
    }
}

impl<H: WireHandler> WireHandler for FlowWitness<H> {
    fn on(&mut self, pkt: &WirePacket) -> (NfqVerdict, Vec<InjectablePacket>) {
        let seg = TcpSegment {
            flow: pkt.flow.clone(),
            seq: pkt.seq,
            ack: pkt.ack,
            flags: pkt.flags,
            window: 0,
            options: TcpOptions::default(),
            ttl: pkt.ttl,
            payload: pkt.payload.clone(),
        };
        let _ = self.tx.send(WitnessEvent::Segment(seg, Instant::now())); // часы на краю
        self.inner.on(pkt) // технику НЕ трогаем — лишь наблюдаем поток
    }
}
