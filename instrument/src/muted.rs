//! ПРИВЕТСТВИЕ ПРИНЯТО, ОТВЕТ ЗАГЛУШЁН — прибор SNI-II (`Distress::HelloMuted`).
//!
//! # Картина, которой он оплачен
//!
//! Стенд, 24.09.2026, узел кэша Google у Билайна (`rr4---sn-8ph2xajvh-hg8l.googlevideo.com`),
//! запись со стороны человека: рукопожатие за 2 мс, `ClientHello` ушёл ОДИН раз, цель его
//! подтвердила (`ack` на все 517 байт) — и не прислала ничего. Через 20 с клиент ушёл сам, повторы
//! его `FIN` цель тоже не подтвердила. Для человека — 20 с крутилки на ролике.
//!
//! Таксономия называет это SNI-II (Xue et al., IMC '22, §5.2): после триггерного приветствия
//! проходит ещё пять–восемь пакетов, затем симметричный дроп. Прибор-сосед (`HelloDropped`,
//! SNI-IV) такой разговор не видит по построению: приветствие подтверждено, клиенту повторять нечего.
//!
//! # Порог — время самой цели
//!
//! Живой сервер после подтверждения приветствия отвечает сразу: на той же записи у 14 здоровых
//! разговоров данные шли не позже 0,3 RTT рукопожатия (0,74 мс в худшем). Молчание дольше
//! [`RTT_TIMES`] её RTT — ставка с тридцатикратным запасом к замеру; снизу порог держит
//! минимальный RTO Linux ([`FLOOR`]): быстрее него судить значит судить сетку, а не цель.
//!
//! Середину разговора прибор не судит НИКОГДА: после первого байта цели он молчит навсегда. Этим он
//! и отличается от `NoBytes` — тот судил тишину разговора целиком и ошибался на долгих сессиях.

use std::time::{Duration, Instant};

use smallvec::{smallvec, SmallVec};

use crate::distress::Distress;
use crate::wire::{ResetBy, Seen, SeenTcp};

/// Во сколько RTT рукопожатия молчание после подтверждения становится заявлением пути.
pub const RTT_TIMES: u32 = 10;

/// Нижний предел порога — минимальный RTO Linux (`TCP_RTO_MIN`).
pub const FLOOR: Duration = Duration::from_millis(200);

/// Порог для цели с этим RTT рукопожатия.
pub fn horizon(rtt: Duration) -> Duration {
    (rtt * RTT_TIMES).max(FLOOR)
}

/// Прибор: приветствие подтверждено, ответа нет.
#[derive(Debug, Clone, Copy, Default)]
pub struct HelloMutedInstrument {
    /// Когда клиент постучал — от него меряется RTT.
    knocked: Option<Instant>,
    /// RTT рукопожатия этой цели.
    rtt: Option<Duration>,
    /// Клиент заговорил после рукопожатия.
    spoke: bool,
    /// Когда цель впервые подтвердила всё сказанное клиентом.
    acknowledged: Option<Instant>,
    /// Цель сказала своё — подозрение снято навсегда.
    answered: bool,
    /// Разговор кончен клиентом — судить больше некого.
    over: bool,
    /// Уже сказали.
    fired: bool,
    /// Буква спрятала наблюдения: ответ цели мог пропасть в дыре (§7).
    blinded: bool,
}

impl HelloMutedInstrument {
    pub fn new() -> HelloMutedInstrument {
        HelloMutedInstrument::default()
    }

    /// Тик: вышел ли порог молчания после подтверждения.
    fn ticked(self, at: Instant) -> (HelloMutedInstrument, SmallVec<[Distress; 2]>) {
        let silent = !(self.answered || self.over || self.fired || self.blinded);
        let due = self
            .acknowledged
            .filter(|_open| silent)
            .zip(self.rtt)
            .filter(|(acknowledged, rtt)| {
                at.saturating_duration_since(*acknowledged) >= horizon(*rtt)
            });
        match due {
            Some((acknowledged, rtt)) => (
                HelloMutedInstrument {
                    fired: true,
                    ..self
                },
                smallvec![Distress::HelloMuted {
                    rtt_ms: rtt.as_millis() as u32,
                    after_ms: at.saturating_duration_since(acknowledged).as_millis() as u32,
                }],
            ),
            None => (self, SmallVec::new()),
        }
    }
}

impl reflex_core::mealy::Mealy for HelloMutedInstrument {
    /// Словарь соединения: рукопожатие и подтверждение — улики TCP.
    type In = reflex_core::DetectorEvent<SeenTcp>;
    type Out = SmallVec<[Distress; 2]>;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        // Прибор судит по ОТСУТСТВИЮ ответа цели, а дыра могла его съесть. Закон буквы, не прибора.
        if event.hides_observation() {
            return (
                HelloMutedInstrument {
                    blinded: true,
                    ..self
                },
                SmallVec::new(),
                (),
            );
        }
        let (state, said) = match event {
            reflex_core::DetectorEvent::Packet { input, at } => {
                let next = match input {
                    SeenTcp::Syn => HelloMutedInstrument {
                        knocked: self.knocked.or(Some(at)),
                        ..self
                    },
                    SeenTcp::Handshaken => HelloMutedInstrument {
                        rtt: self.rtt.or(self
                            .knocked
                            .map(|knocked| at.saturating_duration_since(knocked))),
                        ..self
                    },
                    // Клиент заговорил — у TLS это приветствие с именем.
                    SeenTcp::Anywhere(
                        Seen::Sent { .. }
                        | Seen::Payload {
                            from_client: true, ..
                        },
                    ) => HelloMutedInstrument {
                        spoke: true,
                        ..self
                    },
                    // Цель подтвердила всё сказанное — отсюда меряется молчание.
                    SeenTcp::Acknowledged => HelloMutedInstrument {
                        acknowledged: self.acknowledged.or(self.spoke.then_some(at)),
                        ..self
                    },
                    // ЦЕЛЬ СКАЗАЛА СВОЁ: данные, её повтор, прощание, сброс с её стороны, просьба
                    // подождать. Середину разговора прибор не судит.
                    SeenTcp::Anywhere(
                        Seen::Received { .. }
                        | Seen::Restated { .. }
                        | Seen::Payload {
                            from_client: false, ..
                        }
                        | Seen::Closed {
                            by_client: false, ..
                        },
                    )
                    | SeenTcp::Rst {
                        by: ResetBy::TargetSide,
                    }
                    | SeenTcp::AskedToWait { by_client: false } => HelloMutedInstrument {
                        answered: true,
                        ..self
                    },
                    // Разговор кончил клиент или мы — судить больше некого.
                    SeenTcp::Anywhere(Seen::Closed {
                        by_client: true, ..
                    })
                    | SeenTcp::Rst {
                        by: ResetBy::Person | ResetBy::Ourselves,
                    } => HelloMutedInstrument { over: true, ..self },
                    // Повтор клиента — предмет соседа (SNI-IV); окно клиента — не о цели.
                    SeenTcp::Anywhere(Seen::Resent { .. })
                    | SeenTcp::AskedToWait { by_client: true } => self,
                };
                (next, SmallVec::new())
            }
            // Молчание называет тик: пакета, на котором сказать, у SNI-II нет по построению.
            reflex_core::DetectorEvent::Tick { at, .. } => self.ticked(at),
            reflex_core::DetectorEvent::Opaque { .. } | reflex_core::DetectorEvent::Torn { .. } => {
                (self, SmallVec::new())
            }
        };
        (state, said, ())
    }
}

impl crate::Instrument for HelloMutedInstrument {
    type Signal = Distress;

    const INSTRUMENT: &'static str = "hello_muted";

    /// О мире: путь глушит ответ — свойство пути, а не наше.
    const SUBJECT: crate::Subject = crate::Subject::World;

    /// Транспорт: рукопожатие и подтверждение — улики TCP.
    const LAYER: crate::Layer = crate::Layer::Transport;

    /// Только TCP: подтверждение есть только у соединения.
    const PROTOCOLS: &'static [crate::Protocol] = &[crate::Protocol::Tcp];

    /// Раньше ответа: прибор о том, ответила ли цель на приветствие вообще.
    const RUNG: Option<crate::Rung> = None;

    /// Чужой темп: порог — RTT самой цели; тик лишь приносит время.
    const CADENCE: crate::Cadence = crate::Cadence::Foreign;

    /// Событие: молчание дольше порога уже случилось.
    const SHAPE: crate::Shape = crate::Shape::Event;

    /// Прибор смотрел: цель ответила, клиент ушёл раньше порога либо подтверждения не было.
    const SILENCE: Option<crate::Silence> = Some(crate::Silence::Nothing);

    const LIES: &'static [&'static str] = &[
        "НЕ ЗНАЕТ ПРИЧИНЫ. Буква называет наблюдаемое — приветствие подтверждено, ответа нет; что \
         триггер — ИМЯ (SNI-II), устанавливает только контроль той же дорогой с другим именем. \
         Сервер, подтвердивший приветствие и зависший, даст ту же картину.",
        "ПОРОГ В ДЕСЯТЬ RTT — СТАВКА. Замер один (стенд 24.09.2026, 14 здоровых разговоров, худший \
         0,3 RTT) и на одном вантаже; сервер, считающий ответ дольше десяти своих RTT (TLS за \
         прокси с далёким источником), будет назван заглушённым.",
        "RTT ДОЛЬШЕ СЕКУНДЫ НЕ СУДИТСЯ ЧЕСТНО: порог тогда длиннее срока эвикта молчащего разговора \
         (`MIN_IDLE` движка, 10 с), и машина может уйти раньше слова.",
        "БЕЗ СТУКА НЕТ RTT, И ПРИБОР МОЛЧИТ: разговор, начало которого наблюдатель не видел, этим \
         прибором не судится.",
    ];

    const ORACLES: &'static [&'static str] = &["tests/hello_muted.rs"];

    const DEATH: &'static str =
        "цель сказала своё, клиент ушёл раньше порога, либо подтверждения приветствия не было";

    const EVENTS: &'static [&'static str] = &["hello_muted"];

    fn name(signal: &Self::Signal) -> &'static str {
        signal.name()
    }

    fn alarming(signal: &Self::Signal) -> bool {
        signal.alarming()
    }

    fn detail(signal: &Self::Signal) -> String {
        signal.detail()
    }
}
