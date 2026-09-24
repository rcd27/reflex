//! ПРИВЕТСТВИЕ НЕ ПОДТВЕРЖДЕНО НИ РАЗУ — прибор SNI-IV (`Distress::HelloDropped`).
//!
//! # Картина, которой он оплачен
//!
//! Линия стенда, 24.09.2026, `rutracker.org`, запись в пространстве имён человека без продукта:
//! рукопожатие состоялось, `ClientHello` с именем ушёл — и цель не ответила НИЧЕМ, даже
//! подтверждением. Клиент повторил его через 0,30 · 0,59 · 1,22 · 2,43 · 4,80 · 9,67 с и сдался.
//! Контроль той же дорогой (`ya.ru`, `one.one.one.one` — тот же CDN, что у `rutracker.org`):
//! приветствие подтверждено через 36–37 мс, повторов нет.
//!
//! Батарея молчала о ЭТОЙ болезни законно: повтор клиента — подозрение (обычная потеря даёт то
//! же), `NoBytes` — о данных, а не о подтверждении (молчащий сервер приветствие ПОДТВЕРЖДАЕТ),
//! `Swallowed` требует живой цели.
//!
//! # Оракул подтверждения — ядро клиента
//!
//! Голое подтверждение цели буквы в алфавите провода не имеет: цель видна рукопожатием, данными,
//! своим повтором, прощанием и сбросом. Но TCP клиента повторяет сегмент РОВНО тогда, когда на
//! него не пришло подтверждение. Значит, повтор клиента при полной тишине цели после рукопожатия —
//! и есть свидетельство «приветствие не подтверждено», данное стороной, которая это знает точно.
//!
//! # Порог — ряд, и любой признак жизни цели снимает подозрение навсегда
//!
//! Один повтор бывает от обычной потери; за ним приходит подтверждение, данные — и цель жива. Три
//! потери одного сегмента подряд при потере в 1 % — порядка 10⁻⁶ разговоров. Ставка до замера на
//! канарейке: там счёт срабатываний покажет, держит ли порог плохой Wi-Fi человека.

use std::time::Instant;

use smallvec::{smallvec, SmallVec};

use crate::distress::Distress;
use crate::wire::{ResetBy, Seen, SeenTcp};

/// Сколько повторов подряд при тишине цели считаем заявлением пути. Третий приходит через ~1,2 с
/// после приветствия (замер выше).
const ENOUGH: u32 = 3;

/// Прибор: рукопожатие было, приветствие не подтверждено ни разу.
#[derive(Debug, Clone, Copy, Default)]
pub struct HelloDroppedInstrument {
    /// Цель ответила на стук. Без рукопожатия болезнь другая — `Blackhole`.
    handshaken: bool,
    /// Когда клиент впервые заговорил после рукопожатия.
    spoke: Option<Instant>,
    /// Повторов клиента подряд при тишине цели.
    retries: u32,
    /// Цель подала признак жизни после приветствия — оно дошло, подозрение снято навсегда.
    alive: bool,
    /// Уже сказали.
    fired: bool,
    /// Буква спрятала наблюдения: признак жизни цели мог пропасть в дыре, и её молчание перестало
    /// быть свидетельством (§7).
    blinded: bool,
}

impl HelloDroppedInstrument {
    pub fn new() -> HelloDroppedInstrument {
        HelloDroppedInstrument::default()
    }

    /// Повтор клиента: при тишине цели счёт растёт, на пороге — слово, один раз.
    fn resent(self, at: Instant) -> (HelloDroppedInstrument, SmallVec<[Distress; 2]>) {
        let Some(spoke) = self
            .spoke
            .filter(|_spoke| self.handshaken && !self.alive && !self.fired && !self.blinded)
        else {
            return (self, SmallVec::new());
        };
        let retries = self.retries.saturating_add(1);
        match retries >= ENOUGH {
            false => (HelloDroppedInstrument { retries, ..self }, SmallVec::new()),
            true => (
                HelloDroppedInstrument {
                    retries,
                    fired: true,
                    ..self
                },
                smallvec![Distress::HelloDropped {
                    retries,
                    after_ms: at.saturating_duration_since(spoke).as_millis() as u32,
                }],
            ),
        }
    }
}

impl reflex_core::mealy::Mealy for HelloDroppedInstrument {
    /// Словарь соединения: рукопожатие и автор сброса — улики TCP.
    type In = reflex_core::DetectorEvent<SeenTcp>;
    type Out = SmallVec<[Distress; 2]>;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        // Прибор судит по ОТСУТСТВИЮ ответа цели, а дыра могла его съесть. Закон буквы, не прибора.
        if event.hides_observation() {
            return (
                HelloDroppedInstrument {
                    blinded: true,
                    ..self
                },
                SmallVec::new(),
                (),
            );
        }
        let (state, said) = match event {
            reflex_core::DetectorEvent::Packet { input, at } => match input {
                SeenTcp::Handshaken => (
                    HelloDroppedInstrument {
                        handshaken: true,
                        ..self
                    },
                    SmallVec::new(),
                ),
                // Первые данные клиента после рукопожатия — отсюда меряем. Первые байты потока приходят
                // `Payload` (по ним узнаётся протокол), а не `Sent`: на записи прибор без этой ветки
                // молчал — отсчёт не начинался вовсе.
                SeenTcp::Anywhere(
                    Seen::Sent { .. }
                    | Seen::Payload {
                        from_client: true, ..
                    },
                ) => (
                    HelloDroppedInstrument {
                        spoke: self.spoke.or(Some(at).filter(|_at| self.handshaken)),
                        ..self
                    },
                    SmallVec::new(),
                ),
                SeenTcp::Anywhere(Seen::Resent { .. }) => self.resent(at),
                // ПРИЗНАК ЖИЗНИ ЦЕЛИ: данные, её повтор, её прощание, сброс с её стороны. Приветствие
                // дошло — что было дальше, решают другие приборы.
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
                | SeenTcp::AskedToWait { by_client: false }
                // Приветствие подтверждено — это не SNI-IV; молчание после подтверждения судит
                // сосед (`muted::HelloMutedInstrument`, SNI-II).
                | SeenTcp::Acknowledged => (
                    HelloDroppedInstrument {
                        alive: true,
                        ..self
                    },
                    SmallVec::new(),
                ),
                // Стук, уход и сброс клиента, наш обрыв, первые байты — о подтверждении не говорят.
                SeenTcp::Syn
                | SeenTcp::Rst {
                    by: ResetBy::Person | ResetBy::Ourselves,
                }
                | SeenTcp::AskedToWait { by_client: true }
                | SeenTcp::Anywhere(Seen::Closed {
                    by_client: true, ..
                }) => (self, SmallVec::new()),
            },
            // Порог даёт RTO клиентского ядра, не наш тик.
            reflex_core::DetectorEvent::Tick { .. }
            | reflex_core::DetectorEvent::Opaque { .. }
            | reflex_core::DetectorEvent::Torn { .. } => (self, SmallVec::new()),
        };
        (state, said, ())
    }
}

impl crate::Instrument for HelloDroppedInstrument {
    type Signal = Distress;

    const INSTRUMENT: &'static str = "hello_dropped";

    /// О мире: путь роняет приветствие — свойство пути, а не наше.
    const SUBJECT: crate::Subject = crate::Subject::World;

    /// Транспорт: рукопожатие и повтор сегмента — улики TCP.
    const LAYER: crate::Layer = crate::Layer::Transport;

    /// Только TCP: подтверждение и повтор с тем же номером есть только у соединения.
    const PROTOCOLS: &'static [crate::Protocol] = &[crate::Protocol::Tcp];

    /// Раньше ответа: прибор о том, получила ли цель первые данные вообще.
    const RUNG: Option<crate::Rung> = None;

    /// Чужой темп: порог — RTO ядра клиента.
    const CADENCE: crate::Cadence = crate::Cadence::Foreign;

    /// Событие: ряд повторов уже случился.
    const SHAPE: crate::Shape = crate::Shape::Event;

    /// Прибор смотрел: цель подала признак жизни либо повторов не набралось.
    const SILENCE: Option<crate::Silence> = Some(crate::Silence::Nothing);

    const LIES: &'static [&'static str] = &[
        "НЕ ЗНАЕТ ПРИЧИНЫ. Буква называет наблюдаемое — приветствие не подтверждено; что триггер — \
         ИМЯ (SNI-IV), устанавливает только контроль той же дорогой с другим именем. Мёртвый после \
         рукопожатия сервер даст ту же картину.",
        "ПОРОГ В ТРИ ПОВТОРА — СТАВКА. Замер один (линия стенда, 24.09.2026) и на хорошей линии; \
         плохой Wi-Fi человека теряет больше, и держит ли порог там — покажет счёт на канарейке.",
        "ЦЕЛЬ, ПОДТВЕРДИВШАЯ ПРИВЕТСТВИЕ И ЗАМОЛЧАВШАЯ, ПРИБОРОМ ЗАКОННО НЕ НАЗВАНА: повторов она \
         не вызывает, а подтверждение (`SeenTcp::Acknowledged`) снимает подозрение. Это SNI-II, и \
         его называет сосед — `muted::HelloMutedInstrument`.",
    ];

    const ORACLES: &'static [&'static str] = &[
        "tests/fixtures/hello-dropped-rutracker.pcap",
        "tests/fixtures/hello-answered-ya.pcap",
        "tests/fixtures/hello-answered-cloudflare.pcap",
    ];

    const DEATH: &'static str =
        "цель подала признак жизни после приветствия, либо разговор кончился без ряда повторов";

    const EVENTS: &'static [&'static str] = &["hello_dropped"];

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

#[cfg(test)]
mod tests {
    use super::*;
    use reflex_core::mealy::Mealy;
    use reflex_core::DetectorEvent;
    use std::time::Duration;

    fn run(script: &[(SeenTcp, u64)]) -> Vec<Distress> {
        let start = Instant::now();
        script
            .iter()
            .fold(
                (HelloDroppedInstrument::new(), Vec::new()),
                |(state, said), (seen, ms)| {
                    let (stepped, signals, ()) = state.step(DetectorEvent::Packet {
                        input: seen.clone(),
                        at: start + Duration::from_millis(*ms),
                    });
                    (stepped, said.into_iter().chain(signals).collect())
                },
            )
            .1
    }

    /// Приветствие — `Payload` клиента: так первые байты потока приходят на записанном проводе.
    /// Первая редакция кормила прибор `Sent`, буквой, которой здесь в жизни нет, — и была зелена,
    /// пока прибор молчал на записи.
    fn hello() -> SeenTcp {
        SeenTcp::Anywhere(Seen::Payload {
            head: vec![0x16, 0x03, 0x01],
            from_client: true,
        })
    }

    fn again() -> SeenTcp {
        SeenTcp::Anywhere(Seen::Resent {
            count: 517,
            from: 1,
        })
    }

    /// Картина записи: рукопожатие, приветствие, ряд повторов при тишине цели — сказано на третьем.
    #[test]
    fn a_run_of_repeats_after_a_handshake_and_a_silent_target_is_named() {
        let said = run(&[
            (SeenTcp::Handshaken, 0),
            (hello(), 145),
            (again(), 442),
            (again(), 738),
            (again(), 1363),
            (again(), 2578),
        ]);
        assert_eq!(
            said,
            vec![Distress::HelloDropped {
                retries: 3,
                after_ms: 1218
            }],
            "один раз, на третьем повторе, от первой отправки"
        );
    }

    /// Обычная потеря: один повтор, за ним данные цели — жива, подозрение снято навсегда.
    #[test]
    fn a_lost_segment_answered_after_a_repeat_is_not_named() {
        let said = run(&[
            (SeenTcp::Handshaken, 0),
            (hello(), 100),
            (again(), 400),
            (SeenTcp::Anywhere(Seen::Received { count: 2416 }), 450),
            (again(), 900),
            (again(), 1500),
            (again(), 2700),
        ]);
        assert_eq!(said, Vec::new(), "цель ответила — приветствие дошло");
    }

    /// Без рукопожатия это другая болезнь — `Blackhole`, и этот прибор о ней молчит.
    #[test]
    fn without_a_handshake_it_is_not_this_trouble() {
        let said = run(&[
            (hello(), 0),
            (again(), 300),
            (again(), 600),
            (again(), 1200),
        ]);
        assert_eq!(said, Vec::new());
    }

    /// Дыра могла съесть ответ цели: молчание перестало быть свидетельством.
    #[test]
    fn a_hiding_letter_silences_the_instrument() {
        let start = Instant::now();
        let (state, _, ()) = HelloDroppedInstrument::new().step(DetectorEvent::Packet {
            input: SeenTcp::Handshaken,
            at: start,
        });
        let (state, _, ()) = state.step(DetectorEvent::Packet {
            input: hello(),
            at: start,
        });
        let (state, _, ()) = state.step(DetectorEvent::Torn { at: start });
        let said: Vec<Distress> = (1..=4)
            .fold((state, Vec::new()), |(state, said), nth| {
                let (state, signals, ()) = state.step(DetectorEvent::Packet {
                    input: again(),
                    at: start + Duration::from_millis(300 * nth),
                });
                (state, said.into_iter().chain(signals).collect())
            })
            .1;
        assert_eq!(said, Vec::new(), "через дыру не обвиняем");
    }
}
