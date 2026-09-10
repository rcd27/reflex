//! Повтор без ответа — самая ранняя улика молчаливого дропа, единственный прибор парка без часов.
//! Порог не наш: клиентское ядро уже отмерило RTO под RTT именно этого пути (соседи ждут нашим
//! терпением — константой). Замер 04.09: первый повтор `ClientHello` ~360 мс, наше терпение
//! 1500 мс, человек без нас ждёт 2,3–12 с. Автора не называет — это работа расследования; обычная
//! потеря даёт тот же повтор.

use crate::distress::Distress;
use crate::wire::Seen;
use std::time::Instant;

/// Прибор повтора без ответа. Три величины: когда попросили впервые (величина показания), сколько
/// отдала цель (ненуль снимает подозрение), жаловались ли (второй раз о том же — молчим).
#[derive(Debug, Clone, Copy)]
pub struct RetransmitInstrument {
    /// Когда попросили впервые. `None` — просьбы не видели.
    first_asked: Option<Instant>,
    /// Байт от цели вниз. Ненуль снимает подозрение навсегда.
    down: u32,
    fired: bool,
}

impl Default for RetransmitInstrument {
    fn default() -> Self {
        Self::new()
    }
}

impl RetransmitInstrument {
    pub fn new() -> Self {
        Self {
            first_asked: None,
            down: 0,
            fired: false,
        }
    }
}

impl reflex_core::mealy::Mealy for RetransmitInstrument {
    type In = reflex_core::DetectorEvent<Seen>;
    type Out = smallvec::SmallVec<[Distress; 2]>;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        let (state, signals) = match event {
            reflex_core::DetectorEvent::Packet { input, at } => match input {
                // Просьба открывает отсчёт, повторная не сдвигает: величина — ожидание человека с
                // первой отправки.
                Seen::Sent { .. } => (
                    Self {
                        first_asked: self.first_asked.or(Some(at)),
                        ..self
                    },
                    smallvec::SmallVec::new(),
                ),
                // Голова клиента — тоже просьба: `ClientHello` первым дропается на вантаже.
                Seen::Payload { head, from_client } => match from_client {
                    true => (
                        Self {
                            first_asked: self.first_asked.or(Some(at)),
                            ..self
                        },
                        smallvec::SmallVec::new(),
                    ),
                    false => (
                        Self {
                            down: self.down + head.len() as u32,
                            ..self
                        },
                        smallvec::SmallVec::new(),
                    ),
                },
                Seen::Received { count } => (
                    Self {
                        down: self.down + count,
                        ..self
                    },
                    smallvec::SmallVec::new(),
                ),
                Seen::Resent { .. } => match (self.fired, self.down, self.first_asked) {
                    // Предмет: повторили, а вниз ничего.
                    (false, 0, Some(asked)) => (
                        Self {
                            fired: true,
                            ..self
                        },
                        smallvec::smallvec![Distress::Retransmit {
                            after_ms: at.saturating_duration_since(asked).as_millis() as u32,
                        }],
                    ),
                    // Просьбы не видели (поток с середины) — величины нет; свою слепоту за факт не
                    // выдаём.
                    (false, 0, None) => (self, smallvec::SmallVec::new()),
                    // Цель отдавала байты: повтор — обычная сетевая потеря.
                    (false, 1.., _seen) => (self, smallvec::SmallVec::new()),
                    // Уже сообщали: ретрансмиссий 5–7, следствие одно.
                    (true, _down, _seen) => (self, smallvec::SmallVec::new()),
                },
                Seen::Closed { .. } => (self, smallvec::SmallVec::new()),
            },
            // Часов нет: порог даёт RTO клиентского ядра, не наш тик. Дыра несёт тот же риск для
            // `down`, что и непонятое: обе прячут байты цели от счёта, и прибор УЖЕ читает `down==0`
            // как «цель молчала», не различая честный ноль от недосчитанного (риск назван в `LIES`
            // как «подозрение, не приговор»). Заводить для дыры отдельный запрет, которого нет для
            // равной по силе слепоты `Opaque`, значило бы лечить одно незнание дважды разными
            // законами — вместо одного `LIES` завести два разных источника недосчёта.
            reflex_core::DetectorEvent::Tick { .. }
            | reflex_core::DetectorEvent::Opaque { .. }
            | reflex_core::DetectorEvent::Torn { .. } => (self, smallvec::SmallVec::new()),
        };
        (state, signals, ())
    }
}

impl crate::Instrument for RetransmitInstrument {
    type Signal = Distress;

    const INSTRUMENT: &'static str = "retransmit";

    /// О мире: цель не отвечает на просьбу — свойство пути.
    const SUBJECT: crate::Subject = crate::Subject::World;

    /// Транспорт: повтор опознаётся номером последовательности TCP.
    const LAYER: crate::Layer = crate::Layer::Transport;

    /// Только TCP: у QUIC повтора номера нет (RFC 9000) — потерянное едет с новым номером.
    const PROTOCOLS: &'static [crate::Protocol] = &[crate::Protocol::Tcp];

    /// Отвечали ли — прибор отвечает раньше всех в парке.
    const RUNG: Option<crate::Rung> = Some(crate::Rung::Answered);

    /// Чужой темп — предмет, не компромисс: порог RTO клиентского ядра. Свои часы превратили бы
    /// его в третью копию прибора тишины.
    const CADENCE: crate::Cadence = crate::Cadence::Foreign;

    /// Событие: повтор уже случился.
    const SHAPE: crate::Shape = crate::Shape::Event;

    /// Прибор смотрел: повтора не было либо цель отвечала. (`Blind` — поток с середины, в `LIES`.)
    const SILENCE: Option<crate::Silence> = Some(crate::Silence::Nothing);

    const LIES: &'static [&'static str] = &[
        "НЕ РАЗЛИЧАЕТ БЛОКИРОВКУ ОТ ОБЫЧНОЙ ПОТЕРИ ПАКЕТА, и это главный его режим лжи. \
         Перегруженный канал даёт ровно тот же повтор при нулевом ответе. Отсюда следует, что \
         показание есть ПОДОЗРЕНИЕ, а не приговор: действие по нему (обрыв) обязано иметь \
         собственное предусловие, а не опираться на эту улику одну.",
        "ПОВТОР ЛЮБОГО СЕГМЕНТА, А НЕ ТОЛЬКО ПРИВЕТСТВИЯ. На нашем вантаже дропается `ClientHello` \
         (замер 04.09.2026, 9 целей), но прибор не проверяет, ЧТО повторили: повтор середины \
         запроса при нулевом ответе он назовёт тем же словом.",
        "ПОТОК, ПОДХВАЧЕННЫЙ С СЕРЕДИНЫ, ОСТАЁТСЯ НЕВИДИМЫМ. Просьбы прибор не видел, величины у \
         показания нет, и он молчит — это `Blind`, а не `Nothing`, и лечится оно другим прибором, \
         а не понижением порога здесь.",
        "ЧУЖИЕ ЧАСЫ НЕ НАБЛЮДАЕМЫ. Величина показания есть ожидание человека, но САМ RTO (когда \
         клиентское ядро решило повторить) нам не виден: два клиента с разной настройкой дадут \
         разные величины на одной и той же беде.",
    ];

    const ORACLES: &'static [&'static str] = &["sni_drop(rutracker.org)", "pass"];

    const DEATH: &'static str =
        "заведён различитель «дроп цензора против потери в канале»; подозрение стало приговором";

    const EVENTS: &'static [&'static str] = &["retransmit"];

    // Имя, тревожность и величина — свойства буквы; прибор их только передаёт.
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

    fn at(ms: u64) -> Instant {
        START.with(|start| *start + Duration::from_millis(ms))
    }

    thread_local! {
        static START: Instant = Instant::now();
    }

    fn packet(seen: Seen, ms: u64) -> DetectorEvent<Seen> {
        DetectorEvent::Packet {
            input: seen,
            at: at(ms),
        }
    }

    fn hello() -> Seen {
        Seen::Payload {
            head: b"\x16\x03\x01hello".to_vec(),
            from_client: true,
        }
    }

    /// Предмет: попросил, цель не отдала байта, клиент повторил.
    #[test]
    fn a_repeat_with_nothing_back_is_the_suspicion() {
        let instrument = RetransmitInstrument::new();
        let (instrument, quiet, _) = instrument.step(packet(hello(), 0));
        assert!(quiet.is_empty(), "первая просьба бедой не является");

        let (_instrument, said, _) = instrument.step(packet(Seen::Resent { count: 517 }, 360));

        assert_eq!(
            said.as_slice(),
            [Distress::Retransmit { after_ms: 360 }],
            "повтор при нулевом ответе обязан быть уликой, и величина — ожидание человека"
        );
    }

    /// Вторая половина пары: тот же повтор, но цель ответила — не беда.
    #[test]
    fn a_repeat_after_the_target_answered_is_not_trouble() {
        let instrument = RetransmitInstrument::new();
        let (instrument, _, _) = instrument.step(packet(hello(), 0));
        let (instrument, _, _) = instrument.step(packet(Seen::Received { count: 1400 }, 120));

        let (_instrument, said, _) = instrument.step(packet(Seen::Resent { count: 517 }, 480));

        assert!(
            said.is_empty(),
            "цель отдала байты — повтор есть обычная потеря, а не блокировка"
        );
    }

    /// Жалуемся один раз: ретрансмиссий 5–7, следствие одно.
    #[test]
    fn only_the_first_repeat_speaks() {
        let instrument = RetransmitInstrument::new();
        let (instrument, _, _) = instrument.step(packet(hello(), 0));
        let (instrument, first, _) = instrument.step(packet(Seen::Resent { count: 517 }, 360));
        let (_instrument, second, _) = instrument.step(packet(Seen::Resent { count: 517 }, 1080));

        assert_eq!(first.len(), 1, "первый повтор говорит");
        assert!(second.is_empty(), "второй повтор о том же молчит");
    }

    /// Часов у прибора нет: тик не порождает показания.
    #[test]
    fn a_tick_says_nothing() {
        let instrument = RetransmitInstrument::new();
        let (instrument, _, _) = instrument.step(packet(hello(), 0));

        let (_instrument, said, _) = instrument.step(DetectorEvent::Tick {
            node: 9_000,
            at: at(9_000),
        });

        assert!(said.is_empty(), "прибор с чужим темпом в тишине нем");
    }
}
