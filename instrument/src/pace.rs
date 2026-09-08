//! Темп сервировки — сколько человек ждал ЗАПРОШЕННОГО.

use std::time::Duration;

/// Сколько человек ждал запрошенного — с именем, не голой длительностью: адрес объявляет значение,
/// «шесть секунд» молчит, пока не сказано, чего именно.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Waited(pub Duration);

/// Сказано разговору: ожидание меряется внутри него (промежутков между соединениями не видит).
impl reflex_core::word::Word for Waited {
    type Of = reflex_core::word::Conversation;
}

/// Прибор о человеке: меряет не «сколько байт», а «сколько ждал». Поток, отдавший мегабайт за две
/// минуты, и за две секунды с замиранием — по объёму неразличимы, переживаются противоположно.
pub struct PaceInstrument;

impl PaceInstrument {
    fn read(&self, waited: &Duration, _now_ms: u64) -> Option<Waited> {
        match waited.is_zero() {
            true => None,
            false => Some(Waited(*waited)),
        }
    }
}

impl reflex_core::mealy::Mealy for PaceInstrument {
    type In = reflex_core::DetectorEvent<Duration>;
    /// Слово. Молчание сигналом не является.
    type Out = smallvec::SmallVec<[Waited; 2]>;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        match event {
            reflex_core::DetectorEvent::Packet { input, .. } => {
                let reading = self.read(&input, 0);
                (self, reading.into_iter().collect(), ())
            }
            reflex_core::DetectorEvent::Tick { .. } | reflex_core::DetectorEvent::Opaque { .. } => {
                (self, smallvec::SmallVec::new(), ())
            }
        }
    }
}

impl crate::Instrument for PaceInstrument {
    type Signal = Waited;

    const INSTRUMENT: &'static str = "pace";

    const SUBJECT: crate::Subject = crate::Subject::Person;

    const LAYER: crate::Layer = crate::Layer::Transport;
    const PROTOCOLS: &'static [crate::Protocol] = &[crate::Protocol::Tcp, crate::Protocol::Udp];
    const RUNG: Option<crate::Rung> = None;

    /// Окно трафика (1500 мс): ожидание запрошенного существует, пока человек чего-то просит.
    const CADENCE: crate::Cadence = crate::Cadence::Foreign;

    /// Величина: длительность складывается и сравнивается; перехода нет — «ждал 6 с» есть новость.
    const SHAPE: crate::Shape = crate::Shape::Quantity;

    const SILENCE: Option<crate::Silence> = Some(crate::Silence::Nothing);

    const LIES: &'static [&'static str] = &[
        "ТЕРПЕНИЕ РАЗНОЕ ДЛЯ ОТВЕЧАВШЕГО И НЕ ОТВЕЧАВШЕГО, и это лечение прошлой беды, а не \
         оттенок: `redirector.googlevideo.com` отдал 5404 байта (адреса узлов), после чего жил в \
         HTTP/2 со служебными фреймами вверх — и общий порог в шесть секунд оборвал ЖИВОГО \
         переговорщика. Прибор помнит, отвечал ли сервер; забудет — вернётся та же беда.",
        "ОЖИДАНИЕ МЕЖДУ СОЕДИНЕНИЯМИ ЭТОМУ ПРИБОРУ НЕВИДИМО. Он живёт внутри одного разговора, а \
         человек ждёт и в промежутках, где нашего трафика нет вовсе. Ровно поэтому рядом заведён \
         `time_to_content` в сводке эпизода: 4,2 с внутри соединений против 62 с у человека.",
    ];

    const ORACLES: &'static [&'static str] =
        &["fatflow(1.2.3.4,16,reply,drop)", "throttle(250kbit,6%)"];

    const DEATH: &'static str =
        "ожидание МЕЖДУ соединениями видно этому прибору, а не только сводке";

    const EVENTS: &'static [&'static str] = &["idle"];

    fn name(signal: &Self::Signal) -> &'static str {
        let _ = signal;
        "idle"
    }

    fn alarming(signal: &Self::Signal) -> bool {
        let _ = signal;
        true
    }
}
