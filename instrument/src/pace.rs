//! ТЕМП СЕРВИРОВКИ — сколько человек ждал ЗАПРОШЕННОГО.
//!
//! Переехал из другого крейта при сведении детекции в один дом.

use std::time::Duration;

/// СКОЛЬКО ЧЕЛОВЕК ЖДАЛ ЗАПРОШЕННОГО — с именем, а не голой длительностью.
///
/// Имя заведено затем, что адрес объявляет ЗНАЧЕНИЕ, а длительность сама по себе не говорит ни о
/// ком: «шесть секунд» есть число, пока не сказано, чего именно шесть секунд ждали.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Waited(pub Duration);

/// СКАЗАНО РАЗГОВОРУ: ожидание меряется внутри него — прибор не видит промежутков между
/// соединениями и прямо говорит об этом в паспорте.
impl reflex_core::word::Word for Waited {
    type Of = reflex_core::word::Conversation;
}

/// ПАСПОРТ ТЕМПА СЕРВИРОВКИ — проекция `model/law/Instrument.tla`.
///
/// Прибор о ЧЕЛОВЕКЕ: он меряет не «сколько байт», а «сколько человек ждал ЗАПРОШЕННОГО». Разница
/// не в оттенке: поток, отдавший мегабайт за две минуты, и поток, отдавший тот же мегабайт за две
/// секунды и замерший, по объёму неразличимы, а переживаются противоположно.
pub struct PaceInstrument;

impl PaceInstrument {
    fn read(&self, waited: &Duration, _now_ms: u64) -> Option<Waited> {
        match waited.is_zero() {
            true => None,
            false => Some(Waited(*waited)),
        }
    }
}

impl reflex_core::step::Step for PaceInstrument {
    /// НАБЛЮДЕНИЕ, которое подают прибору.
    type From = reflex_core::DetectorEvent<Duration>;

    /// ПОКАЗАНИЕ. Отсутствие показания сигналом не является: прибор высказывается, когда есть что
    /// сказать, и «ничего не случилось» не занимает места в ленте.
    type To = smallvec::SmallVec<[Waited; 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
        match event {
            reflex_core::DetectorEvent::Packet { input, .. } => {
                let reading = self.read(&input, 0);
                (self, reading.into_iter().collect())
            }
            reflex_core::DetectorEvent::Tick { .. } => (self, smallvec::SmallVec::new()),
            // Прибор мерит РАЗОБРАННЫЙ домен; непонятое им не является и молчит так же, как тик.
            reflex_core::DetectorEvent::Opaque { .. } => (self, smallvec::SmallVec::new()),
        }
    }
}

impl crate::Instrument for PaceInstrument {
    type Signal = Waited;

    const INSTRUMENT: &'static str = "pace";

    const SUBJECT: crate::Subject = crate::Subject::Person;

    /// УРОВЕНЬ: ожидание меряется между байтами и от протокола не зависит.
    const LAYER: crate::Layer = crate::Layer::Transport;
    /// ТРАНСПОРТЫ, а не «любой протокол»: ожидание меряется между байтами, и байты в этом смысле
    /// есть у TCP и UDP. На TLS или DNS «байт» значит уже другое — запись и сообщение.
    const PROTOCOLS: &'static [crate::Protocol] = &[crate::Protocol::Tcp, crate::Protocol::Udp];
    const RUNG: Option<crate::Rung> = None;

    /// ОКНО ТРАФИКА (`PACE_WINDOW` = 1500 мс). Для этого предмета законно: ожидание ЗАПРОШЕННОГО
    /// существует, только пока человек чего-то просит.
    const CADENCE: crate::Cadence = crate::Cadence::Foreign;

    /// ВЕЛИЧИНА: длительность складывается и сравнивается. Перехода не имеет — «ждал 6 с» после
    /// «ждал 6 с» есть новость, а не повтор.
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

    /// СМЕРТЬ: ожидание между соединениями стало наблюдаемым здесь же — тогда прибор перестаёт
    /// быть половиной ответа и `time_to_content` в сводке становится избыточным.
    const DEATH: &'static str =
        "ожидание МЕЖДУ соединениями видно этому прибору, а не только сводке";

    /// ПУБЛИЧНЫЕ ИМЕНА СОБЫТИЙ — реестр, снятый с типа: за границей процесса имя показания не
    /// сторожит компилятор, и `Debug` сменил бы метку молча (#321).
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
