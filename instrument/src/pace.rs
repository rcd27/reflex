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
            // Состояния у прибора НЕТ (`PhantomData`): показание есть функция одной буквы, и от
            // полноты входа не зависит вовсе. Прячущей букве тут нечего исказить — тождество
            // доказано ТИПОМ, а не рассуждением (§7, Д7).
            reflex_core::DetectorEvent::Tick { .. }
            | reflex_core::DetectorEvent::Opaque { .. }
            | reflex_core::DetectorEvent::Torn { .. } => (self, smallvec::SmallVec::new(), ()),
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
        "ПОРОГА ТЕРПЕНИЯ ЗДЕСЬ НЕТ, И ЭТО ВАЖНЕЕ, ЧЕМ КАЖЕТСЯ. Прибор говорит ВЕЛИЧИНУ ожидания и \
         не помнит ничего — состояния у него ноль. Прошлая беда, за которую заплачено: \
         `redirector.googlevideo.com` отдал 5404 байта (адреса узлов), после чего жил в HTTP/2 со \
         служебными фреймами вверх — и общий порог в шесть секунд оборвал ЖИВОГО переговорщика. \
         Вывод сделан ровно противоположный тому, что стоял здесь прежде: порог и память об \
         ответе — НЕ ДЕЛО ПРИБОРА, они у того, кто слушает. Докблок обещал память, которой в \
         машине нет; обещание снято прогоном (`tests`), а не правкой слов.",
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

#[cfg(test)]
mod tests {
    use super::*;
    use reflex_core::mealy::Mealy;
    use reflex_core::DetectorEvent;

    fn said(waited: Duration) -> Vec<Waited> {
        let (_instrument, out, ()) = PaceInstrument.step(DetectorEvent::Packet {
            input: waited,
            at: std::time::Instant::now(),
        });
        out.into_iter().collect()
    }

    /// ПРЕДМЕТ: ожидание есть ВЕЛИЧИНА, а не переход. «Ждал шесть секунд» — уже новость, порога
    /// прибор не держит: чьё терпение и с какого мгновения кончается, решает тот, кто слушает.
    #[test]
    fn waiting_is_reported_as_a_quantity_not_a_threshold() {
        assert_eq!(said(Duration::from_secs(6)), vec![Waited(Duration::from_secs(6))]);
        assert_eq!(
            said(Duration::from_millis(120)),
            vec![Waited(Duration::from_millis(120))],
            "малое ожидание — тоже величина: судит слушающий, не прибор"
        );
    }

    /// Не ждал вовсе — молчание, и это `Silence::Nothing` из паспорта: пустота наблюдения, а не
    /// слепота. Ноль как слово означал бы «замерили и вышло ноль» там, где мерить было нечего.
    #[test]
    fn no_waiting_is_silence_not_a_zero() {
        assert!(said(Duration::ZERO).is_empty());
    }

    /// ПРЯЧУЩАЯ БУКВА НИЧЕГО НЕ МЕНЯЕТ, и это тождество здесь ДОКАЗУЕМО, а не обещано: состояния у
    /// прибора нет, показание есть функция одной буквы. Тест держит именно это — если у прибора
    /// когда-нибудь заведётся память, он покраснеет и потребует пересмотра ветви слепоты.
    #[test]
    fn a_hiding_letter_changes_nothing_because_there_is_nothing_to_change() {
        let at = std::time::Instant::now();
        let (instrument, out, ()) = PaceInstrument.step(DetectorEvent::Torn { at });
        assert!(out.is_empty());

        let (_instrument, after, ()) = instrument.step(DetectorEvent::Packet {
            input: Duration::from_secs(6),
            at,
        });
        assert_eq!(after.into_iter().collect::<Vec<_>>(), vec![Waited(Duration::from_secs(6))]);
    }
}
