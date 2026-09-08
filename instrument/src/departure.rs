//! Уход человека — и образец инверсии зависимости: прибор СПРАШИВАЕТ (вопросы-атомы в
//! [`crate::ask`]), домен ОТВЕЧАЕТ. Прибор перечисляет вопросы в границе (`S: SeveredByPerson +
//! TargetDelivered`); кто и чем отвечает, ему безразлично. Зависимость односторонняя
//! (`домен → instrument`), и прибор поверяется в изоляции — вход строится без доменного типа.

use crate::ask::{SeveredByPerson, TargetDelivered};
use std::marker::PhantomData;

/// Как человек ушёл.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Left {
    /// Ушёл, не получив ничего — беда в единице человека.
    Unserved,
    /// Ушёл, получив своё — конец разговора, не поломка.
    Served,
}

/// Сказано разговору: человек ушёл из того самого разговора, который оборвался.
impl reflex_core::word::Word for Left {
    type Of = reflex_core::word::Conversation;
}

/// Прибор ухода, параметризованный тем, что ему дают. `PhantomData`: трейт требует назвать тип
/// наблюдения, а прибор знает лишь, что тот отвечает на два вопроса.
pub struct DepartureInstrument<S>(PhantomData<S>);

impl<S> Default for DepartureInstrument<S> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<S> DepartureInstrument<S> {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<S: SeveredByPerson + TargetDelivered> DepartureInstrument<S> {
    fn read(&self, observation: &S, _now_ms: u64) -> Option<Left> {
        match observation.severed_by_person() {
            false => None,
            true => match observation.target_delivered() {
                true => Some(Left::Served),
                false => Some(Left::Unserved),
            },
        }
    }
}

impl<S: SeveredByPerson + TargetDelivered> reflex_core::mealy::Mealy for DepartureInstrument<S> {
    type In = reflex_core::DetectorEvent<S>;
    /// Слово. Молчание сигналом не является.
    type Out = smallvec::SmallVec<[Left; 2]>;
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

impl<S: SeveredByPerson + TargetDelivered> crate::Instrument for DepartureInstrument<S> {
    type Signal = Left;

    const INSTRUMENT: &'static str = "departure";

    const SUBJECT: crate::Subject = crate::Subject::Person;

    /// Уровень сеанса: вопрос «ушёл ли обслуженным» — про разговор с именованной целью.
    const LAYER: crate::Layer = crate::Layer::Session;
    /// TCP: уход наблюдается сбросом, а сброс — улика соединения.
    const PROTOCOLS: &'static [crate::Protocol] = &[crate::Protocol::Tcp];
    const RUNG: Option<crate::Rung> = None;

    /// Чужой темп законен: уход сам есть событие; в тишине уходить некому.
    const CADENCE: crate::Cadence = crate::Cadence::Foreign;

    /// Событие: переход уже произошёл.
    const SHAPE: crate::Shape = crate::Shape::Event;

    /// «Не про человека» — `Nothing`, не `Blind`: прибор смотрел и установил, что наблюдение не о
    /// нём.
    const SILENCE: Option<crate::Silence> = Some(crate::Silence::Nothing);

    const LIES: &'static [&'static str] = &[
        "«ПОЛУЧИЛ СВОЁ» ЗНАЧИТ ЛИШЬ «ПОЛУЧИЛ БАЙТЫ». Заглушка «недоступно в вашей стране» тоже \
         байты, и прибор назовёт такой уход обслуженным. Различает их содержимое, а это другой \
         уровень и другой прибор.",
        "УХОД БЕЗ СБРОСА НЕ ВИДЕН. Человек, закрывший вкладку молча (соединение доживает по \
         таймауту), не даёт события вовсе — прибор промолчит, и молчание будет означать «не \
         видели», а не «не уходил».",
    ];

    const ORACLES: &'static [&'static str] = &["abandon(rutracker.org,3)", "pass"];

    const DEATH: &'static str = "содержимое проверяется; обслуженность не равна наличию байтов";

    const EVENTS: &'static [&'static str] = &["left_served", "left_unserved"];

    fn name(signal: &Self::Signal) -> &'static str {
        match signal {
            Left::Served => "left_served",
            Left::Unserved => "left_unserved",
        }
    }

    fn alarming(signal: &Self::Signal) -> bool {
        match signal {
            Left::Unserved => true,
            Left::Served => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Рукодельное наблюдение — вход строится здесь, без доменного типа (в этом смысл инверсии).
    struct Watched {
        severed: bool,
        delivered: bool,
    }

    impl SeveredByPerson for Watched {
        fn severed_by_person(&self) -> bool {
            self.severed
        }
    }

    impl TargetDelivered for Watched {
        fn target_delivered(&self) -> bool {
            self.delivered
        }
    }

    #[test]
    fn a_person_leaving_with_nothing_is_the_trouble() {
        let seen = Watched {
            severed: true,
            delivered: false,
        };
        assert_eq!(
            DepartureInstrument::new().read(&seen, 0),
            Some(Left::Unserved)
        );
    }

    #[test]
    fn a_person_leaving_served_is_not_trouble() {
        let seen = Watched {
            severed: true,
            delivered: true,
        };
        assert_eq!(
            DepartureInstrument::new().read(&seen, 0),
            Some(Left::Served)
        );
    }

    /// Не про человека — молчание, отличимое от обоих вердиктов.
    #[test]
    fn a_conversation_nobody_left_says_nothing() {
        let seen = Watched {
            severed: false,
            delivered: true,
        };
        assert_eq!(DepartureInstrument::<Watched>::new().read(&seen, 0), None);
    }
}
