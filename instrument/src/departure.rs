//! УХОД ЧЕЛОВЕКА — и образец того, как прибор берёт данные у домена, ничего о нём не зная.
//!
//! # Инверсия зависимости: прибор СПРАШИВАЕТ, домен ОТВЕЧАЕТ
//!
//! Прежде этот прибор принимал `Sighting` — тип домена, — и потому не мог переехать в общий дом:
//! он тянул домен за собой. Обратное направление («домен знает про прибор») даёт то же самое
//! знание, но зависимость идёт в правильную сторону.
//!
//! Прибор перечисляет ВОПРОСЫ в границе типа (`S: SeveredByPerson + TargetDelivered`), а сами
//! вопросы живут атомами в [`crate::ask`]. Кто и чем на них отвечает, прибору безразлично:
//! `Sighting` в проде, рукодельная структура в поверке, чужой формат в будущем импортёре. Домен
//! реализует нужные трейты на своём типе, и зависимость становится односторонней —
//! `домен → instrument`, никогда обратно.
//!
//! # Что этим куплено, кроме чистоты
//!
//! Прибор стало возможно поверять В ИЗОЛЯЦИИ: его вход строится здесь же, без единого доменного
//! типа. Пока вход был `Sighting`, всякая поверка тащила домен и «прогнать приборы отдельно»
//! означало «собрать половину продукта».
//!
//! # Почему вопросы атомарны
//!
//! Крупный трейт застывал бы: добавить вопрос — сломать всех, кто отвечает, и дисциплина «не
//! проси лишнего» держалась бы памятью автора. Атомы убирают память из уравнения: лишний вопрос
//! ВИДЕН в границе, новый вопрос есть новый трейт и никого не ломает, а «отдала ли цель»
//! спрашивают трое — и домен отвечает один раз. Подробно — в [`crate::ask`].

use crate::ask::{SeveredByPerson, TargetDelivered};
use std::marker::PhantomData;

/// КАК ЧЕЛОВЕК УШЁЛ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Left {
    /// Ушёл, НЕ получив ничего. Это и есть беда в единице человека.
    Unserved,
    /// Ушёл, получив своё. Конец разговора, а не поломка.
    Served,
}

/// СКАЗАНО РАЗГОВОРУ: «человек ушёл отсюда, получив своё или нет» — это свойство того самого
/// разговора, который оборвался.
impl reflex_core::word::Word for Left {
    type Of = reflex_core::word::Conversation;
}

/// ПРИБОР УХОДА ЧЕЛОВЕКА, параметризованный тем, что ему дают.
///
/// `PhantomData` здесь не украшение: трейт [`crate::Instrument`] требует НАЗВАТЬ тип наблюдения,
/// а прибор его не знает — знает лишь, что тот отвечает на два вопроса. Параметр и есть способ
/// сказать «какой угодно, лишь бы отвечал».
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

impl<S: SeveredByPerson + TargetDelivered> reflex_core::step::Step for DepartureInstrument<S> {
    /// НАБЛЮДЕНИЕ, которое подают прибору.
    type From = reflex_core::DetectorEvent<S>;

    /// СЛОВО. Отсутствие слова сигналом не является: прибор высказывается, когда есть что
    /// сказать, и «ничего не случилось» не занимает места в ленте.
    type To = smallvec::SmallVec<[Left; 2]>;

    /// Показаний этот прибор не заводит: он говорит, что увидел, и не говорит, чем мерил.
    type Notes = ();

    fn step(self, event: Self::From) -> (Self, Self::To, ()) {
        match event {
            reflex_core::DetectorEvent::Packet { input, .. } => {
                let reading = self.read(&input, 0);
                (self, reading.into_iter().collect(), ())
            }
            reflex_core::DetectorEvent::Tick { .. } => (self, smallvec::SmallVec::new(), ()),
            // Прибор мерит РАЗОБРАННЫЙ домен; непонятое им не является и молчит так же, как тик.
            reflex_core::DetectorEvent::Opaque { .. } => (self, smallvec::SmallVec::new(), ()),
        }
    }
}

impl<S: SeveredByPerson + TargetDelivered> crate::Instrument for DepartureInstrument<S> {
    type Signal = Left;

    const INSTRUMENT: &'static str = "departure";

    /// О ЧЕЛОВЕКЕ: что он пережил, а не какова цель и не применилось ли наше действие.
    const SUBJECT: crate::Subject = crate::Subject::Person;

    /// УРОВЕНЬ СЕАНСА: вопрос «ушёл ли обслуженным» ставится про разговор с ИМЕНОВАННОЙ целью.
    const LAYER: crate::Layer = crate::Layer::Session;
    /// TCP: уход человека наблюдается СБРОСОМ, а сброс есть улика соединения. Это записано и в
    /// режимах лжи прибора — «уход без сброса не виден».
    const PROTOCOLS: &'static [crate::Protocol] = &[crate::Protocol::Tcp];
    const RUNG: Option<crate::Rung> = None;

    /// ТЕМП — ЧУЖОЙ, и для этого предмета он законен: уход человека САМ есть событие, а не
    /// состояние, которое надо опрашивать. В тишине уходить уже некому — ушедший и есть
    /// последний, кто послал пакет.
    const CADENCE: crate::Cadence = crate::Cadence::Foreign;

    /// СОБЫТИЕ, не состояние: переход уже произошёл.
    const SHAPE: crate::Shape = crate::Shape::Event;

    /// «НЕ ПРО ЧЕЛОВЕКА» выражено `None`, и это `Nothing`, а не `Blind`: прибор СМОТРЕЛ и
    /// установил, что наблюдение не о нём.
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

    /// СМЕРТЬ: заведён прибор содержимого, и «получил своё» перестанет означать «получил байты».
    const DEATH: &'static str = "содержимое проверяется; обслуженность не равна наличию байтов";

    /// ПУБЛИЧНЫЕ ИМЕНА СОБЫТИЙ — реестр, снятый с типа: за границей процесса имя показания не
    /// сторожит компилятор, и `Debug` сменил бы метку молча (#321).
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

    /// РУКОДЕЛЬНОЕ НАБЛЮДЕНИЕ — и в нём весь смысл инверсии: вход прибора строится ЗДЕСЬ, без
    /// единого доменного типа. Пока входом был `Sighting`, такая поверка была невозможна.
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

    /// НЕ ПРО ЧЕЛОВЕКА — молчание, и оно должно быть отличимо от обоих вердиктов.
    #[test]
    fn a_conversation_nobody_left_says_nothing() {
        let seen = Watched {
            severed: false,
            delivered: true,
        };
        assert_eq!(DepartureInstrument::<Watched>::new().read(&seen, 0), None);
    }
}
