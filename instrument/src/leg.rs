//! НОГА ЗАХЛЁБЫВАЕТСЯ — доля застрявших разговоров в окне.
//!
//! Переехал из другого крейта при сведении детекции в один дом.

/// КАНАЛ (НОГА) — своя область, объявленная снаружи фундамента.
///
/// Ни пакет, ни разговор, ни цель: канал переживает всякий разговор, идущий по нему, и говорить о
/// нём можно, когда ни одного разговора нет. Заводится здесь, а не в фундаменте: маршрут —
/// предмет прибора о мире, и фундаменту знать о нём нечего.
pub struct Link;
impl reflex_core::word::Region for Link {}

/// Канал живёт дольше решения о нём: сказать «в заторе» можно и следующим окном.
impl reflex_core::word::CanDefer for Link {}

/// ЗАХЛЕБНУЛАСЬ ЛИ НОГА. Не `bool`: у булева адресата нет — «истина» не говорит, о чём она, и в
/// позицию слова такое значение не встаёт.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Leg {
    /// Половина разговоров и больше стоит: канал в заторе.
    Stalled,
    /// Затора нет.
    Healthy,
}

/// СКАЗАНО КАНАЛУ: доля застрявших разговоров есть свойство ноги, а не любого из них.
impl reflex_core::word::Word for Leg {
    type Of = Link;
}

/// ПАСПОРТ НАБЛЮДАТЕЛЯ КАНАЛА — проекция `model/law/Instrument.tla`.
///
/// Прибор о МИРЕ, и единственный, отвечающий на вопрос «а не мы ли виноваты в просадке»: при
/// ЗАТОРЕ проседают ВСЕ, при цензуре — избирательно. Различитель пропорциональный, и потому не
/// зависит ни от источника затора, ни от того, виден ли нам весь канал.
pub struct LegInstrument<L>(std::marker::PhantomData<L>);

impl<L> Default for LegInstrument<L> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<L> LegInstrument<L> {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<L: crate::ask::Carrying + crate::ask::Stalled> LegInstrument<L> {
    fn read(&self, link: &L, _now_ms: u64) -> Option<Leg> {
        match link.carrying() {
            // ПУСТОЕ ОКНО НЕ СУДИТСЯ: доли без знаменателя не существует, и «ноль из нуля» есть
            // отсутствие наблюдения, а не здоровая нога.
            0 => None,
            carrying => Some(match link.stalled() * 2 >= carrying {
                true => Leg::Stalled,
                false => Leg::Healthy,
            }),
        }
    }
}

impl<L: crate::ask::Carrying + crate::ask::Stalled> reflex_core::step::Step for LegInstrument<L> {
    /// НАБЛЮДЕНИЕ, которое подают прибору.
    type From = reflex_core::DetectorEvent<L>;

    /// СЛОВО. Отсутствие слова сигналом не является: прибор высказывается, когда есть что
    /// сказать, и «ничего не случилось» не занимает места в ленте.
    type To = smallvec::SmallVec<[Leg; 2]>;

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

impl<L: crate::ask::Carrying + crate::ask::Stalled> crate::Instrument for LegInstrument<L> {
    type Signal = Leg;

    const INSTRUMENT: &'static str = "leg";

    const SUBJECT: crate::Subject = crate::Subject::World;

    /// УРОВЕНЬ: нога есть выбор МАРШРУТА — уровень адреса, а не порта.
    const LAYER: crate::Layer = crate::Layer::Network;
    /// УЛИКИ НА ПРОВОДЕ НЕТ: предмет — выбор МАРШРУТА, а маршрут не наблюдается пакетом.
    const PROTOCOLS: &'static [crate::Protocol] = &[];
    const RUNG: Option<crate::Rung> = None;

    /// ОКНО ТРАФИКА. Для этого предмета законно: затор существует, только пока по каналу идут
    /// байты.
    const CADENCE: crate::Cadence = crate::Cadence::Foreign;

    /// СОСТОЯНИЕ: «канал в заторе» имеет равенство, и переход в него и из него — событие.
    const SHAPE: crate::Shape = crate::Shape::State;

    const SILENCE: Option<crate::Silence> = Some(crate::Silence::Nothing);

    const LIES: &'static [&'static str] = &[
        "ПОСТРОЕН И ЖИВЁТ В СОБСТВЕННЫХ ТЕСТАХ. `link::saturation` не зовётся ни одним живым \
         входом — назван в `pipe.rs` в одном ряду с `Offers` как известный ноль. При этом он есть \
         прямой ответ на режим лжи детектора троттлинга («медленный канал неотличим от цензуры»): \
         прибор, лечащий чужую слепоту, лежит рядом невостребованным.",
        "СЛАБЫЙ ПРИЗНАК ВЗЯТ У НЕВОДА 1 ВМЕСТЕ С ЕГО ЦЕНОЙ: «канал занят» срабатывает, когда \
         человек качает файл И его в это же время душат. Подавлять обвинение по такому признаку \
         значит терять лечение настоящей цензуры ровно тогда, когда канал занят. Оттого решений по \
         нему не принимают — только называют совпадение.",
        "ПРОПОРЦИЯ ТРЕБУЕТ ЧИСЛА РАЗГОВОРОВ. На одном-двух она не значит ничего, и порог этого \
         числа здесь не назван — он живёт у потребителя, которого нет.",
    ];

    const ORACLES: &'static [&'static str] = &["throttle(250kbit,6%)", "pass"];

    /// СМЕРТЬ: наблюдатель канала подключён к живому входу и его вердикт входит в решение о
    /// троттлинге — тогда первый режим лжи умирает, а второй становится проверяемым.
    const DEATH: &'static str = "живой вход читает наблюдателя канала; вердикт входит в решение";

    /// ПУБЛИЧНЫЕ ИМЕНА СОБЫТИЙ — реестр, снятый с типа: за границей процесса имя показания не
    /// сторожит компилятор, и `Debug` сменил бы метку молча (#321).
    const EVENTS: &'static [&'static str] = &["leg_stalled", "leg_healthy"];

    fn name(signal: &Self::Signal) -> &'static str {
        match signal {
            Leg::Stalled => "leg_stalled",
            Leg::Healthy => "leg_healthy",
        }
    }

    fn alarming(signal: &Self::Signal) -> bool {
        match signal {
            Leg::Stalled => true,
            Leg::Healthy => false,
        }
    }
}
