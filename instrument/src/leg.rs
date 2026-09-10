//! Нога захлёбывается — доля застрявших разговоров в окне.

/// Канал (нога) — своя область снаружи фундамента: переживает всякий разговор по нему, говорить о
/// нём можно и когда разговоров нет. Маршрут — предмет прибора о мире, фундаменту о нём знать
/// нечего.
pub struct Link;
impl reflex_core::word::Base for Link {
    type Fibre = ();
}

/// Канал живёт дольше решения о нём.
impl reflex_core::word::CanDefer for Link {}

/// Захлебнулась ли нога. Не `bool`: у булева адреса нет, в позицию слова он не встаёт.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Leg {
    /// Половина разговоров и больше стоит: канал в заторе.
    Stalled,
    /// Затора нет.
    Healthy,
}

/// Сказано каналу: доля застрявших — свойство ноги, не любого из разговоров.
impl reflex_core::word::Word for Leg {
    type Of = Link;
}

/// Наблюдатель канала. Единственный прибор, отвечающий «а не мы ли виноваты в просадке»: при заторе
/// проседают ВСЕ, при цензуре — избирательно. Различитель пропорциональный.
pub struct LinkInstrument<L>(std::marker::PhantomData<L>);

impl<L> Default for LinkInstrument<L> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<L> LinkInstrument<L> {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<L: crate::ask::Carrying + crate::ask::Stalled> LinkInstrument<L> {
    fn read(&self, link: &L, _now_ms: u64) -> Option<Leg> {
        match link.carrying() {
            // Пустое окно не судится: доли без знаменателя нет, «ноль из нуля» — отсутствие
            // наблюдения, не здоровая нога.
            0 => None,
            carrying => Some(match link.stalled() * 2 >= carrying {
                true => Leg::Stalled,
                false => Leg::Healthy,
            }),
        }
    }
}

impl<L: crate::ask::Carrying + crate::ask::Stalled> reflex_core::mealy::Mealy
    for LinkInstrument<L>
{
    type In = reflex_core::DetectorEvent<L>;
    /// Слово. Молчание сигналом не является.
    type Out = smallvec::SmallVec<[Leg; 2]>;
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

impl<L: crate::ask::Carrying + crate::ask::Stalled> crate::Instrument for LinkInstrument<L> {
    type Signal = Leg;

    const INSTRUMENT: &'static str = "leg";

    const SUBJECT: crate::Subject = crate::Subject::World;

    /// Уровень: нога есть выбор маршрута — уровень адреса.
    const LAYER: crate::Layer = crate::Layer::Network;
    /// Улики на проводе нет: маршрут пакетом не наблюдается.
    const PROTOCOLS: &'static [crate::Protocol] = &[];
    const RUNG: Option<crate::Rung> = None;

    /// Окно трафика: затор существует, пока по каналу идут байты.
    const CADENCE: crate::Cadence = crate::Cadence::Foreign;

    /// Состояние: «канал в заторе» имеет равенство, переход — событие.
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

    const DEATH: &'static str = "живой вход читает наблюдателя канала; вердикт входит в решение";

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

#[cfg(test)]
mod tests {
    use super::*;
    use reflex_core::mealy::Mealy;
    use reflex_core::DetectorEvent;

    /// Окно канала, как его видит прибор: сколько разговоров несёт и сколько из них стоит.
    /// Отдельный тип, а не кортеж: прибор спрашивает ДВА независимых закона (`Carrying`,
    /// `Stalled`), и подать их одним кортежем значило бы связать то, что фреймворк развёл.
    #[derive(Debug, Clone, Copy)]
    struct Window {
        carrying: usize,
        stalled: usize,
    }

    impl crate::ask::Carrying for Window {
        fn carrying(&self) -> usize {
            self.carrying
        }
    }

    impl crate::ask::Stalled for Window {
        fn stalled(&self) -> usize {
            self.stalled
        }
    }

    fn said(carrying: usize, stalled: usize) -> Vec<Leg> {
        let (_instrument, out, ()) = LinkInstrument::<Window>::new().step(DetectorEvent::Packet {
            input: Window { carrying, stalled },
            at: std::time::Instant::now(),
        });
        out.into_iter().collect()
    }

    /// ПРЕДМЕТ: различитель ПРОПОРЦИОНАЛЬНЫЙ, и порог — ровно половина. Это единственный прибор,
    /// отвечающий «а не мы ли виноваты»: при заторе стоят ВСЕ, при цензуре — избирательно.
    #[test]
    fn half_the_talks_stalled_is_a_stalled_leg() {
        assert_eq!(said(10, 5), vec![Leg::Stalled], "ровно половина — уже затор");
        assert_eq!(said(10, 9), vec![Leg::Stalled]);
    }

    /// Вторая половина пары: избирательная беда ногу не обвиняет. Без неё тест был бы зелен и на
    /// приборе, который кричит «затор» всегда.
    #[test]
    fn a_few_stalled_talks_do_not_accuse_the_leg() {
        assert_eq!(said(10, 4), vec![Leg::Healthy]);
        assert_eq!(said(10, 0), vec![Leg::Healthy]);
    }

    /// Пустое окно НЕ СУДИТСЯ: доли без знаменателя нет. «Ноль из нуля» есть отсутствие
    /// наблюдения, а не здоровая нога — скажи прибор `Healthy`, и молчащий канал выглядел бы
    /// исправным ровно тогда, когда о нём ничего не известно (§7).
    #[test]
    fn an_empty_window_is_not_a_healthy_leg() {
        assert!(said(0, 0).is_empty());
    }
}
