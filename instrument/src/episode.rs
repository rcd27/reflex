//! Конец эпизода — кончился ли просмотр, и каким образом. Домен помнит эпизод (моменты, признак
//! ухода); прибор решает, ЧТО ЭТО ЗНАЧИТ, — и пороги, по которым судит, его собственные.

use crate::ask::{LastSeen, OpenedAt, PersonLeft};
use std::marker::PhantomData;
use std::time::{Duration, Instant};

/// Сколько бездействия считать уходом. Минута: не тронувший ничего минуту — ушёл.
pub const EPISODE_IDLE: Duration = Duration::from_secs(60);

/// Потолок ожидания. Полчаса — после них эпизод кончился, ДАЖЕ если человек ещё здесь. Утверждение
/// о нас (не дождёмся), не о нём — потому `Ending::Ceiling` названо отдельно.
pub const EPISODE_CEILING: Duration = Duration::from_secs(30 * 60);

/// Как кончился эпизод. Три случая разной надёжности — потому не слиты.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// Уход наблюдён на проводе. В момент ухода.
    Abandoned,
    /// Уход выведен из бездействия дольше [`EPISODE_IDLE`]. На минуту позже него.
    Idle,
    /// Потолок [`EPISODE_CEILING`]: не дождёмся, но сказать обязаны. Утверждение о нас.
    Ceiling,
}

/// Эпизод просмотра — своя область снаружи фундамента: переживает свои разговоры, кончается позже
/// последнего. Предмет прибора о человеке.
pub struct Episode;
impl reflex_core::word::Base for Episode {
    type Fibre = ();
}

/// Эпизод живёт до своего конца, ожидание терпит.
impl reflex_core::word::CanDefer for Episode {}

/// Сказано эпизоду: кончился ли просмотр и как.
impl reflex_core::word::Word for Ending {
    type Of = Episode;
}

/// Прибор конца эпизода, параметризованный тем, что ему дают.
pub struct EpisodeInstrument<W>(PhantomData<W>);

impl<W> Default for EpisodeInstrument<W> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<W> EpisodeInstrument<W> {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<W: OpenedAt + LastSeen + PersonLeft> EpisodeInstrument<W> {
    fn read(&self, observation: &(W, Instant), _now_ms: u64) -> Option<Ending> {
        let (window, now) = observation;

        // Наблюдённый уход сильнее вывода по времени (про то, что видели, а не чего не дождались):
        // проверяется первым и закрывает эпизод сразу.
        match (window.opened_at(), window.last_seen(), window.person_left()) {
            (None, _, _) | (_, None, _) => None,
            (Some(_), Some(_), true) => Some(Ending::Abandoned),
            (Some(opened), Some(last), false) => match (
                now.saturating_duration_since(last) >= EPISODE_IDLE,
                now.saturating_duration_since(opened) >= EPISODE_CEILING,
            ) {
                (true, _) => Some(Ending::Idle),
                (false, true) => Some(Ending::Ceiling),
                (false, false) => None,
            },
        }
    }
}

impl<W: OpenedAt + LastSeen + PersonLeft> reflex_core::mealy::Mealy for EpisodeInstrument<W> {
    type In = reflex_core::DetectorEvent<(W, Instant)>;
    /// Слово. Молчание сигналом не является.
    type Out = smallvec::SmallVec<[Ending; 2]>;
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

impl<W: OpenedAt + LastSeen + PersonLeft> crate::Instrument for EpisodeInstrument<W> {
    type Signal = Ending;

    const INSTRUMENT: &'static str = "episode";

    const SUBJECT: crate::Subject = crate::Subject::Person;

    /// Уровень приложения: эпизод стоит на самом высоком из своих уровней.
    const LAYER: crate::Layer = crate::Layer::Application;
    /// Улики на проводе нет: эпизод складывается из вкладов соединений.
    const PROTOCOLS: &'static [crate::Protocol] = &[];
    const RUNG: Option<crate::Rung> = None;

    /// Свои часы: два исхода из трёх наступают от времени. Шаг равен порогу — меньший опрашивал бы
    /// чаще, чем что-либо меняется.
    const CADENCE: crate::Cadence = crate::Cadence::Own {
        step_ms: EPISODE_IDLE.as_millis() as u64,
    };

    const SHAPE: crate::Shape = crate::Shape::Event;

    /// «Эпизод ещё идёт» — `Nothing`: прибор смотрел и установил, что конца пока нет.
    const SILENCE: Option<crate::Silence> = Some(crate::Silence::Nothing);

    const LIES: &'static [&'static str] = &[
        "ДВА ИСХОДА ИЗ ТРЁХ — ВЫВОД, А НЕ НАБЛЮДЕНИЕ. `Idle` и `Ceiling` говорят о том, чего мы \
         НЕ ВИДЕЛИ (человек молчит), и потому опаздывают на порог: уход, случившийся на первой \
         секунде минуты, будет назван через минуту.",
        "`Ceiling` ЕСТЬ УТВЕРЖДЕНИЕ О НАС. Человек может быть ещё здесь и смотреть; прибор \
         сообщает, что мы перестали ждать, — и путать это с уходом значит считать своим знанием \
         своё нетерпение.",
        "ПОРОГИ НЕ ЗНАЮТ ПРЕДМЕТА. Минута бездействия для чтения статьи и для видеозвонка \
         значат разное; прибор одинаков для обоих, потому что о предмете не спрашивает.",
        "СРОК ПРОВАЛЕН, И ЭТО ЧЕТВЁРТЫЙ МНОЖИТЕЛЬ ГОДНОСТИ. Человек уходит и возвращается к \
         своим делам за секунды, а `Idle` приходит через минуту после его ухода: прибор \
         высказывается ПОЗЖЕ, чем предмет успевает измениться. Часы у него свои и исправны — \
         провален не механизм, а СРОК, и лечится это порогом, зависящим от предмета, а не более \
         частым опросом.",
    ];

    const ORACLES: &'static [&'static str] = &["abandon(rutracker.org,3)", "pass"];

    const DEATH: &'static str = "пороги зависят от предмета; минута перестала быть универсальной";

    const EVENTS: &'static [&'static str] =
        &["episode_abandoned", "episode_idle", "episode_ceiling"];

    fn name(signal: &Self::Signal) -> &'static str {
        match signal {
            Ending::Abandoned => "episode_abandoned",
            Ending::Idle => "episode_idle",
            Ending::Ceiling => "episode_ceiling",
        }
    }

    fn alarming(signal: &Self::Signal) -> bool {
        match signal {
            Ending::Abandoned => true,
            Ending::Idle | Ending::Ceiling => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Рукодельное окно: вход строится здесь, без доменного типа.
    struct Window {
        opened: Option<Instant>,
        last: Option<Instant>,
        left: bool,
    }

    impl OpenedAt for Window {
        fn opened_at(&self) -> Option<Instant> {
            self.opened
        }
    }
    impl LastSeen for Window {
        fn last_seen(&self) -> Option<Instant> {
            self.last
        }
    }
    impl PersonLeft for Window {
        fn person_left(&self) -> bool {
            self.left
        }
    }

    #[test]
    fn a_seen_departure_closes_the_episode_at_once() {
        let now = Instant::now();
        let window = Window {
            opened: Some(now),
            last: Some(now),
            left: true,
        };
        assert_eq!(
            EpisodeInstrument::new().read(&(window, now), 0),
            Some(Ending::Abandoned)
        );
    }

    /// Наблюдённый уход сильнее потолка: без этой клетки порядок проверок можно переставить
    /// незаметно.
    #[test]
    fn a_seen_departure_outranks_the_ceiling() {
        let now = Instant::now();
        let long_ago = now - EPISODE_CEILING - Duration::from_secs(1);
        let window = Window {
            opened: Some(long_ago),
            last: Some(long_ago),
            left: true,
        };
        assert_eq!(
            EpisodeInstrument::new().read(&(window, now), 0),
            Some(Ending::Abandoned)
        );
    }

    #[test]
    fn silence_longer_than_the_threshold_is_inferred_as_idle() {
        let now = Instant::now();
        let window = Window {
            opened: Some(now - Duration::from_secs(120)),
            last: Some(now - EPISODE_IDLE - Duration::from_secs(1)),
            left: false,
        };
        assert_eq!(
            EpisodeInstrument::new().read(&(window, now), 0),
            Some(Ending::Idle)
        );
    }

    #[test]
    fn a_living_episode_says_nothing() {
        let now = Instant::now();
        let window = Window {
            opened: Some(now - Duration::from_secs(10)),
            last: Some(now),
            left: false,
        };
        assert_eq!(
            EpisodeInstrument::<Window>::new().read(&(window, now), 0),
            None
        );
    }
}
