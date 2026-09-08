//! КОНЕЦ ЭПИЗОДА — кончился ли просмотр, и каким образом.
//!
//! # Что здесь прибор, а что домен
//!
//! Домен помнит эпизод: когда он начался, когда была последняя активность, видели ли уход.
//! Прибор решает, ЧТО ЭТО ЗНАЧИТ, — и это решение переехало сюда вместе с ним. Пока оно жило
//! методом доменного типа, прибор был обёрткой над чужой логикой: паспорт у него был, а
//! различающая способность принадлежала не ему.
//!
//! Три факта, которые прибор спрашивает, — про наблюдение (моменты и признак ухода). Пороги,
//! по которым он судит, — его собственные и объявлены здесь.

use crate::ask::{LastSeen, OpenedAt, PersonLeft};
use std::marker::PhantomData;
use std::time::{Duration, Instant};

/// СКОЛЬКО БЕЗДЕЙСТВИЯ СЧИТАТЬ УХОДОМ.
///
/// Минута: человек, не тронувший ничего минуту, ушёл — а вернувшись, начнёт новый просмотр, и
/// это верно даже если он всё это время сидел перед экраном.
pub const EPISODE_IDLE: Duration = Duration::from_secs(60);

/// ПОТОЛОК ОЖИДАНИЯ. Полчаса — после них мы говорим, что эпизод кончился, ДАЖЕ ЕСЛИ человек ещё
/// здесь. Это утверждение о нас (мы не дождёмся), а не о нём, и `Ending::Ceiling` называет его
/// отдельным словом именно поэтому.
pub const EPISODE_CEILING: Duration = Duration::from_secs(30 * 60);

/// КАК КОНЧИЛСЯ ЭПИЗОД. Три случая, и они разной надёжности — потому и не слиты в один.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// УХОД НАБЛЮДЁН на проводе. Приходит в момент ухода.
    Abandoned,
    /// Уход ВЫВЕДЕН из бездействия дольше [`EPISODE_IDLE`]. Приходит на минуту позже него.
    Idle,
    /// Потолок [`EPISODE_CEILING`]: мы не дождёмся, но сказать обязаны. Человек может быть ещё
    /// здесь — это утверждение о НАС, а не о нём.
    Ceiling,
}

/// ЭПИЗОД ПРОСМОТРА — своя область, объявленная снаружи фундамента.
///
/// Ни пакет, ни разговор, ни цель: эпизод переживает свои разговоры и кончается позже последнего
/// из них. Заводится здесь, а не в фундаменте: эпизод — предмет прибора о человеке, и фундаменту
/// знать о нём нечего.
pub struct Episode;
impl reflex_core::word::Base for Episode {
    type Fibre = ();
}

/// Эпизод живёт до своего конца и ожидание терпит: сказать «кончился» можно и следующим тиком.
impl reflex_core::word::CanDefer for Episode {}

/// СКАЗАНО ЭПИЗОДУ: кончился ли просмотр и каким образом.
impl reflex_core::word::Word for Ending {
    type Of = Episode;
}

/// ПРИБОР КОНЦА ЭПИЗОДА, параметризованный тем, что ему дают.
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

        // НАБЛЮДЁННЫЙ УХОД СИЛЬНЕЕ ЛЮБОГО ВЫВОДА ПО ВРЕМЕНИ: он про то, что мы ВИДЕЛИ, а не про
        // то, чего не дождались. Потому проверяется первым и закрывает эпизод сразу.
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
    /// НАБЛЮДЕНИЕ, которое подают прибору.
    type In = reflex_core::DetectorEvent<(W, Instant)>;

    /// СЛОВО. Отсутствие слова сигналом не является: прибор высказывается, когда есть что
    /// сказать, и «ничего не случилось» не занимает места в ленте.
    type Out = smallvec::SmallVec<[Ending; 2]>;

    /// Показаний этот прибор не заводит: он говорит, что увидел, и не говорит, чем мерил.
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
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

impl<W: OpenedAt + LastSeen + PersonLeft> crate::Instrument for EpisodeInstrument<W> {
    type Signal = Ending;

    const INSTRUMENT: &'static str = "episode";

    /// О ЧЕЛОВЕКЕ: кончился ли ЕГО просмотр.
    const SUBJECT: crate::Subject = crate::Subject::Person;

    /// УРОВЕНЬ ПРИЛОЖЕНИЯ: эпизод складывается из всего, что человек пережил, и стоит на самом
    /// высоком из своих уровней.
    const LAYER: crate::Layer = crate::Layer::Application;
    /// УЛИКИ НА ПРОВОДЕ НЕТ: эпизод складывается из вкладов соединений, а не из пакетов.
    const PROTOCOLS: &'static [crate::Protocol] = &[];
    const RUNG: Option<crate::Rung> = None;

    /// СВОИ ЧАСЫ: два исхода из трёх наступают ОТ ВРЕМЕНИ, а не от пакета. Прибор на чужом темпе
    /// молчал бы ровно тогда, когда человек ушёл, — то есть в единственный момент, ради которого
    /// он и заведён.
    ///
    /// ШАГ РАВЕН ПОРОГУ, а не взят покрупнее «на всякий случай»: меньший шаг означал бы опрос
    /// чаще, чем что-либо может измениться, — шестьдесят вопросов вместо одного и ни одного
    /// нового ответа. При переносе прибора сюда шаг был выставлен в секунду по невнимательности,
    /// и это поймал тест паспорта, а не чтение.
    const CADENCE: crate::Cadence = crate::Cadence::Own {
        step_ms: EPISODE_IDLE.as_millis() as u64,
    };

    const SHAPE: crate::Shape = crate::Shape::Event;

    /// «ЭПИЗОД ЕЩЁ ИДЁТ» выражено `None`, и это `Nothing`: прибор смотрел и установил, что конца
    /// пока нет.
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

    /// СМЕРТЬ: пороги стали зависеть от предмета эпизода — тогда «минута молчания» перестанет
    /// значить одно и то же для статьи и для звонка.
    const DEATH: &'static str = "пороги зависят от предмета; минута перестала быть универсальной";

    /// ПУБЛИЧНЫЕ ИМЕНА СОБЫТИЙ — реестр, снятый с типа: за границей процесса имя показания не
    /// сторожит компилятор, и `Debug` сменил бы метку молча (#321).
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

    /// РУКОДЕЛЬНОЕ ОКНО: вход строится здесь, без единого доменного типа.
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

    /// НАБЛЮДЁННЫЙ УХОД СИЛЬНЕЕ ПОТОЛКА: окно, где случилось и то и другое, обязано называться
    /// уходом. Без этой клетки порядок проверок в приборе можно было бы переставить незаметно.
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
