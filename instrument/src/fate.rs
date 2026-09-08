//! Судьба цели — типология, общая для прибора и обоих движков. Судьбу устанавливает плечо, но
//! принадлежит она ЦЕЛИ (свойство того, к кому шли). Две оси, путать нельзя: [`Fate`] — скрытая
//! правда, наблюдению не данная; [`Observed`] — что наблюдатель установил (он не называет судьбу, а
//! СУЖАЕТ круг возможных, [`Observed::admits`]).

/// Скрытая правда о цели. Пять судеб, у каждой своё лечение.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Fate {
    /// Сервер не ответил — рукопожатие не собралось.
    Dead,
    /// Рукопожатие есть, байтов нет: поздоровался впустую. Прямой путь жив на транспорте — лечение
    /// иное, чем у `Dead`.
    Trap,
    /// Байты текут, ресурса нет: заглушка CDN, парковка, чужой сертификат.
    Mirage,
    /// Ресурс тот самый, но добыт повторами — платится временем человека.
    Grinding,
    /// Ресурс тот самый, байты полные, лишнего не заплачено.
    Good,
}

/// Все судьбы. Круг, не сужённый ничем — «не установлено ничего».
pub const ALL_FATES: [Fate; 5] = [
    Fate::Dead,
    Fate::Trap,
    Fate::Mirage,
    Fate::Grinding,
    Fate::Good,
];

/// Что установлено пассивным наблюдением одного плеча. Не судьба, а показание прибора.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observed {
    /// TCP не встал: сервер не поздоровался.
    NoConnect,
    /// Встал и молчит: поздоровался впустую. Объявить мёртвым — похоронить живой прямой путь.
    Mute,
    /// Байты пришли — и это всё, что установлено. Не «работает».
    Bytes,
    /// Плечо брошено: ждать перестали сами. О судьбе ничего — честный прибор даёт полный круг.
    /// (Прежде подставлялось «молчало», и 8 из 28 доменов заперты приговором за молчание, которого
    /// никто не слышал.)
    Unobserved,
    /// Байты без коннекта — наблюдение противоречиво. Факт о ПРИБОРЕ, отдельно от `Bytes`: иначе
    /// брак прибора выглядел бы успехом.
    Inconsistent,
}

impl Observed {
    /// Круг судеб, совместимых с показанием. Закон `Sound`: истинная судьба всегда внутри круга.
    pub const fn admits(self) -> &'static [Fate] {
        match self {
            Observed::NoConnect => &[Fate::Dead],
            Observed::Mute => &[Fate::Trap],
            // Три судьбы: пассивно не делятся (содержимое закрыто), различает активная проба.
            Observed::Bytes => &[Fate::Mirage, Fate::Grinding, Fate::Good],
            Observed::Unobserved => &ALL_FATES,
            Observed::Inconsistent => &ALL_FATES,
        }
    }

    /// Имя для витнеса — низкокардинальный атрибут спана.
    pub const fn name(self) -> &'static str {
        match self {
            Observed::NoConnect => "NoConnect",
            Observed::Mute => "Mute",
            Observed::Bytes => "Bytes",
            Observed::Unobserved => "Unobserved",
            Observed::Inconsistent => "Inconsistent",
        }
    }

    /// Оплачено ли человеком ожидание, ничего не принёсшее. Для `Bytes` — нет; для брошенного —
    /// нет (ждать перестали мы, не сервер).
    pub const fn wasted_the_wait(self) -> bool {
        match self {
            Observed::NoConnect => true,
            Observed::Mute => true,
            Observed::Bytes => false,
            Observed::Unobserved => false,
            Observed::Inconsistent => false,
        }
    }
}

/// Что случилось с байтами на плече. Ось, отдельная от коннекта. Третий исход не декоративен:
/// брошенное плечо наблюдалось не полностью и свидетельствовать не может.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Плечо доставило байты.
    Delivered,
    /// Наблюдалось всё окно и молчало.
    Silent,
    /// Брошено: ждать перестали сами. О пути ничего.
    Abandoned,
}

/// Что установило наблюдение плеча. Чистая функция; разбор тотален по обеим осям. `connected` (SYN)
/// и `delivery` (байты) — разные факты; их слияние и есть бедность словаря, из-за которой продукт
/// знал две судьбы вместо пяти.
pub const fn observe(connected: bool, delivery: Delivery) -> Observed {
    match (connected, delivery) {
        (false, Delivery::Abandoned) => Observed::Unobserved,
        (true, Delivery::Abandoned) => Observed::Unobserved,
        (false, Delivery::Silent) => Observed::NoConnect,
        (true, Delivery::Silent) => Observed::Mute,
        // Байты без коннекта — брак прибора, не судьба цели.
        (false, Delivery::Delivered) => Observed::Inconsistent,
        (true, Delivery::Delivered) => Observed::Bytes,
    }
}

/// Круг допускаемых судеб — с именем, не голой ссылкой на срез: адрес объявляет значение, а срез
/// значением прибора не является.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Admits(pub &'static [Fate]);

/// Сказано цели: круг перечисляет судьбы ЦЕЛИ. Конец плеча — момент сужения, не адресат (разговор
/// уже кончился). Тот же адресат, что у [`crate::resolve::Resolved`].
impl reflex_core::word::Word for Admits {
    type Of = reflex_core::word::Target;
}

/// Прибор пассивного наблюдения судьбы. Самое сильное различение парка и самое неподключённое:
/// показание не называет судьбу, а сужает круг ([`Observed::admits`]).
pub struct ObservedInstrument;

impl ObservedInstrument {
    /// Показание в круг судеб. Момент не используется: судьба доопределяется концом плеча.
    fn read(&self, observation: &Observed, _now_ms: u64) -> &'static [Fate] {
        observation.admits()
    }
}

impl reflex_core::mealy::Mealy for ObservedInstrument {
    type In = reflex_core::DetectorEvent<Observed>;
    /// Слово. Молчание сигналом не является.
    type Out = smallvec::SmallVec<[Admits; 2]>;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        match event {
            reflex_core::DetectorEvent::Packet { input, .. } => {
                let reading = self.read(&input, 0);
                (self, smallvec::smallvec![Admits(reading)], ())
            }
            reflex_core::DetectorEvent::Tick { .. } | reflex_core::DetectorEvent::Opaque { .. } => {
                (self, smallvec::SmallVec::new(), ())
            }
        }
    }
}

impl crate::Instrument for ObservedInstrument {
    type Signal = Admits;

    const INSTRUMENT: &'static str = "observed";

    const SUBJECT: crate::Subject = crate::Subject::World;

    /// Уровень: судьба решается тем, отозвалась ли цель; TLS закрыт, выше пассивно не видно.
    const LAYER: crate::Layer = crate::Layer::Transport;
    const PROTOCOLS: &'static [crate::Protocol] = &[crate::Protocol::Tcp, crate::Protocol::Udp];
    const RUNG: Option<crate::Rung> = Some(crate::Rung::Answered);

    /// Конец плеча (отложенный трафик): круг доопределяется, когда плечо кончилось.
    const CADENCE: crate::Cadence = crate::Cadence::Foreign;

    /// Вердикт: показание сужает круг. Единственный такой в парке.
    const SHAPE: crate::Shape = crate::Shape::Verdict;

    /// `Inconsistent` и есть клетка «прибор не смог» (байты без коннекта — факт о приборе), потому
    /// `Blind`. Отдельным вариантом: склейка с `Bytes` выдавала бы брак за успех.
    const SILENCE: Option<crate::Silence> = Some(crate::Silence::Blind);

    const LIES: &'static [&'static str] = &[
        "КРУГ НЕ РАЗВОРАЧИВАЕТ НИКТО. `admits()` вызывается ТОЛЬКО внутри `#[cfg(test)]` — в \
         `zond/src/fate.rs` граница на строке 151, все семь вызовов ниже; то же в неводе 1. Закон \
         `PassiveFate::Sound` исполняется собственным тестом и больше ничем. Различение здесь \
         максимальное, подключённость нулевая — два разных множителя, и лечатся они по-разному: \
         первое доводкой алфавита, второе ПОТРЕБИТЕЛЕМ ЗАКОНА.",
        "`Observed` ЖИВОЙ, А КРУГ МЁРТВЫЙ. Сам вариант читают `domain::flow` и `domain::session`, \
         пользуясь `Mute`, `NoConnect`, `Unobserved`, `Bytes`. То есть продукт ХРАНИТ показание и \
         никогда не спрашивает, что оно допускает.",
        "РЕЗКОСТЬ ТЕРЯЕТСЯ НА ПЕЧАТИ. Различие `NoConnect` против `Mute` в типе ЕСТЬ, а вывод \
         `zond-probe` сводит оба в «пробито 0/5»: разрешение выхода ниже разрешения алфавита, и \
         расходятся они молча. Замерено поверочным стендом — резкость 0,75 против 1,00 у чужого \
         прибора на тех же клетках.",
    ];

    const ORACLES: &'static [&'static str] = &[
        "syn_drop(1.2.3.4)",
        "sni_drop(rutracker.org)",
        "mirage(1.2.3.4)",
        "fatflow(1.2.3.4,16,reply,drop)",
    ];

    const DEATH: &'static str = "`admits()` вызывается в живом входе, а не только в тестах";

    const EVENTS: &'static [&'static str] = &["fates_admitted"];

    fn name(signal: &Self::Signal) -> &'static str {
        let _ = signal;
        "fates_admitted"
    }

    fn alarming(signal: &Self::Signal) -> bool {
        let _ = signal;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Показание прибора на плече истинной судьбы `f` — обратное к модели, чтобы проверить `Sound`
    /// на коде.
    fn leg_of(f: Fate) -> (bool, Delivery) {
        match f {
            Fate::Dead => (false, Delivery::Silent),
            Fate::Trap => (true, Delivery::Silent),
            Fate::Mirage => (true, Delivery::Delivered),
            Fate::Grinding => (true, Delivery::Delivered),
            Fate::Good => (true, Delivery::Delivered),
        }
    }

    /// Закон `Sound`: правда всегда внутри круга. На всех пяти судьбах.
    #[test]
    fn every_fate_lies_inside_its_own_circle() {
        ALL_FATES.iter().for_each(|f| {
            let (connected, delivery) = leg_of(*f);
            let seen = observe(connected, delivery);
            assert!(
                seen.admits().contains(f),
                "судьба {f:?} вне круга показания {}: прибор утверждает больше, чем установил",
                seen.name()
            );
        });
    }

    /// Молчание после рукопожатия не есть смерть.
    #[test]
    fn silence_after_a_handshake_is_not_death() {
        let seen = observe(true, Delivery::Silent);
        assert_eq!(seen, Observed::Mute);
        assert!(!seen.admits().contains(&Fate::Dead));
    }

    /// Противоречие не выдаёт себя за успех.
    #[test]
    fn a_contradiction_does_not_pass_itself_off_as_success() {
        let seen = observe(false, Delivery::Delivered);
        assert_eq!(seen, Observed::Inconsistent);
        assert_eq!(seen.admits().len(), ALL_FATES.len());
    }

    /// Брошенное плечо ничего не устанавливает — при любом коннекте.
    #[test]
    fn an_abandoned_leg_establishes_nothing_either_way() {
        assert_eq!(observe(true, Delivery::Abandoned), Observed::Unobserved);
        assert_eq!(observe(false, Delivery::Abandoned), Observed::Unobserved);
    }

    /// Показание сужает круг, но не пустеет.
    #[test]
    fn every_observation_admits_at_least_one_fate() {
        let all = [
            Observed::NoConnect,
            Observed::Mute,
            Observed::Bytes,
            Observed::Unobserved,
            Observed::Inconsistent,
        ];
        assert!(all.iter().all(|o| !o.admits().is_empty()));
    }

    /// Байты не значат «работает»: три судьбы пассивно неразличимы.
    #[test]
    fn bytes_alone_admit_three_fates() {
        assert_eq!(Observed::Bytes.admits().len(), 3);
        assert!(Observed::Bytes.admits().contains(&Fate::Mirage));
    }

    /// Брошенное плечо не свидетельствует ни о чём.
    #[test]
    fn an_abandoned_leg_narrows_nothing() {
        assert_eq!(Observed::Unobserved.admits().len(), ALL_FATES.len());
    }

    /// Впустую прожданным считается ожидание, ничего не принёсшее И заставленное сервером.
    #[test]
    fn only_a_fruitless_wait_forced_by_the_server_counts_as_wasted() {
        assert!(Observed::NoConnect.wasted_the_wait());
        assert!(Observed::Mute.wasted_the_wait());
        assert!(!Observed::Bytes.wasted_the_wait());
        assert!(!Observed::Unobserved.wasted_the_wait());
    }
}

#[cfg(test)]
mod observed_passport_tests {
    use super::*;
    use crate::Instrument;

    /// Паспорт отдаёт круг, не судьбу: три показания разной ширины (одного значения мало —
    /// возвращающий всегда `ALL_FATES` прошёл бы любой одиночный вход).
    #[test]
    fn the_passport_hands_back_a_circle_not_a_fate() {
        assert_eq!(
            ObservedInstrument.read(&Observed::NoConnect, 0),
            &[Fate::Dead]
        );
        assert_eq!(
            ObservedInstrument.read(&Observed::Bytes, 0).len(),
            3,
            "пассивно `Mirage`, `Grinding` и `Good` не делятся ничем"
        );
        assert_eq!(
            ObservedInstrument.read(&Observed::Inconsistent, 0).len(),
            ALL_FATES.len(),
            "брак прибора обязан давать полный круг, а не сужать его"
        );
    }

    /// Круг адресован цели, не разговору, на котором сужен. Граница `Of = Target` утверждает это до
    /// запуска.
    #[test]
    fn the_circle_is_addressed_to_the_target() {
        fn to_target<W: reflex_core::word::Word<Of = reflex_core::word::Target>>() {}
        to_target::<Admits>();
        to_target::<crate::resolve::Resolved>();
    }

    /// Клетка молчания — `Blind`: `Inconsistent` есть факт о приборе.
    #[test]
    fn the_passport_calls_inconsistency_its_blindness() {
        assert_eq!(ObservedInstrument::SILENCE, Some(crate::Silence::Blind));
    }

    /// Главный режим лжи назван: круг никто не разворачивает.
    #[test]
    fn the_passport_admits_nobody_unfolds_the_circle() {
        assert!(
            ObservedInstrument::LIES
                .iter()
                .any(|lie| lie.contains("НЕ РАЗВОРАЧИВАЕТ НИКТО")),
            "закон, исполняемый только собственным тестом, обязан сказать это в паспорте"
        );
    }
}
