//! СУДЬБА ЦЕЛИ — типология, ОБЩАЯ для прибора и обоих движков.
//!
//! # Чья это судьба, и почему вопрос не праздный
//!
//! Судьбу УСТАНАВЛИВАЕТ плечо, но принадлежит она ЦЕЛИ: «сервер не ответил», «заглушка CDN»,
//! «ресурс тот самый» суть свойства того, к кому шли, а не того соединения, на котором это
//! выяснилось. Плечо здесь — способ узнать и момент, когда круг сужается; спутать способ с
//! адресатом значит адресовать вывод разговору, который к этому мигу уже кончился.
//!
//! Модель здесь же: `zond/model/ByteOracleSearch.tla`. Невод 1 держит свою копию
//! (#284) и прямо говорит зачем: «копировать механизм не нужно;
//! разделить ИМЕНА — нужно, иначе одна болезнь называется в двух крейтах по-разному и не
//! складывается». Здесь то самое общее место, из которого имена берутся.
//!
//! # Две оси, и путать их нельзя
//!
//! [`Fate`] — СКРЫТАЯ правда о цели, наблюдению не данная никогда.
//! [`Observed`] — что наблюдатель УСТАНОВИЛ. Он не называет судьбу, он СУЖАЕТ круг возможных
//! ([`Observed::admits`]).
//!
//! # Почему это не педантизм
//!
//! Продукт различал две судьбы — «доставили» и «нет». Отсюда болезни, которые нечем было даже
//! назвать: у владельца ролик не стартует (три дня разбора), у Игоря видео замирает 110 раз в
//! сутки — а приборы зелены, потому что байты пришли.

/// Скрытая правда о цели. Пять судеб, у каждой своё лечение.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Fate {
    /// Сервер не ответил вовсе — рукопожатие не собралось.
    Dead,
    /// Рукопожатие есть, байтов нет: поздоровался впустую. Прямой путь при этом ЖИВ на
    /// транспорте, и лечение здесь другое, чем у `Dead`, — потому судьбы и разные.
    Trap,
    /// Байты текут, а ресурса нет: заглушка CDN, парковка, чужой сертификат.
    Mirage,
    /// Ресурс тот самый и байты полные, но добыты ПОВТОРАМИ — платится временем человека.
    Grinding,
    /// Ресурс тот самый, байты полные, лишнего не заплачено.
    Good,
}

/// Все судьбы. Круг, не сужённый ничем, — то есть «не установлено ничего».
pub const ALL_FATES: [Fate; 5] = [
    Fate::Dead,
    Fate::Trap,
    Fate::Mirage,
    Fate::Grinding,
    Fate::Good,
];

/// Что УСТАНОВЛЕНО пассивным наблюдением одного плеча.
///
/// Это НЕ судьба, а показание прибора. Пять вариантов, и два последних — не педантизм, а
/// честность прибора о самом себе.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observed {
    /// TCP не встал: сервер не поздоровался. Человек смотрит на крутилку.
    NoConnect,
    /// Встал и молчит: поздоровался впустую. Объявить такое плечо мёртвым — значит похоронить
    /// живой прямой путь.
    Mute,
    /// Байты пришли — и это ВСЁ, что установлено. Не «работает».
    Bytes,
    /// Плечо БРОШЕНО: ждать перестали сами. О судьбе не установлено ничего, и честный прибор
    /// возвращает полный круг, а не подставляет «молчало».
    ///
    /// Оплачено полем: подставлялось именно оно, и 8 из 28 доменов парка оказались заперты
    /// приговором за молчание, которого никто не слышал.
    Unobserved,
    /// Байты без установленного коннекта — наблюдение противоречиво. Это факт о ПРИБОРЕ, а не о
    /// цели. Отдельным вариантом, а не молчаливой склейкой с [`Observed::Bytes`], — иначе брак
    /// прибора выглядел бы как успех.
    Inconsistent,
}

impl Observed {
    /// Круг судеб, совместимых с этим показанием (`Lights` из `ByteOracleSearch.tla`).
    ///
    /// ЗАКОН (`PassiveFate::Sound`): истинная судьба ВСЕГДА внутри круга. Утверждать уже —
    /// значит утверждать больше, чем установлено.
    pub const fn admits(self) -> &'static [Fate] {
        match self {
            Observed::NoConnect => &[Fate::Dead],
            Observed::Mute => &[Fate::Trap],
            // ТРИ судьбы, а не одна. Пассивно они не делятся ничем: содержимое закрыто, и ECH
            // это закрепит. Различает их только активная проба.
            Observed::Bytes => &[Fate::Mirage, Fate::Grinding, Fate::Good],
            Observed::Unobserved => &ALL_FATES,
            Observed::Inconsistent => &ALL_FATES,
        }
    }

    /// Имя для витнеса. Низкокардинально — атрибут спана, по которому суточные числа считаются
    /// запросом к приёмнику, без отдельного прибора на коробке.
    pub const fn name(self) -> &'static str {
        match self {
            Observed::NoConnect => "NoConnect",
            Observed::Mute => "Mute",
            Observed::Bytes => "Bytes",
            Observed::Unobserved => "Unobserved",
            Observed::Inconsistent => "Inconsistent",
        }
    }

    /// Оплачено ли человеком ожидание, которое НИЧЕГО ему не принесло.
    ///
    /// В единице человека: для [`Observed::NoConnect`] и [`Observed::Mute`] длительность плеча и
    /// есть время, прожданное впустую. Для [`Observed::Bytes`] — нет: байты пришли, и было ли
    /// ожидание лишним, пассивно не установить.
    pub const fn wasted_the_wait(self) -> bool {
        match self {
            Observed::NoConnect => true,
            Observed::Mute => true,
            Observed::Bytes => false,
            // Плечо бросили МЫ — это не сервер заставил ждать.
            Observed::Unobserved => false,
            Observed::Inconsistent => false,
        }
    }
}

/// ЧТО СЛУЧИЛОСЬ С БАЙТАМИ на одном плече. Ось, отдельная от того, встал ли коннект.
///
/// Три исхода, и третий не декоративен: плечо, которое БРОСИЛИ, наблюдалось не полностью, и
/// свидетельствовать о цели не может. Слить его с молчанием — значит вынести приговор за
/// молчание, которого никто не слышал.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Плечо доставило байты.
    Delivered,
    /// Плечо НАБЛЮДАЛОСЬ всё своё окно и молчало.
    Silent,
    /// Плечо брошено: ждать перестали сами. О пути не установлено ничего — ни хорошего, ни
    /// плохого.
    Abandoned,
}

/// Что установило наблюдение одного плеча. Чистая функция от фактов, которые край уже собрал:
/// ни нового наблюдения, ни IO здесь нет.
///
/// РАЗБОР ТОТАЛЕН ПО ОБЕИМ ОСЯМ — шесть пар, все выписаны. `connected` и `delivery` суть РАЗНЫЕ
/// факты: первый про транспорт (сервер ответил на SYN), второй про байты. Их слияние и есть та
/// бедность словаря, из-за которой продукт знал две судьбы вместо пяти.
pub const fn observe(connected: bool, delivery: Delivery) -> Observed {
    match (connected, delivery) {
        // Брошенное плечо не свидетельствует ни о чём — независимо от того, встал ли коннект.
        (false, Delivery::Abandoned) => Observed::Unobserved,
        (true, Delivery::Abandoned) => Observed::Unobserved,
        (false, Delivery::Silent) => Observed::NoConnect,
        (true, Delivery::Silent) => Observed::Mute,
        // Байты без коннекта — брак прибора, а не судьба цели.
        (false, Delivery::Delivered) => Observed::Inconsistent,
        (true, Delivery::Delivered) => Observed::Bytes,
    }
}

/// КРУГ ДОПУСКАЕМЫХ СУДЕБ — с именем, а не голой ссылкой на срез.
///
/// Имя заведено затем, что адрес объявляет ЗНАЧЕНИЕ, а ссылка на статический срез значением
/// прибора не является: она кусок общей памяти, и сказать за неё «кому это сказано» нельзя.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Admits(pub &'static [Fate]);

/// СКАЗАНО ЦЕЛИ: круг перечисляет судьбы ЦЕЛИ, а не свойства соединения.
///
/// Конец плеча — момент, когда круг сужается, а не адресат: разговор к этому мигу кончился, и
/// сказанное ему пропало бы вместе с ним. Тот же адресат, что у [`crate::resolve::Resolved`], и по
/// той же причине — оба говорят о том, к кому шли.
impl reflex_core::word::Word for Admits {
    type Of = reflex_core::word::Target;
}

/// ПАСПОРТ ПАССИВНОГО НАБЛЮДЕНИЯ СУДЬБЫ — проекция `model/law/Instrument.tla`.
///
/// САМОЕ СИЛЬНОЕ РАЗЛИЧЕНИЕ ПАРКА И САМОЕ НЕПОДКЛЮЧЁННОЕ. Показание не называет судьбу, оно
/// СУЖАЕТ круг ([`Observed::admits`], закон `PassiveFate::Sound`) — и этим отличается от всех
/// прочих приборов, которые отвечают одним значением.
pub struct ObservedInstrument;

impl ObservedInstrument {
    /// Показание в круг судеб. Момент не используется: судьба доопределяется концом плеча, а он
    /// уже наступил.
    fn read(&self, observation: &Observed, _now_ms: u64) -> &'static [Fate] {
        observation.admits()
    }
}

impl reflex_core::step::Step for ObservedInstrument {
    /// НАБЛЮДЕНИЕ, которое подают прибору.
    type From = reflex_core::DetectorEvent<Observed>;

    /// СЛОВО. Отсутствие слова сигналом не является: прибор высказывается, когда есть что
    /// сказать, и «ничего не случилось» не занимает места в ленте.
    type To = smallvec::SmallVec<[Admits; 2]>;

    /// Показаний этот прибор не заводит: он говорит, что увидел, и не говорит, чем мерил.
    type Notes = ();

    fn step(self, event: Self::From) -> (Self, Self::To, ()) {
        match event {
            reflex_core::DetectorEvent::Packet { input, .. } => {
                let reading = self.read(&input, 0);
                (self, smallvec::smallvec![Admits(reading)], ())
            }
            reflex_core::DetectorEvent::Tick { .. } => (self, smallvec::SmallVec::new(), ()),
            // Прибор мерит РАЗОБРАННЫЙ домен; непонятое им не является и молчит так же, как тик.
            reflex_core::DetectorEvent::Opaque { .. } => (self, smallvec::SmallVec::new(), ()),
        }
    }
}

impl crate::Instrument for ObservedInstrument {
    type Signal = Admits;

    const INSTRUMENT: &'static str = "observed";

    const SUBJECT: crate::Subject = crate::Subject::World;

    /// УРОВЕНЬ: судьба цели решается тем, отозвалась ли она; TLS закрыт, и выше этого уровня
    /// прибор пассивно не видит.
    const LAYER: crate::Layer = crate::Layer::Transport;
    /// ТРАНСПОРТЫ: судьба решается тем, отозвалась ли цель, и «отозвалась» видно у обоих.
    const PROTOCOLS: &'static [crate::Protocol] = &[crate::Protocol::Tcp, crate::Protocol::Udp];
    const RUNG: Option<crate::Rung> = Some(crate::Rung::Answered);

    /// КОНЕЦ ПЛЕЧА — то есть отложенный трафик. Для судьбы цели это законно: круг доопределяется,
    /// только когда плечо кончилось.
    const CADENCE: crate::Cadence = crate::Cadence::Foreign;

    /// ВЕРДИКТ: показание сужает круг возможных судеб. Единственный такой в парке — прочие дают
    /// событие, состояние или величину.
    const SHAPE: crate::Shape = crate::Shape::Verdict;

    /// `Inconsistent` И ЕСТЬ КЛЕТКА «ПРИБОР НЕ СМОГ»: байты без установленного коннекта суть факт
    /// о ПРИБОРЕ, а не о цели, и круг у него полный. Заведена отдельным вариантом намеренно —
    /// молчаливая склейка с `Bytes` выдавала бы брак прибора за успех.
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

    /// СМЕРТЬ: круг разворачивается ПРОДУКТОМ, а не тестом, — тогда подключённость перестаёт быть
    /// нулевой, и паспорт переписывается вместе с ней.
    const DEATH: &'static str = "`admits()` вызывается в живом входе, а не только в тестах";

    /// ПУБЛИЧНЫЕ ИМЕНА СОБЫТИЙ — реестр, снятый с типа: за границей процесса имя показания не
    /// сторожит компилятор, и `Debug` сменил бы метку молча (#321).
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

    /// Какое показание даёт прибор на плече, чья истинная судьба — `f`. Обратное к `SignalOf`
    /// из модели: нужно, чтобы проверить закон `Sound` на КОДЕ, а не только в TLC.
    fn leg_of(f: Fate) -> (bool, Delivery) {
        match f {
            Fate::Dead => (false, Delivery::Silent),
            Fate::Trap => (true, Delivery::Silent),
            Fate::Mirage => (true, Delivery::Delivered),
            Fate::Grinding => (true, Delivery::Delivered),
            Fate::Good => (true, Delivery::Delivered),
        }
    }

    /// ЗАКОН `PassiveFate::Sound`: правда ВСЕГДА внутри названного круга. Проверяется на ВСЕХ
    /// пяти судьбах, а не на удобных: круг, промахнувшийся хоть по одной, есть ложное
    /// утверждение.
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

    /// МОЛЧАНИЕ ПОСЛЕ РУКОПОЖАТИЯ НЕ ЕСТЬ СМЕРТЬ. Сервер поздоровался — транспорт жив, и
    /// объявить путь мёртвым значит похоронить работающий.
    #[test]
    fn silence_after_a_handshake_is_not_death() {
        let seen = observe(true, Delivery::Silent);
        assert_eq!(seen, Observed::Mute);
        assert!(!seen.admits().contains(&Fate::Dead));
    }

    /// ПРОТИВОРЕЧИЕ НЕ ВЫДАЁТ СЕБЯ ЗА УСПЕХ. Байты без коннекта — брак прибора; засчитать это
    /// за доставку значило бы прятать собственную поломку под видом победы.
    #[test]
    fn a_contradiction_does_not_pass_itself_off_as_success() {
        let seen = observe(false, Delivery::Delivered);
        assert_eq!(seen, Observed::Inconsistent);
        assert_eq!(seen.admits().len(), ALL_FATES.len());
    }

    /// БРОШЕННОЕ ПЛЕЧО НИЧЕГО НЕ УСТАНАВЛИВАЕТ — при любом состоянии коннекта.
    #[test]
    fn an_abandoned_leg_establishes_nothing_either_way() {
        assert_eq!(observe(true, Delivery::Abandoned), Observed::Unobserved);
        assert_eq!(observe(false, Delivery::Abandoned), Observed::Unobserved);
    }

    /// ГЛАВНЫЙ ЗАКОН ТИПОЛОГИИ: показание сужает круг, но никогда не пустеет — иначе прибор
    /// утверждал бы невозможное.
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

    /// БАЙТЫ НЕ ЗНАЧАТ «РАБОТАЕТ». Три судьбы пассивно неразличимы, и тип обязан это говорить,
    /// а не выбирать из них лучшую.
    #[test]
    fn bytes_alone_admit_three_fates() {
        assert_eq!(Observed::Bytes.admits().len(), 3);
        assert!(Observed::Bytes.admits().contains(&Fate::Mirage));
    }

    /// БРОШЕННОЕ ПЛЕЧО НЕ СВИДЕТЕЛЬСТВУЕТ НИ О ЧЁМ. Прежде подставлялось «молчало», и 8 из 28
    /// доменов парка оказались заперты приговором за молчание, которого никто не слышал.
    #[test]
    fn an_abandoned_leg_narrows_nothing() {
        assert_eq!(Observed::Unobserved.admits().len(), ALL_FATES.len());
    }

    /// Впустую прожданным считается только то ожидание, которое ничего не принесло И которое
    /// заставил ждать сервер, а не мы сами.
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

    /// ПАСПОРТ ОТДАЁТ КРУГ, А НЕ СУДЬБУ. Три показания разной ширины: вырожденный круг,
    /// честная тройка, полный круг при отказе прибора.
    ///
    /// Одного значения мало: прибор, возвращающий всегда `ALL_FATES`, прошёл бы проверку на любом
    /// одном входе — и был бы бесполезен, оставаясь честным.
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

    /// КРУГ АДРЕСОВАН ЦЕЛИ, А НЕ РАЗГОВОРУ, НА КОТОРОМ ОН СУЖЕН.
    ///
    /// Конец плеча — момент, а не адресат. Сказанное разговору пропало бы вместе с ним: круг
    /// сужается ровно тогда, когда разговор уже кончился.
    ///
    /// Адрес проверяет компилятор: `type_name` формата не гарантирует, а граница `Of = Target`
    /// утверждает то же и до запуска.
    #[test]
    fn the_circle_is_addressed_to_the_target() {
        fn to_target<W: reflex_core::word::Word<Of = reflex_core::word::Target>>() {}
        // Круг судеб говорит о цели — и о ней же говорит разрешение имени. Два слова об одном
        // предмете обязаны быть адресованы одинаково.
        to_target::<Admits>();
        to_target::<crate::resolve::Resolved>();
    }

    /// КЛЕТКА МОЛЧАНИЯ — `Blind`: `Inconsistent` есть факт О ПРИБОРЕ, а не о цели.
    #[test]
    fn the_passport_calls_inconsistency_its_blindness() {
        assert_eq!(ObservedInstrument::SILENCE, Some(crate::Silence::Blind));
    }

    /// ГЛАВНЫЙ РЕЖИМ ЛЖИ НАЗВАН: круг никто не разворачивает.
    ///
    /// Это прибор с максимальным различением и нулевой подключённостью — два разных множителя,
    /// которые без разведения читаются одинаково («прибор не подключён») и чинятся не тем.
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
