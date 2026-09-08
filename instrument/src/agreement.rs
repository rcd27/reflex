//! Согласие ядра — применилось ли то, что мы приказали.

/// Сошлись ли две точки наблюдения одного пути. Не `bool` и не число: знак расхождения — диагноз,
/// перечисление обязывает разобрать все исходы.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agreement {
    /// Сколько пометили, столько ядро и увело.
    Agreed { both: u64 },
    /// Пометили, но не увели: приказ применён нами и потерян ядром (правило не стоит или метка не
    /// та). Болезнь номер один.
    MarkedNotSteered { ours: u64, kernel: u64 },
    /// Увели больше, чем пометили: через цепочку идёт чужой трафик, правило шире задуманного.
    SteeredNotMarked { ours: u64, kernel: u64 },
    /// Свидетеля нет — сверять не с чем. Не «не сошлось»: зелёный отчёт при отсутствующем
    /// свидетеле и есть то, ради чего сверка заводится.
    NoWitness { ours: u64 },
}

/// Прибор о нас: «наш приказ исполнился?» — и отвечает ЯДРОМ (счётчик правила), а не журналом
/// (журнал говорит, что мы приказали).
pub struct AgreementInstrument;

impl AgreementInstrument {
    fn read(&self, observation: &(u64, Option<u64>), _now_ms: u64) -> Agreement {
        let (ours, kernel) = *observation;
        match kernel {
            None => Agreement::NoWitness { ours },
            Some(kernel) => match (ours == kernel, ours > kernel) {
                (true, _) => Agreement::Agreed { both: ours },
                (false, true) => Agreement::MarkedNotSteered { ours, kernel },
                (false, false) => Agreement::SteeredNotMarked { ours, kernel },
            },
        }
    }
}

impl reflex_core::mealy::Mealy for AgreementInstrument {
    type In = reflex_core::DetectorEvent<(u64, Option<u64>)>;
    /// Сказать соседу нечего: у сверки нет области — её ждёт человек за границей цепочки.
    type Out = ();
    /// Показание. Молчание сигналом не является.
    type Log = smallvec::SmallVec<[Agreement; 2]>;

    fn step(self, event: Self::In) -> (Self, (), Self::Log) {
        match event {
            reflex_core::DetectorEvent::Packet { input, .. } => {
                let reading = self.read(&input, 0);
                (self, (), smallvec::smallvec![reading])
            }
            reflex_core::DetectorEvent::Tick { .. } | reflex_core::DetectorEvent::Opaque { .. } => {
                (self, (), smallvec::SmallVec::new())
            }
        }
    }
}

impl crate::Instrument for AgreementInstrument {
    type Signal = Agreement;

    const INSTRUMENT: &'static str = "agreement";

    const SUBJECT: crate::Subject = crate::Subject::Ourselves;

    /// Уровень: применилось ли правило netfilter — уровень адреса.
    const LAYER: crate::Layer = crate::Layer::Network;
    /// Улики на проводе нет — она счётчик netfilter, наша собственная машина.
    const PROTOCOLS: &'static [crate::Protocol] = &[];
    const RUNG: Option<crate::Rung> = None;

    /// Свои часы: счётчик опрашивается тиком. Расхождение меняется само и в тишине.
    const CADENCE: crate::Cadence = crate::Cadence::Own { step_ms: 2_000 };

    /// Состояние: переход «сошлось → разошлось» и есть событие. Опрос без учёта смены даёт `4096`
    /// на каждый вопрос — величин много, событие одно.
    const SHAPE: crate::Shape = crate::Shape::State;

    /// `NoWitness` — «спросить не у кого»: `Blind`, не `Nothing` («ноль раз» и «свидетеля нет»
    /// дают одно число, лечение противоположное).
    const SILENCE: Option<crate::Silence> = Some(crate::Silence::Blind);

    const LIES: &'static [&'static str] = &[
        "ПОСТРОЕН И НЕ ПОДКЛЮЧЁН. Единственный читатель — пример потребителя, \
         то есть ПРИМЕР, а не живой вход. Прибор, свидетельствующий применение приказов, сам не \
         применён.",
        "ЦЕНА ОПРОСА ЗАМЕРЕНА И ВЫСОКА: `/proc` ×4,6 к стоимости вердикта, `nft` ×760. Поэтому \
         решётка — свои часы с шагом 2 с, а не пакет; на горячий путь этот прибор ставить нельзя.",
        "СЧЁТЧИК ЯДРА МОНОТОНЕН И ПЕРЕЖИВАЕТ НАС. После перезапуска процесса `ours` начинается с \
         нуля, а `kernel` продолжает расти — и `SteeredNotMarked` наступит на ровном месте. \
         Сверять нужно ПРИРАЩЕНИЯ, а не значения; сегодня это на совести потребителя.",
    ];

    const ORACLES: &'static [&'static str] = &["pass", "sni_drop(rutracker.org)"];

    const DEATH: &'static str =
        "живой вход читает свидетельство и сверяет приращения, а не значения";

    const EVENTS: &'static [&'static str] = &[
        "agreed",
        "marked_not_steered",
        "steered_not_marked",
        "no_witness",
    ];

    fn name(signal: &Self::Signal) -> &'static str {
        match signal {
            Agreement::Agreed { .. } => "agreed",
            Agreement::MarkedNotSteered { .. } => "marked_not_steered",
            Agreement::SteeredNotMarked { .. } => "steered_not_marked",
            Agreement::NoWitness { .. } => "no_witness",
        }
    }

    fn alarming(signal: &Self::Signal) -> bool {
        match signal {
            Agreement::Agreed { .. } => false,
            Agreement::MarkedNotSteered { .. }
            | Agreement::SteeredNotMarked { .. }
            | Agreement::NoWitness { .. } => true,
        }
    }
}
