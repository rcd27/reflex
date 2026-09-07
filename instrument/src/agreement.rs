//! СОГЛАСИЕ ЯДРА — применилось ли то, что мы приказали.
//!
//! Переехал из другого крейта при сведении детекции в один дом.

/// СОШЛИСЬ ЛИ ДВЕ ТОЧКИ НАБЛЮДЕНИЯ ОДНОГО ПУТИ (#318).
///
/// Не `bool` и не число: расхождение разнозначно, и знак его есть диагноз. Перечисление
/// обязывает разобрать все исходы, а «не сошлось» слило бы противоположные беды в одну.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agreement {
    /// Сколько пометили, столько ядро и увело.
    Agreed { both: u64 },
    /// ПОМЕТИЛИ, НО НЕ УВЕЛИ: приказ применён нами и потерян ядром — правило не стоит, стоит не
    /// в том хуке либо метка не та. Наша болезнь номер один.
    MarkedNotSteered { ours: u64, kernel: u64 },
    /// УВЕЛИ БОЛЬШЕ, ЧЕМ ПОМЕТИЛИ: через цепочку идёт чужой трафик, правило шире задуманного.
    SteeredNotMarked { ours: u64, kernel: u64 },
    /// СВИДЕТЕЛЯ НЕТ — сверять не с чем. Это не «не сошлось» и молчать об этом нельзя: зелёный
    /// отчёт при отсутствующем свидетеле и есть тот случай, ради которого сверка заводится.
    NoWitness { ours: u64 },
}

/// СВЕРКА НИКОМУ НЕ СКАЗАНА: она копится в отчёт, и ни пакет, ни разговор, ни цель её не ждут.
impl reflex_core::word::Word for Agreement {
    type Of = reflex_core::word::Nobody;
}

/// ПАСПОРТ СВИДЕТЕЛЬСТВА ПРИМЕНЕНИЯ — проекция `model/law/Instrument.tla`.
///
/// Прибор о НАС: он отвечает на вопрос «наш приказ исполнился?» — и отвечает ЯДРОМ, а не
/// собственным журналом. Разница принципиальная: журнал говорит, что мы ПРИКАЗАЛИ; счётчик
/// правила говорит, что ядро СДЕЛАЛО.
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

impl reflex_core::step::Step for AgreementInstrument {
    /// НАБЛЮДЕНИЕ, которое подают прибору.
    type From = reflex_core::DetectorEvent<(u64, Option<u64>)>;

    /// ПОКАЗАНИЕ. Отсутствие показания сигналом не является: прибор высказывается, когда есть что
    /// сказать, и «ничего не случилось» не занимает места в ленте.
    type To = smallvec::SmallVec<[Agreement; 2]>;

    /// Показаний этот прибор не заводит: он говорит, что увидел, и не говорит, чем мерил.
    type Notes = ();

    fn step(self, event: Self::From) -> (Self, Self::To, ()) {
        match event {
            reflex_core::DetectorEvent::Packet { input, .. } => {
                let reading = self.read(&input, 0);
                (self, smallvec::smallvec![reading], ())
            }
            reflex_core::DetectorEvent::Tick { .. } => (self, smallvec::SmallVec::new(), ()),
            // Прибор мерит РАЗОБРАННЫЙ домен; непонятое им не является и молчит так же, как тик.
            reflex_core::DetectorEvent::Opaque { .. } => (self, smallvec::SmallVec::new(), ()),
        }
    }
}

impl crate::Instrument for AgreementInstrument {
    type Signal = Agreement;

    const INSTRUMENT: &'static str = "agreement";

    const SUBJECT: crate::Subject = crate::Subject::Ourselves;

    /// УРОВЕНЬ: применилось ли правило в netfilter — уровень адреса, где правило и стоит.
    const LAYER: crate::Layer = crate::Layer::Network;
    /// УЛИКИ НА ПРОВОДЕ НЕТ ВОВСЕ — она есть счётчик netfilter, то есть наша собственная машина.
    /// Пустой список это и говорит; прежнее `Any` утверждало ровно противоположное.
    const PROTOCOLS: &'static [crate::Protocol] = &[];
    const RUNG: Option<crate::Rung> = None;

    /// СВОИ ЧАСЫ: счётчик опрашивается тиком отчётчика. Предмет (расхождение приказа с
    /// исполнением) меняется САМ и в тишине — правило может перестать матчить, пока трафика нет.
    const CADENCE: crate::Cadence = crate::Cadence::Own { step_ms: 2_000 };

    /// СОСТОЯНИЕ: у согласия есть равенство, и переход «сошлось → разошлось» и есть событие,
    /// ради которого прибор заведён. Опрос счётчика без `distinct_until_changed` даёт `4096` на
    /// каждый вопрос — величин много, событие одно.
    const SHAPE: crate::Shape = crate::Shape::State;

    /// `NoWitness` — «спросить не у кого»: правила нет, счётчик недоступен. Это `Blind`, а не
    /// `Nothing`: «применялось ноль раз» и «свидетеля нет» дают одно число и противоположное
    /// лечение.
    const SILENCE: Option<crate::Silence> = Some(crate::Silence::Blind);

    const LIES: &'static [&'static str] = &[
        "ПОСТРОЕН И НЕ ПОДКЛЮЧЁН. Единственный читатель — `nevod2-runtime/examples/kernel-witness.rs`, \
         то есть ПРИМЕР, а не живой вход. Прибор, свидетельствующий применение приказов, сам не \
         применён.",
        "ЦЕНА ОПРОСА ЗАМЕРЕНА И ВЫСОКА: `/proc` ×4,6 к стоимости вердикта, `nft` ×760. Поэтому \
         решётка — свои часы с шагом 2 с, а не пакет; на горячий путь этот прибор ставить нельзя.",
        "СЧЁТЧИК ЯДРА МОНОТОНЕН И ПЕРЕЖИВАЕТ НАС. После перезапуска процесса `ours` начинается с \
         нуля, а `kernel` продолжает расти — и `SteeredNotMarked` наступит на ровном месте. \
         Сверять нужно ПРИРАЩЕНИЯ, а не значения; сегодня это на совести потребителя.",
    ];

    const ORACLES: &'static [&'static str] = &["pass", "sni_drop(rutracker.org)"];

    /// СМЕРТЬ: свидетельство читается живым входом и сверяется приращениями — тогда первый и
    /// третий режимы лжи умирают вместе.
    const DEATH: &'static str =
        "живой вход читает свидетельство и сверяет приращения, а не значения";

    /// ПУБЛИЧНЫЕ ИМЕНА СОБЫТИЙ — реестр, снятый с типа: за границей процесса имя показания не
    /// сторожит компилятор, и `Debug` сменил бы метку молча (#321).
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
