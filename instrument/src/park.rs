//! Реестр парка: паспорт снят с типа в ЗНАЧЕНИЕ (типы не перебираются, значения — да). Здесь только
//! снимок и его тип; союзный реестр собирается там, где виден весь парк (приборы живут в нескольких
//! крейтах), и сверяется там же.

/// Паспорт, снятый с типа — ровно оси, по которым парк спрашивают. Полей меньше, чем у трейта:
/// снимок заводится под вопрос, а не как второй способ хранить паспорт (копия разъезжается).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Passport {
    /// Публичное имя прибора — им же подписаны его показания.
    pub instrument: &'static str,
    /// Уровень, на котором лежит улика.
    pub layer: crate::Layer,
    /// Протоколы, на которых улика существует. Пустой — улики нет на проводе.
    pub protocols: &'static [crate::Protocol],
    /// Вопрос, на который прибор отвечает. `None` — не детектор ступени.
    pub rung: Option<crate::Rung>,
    /// Полное имя типа — берётся у компилятора ([`std::any::type_name`]), чтобы не разъехалось с
    /// типом (публичного имени для поиска читателей мало). Читателей ищут по части до `<`.
    pub type_path: &'static str,
    /// Что заставляет прибор высказаться — нужно переписи срока (свои часы против чужого темпа).
    pub cadence: crate::Cadence,
}

/// Снять паспорт с типа. Функция, не метод: она о типе, не об экземпляре. `const`-блок поверяет
/// паспорт таблицей улик при мономорфизации — расхождение есть ошибка сборки. Цена: `cargo check`
/// кода не генерирует и этого не ловит; ловят `build`/`test`, потому тест парка — второй оракул.
pub fn of<I: crate::Instrument>() -> Passport
where
    (I::Out, I::Log): crate::Spoken<Signals = smallvec::SmallVec<[I::Signal; 2]>>,
{
    const {
        assert!(
            crate::passport_holds(I::RUNG, I::PROTOCOLS, I::LAYER),
            "паспорт прибора разошёлся с таблицей улик: ступень объявлена там, где улики нет, \
             либо прибор стоит не на том уровне, либо не назван ни один протокол"
        )
    }

    Passport {
        instrument: I::INSTRUMENT,
        layer: I::LAYER,
        protocols: I::PROTOCOLS,
        rung: I::RUNG,
        type_path: std::any::type_name::<I>(),
        cadence: I::CADENCE,
    }
}

/// Приборы этого крейта, чей паспорт читается здесь. Список рукой (трейт по типам не перебирается);
/// полноту держит тест, сверяющий длину с числом реализаций в дереве.
pub fn here() -> Vec<Passport> {
    vec![
        of::<crate::detect::RstInstrument>(),
        of::<crate::detect::SilenceInstrument>(),
        of::<crate::detect::ThrottledInstrument>(),
        of::<crate::detect::ChokedInstrument>(),
        of::<crate::detect::SynDropInstrument>(),
        of::<crate::poison::DnsPoisonInstrument>(),
        of::<crate::retransmit::RetransmitInstrument>(),
        of::<crate::agreement::AgreementInstrument>(),
        of::<crate::drift::HistoryInstrument>(),
        of::<crate::fate::ObservedInstrument>(),
        of::<crate::pace::PaceInstrument>(),
        of::<crate::resolve::ResolutionInstrument>(),
        of::<crate::sag::SagInstrument>(),
        of::<crate::trust::TrustInstrument>(),
    ]
}

/// Приборы, параметризованные доменным типом: их константы паспорта от параметра не зависят, но
/// прочесть их без конкретного типа Rust не даёт, а тип живёт не здесь. Имена, не заглушки — иначе
/// первый читатель принял бы тестовую пустышку за прибор. Их паспорт читает союзный реестр.
pub const PARAMETERISED: [&str; 3] = ["departure", "episode", "leg"];

#[cfg(test)]
mod tests {
    use super::*;

    /// Реестр полон — иначе вопрос к парку отвечает о ЧАСТИ, оставаясь похожим на ответ о парке.
    /// Считается по дереву; игла собрана `concat!` — строка целиком в исходнике не встречается, и
    /// самосчёт невозможен по построению.
    #[test]
    fn the_registry_lists_every_instrument_of_this_crate() {
        let needle = concat!("crate::", "Instrument", " for ");
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let declared: usize = std::fs::read_dir(&root)
            .expect("каталог исходников читается")
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
            .map(|text| text.matches(needle).count())
            .sum();

        assert_eq!(
            here().len() + PARAMETERISED.len(),
            declared,
            "приборов в дереве {declared}, в реестре {} плюс {} параметризованных",
            here().len(),
            PARAMETERISED.len()
        );
    }

    /// Имена в реестре различны: два прибора под одним именем неразличимы в ленте.
    #[test]
    fn no_two_instruments_share_a_name() {
        let names: std::collections::BTreeSet<&str> =
            here().iter().map(|passport| passport.instrument).collect();

        assert_eq!(names.len(), here().len(), "имена приборов повторяются");
    }
}
