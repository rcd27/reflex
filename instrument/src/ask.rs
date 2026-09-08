//! Вопросы приборов — атомы требования к наблюдению, по одному факту на трейт. Крупный трейт
//! застывает (новый вопрос ломает всех отвечающих); атомы убирают память типом: прибор перечисляет
//! требования в границе (`S: SeveredByPerson + TargetDelivered`), лишний вопрос виден, контракт не
//! застывает, вопросы переиспользуются. Требование = произведение вопросов; различение композита ≤
//! различению частей — граница не даёт назвать вопрос, которого никто не задал.

/// Оборвал ли разговор сам человек (закрыл вкладку, переоткрыл). Не «пришёл сброс»: сброс бывает и
/// от цели, и от нас (замер 29.08: из 23 сбросов 17 наши).
pub trait SeveredByPerson {
    fn severed_by_person(&self) -> bool;
}

/// Успела ли цель отдать хоть байт. Этим «ушёл ни с чем» отличается от «ушёл, получив своё».
pub trait TargetDelivered {
    fn target_delivered(&self) -> bool;
}

/// Сколько разговоров несёт нога в окне — знаменатель всякого суждения о ноге.
pub trait Carrying {
    fn carrying(&self) -> usize;
}

/// Сколько из них застряло — не отдают байт при живом спросе.
pub trait Stalled {
    fn stalled(&self) -> usize;
}

/// Когда эпизод начался. `None` — не начинался, не то же, что «начался давно».
pub trait OpenedAt {
    fn opened_at(&self) -> Option<std::time::Instant>;
}

/// Когда в нём в последний раз что-то происходило.
pub trait LastSeen {
    fn last_seen(&self) -> Option<std::time::Instant>;
}

/// Видели ли уход человека на проводе. Отдельно от `SeveredByPerson` (тот про один разговор, этот
/// про эпизод): слить — объявить эпизод законченным от первой закрытой вкладки.
pub trait PersonLeft {
    fn person_left(&self) -> bool;
}

// Ссылка отвечает так же, как значение: иначе домен клонировал бы наблюдение ради вопроса. Правила
// общие, но новый вопрос-атом добавляет и своё.

impl<T: SeveredByPerson> SeveredByPerson for &T {
    fn severed_by_person(&self) -> bool {
        (*self).severed_by_person()
    }
}

impl<T: TargetDelivered> TargetDelivered for &T {
    fn target_delivered(&self) -> bool {
        (*self).target_delivered()
    }
}

impl<T: Carrying> Carrying for &T {
    fn carrying(&self) -> usize {
        (*self).carrying()
    }
}

impl<T: Stalled> Stalled for &T {
    fn stalled(&self) -> usize {
        (*self).stalled()
    }
}

impl<T: OpenedAt> OpenedAt for &T {
    fn opened_at(&self) -> Option<std::time::Instant> {
        (*self).opened_at()
    }
}

impl<T: LastSeen> LastSeen for &T {
    fn last_seen(&self) -> Option<std::time::Instant> {
        (*self).last_seen()
    }
}

impl<T: PersonLeft> PersonLeft for &T {
    fn person_left(&self) -> bool {
        (*self).person_left()
    }
}

/// Наблюдение, отвечающее на один вопрос, не годится прибору, спрашивающему два — проверка, что
/// граница не украшение. Пример обязан не компилироваться:
///
/// ```compile_fail
/// use reflex_instrument::ask::SeveredByPerson;
/// use reflex_instrument::departure::DepartureInstrument;
/// use reflex_core::mealy::Mealy;
/// use reflex_core::DetectorEvent;
///
/// struct Half(bool);
/// impl SeveredByPerson for Half {
///     fn severed_by_person(&self) -> bool { self.0 }
/// }
///
/// // `TargetDelivered` не реализован — прибор не собирается.
/// let _ = DepartureInstrument::<Half>::new().step(DetectorEvent::packet_now(Half(true)));
/// ```
///
/// А с обоими ответами — собирается:
///
/// ```
/// use reflex_instrument::ask::{SeveredByPerson, TargetDelivered};
/// use reflex_instrument::departure::{DepartureInstrument, Left};
/// use reflex_core::mealy::Mealy;
/// use reflex_core::DetectorEvent;
///
/// struct Whole { severed: bool, delivered: bool }
/// impl SeveredByPerson for Whole {
///     fn severed_by_person(&self) -> bool { self.severed }
/// }
/// impl TargetDelivered for Whole {
///     fn target_delivered(&self) -> bool { self.delivered }
/// }
///
/// let seen = Whole { severed: true, delivered: false };
/// let (_, said, ()) = DepartureInstrument::new().step(DetectorEvent::packet_now(seen));
/// assert_eq!(said.as_slice(), &[Left::Unserved]);
/// ```
pub const BOUND_HOLDS: () = ();
