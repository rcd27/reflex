//! СРОК ИСТЁК — оператор времени БЕЗ ЧАСОВ, и с двумя сроками, которые нельзя путать.
//!
//! # Почему сроков два, и это не удобство
//!
//! Срока два, потому что они говорят о РАЗНОМ и путать их значит лгать об источнике знания:
//!
//! * **[`Expiry::Idle`]** — тишина дольше порога. ВЫВОД О МИРЕ: предмет замолчал. Опаздывает
//!   ровно на порог — уход, случившийся на первой секунде минуты, будет назван через минуту.
//! * **[`Expiry::Ceiling`]** — потолок ожидания. УТВЕРЖДЕНИЕ О НАС: мы перестали ждать. Предмет
//!   может быть жив и продолжать говорить; путать это с его молчанием значит «считать своим
//!   знанием своё нетерпение».
//!
//! Один общий `Expired` слил бы их, и потребитель не смог бы отличить факт о мире от факта о
//! себе — при том что решения по ним разные.
//!
//! # Чего этот оператор НЕ знает
//!
//! Ни часов, ни рантайма: время приходит буквой `Tick` из шва ([`crate::interleave`]). Оттого он
//! работает в синхронной плоскости, на записи идёт со скоростью чтения файла, а проверяется
//! таблицей.
//!
//! Цена та же, что у [`crate::debounce`]: момент высказывания квантуется сеткой — срок назовут на
//! первом узле после его наступления, не позже чем через шаг.

use core::time::Duration;
use std::time::Instant;

use smallvec::{smallvec, SmallVec};

use crate::detector::DetectorEvent;
use crate::step::Step;

/// КАКОЙ СРОК ИСТЁК. Два слова, потому что говорят они о РАЗНОМ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expiry {
    /// Предмет молчит дольше порога. Вывод о мире, опаздывающий на порог.
    Idle,
    /// Мы перестали ждать. Утверждение о НАС — предмет может быть жив.
    Ceiling,
}

/// СРОК, НАЗВАННЫЙ ТОМУ, ЗА КЕМ СМОТРЕЛИ.
///
/// # Почему адрес наследуется, а не назначается
///
/// Оператор говорит «ПРЕДМЕТ замолчал», а не «разговор замолчал», и годится сроку разговора, цели,
/// эпизода, канала — всякой стадии, у которой есть события. Прибей область к одной из них — и
/// подпись соврала бы про все остальные. Предмет здесь `T`, адрес берётся у него, и оператор
/// остаётся тем же обобщением, каким был.
pub struct Deadline<T> {
    /// Какой именно срок истёк.
    pub expiry: Expiry,
    /// `fn(T)`, а не `T`: предмет не хранится, авто-трейты его не наследуются.
    subject: core::marker::PhantomData<fn(T)>,
}

impl<T> Deadline<T> {
    /// Назвать срок предмету `T`.
    pub fn of(expiry: Expiry) -> Self {
        Self {
            expiry,
            subject: core::marker::PhantomData,
        }
    }
}

/// АДРЕС БЕРЁТСЯ У ПРЕДМЕТА: срок сказан тому, за кем смотрели.
impl<T: crate::word::Word> crate::word::Word for Deadline<T> {
    type Of = T::Of;
}

// РУКАМИ, А НЕ `derive`: производный код навесил бы `T: Clone`, `T: PartialEq` и прочие баунды,
// ложные по построению — предмет здесь не хранится.
impl<T> Clone for Deadline<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Deadline<T> {}

impl<T> PartialEq for Deadline<T> {
    fn eq(&self, other: &Self) -> bool {
        self.expiry == other.expiry
    }
}

impl<T> Eq for Deadline<T> {}

impl<T> core::fmt::Debug for Deadline<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&self.expiry, f)
    }
}

/// ЧТО ИЗВЕСТНО О ТЕКУЩЕМ ОЖИДАНИИ.
///
/// Алгебраический тип, а не пара `Option` с флагом «уже сказали»: состояние «срок назван и ждём
/// новой жизни» отличается от «ждём первого события» тем, что делать при следующем тике, и флаг
/// рядом с моментами позволил бы собрать пару, которой не бывает.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Waiting {
    /// Ничего не приходило: истекать нечему.
    Unarmed,
    /// Ждём: разговор начался в `opened`, последнее событие было в `last`.
    Since { opened: Instant, last: Instant },
    /// Срок назван; молчим до нового события, которое заведёт ожидание заново.
    Spoken,
}

/// ГОВОРИТ, КОГДА ОЖИДАНИЕ ПЕРЕСТАЛО БЫТЬ ОСМЫСЛЕННЫМ.
///
/// Параметр `T` — тип события, которое оператор ВИДИТ, но не читает: срок считается по моментам, а
/// не по содержимому. Он нужен, чтобы детектор вставал в цепочку своего уровня стека (сегмент,
/// датаграмма) и компилятор проверял стыковку — то есть параметр здесь не украшение, а то самое
/// сужение типа, которым цепочка и держится.
#[derive(Debug, Clone, Copy)]
pub struct Timeout<T> {
    idle_after: Duration,
    ceiling: Duration,
    waiting: Waiting,
    sees: core::marker::PhantomData<T>,
}

impl<T> Timeout<T> {
    /// `idle_after` — сколько тишины считать молчанием предмета; `ceiling` — сколько всего мы
    /// готовы ждать, чем бы предмет ни был занят.
    pub fn new(idle_after: Duration, ceiling: Duration) -> Self {
        Self {
            idle_after,
            ceiling,
            waiting: Waiting::Unarmed,
            sees: core::marker::PhantomData,
        }
    }

    /// КАКОЙ СРОК НАСТУПИЛ К МОМЕНТУ `at`.
    ///
    /// Выигрывает тот, чей момент РАНЬШЕ, а не тот, что проверен первым: иначе порядок проверок в
    /// коде стал бы скрытым правилом, и при потолке короче тишины прибор соврал бы о причине.
    fn crossed(&self, opened: Instant, last: Instant, at: Instant) -> Option<Expiry> {
        let silence = last + self.idle_after;
        let patience = opened + self.ceiling;
        match (at >= silence, at >= patience) {
            (false, false) => None,
            (true, false) => Some(Expiry::Idle),
            (false, true) => Some(Expiry::Ceiling),
            (true, true) => match silence <= patience {
                true => Some(Expiry::Idle),
                false => Some(Expiry::Ceiling),
            },
        }
    }
}

impl<T: crate::word::Word> Step for Timeout<T> {
    type From = DetectorEvent<T>;
    type To = SmallVec<[Deadline<T>; 2]>;
    /// Показаний этот оператор не заводит: он говорит, что увидел, и не говорит, чем мерил.
    type Notes = ();

    fn step(self, event: Self::From) -> (Self, Self::To, ()) {
        match (event, self.waiting) {
            // ВСЯКОЕ СОБЫТИЕ ОТОДВИГАЕТ ТИШИНУ, но не потолок: потолок про то, сколько ждём МЫ.
            (DetectorEvent::Packet { at, .. }, Waiting::Since { opened, .. }) => (
                Self {
                    waiting: Waiting::Since { opened, last: at },
                    ..self
                },
                smallvec![],
                (),
            ),
            // ПЕРВОЕ СОБЫТИЕ ЗАВОДИТ ОЖИДАНИЕ; оно же заводит его заново после названного срока —
            // поток, замерший дважды, обязан дать два высказывания, а не одно длинное.
            (DetectorEvent::Packet { at, .. }, Waiting::Unarmed | Waiting::Spoken) => (
                Self {
                    waiting: Waiting::Since {
                        opened: at,
                        last: at,
                    },
                    ..self
                },
                smallvec![],
                (),
            ),
            (DetectorEvent::Tick { at, .. }, Waiting::Since { opened, last }) => {
                match self.crossed(opened, last, at) {
                    None => (self, smallvec![], ()),
                    Some(expiry) => (
                        Self {
                            waiting: Waiting::Spoken,
                            ..self
                        },
                        smallvec![Deadline::of(expiry)],
                        (),
                    ),
                }
            }
            // Истекать нечему: либо ничего не приходило, либо срок уже назван.
            (DetectorEvent::Tick { .. }, Waiting::Unarmed | Waiting::Spoken) => {
                (self, smallvec![], ())
            }
            // ОПЕРАТОР ВИДИТ `T`, НО НЕ СОДЕРЖИМОЕ — а непонятое даже не гарантирует, что оно
            // вообще нашего предмета: разбор не состоялся раньше, чем стало известно, тому ли
            // разговору байты принадлежат. Считать его «признаком жизни» значило бы отодвигать
            // тишину по факту, которого прибор не вправе утверждать. Ожидание не трогается.
            (DetectorEvent::Opaque { .. }, _) => (self, smallvec![], ()),
        }
    }
}
