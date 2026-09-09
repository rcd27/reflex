//! Срок истёк — оператор времени без часов, с двумя сроками, которые нельзя путать (канон §8).
//! [`Expiry::Idle`] — тишина дольше порога: вывод О МИРЕ (предмет замолчал), опаздывает на порог.
//! [`Expiry::Ceiling`] — потолок ожидания: утверждение О НАС (мы перестали ждать; предмет может быть
//! жив). Один общий `Expired` слил бы факт о мире с фактом о себе — а решения по ним разные. Ни
//! часов, ни рантайма: время буквой `Tick` из шва ([`crate::interleave`]). Цена как у
//! [`crate::debounce`]: срок назовут на первом узле после наступления, не позже шага.

use core::time::Duration;
use std::time::Instant;

use smallvec::{smallvec, SmallVec};

use crate::detector::DetectorEvent;
use crate::mealy::Mealy;

/// Какой срок истёк. Два слова, потому что говорят о РАЗНОМ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expiry {
    /// Предмет молчит дольше порога. Вывод о мире, опаздывающий на порог.
    Idle,
    /// Мы перестали ждать. Утверждение о НАС — предмет может быть жив.
    Ceiling,
}

/// Срок, названный тому, за кем смотрели. Адрес наследуется, не назначается: оператор говорит
/// «ПРЕДМЕТ замолчал» и годится сроку разговора, цели, эпизода, канала — всякой стадии с событиями;
/// прибей область к одной — подпись соврала бы про остальные. Предмет `T`, адрес берётся у него.
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

/// Адрес берётся у предмета: срок сказан тому, за кем смотрели.
impl<T: crate::word::Word> crate::word::Word for Deadline<T> {
    type Of = T::Of;
}

// Руками, а не `derive`: производный код навесил бы `T: Clone`/`T: PartialEq`, ложные по построению
// — предмет здесь не хранится.
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

/// Что известно о текущем ожидании. Алгебраический тип, не пара `Option` с флагом «уже сказали»:
/// «срок назван и ждём новой жизни» отличается от «ждём первого события» тем, что делать при
/// следующем тике, а флаг рядом с моментами позволил бы собрать пару, которой не бывает.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Waiting {
    /// Ничего не приходило: истекать нечему.
    Unarmed,
    /// Ждём: разговор начался в `opened`, последнее событие было в `last`.
    Since { opened: Instant, last: Instant },
    /// Срок назван; молчим до нового события, которое заведёт ожидание заново.
    Spoken,
}

/// Говорит, когда ожидание перестало быть осмысленным. Параметр `T` — тип события, которое оператор
/// ВИДИТ, но не читает (срок по моментам, не по содержимому): он ставит детектор в цепочку своего
/// уровня стека, компилятор проверяет стыковку — то самое сужение типа, которым цепочка держится.
#[derive(Debug, Clone, Copy)]
pub struct Timeout<T> {
    idle_after: Duration,
    ceiling: Duration,
    waiting: Waiting,
    sees: core::marker::PhantomData<T>,
}

impl<T> Timeout<T> {
    /// `idle_after` — сколько тишины считать молчанием предмета; `ceiling` — сколько всего мы готовы
    /// ждать, чем бы предмет ни был занят.
    pub fn new(idle_after: Duration, ceiling: Duration) -> Self {
        Self {
            idle_after,
            ceiling,
            waiting: Waiting::Unarmed,
            sees: core::marker::PhantomData,
        }
    }

    /// Какой срок наступил к моменту `at`. Выигрывает тот, чей момент РАНЬШЕ, не проверенный первым:
    /// иначе порядок проверок стал бы скрытым правилом, и при потолке короче тишины прибор соврал бы
    /// о причине.
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

impl<T: crate::word::Word> Mealy for Timeout<T> {
    type In = DetectorEvent<T>;
    type Out = SmallVec<[Deadline<T>; 2]>;
    /// Показаний не заводит: говорит, что увидел, не говорит, чем мерил.
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        match (event, self.waiting) {
            // Всякое событие отодвигает тишину, но не потолок: потолок про то, сколько ждём МЫ.
            (DetectorEvent::Packet { at, .. }, Waiting::Since { opened, .. }) => (
                Self {
                    waiting: Waiting::Since { opened, last: at },
                    ..self
                },
                smallvec![],
                (),
            ),
            // Первое событие заводит ожидание; оно же заводит заново после названного срока — поток,
            // замерший дважды, обязан дать два высказывания, не одно длинное.
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
            // Оператор видит `T`, но не содержимое — а непонятое даже не гарантирует, что оно нашего
            // предмета (разбор не состоялся раньше, чем стало известно, тому ли разговору байты).
            // Считать его признаком жизни значило бы отодвигать тишину по неутверждаемому факту.
            (DetectorEvent::Opaque { .. }, _) => (self, smallvec![], ()),
        }
    }
}
