//! СРОК ИСТЁК — оператор времени БЕЗ ЧАСОВ, и с двумя сроками, которые нельзя путать.
//!
//! # Почему сроков два, и это не удобство
//!
//! Форма взята замером продукта (`reflex_instrument::episode`), а не выдумана. Там сроков два, и собственный
//! паспорт прибора называет их смешение ложью:
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

use crate::detector::{Detector, DetectorEvent};

/// КАКОЙ СРОК ИСТЁК. Два слова, потому что говорят они о РАЗНОМ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expiry {
    /// Предмет молчит дольше порога. Вывод о мире, опаздывающий на порог.
    Idle,
    /// Мы перестали ждать. Утверждение о НАС — предмет может быть жив.
    Ceiling,
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

impl<T> Detector for Timeout<T> {
    type Input = T;
    type Signal = Expiry;

    fn step(self, event: DetectorEvent<Self::Input>) -> (Self, SmallVec<[Self::Signal; 2]>) {
        match (event, self.waiting) {
            // ВСЯКОЕ СОБЫТИЕ ОТОДВИГАЕТ ТИШИНУ, но не потолок: потолок про то, сколько ждём МЫ.
            (DetectorEvent::Packet { at, .. }, Waiting::Since { opened, .. }) => (
                Self {
                    waiting: Waiting::Since { opened, last: at },
                    ..self
                },
                smallvec![],
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
            ),
            (DetectorEvent::Tick { at }, Waiting::Since { opened, last }) => {
                match self.crossed(opened, last, at) {
                    None => (self, smallvec![]),
                    Some(expiry) => (
                        Self {
                            waiting: Waiting::Spoken,
                            ..self
                        },
                        smallvec![expiry],
                    ),
                }
            }
            // Истекать нечему: либо ничего не приходило, либо срок уже назван.
            (DetectorEvent::Tick { .. }, Waiting::Unarmed | Waiting::Spoken) => (self, smallvec![]),
        }
    }
}
