//! ЧТО РАЗГОВОР О СЕБЕ СООБЩИЛ — три закона решётки.
//!
//! Переехало из `dataplane` невода (05.09.2026). Там это было про имя цели в `ClientHello`; на
//! деле это форма всякого сведения, добываемого из разговора: имя, версия протокола, выбранный
//! шифр, идентификатор соединения. Общее в них — не предмет, а ПОРЯДОК: сведения только растут.

use reflex_core::disclosure::{joined_with, stood_on, Disclosed};

/// Слияние без разрешения расхождений — для случая, когда значений нет вовсе.
fn joined(known: Disclosed<()>, said: Disclosed<()>) -> Disclosed<()> {
    joined_with(known, said, |mine, _theirs| mine)
}

const LADDER: [Disclosed<()>; 3] = [Disclosed::Awaited, Disclosed::Silent, Disclosed::Spoken(())];

/// ЗАКОН 1: ЗНАНИЕ НЕ УБЫВАЕТ. Никакое событие провода не делает нас осведомлённее меньше.
#[test]
fn knowledge_never_decreases() {
    for known in LADDER {
        for said in LADDER {
            let after = joined(known, said);
            assert!(
                rung(after) >= rung(known),
                "{known:?} ⊔ {said:?} = {after:?} — знание убыло"
            );
        }
    }
}

/// ЗАКОН 2: ПОВТОР ТОГО ЖЕ НЕ СОБЫТИЕ. Ретрансмиссия того же приветствия ничего не добавляет.
#[test]
fn repeating_the_same_event_adds_nothing() {
    for known in LADDER {
        for said in LADDER {
            let once = joined(known, said);
            assert_eq!(
                joined(once, said),
                once,
                "повтор {said:?} поверх {known:?} изменил знание"
            );
        }
    }
}

/// ЗАКОН 3: ПОРЯДОК СОБЫТИЙ НЕ ВЛИЯЕТ.
///
/// Не украшение: провод переставляет пакеты, а движок, выпускающий разговоры из горячего пути,
/// видит ПОДМНОЖЕСТВО событий. Вердикт, зависящий от порядка прихода, на таком проводе
/// недетерминирован — две коробки на одном трафике решат по-разному.
#[test]
fn the_order_of_events_does_not_matter() {
    for one in LADDER {
        for other in LADDER {
            assert_eq!(
                joined(joined(Disclosed::Awaited, one), other),
                joined(joined(Disclosed::Awaited, other), one),
                "{one:?} и {other:?} дали разное в разном порядке"
            );
        }
    }
}

/// РАСХОЖДЕНИЕ ДВУХ ЗНАЧЕНИЙ РАЗРЕШАЕТ ВЫЗЫВАЮЩИЙ, а не решётка молча.
///
/// В `dataplane` невода ⊤ («противоречие») намеренно не заводили: частота явления не замерена, а
/// тип под неизмеренное потом не снимается. Но молчаливый выбор победителя — не отсутствие
/// решения, а незаписанное решение. Здесь правило приходит аргументом: не назвав его, слить два
/// разных значения нельзя.
#[test]
fn a_conflict_between_two_values_is_settled_by_the_caller() {
    let mine = Disclosed::Spoken("первое");
    let theirs = Disclosed::Spoken("второе");

    assert_eq!(
        joined_with(mine, theirs, |a, _b| a),
        Disclosed::Spoken("первое")
    );
    assert_eq!(
        joined_with(mine, theirs, |_a, b| b),
        Disclosed::Spoken("второе")
    );
}

/// СНИМОК «НА ЧЁМ СТОЯЛО РЕШЕНИЕ» — ДРУГАЯ ВЕЛИЧИНА, И ОНА ОТ ПОРЯДКА ЗАВИСЕТЬ ОБЯЗАНА.
///
/// Знание растёт и порядка не помнит. Запись о ПРОШЛОМ решении — помнит: мы действовали тем, что
/// пришло первым, и переставить это задним числом нельзя. Требовать от неё коммутативности значит
/// требовать, чтобы запись о случившемся не зависела от того, что случилось.
#[test]
fn what_a_decision_stood_on_freezes_at_the_first_word() {
    assert_eq!(
        stood_on(Disclosed::Awaited, Disclosed::<&str>::Silent),
        Disclosed::Silent,
        "первое непустое слово принимается"
    );
    assert_eq!(
        stood_on(Disclosed::Silent, Disclosed::Spoken("позже")),
        Disclosed::Silent,
        "и остаётся навсегда: позднее имя не двигает решение на середине применения"
    );
    assert_eq!(
        stood_on(Disclosed::Awaited, Disclosed::<&str>::Awaited),
        Disclosed::Awaited,
        "ждём дальше, если не сказано ничего"
    );
}

#[test]
fn freezing_is_deliberately_not_commutative() {
    let early = Disclosed::Silent;
    let late = Disclosed::Spoken("позже");

    assert_ne!(
        stood_on(early, late),
        stood_on(late, early),
        "если бы снимок был коммутативен, он перестал бы говорить, ЧТО пришло первым"
    );
}

/// Ступень на лестнице информации — только для проверки монотонности.
fn rung(disclosed: Disclosed<()>) -> u8 {
    match disclosed {
        Disclosed::Awaited => 0,
        Disclosed::Silent => 1,
        Disclosed::Spoken(()) => 2,
    }
}
