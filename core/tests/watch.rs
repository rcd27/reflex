//! ВЫПУСК РАЗГОВОРА ИЗ ГОРЯЧЕГО ПУТИ — законы решения.
//!
//! Переехало из `dataplane` невода (05.09.2026), где было выражено в терминах меток `nft` и
//! программы десинка. Метки остались там; сюда приехало то, что верно для всякого движка,
//! перехватывающего трафик в userspace: цена — в дороге, а не в вердикте, и потому разговор,
//! который больше нечему научить, платить её не обязан.

use reflex_core::disclosure::Disclosed;
use reflex_core::watch::{watched, Interest, Watch};

/// Три источника, из которых складывается решение, и каждый умеет его ОТМЕНИТЬ.
fn release_of(
    knowledge: Disclosed<&'static str>,
    decision: Option<u32>,
    interest: Interest,
) -> Watch<u32> {
    watched(knowledge, decision, interest)
}

/// ГЛАВНЫЙ ЗАКОН: ПОКА ЗНАНИЕ В ⊥, НЕ ВЫПУСКАЕМ — при любом решении и любом интересе.
///
/// Не «N первых пакетов»: порог по счётчику взят бы из ЦЕНЫ, и то, что он больше длины
/// рукопожатия, было бы совпадением, а не свойством. Две коробки с разными порогами получили бы
/// разные планы на одном трафике.
#[test]
fn a_conversation_whose_knowledge_is_still_bottom_is_never_released() {
    for decision in [None, Some(0), Some(7)] {
        for interest in [Interest::Idle, Interest::Watching] {
            assert_eq!(
                release_of(Disclosed::Awaited, decision, interest),
                Watch::Hold,
                "решение {decision:?} при интересе {interest:?} выпустило разговор в ⊥"
            );
        }
    }
}

/// «СОБЫТИЕ ПРОШЛО, ЗНАЧЕНИЯ НЕ ПОНЕСЛО» — ТОЖЕ ЗНАНИЕ, и оно выпускает.
///
/// Разговор, у которого приветствие прошло пустым, ждать больше нечего: он сказал о себе всё, что
/// скажет. Слить этот случай с ⊥ значило бы держать в горячем пути самый частый вид трафика.
#[test]
fn an_event_that_carried_nothing_still_settles_the_question() {
    assert_eq!(
        release_of(Disclosed::Silent, Some(3), Interest::Idle),
        Watch::Release(3)
    );
}

#[test]
fn a_settled_conversation_with_a_decision_and_no_instruments_is_released() {
    assert_eq!(
        release_of(Disclosed::Spoken("цель"), Some(42), Interest::Idle),
        Watch::Release(42)
    );
}

/// РЕШЕНИЯ НЕТ — ДЕРЖИМ. Поручать ядру нести то, чего мы не решили, незачем.
#[test]
fn without_a_decision_there_is_nothing_to_release_with() {
    assert_eq!(
        release_of(Disclosed::Spoken("цель"), None, Interest::Idle),
        Watch::Hold
    );
}

/// ИНТЕРЕС ПРИБОРОВ ПЕРЕВЕШИВАЕТ РЕШЁННОСТЬ.
///
/// Выпущенный разговор перестаёт давать наблюдения — ответ цели, авторство сброса, миг закрытия.
/// Если приборы этой целью заняты, знание о ней дороже сэкономленной дороги.
#[test]
fn instruments_that_want_to_keep_looking_outrank_a_settled_decision() {
    assert_eq!(
        release_of(Disclosed::Spoken("цель"), Some(42), Interest::Watching),
        Watch::Hold
    );
}

/// ТРИ ИСТОЧНИКА, И КАЖДЫЙ ОТМЕНЯЕТ ВЫПУСК В ОДИНОЧКУ. Выпуск наступает только когда все трое
/// согласны, и это ровно то свойство, ради которого решение собрано в одном месте: оболочка,
/// сводящая их порознь, могла бы свести неправильно.
#[test]
fn release_needs_all_three_and_any_one_of_them_vetoes() {
    let settled = Disclosed::Spoken("цель");

    assert_eq!(
        release_of(settled, Some(1), Interest::Idle),
        Watch::Release(1),
        "все трое согласны"
    );
    assert_eq!(
        release_of(Disclosed::Awaited, Some(1), Interest::Idle),
        Watch::Hold
    );
    assert_eq!(release_of(settled, None, Interest::Idle), Watch::Hold);
    assert_eq!(
        release_of(settled, Some(1), Interest::Watching),
        Watch::Hold
    );
}
