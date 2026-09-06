//! ДОМЕН ОПРЕДЕЛЁННОСТИ КОМПОЗИЦИИ — третий закон.
//!
//! Композиция двух звеньев, каждое верное порознь, может выйти за домен определения, если их
//! границы не совпадают: `detect_per` определён лишь при ограниченном множестве ключей, а
//! ключующая функция способна дать неограниченное. Проверка каждого звена по отдельности этого не
//! ловит — предмет здесь СТЫК, а не оператор, и стык нуждается в собственных тестах, а не в
//! умозаключении «оба звена зелёные, значит и стык цел».

use futures::{stream, StreamExt};
use reflex_core::step::Step;
use reflex_core::stream::{Keys, Lifetime};
use reflex_core::{DetectorEvent, ReflexExt};
use smallvec::{smallvec, SmallVec};

/// Детектор с памятью: считает, сколько раз видел свой ключ, и говорит это на тике.
#[derive(Debug, Clone, Copy, Default)]
struct Counting(u8);

impl Step for Counting {
    type From = DetectorEvent<u8>;
    type To = SmallVec<[u8; 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
        match event {
            DetectorEvent::Packet { .. } => (Counting(self.0 + 1), smallvec![]),
            DetectorEvent::Tick { .. } => (self, smallvec![self.0]),
        }
    }
}

// ЗАКОН 3 — ОБЛАСТЬ ОПРЕДЕЛЁННОСТИ КОМПОЗИЦИИ ЕСТЬ ПЕРЕСЕЧЕНИЕ ОБЛАСТЕЙ.
//
// # ДВА СЦЕНАРИЯ, А НЕ ОДИН
//
// Пересечение значит «выпал по ЛЮБОМУ из». Проверять это одним прогоном нельзя: то звено, чья
// граница достигается раньше, забирает предмет себе, и второе стоит декоративно. Отсюда два
// теста: в каждом ровно ОДНА граница достижима, вторая заведомо нет. Слом первого звена красит
// первый, слом второго — второй.

/// ВЫПАДЕНИЕ ПО ВРЕМЕНИ: групп мало, до потолка далеко — из домена выводит только срок.
#[tokio::test]
async fn the_composition_forgets_when_the_time_bound_is_crossed() {
    let t0 = std::time::Instant::now();
    let limit = std::time::Duration::from_secs(10);
    let packet = |key: u8, at: std::time::Instant| DetectorEvent::Packet { input: key, at };

    let counted: Vec<(u8, u8)> = stream::iter([
        packet(1, t0),
        packet(1, t0),
        DetectorEvent::Tick { at: t0 },
        // Молчание дольше срока: звено по ВРЕМЕНИ обязано забыть.
        DetectorEvent::Tick { at: t0 + limit },
        packet(1, t0 + limit * 2),
        DetectorEvent::Tick { at: t0 + limit * 2 },
    ])
    .detect_per(|k: &u8| *k, Counting::default, Lifetime::UntilIdle(limit))
    // Потолок ЗАВЕДОМО НЕ ДОСТИГАЕТСЯ: ключ один, групп хватает на десять.
    .group_by(
        |(k, _): &(u8, u8)| *k,
        || 0u32,
        |_seen: &mut u32, (k, count)| Some((k, count)),
        Keys::AtMost(10),
    )
    .collect()
    .await;

    assert_eq!(
        counted.last().map(|(_, c)| *c),
        Some(1),
        "звено по времени забыло, а композиция помнит: {counted:?}"
    );
}

/// ВЫПАДЕНИЕ ПО ЧИСЛУ: срок заведомо не истекает — из домена выводит только потолок групп.
#[tokio::test]
async fn the_composition_forgets_when_the_count_bound_is_crossed() {
    let t0 = std::time::Instant::now();
    let limit = std::time::Duration::from_secs(10);
    let packet = |key: u8, at: std::time::Instant| DetectorEvent::Packet { input: key, at };

    // Всё происходит в один момент: срок не истекает НИ РАЗУ.
    let counted: Vec<(u8, u32)> = stream::iter([
        packet(1, t0),
        DetectorEvent::Tick { at: t0 },
        // Ключ 2 вытесняет группу ключа 1 — потолок в одну группу.
        packet(2, t0),
        DetectorEvent::Tick { at: t0 },
        packet(1, t0),
        DetectorEvent::Tick { at: t0 },
    ])
    .detect_per(|k: &u8| *k, Counting::default, Lifetime::UntilIdle(limit))
    .group_by(
        |(k, _): &(u8, u8)| *k,
        || 0u32,
        |seen: &mut u32, (k, _count)| {
            *seen += 1;
            Some((k, *seen))
        },
        Keys::AtMost(1),
    )
    .collect()
    .await;

    let last_about_one = counted.iter().rev().find(|(k, _)| *k == 1).map(|(_, n)| *n);
    assert_eq!(
        last_about_one,
        Some(1),
        "звено по числу вытеснило группу, а композиция помнит: {counted:?}"
    );
}

/// КОНТРОЛЬ к обоим: пока НИ ОДНА граница не достигнута, композиция не забывает ничего.
///
/// Без него законы держались бы и на цепочке, теряющей состояние всегда, — а такая цепочка не
/// композиция операторов, а решето.
#[tokio::test]
async fn within_both_domains_nothing_is_forgotten() {
    let t0 = std::time::Instant::now();
    let limit = std::time::Duration::from_secs(10);
    let packet = |key: u8, at: std::time::Instant| DetectorEvent::Packet { input: key, at };

    let counted: Vec<(u8, u8)> = stream::iter([
        packet(1, t0),
        packet(1, t0),
        packet(1, t0),
        DetectorEvent::Tick { at: t0 },
    ])
    .detect_per(|k: &u8| *k, Counting::default, Lifetime::UntilIdle(limit))
    .group_by(
        |(k, _): &(u8, u8)| *k,
        || 0u32,
        |_seen: &mut u32, (k, count)| Some((k, count)),
        Keys::AtMost(10),
    )
    .collect()
    .await;

    assert_eq!(
        counted.last().map(|(_, c)| *c),
        Some(3),
        "внутри обоих доменов состояние потеряно: {counted:?}"
    );
}
