//! ЗАКОНЫ КАТЕГОРИИ — проверкой, а не декларацией (#295, срез 5).
//!
//! Vision §6 объявляет четыре закона; для стрим-операторов не было ни одного теста ассоциативности,
//! тождества или дистрибутивности. Фреймворк, называющий себя категорным, был единственным слоем
//! дерева без формального референта вообще.
//!
//! # Метод взят у `reflex-os`
//!
//! Там законы restriction-категории проверены ИСЧЕРПЫВАЮЩИМ перебором конечного мира, а не
//! случайным property-раннером: «перебор всех состояний строже любого property-раннера и не
//! требует новой зависимости». Здесь то же: входы короткие и перебираются целиком, равенство —
//! НАБЛЮДАТЕЛЬНОЕ (две цепочки равны, если на всех входах дают один выход).
//!
//! # ЧТО ЗДЕСЬ ОБЕЗОРУЖЕНО, А ЧТО ДЕРЖИТСЯ ТИПОМ — сказано прямо
//!
//! Законы 1 и 2 (ассоциативность, тождество) сломать, СОХРАНИВ СИГНАТУРУ, невозможно: `tap` и
//! `classify` обобщены по типу элемента и потому физически не могут ни изменить значение, ни
//! завести состояние. Попытки это сделать не компилируются — то есть падает сборка, а не тест.
//!
//! Значит эти два теста сторожат РЕГРЕССИЮ СИГНАТУРЫ, а не логику, и называть их обезоруженными
//! было бы враньём. Записано, чтобы читатель не принял их силу за большую, чем она есть: сегодня
//! ложное обезоруживание («слом не скомпилировался, тесты не покраснели — значит они плохи»)
//! случилось здесь же и было поймано только проверкой самой сборки.
//!
//! Закон 3 обезоружен ПО-НАСТОЯЩЕМУ и покомпонентно: слом каждой границы красит ровно свой тест.
//!
//! # Почему это не украшение
//!
//! Третий закон — про домен определённости композиции — есть прямая приёмка эпика: именно его
//! нарушение дало утечку в `nevod2::pipe::alarms` (#294). `detect_per` требовал ограниченных
//! ключей, `key_of` давал 5-tuple соединения, и композиция двух корректных по отдельности вещей
//! оказалась неограниченной. Требование, которого не назвал никто.

use futures::{stream, StreamExt};
use reflex_core::category::{from_source, Pipeline};
use reflex_core::stream::{Keys, Lifetime};
use reflex_core::{Detector, DetectorEvent, DetectorExt, ReflexExt};
use smallvec::{smallvec, SmallVec};

/// МИР КОНЕЧЕН: все последовательности длины ≤ 3 из трёх значений. 39 входов, перебираются целиком.
fn every_input() -> Vec<Vec<u8>> {
    const ATOMS: [u8; 3] = [0, 1, 7];
    let singles: Vec<Vec<u8>> = ATOMS.iter().map(|a| vec![*a]).collect();
    let pairs: Vec<Vec<u8>> = ATOMS
        .iter()
        .flat_map(|a| ATOMS.iter().map(|b| vec![*a, *b]).collect::<Vec<_>>())
        .collect();
    let triples: Vec<Vec<u8>> = ATOMS
        .iter()
        .flat_map(|a| {
            ATOMS
                .iter()
                .flat_map(|b| ATOMS.iter().map(|c| vec![*a, *b, *c]).collect::<Vec<_>>())
                .collect::<Vec<_>>()
        })
        .collect();
    std::iter::once(Vec::new())
        .chain(singles)
        .chain(pairs)
        .chain(triples)
        .collect()
}

/// ЗАКОН 1 — АССОЦИАТИВНОСТЬ КОМПОЗИЦИИ (§6.1).
///
/// `(classify ∘ react)` применённое как две ступени обязано давать то же, что одна ступень с
/// составленной функцией. Это и есть ассоциативность в наблюдаемой форме: скобки в композиции
/// морфизмов не влияют на результат.
#[tokio::test]
async fn composition_is_associative() {
    let c = |signal: bool| match signal {
        true => 10u32,
        false => 1,
    };
    let r = |weight: u32| weight * 3;

    for input in every_input() {
        let stepwise: Vec<u32> = Pipeline::of_packets(stream::iter(input.clone()))
            .map_signals(|b| b > 4)
            .classify(c)
            .react(r)
            .into_stream()
            .collect()
            .await;

        let fused: Vec<u32> = Pipeline::of_packets(stream::iter(input.clone()))
            .map_signals(|b| b > 4)
            .classify(move |s| r(c(s)))
            .into_stream()
            .collect()
            .await;

        assert_eq!(
            stepwise, fused,
            "скобки в композиции изменили результат на входе {input:?}"
        );
    }
}

/// ЗАКОН 2 — ТОЖДЕСТВЕННЫЙ МОРФИЗМ (§6.2).
///
/// `tap` с пустым наблюдателем есть `id`: композиция с ним не меняет ничего. Проверяется с обеих
/// сторон — до и после морфизма, — потому что `id ∘ f = f = f ∘ id` есть ДВА равенства, и
/// проверять одно значило бы принять половину закона за целый.
#[tokio::test]
async fn identity_composes_from_both_sides() {
    for input in every_input() {
        let plain: Vec<bool> = Pipeline::of_packets(stream::iter(input.clone()))
            .map_signals(|b| b > 4)
            .into_stream()
            .collect()
            .await;

        let id_before: Vec<bool> = Pipeline::of_packets(stream::iter(input.clone()))
            .tap(|_| ())
            .map_signals(|b| b > 4)
            .into_stream()
            .collect()
            .await;

        let id_after: Vec<bool> = Pipeline::of_packets(stream::iter(input.clone()))
            .map_signals(|b| b > 4)
            .tap(|_| ())
            .into_stream()
            .collect()
            .await;

        assert_eq!(plain, id_before, "id слева изменил поток на {input:?}");
        assert_eq!(plain, id_after, "id справа изменил поток на {input:?}");
    }
}

/// КОНТРОЛЬ НЕВАКУУМНОСТИ обоих законов выше.
///
/// Если бы цепочка выбрасывала всё, оба закона держались бы даром: пустое равно пустому. Здесь
/// доказывается, что на этих же входах результат НЕ пуст и различает входы.
#[tokio::test]
async fn the_chain_actually_distinguishes_inputs() {
    let big: Vec<bool> = Pipeline::of_packets(stream::iter([7u8]))
        .map_signals(|b| b > 4)
        .into_stream()
        .collect()
        .await;
    let small: Vec<bool> = Pipeline::of_packets(stream::iter([1u8]))
        .map_signals(|b| b > 4)
        .into_stream()
        .collect()
        .await;

    assert_eq!(big, vec![true]);
    assert_eq!(small, vec![false]);
}

// ─── ЗАКОН 3: ДОМЕН ОПРЕДЕЛЁННОСТИ КОМПОЗИЦИИ ────────────────────────────────────────────────

/// Детектор с памятью: считает, сколько раз видел свой ключ, и говорит это на тике.
#[derive(Debug, Clone, Copy, Default)]
struct Counting(u8);

impl Detector for Counting {
    type Input = u8;
    type Signal = u8;

    fn step(self, event: DetectorEvent<u8>) -> (Self, SmallVec<[u8; 2]>) {
        match event {
            DetectorEvent::Packet { .. } => (Counting(self.0 + 1), smallvec![]),
            DetectorEvent::Tick { .. } => (self, smallvec![self.0]),
        }
    }
}

// ЗАКОН 3 — ОБЛАСТЬ ОПРЕДЕЛЁННОСТИ КОМПОЗИЦИИ ЕСТЬ ПЕРЕСЕЧЕНИЕ ОБЛАСТЕЙ.
//
// # Приёмка эпика
//
// Именно этот закон был нарушен в `nevod2::pipe::alarms` (#294): `detect_per` определён лишь при
// ограниченном множестве ключей, `key_of` давал 5-tuple соединения — то есть неограниченное. Оба
// звена корректны по отдельности; композиция вышла за домен, и требования этого не назвал никто.
//
// # ДВА СЦЕНАРИЯ, А НЕ ОДИН — и это оплачено дважды
//
// Пересечение значит «выпал по ЛЮБОМУ из». Проверять это одним прогоном нельзя: то звено, чья
// граница достигается раньше, забирает предмет себе, и второе стоит декоративно.
//
// Первая редакция подавала один ключ — работала только граница по ВРЕМЕНИ, слом границы по числу
// не красил ничего. Вторая подавала два — стала работать только граница по ЧИСЛУ, и перестал
// краснеть слом по времени. Оба раза тест назывался «пересечение» и проверял одну половину.
//
// Отсюда два теста: в каждом ровно ОДНА граница достижима, вторая заведомо нет. Слом первого
// звена красит первый, слом второго — второй.

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

/// `from_source` в законах не участвует, но обязан существовать — иначе импорт врёт.
#[allow(dead_code)]
fn source_is_reachable<B>(b: &mut B)
where
    B: reflex_core::backend::Source + reflex_core::capability::CanObserve,
{
    let _ = from_source(b);
}
