//! У КАЖДОГО ПРИБОРА ЕСТЬ ПАСПОРТ — и это проверяется, а не помнится.
//!
//! [`Instrument`](reflex_instrument::Instrument) объявляет о приборе одиннадцать вещей: на каком
//! уровне стоит, на каких протоколах живёт его улика, что говорит при молчании, как врёт, каким
//! вторым оракулом поверяется, от чего умирает. Половина выводится типами, половина объявляется —
//! и объявляется РУКАМИ.
//!
//! Компилятор держит здесь ровно одно: если паспорт начат, он обязан быть полон — ни одна
//! константа не имеет умолчания. Чего он не держит: САМ ФАКТ, что паспорт начат. `Instrument` —
//! отдельный трейт, и не реализовать его совершенно законно.
//!
//! **Замер 11.09.2026: прибор без паспорта уже завёлся.** `UnreachedInstrument` (ответы цели не
//! доходят) написан в тот же день, несёт `Mealy` и паспорта не имеет. Ничто этого не заметило —
//! ни сборка, ни 964 теста, ни аудит: его скрипты читают паспорта, а прибор без паспорта для них
//! просто не существует.
//!
//! Предмет здесь КОНЕЧЕН И ПЕРЕЧИСЛИМ (типы с суффиксом `Instrument` в одном крейте), а накопление
//! ловится ровно там, где известно, чего и сколько должно быть.

use std::collections::BTreeSet;
use std::path::Path;

/// Что объявлено в исходниках крейта: приборы и паспорта, по именам типов.
fn declared() -> (BTreeSet<String>, BTreeSet<String>) {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut instruments = BTreeSet::new();
    let mut passports = BTreeSet::new();

    for entry in std::fs::read_dir(&src).expect("исходники крейта читаются").flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|kind| kind != "rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("модуль читается");
        for line in text.lines() {
            let line = line.trim();
            // Прибор: `pub struct XInstrument` — с параметрами или без.
            if let Some(rest) = line.strip_prefix("pub struct ") {
                let name = rest.split(['<', '(', ' ', '{', ';']).next().unwrap_or_default();
                if name.ends_with("Instrument") {
                    instruments.insert(name.to_string());
                }
            }
            // Паспорт: `impl … Instrument for X` — обобщённый или нет. Ищем по `for`, а не по
            // началу строки: `impl<S: Trait> crate::Instrument for X<S>` начинается иначе.
            if line.starts_with("impl") {
                if let Some(rest) = line.split("Instrument for ").nth(1) {
                    let name = rest.split(['<', ' ', '{']).next().unwrap_or_default();
                    if name.ends_with("Instrument") {
                        passports.insert(name.to_string());
                    }
                }
            }
        }
    }
    (instruments, passports)
}

/// ПРИБОР БЕЗ ПАСПОРТА — ДЕФЕКТ, И ОН ОБЯЗАН БЫТЬ ВИДЕН.
///
/// Паспорт не украшение: им живёт аудит (`instrument/audit/`), по нему собирается публичный круг
/// имён, и в нём объявлены известные режимы лжи прибора. Прибор без паспорта для всего этого
/// невидим — он работает, говорит, а в реестре его нет.
#[test]
fn у_каждого_прибора_есть_паспорт() {
    let (instruments, passports) = declared();

    let naked: Vec<&String> = instruments.difference(&passports).collect();
    assert!(
        naked.is_empty(),
        "приборы без `impl Instrument`: {naked:?}. Паспорт объявляет, на каком уровне прибор \
         стоит, что говорит при молчании, как врёт и чем поверяется; без него прибор невидим для \
         аудита и для публичного круга имён — работает, а в реестре его нет"
    );
}

/// РАЗБОР НАШЁЛ ОБОИХ, А НЕ МОЛЧА НОЛЬ.
///
/// Первый тест зелен на пустоте: пустое множество не содержит приборов без паспорта. Сломай разбор
/// — и он станет вечно зелёным, охраняя ничто. Числа сверяются с порядком величины, а не с точным
/// значением: приборы заводятся и снимаются, и тест не должен краснеть от каждого нового.
#[test]
fn разбор_нашёл_и_приборы_и_паспорта() {
    let (instruments, passports) = declared();

    assert!(
        instruments.len() >= 14,
        "приборов найдено {} — разбор потерял их, и первый тест стал бы зелен на пустоте",
        instruments.len()
    );
    assert!(
        passports.len() >= 14,
        "паспортов найдено {} — разбор ищет `impl … Instrument for`, и он, похоже, сломан",
        passports.len()
    );
}
