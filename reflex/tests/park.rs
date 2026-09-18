//! ПАРК ФАСАДА ОТДАЁТ ТО, ЧТО СЛОВАРЬ ОБЕЩАЕТ — прогоном, а не перечислением в докблоке.
//!
//! Замер 11.09.2026, нашедший нужду в этом файле: словарь `Distress` содержал `Rst` и `Throttled`,
//! а дверей к приборам, которые их произносят, в парке НЕ БЫЛО. Фасад умел про сброс и троттлинг
//! СКАЗАТЬ и не умел их УВИДЕТЬ. Потребитель писал `Distress::Rst => …`, компилятор не спорил,
//! ветка не срабатывала никогда.
//!
//! Нашлось у ПОТРЕБИТЕЛЯ и прогоном: цепочка, собранная из всего, что предлагал парк,
//! молчала на записях, где сброс и троттлинг ЕСТЬ. Слепота была молчаливой — а молчание прибора
//! читается как «беды нет».
//!
//! Отсюда закон файла: **всякое слово словаря обязано иметь в парке того, кто его произносит**, и
//! это проверяется прогоном на сочинённом проводе (`reflex::scenario`), а не глазами.

use std::time::Duration;

use reflex::scenario::{log, reply, request, rst, syn, taken, Paper};
use reflex::*;

/// СБРОС СЛЫШЕН. Дверь `Rst::seen()` заведена 11.09.2026; до неё слово `Distress::Rst` в словаре
/// стояло, а произнести его было некому.
#[test]
fn a_reset_from_the_target_reaches_the_consumer() {
    let said = log::<String>();
    engine(
        Paper::new()
            .then_packet(syn(40001))
            .then_packet(request(40001))
            .then_packet(rst(40001))
            .then_stop(),
    )
    .from(Tcp)
    .extract(Sni)
    .detect(Rst::seen())
    .on(move |_target, distress| {
        if let Distress::Rst = distress {
            said.lock()
                .expect("журнал не отравлен")
                .push("rst".to_string());
        }
    })
    .run();

    assert!(
        taken(said).contains(&"rst".to_string()),
        "сброс есть в проводе — прибор обязан его назвать; молчание здесь читалось бы как «беды нет»"
    );
}

/// ПАРК НЕ ПУСТ И НЕ СЛЕП НА ЧИСТОМ ПРОВОДЕ: разговор без сброса сброса и не даёт.
///
/// Держит первый тест честным: прибор, кричащий всегда, прошёл бы его, не умея различать.
#[test]
fn a_clean_conversation_is_not_announced_as_a_reset() {
    let said = log::<String>();
    engine(
        Paper::new()
            .then_packet(syn(40002))
            .then_packet(request(40002))
            .then_packet(reply(40002, 64))
            .then_stop(),
    )
    .from(Tcp)
    .extract(Sni)
    .detect(Rst::seen())
    .on(move |_target, distress| {
        if let Distress::Rst = distress {
            said.lock()
                .expect("журнал не отравлен")
                .push("rst".to_string());
        }
    })
    .run();

    assert!(
        taken(said).is_empty(),
        "сброса в проводе нет — называть его нечем: {:?}",
        taken(said)
    );
}

/// ЗАХЛЁБЫВАНИЕ И ТРОТТЛИНГ СОБИРАЮТСЯ В ЦЕПОЧКУ. Здесь проверяется ФОРМА двери, а не срабатывание:
/// показание обоих — величина, и порог у них замеряется на живом трафике, а не сочиняется.
///
/// Названо прямо, чтобы зелёный тест не читался шире правды: он держит то, что двери есть и
/// цепочка с ними строится, — ровно тот дефект, что был найден (механизм есть, двери нет).
#[test]
fn the_doors_for_quantities_exist_and_a_chain_builds_with_them() {
    engine(Paper::new().then_packet(request(40003)).then_stop())
        .from(Tcp)
        .extract(Sni)
        .detect(Throttled::over(Duration::from_secs(2)))
        .detect(Choked::after(64 * 1024, Duration::from_secs(3)))
        .on(|_target, _distress| {})
        .run();
}

// ─── Сторож класса, а не одного случая ────────────────────────────────────────────────────────

/// ВСЯКОЕ СЛОВО СЛОВАРЯ ДОСТИЖИМО ИЗ ПАРКА.
///
/// Сегодняшний дефект был не один, а четвёртый в череде одной породы (счёт соседней сессии):
/// запись, не доезжавшая до приборов; `Interleave::answered`, построенный и ни разу не позванный;
/// носитель, объявивший `CanRemember` и не помнивший марку; парк без трёх приборов. Общий признак
/// назван ею же: **механизм выглядит готовым, а половина его предмета недостижима, и
/// обнаруживается это только прогоном**.
///
/// Прогоном — значит поздно и случайно. Здесь предмет КОНЕЧЕН И ПЕРЕЧИСЛИМ (варианты `Distress`), а
/// накопление ловится ровно там, где известно, чего и сколько должно быть. Отсюда сторож.
///
/// # Что он мерит и чего не мерит
///
/// Мерит он ДОСТИЖИМОСТЬ ПО ТЕКСТУ: слово произносит какой-то модуль `instrument`, и хотя бы один
/// такой модуль фасад импортирует. Это КОСВЕННЫЙ признак, и назвать его косвенным обязательно —
/// иначе сторож прочтётся сильнее, чем держит.
///
/// Чего он НЕ ловит, проверено мутацией: убери из парка `impl IntoProbe for Rst`, оставив импорт, —
/// сторож зелен. Краснеет при этом ДРУГОЕ, и краснеет надёжнее: прогоны выше не компилируются
/// вовсе, потому что `.detect(Rst::seen())` без `IntoProbe` цепочки не собирает.
///
/// Отсюда устройство защиты, и оно двухслойное не по осторожности, а потому что слои ловят разное:
/// * ПРОГОН держит ДВЕРЬ — компилятором, то есть строже всего, что тут возможно;
/// * СТОРОЖ держит СЛОВАРЬ — текстом, и ловит ровно то, чего прогон не видит: слово, у которого
///   прогона нет вовсе. Именно так и жил дефект: прогонов на `Rst` не было ни одного, и дверь
///   отсутствовала молча.
///
/// Сам `distress.rs` из произносящих исключён: там слово только объявлено и напечатано, а
/// объявление словом не является — ровно эту разницу дефект и вскрыл.
#[test]
fn every_word_of_distress_has_someone_in_the_park_who_utters_it() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("корень воркспейса");
    let dictionary =
        std::fs::read_to_string(root.join("instrument/src/distress.rs")).expect("словарь читается");
    let facade = std::fs::read_to_string(root.join("reflex/src/lib.rs")).expect("фасад читается");

    // Варианты берутся из САМОГО перечисления, а не из списка в тесте: список разошёлся бы со
    // словарём молча, и сторож охранял бы вчерашний день.
    let body = dictionary
        .split_once("pub enum Distress {")
        .expect("перечисление на месте")
        .1
        .split_once("\n}")
        .expect("перечисление закрыто")
        .0;
    let words: Vec<&str> = body
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("//") && !line.starts_with("///"))
        .filter_map(|line| line.split([' ', ',', '{']).next())
        .filter(|name| name.starts_with(|c: char| c.is_ascii_uppercase()))
        .collect();
    assert!(
        words.len() >= 8,
        "разбор словаря нашёл {} слов — он и есть предмет теста, слепой разбор сделал бы его \
         зелёным на пустоте",
        words.len()
    );

    let mut voiceless: Vec<String> = Vec::new();
    for word in &words {
        let spoken_in: Vec<String> = std::fs::read_dir(root.join("instrument/src"))
            .expect("модули прибора читаются")
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|kind| kind == "rs"))
            .filter(|path| path.file_stem().is_some_and(|name| name != "distress"))
            .filter(|path| {
                std::fs::read_to_string(path)
                    .is_ok_and(|text| text.contains(&format!("Distress::{word}")))
            })
            .filter_map(|path| {
                path.file_stem()
                    .map(|name| name.to_string_lossy().to_string())
            })
            .collect();

        let reachable = spoken_in
            .iter()
            .any(|module| facade.contains(&format!("reflex_instrument::{module}::")));
        if !reachable {
            voiceless.push(format!("{word} (произносят: {spoken_in:?})"));
        }
    }

    assert!(
        voiceless.is_empty(),
        "слова словаря, за которыми в парке НЕТ произносящего: {voiceless:?}. Потребитель напишет \
         по ним ветку `match`, компилятор не возразит, а сработать ей будет некому — и цепочка \
         поедет слепым, не узнав об этом"
    );
}

/// ГРАНИЦА ПЛАТФОРМЫ ПРОВЕРЯЕТСЯ ТЕМ ЖЕ ГРЕПОМ, КОТОРЫМ ОНА ОБЪЯВЛЕНА.
///
/// Докблок `mod nfqueue` обещает: «граница проверяема ГРЕПОМ — имени линукс-крейта в `lib.rs` не
/// должно встретиться ни разу, иначе „WinDivert встаёт в ту же дверь“ остаётся обещанием, а не
/// свойством». Обещание держалось честным словом: грепа не было ни в тестах, ни в CI, и §10.9
/// называет такое прямо — принадлежность классу, подтверждённая ИМЕНЕМ проверки, а не её признаком.
///
/// Сборка этого не ловит по построению: `mod nfqueue` стоит под `#[cfg(unix)]`, и на Linux
/// компилятор одинаково рад и одной строке с именем линукс-крейта, и сотне. Свойство держит
/// РАЗМЕЩЕНИЕ имени, а размещение видно только тексту.
///
/// Способность краснеть показана мутацией: допиши в `lib.rs` любое `reflex_linux::` вне модуля
/// носителя — и список ниже перестанет быть пустым.
#[test]
fn the_linux_crate_name_never_appears_in_the_facade_door() {
    let facade = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"),
    )
    .expect("фасад читается");

    // Докблок `mod nfqueue` — единственное законное место имени: он ОБЪЯСНЯЕТ границу, а не
    // пересекает её. Отличаем объяснение от употребления по префиксу докстроки, а не по номеру
    // строки: номера разъезжаются от любой правки выше, и сторож стерёг бы вчерашний файл.
    let trespassing: Vec<(usize, &str)> = facade
        .lines()
        .enumerate()
        .filter(|(_, line)| line.contains("reflex_linux"))
        .filter(|(_, line)| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("///") && !trimmed.starts_with("//")
        })
        .map(|(number, line)| (number + 1, line.trim()))
        .collect();

    assert!(
        trespassing.is_empty(),
        "имя линукс-крейта названо в `reflex/src/lib.rs` вне модуля носителя: {trespassing:?}. \
         Дверь фасада обязана быть одна на все платформы — носителя называет ПЕРВАЯ строка цепочки \
         потребителя, а не сам фасад"
    );
}
