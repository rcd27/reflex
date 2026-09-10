//! ОДИН ФУНКТОР: доменный акт → слово носителя и список эффектов (§9.4, §12.4).
//!
//! Прежде перевод акта в слово носителя жил тремя разборами в разных местах, а обрыв и вовсе
//! исполнялся императивно в петле — фасад знал про сокет инъекции. Функтор чист: он ОТДАЁТ команду,
//! а не шлёт её; исполняет петля, и в режиме переигровки — не исполняет. Тем лента и остаётся
//! переигрываемой (§10).

use reflex::{emit, Act};
use reflex_core::effect::Effect;
use reflex_linux::nfqueue::{Answer, NfqueueBackend};

/// НАБЛЮДЕНИЕ ОТПУСКАЕТ ПАКЕТ И НЕ РОЖДАЕТ ЭФФЕКТОВ.
#[test]
fn наблюдение_отпускает_и_молчит() {
    let (word, effects) = emit::<NfqueueBackend>(Act::observe(), &[]);

    assert_eq!(word, Answer::Pass, "пакет идёт как шёл");
    assert!(effects.is_empty(), "наблюдение мира не касается");
}

/// ОБРЫВ ДАЁТ ДВА ВЫХОДА: слово носителю и КОМАНДУ инъекции.
///
/// Пакет при этом отпускается: обрыв делает инъекция, а не дроп. Команда возвращается, а не
/// исполняется — иначе переигровка слала бы RST заново, и функтор перестал бы быть функтором.
#[test]
fn обрыв_отпускает_пакет_и_возвращает_команду() {
    let syn_ack = tcp_frame();
    let (word, effects) = emit::<NfqueueBackend>(Act::sever(), &syn_ack);

    assert_eq!(word, Answer::Pass, "обрыв делает инъекция, не дроп");
    assert!(
        matches!(effects.as_slice(), [Effect::Inject(_)]),
        "обрыв вернул команду инъекции, а не отправил её"
    );
}

/// НЕЧЕМ ОБОРВАТЬ — НЕТ И КОМАНДЫ.
///
/// `notice` отдаёт `None`, когда формы обрыва на этом наблюдении нет. Пустой список эффектов — не
/// молчание об ошибке: акт исполнен, сказать оказалось нечем, и слово носителю всё равно есть.
#[test]
fn нечем_оборвать_нет_и_команды() {
    let (word, effects) = emit::<NfqueueBackend>(Act::sever(), &[0xFF; 8]);

    assert_eq!(word, Answer::Pass);
    assert!(effects.is_empty(), "формы обрыва нет — команды нет");
}

/// Минимальный TCP-сегмент в IP — ровно то, что очередь ядра кладёт в руки: без Ethernet, с
/// заголовка IPv4.
fn tcp_frame() -> Vec<u8> {
    let mut packet = vec![0u8; 20 + 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(20u16 + 20).to_be_bytes());
    packet[9] = 6;
    packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
    packet[16..20].copy_from_slice(&[93, 184, 216, 34]);
    packet[20..22].copy_from_slice(&44321u16.to_be_bytes());
    packet[22..24].copy_from_slice(&443u16.to_be_bytes());
    packet[32] = 5 << 4;
    packet[33] = 0x18;
    packet
}

/// ВОПРОС НАД НОСИТЕЛЕМ БЕЗ КОНТУРА НЕ СОБИРАЕТСЯ — гейт по акту (§9.1).
///
/// Прежде здесь стоял прогон: `Act::Ask` собирался, `question` отдавал `None`, эффектов не было, и
/// тест это фиксировал как «носитель сказал, что спросить нечем». Но машина, задавшая вопрос,
/// уходит ЖДАТЬ ответа — а его никто не пошлёт. Молчаливый висяк вместо ошибки.
///
/// Теперь очередь `CanAsk` не заявляет вовсе, и конструктора `ask` у её акта просто НЕТ. Причина
/// отказа сверена текстом, а не принята на веру: зелёный `compile_fail` без сверки доказывает лишь
/// «не собралось» — хоть по опечатке.
#[test]
fn вопрос_над_очередью_не_собирается() {
    let sample = concat!(
        "fn main() {\n",
        "    let _ = reflex::Act::<reflex_linux::nfqueue::NfqueueBackend>::ask(42);\n",
        "}\n"
    );
    let dir = std::env::temp_dir().join("reflex-act-gate");
    std::fs::create_dir_all(&dir).expect("каталог для образца");
    let source = dir.join("ask_over_queue.rs");
    std::fs::write(&source, sample).expect("образец записан");

    // АРТЕФАКТ НАЗЫВАЕТ САМА СБОРКА, А НЕ ВРЕМЯ ПРАВКИ ФАЙЛА.
    //
    // Прежде брался свежайший `libreflex_linux-*.rlib` в `deps`, и оракул врал: любой прогон с
    // другим набором фич (`cargo test -p reflex-linux --features conntrack`) кладёт туда СВОЙ
    // артефакт, тот оказывается новее, и образец падает с `cannot find nfqueue` — отказом по
    // ЧУЖОЙ причине, неотличимым от нашего по вердикту «не собралось». Одна такая ложная краснота
    // уже стоила разбирательства. Время правки — следствие сборки, а не она сама.
    //
    // `--message-format=json` называет файлы ТОЙ сборки, что здесь запрошена, вместе с её фичами,
    // и делает это даже когда собирать нечего (`fresh: true` — сообщение приходит всё равно).
    let built = std::process::Command::new(env!("CARGO"))
        .args([
            "build",
            "-p",
            "reflex",
            "-p",
            "reflex-linux",
            "--message-format=json",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("сборка зависимостей образца");
    assert!(built.status.success(), "зависимости образца не собрались");
    let manifest = String::from_utf8_lossy(&built.stdout);

    // Разбор без serde: крейту он не нужен ни для чего другого, а искомое — одна строка внутри
    // одного массива. Ошибка формы даст `panic` с именем крейта, а не молчаливо чужой артефакт.
    // Имя ЦЕЛИ, не пакета: cargo зовёт её `reflex_linux` там, где пакет зовётся
    // `reflex-linux`, и ровно это имя стоит в `--extern` ниже — одно имя на оба употребления.
    let artifact = |target: &str| -> std::path::PathBuf {
        let mark = format!("\"name\":\"{target}\"");
        manifest
            .lines()
            .filter(|line| line.contains("\"reason\":\"compiler-artifact\"") && line.contains(&mark))
            .find_map(|line| {
                let tail = line.split("\"filenames\":[").nth(1)?;
                tail.split(&[',', ']'][..])
                    .map(|name| name.trim_matches(&['"', ' '][..]))
                    // ЧЕРЕЗ `.rmeta` В `deps`, А НЕ ЧЕРЕЗ НАЗВАННЫЙ `.rlib`.
                    //
                    // Артефакт члена воркспейса cargo ПОДНИМАЕТ: называет `target/debug/libX.rlib`
                    // (копия без хеша) и рядом — `deps/libX-ХЕШ.rmeta`. Взять поднятую копию
                    // значит увести `-L` из `deps`, где лежат транзитивные зависимости, и
                    // получить E0460 «возможно, более новая версия крейта» — снова отказ по ЧУЖОЙ
                    // причине. Хешированный `.rlib` (жёсткая ссылка на ту же копию) в `filenames`
                    // не назван, но стоит рядом с `.rmeta` и зовётся так же.
                    .find(|name| name.ends_with(".rmeta") && name.contains("/deps/"))
                    .map(|meta| std::path::PathBuf::from(meta).with_extension("rlib"))
                    .filter(|rlib| rlib.exists())
            })
            .unwrap_or_else(|| panic!("сборка не назвала rlib цели {target}"))
    };
    let reflex_rlib = artifact("reflex");
    let linux_rlib = artifact("reflex_linux");
    let deps = linux_rlib.parent().expect("каталог артефактов").to_path_buf();

    let compiled = std::process::Command::new("rustc")
        .arg(&source)
        .args(["--edition", "2021", "--crate-type", "bin"])
        .arg("-L")
        .arg(&deps)
        .arg("--extern")
        .arg(format!("reflex={}", reflex_rlib.display()))
        .arg("--extern")
        .arg(format!("reflex_linux={}", linux_rlib.display()))
        .arg("-o")
        .arg(dir.join("ask_over_queue"))
        .output()
        .expect("rustc запущен");

    let complaint = String::from_utf8_lossy(&compiled.stderr);
    assert!(!compiled.status.success(), "образец обязан не собраться");
    assert!(
        complaint.contains("no function or associated item named `ask`")
            || complaint.contains("CanAsk"),
        "отказ по ТОЙ причине — отсутствию способности спрашивать, а не по опечатке:\n{complaint}"
    );
}
