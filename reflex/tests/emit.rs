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

    let deps = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("корень воркспейса")
        .join("target/debug/deps");
    // Свежайший артефакт крейта: в `deps` их лежит по нескольку (разные профили и прогоны), и
    // `--extern` по имени выбрать не сможет — откажется с E0464, то есть НЕ по нашей причине.
    let newest = |crate_name: &str| -> std::path::PathBuf {
        let prefix = format!("lib{crate_name}-");
        std::fs::read_dir(&deps)
            .expect("каталог артефактов")
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension().is_some_and(|kind| kind == "rlib")
                    && path
                        .file_name()
                        .is_some_and(|name| name.to_string_lossy().starts_with(&prefix))
            })
            .max_by_key(|path| {
                std::fs::metadata(path)
                    .and_then(|meta| meta.modified())
                    .expect("время правки артефакта")
            })
            .unwrap_or_else(|| panic!("артефакт {crate_name} не найден в {}", deps.display()))
    };
    let built = std::process::Command::new(env!("CARGO"))
        .args(["build", "-p", "reflex", "-p", "reflex-linux"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("сборка зависимостей образца");
    assert!(built.status.success(), "зависимости образца не собрались");

    let compiled = std::process::Command::new("rustc")
        .arg(&source)
        .args(["--edition", "2021", "--crate-type", "bin"])
        .arg("-L")
        .arg(&deps)
        .arg("--extern")
        .arg(format!("reflex={}", newest("reflex").display()))
        .arg("--extern")
        .arg(format!("reflex_linux={}", newest("reflex_linux").display()))
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
