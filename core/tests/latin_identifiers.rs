//! ИДЕНТИФИКАТОРЫ — ЛАТИНИЦЕЙ, речь — по-русски.
//!
//! Дерево говорит с читателем по-русски, но собирается чужими инструментами: грепом, `rustfmt`,
//! IDE, чужими глазами. Кириллица в ИМЕНИ ломает и поиск, и привычку; в комментарии и в строке для
//! человека — не мешает ничему. Оттого закон режет ровно по этой границе.
//!
//! Сторож текстовый, и иначе нельзя: компилятору кириллическое имя законно, он о нём не скажет
//! никогда. Значит правило, не предъявленное прогоном, держалось бы памятью — а память уже
//! подводила: за один день в дереве набралось 269 таких имён.

use std::path::{Path, PathBuf};

/// Каталоги вне сканирования: собранное и служебное.
const SKIP_DIRS: &[&str] = &["target", ".git", "node_modules"];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("core лежит прямо в воркспейсе")
        .to_path_buf()
}

fn collect_rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if SKIP_DIRS.contains(&name) || name.starts_with('.') {
                continue;
            }
            collect_rust_files(&path, out);
        } else if path.extension().is_some_and(|kind| kind == "rs") {
            out.push(path);
        }
    }
}

/// Объявление имени: за ключевым словом — кириллица. Ловит `fn`, `let`, `const`, `static`,
/// `struct`, `enum`, `mod`, `type`, `trait`.
fn declares_cyrillic_name(line: &str) -> bool {
    const KEYWORDS: &[&str] = &[
        "fn ", "let ", "const ", "static ", "struct ", "enum ", "mod ", "type ", "trait ",
    ];
    let code = line.split("//").next().unwrap_or("");
    KEYWORDS.iter().any(|keyword| {
        code.match_indices(keyword).any(|(at, _)| {
            code[at + keyword.len()..]
                .trim_start()
                .starts_with(|c: char| ('\u{0400}'..='\u{04FF}').contains(&c))
        })
    })
}

#[test]
fn identifiers_are_written_in_latin_letters() {
    let root = workspace_root();
    let mut files = Vec::new();
    collect_rust_files(&root, &mut files);

    assert!(
        files.len() > 100,
        "обход дерева нашёл {} файлов — он и есть предмет теста, слепой обход был бы зелен на \
         пустоте",
        files.len()
    );

    let mut cyrillic: Vec<String> = Vec::new();
    for file in &files {
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        for (number, line) in text.lines().enumerate() {
            if declares_cyrillic_name(line) {
                let short = file.strip_prefix(&root).unwrap_or(file);
                cyrillic.push(format!(
                    "{}:{}: {}",
                    short.display(),
                    number + 1,
                    line.trim()
                ));
            }
        }
    }

    assert!(
        cyrillic.is_empty(),
        "имена объявлены кириллицей — дерево собирается чужими инструментами, и латиница в именах \
         не вкус, а условие их работы:\n{}",
        cyrillic.join("\n")
    );
}
