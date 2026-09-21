//! ЦЕНА ОДНОГО ДАМПА CONNTRACK — замером, а не оценкой.
//!
//! Продукту (#340) нужно видеть, сколько прошло под маркой слота, у цели, которая НЕ жалуется.
//! Счётчики держит ядро, и вопрос ровно один: сколько стоит их спросить и как часто это можно
//! делать, не отнимая коробку у человека.

use std::time::Instant;

fn main() {
    let Ok(dump) = reflex_linux::conntrack::Dump::open() else {
        eprintln!("не открылся сокет conntrack (нужны права)");
        return;
    };

    // Первый прогон отдельно: он греет кеши и мерил бы не то.
    let _warm = dump.entries();

    let runs = 20;
    let started = Instant::now();
    let counted: usize = (0..runs)
        .map(|_nth| dump.entries().map(|entries| entries.len()).unwrap_or(0))
        .sum();
    let spent = started.elapsed();

    let records = counted / runs.max(1);
    println!("записей в таблице: {records}");
    println!("один дамп: {:?}", spent / runs as u32);
    println!(
        "на 1000 записей: {:?}",
        match records {
            0 => spent / runs as u32,
            n => (spent / runs as u32) * 1000 / n as u32,
        }
    );
}
