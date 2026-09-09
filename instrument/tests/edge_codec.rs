//! Кодек марки — чистая арифметика над `u32`. Маска — ПАРАМЕТР цепочки, не константа фреймворка:
//! он не знает соседа по машине. Писателя называет тег (сравнение с константой, не с памятью), и
//! «по нашим битам писал другой» — заселённая клетка `Recall::Foreign`, а не пустота.

use reflex_instrument::edge::{Layout, Memo, Phase, Recall};

// Пятнадцать бит: тег 4 + фаза 3 + оттиск 8. Маска — ПАРАМЕТР, здесь лишь пример.
const LAYOUT: Layout = Layout {
    mask: 0x0FFF_E000,
    tag: 0b101,
};

/// Чужие биты переживают наш шаг: сосед по машине нам неизвестен, и стереть его разметку мы не
/// вправе — даже не зная, что она есть.
#[test]
fn foreign_bits_survive_the_write() {
    let foreign = 0x2000_00FF;
    let written = LAYOUT.write(
        foreign,
        Memo {
            phase: Phase::Suspected,
            imprint: 3,
        },
    );
    assert_eq!(written & !LAYOUT.mask, foreign, "вне маски — байт в байт");
}

/// Записанное читается обратно.
#[test]
fn what_was_written_is_read_back() {
    let word = LAYOUT.write(
        0,
        Memo {
            phase: Phase::Confirmed,
            imprint: 200,
        },
    );
    match LAYOUT.read(word) {
        Recall::Ours(memo) => {
            assert_eq!(memo.phase, Phase::Confirmed);
            assert_eq!(memo.imprint, 200);
        }
        Recall::Foreign { theirs } => panic!("своё прочлось чужим: {theirs:#x}"),
    }
}

/// Писателя называет тег, а не память: сравнение с КОНСТАНТОЙ, иначе юзерспейс снова обзавёлся бы
/// состоянием ради проверки, что состояния не держит.
#[test]
fn another_writer_is_recognised_without_memory() {
    let alien = LAYOUT.write(
        0,
        Memo {
            phase: Phase::Suspected,
            imprint: 1,
        },
    ) ^ 0x0000_2000;
    assert!(matches!(LAYOUT.read(alien), Recall::Foreign { .. }));
}

/// Пустое слово — не «наша тишина», а чужое: нулевой тег нашим не бывает.
#[test]
fn empty_word_is_foreign() {
    assert!(matches!(LAYOUT.read(0), Recall::Foreign { theirs: 0 }));
}

/// Маска у́же полей — отказ, а не тихое обрезание старшего бита оттиска. 14 бит < 15 нужных.
#[test]
#[should_panic]
fn a_mask_too_narrow_for_the_fields_is_refused() {
    let narrow = Layout {
        mask: 0x07FF_E000,
        tag: 0b101,
    };
    narrow.write(
        0,
        Memo {
            phase: Phase::Suspected,
            imprint: 0xFF,
        },
    );
}

/// Нулевой тег — отказ: с ним пустое слово прочлось бы «нашим», и нетронутый поток выглядел бы уже
/// наблюдаемым.
#[test]
#[should_panic]
fn a_zero_tag_is_refused() {
    let untagged = Layout {
        mask: 0x0FFF_E000,
        tag: 0,
    };
    untagged.read(0);
}
