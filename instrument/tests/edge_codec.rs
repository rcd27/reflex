//! Кодек марки — чистая арифметика над `u32`. Маска — ПАРАМЕТР цепочки, не константа фреймворка:
//! он не знает соседа по машине. Писателя называет тег (сравнение с константой, не с памятью), и
//! «по нашим битам писал другой» — заселённая клетка `Recall::Foreign`, а не пустота.

use reflex_instrument::edge::{Layout, Memo, Phase, Recall};

// Пятнадцать бит: тег 4 + фаза 3 + оттиск 8. Маска — ПАРАМЕТР, здесь лишь пример. Дверь одна —
// `new`, потому не `const`-литерал (проверка предпосылок не `const`).
fn layout() -> Layout {
    Layout::new(0x0FFF_E000, 0b101).expect("15-битная маска, ненулевой тег")
}

/// Чужие биты переживают наш шаг: сосед по машине нам неизвестен, и стереть его разметку мы не
/// вправе — даже не зная, что она есть.
#[test]
fn foreign_bits_survive_the_write() {
    let layout = layout();
    let foreign = 0x2000_00FF;
    let written = Memo::new(layout, Phase::Suspected, 3).apply_to(foreign);
    assert_eq!(written & !layout.mask(), foreign, "вне маски — байт в байт");
}

/// Записанное читается обратно.
#[test]
fn what_was_written_is_read_back() {
    let word = Memo::new(layout(), Phase::Confirmed, 200).apply_to(0);
    match layout().read(word) {
        Recall::Ours(memo) => {
            assert_eq!(memo.phase, Phase::Confirmed);
            assert_eq!(memo.imprint, 200);
        }
        Recall::Foreign { theirs } => panic!("своё прочлось чужим: {theirs:#x}"),
        Recall::Untouched => panic!("своё прочлось нетронутым: {word:#x}"),
    }
}

/// Писателя называет тег, а не память: сравнение с КОНСТАНТОЙ, иначе юзерспейс снова обзавёлся бы
/// состоянием ради проверки, что состояния не держит.
#[test]
fn another_writer_is_recognised_without_memory() {
    let alien = Memo::new(layout(), Phase::Suspected, 1).apply_to(0) ^ 0x0000_2000;
    assert!(matches!(layout().read(alien), Recall::Foreign { .. }));
}

/// Пустое слово — не «наша тишина» и не чужой писатель, а НЕТРОНУТАЯ марка: под нашими битами
/// никто не писал. Клетка отдельная, потому что прежде она делила `Foreign` с настоящим
/// расхождением, и различал их потребитель по `theirs != 0`.
#[test]
fn empty_word_is_untouched() {
    assert!(matches!(layout().read(0), Recall::Untouched));
}

/// СОСЕД ВНЕ НАШЕЙ МАСКИ — НЕ ЧУЖОЙ ПИСАТЕЛЬ. Читатель обязан говорить то же, что писатель:
/// `foreign_bits_survive_the_write` выше объявляет его биты законными, и объявить их же находкой
/// на чтении значило бы держать два закона об одном. Цена ошибки замерена неводом 3 на живой
/// цензуре 20.09.2026 — марка маршрутизации `0xCC` давала `Diverged` на каждом пакете укрытой
/// цели.
#[test]
fn a_neighbour_outside_our_mask_is_untouched_not_foreign() {
    assert!(matches!(layout().read(0x0000_00CC), Recall::Untouched));
    assert!(matches!(layout().read(0xF000_0000), Recall::Untouched));
}

/// А ВОТ ПО НАШИМ БИТАМ ЧУЖОЙ ТЕГ — НАХОДКА, и слово отдаётся целиком: клетка уже различена
/// типом, а человеку нужна вся марка, чтобы узнать соседа.
#[test]
fn a_foreign_tag_under_our_mask_is_reported_with_the_whole_word() {
    let alien = 0x0055_0000 | 0x0000_00CC;
    assert!(matches!(
        layout().read(alien),
        Recall::Foreign { theirs } if theirs == alien
    ));
}

/// Маска у́же полей — отказ (`None`), а не тихое обрезание старшего бита оттиска. 14 бит < 15 нужных.
#[test]
fn a_mask_too_narrow_for_the_fields_is_refused() {
    assert!(Layout::new(0x07FF_E000, 0b101).is_none());
}

/// Нулевой тег — отказ: с ним пустое слово прочлось бы «нашим», и нетронутый поток выглядел бы уже
/// наблюдаемым.
#[test]
fn a_zero_tag_is_refused() {
    assert!(Layout::new(0x0FFF_E000, 0).is_none());
}

/// ПРЕРЫВИСТАЯ маска — отказ, хотя бит в ней хватает (16 ≥ 15): в дырку данные писались бы мимо и
/// читались мусором. Ловит `field & mask == field`, чего `count_ones() >= 15` не поймал бы.
#[test]
fn a_discontiguous_mask_is_refused() {
    assert!(Layout::new(0xFF00_FF00, 0b101).is_none());
}
