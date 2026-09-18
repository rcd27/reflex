//! Дыра — БУКВА, а не запись в журнал. Пока носитель был один, потерю печатал фасад: знание о
//! входе получал писатель вне алфавита, и §2 (полнота) нарушался молча.

use core::time::Duration;
use std::time::Instant;

use reflex_core::interleave::Interleave;
use reflex_core::DetectorEvent;

/// Дыра несёт свой момент — иначе её нельзя поставить в последовательность.
#[test]
fn a_gap_carries_its_own_moment() {
    let at = Instant::now();
    let torn: DetectorEvent<()> = DetectorEvent::Torn { at };
    assert_eq!(torn.at(), at);
}

/// Дыра двигает сетку так же, как непонятое: шов про МОМЕНТЫ, не про содержимое. Не двигай она
/// сетку — поток из одних дыр не закрывал бы окон, и молчание стало бы неотличимо от «пакетов нет».
#[test]
fn the_nodes_a_gap_stepped_over_come_out_before_it() {
    let start = Instant::now();
    let seam = Interleave::started(start, Duration::from_millis(100));
    let (_seam, letters) = seam.torn::<()>(start + Duration::from_millis(250));

    assert!(matches!(
        letters.as_slice(),
        [
            DetectorEvent::Tick { node: 1, .. },
            DetectorEvent::Tick { node: 2, .. },
            DetectorEvent::Torn { .. }
        ]
    ));
}
