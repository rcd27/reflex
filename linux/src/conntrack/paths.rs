//! Темп ЛЕЧИМОГО и ПРЯМОГО пути цели — из двух снимков conntrack за одно окно. Вход вердикта
//! [`reflex_core::remedy::remedy`]: сам вердикт не знает ядра, ядро не знает вердикта.
//!
//! Путь различает бит ядра ([`CtDst`]), а не приказ марки: уведённый разговор — тот, чей адрес
//! назначения переписан. Протокол не различается НАРОЧНО: на канарейке 17.09.2026 уведённым был TCP, а
//! несла прямая по QUIC к тому же узлу, и сравнение внутри одного протокола этот случай не увидело бы.
//!
//! # ЧЕЙ разговор — решает потребитель, а не адрес
//!
//! Первая редакция относила к цели всякий разговор к её адресам, и на стенде 17.09 вердикт снимал увод
//! с `i.ytimg.com` и `optimizationguide-pa.googleapis.com`: это общие фронты Google, и прямая к тому же
//! адресу «несла» 7,5 МБ/с чужого трафика. Поэтому здесь два предиката над четвёркой: лечимый путь
//! (обычно — адреса решения, увод в ядре адресный) и прямой (обычно — имя разговора равно имени цели).
//! Откуда потребитель знает имя, фундаменту знать не нужно.
//!
//! ЦЕНА НАЗВАНА: разговор, умерший между снимками, в счёт не попадает — его байты за окно теряются.
//! Для вердикта это сторона осторожности: недосчитанный путь реже признаётся несущим. Записи с
//! [`CtDst::Unknown`] не идут ни в один путь — «не переписан» о них было бы ложью.

use reflex_core::meter::Pace;

use super::wire::{CtDst, Entry, Tuple};

/// Сколько прошло вниз за окно по каждому пути цели.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Paths {
    pub treated: Pace,
    pub direct: Pace,
}

/// Прирост байт ответа за окно: разговор, которого не было в первом снимке, растёт от нуля.
fn grown(before: &[Entry], entry: &Entry) -> u64 {
    let earlier = before
        .iter()
        .find(|seen| seen.orig == entry.orig)
        .map_or(0, |seen| seen.reply_counts.bytes);
    entry.reply_counts.bytes.saturating_sub(earlier)
}

/// Два снимка, чьи разговоры считать лечимыми (среди переписанных) и прямыми (среди непереписанных), и
/// длина окна в наносекундах — темп каждого пути.
pub fn paths(
    before: &[Entry],
    after: &[Entry],
    treated: impl Fn(&Tuple) -> bool,
    direct: impl Fn(&Tuple) -> bool,
    over_nanos: u64,
) -> Paths {
    let (on_treated, on_direct) =
        after
            .iter()
            .fold((0u64, 0u64), |(on_treated, on_direct), entry| {
                match entry.dst {
                    CtDst::Rewritten if treated(&entry.orig) => {
                        (on_treated.saturating_add(grown(before, entry)), on_direct)
                    }
                    CtDst::Kept if direct(&entry.orig) => {
                        (on_treated, on_direct.saturating_add(grown(before, entry)))
                    }
                    CtDst::Rewritten | CtDst::Kept | CtDst::Unknown => (on_treated, on_direct),
                }
            });
    Paths {
        treated: Pace {
            bytes: on_treated,
            over_nanos,
        },
        direct: Pace {
            bytes: on_direct,
            over_nanos,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conntrack::wire::Counts;
    use std::net::Ipv4Addr;

    const WINDOW: u64 = 30_000_000_000;
    const NODE: Ipv4Addr = Ipv4Addr::new(74, 125, 104, 200);

    fn entry(dst: Ipv4Addr, client_port: u16, proto: u8, path: CtDst, reply_bytes: u64) -> Entry {
        Entry {
            orig: Tuple {
                src: u32::from(Ipv4Addr::new(192, 168, 2, 196)),
                dst: u32::from(dst),
                src_port: client_port,
                dst_port: 443,
                proto,
            },
            reply_counts: Counts {
                packets: 1,
                bytes: reply_bytes,
            },
            dst: path,
            ..Entry::default()
        }
    }

    fn to_node(tuple: &Tuple) -> bool {
        Ipv4Addr::from(tuple.dst) == NODE
    }

    #[test]
    fn the_field_case_quic_carries_directly_while_the_diverted_tcp_trickles() {
        // .8, 17.09: TCP к узлу уведён — 216 байт; QUIC к тому же узлу по прямой — рос с 1 МБ до 6 МБ за окно.
        let before = [entry(NODE, 51_000, 17, CtDst::Kept, 1_000_000)];
        let after = [
            entry(NODE, 36_012, 6, CtDst::Rewritten, 216),
            entry(NODE, 51_000, 17, CtDst::Kept, 6_000_000),
        ];
        assert_eq!(
            paths(&before, &after, to_node, to_node, WINDOW),
            Paths {
                treated: Pace {
                    bytes: 216,
                    over_nanos: WINDOW
                },
                direct: Pace {
                    bytes: 5_000_000,
                    over_nanos: WINDOW
                },
            }
        );
    }

    #[test]
    fn a_stranger_on_a_shared_front_is_not_the_direct_path_of_the_target() {
        // Стенд, 17.09: на тот же адрес фронта по прямой шли 7,5 МБ/с чужого имени. Прямая цели — только её
        // разговоры; здесь «её» — порт клиента 51 000, чужой — 52 000.
        let after = [
            entry(NODE, 36_012, 6, CtDst::Rewritten, 216),
            entry(NODE, 52_000, 17, CtDst::Kept, 225_000_000),
        ];
        let theirs = |tuple: &Tuple| to_node(tuple) && tuple.src_port == 51_000;
        assert_eq!(paths(&[], &after, to_node, theirs, WINDOW).direct.bytes, 0);
    }

    #[test]
    fn an_unknown_path_is_counted_nowhere() {
        let after = [entry(NODE, 40_000, 6, CtDst::Unknown, 9_999_999)];
        let counted = paths(&[], &after, to_node, to_node, WINDOW);
        assert_eq!((counted.treated.bytes, counted.direct.bytes), (0, 0));
    }
}
