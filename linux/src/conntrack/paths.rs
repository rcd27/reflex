//! Темп ЛЕЧИМОГО и ПРЯМОГО пути к адресам цели — из двух снимков conntrack за одно окно. Вход
//! вердикта [`reflex_core::remedy::remedy`]: сам вердикт не знает ядра, ядро не знает вердикта.
//!
//! Путь различает бит ядра ([`CtDst`]), а не приказ марки: уведённый разговор — тот, чей адрес
//! назначения переписан. Протокол не различается НАРОЧНО: на канарейке 17.09.2026 уведённым был TCP, а
//! несла прямая по QUIC к тому же адресу, и сравнение внутри одного протокола этот случай не увидело бы.
//!
//! ЦЕНА НАЗВАНА: разговор, умерший между снимками, в счёт не попадает — его байты за окно теряются.
//! Для вердикта это сторона осторожности: недосчитанный путь реже признаётся несущим. Записи с
//! [`CtDst::Unknown`] не идут ни в один путь — «не переписан» о них было бы ложью.

use std::net::Ipv4Addr;

use reflex_core::meter::Pace;

use super::wire::{CtDst, Entry};

/// Сколько прошло вниз за окно по каждому пути к адресам цели.
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

/// Два снимка, адреса цели и длина окна в наносекундах — темп каждого пути.
pub fn paths(before: &[Entry], after: &[Entry], addrs: &[Ipv4Addr], over_nanos: u64) -> Paths {
    let (treated, direct) = after
        .iter()
        .filter(|entry| addrs.contains(&Ipv4Addr::from(entry.orig.dst)))
        .fold((0u64, 0u64), |(treated, direct), entry| match entry.dst {
            CtDst::Rewritten => (treated.saturating_add(grown(before, entry)), direct),
            CtDst::Kept => (treated, direct.saturating_add(grown(before, entry))),
            CtDst::Unknown => (treated, direct),
        });
    Paths {
        treated: Pace {
            bytes: treated,
            over_nanos,
        },
        direct: Pace {
            bytes: direct,
            over_nanos,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conntrack::wire::{Counts, Tuple};

    const WINDOW: u64 = 30_000_000_000;

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

    const NODE: Ipv4Addr = Ipv4Addr::new(74, 125, 104, 200);

    #[test]
    fn the_field_case_quic_carries_directly_while_the_diverted_tcp_trickles() {
        // .8, 17.09: TCP к узлу уведён — 216 байт; QUIC к тому же узлу по прямой — рос с 1 МБ до 6 МБ за окно.
        let before = [entry(NODE, 51_000, 17, CtDst::Kept, 1_000_000)];
        let after = [
            entry(NODE, 36_012, 6, CtDst::Rewritten, 216),
            entry(NODE, 51_000, 17, CtDst::Kept, 6_000_000),
        ];
        assert_eq!(
            paths(&before, &after, &[NODE], WINDOW),
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
    fn other_addresses_do_not_count() {
        let after = [entry(
            Ipv4Addr::new(1, 1, 1, 1),
            40_000,
            6,
            CtDst::Kept,
            9_999_999,
        )];
        assert_eq!(paths(&[], &after, &[NODE], WINDOW).direct.bytes, 0);
    }

    #[test]
    fn an_unknown_path_is_counted_nowhere() {
        let after = [entry(NODE, 40_000, 6, CtDst::Unknown, 9_999_999)];
        let counted = paths(&[], &after, &[NODE], WINDOW);
        assert_eq!((counted.treated.bytes, counted.direct.bytes), (0, 0));
    }
}
