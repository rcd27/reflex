//! Ключ потока — одна личность из двух источников. Пока горячий путь берёт четвёрку из
//! `CTA_TUPLE_ORIG`, а фолбэк — из провода, оба обязаны ковать ТОТ ЖЕ ключ: иначе беда, найденная
//! по ядерному состоянию, не найдёт имени, заведённого по проводу (шов из спеки ct-края).
//!
//! Каждый тест обязан УМЕТЬ УПАСТЬ на сломанной ковке (Global Constraint плана): тавтология вида
//! `f(x) == f(x)` зелена на любой реализации и охраняет пустоту.

use reflex_engine_nfq::parse::{datagrammed, keyed, keyed_of_orig, wired, Ends, Header, Payload, Segment};
use reflex_linux::conntrack::Tuple;

/// SYN-сегмент клиента к серверу — минимум, чтобы `wired` выковал ключ по проводу.
fn syn_from(src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16) -> Segment<'static> {
    Segment {
        header: Header {
            ends: Ends {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
            },
            seq: 0,
            ack: 0,
            window: 0,
        },
        opens: true,
        handshakes: false,
        closes: false,
        resets: false,
        payload: &[],
    }
}

/// Датаграмма клиента к серверу — минимум, чтобы `datagrammed` выковал ключ по проводу.
fn payload_from(src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16) -> Payload<'static> {
    Payload {
        ends: Ends {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        },
        payload: &[],
    }
}

/// Ключ, выкованный из разобранного провода, и ключ из четвёрки ядра — один и тот же ключ.
/// Иначе беда, найденная по ядерному состоянию, не найдёт имени, заведённого по проводу.
/// Ловит поломку: перепутай стороны в `keyed_of_orig` — ключ разойдётся с проводным, тест краснеет.
#[test]
fn kernel_tuple_and_wire_forge_the_same_key() {
    let wire_key = keyed(0x0A00_0001, 44321, 0x5DB8_D822, 443);
    let tuple = Tuple {
        src: 0x0A00_0001,
        dst: 0x5DB8_D822,
        src_port: 44321,
        dst_port: 443,
        proto: 6,
    };
    assert_eq!(keyed_of_orig(tuple), wire_key);
}

/// Подмена ORIG на REPLY ловится, а не проходит молча: ключ несимметричен, и кортеж ответного
/// направления даёт ДРУГОЙ ключ. Охраняет не арифметику, а то, что направление вообще значимо —
/// ковка, слепая к сторонам, тут краснеет.
#[test]
fn feeding_the_reply_tuple_changes_the_key() {
    let orig = Tuple {
        src: 0x0A00_0001,
        dst: 0x5DB8_D822,
        src_port: 44321,
        dst_port: 443,
        proto: 6,
    };
    let reply = Tuple {
        src: orig.dst,
        dst: orig.src,
        src_port: orig.dst_port,
        dst_port: orig.src_port,
        proto: 6,
    };
    assert_ne!(
        keyed_of_orig(reply),
        keyed_of_orig(orig),
        "ключ несимметричен: перепутать направления — получить второй разговор"
    );
}

/// Два источника четвёрки дают один ключ: пока это так, фолбэк на провод не заводит второго
/// понятия «какой это поток». Идёт через `wired`, потому ловит поломку сторон в ковке.
#[test]
fn both_sources_agree_while_both_exist() {
    let segment = syn_from(0x0A00_0001, 44321, 0x5DB8_D822, 443);
    let from_wire = wired(segment, true).flow;
    let tuple = Tuple {
        src: 0x0A00_0001,
        dst: 0x5DB8_D822,
        src_port: 44321,
        dst_port: 443,
        proto: 6,
    };
    assert_eq!(
        keyed_of_orig(tuple),
        from_wire,
        "ORIG-инициатор и upward-клиент — одно лицо"
    );
}

/// Протокол в ключ не входит — и проверяется это ТАМ, ГДЕ ПРОТОКОЛ ЕСТЬ: ключ TCP-сегмента и
/// ключ UDP-датаграммы к одной цели совпадают, как объявляет докблок `datagrammed` («иначе знание
/// о цели разъедется по транспортам»). Сравнивать два вызова ковки, которая протокол не принимает, —
/// тавтология: такой тест зелен и на сломанной обёртке.
#[test]
fn tcp_and_udp_to_one_target_share_the_conversation() {
    let (src, src_port, dst, dst_port) = (0x0A00_0001, 44321, 0x5DB8_D822, 443);
    let over_tcp = wired(syn_from(src, src_port, dst, dst_port), true).flow;
    let over_udp = datagrammed(payload_from(src, src_port, dst, dst_port), true).flow;
    assert_eq!(over_tcp, over_udp, "один разговор, два транспорта");
    // И ключ из UDP-кортежа ядра (proto=17) совпадает с проводным TCP-ключом — proto роняется.
    assert_eq!(
        keyed_of_orig(Tuple {
            src,
            dst,
            src_port,
            dst_port,
            proto: 17,
        }),
        over_tcp
    );
}
