//! Ключ потока — одна личность из двух источников. Пока горячий путь берёт четвёрку из
//! `CTA_TUPLE_ORIG`, а фолбэк — из провода, оба обязаны ковать ТОТ ЖЕ ключ: иначе беда, найденная
//! по ядерному состоянию, не найдёт имени, заведённого по проводу (шов из спеки ct-края).

use reflex_engine_nfq::parse::{keyed, keyed_of_tuple, wired, Ends, Header, Segment};
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

/// Ключ, выкованный из разобранного провода, и ключ из четвёрки ядра — один и тот же ключ.
/// Иначе беда, найденная по ядерному состоянию, не найдёт имени, заведённого по проводу.
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
    assert_eq!(
        keyed_of_tuple(tuple.src, tuple.src_port, tuple.dst, tuple.dst_port),
        wire_key
    );
}

/// Направление не теряется: ответный кортеж даёт ключ того же разговора, а не второго.
#[test]
fn reply_direction_yields_the_same_conversation() {
    let tuple = Tuple {
        src: 0x0A00_0001,
        dst: 0x5DB8_D822,
        src_port: 44321,
        dst_port: 443,
        proto: 6,
    };
    let reply = Tuple {
        src: tuple.dst,
        dst: tuple.src,
        src_port: tuple.dst_port,
        dst_port: tuple.src_port,
        proto: 6,
    };
    // Разворот перед ковкой — обязанность зовущего: ключ несимметричен по построению.
    assert_eq!(
        keyed_of_tuple(reply.dst, reply.dst_port, reply.src, reply.src_port),
        keyed_of_tuple(tuple.src, tuple.src_port, tuple.dst, tuple.dst_port)
    );
}

/// Два источника четвёрки дают один ключ: пока это так, фолбэк на провод не заводит второго
/// понятия «какой это поток».
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
        keyed_of_tuple(tuple.src, tuple.src_port, tuple.dst, tuple.dst_port),
        from_wire,
        "ORIG-инициатор и upward-клиент — одно лицо"
    );
}

/// Протокол в ключ не входит: QUIC и TCP к одной цели остаются одним разговором, как объявлено
/// докблоком `datagrammed`.
#[test]
fn protocol_does_not_enter_the_key() {
    let tcp = Tuple {
        src: 0x0A00_0001,
        dst: 0x5DB8_D822,
        src_port: 44321,
        dst_port: 443,
        proto: 6,
    };
    let quic = Tuple { proto: 17, ..tcp };
    assert_eq!(
        keyed_of_tuple(tcp.src, tcp.src_port, tcp.dst, tcp.dst_port),
        keyed_of_tuple(quic.src, quic.src_port, quic.dst, quic.dst_port)
    );
}
