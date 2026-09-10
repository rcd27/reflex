//! Ключ потока — одна личность из двух источников. Пока горячий путь берёт четвёрку из
//! `CTA_TUPLE_ORIG`, а фолбэк — из провода, оба обязаны ковать ТОТ ЖЕ ключ: иначе беда, найденная
//! по ядерному состоянию, не найдёт имени, заведённого по проводу (шов из спеки ct-края).
//!
//! Каждый тест обязан УМЕТЬ УПАСТЬ на сломанной ковке (Global Constraint плана): тавтология вида
//! `f(x) == f(x)` зелена на любой реализации и охраняет пустоту.

use reflex_core::types::Protocol;
use reflex_engine::parse::{datagrammed, keyed, keyed_of_orig, wired, Ends, Header, Payload, Segment};
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
    let wire_key = keyed(0x0A00_0001, 44321, 0x5DB8_D822, 443, Protocol::Tcp);
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

/// Протокол ВХОДИТ в личность разговора: беседа по TCP и беседа по QUIC к одной цели — разные
/// разговоры, и одна машина на два транспорта была бы двумя машинами на одном ключе (§4).
///
/// Прежняя редакция утверждала обратное — ключи совпадают, «иначе знание о цели разъедется по
/// транспортам». Претензия была верной, а место ей не то: слив нужен ЦЕЛИ, а не разговору. Как
/// только цель стала отдельным слоем (`TargetKey` протокола не несёт), сведение переехало туда —
/// его делает копредел по слою, а не общий ключ разговора.
#[test]
fn tcp_and_udp_are_different_conversations_of_one_target() {
    let ends = (0x0A00_0001u32, 44321u16, 0x5DB8_D822u32, 443u16);
    let over_tcp = keyed(ends.0, ends.1, ends.2, ends.3, Protocol::Tcp);
    let over_udp = keyed(ends.0, ends.1, ends.2, ends.3, Protocol::Udp);

    assert_ne!(over_tcp, over_udp, "разные транспорты — разные разговоры");
    assert_eq!(
        (over_tcp.src, over_tcp.dst),
        (over_udp.src, over_udp.dst),
        "цель у них одна: сводит слой ЦЕЛИ, а не ключ разговора"
    );
}

/// ТО ЖЕ СОГЛАСИЕ ДВУХ ИСТОЧНИКОВ, НО НА UDP — и оно не следствие проверенного на TCP.
///
/// Проводные пути у транспортов РАЗНЫЕ функции (`wired` и `datagrammed`), и каждая сама решает,
/// кто клиент, а кто сервер. Согласие одной с ядром ничего не обещает о второй: перепутай стороны
/// в `datagrammed` — TCP-тесты выше останутся зелены все до одного.
///
/// Закон нужен не ради симметрии: на UDP едет разбор DNS, и разошедшийся ключ значил бы, что
/// подмена, найденная по ответу, не найдёт разговора, заведённого по запросу.
///
/// Прежде здесь был лишь заготовленный [`payload_from`], которого никто не звал: помощник без
/// закона — обещание, за которое ничего не отвечает. Компилятор говорил о нём предупреждением
/// целый день, и оно ЧИСЛИЛОСЬ ПРИНЯТЫМ в бюджете (`scripts/warnings.sh`) — принятым было не
/// «мёртвый код», а ненаписанный тест.
#[test]
fn both_sources_agree_over_udp_too() {
    let datagram = payload_from(0x0A00_0001, 44321, 0x5DB8_D822, 443);
    let from_wire = datagrammed(datagram, true).flow;
    let tuple = Tuple {
        src: 0x0A00_0001,
        dst: 0x5DB8_D822,
        src_port: 44321,
        dst_port: 443,
        proto: 17,
    };
    assert_eq!(
        keyed_of_orig(tuple),
        from_wire,
        "ORIG-инициатор датаграммы и upward-клиент — одно лицо"
    );
}
