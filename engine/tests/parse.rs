use reflex_engine::{Addr, Dir};
use reflex_engine::parse::{head_of, read, Head, Read, SERVER_PORT};

const CLIENT: u32 = 0xC0A8_0164;
const SERVER: u32 = 0x8EFA_BD0E;
const NAME: &[u8] = b"www.youtube.com";

/// Кадр с датаграммой: тот же IP-заголовок, протокол 17, восьмибайтовый заголовок UDP.
fn udp_frame(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, body: &[u8]) -> Vec<u8> {
    let payload = (8 + body.len()) as u16;
    [
        &[0x45u8, 0x00][..],
        &(20 + payload).to_be_bytes(),
        &[0x00, 0x01, 0x40, 0x00, 0x40, 17, 0x00, 0x00],
        &src_ip.to_be_bytes(),
        &dst_ip.to_be_bytes(),
        &src_port.to_be_bytes(),
        &dst_port.to_be_bytes(),
        &payload.to_be_bytes(),
        &[0x00, 0x00],
        body,
    ]
    .concat()
}

fn frame(
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    flags: u8,
    body: &[u8],
) -> Vec<u8> {
    let total = (40 + body.len()) as u16;
    [
        &[0x45u8, 0x00][..],
        &total.to_be_bytes(),
        &[0x00, 0x01, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00],
        &src_ip.to_be_bytes(),
        &dst_ip.to_be_bytes(),
        &src_port.to_be_bytes(),
        &dst_port.to_be_bytes(),
        &[0, 0, 0, 1, 0, 0, 0, 1],
        &[0x50, flags, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00],
        body,
    ]
    .concat()
}

fn hello(extensions: &[u8]) -> Vec<u8> {
    let body = [
        &[0x03u8, 0x03][..],
        &[0x11; 32],
        &[32],
        &[0x22; 32],
        &[0x00, 0x04],
        &[0x13, 0x01, 0x13, 0x02],
        &[0x01, 0x00],
        &(extensions.len() as u16).to_be_bytes(),
        extensions,
    ]
    .concat();
    let handshake = [
        &[0x01u8][..],
        &(body.len() as u32).to_be_bytes()[1..4],
        &body,
    ]
    .concat();
    [
        &[0x16u8, 0x03, 0x01][..],
        &(handshake.len() as u16).to_be_bytes(),
        &handshake,
    ]
    .concat()
}

fn sni_extension(name: &[u8]) -> Vec<u8> {
    let entry = [&[0x00u8][..], &(name.len() as u16).to_be_bytes(), name].concat();
    let list = [&(entry.len() as u16).to_be_bytes()[..], &entry].concat();
    [
        &[0x00u8, 0x00][..],
        &(list.len() as u16).to_be_bytes(),
        &list,
    ]
    .concat()
}

fn padding_extension(len: usize) -> Vec<u8> {
    [
        &[0x00u8, 0x15][..],
        &(len as u16).to_be_bytes(),
        &vec![0u8; len],
    ]
    .concat()
}

#[test]
fn the_sni_offset_indexes_the_name_itself_not_a_number_near_it() {
    let payload = hello(&sni_extension(NAME));

    match head_of(&payload) {
        Head::Hello { sni_at, sni_len } => {
            let at = sni_at as usize;
            assert_eq!(&payload[at..at + sni_len as usize], NAME);
        }
        other => panic!("ожидалось имя, пришло {other:?}"),
    }
}

#[test]
fn the_name_is_found_behind_other_extensions() {
    let payload = hello(&[padding_extension(37), sni_extension(NAME)].concat());

    match head_of(&payload) {
        Head::Hello { sni_at, sni_len } => {
            let at = sni_at as usize;
            assert_eq!(&payload[at..at + sni_len as usize], NAME);
        }
        other => panic!("ожидалось имя, пришло {other:?}"),
    }
}

#[test]
fn a_hello_without_the_extension_is_told_apart_from_something_that_is_not_a_hello() {
    assert_eq!(
        head_of(&hello(&padding_extension(8))),
        Head::HelloWithoutName
    );
    assert_eq!(head_of(b"GET / HTTP/1.1\r\n"), Head::Opaque);
    assert_eq!(head_of(&[]), Head::Opaque);
}

#[test]
fn a_truncated_hello_never_points_past_the_payload() {
    let full = hello(&sni_extension(NAME));

    (0..full.len()).for_each(|cut| match head_of(&full[..cut]) {
        Head::Hello { sni_at, sni_len } => {
            assert!(sni_at as usize + sni_len as usize <= cut, "срез {cut}");
        }
        Head::HelloWithoutName => (),
        Head::Opaque => (),
    });
}

#[test]
fn both_directions_of_one_conversation_share_a_single_flow_key() {
    let up = frame(CLIENT, SERVER, 51000, SERVER_PORT, 0x18, b"hi");
    let down = frame(SERVER, CLIENT, SERVER_PORT, 51000, 0x18, b"ho");

    match (read(&up, SERVER_PORT), read(&down, SERVER_PORT)) {
        (Read::Tcp(upward), Read::Tcp(downward)) => {
            assert_eq!(upward.flow, downward.flow);
            assert_eq!(upward.dir, Dir::Up);
            assert_eq!(downward.dir, Dir::Down);
        }
        other => panic!("ожидались два TCP, пришло {other:?}"),
    }
}

#[test]
fn the_target_is_the_server_in_both_directions() {
    let up = frame(CLIENT, SERVER, 51000, SERVER_PORT, 0x18, b"hi");
    let down = frame(SERVER, CLIENT, SERVER_PORT, 51000, 0x18, b"ho");

    match (read(&up, SERVER_PORT), read(&down, SERVER_PORT)) {
        (Read::Tcp(upward), Read::Tcp(downward)) => {
            assert_eq!(upward.dst, Addr(SERVER));
            assert_eq!(downward.dst, Addr(SERVER));
        }
        other => panic!("ожидались два TCP, пришло {other:?}"),
    }
}

#[test]
fn different_clients_behind_one_box_do_not_share_a_cursor() {
    let one = frame(CLIENT, SERVER, 51000, SERVER_PORT, 0x02, b"");
    let other = frame(CLIENT + 1, SERVER, 51000, SERVER_PORT, 0x02, b"");
    let same_client_other_port = frame(CLIENT, SERVER, 51001, SERVER_PORT, 0x02, b"");

    match (
        read(&one, SERVER_PORT),
        read(&other, SERVER_PORT),
        read(&same_client_other_port, SERVER_PORT),
    ) {
        (Read::Tcp(first), Read::Tcp(second), Read::Tcp(third)) => {
            assert_ne!(first.flow, second.flow);
            assert_ne!(first.flow, third.flow);
        }
        other => panic!("ожидались три TCP, пришло {other:?}"),
    }
}

#[test]
fn flags_are_read_as_the_events_the_law_reacts_to() {
    let syn = frame(CLIENT, SERVER, 51000, SERVER_PORT, 0x02, b"");
    let fin = frame(CLIENT, SERVER, 51000, SERVER_PORT, 0x11, b"");
    let rst = frame(SERVER, CLIENT, SERVER_PORT, 51000, 0x04, b"");

    match (
        read(&syn, SERVER_PORT),
        read(&fin, SERVER_PORT),
        read(&rst, SERVER_PORT),
    ) {
        (Read::Tcp(opened), Read::Tcp(closed), Read::Tcp(reset)) => {
            assert!(opened.opens && !opened.closes && !opened.resets);
            assert!(closed.closes && !closed.opens);
            assert!(reset.resets && reset.dir == Dir::Down);
        }
        other => panic!("ожидались три TCP, пришло {other:?}"),
    }
}

#[test]
fn traffic_that_is_not_ours_is_named_rather_than_silently_dropped() {
    let elsewhere = frame(CLIENT, SERVER, 51000, 22, 0x18, b"ssh");
    // ICMP: не TCP и не UDP — разбирать нечем.
    let icmpish = [&frame(CLIENT, SERVER, 1, 2, 0, b"")[..9], &[1u8][..]].concat();

    assert_eq!(read(&elsewhere, SERVER_PORT), Read::NotOurPort);
    assert_eq!(read(&icmpish, SERVER_PORT), Read::NotOurProtocol);
    assert_eq!(read(&[0x60], SERVER_PORT), Read::NotIpv4);
    assert_eq!(read(&[], SERVER_PORT), Read::Truncated);
}

/// ОБРЕЗАННЫЙ КАДР НАЗЫВАЕТСЯ ОБРЕЗАННЫМ, А НЕ ЧУЖИМ.
///
/// Причина отказа уходит в счётчик `unparsed`, и подмена «кадр обрезан» на «мы такое не
/// разбираем» превращает беду в норму: первое требует разбирательства, второе — нет.
#[test]
fn a_truncated_frame_of_our_protocol_is_named_truncated() {
    let full = frame(CLIENT, SERVER, 51000, SERVER_PORT, 0x18, b"hello");
    [14usize, 16, 18].into_iter().for_each(|cut| {
        assert_eq!(
            read(&full[..cut], SERVER_PORT),
            Read::Truncated,
            "кадр TCP, обрезанный на {cut} байтах"
        );
    });

    let datagram = udp_frame(CLIENT, SERVER, 51000, SERVER_PORT, b"initial");
    assert_eq!(read(&datagram[..16], SERVER_PORT), Read::Truncated);
}

/// ДАТАГРАММА РАЗБИРАЕТСЯ КАК СОЕДИНЕНИЕ И ВЕДЁТ К ТОЙ ЖЕ ЦЕЛИ, но разговором остаётся ДРУГИМ:
/// протокол входит в личность (§4).
///
/// Прежде тест требовал совпадения ключей, и требование было верным по намерению: разойдись
/// знание о цели по транспортам — лечение, заработанное на TCP, не досталось бы QUIC. Но место
/// намерению не то. Сводить транспорты — работа слоя ЦЕЛИ (`TargetKey` протокола не несёт), а не
/// общего ключа разговора; слитый ключ брал у личности разговора взаймы для нужд цели.
#[test]
fn a_datagram_leads_to_the_same_target_but_is_another_conversation() {
    let quic = udp_frame(CLIENT, SERVER, 51000, SERVER_PORT, b"initial");
    let tcp = frame(CLIENT, SERVER, 51000, SERVER_PORT, 0x18, b"hello");

    match (read(&quic, SERVER_PORT), read(&tcp, SERVER_PORT)) {
        (Read::Udp(datagram), Read::Tcp(wire)) => {
            assert_ne!(datagram.flow, wire.flow, "разные транспорты — разные разговоры");
            assert_eq!(
                (datagram.flow.src, datagram.flow.dst),
                (wire.flow.src, wire.flow.dst),
                "концы те же: цель одна, сводит её слой цели"
            );
            assert_eq!(datagram.dst, wire.dst);
            assert_eq!(datagram.payload, b"initial");
        }
        (left, right) => panic!("кадры не разобраны: {left:?} / {right:?}"),
    }
}

/// СТОРОНУ ДАТАГРАММЫ РАЗВОДИТ ПОРТ, как и у соединения: ответ цели идёт вниз.
#[test]
fn a_datagram_from_the_target_goes_downward() {
    let back = udp_frame(SERVER, CLIENT, SERVER_PORT, 51000, b"reply");
    match read(&back, SERVER_PORT) {
        Read::Udp(datagram) => {
            assert_eq!(datagram.dir, Dir::Down);
            assert_eq!(datagram.dst, Addr(SERVER), "цель — та же сторона");
        }
        other => panic!("датаграмма не разобрана: {other:?}"),
    }
}

/// ЧУЖОЙ ПОРТ У ДАТАГРАММЫ ОТВЕРГАЕТСЯ ТАК ЖЕ, как у соединения: DNS по 53 в очередь не идёт.
#[test]
fn a_datagram_on_a_foreign_port_is_not_ours() {
    let dns = udp_frame(CLIENT, SERVER, 51000, 53, b"query");
    assert_eq!(read(&dns, SERVER_PORT), Read::NotOurPort);
}

#[test]
fn the_servers_syn_ack_is_not_counted_as_the_client_opening_a_conversation() {
    let syn = frame(CLIENT, SERVER, 51000, SERVER_PORT, 0x02, b"");
    let syn_ack = frame(SERVER, CLIENT, SERVER_PORT, 51000, 0x12, b"");

    match (read(&syn, SERVER_PORT), read(&syn_ack, SERVER_PORT)) {
        (Read::Tcp(client), Read::Tcp(server)) => {
            assert!(client.opens);
            assert!(!server.opens);
        }
        other => panic!("ожидались два TCP, пришло {other:?}"),
    }
}
