//! Клиент SOCKS5 UDP ASSOCIATE (#355, мост звонков Telegram) — против ПОДДЕЛЬНОГО сервера на
//! `127.0.0.1`: настоящего `xray` здесь нет, а протокол (RFC 1928 §4, §7) от него не зависит.
//! Живой прогон против настоящего `xray` — `association_reaches_a_real_stun_server_through_xray`,
//! `#[ignore]`.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use reflex_linux::socks_udp::Association;

/// Поддельный SOCKS5-сервер: greeting (no-auth) → ASSOCIATE → BND `0.0.0.0:<порт своего UDP>`.
/// Возвращает адрес, на котором слушает управляющий TCP, и адрес UDP-релея (для сверки datagram).
async fn fake_server() -> (SocketAddrV4, UdpSocket, TcpListener) {
    let control = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind control");
    let addr = match control.local_addr().expect("control addr") {
        SocketAddr::V4(v4) => v4,
        SocketAddr::V6(_) => panic!("тест поднимает control только на IPv4"),
    };
    let relay = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind relay udp");
    (addr, relay, control)
}

/// Проводит greeting+ASSOCIATE со стороны поддельного сервера один раз, отвечая BND `0.0.0.0` с
/// портом `relay` — ровно так отвечает `xray` (закон брифа задачи 3: `0.0.0.0` значит «мой адрес»).
async fn handshake(mut control: TcpStream, relay_port: u16) -> TcpStream {
    let mut greeting = [0u8; 3];
    control.read_exact(&mut greeting).await.expect("greeting");
    assert_eq!(
        greeting,
        [0x05, 0x01, 0x00],
        "клиент обязан просить no-auth"
    );
    control
        .write_all(&[0x05, 0x00])
        .await
        .expect("method reply");

    let mut associate = [0u8; 10];
    control
        .read_exact(&mut associate)
        .await
        .expect("associate request");
    assert_eq!(
        associate,
        [0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
        "ASSOCIATE обязан просить 0.0.0.0:0 (адрес пока неизвестен)"
    );

    let mut reply = vec![0x05, 0x00, 0x00, 0x01];
    reply.extend_from_slice(&Ipv4Addr::UNSPECIFIED.octets()); // BND.ADDR = 0.0.0.0 — закон xray
    reply.extend_from_slice(&relay_port.to_be_bytes());
    control.write_all(&reply).await.expect("associate reply");
    control
}

#[tokio::test]
async fn a_round_trip_through_a_fake_socks5_server() {
    let (proxy, relay, control_listener) = fake_server().await;
    let relay_port = relay.local_addr().expect("relay addr").port();

    let accepted = tokio::spawn(async move {
        let (control, _peer) = control_listener.accept().await.expect("accept control");
        handshake(control, relay_port).await
    });

    let association = tokio::time::timeout(Duration::from_secs(2), Association::opened(proxy))
        .await
        .expect("opened() не должен висеть")
        .expect("opened() обязан открыть ассоциацию");
    let _control = accepted.await.expect("сервер поднял связку");

    let target = SocketAddrV4::new(Ipv4Addr::new(91, 108, 9, 68), 1400);
    let sent_payload = b"STUN-BINDING-REQUEST".to_vec();
    association
        .sent(target, &sent_payload)
        .await
        .expect("sent() обязан уйти к релею");

    // Сервер получает завёрнутую датаграмму, проверяет адрес цели и отвечает "эхом от цели":
    // ту же DATA с иным DST (реального адреса релея тут нет — цель отвечает клиенту напрямую по
    // протоколу, релей лишь перекладывает).
    let mut buf = [0u8; 4096];
    let (n, from_client) = tokio::time::timeout(Duration::from_secs(2), relay.recv_from(&mut buf))
        .await
        .expect("relay должен получить датаграмму")
        .expect("recv_from");
    let incoming = &buf[..n];
    assert_eq!(
        &incoming[..4],
        &[0x00, 0x00, 0x00, 0x01],
        "RSV/FRAG/ATYP заголовка"
    );
    assert_eq!(
        &incoming[4..8],
        &target.ip().octets(),
        "DST.ADDR обязан быть адресом цели"
    );
    assert_eq!(
        &incoming[8..10],
        &target.port().to_be_bytes(),
        "DST.PORT обязан быть портом цели"
    );
    assert_eq!(
        &incoming[10..],
        &sent_payload[..],
        "DATA обязана дойти без изменений"
    );

    let mut echo = vec![0x00, 0x00, 0x00, 0x01];
    echo.extend_from_slice(&target.ip().octets());
    echo.extend_from_slice(&target.port().to_be_bytes());
    echo.extend_from_slice(b"echo:STUN-BINDING-REQUEST");
    relay
        .send_to(&echo, from_client)
        .await
        .expect("relay send_to");

    let (from, payload) = tokio::time::timeout(Duration::from_secs(2), association.received())
        .await
        .expect("received() не должен висеть")
        .expect("received() обязан вернуть датаграмму");
    assert_eq!(
        from,
        SocketAddr::V4(target),
        "от кого пришло — цель, а не релей"
    );
    assert_eq!(payload, b"echo:STUN-BINDING-REQUEST");
    assert!(association.alive(), "связка управления ещё жива");
}

#[tokio::test]
async fn closing_the_control_connection_kills_the_association() {
    let (proxy, relay, control_listener) = fake_server().await;
    let relay_port = relay.local_addr().expect("relay addr").port();

    let accepted = tokio::spawn(async move {
        let (control, _peer) = control_listener.accept().await.expect("accept control");
        handshake(control, relay_port).await
    });

    let association = tokio::time::timeout(Duration::from_secs(2), Association::opened(proxy))
        .await
        .expect("opened() не должен висеть")
        .expect("opened() обязан открыть ассоциацию");
    let control = accepted.await.expect("сервер поднял связку");

    drop(control); // сервер рвёт TCP-связку управления — ассоциация обязана умереть по RFC 1928 §7

    let died = tokio::time::timeout(Duration::from_secs(2), async {
        while association.alive() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        died.is_ok(),
        "alive() обязан стать false, а не остаться true навсегда"
    );

    let outcome = tokio::time::timeout(Duration::from_secs(2), association.received()).await;
    assert!(
        outcome.is_ok(),
        "received() обязан кончиться (ошибкой), а не висеть"
    );
    assert!(
        outcome.expect("timeout снят строкой выше").is_err(),
        "received() на мёртвой ассоциации обязан вернуть ошибку"
    );
}

/// STUN Binding Request (RFC 5389 §6): TYPE=0x0001, LENGTH=0, MAGIC COOKIE=0x2112A442, 12 байт
/// transaction id. Годится любым содержимым — сервер его не проверяет по значению.
fn stun_binding_request() -> Vec<u8> {
    let mut request = vec![0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42];
    request.extend(std::iter::repeat_with(rand_byte).take(12));
    request
}

/// Без внешней зависимости на `rand` ради двенадцати байт одного живого теста: адрес процесса как
/// источник разброса достаточен — transaction id не обязан быть криптографически случайным.
fn rand_byte() -> u8 {
    let addr = &stun_binding_request as *const _ as usize;
    (addr ^ std::time::Instant::now().elapsed().as_nanos() as usize) as u8
}

/// ЖИВОЙ ПРОГОН: настоящий `xray` на dev-машине (см. бриф задачи 3), STUN к серверу Telegram-
/// рефлектора `91.108.9.68:1400`. Не в обычной батарее — нужен запущенный процесс `xray` и сеть.
#[tokio::test]
#[ignore = "нужен запущенный xray (scratchpad/xray-spike) и доступ в сеть к 91.108.9.68:1400"]
async fn association_reaches_a_real_stun_server_through_xray() {
    let proxy = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 10808);
    let association = tokio::time::timeout(Duration::from_secs(5), Association::opened(proxy))
        .await
        .expect("opened() не должен висеть")
        .expect("opened() обязан открыть ассоциацию через живой xray");

    let target = SocketAddrV4::new(Ipv4Addr::new(91, 108, 9, 68), 1400);
    association
        .sent(target, &stun_binding_request())
        .await
        .expect("sent() обязан уйти к релею");

    let (from, payload) = tokio::time::timeout(Duration::from_secs(10), association.received())
        .await
        .expect("STUN-сервер обязан ответить за 10 секунд")
        .expect("received() обязан вернуть ответ STUN");
    assert_eq!(
        from,
        SocketAddr::V4(target),
        "ответ обязан прийти от адреса STUN-сервера"
    );
    assert!(payload.len() >= 20, "STUN-заголовок сам по себе 20 байт");
    assert_eq!(
        &payload[4..8],
        &[0x21, 0x12, 0xA4, 0x42],
        "magic cookie обязан вернуться как есть"
    );
}
