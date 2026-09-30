//! Клиент SOCKS5 CONNECT (#355) — против ПОДДЕЛЬНОГО сервера на `127.0.0.1`: протокол
//! (RFC 1928 §4) от `xray` не зависит.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use reflex_linux::socks_tcp::connected;

async fn listener() -> (TcpListener, SocketAddrV4) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let SocketAddr::V4(addr) = listener.local_addr().expect("addr") else {
        panic!("тест слушает только IPv4");
    };
    (listener, addr)
}

/// Поддельный прокси: greeting → CONNECT → ответ `rep`; при успехе — эхо всего, что пришло после.
/// Возвращает запрос CONNECT, каким его прислал клиент.
async fn fake_proxy(listener: TcpListener, rep: u8) -> [u8; 10] {
    let (mut stream, _) = listener.accept().await.expect("accept");
    let mut greeting = [0u8; 3];
    stream.read_exact(&mut greeting).await.expect("greeting");
    assert_eq!(
        greeting,
        [0x05, 0x01, 0x00],
        "клиент обязан просить no-auth"
    );
    stream.write_all(&[0x05, 0x00]).await.expect("method");
    let mut request = [0u8; 10];
    stream.read_exact(&mut request).await.expect("connect");
    stream
        .write_all(&[0x05, rep, 0x00, 0x01, 10, 0, 0, 1, 0x30, 0x39])
        .await
        .expect("reply");
    let mut echo = [0u8; 5];
    match rep {
        0x00 => {
            stream.read_exact(&mut echo).await.expect("payload");
            stream.write_all(&echo).await.expect("echo");
        }
        _refused => (),
    }
    request
}

#[tokio::test]
async fn bytes_after_connect_reach_the_target_and_come_back() {
    let (listener, proxy) = listener().await;
    let target = SocketAddrV4::new(Ipv4Addr::new(149, 154, 171, 255), 443);
    let server = tokio::spawn(fake_proxy(listener, 0x00));

    let Ok(mut stream) = connected(proxy, target).await else {
        panic!("CONNECT не прошёл");
    };
    stream.write_all(b"hello").await.expect("write");
    let mut back = [0u8; 5];
    stream.read_exact(&mut back).await.expect("read");

    assert_eq!(&back, b"hello");
    let Ok(request) = server.await else {
        panic!("сервер упал");
    };
    assert_eq!(
        request,
        [0x05, 0x01, 0x00, 0x01, 149, 154, 171, 255, 0x01, 0xbb]
    );
}

#[tokio::test]
async fn a_refused_connect_is_named_as_connect() {
    let (listener, proxy) = listener().await;
    let target = SocketAddrV4::new(Ipv4Addr::new(149, 154, 175, 211), 443);
    let _server = tokio::spawn(fake_proxy(listener, 0x05));

    let refused = connected(proxy, target).await;

    assert!(
        matches!(&refused, Err(why) if why.contains("CONNECT") && why.contains("0x5")),
        "отказ прокси не назван: {:?}",
        refused.map(|_stream| ())
    );
}
