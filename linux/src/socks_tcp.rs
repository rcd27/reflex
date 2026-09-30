//! КЛИЕНТ SOCKS5 CONNECT (RFC 1928 §4) — общего назначения, сосед [`crate::socks_udp`]: TCP к
//! адресату через прокси (в проде — локальный `xray`; мост Telegram везёт им DC, которые край
//! WebSocket не обслуживает, #355).
//!
//! Рукопожатие одно на оба клиента — greeting, no-auth и разбор ответа живут в `socks_udp`, и
//! здесь они не повторены: две копии разбора ответа разошлись бы молча, как уже расходились
//! смещения заголовка датаграммы до того, как грамматику вынесли.
//!
//! Возвращается сам поток: после успешного ответа прокси он прозрачен, и первый байт, записанный
//! в него, уходит адресату. `BND.ADDR` ответа не нужен вовсе — это адрес, с которого прокси
//! говорит с адресатом, а не адрес, на который пишем мы.

use std::net::{SocketAddr, SocketAddrV4};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::socks_udp::{accepted_no_auth, greeting, read_reply};

const VERSION: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const RESERVED: u8 = 0x00;
const ATYP_V4: u8 = 0x01;

/// TCP к `target` через SOCKS5-прокси `proxy`: greeting (no-auth) → `CONNECT target` → поток.
pub async fn connected(proxy: SocketAddrV4, target: SocketAddrV4) -> Result<TcpStream, String> {
    let mut stream = TcpStream::connect(SocketAddr::V4(proxy))
        .await
        .map_err(|err| format!("SOCKS5: TCP к прокси {proxy} не поднят: {err}"))?;
    stream
        .write_all(&greeting())
        .await
        .map_err(|err| format!("SOCKS5: greeting не отправлен: {err}"))?;
    let mut method_reply = [0u8; 2];
    stream
        .read_exact(&mut method_reply)
        .await
        .map_err(|err| format!("SOCKS5: ответ на greeting не прочитан: {err}"))?;
    accepted_no_auth(method_reply)?;
    stream
        .write_all(&connect_request(target))
        .await
        .map_err(|err| format!("SOCKS5 CONNECT: запрос не отправлен: {err}"))?;
    let _bound = read_reply(&mut stream, *proxy.ip(), "CONNECT").await?;
    Ok(stream)
}

/// `VER CMD=CONNECT RSV ATYP=IPv4 DST.ADDR DST.PORT` (RFC 1928 §4).
fn connect_request(target: SocketAddrV4) -> Vec<u8> {
    [VERSION, CMD_CONNECT, RESERVED, ATYP_V4]
        .into_iter()
        .chain(target.ip().octets())
        .chain(target.port().to_be_bytes())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn connect_request_names_the_target_by_address() {
        assert_eq!(
            connect_request(SocketAddrV4::new(Ipv4Addr::new(149, 154, 171, 255), 443)),
            vec![0x05, 0x01, 0x00, 0x01, 149, 154, 171, 255, 0x01, 0xbb]
        );
    }
}
