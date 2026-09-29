//! ЧИСТАЯ ГРАММАТИКА SOCKS5 UDP (RFC 1928, §7) — заголовок датаграммы `UDP ASSOCIATE`.
//!
//! # Зачем отдельно от сокета
//!
//! Звонковый UDP человека мы впрыскиваем в локальный `xray` через SOCKS5 `UDP ASSOCIATE`: сокет
//! принимает не голую датаграмму, а датаграмму С ЗАГОЛОВКОМ, называющим настоящего адресата
//! (`DST.ADDR`/`DST.PORT`). Разбор заголовка — байты в байты, без сети и без сокета: держать его
//! вместе с сокетом значило бы проверять смещения только живым `xray`, а ошибиться в них легче
//! всего именно там.
//!
//! # Три исхода разбора, а не один `Option`
//!
//! [`Fragmented`](Decapsulated::Fragmented) и [`Malformed`](Decapsulated::Malformed) — РАЗНЫЕ
//! вещи, хотя обе «не датаграмма». Фрагмент (`FRAG ≠ 0`) — законный на проводе случай, которого мы
//! не поддерживаем: склеить его догадкой значило бы отдать человеку кусок под видом целого пакета
//! голоса, который клиент Telegram молча уронит, а глава хроники посчитает доставленным.
//! `Malformed` — заголовок, который вообще нельзя прочесть (обрезан, домен вместо адреса).
//! Смешать оба исхода в один `None` значило бы вернуть причину потери туда же, откуда её унесли, —
//! в догадку вызывающего.
//!
//! # Почему домен (ATYP 3) — `Malformed`, а не третий вид адреса
//!
//! `xray` вправе отвечать доменным именем ТОМУ, кто сам назвал адресата доменом. Мы называем
//! цель [`SocketAddrV4`] в [`encapsulated`], и своим же видом адреса отвечает нам только тот, кого
//! мы сами так назвали, — ответ доменом на нашей паре сокетов не наш протокол. Адрес ответа релея
//! обязан быть адресом: заголовку IP, которым мы впрыскиваем пакет человеку, некуда положить имя.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

/// ЗАВЕРНУТЬ ДАТАГРАММУ для `UDP ASSOCIATE`: `RSV(2)=0 FRAG(1)=0 ATYP(1)=1 DST.ADDR DST.PORT DATA`.
///
/// `FRAG` всегда ноль — фрагментацию посредники почти поголовно не поддерживают, а нам она и не
/// нужна: голос несёт свою датаграмму (RTP, QUIC) целиком внутри одного UDP-пакета.
pub fn encapsulated(target: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    [0x00, 0x00, 0x00, 0x01]
        .into_iter()
        .chain(target.ip().octets())
        .chain(target.port().to_be_bytes())
        .chain(payload.iter().copied())
        .collect()
}

/// РЕЗУЛЬТАТ РАЗБОРА ответа `UDP ASSOCIATE`: кто прислал и что, либо названная причина отказа.
///
/// Три формы вместо `Option<(SocketAddr, &[u8])>` — см. докблок модуля: `Fragmented` и
/// `Malformed` требуют РАЗНОГО лечения у вызывающего, и не различать их значило бы решить это
/// молча за него.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decapsulated<'a> {
    /// Заголовок цел, адрес — IPv4 или IPv6. `payload` — срез хвоста ВХОДНОЙ датаграммы, без
    /// копии: копия на каждый звонковый пакет — аллокация в горячем пути голоса.
    Datagram { from: SocketAddr, payload: &'a [u8] },
    /// `FRAG ≠ 0`: датаграмма — часть более крупной, которую мы не склеиваем.
    Fragmented,
    /// Заголовок нельзя прочесть: обрезан либо адрес — домен (ATYP 3) или неизвестный вид.
    Malformed,
}

/// РАЗВЕРНУТЬ ОТВЕТ `UDP ASSOCIATE`.
///
/// `RSV` не проверяется отдельно: RFC требует нулей, но эти два байта ни на что не влияют дальше
/// — заголовок с мусорным `RSV`, но осмысленными `FRAG`/`ATYP`/адресом, разбирается так же, как
/// назвал бы его сам `xray`, если бы вдруг не занулил резерв. Судить о содержимом по резерву,
/// который никто не читает, — ложная строгость.
pub fn decapsulated(datagram: &[u8]) -> Decapsulated<'_> {
    match datagram.get(2..4) {
        Some([0, 0x01]) => v4_datagram(datagram).unwrap_or(Decapsulated::Malformed),
        Some([0, 0x04]) => v6_datagram(datagram).unwrap_or(Decapsulated::Malformed),
        Some([0, _domain_or_unknown_atyp]) => Decapsulated::Malformed,
        Some([_nonzero_frag, _any_atyp]) => Decapsulated::Fragmented,
        _too_short_for_frag_and_atyp => Decapsulated::Malformed,
    }
}

/// `DST.ADDR`/`DST.PORT` вида IPv4 (ATYP 1): четыре байта адреса и два байта порта сразу за ними.
fn v4_datagram(datagram: &[u8]) -> Option<Decapsulated<'_>> {
    let octets: [u8; 4] = datagram.get(4..8)?.try_into().ok()?;
    let port = u16::from_be_bytes(datagram.get(8..10)?.try_into().ok()?);
    let payload = datagram.get(10..)?;
    Some(Decapsulated::Datagram {
        from: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(octets), port)),
        payload,
    })
}

/// `DST.ADDR`/`DST.PORT` вида IPv6 (ATYP 4): шестнадцать байт адреса и два байта порта.
fn v6_datagram(datagram: &[u8]) -> Option<Decapsulated<'_>> {
    let octets: [u8; 16] = datagram.get(4..20)?.try_into().ok()?;
    let port = u16::from_be_bytes(datagram.get(20..22)?.try_into().ok()?);
    let payload = datagram.get(22..)?;
    Some(Decapsulated::Datagram {
        from: SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(octets), port, 0, 0)),
        payload,
    })
}
