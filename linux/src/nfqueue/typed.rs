//! Капабилити типизированного разбора (проекция `model/wire/FamilyGate.tla`): сырой
//! NFQUEUE-пакет парсится ОДИН раз на границе → семейство-гейт → типизированный вид
//! доменному хендлеру. General-purpose: reflex-подложка, не домен.
//!
//! Не-семейство (не IPv4+TCP) DOWN-SHIFT'ится (fail-open Accept), хендлер НЕ зовётся.
//! Поддержанное → `WireHandler::on(&WirePacket)` с распарсенным L7. Домен перестаёт
//! сам байт-walk'ать IP/TCP.

use std::net::{Ipv4Addr, SocketAddr};

use reflex_core::command::InjectablePacket;
use reflex_core::tls::{self, Sni};
use reflex_core::types::{Flow, Protocol, TcpFlags};

use super::pipeline::{NfqHandler, NfqPacket, NfqVerdict};

/// Типизированный L7-контент поддержанного пакета (sealed, Rule 4). SNI живёт ТОЛЬКО в
/// `TlsClientHello` → для прочих L7 он структурно непредставим.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L7 {
    /// TLS ClientHello. `sni` опционален (SNI — опциональное TLS-расширение), но КОГДА есть —
    /// имя и диапазон неразделимы (`Sni`), рассинхрон непредставим.
    TlsClientHello { sni: Option<Sni> },
    /// Ответ сервера (ChangeCipherSpec/Alert/Handshake/ApplicationData).
    ServerResp,
    /// Прочий/непарсимый L7.
    Other,
}

/// Типизированный вид пакета поддержанного семейства (парс ОДИН раз на границе).
/// Доменный хендлер видит ЭТО, не сырые байты (`FamilyGate.tla`: `delivered`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WirePacket {
    /// Проводное направление src→dst (канонизацию — домену, если нужна).
    pub flow: Flow,
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
    pub ttl: u8,
    /// Сырой TCP-payload (L7-байты) — для техник, режущих hello (split).
    pub payload: Vec<u8>,
    /// Типизированная классификация payload.
    pub l7: L7,
}

/// Доменный хендлер над типизированным видом. Семейство-гейт уже пройден, парс сделан —
/// хендлер лишь принимает решение (проекция `WireHandler` капабилити).
pub trait WireHandler {
    fn on(&mut self, packet: &WirePacket) -> (NfqVerdict, Vec<InjectablePacket>);
}

/// Адаптер: реализует низкоуровневый `NfqHandler`, парся пакет ОДИН раз, применяя
/// семейство-гейт (не-IPv4/TCP → down-shift Accept, хендлер не зовётся) и делегируя
/// `WireHandler`. Проекция `FamilyGate.tla` (Typed-гейт).
pub struct TypedNfq<H> {
    inner: H,
}

impl<H: WireHandler> TypedNfq<H> {
    pub fn new(inner: H) -> Self {
        Self { inner }
    }
}

impl<H: WireHandler> NfqHandler for TypedNfq<H> {
    fn handle(&mut self, packet: &NfqPacket) -> (NfqVerdict, Vec<InjectablePacket>) {
        match parse_wire(&packet.payload) {
            Some(wire) => self.inner.on(&wire),
            // Down-shift: не-семейство fail-open, в домен не попадает.
            // TODO(BL-203): для ЗАБЛОКИРОВАННОГО необработанного протокола Accept=«умер на DPI»;
            // модель ByteFlowFloor требует route-to-floor (proxy), не слепой пропуск.
            None => (NfqVerdict::Accept, vec![]),
        }
    }
}

/// Парс сырого IP-пакета в типизированный `WirePacket`. `None` = не IPv4+TCP (семейство-гейт
/// down-shift). ЕДИНСТВЕННОЕ место проверки семейства (`FamilyGate.tla`: `Supported`).
fn parse_wire(payload: &[u8]) -> Option<WirePacket> {
    // Семейство-гейт: версия=4 И протокол=TCP. Иначе None → down-shift.
    if payload.len() < 20 || (payload[0] >> 4) != 4 || payload[9] != 6 {
        return None;
    }
    let ihl = (payload[0] & 0x0F) as usize * 4;
    if payload.len() < ihl + 20 {
        return None;
    }
    let ttl = payload[8];
    let src_ip = Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]);
    let dst_ip = Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);

    let tcp = &payload[ihl..];
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    let data_off = ((tcp[12] >> 4) as usize) * 4;
    let flags = TcpFlags::from_bits_truncate(tcp[13]);
    let l7 = payload.get(ihl + data_off..).unwrap_or(&[]).to_vec();

    let flow = Flow {
        src: SocketAddr::new(src_ip.into(), src_port),
        dst: SocketAddr::new(dst_ip.into(), dst_port),
        protocol: Protocol::Tcp,
    };
    let classified = classify_l7(&l7);
    Some(WirePacket {
        flow,
        seq,
        ack,
        flags,
        ttl,
        payload: l7,
        l7: classified,
    })
}

/// Классификация L7-байт в типизированный вариант.
fn classify_l7(l7: &[u8]) -> L7 {
    if tls::is_client_hello(l7) {
        L7::TlsClientHello { sni: tls::sni(l7) }
    } else if tls::is_server_response(l7) {
        L7::ServerResp
    } else {
        L7::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reflex_core::builder::TcpBuilder;

    const CLIENT: (Ipv4Addr, u16) = (Ipv4Addr::new(10, 0, 0, 2), 55555);
    const SERVER: (Ipv4Addr, u16) = (Ipv4Addr::new(1, 2, 3, 4), 443);

    fn flow(src: (Ipv4Addr, u16), dst: (Ipv4Addr, u16)) -> Flow {
        Flow {
            src: SocketAddr::new(src.0.into(), src.1),
            dst: SocketAddr::new(dst.0.into(), dst.1),
            protocol: Protocol::Tcp,
        }
    }

    /// Хендлер-шпион: записывает полученный WirePacket (или его отсутствие).
    struct Spy {
        seen: Option<WirePacket>,
    }
    impl WireHandler for Spy {
        fn on(&mut self, packet: &WirePacket) -> (NfqVerdict, Vec<InjectablePacket>) {
            self.seen = Some(packet.clone());
            (NfqVerdict::Drop, vec![])
        }
    }

    fn ipv4_tls(sni: &str) -> Vec<u8> {
        TcpBuilder::new()
            .flow(&flow(CLIENT, SERVER))
            .seq(1000)
            .flags(TcpFlags::PSH | TcpFlags::ACK)
            .payload(&tls::build_client_hello(sni))
            .build()
            .serialize_ip()
    }

    /// Семейство-гейт: не-IPv4 (IPv6 nibble) → down-shift Accept, хендлер НЕ зван.
    #[test]
    fn non_ipv4_downshifts_without_calling_handler() {
        let mut h = TypedNfq::new(Spy { seen: None });
        let ipv6ish = vec![0x60u8; 40]; // версия=6
        let (verdict, injects) = h.handle(&NfqPacket {
            payload: ipv6ish,
            fwmark: 0,
        });
        assert!(
            matches!(verdict, NfqVerdict::Accept),
            "не-семейство fail-open"
        );
        assert!(injects.is_empty());
        assert!(h.inner.seen.is_none(), "хендлер НЕ должен быть зван");
    }

    /// IPv4+TCP ClientHello → хендлер получает типизированный вид: L7 с sni_span на хосте,
    /// payload = байты hello.
    #[test]
    fn ipv4_tls_delivers_typed_client_hello() {
        let mut h = TypedNfq::new(Spy { seen: None });
        let (_v, _i) = h.handle(&NfqPacket {
            payload: ipv4_tls("rutracker.org"),
            fwmark: 0,
        });
        let wire = h
            .inner
            .seen
            .expect("хендлер зван на поддержанном семействе");
        assert_eq!(wire.seq, 1000);
        let L7::TlsClientHello { sni: Some(sni) } = &wire.l7 else {
            panic!("ожидался TlsClientHello c SNI, got {:?}", wire.l7);
        };
        assert_eq!(sni.name, "rutracker.org");
        let (off, len) = sni.span;
        assert_eq!(&wire.payload[off..off + len], b"rutracker.org");
    }
}
