//! Вопросы маршрутизатору ядра и разбор его ответов — чисто, без сокета. Отделено от IO по тому же
//! закону, что разбор дампа conntrack: место, где свидетель может соврать молча, обязано
//! проверяться без root.

use std::net::Ipv4Addr;

use reflex_core::types::{IpProtocol, Protocol};

use crate::netlink::{attrs, portion_of, tlv, u32_at, Portion, HDR};

const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const RTM_NEWROUTE: u16 = 24;
const RTM_GETROUTE: u16 = 26;
const NLM_F_REQUEST: u16 = 0x001;
const NLM_F_DUMP: u16 = 0x300;
const AF_INET: u8 = 2;
const RTMSG: usize = 12;
const IFADDRMSG: usize = 8;
const RTM_TYPE_AT: usize = 7;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_MARK: u16 = 16;
const RTA_IP_PROTO: u16 = 27;
const RTA_DPORT: u16 = 29;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const RTN_LOCAL: u8 = 2;

/// Куда ядро повело бы пакет. Алфавит закрыт: всякий ответ маршрутизатора ложится в клетку, и
/// нечитаемый — тоже (`Unread`), а не в «ушёл в ногу» по умолчанию.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Went {
    /// Адрес свой: пакет остаётся машине.
    Local,
    /// Уходит в устройство с этим индексом.
    Device(u32),
    /// Маршрут есть, устройства нет (`blackhole`, `prohibit`): тип маршрута ядра.
    Nowhere(u8),
    /// Ядро отказало ответить — положительный errno (`ENETUNREACH` = 101: пути нет вовсе).
    Refused(i32),
    /// Ни маршрута, ни отказа.
    Unread,
}

fn message(kind: u16, flags: u16, seq: u32, body: &[u8]) -> Vec<u8> {
    ((HDR + body.len()) as u32)
        .to_ne_bytes()
        .into_iter()
        .chain(kind.to_ne_bytes())
        .chain(flags.to_ne_bytes())
        .chain(seq.to_ne_bytes())
        .chain(0u32.to_ne_bytes())
        .chain(body.iter().copied())
        .collect()
}

/// Вопрос «куда уйдёт пакет с меткой `mark`, протокола `l4`, к `dst:port`». Протокол и порт
/// спрашиваются НЕ для красоты: правило `ip rule … ipproto tcp` покрывает один L4, и без них ядро
/// ответило бы за оба одинаково — ровно та слепота, что оставила QUIC без увода.
pub(crate) fn route_request(
    dst: Ipv4Addr,
    mark: u32,
    l4: Protocol,
    port: u16,
    seq: u32,
) -> Vec<u8> {
    let number = match l4 {
        Protocol::Tcp => IpProtocol::Tcp,
        Protocol::Udp => IpProtocol::Udp,
    }
    .to_u8();
    let rtmsg = [AF_INET, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let body: Vec<u8> = rtmsg
        .into_iter()
        .chain(tlv(RTA_DST, &dst.octets()))
        .chain(tlv(RTA_MARK, &mark.to_ne_bytes()))
        .chain(tlv(RTA_IP_PROTO, &[number]))
        .chain(tlv(RTA_DPORT, &port.to_be_bytes()))
        .collect();
    message(RTM_GETROUTE, NLM_F_REQUEST, seq, &body)
}

/// Дамп своих адресов IPv4.
pub(crate) fn locals_request(seq: u32) -> Vec<u8> {
    message(
        RTM_GETADDR,
        NLM_F_REQUEST | NLM_F_DUMP,
        seq,
        &[AF_INET, 0, 0, 0, 0, 0, 0, 0],
    )
}

/// Ответ на [`route_request`]. Тип маршрута читается ПРЕЖДЕ устройства: у своего адреса устройство
/// тоже есть (`lo`), и по одному индексу «остался себе» не отличить от «ушёл в петлю».
pub(crate) fn went_of(reply: &[u8]) -> Went {
    match portion_of(reply, |kind, body| {
        (kind == RTM_NEWROUTE).then(|| route_of(body)).flatten()
    }) {
        Portion::Failed(code) => Went::Refused(code.saturating_neg()),
        Portion::More(found) | Portion::Done(found) => {
            found.into_iter().next().unwrap_or(Went::Unread)
        }
    }
}

fn route_of(body: &[u8]) -> Option<Went> {
    body.get(RTM_TYPE_AT).copied().map(|kind| match kind {
        RTN_LOCAL => Went::Local,
        other => body
            .get(RTMSG..)
            .and_then(|rest| attrs(rest).find(|(attr, _)| *attr == RTA_OIF))
            .and_then(|(_, oif)| u32_at(oif, 0))
            .map_or(Went::Nowhere(other), Went::Device),
    })
}

/// Порция дампа адресов. `IFA_LOCAL` прежде `IFA_ADDRESS`: на точка-точка второй — адрес СОСЕДА.
pub(crate) fn locals_of(reply: &[u8]) -> Portion<Ipv4Addr> {
    portion_of(reply, |kind, body| {
        (kind == RTM_NEWADDR).then(|| address_of(body)).flatten()
    })
}

fn address_of(body: &[u8]) -> Option<Ipv4Addr> {
    let found: Vec<(u16, &[u8])> = (body.first() == Some(&AF_INET))
        .then(|| body.get(IFADDRMSG..))
        .flatten()
        .map(|rest| attrs(rest).collect())
        .unwrap_or_default();
    [IFA_LOCAL, IFA_ADDRESS]
        .into_iter()
        .find_map(|want| found.iter().find(|(attr, _)| *attr == want))
        .and_then(|(_, value)| <[u8; 4]>::try_from(*value).ok())
        .map(Ipv4Addr::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::{u16_at, NLMSG_DONE, NLMSG_ERROR};

    fn reply(kind: u16, body: &[u8]) -> Vec<u8> {
        message(kind, 0, 1, body)
    }

    fn route_reply(rtm_type: u8, oif: Option<u32>) -> Vec<u8> {
        let rtmsg = [AF_INET, 32, 0, 0, 254, 0, 0, rtm_type, 0, 0, 0, 0];
        let body: Vec<u8> = rtmsg
            .into_iter()
            .chain(
                oif.map(|index| tlv(RTA_OIF, &index.to_ne_bytes()))
                    .unwrap_or_default(),
            )
            .collect();
        reply(RTM_NEWROUTE, &body)
    }

    /// Свой адрес читается своим ДАЖЕ с устройством в ответе: ядро отдаёт `lo`, и индекс без типа
    /// сказал бы «ушёл в устройство».
    #[test]
    fn свой_адрес_читается_по_типу_а_не_по_устройству() {
        assert_eq!(went_of(&route_reply(RTN_LOCAL, Some(1))), Went::Local);
        assert_eq!(went_of(&route_reply(1, Some(7))), Went::Device(7));
        assert_eq!(
            went_of(&route_reply(6, None)),
            Went::Nowhere(6),
            "blackhole — не устройство"
        );
    }

    /// `ENETUNREACH` приходит отрицательным в `NLMSG_ERROR`; клетка несёт его положительным.
    #[test]
    fn отказ_маршрутизатора_есть_клетка_а_не_пустота() {
        assert_eq!(
            went_of(&reply(NLMSG_ERROR, &(-101i32).to_ne_bytes())),
            Went::Refused(101)
        );
        assert_eq!(went_of(&[]), Went::Unread);
        assert_eq!(
            went_of(&reply(RTM_NEWADDR, &[AF_INET; 8])),
            Went::Unread,
            "чужой ответ"
        );
    }

    /// Порт уходит big-endian, метка — в порядке хоста: у rtnetlink они РАЗНЫЕ, и перепутанный порт
    /// спросил бы ядро о чужом разговоре, получив честный ответ на не тот вопрос.
    #[test]
    fn вопрос_несёт_протокол_порт_и_метку_в_их_порядке_байтов() {
        let asked = route_request(
            Ipv4Addr::new(198, 51, 100, 1),
            0x10000,
            Protocol::Udp,
            443,
            9,
        );
        assert_eq!(u16_at(&asked, 4), Some(RTM_GETROUTE));
        assert_eq!(u32_at(&asked, 0), Some(asked.len() as u32));
        let found: Vec<(u16, Vec<u8>)> = attrs(&asked[HDR + RTMSG..])
            .map(|(k, v)| (k, v.to_vec()))
            .collect();
        assert!(found.contains(&(RTA_DST, vec![198, 51, 100, 1])));
        assert!(found.contains(&(RTA_MARK, 0x10000u32.to_ne_bytes().to_vec())));
        assert!(found.contains(&(RTA_IP_PROTO, vec![17])));
        assert!(found.contains(&(RTA_DPORT, vec![0x01, 0xBB])));
    }

    fn address_reply(attr: u16, octets: [u8; 4]) -> Vec<u8> {
        let body: Vec<u8> = [AF_INET, 24, 0, 0, 3, 0, 0, 0]
            .into_iter()
            .chain(tlv(attr, &octets))
            .collect();
        reply(RTM_NEWADDR, &body)
    }

    #[test]
    fn дамп_адресов_собирается_до_конца_и_берёт_свой_а_не_соседский() {
        let portion: Vec<u8> = [
            address_reply(IFA_LOCAL, [127, 0, 0, 1]),
            address_reply(IFA_ADDRESS, [192, 168, 77, 1]),
            reply(NLMSG_DONE, &0i32.to_ne_bytes()),
        ]
        .concat();
        assert_eq!(
            locals_of(&portion),
            Portion::Done(vec![
                Ipv4Addr::new(127, 0, 0, 1),
                Ipv4Addr::new(192, 168, 77, 1)
            ])
        );
        let both: Vec<u8> = [AF_INET, 32, 0, 0, 3, 0, 0, 0]
            .into_iter()
            .chain(tlv(IFA_ADDRESS, &[10, 0, 0, 2]))
            .chain(tlv(IFA_LOCAL, &[10, 0, 0, 1]))
            .collect();
        assert_eq!(
            address_of(&both),
            Some(Ipv4Addr::new(10, 0, 0, 1)),
            "точка-точка: свой, не сосед"
        );
    }
}
