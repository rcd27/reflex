use reflex_core::types::{Flow, Protocol};
use crate::{Addr, Dir};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub const SERVER_PORT: u16 = 443;

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;
const RECORD_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_HELLO: u8 = 0x01;
const EXTENSION_SNI: u16 = 0x0000;
const EXTENSIONS_SCANNED: u8 = 32;

/// Что видно в голове разговора. Живёт в оболочке, в домен не попадает: сверка имён с чужим оракулом
/// — работа края. Отсутствие имени имеет две причины, и это разные варианты, а не `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Head {
    Opaque,
    Hello { sni_at: u16, sni_len: u16 },
    HelloWithoutName,
}

/// Концы разговора — всё, над чем работает правило сторон, и всё, что есть у обоих транспортов.
/// Отдельным типом: правило «кто из двоих клиент» приходит СНАРУЖИ и у каждого входа своё (порт у
/// очереди, улика у записи); общим оно обязано быть в типе, иначе каждая сторона заведёт свою
/// четвёрку — с чего вторая реализация края и началась.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ends {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

/// Четвёрка разговора в том виде, в каком его завели, ПЛЮС протокол — форма кортежа conntrack
/// (`CTA_TUPLE_ORIG`). Переехал сюда из `reflex-linux::conntrack::wire` (задача 12½) вместе с
/// [`keyed_of_orig`], единственным потребителем: сам тип не зовёт netlink и не знает ядра — пять
/// плоских полей, разбор ctnetlink лишь ИХ ЗАПОЛНЯЕТ. `reflex_linux::conntrack::wire::Tuple`
/// теперь реэкспорт ОТСЮДА (один предмет — один закон, не вторая копия формы): дом переехал туда,
/// где у формы нет соседей, тянущих Linux, а разбор дампа ctnetlink продолжает жить в `reflex-linux`
/// и строит эти же поля так же, как строил.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Tuple {
    pub src: u32,
    pub dst: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}

/// Заголовочные поля разговора. Домену не нужны: он говорит о цели и направлении.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub ends: Ends,
    pub seq: u32,
    pub ack: u32,
    pub window: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Wire<'a> {
    pub header: Header,
    pub dst: Addr,
    pub dir: Dir,
    pub flow: Flow,
    pub opens: bool,
    /// Цель ответила на стук — `SYN+ACK`. Отдельно от [`Wire::opens`] (`SYN` без `ACK`): вердикту
    /// разница безразлична, наблюдению нет — без неё блокировка по адресу (рукопожатия не было) и по
    /// имени (оборвалось после `ClientHello`) сливаются (замер на `syn_drop`/`sni_drop`).
    pub handshakes: bool,
    pub closes: bool,
    pub resets: bool,
    pub head: Head,
    pub payload: &'a [u8],
}

/// Датаграмма — то же, что [`Wire`], минус всё, чего у датаграмм нет: номера, окна, флаги,
/// рукопожатие. Отдельный тип, не поля-заглушки: подставляя `rst = false`, `window = u16::MAX`, край
/// держал расщепление истинным в коде и невыразимым в типе (#320).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Datagram<'a> {
    pub dst: Addr,
    pub dir: Dir,
    pub flow: Flow,
    pub payload: &'a [u8],
}

/// Разбор байтов — то, что читается из кадра без предположения о том, кто клиент. Уровня два, не
/// один: в одной корзине лежали отказы двух родов — «байты не разобрались» (свойство КАДРА) и
/// «разобрались, но правило сторон их не берёт» (`NotOurPort`, свойство ВХОДА, у входов разное:
/// очередь берёт только `SERVER_PORT`, запись `tcpdump` — любые порты). Смешение оплачено дважды:
/// усечённый TCP-кадр уезжал в «чужой протокол» (беда читалась как норма), и край заводил свой
/// разбор, отчего перевод в наблюдение жил в двух местах и расходился молча.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framed<'a> {
    Tcp(Segment<'a>),
    Udp(Payload<'a>),
    NotIpv4,
    /// Ни TCP, ни UDP: ICMP, SCTP, что угодно ещё. Разбирать нечем и гадать нельзя.
    NotOurProtocol,
    Truncated,
}

impl Framed<'_> {
    /// Исход разбора как причина, если разбор не состоялся. `None` — «разобралось».
    pub fn unread(&self) -> Option<reflex_core::parse::Unread> {
        match self {
            Framed::Tcp(_) | Framed::Udp(_) => None,
            Framed::NotIpv4 => Some(reflex_core::parse::Unread::NotIpv4),
            Framed::NotOurProtocol => Some(reflex_core::parse::Unread::NotOurProtocol),
            Framed::Truncated => Some(reflex_core::parse::Unread::Truncated),
        }
    }
}

#[cfg(test)]
mod unread_tests {
    //! Перевод исхода разбора в причину фундамента — по варианту, не по догадке.
    use super::*;

    fn ends() -> Ends {
        Ends {
            src_ip: 0,
            dst_ip: 0,
            src_port: 0,
            dst_port: 0,
        }
    }

    #[test]
    fn success_variants_carry_no_reason() {
        let tcp = Framed::Tcp(Segment {
            header: Header {
                ends: ends(),
                seq: 0,
                ack: 0,
                window: 0,
            },
            opens: false,
            handshakes: false,
            closes: false,
            resets: false,
            payload: &[],
        });
        assert_eq!(
            tcp.unread(),
            None,
            "разобранный TCP не несёт причины отказа"
        );

        let udp = Framed::Udp(Payload {
            ends: ends(),
            payload: &[],
        });
        assert_eq!(
            udp.unread(),
            None,
            "разобранный UDP не несёт причины отказа"
        );
    }

    #[test]
    fn each_refusal_names_its_own_reason() {
        assert_eq!(
            Framed::NotIpv4.unread(),
            Some(reflex_core::parse::Unread::NotIpv4)
        );
        assert_eq!(
            Framed::NotOurProtocol.unread(),
            Some(reflex_core::parse::Unread::NotOurProtocol)
        );
        assert_eq!(
            Framed::Truncated.unread(),
            Some(reflex_core::parse::Unread::Truncated)
        );
    }
}

/// Сегмент до правила сторон: флаги и номера прочитаны, направление не названо. Нет ни `dst`, ни
/// `dir`, ни `flow`, ни `head` — все четыре суть функции СТОРОНЫ, не байтов (голова бывает только у
/// пришедшего; читать её до того, как сторона названа, значило бы искать `ClientHello` в ответе).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment<'a> {
    pub header: Header,
    pub opens: bool,
    pub handshakes: bool,
    pub closes: bool,
    pub resets: bool,
    pub payload: &'a [u8],
}

/// Датаграмма до правила сторон. Номеров и флагов у неё нет — оттого полей меньше, чем у
/// [`Segment`], а не оттого, что «пока не разобрали».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Payload<'a> {
    pub ends: Ends,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Read<'a> {
    Tcp(Wire<'a>),
    Udp(Datagram<'a>),
    NotIpv4,
    /// Ни TCP, ни UDP: ICMP, SCTP, что угодно ещё. Разбирать нечем и гадать нельзя.
    NotOurProtocol,
    NotOurPort,
    Truncated,
}

fn be16(bytes: &[u8], at: usize) -> Option<u16> {
    bytes
        .get(at..at + 2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
}

fn be32(bytes: &[u8], at: usize) -> Option<u32> {
    bytes
        .get(at..at + 4)
        .map(|quad| u32::from_be_bytes([quad[0], quad[1], quad[2], quad[3]]))
}

/// Разбор кадра до правила сторон — общий вход обоих путей: очереди и записи.
pub fn framed(frame: &[u8]) -> Framed<'_> {
    match frame.first() {
        None => Framed::Truncated,
        Some(first) => match first >> 4 == 4 {
            false => Framed::NotIpv4,
            true => ipv4(frame, ((first & 0x0f) as usize) * 4),
        },
    }
}

/// Правило сторон по порту — то, которым живёт очередь. `Some(true)` — к серверу, `Some(false)` — от
/// него; `None` — порт сторон не разводит (оба конца чужие или оба свои). Не отказ разбора, а отказ
/// ПРАВИЛА (оттого `Option`): у другого входа на том же кадре правило своё и работает.
pub fn upward(ends: &Ends, server_port: u16) -> Option<bool> {
    match (ends.dst_port == server_port, ends.src_port == server_port) {
        (false, false) | (true, true) => None,
        (up, _down) => Some(up),
    }
}

/// Сегмент плюс названная сторона = наблюдаемое соединение. Публична ради края (он называет сторону
/// уликой, не портом) и обязана дать ТОТ ЖЕ `Wire` той же сборкой — иначе ключ разговора и голова
/// потока разойдутся, и память приборов перестанет сходиться с памятью плоскости.
pub fn wired(segment: Segment<'_>, upward: bool) -> Wire<'_> {
    let ends = segment.header.ends;
    let (server, client, server_seen, client_port) = match upward {
        true => (ends.dst_ip, ends.src_ip, ends.dst_port, ends.src_port),
        false => (ends.src_ip, ends.dst_ip, ends.src_port, ends.dst_port),
    };
    Wire {
        header: segment.header,
        dst: Addr(server),
        dir: match upward {
            true => Dir::Up,
            false => Dir::Down,
        },
        flow: keyed(client, client_port, server, server_seen, Protocol::Tcp),
        opens: segment.opens,
        handshakes: segment.handshakes,
        closes: segment.closes,
        resets: segment.resets,
        // Голова читается только у пришедшего: `ClientHello` шлёт клиент, разбирать по нему ответ
        // сервера значило бы искать имя там, где его не бывает.
        head: match upward {
            true => head_of(segment.payload),
            false => Head::Opaque,
        },
        payload: segment.payload,
    }
}

/// Датаграмма плюс названная сторона. Ключ считает та же [`keyed`], что и у соединения, но протокол
/// в личность ВХОДИТ: разговор по QUIC и разговор по TCP — разные разговоры. Прежняя редакция
/// сливала их одним ключом, чтобы знание о цели не разъехалось по транспортам; после того как цель
/// стала отдельным слоем (`TargetKey` протокола не несёт), слив живёт ТАМ — сводит разговоры
/// копредел по слою, а не общий ключ. Слитый ключ разговора был удобством знания о цели, взятым в
/// долг у личности разговора.
pub fn datagrammed(payload: Payload<'_>, upward: bool) -> Datagram<'_> {
    let ends = payload.ends;
    let (server, client, server_seen, client_port) = match upward {
        true => (ends.dst_ip, ends.src_ip, ends.dst_port, ends.src_port),
        false => (ends.src_ip, ends.dst_ip, ends.src_port, ends.dst_port),
    };
    Datagram {
        dst: Addr(server),
        dir: match upward {
            true => Dir::Up,
            false => Dir::Down,
        },
        flow: keyed(client, client_port, server, server_seen, Protocol::Udp),
        payload: payload.payload,
    }
}

pub fn read(frame: &[u8], server_port: u16) -> Read<'_> {
    match framed(frame) {
        Framed::Tcp(segment) => match upward(&segment.header.ends, server_port) {
            None => Read::NotOurPort,
            Some(up) => Read::Tcp(wired(segment, up)),
        },
        Framed::Udp(payload) => match upward(&payload.ends, server_port) {
            None => Read::NotOurPort,
            Some(up) => Read::Udp(datagrammed(payload, up)),
        },
        Framed::NotIpv4 => Read::NotIpv4,
        Framed::NotOurProtocol => Read::NotOurProtocol,
        Framed::Truncated => Read::Truncated,
    }
}

/// Протокол читается отдельно от полноты кадра: одним кортежем усечённый TCP-кадр попадал в «чужой
/// протокол», и причина отказа выходила ложной («не разбираем» вместо «обрезан») — первое читается
/// как норма, второе как беда, различает их счётчик `unparsed`. Нашёл компилятор (недостижимые ветви).
fn ipv4(frame: &[u8], header: usize) -> Framed<'_> {
    let body = (be32(frame, 12), be32(frame, 16), frame.get(header..));
    match (frame.get(9), body) {
        (Some(&PROTO_TCP), (Some(src_ip), Some(dst_ip), Some(body))) => tcp(body, src_ip, dst_ip),
        (Some(&PROTO_UDP), (Some(src_ip), Some(dst_ip), Some(body))) => udp(body, src_ip, dst_ip),
        (Some(&PROTO_TCP) | Some(&PROTO_UDP), _incomplete) => Framed::Truncated,
        (Some(_other), _) => Framed::NotOurProtocol,
        (None, _) => Framed::Truncated,
    }
}

/// Разбор датаграммы. Заголовок восемь байт: порты, длина, контрольная сумма — и сразу тело.
fn udp(datagram: &[u8], src_ip: u32, dst_ip: u32) -> Framed<'_> {
    match (be16(datagram, 0), be16(datagram, 2), datagram.get(8..)) {
        (Some(src_port), Some(dst_port), Some(payload)) => Framed::Udp(Payload {
            ends: Ends {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
            },
            payload,
        }),
        _incomplete => Framed::Truncated,
    }
}

fn tcp(segment: &[u8], src_ip: u32, dst_ip: u32) -> Framed<'_> {
    let parts = (
        be16(segment, 0),
        be16(segment, 2),
        segment.get(12).copied(),
        segment.get(13).copied(),
    );
    let numbers = (be32(segment, 4), be32(segment, 8), be16(segment, 14));
    match (parts, numbers) {
        (
            (Some(src_port), Some(dst_port), Some(offset), Some(flags)),
            (Some(seq), Some(ack), Some(window)),
        ) => match segment.get(((offset >> 4) as usize) * 4..) {
            None => Framed::Truncated,
            Some(payload) => Framed::Tcp(Segment {
                header: Header {
                    ends: Ends {
                        src_ip,
                        dst_ip,
                        src_port,
                        dst_port,
                    },
                    seq,
                    ack,
                    window,
                },
                opens: flags & SYN != 0 && flags & ACK == 0,
                handshakes: flags & SYN != 0 && flags & ACK != 0,
                closes: flags & FIN != 0,
                resets: flags & RST != 0,
                payload,
            }),
        },
        _incomplete => Framed::Truncated,
    }
}

/// Личность разговора из названных сторон. Возвращает ЧЕТВЁРКУ, а не её отпечаток: ключ области —
/// то, чем она расслаивается (§4), а сжатие в `u64` было лосси — две разные четвёрки с одним хэшем
/// становились одним разговором, то есть одна машина держала два (§4, «машина на двух ключах —
/// две машины»), и молча. Замер цены: карта по четвёрке против карты по отпечатку — 1–4 нс на
/// операцию против микросекунд на пакет, то есть отпечаток покупал доли процента ценой коллизии.
///
/// Протокол входит в личность: разговор по TCP и разговор по QUIC к одной цели — РАЗНЫЕ разговоры.
/// Сводит их слой ЦЕЛИ (`TargetKey` протокола не несёт), а не общий ключ разговора.
pub fn keyed(
    client: u32,
    client_port: u16,
    server: u32,
    server_port: u16,
    protocol: Protocol,
) -> Flow {
    Flow {
        src: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(client)), client_port),
        dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(server)), server_port),
        protocol,
    }
}

/// Ключ из ORIG-кортежа ядра (`CTA_TUPLE_ORIG`). Принимает кортеж ЦЕЛИКОМ, и имя кричит, какой:
/// подать `CTA_TUPLE_REPLY` по ошибке можно, но ключ несимметричен — выйдет ДРУГОЙ разговор, и это
/// ловит тест. Тело — та же [`keyed`], что и у провода: инициатор ORIG'а есть клиент, и это
/// единственное знание, что добавляет обёртка. Своей арифметики нет — иначе была бы вторая ковка,
/// и два ключа одного разговора разошлись бы молча.
pub fn keyed_of_orig(orig: Tuple) -> Flow {
    keyed(
        orig.src,
        orig.src_port,
        orig.dst,
        orig.dst_port,
        match orig.proto {
            17 => Protocol::Udp,
            _tcp_or_other => Protocol::Tcp,
        },
    )
}


pub fn head_of(payload: &[u8]) -> Head {
    match hello_at(payload) {
        None => Head::Opaque,
        Some(after_random) => match extensions_at(payload, after_random) {
            None => Head::HelloWithoutName,
            Some(at) => match named(payload, at, 0) {
                None => Head::HelloWithoutName,
                Some((sni_at, sni_len)) => Head::Hello { sni_at, sni_len },
            },
        },
    }
}

fn hello_at(payload: &[u8]) -> Option<usize> {
    let record = payload.first().copied()?;
    let handshake = payload.get(5).copied()?;
    match record == RECORD_HANDSHAKE && handshake == HANDSHAKE_HELLO {
        false => None,
        true => Some(43),
    }
}

fn extensions_at(payload: &[u8], after_random: usize) -> Option<usize> {
    let session = payload.get(after_random).copied()? as usize;
    let ciphers_at = after_random + 1 + session;
    let ciphers = be16(payload, ciphers_at)? as usize;
    let compressions_at = ciphers_at + 2 + ciphers;
    let compressions = payload.get(compressions_at).copied()? as usize;
    let block = compressions_at + 1 + compressions;
    be16(payload, block).map(|_declared| block + 2)
}

fn named(payload: &[u8], at: usize, scanned: u8) -> Option<(u16, u16)> {
    match scanned >= EXTENSIONS_SCANNED {
        true => None,
        false => {
            let kind = be16(payload, at)?;
            let len = be16(payload, at + 2)? as usize;
            match kind == EXTENSION_SNI {
                false => named(payload, at + 4 + len, scanned + 1),
                true => {
                    let name_len = be16(payload, at + 7)? as usize;
                    let name_at = at + 9;
                    match name_at + name_len <= payload.len() {
                        false => None,
                        true => Some((name_at as u16, name_len as u16)),
                    }
                }
            }
        }
    }
}
