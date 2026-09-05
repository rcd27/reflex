use reflex_engine::{Addr, Dir, FlowKey};

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

/// ЧТО ВИДНО В ГОЛОВЕ РАЗГОВОРА. Живёт В ОБОЛОЧКЕ и в домен не попадает: закон о рукопожатии
/// ничего не решает, а прибор сверки имён с чужим оракулом — работа края.
///
/// Отсутствие имени имеет ДВЕ причины, и они разные варианты, а не `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Head {
    Opaque,
    Hello { sni_at: u16, sni_len: u16 },
    HelloWithoutName,
}

/// КОНЦЫ РАЗГОВОРА — всё, над чем работает правило сторон, и всё, что есть у обоих транспортов.
///
/// Отдельным типом, а не четвёркой полей в двух местах: правило «кто из двоих клиент» приходит
/// СНАРУЖИ и у каждого входа своё (порт у очереди, улика у записи). Общий у них ровно этот
/// предмет, и общим он обязан быть в типе, иначе каждая сторона заведёт свою четвёрку — с чего
/// вторая реализация края и началась.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ends {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
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
    pub flow: FlowKey,
    pub opens: bool,
    /// ЦЕЛЬ ОТВЕТИЛА НА СТУК — `SYN+ACK`.
    ///
    /// Отдельно от [`Wire::opens`], потому что `opens` есть `SYN` БЕЗ `ACK`, и ответ цели в нём
    /// схлопывается с обычным подтверждением. Вердикту эта разница безразлична — плану всё равно,
    /// кто прислал пакет, — а НАБЛЮДЕНИЮ нет: без неё блокировка по адресу (рукопожатия не было
    /// вовсе) и блокировка по имени (рукопожатие состоялось и оборвалось после `ClientHello`)
    /// сливаются в одну картину. Замерено на фикстурах `syn_drop` и `sni_drop`.
    pub handshakes: bool,
    pub closes: bool,
    pub resets: bool,
    pub head: Head,
    pub payload: &'a [u8],
}

/// ДАТАГРАММА — то же, что [`Wire`], МИНУС всё, чего у датаграмм нет: номера, окна, флагов,
/// рукопожатия. Отдельный тип, а не поля-заглушки: подставляя `rst = false`, `window = u16::MAX`,
/// край уже держал это расщепление истинным в коде и невыразимым в типе (#320, 02.09).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Datagram<'a> {
    pub dst: Addr,
    pub dir: Dir,
    pub flow: FlowKey,
    pub payload: &'a [u8],
}

/// РАЗБОР БАЙТОВ — то, что читается из кадра БЕЗ единого предположения о том, кто из двоих
/// клиент.
///
/// # Почему уровня два, а не один
///
/// У [`Read`] в одной корзине лежали отказы двух разных родов: «байты не разобрались»
/// (`Truncated`, `NotIpv4`, `NotOurProtocol`) и «разобрались, но правило сторон их не берёт»
/// (`NotOurPort`). Первое — свойство кадра, второе — свойство ВХОДА, и у входов оно разное:
/// через очередь идёт только `SERVER_PORT`, и клиент известен правилом; запись `tcpdump` несёт
/// любые порты, и клиента называет улика (`SYN` без `ACK`).
///
/// Смешение уже оплачено дважды. Первый раз — усечённым TCP-кадром, уезжавшим в «чужой протокол»
/// (`fa7a5167`): беда читалась как норма. Второй — тем, что край не мог взять готовый разбор и
/// завёл СВОЙ, отчего перевод в наблюдение стал жить в двух местах и расходиться молча.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framed<'a> {
    Tcp(Segment<'a>),
    Udp(Payload<'a>),
    NotIpv4,
    /// Ни TCP, ни UDP: ICMP, SCTP, что угодно ещё. Разбирать нечем и гадать нельзя.
    NotOurProtocol,
    Truncated,
}

/// СЕГМЕНТ ДО ПРАВИЛА СТОРОН: флаги и номера прочитаны, направление ещё не названо.
///
/// Здесь нет ни `dst`, ни `dir`, ни `flow`, ни `head` — все четыре суть функции СТОРОНЫ, а не
/// байтов. Голова разговора в том числе: она бывает только у того, кто пришёл, и вычислять её до
/// того, как сторона названа, значило бы читать `ClientHello` в ответе сервера.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment<'a> {
    pub header: Header,
    pub opens: bool,
    pub handshakes: bool,
    pub closes: bool,
    pub resets: bool,
    pub payload: &'a [u8],
}

/// ДАТАГРАММА ДО ПРАВИЛА СТОРОН. Номеров и флагов у неё нет — оттого и полей меньше, чем у
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

/// РАЗБОР КАДРА ДО ПРАВИЛА СТОРОН — общий вход обоих путей: очереди и записи.
pub fn framed(frame: &[u8]) -> Framed<'_> {
    match frame.first() {
        None => Framed::Truncated,
        Some(first) => match first >> 4 == 4 {
            false => Framed::NotIpv4,
            true => ipv4(frame, ((first & 0x0f) as usize) * 4),
        },
    }
}

/// ПРАВИЛО СТОРОН ПО ПОРТУ — то, которым живёт очередь.
///
/// `Some(true)` — к серверу, `Some(false)` — от него. `None` значит, что порт СТОРОН НЕ РАЗВОДИТ:
/// либо оба конца чужие, либо оба свои. Это не отказ разбора, а отказ ПРАВИЛА, и потому здесь
/// `Option`, а не вариант ошибки: у другого входа (запись любых портов) на том же кадре правило
/// своё и работает.
pub fn upward(ends: &Ends, server_port: u16) -> Option<bool> {
    match (ends.dst_port == server_port, ends.src_port == server_port) {
        (false, false) | (true, true) => None,
        (up, _down) => Some(up),
    }
}

/// СЕГМЕНТ ПЛЮС НАЗВАННАЯ СТОРОНА = наблюдаемое соединение.
///
/// Публична ради края: он называет сторону уликой, а не портом, и обязан получить ТОТ ЖЕ `Wire`
/// той же сборкой. Разойдись сборка — разойдутся ключ разговора и голова потока, то есть память
/// приборов перестала бы сходиться с памятью плоскости.
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
        flow: keyed(client, client_port, server, server_seen),
        opens: segment.opens,
        handshakes: segment.handshakes,
        closes: segment.closes,
        resets: segment.resets,
        // ГОЛОВА ЧИТАЕТСЯ ТОЛЬКО У ПРИШЕДШЕГО: `ClientHello` шлёт клиент, и разбирать по этому
        // образцу ответ сервера значило бы искать имя там, где его не бывает.
        head: match upward {
            true => head_of(segment.payload),
            false => Head::Opaque,
        },
        payload: segment.payload,
    }
}

/// ДАТАГРАММА ПЛЮС НАЗВАННАЯ СТОРОНА. Ключ считает та же [`keyed`], что и у соединения: разговор
/// по QUIC и разговор по TCP к одной цели обязаны ключеваться одинаково, иначе знание о цели
/// разъедется по транспортам.
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
        flow: keyed(client, client_port, server, server_seen),
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

/// ПРОТОКОЛ ЧИТАЕТСЯ ОТДЕЛЬНО ОТ ПОЛНОТЫ КАДРА, и это не стиль.
///
/// Одним кортежем эти две проверки сливались: усечённый TCP-кадр попадал в ветвь «чужой
/// протокол», и причина отказа выходила ЛОЖНОЙ — «мы такое не разбираем» вместо «кадр обрезан».
/// Первое читается как норма, второе как беда, и различает их счётчик `unparsed`. Нашёл
/// компилятор, предупредив о недостижимых ветвях.
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

/// РАЗБОР ДАТАГРАММЫ. Заголовок восемь байт: порты, длина, контрольная сумма — и сразу тело.
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

pub fn keyed(client: u32, client_port: u16, server: u32, server_port: u16) -> FlowKey {
    let tuple = ((client as u64) << 32) | ((client_port as u64) << 16) | (server_port as u64);
    FlowKey(mixed(mixed(tuple) ^ (server as u64)))
}

fn mixed(word: u64) -> u64 {
    let spread = (word ^ (word >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    let folded = (spread ^ (spread >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    folded ^ (folded >> 31)
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
