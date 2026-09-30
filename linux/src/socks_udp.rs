//! КЛИЕНТ SOCKS5 UDP ASSOCIATE (RFC 1928 §4, §7) — общего назначения, к любому SOCKS5-прокси с
//! включённым UDP (в проде — локальный `xray`, звонковый мост Telegram, #355).
//!
//! # Почему на краю, а не в `reflex_core`
//!
//! Грамматика ЗАГОЛОВКА датаграммы (`RSV FRAG ATYP DST.ADDR DST.PORT`) чистая и живёт в
//! [`reflex_core::socks_udp`] (задача 1) — байты в байты, без сети. Здесь — TCP-связка управления
//! и UDP-сокет к релею: сокеты и `tokio` есть предмет самого модуля, а не примесь к разбору.
//!
//! # Ассоциация живёт, пока жива TCP-связка (RFC 1928 §7)
//!
//! RFC не даёт другого способа закрыть ассоциацию, кроме закрытия TCP-связки: у неё нет отдельной
//! команды `UDP DISASSOCIATE`. Связку не читаем после хендшейка — `xray` на неё больше ничего не
//! шлёт, — но обязаны ЗНАТЬ, жива ли она, не блокируя вызывающего. Эту работу делает фоновая
//! задача ([`watch_control`]): она читает связку до EOF/ошибки и кладёт факт закрытия в
//! [`tokio::sync::watch`] — один писатель, читатели не ждут друг друга. `JoinHandle` заведённой
//! задачи держит сама `Association` и обрывает её в [`Drop`]: иначе задача пережила бы ассоциацию
//! (орфан навечно на блокирующем `read`), а связка осталась бы висеть открытой у `xray`.
//!
//! # Закон xray: BND.ADDR `0.0.0.0` значит «мой собственный адрес»
//!
//! В ответе на UDP ASSOCIATE `xray` не знает заранее, каким интерфейсом ответит, и подставляет
//! `0.0.0.0` вместо реального адреса релея. Это НЕ «любой адрес» (RFC формально не запрещает
//! `0.0.0.0` как признак неизвестности) — [`granted_relay`] заменяет его адресом самого прокси,
//! которым мы уже соединились по TCP, и это же поведение проверено тестом
//! `a_round_trip_through_a_fake_socks5_server` в `tests/socks_udp.rs`.
//!
//! # `Fragmented`/`Malformed` — пропуск, а не ошибка ассоциации
//!
//! [`received`](Association::received) тихо пропускает [`Decapsulated::Fragmented`] и
//! [`Decapsulated::Malformed`] (см. докблок [`reflex_core::socks_udp`], откуда взяты сами формы) и
//! ждёт следующую датаграмму: единичный мусорный или фрагментированный пакет — не повод объявить
//! всю ассоциацию мёртвой, а полноценного склеивания фрагментов этот клиент не делает нигде.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use reflex_core::socks_udp::{decapsulated, encapsulated, Decapsulated};

const VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_V4: u8 = 0x01;
const RESERVED: u8 = 0x00;
const REPLY_SUCCEEDED: u8 = 0x00;
/// Верхний предел UDP-датаграммы на проводе (RFC 791: IPv4-пакет ≤ 65535 байт минус заголовки).
/// Не аллокация под запас, а разовый стековый буфер на приём одной датаграммы (MEM-выстёг: не
/// склад ёмкостью на N штук, а размер ОДНОГО пакета).
const MAX_DATAGRAM: usize = 65_507;

/// Открытая ассоциация UDP ASSOCIATE: TCP-связка управления (живёт фоновой задачей, см. докблок
/// модуля) + UDP-сокет, уже `connect`-нутый на релей ([`granted_relay`]).
pub struct Association {
    relay: SocketAddrV4,
    socket: UdpSocket,
    closed: watch::Receiver<bool>,
    // Держим хендл, а не бросаем: без него задача-наблюдатель за связкой стала бы орфаном
    // (MEM-выстёг). `Drop` обрывает её, что роняет и саму TCP-связку — ассоциация закрывается
    // ЯВНО, а не полагается на то, что ОС когда-нибудь подберёт забытый сокет.
    watcher: JoinHandle<()>,
}

impl Association {
    /// RFC 1928 §4/§7: greeting (no-auth) → `UDP ASSOCIATE 0.0.0.0:0` → `BND.ADDR:BND.PORT`.
    /// `0.0.0.0:0` в запросе — не магическое «порт 0 значит любой», а буквальное «адрес, с
    /// которого клиент будет слать датаграммы, ещё не известен» (RFC 1928 §7 разрешает это, если
    /// клиент не знает его заранее — здесь так и есть: адрес назначает ОС при `bind`).
    pub async fn opened(proxy: SocketAddrV4) -> Result<Association, String> {
        let mut control = TcpStream::connect(SocketAddr::V4(proxy))
            .await
            .map_err(|err| format!("SOCKS5: TCP к прокси {proxy} не поднят: {err}"))?;

        control
            .write_all(&greeting())
            .await
            .map_err(|err| format!("SOCKS5: greeting не отправлен: {err}"))?;
        let mut method_reply = [0u8; 2];
        control
            .read_exact(&mut method_reply)
            .await
            .map_err(|err| format!("SOCKS5: ответ на greeting не прочитан: {err}"))?;
        accepted_no_auth(method_reply)?;

        control
            .write_all(&associate_request())
            .await
            .map_err(|err| format!("SOCKS5 ASSOCIATE: запрос не отправлен: {err}"))?;
        let relay = read_reply(&mut control, *proxy.ip(), "ASSOCIATE").await?;

        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .map_err(|err| format!("SOCKS5 UDP: локальный сокет не поднят: {err}"))?;
        socket
            .connect(relay)
            .await
            .map_err(|err| format!("SOCKS5 UDP: connect к релею {relay} не удался: {err}"))?;

        let (closed_tx, closed_rx) = watch::channel(false);
        let watcher = tokio::spawn(watch_control(control, closed_tx));

        Ok(Association {
            relay,
            socket,
            closed: closed_rx,
            watcher,
        })
    }

    /// Завернуть `payload` заголовком [`encapsulated`] и отправить релею. `target` — настоящий
    /// адресат (голос, STUN и т. п.), не релей: релею датаграмма уходит потому, что `socket`
    /// `connect`-нут на него в [`opened`].
    pub async fn sent(&self, target: SocketAddrV4, payload: &[u8]) -> Result<(), String> {
        let datagram = encapsulated(target, payload);
        self.socket
            .send(&datagram)
            .await
            .map(|_written| ())
            .map_err(|err| {
                format!(
                    "SOCKS5 UDP: отправка к релею {} не удалась: {err}",
                    self.relay
                )
            })
    }

    /// Принять одну датаграмму от релея и развернуть её [`decapsulated`]. Пропускает
    /// [`Decapsulated::Fragmented`]/[`Decapsulated::Malformed`] и ждёт следующую (см. докблок
    /// модуля) — сюрпризом это станет только на потоке чистого мусора, которого от `xray`
    /// не ожидается. Гонка со смертью связки — [`tokio::select!`], а не последовательные попытки:
    /// иначе `recv` мог бы ждать вечно уже ПОСЛЕ того, как связка умерла.
    ///
    /// Ждёт ГОТОВНОСТИ сокета, а читает уже без ожидания ([`Self::read_ready`]): буфер датаграммы
    /// живёт только в миг чтения. Будь он объявлен до `select!`, 64 КиБ лежали бы в состоянии
    /// этого будущего всё время ожидания — у моста звонков (#355) это сотни ассоциаций, почти
    /// всегда ждущих ответа (сторож — `a_waiting_receive_does_not_hold_a_datagram_buffer`).
    pub async fn received(&self) -> Result<(SocketAddr, Vec<u8>), String> {
        let mut closed = self.closed.clone();
        loop {
            tokio::select! {
                biased;
                _ = closed.changed() => {
                    return Err(
                        "SOCKS5: TCP-связка управления закрыта — ассоциация мертва".to_string(),
                    );
                }
                ready = self.socket.readable() => {
                    ready.map_err(|err| format!("SOCKS5 UDP: ожидание релея упало: {err}"))?;
                    match self.read_ready()? {
                        Some(datagram) => return Ok(datagram),
                        None => continue,
                    }
                }
            }
        }
    }

    /// Прочитать готовую датаграмму без ожидания. `None` — читать нечего: готовность оказалась
    /// ложной (`WouldBlock`, штатно по контракту `readable`), либо датаграмма пропущена как
    /// [`Decapsulated::Fragmented`]/[`Decapsulated::Malformed`] (см. докблок модуля).
    fn read_ready(&self) -> Result<Option<(SocketAddr, Vec<u8>)>, String> {
        let mut buf = [0u8; MAX_DATAGRAM];
        match self.socket.try_recv(&mut buf) {
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(err) => Err(format!("SOCKS5 UDP: приём от релея упал: {err}")),
            Ok(n) => Ok(match decapsulated(&buf[..n]) {
                Decapsulated::Datagram { from, payload } => Some((from, payload.to_vec())),
                Decapsulated::Fragmented => {
                    tracing::debug!("SOCKS5 UDP: фрагмент датаграммы пропущен");
                    None
                }
                Decapsulated::Malformed => {
                    tracing::debug!("SOCKS5 UDP: заголовок датаграммы не прочитан, пропущен");
                    None
                }
            }),
        }
    }

    /// TCP-связка управления ещё не закрыта — по RFC 1928 §7 ровно это и значит «ассоциация
    /// жива». Не блокируется: `watch::Receiver::borrow` — снимок последнего значения.
    pub fn alive(&self) -> bool {
        !*self.closed.borrow()
    }
}

impl Drop for Association {
    fn drop(&mut self) {
        // Обрываем наблюдателя за связкой — вместе с ним закрывается и сама TCP-связка (RFC 1928
        // §7: закрытие связки есть закрытие ассоциации). Без этого связка висела бы у `xray` до
        // истечения его собственного тайм-аута, хотя вызывающий уже отпустил `Association`.
        self.watcher.abort();
    }
}

/// Фоновая задача-наблюдатель: держит `control` живой и объявляет её смерть через `closed`.
/// Читать с неё нечего — `xray` после ASSOCIATE на связку ничего не шлёт, — поэтому входящие
/// байты (если вдруг придут) просто отбрасываются: не наш протокол, не наша забота. Единственный
/// исход, который нас интересует, — EOF или ошибка.
async fn watch_control(mut control: TcpStream, closed: watch::Sender<bool>) {
    let mut sink = [0u8; 256];
    loop {
        match control.read(&mut sink).await {
            Ok(0) => break,
            Ok(_unexpected_bytes) => continue,
            Err(_broken) => break,
        }
    }
    // Получателей может уже не быть (`Association` дропнута раньше, чем связка умерла сама) —
    // это не ошибка наблюдателя, а обычный порядок закрытия.
    let _ = closed.send(true);
}

/// `VER=5, NMETHODS=1, METHODS=[NO_AUTH]` (RFC 1928 §3).
pub(crate) fn greeting() -> [u8; 3] {
    [VERSION, 1, METHOD_NO_AUTH]
}

/// Ответ на greeting обязан принять именно no-auth: другого метода мы не предлагали, и сервер,
/// требующий что-то ещё, не наш случай (`xray` без пароля отвечает `[5, 0]` всегда).
pub(crate) fn accepted_no_auth(reply: [u8; 2]) -> Result<(), String> {
    match reply {
        [VERSION, METHOD_NO_AUTH] => Ok(()),
        [version, method] => Err(format!(
            "SOCKS5: прокси отверг no-auth (версия {version}, метод {method:#x})"
        )),
    }
}

/// `VER CMD=UDP_ASSOCIATE RSV ATYP=IPv4 DST.ADDR=0.0.0.0 DST.PORT=0` (RFC 1928 §4) — see докблок
/// [`Association::opened`] про смысл нулевого адреса здесь (это не тот же нуль, что в BND-ответе).
fn associate_request() -> Vec<u8> {
    [VERSION, CMD_UDP_ASSOCIATE, RESERVED, ATYP_V4]
        .into_iter()
        .chain(Ipv4Addr::UNSPECIFIED.octets())
        .chain(0u16.to_be_bytes())
        .collect()
}

/// Прочитать и разобрать ответ на запрос `command` (RFC 1928 §6) — один разбор на `ASSOCIATE` и
/// `CONNECT`: у ответа одна форма. IO — read_exact заголовка, затем, только для успеха с
/// IPv4-адресом, ещё шести байт адрес+порт: длина полей зависит от `ATYP`, поэтому решить, сколько
/// читать дальше, можно только после первых четырёх байт.
pub(crate) async fn read_reply(
    control: &mut TcpStream,
    proxy: Ipv4Addr,
    command: &str,
) -> Result<SocketAddrV4, String> {
    let mut header = [0u8; 4];
    control
        .read_exact(&mut header)
        .await
        .map_err(|err| format!("SOCKS5 {command}: заголовок ответа не прочитан: {err}"))?;
    match header {
        [VERSION, REPLY_SUCCEEDED, _reserved, ATYP_V4] => {
            let mut body = [0u8; 6];
            control
                .read_exact(&mut body)
                .await
                .map_err(|err| format!("SOCKS5 {command}: адрес ответа не прочитан: {err}"))?;
            Ok(granted_relay(body, proxy))
        }
        [VERSION, REPLY_SUCCEEDED, _reserved, other_atyp] => Err(format!(
            "SOCKS5 {command}: сервер ответил адресом вида {other_atyp:#x}, клиент понимает только IPv4"
        )),
        [VERSION, rep, _reserved, _atyp] => {
            Err(format!("SOCKS5 {command} отказан сервером, REP={rep:#x}"))
        }
        [version, _rep, _reserved, _atyp] => Err(format!(
            "SOCKS5: неожиданная версия протокола в ответе {command} ({version})"
        )),
    }
}

/// Чистая половина разбора успешного ответа: `BND.ADDR`(4)+`BND.PORT`(2) → адрес релея, с ЗАКОНОМ
/// `xray` про `0.0.0.0` (см. докблок модуля). Тестируется без сети — `zero_bnd_addr_means_the_proxys_own_address`.
fn granted_relay(body: [u8; 6], proxy: Ipv4Addr) -> SocketAddrV4 {
    let addr = Ipv4Addr::new(body[0], body[1], body[2], body[3]);
    let port = u16::from_be_bytes([body[4], body[5]]);
    let resolved = match addr == Ipv4Addr::UNSPECIFIED {
        true => proxy,
        false => addr,
    };
    SocketAddrV4::new(resolved, port)
}

#[cfg(test)]
mod tests {
    //! Чистая половина протокола — без сети. Круговой обмен через поддельный TCP/UDP-сервер живёт
    //! в `tests/socks_udp.rs` (интеграционный тест, ему нужны настоящие сокеты).

    use super::*;

    #[test]
    fn zero_bnd_addr_means_the_proxys_own_address() {
        let proxy = Ipv4Addr::new(127, 0, 0, 1);
        let body = {
            let mut b = [0u8; 6];
            b[4..6].copy_from_slice(&1080u16.to_be_bytes());
            b
        };
        assert_eq!(
            granted_relay(body, proxy),
            SocketAddrV4::new(proxy, 1080),
            "BND.ADDR 0.0.0.0 обязан читаться как адрес прокси, а не как 0.0.0.0 буквально"
        );
    }

    #[test]
    fn a_real_bnd_addr_is_kept_as_is() {
        let proxy = Ipv4Addr::new(127, 0, 0, 1);
        let body = [10, 0, 0, 5, 0x04, 0x38]; // 10.0.0.5:1080
        assert_eq!(
            granted_relay(body, proxy),
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 1080)
        );
    }

    #[test]
    fn greeting_asks_for_no_auth_only() {
        assert_eq!(greeting(), [0x05, 0x01, 0x00]);
    }

    #[test]
    fn associate_request_names_an_unknown_source_address() {
        assert_eq!(
            associate_request(),
            vec![0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn a_non_zero_method_reply_is_rejected() {
        assert!(
            accepted_no_auth([0x05, 0x02]).is_err(),
            "метод кроме no-auth не наш случай"
        );
    }
}
