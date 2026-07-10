//! Субстрат данных: терминация TCP из tun-устройства в async-потоки с ОРИГИНАЛЬНЫМ dst.
//!
//! Механизм `CaptureMech="Tun"` (проекция `model/wire/TransparentCapture.tla` в неводе): userspace-
//! стек (netstack на движке smoltcp) читает dst ПРЯМО из IP-заголовка → истинная цель, петля-на-себя
//! невыразима. reflex несёт НЕСУЩУЮ (открыть tun + качать пакеты + завершать TCP), потребитель (невод)
//! остаётся мозгом обхода: берёт `(поток, цель)` из `accept` и ведёт earned-routing, не касаясь пакетов.
//!
//! Устройство: невод сам владеет tun (без внешнего tun2socks — hev/lwIP отброшены). eBPF-steer +
//! маршрут подают целевой кадр в устройство (неизменный субстрат); этот модуль — его ПОТРЕБИТЕЛЬ.

use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use tokio::io::unix::AsyncFd;
use tokio::task::JoinHandle;

use netstack_smoltcp::StackBuilder;

/// Терминированный TCP-флоу из tun: async-поток к цели. Реэкспорт типа netstack (несёт tokio
/// `AsyncRead`/`AsyncWrite`) — потребитель зависит от трейт-поверхности, не от конкретного стека
/// (смена движка = правка только reflex).
pub use netstack_smoltcp::TcpStream as TunStream;

const TUNSETIFF: libc::c_ulong = 0x4004_54ca; // _IOW('T', 202, int)
const IFF_TUN: libc::c_short = 0x0001; // L3 tun (не tap): кадры = чистые IP-пакеты
const IFF_NO_PI: libc::c_short = 0x1000; // без 4-байтного tun_pi-префикса → сырой IP

#[repr(C)]
struct IfReq {
    name: [libc::c_char; 16], // IFNAMSIZ
    flags: libc::c_short,
    _pad: [u8; 22], // ifreq = 40 байт (name[16] + union[24])
}

/// Открывает tun-устройство `dev` (создаёт при отсутствии), IPv4 (`IFF_TUN|IFF_NO_PI`), non-blocking.
/// Требует CAP_NET_ADMIN. Возвращает владеющий fd. `pub(crate)` — originate-нога (`tun_egress`) качает
/// пакеты через СВОЙ tun тем же механизмом (насосы read/write), не дублируя открытие устройства.
pub(crate) fn open_tun(dev: &str) -> io::Result<OwnedFd> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")?;
    let owned = OwnedFd::from(file);

    let mut req = IfReq {
        name: [0; 16],
        flags: IFF_TUN | IFF_NO_PI,
        _pad: [0; 22],
    };
    for (slot, b) in req.name.iter_mut().zip(dev.bytes().take(15)) {
        *slot = b as libc::c_char;
    }
    // `as _`: тип request у `ioctl` зависит от таргета (c_ulong glibc-x86_64, c_int musl-aarch64).
    let rc = unsafe { libc::ioctl(owned.as_raw_fd(), TUNSETIFF as _, &mut req as *mut IfReq) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }

    let cur = unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_GETFL) };
    if cur < 0
        || unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_SETFL, cur | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(owned)
}

/// Одно неблокирующее чтение пакета из tun (`EWOULDBLOCK` → AsyncFd повторит).
pub(crate) async fn read_tun(fd: &AsyncFd<OwnedFd>, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        let mut guard = fd.readable().await?;
        let res = guard.try_io(|inner| {
            let n = unsafe {
                libc::read(
                    inner.get_ref().as_raw_fd(),
                    buf.as_mut_ptr() as *mut _,
                    buf.len(),
                )
            };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        });
        match res {
            Ok(r) => return r,
            Err(_would_block) => continue,
        }
    }
}

/// Одна неблокирующая запись пакета в tun.
pub(crate) async fn write_tun(fd: &AsyncFd<OwnedFd>, pkt: &[u8]) -> io::Result<usize> {
    loop {
        let mut guard = fd.writable().await?;
        let res = guard.try_io(|inner| {
            let n = unsafe {
                libc::write(
                    inner.get_ref().as_raw_fd(),
                    pkt.as_ptr() as *const _,
                    pkt.len(),
                )
            };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        });
        match res {
            Ok(r) => return r,
            Err(_would_block) => continue,
        }
    }
}

/// Источник терминированных TCP-флоу из tun. `bind` открывает устройство, поднимает netstack и качает
/// пакеты в обе стороны (насосы); `accept` отдаёт следующий поток + ИСТИННЫЙ dst (цель клиента).
pub struct TunFlows {
    listener: netstack_smoltcp::TcpListener,
    _tasks: Vec<JoinHandle<()>>, // держим runner+насосы живыми, пока жив TunFlows
}

impl TunFlows {
    /// Открывает `dev`, поднимает netstack (только TCP), спавнит runner + два насоса (tun↔стек).
    pub fn bind(dev: &str) -> io::Result<Self> {
        let fd = Arc::new(AsyncFd::new(open_tun(dev)?)?);
        let (stack, runner, _udp, listener) = StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(false)
            .enable_icmp(false)
            .build()?;
        let listener =
            listener.ok_or_else(|| io::Error::other("netstack собран без TCP-listener"))?;

        let (mut to_stack, mut from_stack) = stack.split();
        let mut tasks = Vec::new();

        if let Some(runner) = runner {
            tasks.push(tokio::spawn(async move {
                let _ = runner.await; // runner: Future<Output=io::Result<()>> — исход отбрасываем
            }));
        }

        // Насос tun → стек: сырой пакет из устройства подаётся в netstack на терминацию.
        {
            let fd = fd.clone();
            tasks.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    match read_tun(&fd, &mut buf).await {
                        Ok(n) if n > 0 => {
                            if to_stack.send(buf[..n].to_vec()).await.is_err() {
                                break; // стек закрылся
                            }
                        }
                        _ => break, // EOF/сбой устройства
                    }
                }
            }));
        }

        // Насос стек → tun: исходящий кадр netstack (SYN-ACK, данные обратно клиенту) пишется в устройство.
        {
            let fd = fd.clone();
            tasks.push(tokio::spawn(async move {
                while let Some(pkt) = from_stack.next().await {
                    match pkt {
                        Ok(p) => {
                            let _ = write_tun(&fd, &p).await;
                        }
                        Err(_) => break,
                    }
                }
            }));
        }

        Ok(Self {
            listener,
            _tasks: tasks,
        })
    }

    /// Следующий терминированный флоу: `(поток, dst)`, где `dst` = ОРИГИНАЛЬНАЯ цель, куда шёл клиент.
    /// ВНИМАНИЕ: netstack-smoltcp именует КОНТРИНТУИТИВНО — `TcpListener` отдаёт `(stream, local_addr,
    /// remote_addr)`, но `local_addr()` = `src_addr` = КЛИЕНТ (инициатор), а `remote_addr()` =
    /// `dst_addr` = ЦЕЛЬ. Значит dst = ТРЕТИЙ элемент (`remote`), не второй (проверено: box-local nc к
    /// цели дал в спане клиентский src как dst → serve_flow шёл к клиенту → дроп). `None` — listener закрыт.
    pub async fn accept(&mut self) -> Option<(TunStream, SocketAddr)> {
        let (stream, _client, dst) = self.listener.next().await?;
        Some((stream, dst))
    }
}

/// Датаграммный сабстрат из tun (UDP-плоскость, BL-233): та же несущая, что `TunFlows`, но без
/// терминации соединения — UDP без состояния. `recv` отдаёт `(payload, КЛИЕНТ, ИСТИННЫЙ dst)` (цель
/// прямо из IP-заголовка, как `accept` у TunFlows); `send` ФОРЖИТ датаграмму с ПРОИЗВОЛЬНЫМ src —
/// прозрачный релей «ответ клиенту от имени dest» (`send(payload, src=dest, dst=client)`).
///
/// Спайк netstack-smoltcp ЗЕЛЁНЫЙ (BL-233): `udp::WriteHalf` — stateless-форж (`PacketBuilder::ipv4`
/// из отданных src/dst, БЕЗ bind/socket-table), arbitrary-src нативно, raw-inject не нужен. Ассоциация
/// (обратная dst→client, idle-эвикт, гонка ног) — НЕ здесь: субстрат тупой, мозг в потребителе.
///
/// TODO(BL-233): один tun-девайс = один netstack. Совместный прогон с `TunFlows` на ОДНОМ устройстве
/// (два netstack'а на одном fd делят пакеты пополам) требует общего стека (`enable_tcp+udp`, один
/// listener + один udp-socket, «один стек оба потребителя», срез 3 эпика) — интеграция + rewire
/// `main.rs`. Пока standalone (udp-only netstack), потребляется `serve_udp` на своём девайсе.
pub struct TunDatagrams {
    rx: netstack_smoltcp::udp::ReadHalf, // Stream<(payload, client_src, true_dst)>
    tx: netstack_smoltcp::udp::WriteHalf, // Sink<(payload, src, dst)> — stateless-форж
    _tasks: Vec<JoinHandle<()>>,         // держим насосы живыми, пока жив TunDatagrams
}

impl TunDatagrams {
    /// Открывает `dev`, поднимает netstack (только UDP — runner/TCP-listener не нужны), спавнит два
    /// насоса (tun↔стек). Требует CAP_NET_ADMIN.
    pub fn bind(dev: &str) -> io::Result<Self> {
        let fd = Arc::new(AsyncFd::new(open_tun(dev)?)?);
        let (stack, _runner, udp, _listener) = StackBuilder::default()
            .enable_tcp(false)
            .enable_udp(true)
            .enable_icmp(false)
            .build()?;
        let udp = udp.ok_or_else(|| io::Error::other("netstack собран без UDP-сокета"))?;
        let (rx, tx) = udp.split();

        let (mut to_stack, mut from_stack) = stack.split();
        let mut tasks = Vec::new();

        // Насос tun → стек: сырой пакет из устройства подаётся в netstack (маршрутизируется в UDP-плоскость).
        {
            let fd = fd.clone();
            tasks.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    match read_tun(&fd, &mut buf).await {
                        Ok(n) if n > 0 => {
                            if to_stack.send(buf[..n].to_vec()).await.is_err() {
                                break; // стек закрылся
                            }
                        }
                        _ => break, // EOF/сбой устройства
                    }
                }
            }));
        }

        // Насос стек → tun: форжнутая датаграмма (WriteHalf → stack_tx → from_stack) пишется в устройство.
        {
            let fd = fd.clone();
            tasks.push(tokio::spawn(async move {
                while let Some(pkt) = from_stack.next().await {
                    match pkt {
                        Ok(p) => {
                            let _ = write_tun(&fd, &p).await;
                        }
                        Err(_) => break,
                    }
                }
            }));
        }

        Ok(Self {
            rx,
            tx,
            _tasks: tasks,
        })
    }

    /// Следующая датаграмма клиента: `(payload, client_src, true_dst)`. `None` — стек закрылся.
    pub async fn recv(&mut self) -> Option<(Vec<u8>, SocketAddr, SocketAddr)> {
        self.rx.next().await
    }

    /// Форж датаграммы в tun с ПРОИЗВОЛЬНЫМ src. Прозрачный релей: `src`=цель, `dst`=клиент → клиент
    /// видит ответ «от dest». v4/v6 не мешать (netstack вернёт InvalidData на разнотипье).
    pub async fn send(
        &mut self,
        payload: Vec<u8>,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> io::Result<()> {
        self.tx.send((payload, src, dst)).await
    }

    /// Разделяет на приём/отправку — драйвер держит их в РАЗНЫХ ветках `select!` без конфликта
    /// заимствований (`recv` берёт только rx, `send` только tx). Насосы (`_tasks`) переезжают в tx.
    pub fn split(self) -> (TunDatagramsRx, TunDatagramsTx) {
        (
            TunDatagramsRx { rx: self.rx },
            TunDatagramsTx {
                tx: self.tx,
                _tasks: self._tasks,
            },
        )
    }
}

/// Приёмная половина `TunDatagrams` (см. `split`): датаграммы клиента с истинным dst.
pub struct TunDatagramsRx {
    rx: netstack_smoltcp::udp::ReadHalf,
}

impl TunDatagramsRx {
    /// Следующая датаграмма клиента: `(payload, client_src, true_dst)`. `None` — стек закрылся.
    pub async fn recv(&mut self) -> Option<(Vec<u8>, SocketAddr, SocketAddr)> {
        self.rx.next().await
    }
}

/// Отправная половина `TunDatagrams` (см. `split`): форж датаграмм с произвольным src. Держит насосы.
pub struct TunDatagramsTx {
    tx: netstack_smoltcp::udp::WriteHalf,
    _tasks: Vec<JoinHandle<()>>,
}

impl TunDatagramsTx {
    /// Форж датаграммы в tun с ПРОИЗВОЛЬНЫМ src (`src`=цель, `dst`=клиент → «ответ от dest»).
    pub async fn send(
        &mut self,
        payload: Vec<u8>,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> io::Result<()> {
        self.tx.send((payload, src, dst)).await
    }
}
