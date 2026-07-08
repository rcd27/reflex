//! Originate-нога: СВОЙ netstack ИСХОДЯЩИХ TCP-сокетов (active-open) на движке smoltcp.
//!
//! ЗАЧЕМ отдельно от `tun` (listener): `netstack-smoltcp` умеет ЛИШЬ терминировать входящие флоу
//! (модель tun2socks — `socket.listen` на dst входящего SYN), исходящего `connect` в нём НЕТ. Для
//! L2Glue-egress (проекция `model/wire/EgressIdentity` + `SteerDatapath.Egress="L2Glue"`) неводу нужно
//! САМОМУ инициировать TCP к реальной цели: netstack эмитит SYN/ClientHello/ACK'и в egress-tun, а eBPF
//! (`reflex_egress`) переклеивает L2/L3-личность на ВЫУЧЕННУЮ роутеровскую и `bpf_redirect(eth0)`.
//!
//! ЗАКОН датаплейна (memory `v002_datapath_law`): ядерный L3-originate ВВЕРХ на этой коробке —
//! доказанная чёрная дыра (Билайн MAC-auth + forward↔tun дроп). Значит egress ОБЯЗАН идти netstack'ом
//! в tun (как вход/возврат), не `TcpStream::connect`. Этот модуль — тот самый netstack.
//!
//! Стек tun-агностичен: пакетный ввод/вывод через каналы (`EgressWire`) — так originate тестируется
//! IN-MEMORY (пир = listener `netstack-smoltcp`, без root/tun), а прод-обёртка `TunEgress` качает те же
//! каналы в реальный tun. Async-семантика (control-буферы + wakers + poll-луп) зеркалит `netstack-smoltcp`.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer, State as TcpState};
use smoltcp::storage::RingBuffer;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use spin::Mutex as SpinMutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc::{
    error::TryRecvError, unbounded_channel, UnboundedReceiver, UnboundedSender,
};
use tokio::sync::{oneshot, Notify};
use tokio::task::JoinHandle;

const TCP_BUF: usize = 64 * 1024; // send/recv буфер сокета И control-буфер (обе стороны насоса)
const IDLE_POLL: Duration = Duration::from_millis(50); // страховочный тик, если smoltcp не дал delay
const EGRESS_MTU: usize = 1500;

// ── Общий control сокета: мост между sync poll-лупом (пишет буферы, будит) и async-стримом ──
// (`EgressStream` читает/пишет буферы, регистрирует waker). SpinMutex: критические секции коротки,
// держатся и в sync-лупе, и в async-poll'ах — как в `netstack-smoltcp`.

#[derive(Clone, Copy, PartialEq, Eq)]
enum Half {
    Normal,
    Close,   // async-сторона попросила SHUT_WR / drop
    Closing, // FIN отправлен, дренируем
    Closed,  // сокет закрыт — EOF/BrokenPipe наружу
}

struct SockControl {
    send_buffer: RingBuffer<'static, u8>,
    send_waker: Option<Waker>,
    recv_buffer: RingBuffer<'static, u8>,
    recv_waker: Option<Waker>,
    recv_state: Half,
    send_state: Half,
}

impl SockControl {
    fn new() -> SharedControl {
        Arc::new(SpinMutex::new(SockControl {
            send_buffer: RingBuffer::new(vec![0u8; TCP_BUF]),
            send_waker: None,
            recv_buffer: RingBuffer::new(vec![0u8; TCP_BUF]),
            recv_waker: None,
            recv_state: Half::Normal,
            send_state: Half::Normal,
        }))
    }
}

type SharedControl = Arc<SpinMutex<SockControl>>;

/// Запрос на active-open, посылаемый в poll-луп (только там жив `iface.context()` для `connect`).
struct ConnectReq {
    remote: IpEndpoint,
    local_port: u16,
    control: SharedControl,
    ready: oneshot::Sender<io::Result<()>>, // Ok при Established, Err при отказе/RST до установления
}

/// Per-socket запись в poll-лупе: общий control + (пока не установлен) канал сигнала `connect`.
struct SockEntry {
    control: SharedControl,
    ready: Option<oneshot::Sender<io::Result<()>>>,
}

// ── Канальное smoltcp-устройство: rx из очереди (реплаи с провода), tx в unbounded-сендер (кадры,
// что стек хочет отправить). medium-ip: tun даёт сырой IP, L2 клеит eBPF (не стек). ──

struct ChannelDevice {
    rx: VecDeque<Vec<u8>>,
    tx: UnboundedSender<Vec<u8>>,
}

struct RxTok(Vec<u8>);
struct TxTok(UnboundedSender<Vec<u8>>);

impl RxToken for RxTok {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0[..])
    }
}

impl TxToken for TxTok {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        let _ = self.0.send(buf); // провод закрыт → кадр молча теряется (стек это переживёт)
        r
    }
}

impl Device for ChannelDevice {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok;

    fn receive(&mut self, _t: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let buf = self.rx.pop_front()?;
        Some((RxTok(buf), TxTok(self.tx.clone())))
    }

    fn transmit(&mut self, _t: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TxTok(self.tx.clone()))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = EGRESS_MTU;
        c
    }
}

/// Пакетный порт стека: `feed` (клон-хендл) подаёт реплай с провода внутрь, `outbound` (owned-ресивер)
/// отдаёт кадры, что стек хочет положить на провод. Разнесены — feed и дренаж outbound живут в РАЗНЫХ
/// задачах (насос tun→стек vs стек→tun). Обёртка `TunEgress` качает это в реальный tun; тест — в пир.
pub struct EgressWire {
    pub feed: EgressFeed,
    pub outbound: UnboundedReceiver<Vec<u8>>,
}

/// Клонируемый хендл подачи реплаев в стек (держит sender+notify; НЕ владеет outbound).
#[derive(Clone)]
pub struct EgressFeed {
    inbound_tx: UnboundedSender<Vec<u8>>,
    notify: Arc<Notify>,
}

impl EgressFeed {
    /// Реплай с провода → в стек. Будит poll-луп (тот дренирует канал `try_recv` на след. тике).
    pub fn feed(&self, pkt: Vec<u8>) {
        if self.inbound_tx.send(pkt).is_ok() {
            self.notify.notify_one();
        }
    }
}

/// Originate-стек: держит poll-задачу, раздаёт `connect`. Клон-дешёвый хендл (каналы + notify).
pub struct EgressStack {
    connect_tx: UnboundedSender<ConnectReq>,
    notify: Arc<Notify>,
    local_ip: Ipv4Addr,
    _task: Arc<JoinHandle<()>>,
}

impl EgressStack {
    /// Поднять стек с исходной личностью `local_ip` (src-IP кадров ДО eBPF-переклейки). Возвращает
    /// хендл + пакетный порт `EgressWire` (подключить к tun или тесту).
    pub fn spawn(local_ip: Ipv4Addr) -> (Self, EgressWire) {
        let (connect_tx, connect_rx) = unbounded_channel::<ConnectReq>();
        let (inbound_tx, inbound_rx) = unbounded_channel::<Vec<u8>>();
        let (outbound_tx, outbound_rx) = unbounded_channel::<Vec<u8>>();
        let notify = Arc::new(Notify::new());

        let task = tokio::spawn(drive(
            local_ip,
            connect_rx,
            inbound_rx,
            outbound_tx,
            notify.clone(),
        ));

        (
            Self {
                connect_tx,
                notify: notify.clone(),
                local_ip,
                _task: Arc::new(task),
            },
            EgressWire {
                feed: EgressFeed { inbound_tx, notify },
                outbound: outbound_rx,
            },
        )
    }

    /// Active-open к `dst` с исходным портом `src_port` (box-owned — ключ демукса eBPF-реплая).
    /// Ждёт установления (Established) либо отказа (RST/закрытие до установления). Отдаёт async-стрим.
    pub async fn connect(&self, dst: SocketAddrV4, src_port: u16) -> io::Result<EgressStream> {
        let control = SockControl::new();
        let (ready_tx, ready_rx) = oneshot::channel();
        let remote = IpEndpoint::new(IpAddress::Ipv4(*dst.ip()), dst.port());

        self.connect_tx
            .send(ConnectReq {
                remote,
                local_port: src_port,
                control: control.clone(),
                ready: ready_tx,
            })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "egress-стек мёртв"))?;
        self.notify.notify_one();

        match ready_rx.await {
            Ok(Ok(())) => Ok(EgressStream {
                control,
                notify: self.notify.clone(),
            }),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "egress-стек закрылся до установления",
            )),
        }
    }

    /// Исходная личность стека (src-IP до eBPF-переклейки) — для сборки src-эндпоинта в тестах/логах.
    pub fn local_ip(&self) -> Ipv4Addr {
        self.local_ip
    }
}

/// Async-стрим установленного egress-сокета. `AsyncRead`/`AsyncWrite` поверх control-буферов (poll-луп
/// шаффлит их со smoltcp-сокетом). Зеркалит `netstack-smoltcp::TcpStream`.
pub struct EgressStream {
    control: SharedControl,
    notify: Arc<Notify>,
}

impl Drop for EgressStream {
    fn drop(&mut self) {
        let mut c = self.control.lock();
        if c.recv_state == Half::Normal {
            c.recv_state = Half::Close;
        }
        if c.send_state == Half::Normal {
            c.send_state = Half::Close;
        }
        drop(c);
        self.notify.notify_one(); // луп закроет сокет (FIN)
    }
}

impl AsyncRead for EgressStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut c = self.control.lock();
        if c.recv_buffer.is_empty() {
            if c.recv_state == Half::Closed {
                return Poll::Ready(Ok(())); // EOF
            }
            replace_waker(&mut c.recv_waker, cx);
            return Poll::Pending;
        }
        let unfilled = unsafe {
            std::mem::transmute::<&mut [std::mem::MaybeUninit<u8>], &mut [u8]>(buf.unfilled_mut())
        };
        let n = c.recv_buffer.dequeue_slice(unfilled);
        buf.advance(n);
        drop(c);
        if n > 0 {
            self.notify.notify_one(); // освободили место в recv-буфере → луп может дочитать сокет
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for EgressStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut c = self.control.lock();
        if c.send_state != Half::Normal {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if c.send_buffer.is_full() {
            replace_waker(&mut c.send_waker, cx);
            return Poll::Pending;
        }
        let n = c.send_buffer.enqueue_slice(buf);
        drop(c);
        if n > 0 {
            self.notify.notify_one(); // разбудить луп — переложит в сокет и qmit'нет
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(())) // данные уже в буфере, луп отправит; smoltcp сам решает сегментацию
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut c = self.control.lock();
        if c.send_state == Half::Closed {
            return Poll::Ready(Ok(()));
        }
        if c.send_state == Half::Normal {
            c.send_state = Half::Close;
        }
        replace_waker(&mut c.send_waker, cx);
        drop(c);
        self.notify.notify_one();
        Poll::Pending
    }
}

/// Зарегистрировать waker, разбудив прежний если это другая задача (контракт smoltcp-async).
fn replace_waker(slot: &mut Option<Waker>, cx: &Context<'_>) {
    if let Some(old) = slot.replace(cx.waker().clone()) {
        if !old.will_wake(cx.waker()) {
            old.wake();
        }
    }
}

/// Poll-луп стека (одна задача): владеет iface/device/sockets. Каждый тик — дренирует запросы
/// `connect` (active-open) и реплаи с провода, поллит smoltcp, шаффлит буферы, будит стримы, снимает
/// закрытые. Спит до следующего события (`notify` от стрима/провода) либо smoltcp-delay.
async fn drive(
    local_ip: Ipv4Addr,
    mut connect_rx: UnboundedReceiver<ConnectReq>,
    mut inbound_rx: UnboundedReceiver<Vec<u8>>,
    outbound_tx: UnboundedSender<Vec<u8>>,
    notify: Arc<Notify>,
) {
    let mut device = ChannelDevice {
        rx: VecDeque::new(),
        tx: outbound_tx,
    };
    let mut iface = build_iface(local_ip, &mut device);
    let mut sockets = SocketSet::new(vec![]);
    let mut entries: HashMap<SocketHandle, SockEntry> = HashMap::new();

    loop {
        // 1. Новые active-open: создать сокет, `connect` (нужен iface.context()), добавить в set.
        loop {
            match connect_rx.try_recv() {
                Ok(req) => open_socket(&mut iface, &mut sockets, &mut entries, req),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return, // все хендлы стека упали
            }
        }

        // 2. Реплаи с провода → в устройство (smoltcp прожуёт на poll).
        loop {
            match inbound_rx.try_recv() {
                Ok(pkt) => device.rx.push_back(pkt),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {} // провод закрыт — стек ещё дренирует сокеты
            }
        }

        let now = SmolInstant::now();
        iface.poll(now, &mut device, &mut sockets);
        service_sockets(&mut sockets, &mut entries);

        // 3. Сон до следующего события. smoltcp-delay (таймеры/ретрансмиты) ИЛИ страховочный тик;
        //    notify будит раньше при write/read/drop стрима или новом реплае/connect.
        let delay = iface
            .poll_delay(now, &sockets)
            .map(|d| Duration::from_micros(d.total_micros()))
            .unwrap_or(IDLE_POLL)
            .min(IDLE_POLL);
        let _ = tokio::time::timeout(delay, notify.notified()).await;
    }
}

/// Собрать smoltcp-iface для originate: medium-ip, адрес = `local_ip`, дефолт-роут (на medium-ip
/// шлюз номинален — L2 не резолвится, кадр кладётся сырым IP в устройство).
fn build_iface(local_ip: Ipv4Addr, device: &mut ChannelDevice) -> Interface {
    let mut cfg = IfaceConfig::new(HardwareAddress::Ip);
    cfg.random_seed = u64::from(u32::from(local_ip)) ^ 0x9E37_79B9_7F4A_7C15; // ISN-разброс без rand-депа
    let mut iface = Interface::new(cfg, device, SmolInstant::now());
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(local_ip), 24));
    });
    // Дефолт-роут обязателен, чтобы стек отправил к произвольной цели; шлюз = сам себя (medium-ip).
    let _ = iface.routes_mut().add_default_ipv4_route(local_ip);
    iface
}

/// Создать TCP-сокет и инициировать active-open. Отказ `connect` (плохой эндпоинт) → сразу сигналим Err.
fn open_socket(
    iface: &mut Interface,
    sockets: &mut SocketSet<'static>,
    entries: &mut HashMap<SocketHandle, SockEntry>,
    req: ConnectReq,
) {
    let mut socket = TcpSocket::new(
        SocketBuffer::new(vec![0u8; TCP_BUF]),
        SocketBuffer::new(vec![0u8; TCP_BUF]),
    );
    match socket.connect(iface.context(), req.remote, req.local_port) {
        Ok(()) => {
            let handle = sockets.add(socket);
            entries.insert(
                handle,
                SockEntry {
                    control: req.control,
                    ready: Some(req.ready),
                },
            );
        }
        Err(e) => {
            let _ = req.ready.send(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("smoltcp connect: {e}"),
            )));
        }
    }
}

/// Пройтись по сокетам: просигналить установление/отказ ждущему `connect`, переложить принятые байты
/// в recv-буфер (разбудив читателя), отдать send-буфер в сокет (разбудив писателя), снять закрытые.
fn service_sockets(
    sockets: &mut SocketSet<'static>,
    entries: &mut HashMap<SocketHandle, SockEntry>,
) {
    let mut to_remove = Vec::new();

    for (handle, entry) in entries.iter_mut() {
        let socket = sockets.get_mut::<TcpSocket>(*handle);
        let state = socket.state();

        // Сигнал `connect`: Established → Ok; закрыт до установления (RST/refused) → Err.
        if entry.ready.is_some() {
            if state == TcpState::Established {
                let _ = entry.ready.take().unwrap().send(Ok(()));
            } else if state == TcpState::Closed {
                let _ = entry
                    .ready
                    .take()
                    .unwrap()
                    .send(Err(io::ErrorKind::ConnectionRefused.into()));
            }
        }

        let mut c = entry.control.lock();

        if state == TcpState::Closed {
            c.recv_state = Half::Closed;
            c.send_state = Half::Closed;
            wake(&mut c.recv_waker);
            wake(&mut c.send_waker);
            to_remove.push(*handle);
            continue;
        }

        // Приём: сокет → recv-буфер стрима.
        let mut woke_reader = false;
        while socket.can_recv() && !c.recv_buffer.is_full() {
            let pushed = socket
                .recv(|data| {
                    let n = c.recv_buffer.enqueue_slice(data);
                    (n, n)
                })
                .unwrap_or(0);
            if pushed == 0 {
                break;
            }
            woke_reader = true;
        }
        // Дальняя сторона закрыла запись (не сможем больше принять) → EOF читателю. ТОЛЬКО когда сокет
        // ушёл из «живых» состояний: до-established (SynSent) `may_recv`=false ЗАКОННО, не EOF (иначе
        // читатель получал бы EOF ещё в рукопожатии — измерено). Whitelist зеркалит netstack-listener.
        let alive = matches!(
            state,
            TcpState::SynSent
                | TcpState::SynReceived
                | TcpState::Established
                | TcpState::FinWait1
                | TcpState::FinWait2
        );
        if c.recv_state == Half::Normal && !socket.may_recv() && !alive {
            c.recv_state = Half::Closed;
            woke_reader = true;
        }
        if woke_reader {
            wake(&mut c.recv_waker);
        }

        // Отдача: send-буфер стрима → сокет.
        let mut woke_writer = false;
        while socket.can_send() && !c.send_buffer.is_empty() {
            let sent = socket
                .send(|space| {
                    let n = c.send_buffer.dequeue_slice(space);
                    (n, n)
                })
                .unwrap_or(0);
            if sent == 0 {
                break;
            }
            woke_writer = true;
        }
        if woke_writer {
            wake(&mut c.send_waker);
        }

        // SHUT_WR/drop → FIN, но ЛИШЬ когда весь send-буфер ушёл в сокет (иначе теряем последнюю
        // запись: close() до дренажа рубит `can_send`, и хвост застревает навсегда — тот баг был
        // виден в тесте как потерянный PONG). Закрываем строго после опустошения буфера.
        if c.send_state == Half::Close && c.send_buffer.is_empty() {
            socket.close();
            c.send_state = Half::Closing;
        }
    }

    for handle in to_remove {
        entries.remove(&handle);
        sockets.remove(handle);
    }
}

fn wake(slot: &mut Option<Waker>) {
    if let Some(w) = slot.take() {
        w.wake();
    }
}

// ── Прод-обёртка: тот же стек, но качаем `EgressWire` в реальный tun (насосы read/write) ──

use tokio::io::unix::AsyncFd;

/// Originate поверх реального tun-устройства: netstack эмитит SYN/данные → tun → eBPF (`reflex_egress`)
/// переклеит личность и `bpf_redirect(eth0)`; реплай eth0→eBPF→tun → стек. `bind` открывает `dev`,
/// поднимает стек и качает пакеты в обе стороны. `connect` проксирует в стек.
pub struct TunEgress {
    stack: EgressStack,
    _pumps: Vec<JoinHandle<()>>,
}

impl TunEgress {
    /// Открыть `dev` (IFF_TUN|IFF_NO_PI), поднять originate-стек с личностью `local_ip`, спавнить насосы.
    pub fn bind(dev: &str, local_ip: Ipv4Addr) -> io::Result<Self> {
        let fd = Arc::new(AsyncFd::new(crate::tun::open_tun(dev)?)?);
        let (stack, wire) = EgressStack::spawn(local_ip);
        let EgressWire { feed, mut outbound } = wire;
        let mut pumps = Vec::new();

        // Насос стек → tun: кадр, что стек хочет отправить (SYN/данные), пишем в устройство.
        {
            let fd = fd.clone();
            pumps.push(tokio::spawn(async move {
                while let Some(pkt) = outbound.recv().await {
                    let _ = crate::tun::write_tun(&fd, &pkt).await;
                }
            }));
        }

        // Насос tun → стек: сырой IP-реплай из устройства подаём внутрь стека (feed — клон-хендл).
        {
            let fd = fd.clone();
            pumps.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    match crate::tun::read_tun(&fd, &mut buf).await {
                        Ok(n) if n > 0 => feed.feed(buf[..n].to_vec()),
                        _ => break,
                    }
                }
            }));
        }

        Ok(Self {
            stack,
            _pumps: pumps,
        })
    }

    /// Инициировать egress-флоу к `dst` из box-owned порта `src_port` (ключ eBPF-демукса реплая).
    pub async fn connect(&self, dst: SocketAddrV4, src_port: u16) -> io::Result<EgressStream> {
        self.stack.connect(dst, src_port).await
    }

    pub fn local_ip(&self) -> Ipv4Addr {
        self.stack.local_ip()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{SinkExt, StreamExt};
    use netstack_smoltcp::StackBuilder;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Originate-стек РЕАЛЬНО устанавливает исходящий TCP и гоняет байты — проверено IN-MEMORY:
    /// пир = listener `netstack-smoltcp`, провод = каналы (egress.outbound → listener.in,
    /// listener.out → egress.feed). Без root/tun. Это несущий неизвестный слайса (Правило 1/6):
    /// доказывает, что active-open на нашем smoltcp-стеке работает end-to-end (SYN→SYN-ACK→данные).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn originate_connects_and_echoes_through_inmemory_peer() {
        // Пир-терминатор (listener netstack-smoltcp): принимает флоу на dst входящего SYN.
        let (peer_stack, runner, _udp, listener) =
            StackBuilder::default().enable_tcp(true).build().unwrap();
        let mut listener = listener.unwrap();
        if let Some(runner) = runner {
            tokio::spawn(async move {
                let _ = runner.await;
            });
        }
        let (mut peer_in, mut peer_out) = peer_stack.split();

        // Originate-стек (клиент): личность 10.0.0.2, подключимся к 10.0.0.1:80.
        let (egress, wire) = EgressStack::spawn(Ipv4Addr::new(10, 0, 0, 2));
        let EgressWire { feed, mut outbound } = wire;

        // Провод (два форвардера): egress-кадры → в пир; кадры пира → egress.feed.
        tokio::spawn(async move {
            while let Some(pkt) = outbound.recv().await {
                if peer_in.send(pkt).await.is_err() {
                    break;
                }
            }
        });
        tokio::spawn(async move {
            while let Some(pkt) = peer_out.next().await {
                match pkt {
                    Ok(p) => feed.feed(p),
                    Err(_) => break,
                }
            }
        });

        // Пир принимает флоу и эхо-обслуживает: читает hello, шлёт ответ, ЖИВЁТ до EOF клиента (иначе
        // netstack-пир закрыл бы сокет до отправки PONG — своя close-before-drain особенность). Спавним
        // ДО connect.
        let peer = tokio::spawn(async move {
            let (mut stream, _client, _dst) = listener.next().await.expect("пир принял флоу");
            let mut got = vec![0u8; 64];
            let n = stream.read(&mut got).await.expect("пир прочитал hello");
            got.truncate(n);
            stream.write_all(b"PONG").await.expect("пир ответил");
            stream.flush().await.ok();
            // Держим сокет живым, пока клиент не прочитает PONG и не закроется (read→0 = EOF клиента).
            let mut drain = [0u8; 8];
            let _ = stream.read(&mut drain).await;
            got
        });

        // Active-open + обмен: пишем hello, читаем ответ пира.
        let dst = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 80);
        let mut stream = tokio::time::timeout(Duration::from_secs(5), egress.connect(dst, 40000))
            .await
            .expect("connect не завис")
            .expect("egress установил исходящий TCP");

        stream
            .write_all(b"PING")
            .await
            .expect("egress записал hello");
        let mut resp = vec![0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut resp))
            .await
            .expect("read не завис")
            .expect("egress прочитал ответ");
        resp.truncate(n);
        drop(stream); // закрываемся → пир увидит EOF и вернётся

        assert_eq!(
            resp, b"PONG",
            "egress получил байты пира через свой active-open"
        );
        assert_eq!(
            peer.await.unwrap(),
            b"PING",
            "пир получил hello, что originate-стек эмитил в SYN-флоу"
        );
    }
}
