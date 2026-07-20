//! Слушатель: СВОЙ netstack ВХОДЯЩИХ TCP-флоу (passive-open) на движке smoltcp — замена
//! `netstack-smoltcp` в `TunFlows` (ПИВОТ #74). Тот же движок, но обёртка ЖИВЁТ В reflex → сокет,
//! его буфер, backpressure и время жизни В НАШЕЙ юрисдикции.
//!
//! ЗАЧЕМ пивот (issue #74): `netstack-smoltcp` — тонкий сторонний переходник (15★), снимает сокет из
//! `SocketSet` ТОЛЬКО по `Closed` с таймаутом 2ч (`set_timeout(7200)`), а не на терминале app-уровня.
//! Field-сценарий: звонок встал → сокет открыт, байт нет, бизнес-флоу умер (verdict=Unreachable за
//! ~1.5с) → буфер висит по вере таймера = орфан. Сотни орфанов/мин → RSS ползёт → USB-нога голодает →
//! дроп ноги через 5-10 мин. Утечку не локализовать: буфер/lifecycle вне нашего кода.
//!
//! ЗЕРКАЛО `tun_egress` (originate-нога): та же несущая (ChannelDevice `phy::Device` → poll-луп `drive`
//! владеет iface+SocketSet → SockControl RingBuffer+wakers → async-стрим), но `socket.listen(dst)`
//! вместо `socket.connect`. Прозрачный listen на ЛЮБОЙ dst: `set_any_ip(true)` + placeholder-адрес,
//! сокет рождается ПО ВХОДЯЩЕМУ SYN (движок сам не создаёт — драйвер парсит кадр и заводит listen).
//!
//! ТРИ ПРОЕКЦИИ (молекулы `model/molecule/`, TLC GREEN):
//!   - `WitnessedLease` (Holding ⟹ Witnessed): `TunStream::Drop → socket.abort()` (RST) снимает сокет
//!     ТЕМ ЖЕ тиком = реап на конце флоу, НЕ по таймеру 2ч. Орфан невыразим в типах (как `PidGuard`).
//!     Backstop: молчание байт-witness дольше `BYTE_IDLE` → abort (добивает завис `write_all`, корень #3).
//!   - `FlowPermit` (inflight ≤ Cap): потолок НА АЛЛОКАЦИИ (на SYN, до создания сокета) — полно → SYN
//!     дропается, клиент ретрансмитит = ТЕМП, не сброс (решённая развилка #74). Не на `accept` — там
//!     буфер уже аллоцирован (замер: netstack аллоцирует на SYN, потолок-на-accept память НЕ связывает).
//!   - bounded-каналы (эталон tailscale-rs `ts_netstack_smoltcp`: командный канал `Some(32)`) вместо
//!     `unbounded` — снимает MEM-выстёг «склад без берегов».
//!
//! TODO(#74): UDP-в-туннель — та же юрисдикция позже (грань молекулы keyed by dst). Пока UDP не в
//! netstack вовсе (пульсар на eBPF-счётчиках), потому слушатель TCP-only; `netstack-smoltcp` для UDP
//! остаётся legacy до отдельного среза.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer, State as TcpState};
use smoltcp::storage::RingBuffer;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Packet, TcpPacket};
use spin::Mutex as SpinMutex;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

const TCP_BUF: usize = 16 * 1024; // буфер сокета smoltcp (эталон tailscale ts_netstack_smoltcp)
const CTRL_BUF: usize = 16 * 1024; // control-буфер стороны стрима (recv/send RingBuffer)
const LISTEN_MTU: usize = 1500;
const IDLE_POLL: Duration = Duration::from_millis(50); // страховочный тик, если smoltcp не дал delay
const FRAME_CHAN_CAP: usize = 256; // bounded пакетный канал (насос backpressure'ит на переполнении)
const DEFAULT_FLOW_CAP: usize = 512; // FlowPermit-потолок по умолчанию (env NEVOD_FLOW_CAP переопределит)
                                     // WitnessedLease backstop: молчание байт-witness дольше этого → abort. СТРОГО ПОЗЖЕ релейного
                                     // `FLOW_IDLE`=120с (`nevod catch.rs`): в норме флоу реапит релей (idle-splice) → Drop→abort;
                                     // backstop добивает лишь ЗАВИС-кейс (write_all под отвалившейся ногой, корень #3), которого релей не
                                     // достал. Раньше 120с рубил бы легитимно-idle соединения, что релей считает живыми. Не 2ч (анти-паттерн).
const BYTE_IDLE_MS: u64 = 180_000;

// ── Общий control сокета: мост между sync poll-лупом (пишет буферы, будит) и async-стримом ──
// Зеркалит `tun_egress::SockControl`, плюс поле `abort` — `TunStream::Drop` поднимает флаг, `drive`
// делает `socket.abort()` (RST) ТЕМ ЖЕ тиком (WitnessedLease: реап на конце флоу, не по таймеру).

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
    abort: bool, // Drop поднял → RST + снятие ТЕМ ЖЕ тиком (орфан невыразим)
}

type SharedControl = Arc<SpinMutex<SockControl>>;

impl SockControl {
    fn new() -> SharedControl {
        Arc::new(SpinMutex::new(SockControl {
            send_buffer: RingBuffer::new(vec![0u8; CTRL_BUF]),
            send_waker: None,
            recv_buffer: RingBuffer::new(vec![0u8; CTRL_BUF]),
            recv_waker: None,
            recv_state: Half::Normal,
            send_state: Half::Normal,
            abort: false,
        }))
    }
}

/// Per-socket запись в poll-лупе: общий control + witness-отметка (`last_active` — когда последний байт
/// РЕАЛЬНО двигался). Молчание дольше `BYTE_IDLE_MS` = чёрствый труп → backstop-реап (WitnessedLease).
struct SockEntry {
    control: SharedControl,
    last_active: SmolInstant,
}

// ── Канальное smoltcp-устройство: rx из очереди (кадры клиента), tx в BOUNDED-сендер (кадры, что стек
// хочет отправить — SYN-ACK/данные обратно). medium-ip: tun даёт сырой IP, L2 клеит eBPF. ──

struct ChannelDevice {
    rx: VecDeque<Vec<u8>>,
    tx: Sender<Vec<u8>>,
}

struct RxTok(Vec<u8>);
struct TxTok(Sender<Vec<u8>>);

impl RxToken for RxTok {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0[..])
    }
}

impl TxToken for TxTok {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        // bounded (MEM-выстёг «берега есть»): канал полон → кадр молча теряется, TCP ретрансмитнет.
        let _ = self.0.try_send(buf);
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
        c.max_transmission_unit = LISTEN_MTU;
        c
    }
}

/// Терминированный TCP-флоу из tun: async-поток к цели. `AsyncRead`/`AsyncWrite` поверх control-буферов
/// (poll-луп шаффлит их со smoltcp-сокетом). Потребитель (`serve_tun`) зависит от трейт-поверхности,
/// не от движка. `Drop = abort` — сокет ⊆ время жизни флоу (см. `Drop` ниже).
pub struct TunStream {
    control: SharedControl,
    notify: Arc<Notify>,
}

impl Drop for TunStream {
    fn drop(&mut self) {
        // WitnessedLease: конец флоу = реап сокета ТЕМ ЖЕ шагом. Флаг `abort` → `drive` делает
        // `socket.abort()` (RST, не graceful FIN) → снятие из SocketSet немедленно → буфер освобождён.
        // netstack держал бы сокет до `Closed`/2ч (орфан). Здесь орфан невыразим — как flock у `PidGuard`.
        let mut c = self.control.lock();
        c.abort = true;
        drop(c);
        self.notify.notify_one();
    }
}

impl AsyncRead for TunStream {
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
            self.notify.notify_one(); // освободили место в recv-буфере → луп дочитает сокет
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TunStream {
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
        Poll::Ready(Ok(())) // данные в буфере, луп отправит; smoltcp сам решает сегментацию
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

fn wake(slot: &mut Option<Waker>) {
    if let Some(w) = slot.take() {
        w.wake();
    }
}

/// Разобрать входящий кадр: IPv4 + TCP + `SYN && !ACK` = первый пакет рукопожатия (новый флоу).
/// Отдаёт ИСТИННЫЙ dst (цель клиента прямо из IP-заголовка — петля-на-себя невыразима). Не-SYN и
/// не-TCP → `None` (кадр всё равно кормится стеку для существующих сокетов). Тотальна: `?`/`.ok()`,
/// без `unwrap`; протокол сверяем равенством (не `_ =>`).
fn parse_syn(frame: &[u8]) -> Option<SocketAddrV4> {
    let ip = Ipv4Packet::new_checked(frame).ok()?;
    if ip.next_header() != IpProtocol::Tcp {
        return None;
    }
    let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
    // SocketAddrV4 (не SocketAddr): `From<SocketAddrV4> for IpListenEndpoint` доступен при одном
    // proto-ipv4 (SocketAddr-конверсия smoltcp требует ещё proto-ipv6 — не тянем, nevod0 IPv4-only).
    (tcp.syn() && !tcp.ack()).then(|| SocketAddrV4::new(ip.dst_addr(), tcp.dst_port()))
}

/// Собрать smoltcp-iface для ПРОЗРАЧНОГО listen: medium-ip, placeholder-адрес `0.0.0.1/0` + дефолт-роут
/// на себя, `set_any_ip(true)` — iface принимает пакет на ЛЮБОЙ dst (истинную цель несёт listen-сокет).
/// Зеркалит netstack-smoltcp `stack.rs` (тот же приём для tun2socks-модели), но IPv4-only (nevod0).
fn build_iface(device: &mut ChannelDevice, seed: u64) -> Interface {
    let mut cfg = IfaceConfig::new(HardwareAddress::Ip);
    cfg.random_seed = seed; // ISN-разброс без rand-депа
    let mut iface = Interface::new(cfg, device, SmolInstant::now());
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0));
    });
    let _ = iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Addr::new(0, 0, 0, 1));
    iface.set_any_ip(true);
    iface
}

/// Poll-луп слушателя (одна задача): владеет iface/device/sockets/entries. Каждый тик — дренирует
/// входящие кадры (SYN → допуск по FlowPermit → listen-сокет + emit в `accept`; все кадры → в движок),
/// поллит smoltcp, шаффлит буферы, будит стримы, реапит закрытые/abort/чёрствые. Спит до события
/// (`notify` от стрима/насоса) либо smoltcp-delay.
async fn drive(
    accept_tx: Sender<(TunStream, SocketAddr)>,
    mut inbound_rx: Receiver<Vec<u8>>,
    outbound_tx: Sender<Vec<u8>>,
    notify: Arc<Notify>,
    flow_cap: usize,
) {
    let mut device = ChannelDevice {
        rx: VecDeque::new(),
        tx: outbound_tx,
    };
    let mut iface = build_iface(&mut device, 0x9E37_79B9_7F4A_7C15);
    let mut sockets = SocketSet::new(vec![]);
    let mut entries: HashMap<SocketHandle, SockEntry> = HashMap::new();

    loop {
        let now = SmolInstant::now();

        // 1. Входящие кадры: SYN → допуск+сокет+emit, все кадры → в устройство (движок прожуёт на poll).
        loop {
            match inbound_rx.try_recv() {
                Ok(frame) => ingest(
                    &mut iface,
                    &mut sockets,
                    &mut entries,
                    &mut device,
                    &accept_tx,
                    &notify,
                    frame,
                    now,
                    flow_cap,
                ),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return, // насос tun→стек умер
            }
        }

        iface.poll(now, &mut device, &mut sockets);
        service_sockets(&mut sockets, &mut entries, now);

        // 2. Сон до следующего события. smoltcp-delay (таймеры/ретрансмиты) ИЛИ страховочный тик;
        //    notify будит раньше при write/read/drop стрима или новом кадре.
        let delay = iface
            .poll_delay(now, &sockets)
            .map(|d| Duration::from_micros(d.total_micros()))
            .unwrap_or(IDLE_POLL)
            .min(IDLE_POLL);
        let _ = tokio::time::timeout(delay, notify.notified()).await;
    }
}

/// Обработать один входящий кадр. На `SYN && !ACK` — ПОТОЛОК (FlowPermit): полно → кадр НЕ кормится
/// (сокет не рождается, память не тратится, клиент ретрансмитит = темп); есть слот → listen-сокет на
/// dst + emit в `accept`. Любой кадр (принятый SYN и данные существующих флоу) кладётся в устройство.
#[allow(clippy::too_many_arguments)]
fn ingest(
    iface: &mut Interface,
    sockets: &mut SocketSet<'static>,
    entries: &mut HashMap<SocketHandle, SockEntry>,
    device: &mut ChannelDevice,
    accept_tx: &Sender<(TunStream, SocketAddr)>,
    notify: &Arc<Notify>,
    frame: Vec<u8>,
    now: SmolInstant,
    flow_cap: usize,
) {
    if let Some(dst) = parse_syn(&frame) {
        // FlowPermit: inflight == entries.len(). Полно → дроп SYN (backpressure, НЕ shed).
        if entries.len() >= flow_cap {
            return;
        }
        let mut socket = TcpSocket::new(
            SocketBuffer::new(vec![0u8; TCP_BUF]),
            SocketBuffer::new(vec![0u8; TCP_BUF]),
        );
        // НЕТ set_timeout(7200): реап по witness (Drop/idle), не по таймеру 2ч (WitnessedLease).
        if socket.listen(dst).is_err() {
            return; // listen на этот endpoint не встал — кадр не кормим (не наш флоу)
        }
        let control = SockControl::new();
        let handle = sockets.add(socket);
        entries.insert(
            handle,
            SockEntry {
                control: control.clone(),
                last_active: now,
            },
        );
        let stream = TunStream {
            control,
            notify: notify.clone(),
        };
        // accept-канал bounded == flow_cap → на потолке допуска Full невозможен; Err = потребитель
        // (`serve_tun`) ушёл → стрим дропнут в этой ветке → `abort`-флаг → сокет снимется следующим тиком.
        let _ = accept_tx.try_send((stream, SocketAddr::V4(dst)));
    }
    let _ = iface; // context не нужен для listen (в отличие от connect в egress) — держим сигнатуру симметричной
    device.rx.push_back(frame);
}

/// Пройтись по сокетам: реапнуть abort/closed/чёрствые, переложить принятые байты в recv-буфер (разбудив
/// читателя), отдать send-буфер в сокет (разбудив писателя), освежить witness на движении байт, закрыть
/// по SHUT_WR. Реап-грань `WitnessedLease`: держим буфер ТОЛЬКО пока witnessed (Drop ИЛИ idle → abort).
fn service_sockets(
    sockets: &mut SocketSet<'static>,
    entries: &mut HashMap<SocketHandle, SockEntry>,
    now: SmolInstant,
) {
    let mut to_remove = Vec::new();

    for (handle, entry) in entries.iter_mut() {
        let socket = sockets.get_mut::<TcpSocket>(*handle);
        let state = socket.state();
        let mut c = entry.control.lock();

        // Реап #1 (WitnessedLease): Drop поднял abort ЛИБО сокет закрыт → RST/снять, вернуть permit.
        if c.abort || state == TcpState::Closed {
            if c.abort {
                socket.abort(); // RST: не ждём graceful-хендшейк молчащего клиента
            }
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
        // Дальняя сторона закрыла запись → EOF читателю, но ТОЛЬКО когда сокет ушёл из «живых» состояний
        // (до-established `may_recv`=false законно, не EOF). Passive-open: живой whitelist без SynSent.
        let alive = matches!(
            state,
            TcpState::SynReceived | TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2
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

        // SHUT_WR/drop → FIN, но ЛИШЬ когда весь send-буфер ушёл в сокет (иначе теряем последнюю запись:
        // close() до дренажа рубит can_send). Закрываем строго после опустошения буфера (как egress).
        if c.send_state == Half::Close && c.send_buffer.is_empty() {
            socket.close();
            c.send_state = Half::Closing;
        }
        drop(c);

        // Witness: байт РЕАЛЬНО двигался → освежить last_active.
        if woke_reader || woke_writer {
            entry.last_active = now;
        }

        // Реап #2 (WitnessedLease backstop): молчание байт-witness дольше BYTE_IDLE → abort. Добивает
        // чёрствый труп (завис `write_all` под отвалившейся ногой = корень #3), которого Drop не достаёт.
        if (now - entry.last_active).total_millis() >= BYTE_IDLE_MS {
            socket.abort();
            let mut c = entry.control.lock();
            c.recv_state = Half::Closed;
            c.send_state = Half::Closed;
            wake(&mut c.recv_waker);
            wake(&mut c.send_waker);
            to_remove.push(*handle);
        }
    }

    for handle in to_remove {
        entries.remove(&handle);
        sockets.remove(handle);
    }
}

/// Резолв FlowPermit-потолка: env `NEVOD_FLOW_CAP` (число) переопределяет дефолт. Потолок = связка
/// рабочего набора с КОНСТАНТОЙ, не с приходящим морем флоу (проекция `FlowPermit.tla`, Cap).
fn resolve_flow_cap() -> usize {
    std::env::var("NEVOD_FLOW_CAP")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&c| c > 0)
        .unwrap_or(DEFAULT_FLOW_CAP)
}

/// Спавн ядра слушателя над готовыми пакетными каналами (`inbound` — кадры клиента внутрь, `outbound` —
/// кадры стека наружу). Отдаёт приём флоу (`accept_rx`) + задачу драйвера. Разнесено от tun-насосов →
/// тестируется IN-MEMORY (пир = наш egress-стек, без root/tun), прод-обёртка `TunFlows::bind` качает в tun.
fn spawn_core(
    inbound_rx: Receiver<Vec<u8>>,
    outbound_tx: Sender<Vec<u8>>,
    flow_cap: usize,
) -> (Receiver<(TunStream, SocketAddr)>, JoinHandle<()>) {
    let (accept_tx, accept_rx) = channel::<(TunStream, SocketAddr)>(flow_cap);
    let notify = Arc::new(Notify::new());
    let task = tokio::spawn(drive(accept_tx, inbound_rx, outbound_tx, notify, flow_cap));
    (accept_rx, task)
}

/// Источник терминированных TCP-флоу из tun (замена `netstack-smoltcp` `TunFlows` в #74). `bind`
/// открывает устройство, поднимает СВОЙ netstack и качает пакеты в обе стороны (насосы); `accept`
/// отдаёт следующий поток + ИСТИННЫЙ dst. Публичный контракт байт-в-байт как у старого `TunFlows` →
/// `serve_tun` не меняется.
pub struct TunFlows {
    accept_rx: Receiver<(TunStream, SocketAddr)>,
    _tasks: Vec<JoinHandle<()>>, // держим драйвер+насосы живыми, пока жив TunFlows
}

impl TunFlows {
    /// Открывает `dev` (IFF_TUN|IFF_NO_PI), поднимает слушатель-стек, спавнит драйвер + два насоса
    /// (tun↔стек). Требует CAP_NET_ADMIN. FlowPermit-потолок берётся из env (`resolve_flow_cap`).
    pub fn bind(dev: &str) -> io::Result<Self> {
        let fd = Arc::new(AsyncFd::new(crate::tun::open_tun(dev)?)?);
        let (inbound_tx, inbound_rx) = channel::<Vec<u8>>(FRAME_CHAN_CAP);
        let (outbound_tx, mut outbound_rx) = channel::<Vec<u8>>(FRAME_CHAN_CAP);
        let (accept_rx, driver) = spawn_core(inbound_rx, outbound_tx, resolve_flow_cap());

        let mut tasks = vec![driver];

        // Насос tun → стек: сырой пакет из устройства подаётся драйверу (bounded → backpressure на насос).
        {
            let fd = fd.clone();
            tasks.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    match crate::tun::read_tun(&fd, &mut buf).await {
                        Ok(n) if n > 0 => {
                            if inbound_tx.send(buf[..n].to_vec()).await.is_err() {
                                break; // драйвер закрылся
                            }
                        }
                        _ => break, // EOF/сбой устройства
                    }
                }
            }));
        }

        // Насос стек → tun: исходящий кадр (SYN-ACK, данные обратно клиенту) пишется в устройство.
        {
            let fd = fd.clone();
            tasks.push(tokio::spawn(async move {
                while let Some(pkt) = outbound_rx.recv().await {
                    let _ = crate::tun::write_tun(&fd, &pkt).await;
                }
            }));
        }

        Ok(Self {
            accept_rx,
            _tasks: tasks,
        })
    }

    /// Следующий терминированный флоу: `(поток, dst)`, где `dst` = ОРИГИНАЛЬНАЯ цель клиента (прямо из
    /// IP-заголовка SYN). `None` — драйвер закрылся (устройство/каналы умерли).
    pub async fn accept(&mut self) -> Option<(TunStream, SocketAddr)> {
        self.accept_rx.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tun_egress::{EgressStack, EgressWire};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// `parse_syn` вынимает ИСТИННЫЙ dst из SYN и молчит на не-SYN/не-TCP (тотальность границы).
    #[test]
    fn parse_syn_extracts_dst_and_ignores_non_syn() {
        use smoltcp::wire::{
            IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr,
            TcpSeqNumber,
        };
        let build = |ctrl: TcpControl| {
            let tcp_repr = TcpRepr {
                src_port: 51000,
                dst_port: 443,
                control: ctrl,
                seq_number: TcpSeqNumber(0),
                ack_number: None,
                window_len: 64240,
                window_scale: None,
                max_seg_size: None,
                sack_permitted: false,
                sack_ranges: [None, None, None],
                timestamp: None,
                payload: &[],
            };
            let src = Ipv4Address::new(10, 0, 0, 9);
            let dst = Ipv4Address::new(93, 184, 216, 34);
            let ip_repr = Ipv4Repr {
                src_addr: src,
                dst_addr: dst,
                next_header: IpProtocol::Tcp,
                payload_len: tcp_repr.buffer_len(),
                hop_limit: 64,
            };
            let mut frame = vec![0u8; ip_repr.buffer_len() + tcp_repr.buffer_len()];
            let mut ip = Ipv4Packet::new_unchecked(&mut frame);
            ip_repr.emit(&mut ip, &Default::default());
            let mut tcp = TcpPacket::new_unchecked(ip.payload_mut());
            tcp_repr.emit(
                &mut tcp,
                &src.into(),
                &dst.into(),
                &smoltcp::phy::ChecksumCapabilities::default(),
            );
            frame
        };

        // SYN (первый пакет рукопожатия) → dst = цель клиента.
        let syn = build(TcpControl::Syn);
        assert_eq!(
            parse_syn(&syn),
            Some("93.184.216.34:443".parse().unwrap()),
            "SYN отдаёт истинный dst из IP-заголовка"
        );
        // не-SYN (голый ACK) → None (кадр существующего флоу, не новый допуск).
        let ack = build(TcpControl::None);
        assert_eq!(parse_syn(&ack), None, "не-SYN не порождает новый флоу");
    }

    /// Слушатель РЕАЛЬНО терминирует входящий TCP и гоняет байты — проверено IN-MEMORY: клиент = наш
    /// egress-стек (active-open), провод = каналы (egress.outbound → listener.inbound, listener.outbound
    /// → egress.feed). Без root/tun. Несущий неизвестный слайса (Правило 1/6): passive-open на нашем
    /// smoltcp-стеке работает end-to-end (SYN → SYN-ACK → данные → эхо).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn listener_terminates_inbound_and_echoes_from_our_egress() {
        // Слушатель (наше ядро) над in-memory проводом.
        let (l_inbound_tx, l_inbound_rx) = channel::<Vec<u8>>(FRAME_CHAN_CAP);
        let (l_outbound_tx, mut l_outbound_rx) = channel::<Vec<u8>>(FRAME_CHAN_CAP);
        let (mut accept_rx, _driver) = spawn_core(l_inbound_rx, l_outbound_tx, DEFAULT_FLOW_CAP);

        // Клиент = наш egress-стек (личность 10.0.0.2 → цель 10.0.0.1:80).
        let (egress, wire) = EgressStack::spawn(Ipv4Addr::new(10, 0, 0, 2));
        let EgressWire { feed, mut outbound } = wire;

        // Провод: egress-кадры → в слушатель; кадры слушателя → egress.feed.
        tokio::spawn(async move {
            while let Some(pkt) = outbound.recv().await {
                if l_inbound_tx.send(pkt).await.is_err() {
                    break;
                }
            }
        });
        tokio::spawn(async move {
            while let Some(pkt) = l_outbound_rx.recv().await {
                feed.feed(pkt);
            }
        });

        // Слушатель принимает флоу и эхо-обслуживает: читает hello, шлёт PONG, живёт до EOF клиента.
        let server = tokio::spawn(async move {
            let (mut stream, dst) = accept_rx.recv().await.expect("слушатель принял флоу");
            let mut got = vec![0u8; 64];
            let n = stream
                .read(&mut got)
                .await
                .expect("слушатель прочитал hello");
            got.truncate(n);
            stream.write_all(b"PONG").await.expect("слушатель ответил");
            stream.flush().await.ok();
            let mut drain = [0u8; 8];
            let _ = stream.read(&mut drain).await;
            (got, dst)
        });

        // Active-open клиента + обмен.
        let dst = std::net::SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 80);
        let mut stream = tokio::time::timeout(Duration::from_secs(5), egress.connect(dst, 40000))
            .await
            .expect("connect не завис")
            .expect("egress установил исходящий TCP к слушателю");
        stream
            .write_all(b"PING")
            .await
            .expect("клиент записал hello");
        let mut resp = vec![0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut resp))
            .await
            .expect("read не завис")
            .expect("клиент прочитал ответ");
        resp.truncate(n);
        drop(stream);

        assert_eq!(resp, b"PONG", "клиент получил эхо слушателя");
        let (got, dst_seen) = server.await.unwrap();
        assert_eq!(got, b"PING", "слушатель принял hello клиента");
        assert_eq!(
            dst_seen,
            "10.0.0.1:80".parse().unwrap(),
            "accept отдал ИСТИННЫЙ dst из SYN"
        );
    }

    /// FlowPermit: при `inflight == Cap` следующий SYN дропается (сокет не создаётся) — потолок стоит
    /// НА АЛЛОКАЦИИ. Проверяем через `ingest` напрямую: Cap=1, два разных SYN → принят один флоу.
    #[tokio::test]
    async fn flow_permit_caps_admission_at_syn() {
        use smoltcp::wire::{
            IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr,
            TcpSeqNumber,
        };
        let syn_to = |dst_port: u16| {
            let tcp_repr = TcpRepr {
                src_port: 50000 + dst_port,
                dst_port,
                control: TcpControl::Syn,
                seq_number: TcpSeqNumber(0),
                ack_number: None,
                window_len: 64240,
                window_scale: None,
                max_seg_size: None,
                sack_permitted: false,
                sack_ranges: [None, None, None],
                timestamp: None,
                payload: &[],
            };
            let src = Ipv4Address::new(10, 0, 0, 9);
            let dst = Ipv4Address::new(93, 184, 216, 34);
            let ip_repr = Ipv4Repr {
                src_addr: src,
                dst_addr: dst,
                next_header: IpProtocol::Tcp,
                payload_len: tcp_repr.buffer_len(),
                hop_limit: 64,
            };
            let mut frame = vec![0u8; ip_repr.buffer_len() + tcp_repr.buffer_len()];
            let mut ip = Ipv4Packet::new_unchecked(&mut frame);
            ip_repr.emit(&mut ip, &Default::default());
            let mut tcp = TcpPacket::new_unchecked(ip.payload_mut());
            tcp_repr.emit(
                &mut tcp,
                &src.into(),
                &dst.into(),
                &smoltcp::phy::ChecksumCapabilities::default(),
            );
            frame
        };

        let (outbound_tx, _outbound_rx) = channel::<Vec<u8>>(FRAME_CHAN_CAP);
        let (accept_tx, mut accept_rx) = channel::<(TunStream, SocketAddr)>(4);
        let notify = Arc::new(Notify::new());
        let mut device = ChannelDevice {
            rx: VecDeque::new(),
            tx: outbound_tx,
        };
        let mut iface = build_iface(&mut device, 1);
        let mut sockets = SocketSet::new(vec![]);
        let mut entries: HashMap<SocketHandle, SockEntry> = HashMap::new();
        let now = SmolInstant::now();
        let cap = 1;

        ingest(
            &mut iface,
            &mut sockets,
            &mut entries,
            &mut device,
            &accept_tx,
            &notify,
            syn_to(443),
            now,
            cap,
        );
        ingest(
            &mut iface,
            &mut sockets,
            &mut entries,
            &mut device,
            &accept_tx,
            &notify,
            syn_to(8443),
            now,
            cap,
        );

        assert_eq!(entries.len(), 1, "Cap=1: второй SYN дропнут на аллокации");
        assert!(accept_rx.try_recv().is_ok(), "первый флоу принят");
        assert!(
            accept_rx.try_recv().is_err(),
            "второй флоу НЕ создан (backpressure на SYN)"
        );
    }
}
