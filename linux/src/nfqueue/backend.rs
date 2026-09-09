use nfq::Queue;

/// Set FD_CLOEXEC on all open file descriptors that are sockets.
/// This prevents child processes (headless Chrome) from inheriting
/// NFQUEUE netlink fds, which would block re-bind after daemon exit.
fn set_cloexec_netlink_fds() {
    let Ok(entries) = std::fs::read_dir("/proc/self/fd") else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(fd_num) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        // Check if it's a socket by reading the link target
        let Ok(link) = std::fs::read_link(entry.path()) else {
            continue;
        };
        if !link.to_string_lossy().starts_with("socket:") {
            continue;
        }
        // Set CLOEXEC on all sockets — safe, since daemon doesn't intend
        // child processes to inherit any sockets
        unsafe {
            let flags = libc::fcntl(fd_num, libc::F_GETFD);
            if flags >= 0 && (flags & libc::FD_CLOEXEC) == 0 {
                libc::fcntl(fd_num, libc::F_SETFD, flags | libc::FD_CLOEXEC);
            }
        }
    }
}

/// Какие сокеты открыты прямо сейчас. Нужен, чтобы РАЗНИЦЕЙ узнать дескриптор очереди: крейт
/// `nfq` держит его приватным и `AsRawFd` не реализует, а без него ждать на нём нечем.
fn open_sockets() -> std::collections::BTreeSet<i32> {
    match std::fs::read_dir("/proc/self/fd") {
        Err(_no_proc) => std::collections::BTreeSet::new(),
        Ok(entries) => entries
            .flatten()
            .filter_map(|entry| {
                let number = entry.file_name().to_string_lossy().parse::<i32>().ok()?;
                let link = std::fs::read_link(entry.path()).ok()?;
                match link.to_string_lossy().starts_with("socket:") {
                    true => Some(number),
                    false => None,
                }
            })
            .collect(),
    }
}

/// Что дало ожидание. `Blind` — дескриптор добыть не удалось, ждать не на чем (зовущий обязан сам
/// не жечь процессор); отдельный вариант, не «ничего не пришло» — у них разная починка.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Waited {
    Ready,
    Idle,
    Blind,
}

pub struct NfqueueBackend {
    queue: Queue,
    /// Дескриптор очереди, добытый разницей при открытии. `None` — ждать не на чем.
    watched: Option<i32>,
}

// Заявления способностей живут в `super::terminal`, не здесь: бэкенд не `Source` и не `Sink`
// (`Source::packets(&mut self)` держал бы его заимствованным, а ответ требует второго `&mut`,
// `E0499`; netlink-сокет один, делить, как `AfPacketBackend` делит кольцо и инжектор, нечем). Форма
// — `Serves` (взять и ответить неделимо) плюс `CanHold`/`CanRefuse`/`CanRewrite`/`CanMark` над
// `Terminal`, все с предметом и под законами.

impl NfqueueBackend {
    pub fn open(queue_num: u16) -> Result<Self, String> {
        let before = open_sockets();
        let mut queue = Queue::open().map_err(|e| format!("failed to open nfqueue: {e}"))?;
        let appeared: Vec<i32> = open_sockets().difference(&before).copied().collect();
        // Ровно один новый сокет — иначе не наш, и лучше ослепнуть, чем ждать на чужом.
        let fresh = match appeared.as_slice() {
            [only] => Some(*only),
            _ambiguous => None,
        };
        queue
            .bind(queue_num)
            .map_err(|e| format!("failed to bind queue {queue_num}: {e}"))?;
        queue.set_nonblocking(true);
        queue
            .set_copy_range(queue_num, 0xFFFF)
            .map_err(|e| format!("failed to set copy range: {e}"))?;

        // Prevent child processes (e.g. headless Chrome) from inheriting this fd.
        // nfq crate creates NETLINK socket without SOCK_CLOEXEC; leaked fd blocks
        // subsequent NFQUEUE binds even after daemon exits.
        set_cloexec_netlink_fds();

        Ok(Self {
            queue,
            watched: fresh,
        })
    }

    /// Ждать на дескрипторе, а не крутиться. Прежде `recv()` в неблокирующем режиме возвращал
    /// «пусто» мгновенно, и цикл звал его снова: ~1100 холостых чтений НА ПАКЕТ — сожжённое ядро,
    /// делавшее непригодным замер цены обработки. Неблокирующий режим остаётся: без него цикл не
    /// проверит условие выхода и не кончится на пустой очереди.
    pub fn wait(&self, millis: i32) -> Waited {
        match self.watched {
            None => Waited::Blind,
            Some(fd) => {
                let mut watched = libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                match unsafe { libc::poll(&mut watched, 1, millis) } {
                    ready if ready > 0 => Waited::Ready,
                    _nothing => Waited::Idle,
                }
            }
        }
    }

    pub fn recv(&mut self) -> Result<nfq::Message, String> {
        self.queue
            .recv()
            .map_err(|e| format!("nfqueue recv error: {e}"))
    }

    /// Отдать вердикт ядру и вернуть, приняло ли оно. Единственное место, где очередь отвечает
    /// миру: прежде их было четыре (`accept`/`accept_marked`/`drop_packet`/`modify`, в каждом `let _
    /// = self.queue.verdict(msg)` — отказ ядра исчезал четырьмя способами). Теперь решение приезжает
    /// `Answered`, вердикт выбирается раз в `super::terminal`, отказ становится величиной
    /// (`NfqCounts::not_taken`).
    pub(crate) fn send_verdict(&mut self, msg: nfq::Message) -> std::io::Result<()> {
        self.queue.verdict(msg)
    }
}
