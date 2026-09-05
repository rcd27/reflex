use nfq::{Queue, Verdict};

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

/// ЧТО ДАЛО ОЖИДАНИЕ. `Blind` — дескриптор добыть не удалось, ждать не на чем; зовущий обязан
/// сам не жечь процессор. Это ОТДЕЛЬНЫЙ вариант, а не «ничего не пришло»: у них разная починка.
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

// ЗАЯВЛЕНИЯ СНЯТЫ, ПОТОМУ ЧТО У НИХ НЕ БЫЛО ПРЕДМЕТА (05.09.2026). Бэкенд не реализует ни
// `Source`, ни `Sink` — то есть в цепочку не встаёт ни при каких обстоятельствах, и «умею
// вводить»/«умею наблюдать» здесь нельзя было ни подтвердить, ни опровергнуть. С обязательством
// `inject` и супертрейтом `Source` это стало ошибкой сборки, а не тихой пометкой.
//
// ОСТАВШИЕСЯ ТРИ — ТАКИЕ ЖЕ ПУСТЫЕ, и держатся только тем, что до них ещё не дошёл микрошаг:
// `CanHold`/`CanModify`/`CanDrop` сегодня без предмета и снимутся тем же способом.
// TODO(#326): подключить очередь к категории — `NfqSource`/`DesyncSink` из целевого `main()`.
// До тех пор способности этого типа не заявляются вовсе.

impl NfqueueBackend {
    pub fn open(queue_num: u16) -> Result<Self, String> {
        let before = open_sockets();
        let mut queue = Queue::open().map_err(|e| format!("failed to open nfqueue: {e}"))?;
        let appeared: Vec<i32> = open_sockets().difference(&before).copied().collect();
        // РОВНО ОДИН новый сокет — иначе не наш, и лучше ослепнуть, чем ждать на чужом.
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

    /// ЖДАТЬ НА ДЕСКРИПТОРЕ, А НЕ КРУТИТЬСЯ. Прежде `recv()` в неблокирующем режиме возвращал
    /// «пусто» мгновенно, и цикл звал его снова: замер стенда дал ~1100 холостых чтений НА ПАКЕТ.
    /// Это не потеря пакетов, это сожжённое ядро — и оно делало непригодным всякий замер цены
    /// обработки, потому что мерило оболочку.
    ///
    /// Неблокирующий режим при этом ОСТАЁТСЯ: без него цикл не может проверить своё условие
    /// выхода и не заканчивается никогда на пустой очереди.
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

    /// ПРОПУСТИТЬ, ПОСТАВИВ МЕТКУ. Метка уезжает в ядро ТЕМ ЖЕ сообщением, что и вердикт, — то
    /// есть решение и его исполнение неразделимы, и «пометили, но не донесли» непредставимо.
    ///
    /// ПАКЕТ ПРОДОЛЖАЕТ ОБХОД С МЕСТА, ГДЕ ЕГО ЗАБРАЛИ: правило, читающее метку, обязано стоять
    /// НИЖЕ по цепочке, чем правило очереди. Поставь его выше — метка встанет и не будет прочитана
    /// никем, а прибор покажет «решение принято».
    /// ОТДАТЬ ВЕРДИКТ ЯДРУ И ВЕРНУТЬ, ПРИНЯЛО ЛИ ОНО.
    ///
    /// Единственное место, где очередь отвечает миру. Заведено ради того, чтобы отказ ядра
    /// перестал быть тишиной: четыре метода ниже выбрасывали его через `let _ =`, и «мы ответили»
    /// было неотличимо от «ответ не доехал». Ими пользуется терминальный морфизм
    /// (`super::terminal`), а сами они остаются для потребителей, ещё не переведённых на значения.
    pub(crate) fn send_verdict(&mut self, msg: nfq::Message) -> std::io::Result<()> {
        self.queue.verdict(msg)
    }

    pub fn accept_marked(&mut self, mut msg: nfq::Message, mark: u32) {
        msg.set_nfmark(mark);
        msg.set_verdict(Verdict::Accept);
        let _ = self.queue.verdict(msg);
    }

    pub fn accept(&mut self, mut msg: nfq::Message) {
        msg.set_verdict(Verdict::Accept);
        let _ = self.queue.verdict(msg);
    }

    pub fn drop_packet(&mut self, mut msg: nfq::Message) {
        msg.set_verdict(Verdict::Drop);
        let _ = self.queue.verdict(msg);
    }

    pub fn modify(&mut self, mut msg: nfq::Message, new_payload: &[u8]) {
        msg.set_payload(new_payload.to_vec());
        msg.set_verdict(Verdict::Accept);
        let _ = self.queue.verdict(msg);
    }
}
