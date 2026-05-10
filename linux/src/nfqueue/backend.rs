use nfq::{Queue, Verdict};
use reflex_core::{CanDrop, CanHold, CanInject, CanModify, CanObserve};

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

pub struct NfqueueBackend {
    queue: Queue,
}

impl CanObserve for NfqueueBackend {}
impl CanInject for NfqueueBackend {}
impl CanHold for NfqueueBackend {}
impl CanModify for NfqueueBackend {}
impl CanDrop for NfqueueBackend {}

impl NfqueueBackend {
    pub fn open(queue_num: u16) -> Result<Self, String> {
        let mut queue = Queue::open().map_err(|e| format!("failed to open nfqueue: {e}"))?;
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

        Ok(Self { queue })
    }

    pub fn recv(&mut self) -> Result<nfq::Message, String> {
        self.queue
            .recv()
            .map_err(|e| format!("nfqueue recv error: {e}"))
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
