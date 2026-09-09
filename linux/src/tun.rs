//! Fd-субстрат tun-устройства: открыть tun (IPv4, `IFF_TUN|IFF_NO_PI`, non-blocking) + неблокирующие
//! read/write одного пакета. Тонкий примитив края, потребляемый обёртками стека: `tun_listen`
//! (терминация входящих TCP, passive-open) и `tun_egress` (originate, active-open) качают пакеты через
//! свой netstack на движке smoltcp тем же fd. Устройство отдаёт сырой L3 → dst прямо из IP-заголовка,
//! петля-на-себя невыразима. Прежде здесь жила netstack-smoltcp обёртка (#74) — срезана, TCP-терминацию
//! несёт своя обёртка `tun_listen`.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

use tokio::io::unix::AsyncFd;

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
/// Требует CAP_NET_ADMIN. Возвращает владеющий fd. `pub(crate)` — обёртки стека (`tun_listen`,
/// `tun_egress`) качают пакеты через СВОЙ tun тем же механизмом (насосы read/write), не дублируя открытие.
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
