use libc::{
    c_int, close, ioctl, sendto, sockaddr, sockaddr_ll, socket, AF_PACKET, ETH_P_ALL, IFNAMSIZ,
    SOCK_RAW,
};
use std::ffi::CString;
use std::mem;

const SIOCGIFINDEX: libc::c_ulong = 0x8933;

#[repr(C)]
union IfReqData {
    ifindex: c_int,
    pad: [u8; 24],
}

#[repr(C)]
struct IfReq {
    ifr_name: [u8; IFNAMSIZ],
    data: IfReqData,
}

pub struct Injector {
    fd: i32,
    ifindex: i32,
}

// SAFETY: Injector owns the fd exclusively.
unsafe impl Send for Injector {}
unsafe impl Sync for Injector {}

impl Injector {
    pub fn open(interface: &str) -> Result<Self, String> {
        let fd = unsafe { socket(AF_PACKET, SOCK_RAW, (ETH_P_ALL as u16).to_be() as c_int) };
        if fd < 0 {
            return Err(format!(
                "socket(AF_PACKET) for inject failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        let ifindex = match unsafe { get_ifindex(fd, interface) } {
            Ok(idx) => idx,
            Err(e) => {
                unsafe { close(fd) };
                return Err(e);
            }
        };

        Ok(Injector { fd, ifindex })
    }

    pub fn send(&self, data: &[u8]) -> Result<(), String> {
        let mut sll: sockaddr_ll = unsafe { mem::zeroed() };
        sll.sll_family = AF_PACKET as u16;
        sll.sll_protocol = (ETH_P_ALL as u16).to_be();
        sll.sll_ifindex = self.ifindex;
        sll.sll_halen = 6;

        // copy dst MAC from packet (first 6 bytes of Ethernet frame)
        if data.len() >= 6 {
            sll.sll_addr[..6].copy_from_slice(&data[..6]);
        }

        let ret = unsafe {
            sendto(
                self.fd,
                data.as_ptr() as *const _,
                data.len(),
                0,
                &sll as *const sockaddr_ll as *const sockaddr,
                mem::size_of::<sockaddr_ll>() as u32,
            )
        };

        if ret < 0 {
            Err(format!(
                "sendto() failed: {}",
                std::io::Error::last_os_error()
            ))
        } else {
            Ok(())
        }
    }
}

impl Drop for Injector {
    fn drop(&mut self) {
        unsafe {
            close(self.fd);
        }
    }
}

unsafe fn get_ifindex(fd: i32, name: &str) -> Result<i32, String> {
    if name.len() >= IFNAMSIZ {
        return Err(format!(
            "interface name '{}' too long (max {})",
            name,
            IFNAMSIZ - 1
        ));
    }

    let mut req: IfReq = mem::zeroed();
    let name_cstr =
        CString::new(name).map_err(|_| format!("interface name '{}' contains null byte", name))?;
    let name_bytes = name_cstr.as_bytes_with_nul();
    req.ifr_name[..name_bytes.len()].copy_from_slice(name_bytes);

    #[allow(clippy::cast_possible_wrap)]
    let ret = ioctl(fd, SIOCGIFINDEX as _, &mut req as *mut IfReq);
    if ret < 0 {
        return Err(format!(
            "ioctl(SIOCGIFINDEX) for '{}' failed: {}",
            name,
            std::io::Error::last_os_error()
        ));
    }

    Ok(req.data.ifindex)
}
