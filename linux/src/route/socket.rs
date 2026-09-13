//! Сокет к маршрутизатору ядра (`NETLINK_ROUTE`). Всё IO свидетеля — здесь; разбор — в `wire`.

use std::ffi::CString;
use std::net::Ipv4Addr;

use libc::{
    c_int, c_void, close, recv, send, socket, AF_NETLINK, NETLINK_ROUTE, SOCK_CLOEXEC, SOCK_RAW,
};
use reflex_core::types::Protocol;

use super::wire::{locals_of, locals_request, route_request, went_of, Went};
use crate::netlink::{errno, Portion};

const BUFFER: usize = 64 * 1024;

/// Индекс устройства по имени; `None` — такого нет в ЭТОМ сетевом пространстве.
pub(crate) fn index_of(device: &str) -> Option<u32> {
    CString::new(device)
        .ok()
        .map(|name| unsafe { libc::if_nametoindex(name.as_ptr()) })
        .filter(|&index| index != 0)
}

pub(crate) struct Router {
    fd: c_int,
}

impl Router {
    pub(crate) fn open() -> Result<Router, i32> {
        match unsafe { socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE) } {
            below if below < 0 => Err(errno()),
            fd => Ok(Router { fd }),
        }
    }

    pub(crate) fn route(
        &self,
        dst: Ipv4Addr,
        mark: u32,
        l4: Protocol,
        port: u16,
    ) -> Result<Went, i32> {
        self.ask(&route_request(dst, mark, l4, port, 1))?;
        self.portion().map(|reply| went_of(&reply))
    }

    /// Свои адреса. Конец объявляет ядро (`NLMSG_DONE`); пустое чтение — тоже конец, иначе обход
    /// ждал бы порции, которой не будет.
    pub(crate) fn locals(&self) -> Result<Vec<Ipv4Addr>, i32> {
        self.ask(&locals_request(2))?;
        self.drain(Vec::new())
    }

    fn drain(&self, so_far: Vec<Ipv4Addr>) -> Result<Vec<Ipv4Addr>, i32> {
        let portion = self.portion()?;
        match (portion.is_empty(), locals_of(&portion)) {
            (true, _) => Ok(so_far),
            (false, Portion::Failed(code)) => Err(code.saturating_neg()),
            (false, Portion::Done(last)) => Ok(so_far.into_iter().chain(last).collect()),
            (false, Portion::More(more)) => self.drain(so_far.into_iter().chain(more).collect()),
        }
    }

    fn ask(&self, request: &[u8]) -> Result<(), i32> {
        match unsafe { send(self.fd, request.as_ptr() as *const c_void, request.len(), 0) } {
            below if below < 0 => Err(errno()),
            _sent => Ok(()),
        }
    }

    fn portion(&self) -> Result<Vec<u8>, i32> {
        // Мутация живёт ровно здесь: ядру нужен буфер, в который оно пишет.
        let mut buffer = vec![0u8; BUFFER];
        match unsafe { recv(self.fd, buffer.as_mut_ptr() as *mut c_void, BUFFER, 0) } {
            below if below < 0 => Err(errno()),
            got => {
                buffer.truncate(got as usize);
                Ok(buffer)
            }
        }
    }
}

impl Drop for Router {
    fn drop(&mut self) {
        unsafe { close(self.fd) };
    }
}
