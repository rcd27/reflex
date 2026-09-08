//! Присутствие сетевого устройства как `Level<bool>`. netlink здесь — ТОЛЬКО подсказка, ни одно его
//! сообщение не разбирается: истину даёт sysfs (`/sys/class/net/<имя>` существует ⟺ устройство
//! есть). Это следствие «событие есть повод, не истина»: кто разбирает `RTM_NEWLINK`, чтобы узнать
//! состояние, верит фронту и получает гонку подписки + потерю.

use crate::Level;
use std::time::Duration;

/// Уровень «устройство существует», подсказываемый netlink. Отказ подписки — ОШИБКОЙ, не тихим
/// поллингом: тихая деградация маскирует поломку среды там, где её надо увидеть; решение «жить на
/// одном поле» принимает вызывающий одной видимой строкой.
pub fn present(name: &str, floor: Duration) -> std::io::Result<Level<bool>> {
    present_at(std::path::PathBuf::from("/sys/class/net").join(name), floor)
}

/// То же, но путь пробы задан явно — для тестовых харнессов. Подсказка остаётся настоящей:
/// подменяется источник истины, не источник поводов, потому подмена не делает тест зелёным даром.
pub fn present_at(probe: std::path::PathBuf, floor: Duration) -> std::io::Result<Level<bool>> {
    let hint = link_group_socket()?;
    Ok(Level::hinted(hint, floor, move || {
        std::fs::metadata(&probe).is_ok()
    }))
}

/// Сокет, подписанный на группу link-событий. `nl_pid = 0` — адрес назначает ядро; хардкод своего
/// pid столкнул бы два таких уровня в процессе (второй bind — `EADDRINUSE`).
fn link_group_socket() -> std::io::Result<std::os::fd::OwnedFd> {
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Владение берём немедленно: при провале bind дескриптор закроется сам, а не утечёт.
    let owned = unsafe { std::os::fd::FromRawFd::from_raw_fd(raw) };
    // Край FFI: `sockaddr_nl` несёт приватное поле-заполнитель, литералом не строится — нули, затем
    // публичные поля.
    let addr = {
        let mut slot: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        slot.nl_family = libc::AF_NETLINK as u16;
        slot.nl_groups = libc::RTMGRP_LINK as u32;
        slot
    };
    let bound = unsafe {
        libc::bind(
            raw,
            std::ptr::addr_of!(addr) as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if bound < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Outcome;

    // `lo` есть на любом Linux — истина без подготовки среды.
    #[test]
    fn present_sees_loopback() {
        let level = present("lo", Duration::from_millis(50));
        assert!(level.is_ok());
        assert_eq!(level.map(|l| l.get()).ok(), Some(true));
    }

    // Проба по явному пути — истина берётся оттуда, куда указали.
    #[test]
    fn present_at_reads_the_given_path() {
        let here = std::env::temp_dir();
        let level = present_at(here, Duration::from_millis(50));
        assert!(level.is_ok());
        assert_eq!(level.map(|l| l.get()).ok(), Some(true));

        let nowhere = std::path::PathBuf::from("/такого/пути/нет");
        let level = present_at(nowhere, Duration::from_millis(50));
        assert_eq!(level.map(|l| l.get()).ok(), Some(false));
    }

    // Заведомо несуществующее имя: уровень честно ложен, ожидание доходит до дедлайна.
    #[test]
    fn absent_device_times_out() {
        let level = present("устройства-которого-нет", Duration::from_millis(50));
        assert!(level.is_ok());
        let waited = level.map(|l| l.wait_until(|up| *up, Duration::from_millis(200)));
        assert_eq!(waited.ok(), Some(Outcome::TimedOut));
    }
}
