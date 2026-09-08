//! Присутствие сетевого устройства как `Level<bool>` (#152).
//!
//! Референт: `model/infra/WitnessSource.tla` — мир `EventResyncFloor` (tobe).
//!
//! Ключевое решение, и оно прямо следует из закона примитива: **netlink здесь
//! используется ТОЛЬКО как подсказка, и ни одно его сообщение не разбирается.**
//! Истину даёт sysfs — `/sys/class/net/<имя>` существует ⟺ устройство есть. Значит
//! парсера netlink в этом источнике нет вовсе: ни заголовков, ни атрибутов, ни
//! проверки типа сообщения.
//!
//! Это не срезанный угол, а прямое следствие «событие есть повод, не истина». Кто
//! разбирает `RTM_NEWLINK`, чтобы узнать, поднялось ли устройство, — уже верит
//! фронту и получает мир `EventOnly` (RED: гонка подписки + потеря).

use crate::Level;
use std::time::Duration;

/// Уровень «устройство существует», подсказываемый netlink.
///
/// Отказ завести подписку возвращается ОШИБКОЙ, а не тихим переходом на поллинг.
/// Тихая деградация была бы соблазнительна — корректность-то от подсказки не зависит,
/// — но она маскирует поломку среды ровно там, где её и надо увидеть. Решение
/// «жить дальше на одном поле» принимает вызывающий, одной видимой строкой.
pub fn present(name: &str, floor: Duration) -> std::io::Result<Level<bool>> {
    present_at(std::path::PathBuf::from("/sys/class/net").join(name), floor)
}

/// То же, но проба задаётся путём явно.
///
/// Нужно там, где истина живёт не по каноническому адресу — прежде всего в тестовых
/// харнессах, подставляющих свой корень. Подсказка при этом остаётся НАСТОЯЩЕЙ:
/// подменяется источник истины, а не источник поводов, и потому подмена не делает
/// тест зелёным даром.
pub fn present_at(probe: std::path::PathBuf, floor: Duration) -> std::io::Result<Level<bool>> {
    let hint = link_group_socket()?;
    Ok(Level::hinted(hint, floor, move || {
        std::fs::metadata(&probe).is_ok()
    }))
}

/// Сокет, подписанный на группу link-событий маршрутизации.
///
/// `nl_pid = 0` — адрес назначает ЯДРО. Хардкод собственного pid столкнул бы два
/// таких уровня в одном процессе (`both` этого и хочет), и второй bind упал бы
/// с `EADDRINUSE`.
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
    // Владение берём НЕМЕДЛЕННО: при провале bind дескриптор закроется сам, а не
    // утечёт (MEM — «витнес располагает»).
    let owned = unsafe { std::os::fd::FromRawFd::from_raw_fd(raw) };
    // Край FFI: `sockaddr_nl` несёт приватное поле-заполнитель, литералом не строится —
    // потому нули, затем присвоение публичных полей.
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

    // `lo` есть на любом Linux — истина, которую можно утверждать без подготовки среды.
    #[test]
    fn present_sees_loopback() {
        let level = present("lo", Duration::from_millis(50));
        assert!(level.is_ok());
        assert_eq!(level.map(|l| l.get()).ok(), Some(true));
    }

    // Проба по явному пути — истина берётся оттуда, куда указали, а не из канона.
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
