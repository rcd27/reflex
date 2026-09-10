// reflex/linux/src/nfqueue/preflight.rs

use std::fmt;
use std::fs;
use std::process::Command;

use tracing::info;

#[derive(Debug)]
pub enum PreflightError {
    NoCapabilities {
        has_net_admin: bool,
        has_net_raw: bool,
        is_root: bool,
    },
    NoKernelModule,
    /// Модуль `nf_conntrack` не загружен — вида края нет вовсе.
    NoConntrack,
    /// Учёт conntrack выключен: счётчики читаются нулём, и «цель не ответила» неотличимо от «мы не
    /// считали». Разные последствия с `NoTimestamps`, потому отдельная буква.
    NoAccounting,
    /// Штампы времени conntrack выключены — возраста потока нет.
    NoTimestamps,
}

impl fmt::Display for PreflightError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCapabilities {
                has_net_admin,
                has_net_raw,
                is_root,
            } => {
                let mut missing = Vec::new();
                if !has_net_admin {
                    missing.push("CAP_NET_ADMIN");
                }
                if !has_net_raw {
                    missing.push("CAP_NET_RAW");
                }
                write!(
                    f,
                    "insufficient privileges: missing {}. is_root={is_root}. \
                     Fix: run as root, or: sudo setcap 'cap_net_admin,cap_net_raw+ep' <binary>",
                    missing.join(", ")
                )
            }
            Self::NoKernelModule => {
                write!(
                    f,
                    "kernel module nfnetlink_queue not loaded. \
                     Fix: sudo modprobe nfnetlink_queue"
                )
            }
            Self::NoConntrack => {
                write!(
                    f,
                    "kernel module nf_conntrack not loaded — no edge view. \
                     Fix: sudo modprobe nf_conntrack"
                )
            }
            Self::NoAccounting => {
                write!(
                    f,
                    "conntrack accounting off — edge counters read zero, a silent drop is \
                     indistinguishable from 'not counted'. \
                     Fix: sudo sysctl -w net.netfilter.nf_conntrack_acct=1"
                )
            }
            Self::NoTimestamps => {
                write!(
                    f,
                    "conntrack timestamps off — no flow age. \
                     Fix: sudo sysctl -w net.netfilter.nf_conntrack_timestamp=1"
                )
            }
        }
    }
}

impl std::error::Error for PreflightError {}

/// Годится ли МАШИНА для очереди: права, модули ядра, учёт conntrack.
///
/// Зовётся носителем при открытии (`IntoCarrier::open`), а не циклом: предпосылка проверяется до
/// первого пакета, иначе потребитель узнаёт о ней голым `errno` из `socket(2)`. Каждая ветка
/// ошибки несёт ЛЕЧЕНИЕ, а не только диагноз («Fix: sudo modprobe …»): первый запуск у нового
/// человека проваливается чаще всего именно здесь, и «Operation not permitted» ему не говорит
/// ничего.
pub fn check() -> Result<(), PreflightError> {
    check_capabilities()?;
    check_kernel_module()?;
    check_conntrack()?;
    check_accounting()?;
    check_timestamps()?;
    info!("NFQUEUE preflight checks passed");
    Ok(())
}

/// Модуль conntrack загружен — без него `NFQA_CT` не приедет, и весь путь края мёртв.
fn check_conntrack() -> Result<(), PreflightError> {
    let modules = fs::read_to_string("/proc/modules").unwrap_or_default();
    match modules.lines().any(|line| line.starts_with("nf_conntrack ")) {
        true => Ok(()),
        false => Err(PreflightError::NoConntrack),
    }
}

/// Sysctl включён (`1`). Отсутствие файла — тоже отказ: считать «включено по умолчанию» нельзя,
/// оба по умолчанию ВЫКЛЮЧЕНЫ.
fn sysctl_on(leaf: &str) -> bool {
    fs::read_to_string(format!("/proc/sys/net/netfilter/{leaf}"))
        .map(|value| value.trim() == "1")
        .unwrap_or(false)
}

fn check_accounting() -> Result<(), PreflightError> {
    match sysctl_on("nf_conntrack_acct") {
        true => Ok(()),
        false => Err(PreflightError::NoAccounting),
    }
}

fn check_timestamps() -> Result<(), PreflightError> {
    match sysctl_on("nf_conntrack_timestamp") {
        true => Ok(()),
        false => Err(PreflightError::NoTimestamps),
    }
}

fn check_capabilities() -> Result<(), PreflightError> {
    let is_root = unsafe { libc::geteuid() } == 0;
    if is_root {
        return Ok(());
    }

    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    let eff_hex = status
        .lines()
        .find(|l| l.starts_with("CapEff:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|h| u64::from_str_radix(h, 16).ok())
        .unwrap_or(0);

    let has_net_admin = eff_hex & (1 << 12) != 0;
    let has_net_raw = eff_hex & (1 << 13) != 0;

    if has_net_admin && has_net_raw {
        Ok(())
    } else {
        Err(PreflightError::NoCapabilities {
            has_net_admin,
            has_net_raw,
            is_root,
        })
    }
}

fn check_kernel_module() -> Result<(), PreflightError> {
    let modules = fs::read_to_string("/proc/modules").unwrap_or_default();
    if modules.contains("nfnetlink_queue") {
        return Ok(());
    }

    let _ = Command::new("modprobe").arg("nfnetlink_queue").output();

    let modules = fs::read_to_string("/proc/modules").unwrap_or_default();
    if modules.contains("nfnetlink_queue") {
        info!("loaded nfnetlink_queue kernel module");
        Ok(())
    } else {
        Err(PreflightError::NoKernelModule)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_preflight_error_readable() {
        let err = PreflightError::NoCapabilities {
            has_net_admin: false,
            has_net_raw: true,
            is_root: false,
        };
        let msg = format!("{err}");
        assert!(msg.contains("CAP_NET_ADMIN"));
        assert!(!msg.contains("CAP_NET_RAW"));
    }

    #[test]
    fn format_preflight_error_module() {
        let err = PreflightError::NoKernelModule;
        let msg = format!("{err}");
        assert!(msg.contains("nfnetlink_queue"));
    }

    /// Выключенный acct — факт о машине, и человеку говорят, ЧЕМ его включить: без счётчиков приборы
    /// края видят нули при зелёной сборке.
    #[test]
    fn accounting_error_names_the_fix() {
        let message = format!("{}", PreflightError::NoAccounting);
        assert!(message.contains("nf_conntrack_acct"));
        assert!(message.contains("sysctl"), "рецепт починки, а не констатация");
    }

    /// Оба sysctl названы РАЗДЕЛЬНО: у них разные последствия (без acct слепнут счётчики, без
    /// timestamp нет возраста), и рецепт у каждого свой.
    #[test]
    fn accounting_and_timestamps_are_named_separately() {
        assert!(format!("{}", PreflightError::NoAccounting).contains("nf_conntrack_acct"));
        assert!(format!("{}", PreflightError::NoTimestamps).contains("nf_conntrack_timestamp"));
    }

}
