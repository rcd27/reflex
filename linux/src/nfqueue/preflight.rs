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
        }
    }
}

impl std::error::Error for PreflightError {}

pub(crate) fn check() -> Result<(), PreflightError> {
    check_capabilities()?;
    check_kernel_module()?;
    info!("NFQUEUE preflight checks passed");
    Ok(())
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
}
