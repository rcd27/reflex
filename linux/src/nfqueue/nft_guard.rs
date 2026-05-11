use std::fmt;
use std::process::Command;

use reflex_core::guard::{CleanupReport, TrafficGuard};
use tracing::{info, warn};

const TABLE_NAME: &str = "geneva";
const TABLE_FAMILY: &str = "inet";

#[derive(Debug, Clone)]
pub struct NftGuardError(pub String);

impl fmt::Display for NftGuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for NftGuardError {}

#[derive(Debug, Clone)]
pub struct SlotConfig {
    pub fwmark: u32,
    pub queue_num: u16,
}

#[derive(Debug, Clone)]
pub struct NftConfig {
    pub inject_mark: u32,
    pub main_queue: u16,
    pub slots: Vec<SlotConfig>,
}

pub struct NftGuard;

impl NftGuard {
    pub fn install(config: NftConfig) -> Result<Self, NftGuardError> {
        let mut script = String::new();
        script.push_str(&format!("add table {TABLE_FAMILY} {TABLE_NAME}\n"));
        script.push_str(&format!("flush table {TABLE_FAMILY} {TABLE_NAME}\n"));

        // Output chain
        script.push_str(&format!(
            "add chain {TABLE_FAMILY} {TABLE_NAME} output {{ type filter hook output priority 0; policy accept; }}\n"
        ));

        // Global: drop all IPv6 HTTPS
        script.push_str(&format!(
            "add rule {TABLE_FAMILY} {TABLE_NAME} output ip6 version 6 tcp dport 443 counter drop\n"
        ));

        // Global: drop all QUIC (UDP :443)
        script.push_str(&format!(
            "add rule {TABLE_FAMILY} {TABLE_NAME} output udp dport 443 counter drop\n"
        ));

        // Inject mark -> accept (skip queue for injected packets)
        script.push_str(&format!(
            "add rule {TABLE_FAMILY} {TABLE_NAME} output tcp dport 443 meta mark 0x{:x} counter accept\n",
            config.inject_mark
        ));

        // Per-slot rules: fwmark -> slot queue
        for slot in &config.slots {
            script.push_str(&format!(
                "add rule {TABLE_FAMILY} {TABLE_NAME} output tcp dport 443 meta mark 0x{:x} counter queue num {} bypass\n",
                slot.fwmark, slot.queue_num
            ));
        }

        // Default: unmatched HTTPS -> main queue
        script.push_str(&format!(
            "add rule {TABLE_FAMILY} {TABLE_NAME} output tcp dport 443 counter queue num {} bypass\n",
            config.main_queue
        ));

        // Input chain (RST detection on main queue only)
        script.push_str(&format!(
            "add chain {TABLE_FAMILY} {TABLE_NAME} input {{ type filter hook input priority 0; policy accept; }}\n"
        ));
        script.push_str(&format!(
            "add rule {TABLE_FAMILY} {TABLE_NAME} input ip6 version 6 tcp sport 443 counter drop\n"
        ));
        script.push_str(&format!(
            "add rule {TABLE_FAMILY} {TABLE_NAME} input tcp sport 443 counter queue num {} bypass\n",
            config.main_queue
        ));

        run_nft_batch(&script)?;
        info!(
            "nftables table {TABLE_FAMILY} {TABLE_NAME} installed ({} slots)",
            config.slots.len()
        );

        Ok(Self)
    }
}

impl Drop for NftGuard {
    fn drop(&mut self) {
        let cmd = format!("delete table {TABLE_FAMILY} {TABLE_NAME}");
        match run_nft(&cmd) {
            Ok(()) => info!("nftables table {TABLE_FAMILY} {TABLE_NAME} removed"),
            Err(e) => warn!("nft cleanup: {e}"),
        }
    }
}

impl TrafficGuard for NftGuard {
    type Rules = NftConfig;
    type Error = NftGuardError;

    fn install(rules: Self::Rules) -> Result<Self, Self::Error> {
        NftGuard::install(rules)
    }

    fn cleanup_stale() -> Result<CleanupReport, Self::Error> {
        let output = Command::new("nft")
            .args(["list", "tables"])
            .output()
            .map_err(|e| NftGuardError(e.to_string()))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains(TABLE_NAME) {
            let cmd = format!("delete table {TABLE_FAMILY} {TABLE_NAME}");
            run_nft(&cmd)?;
            Ok(CleanupReport {
                rules_removed: 1,
                routes_removed: 0,
            })
        } else {
            Ok(CleanupReport::default())
        }
    }
}

fn run_nft(cmd: &str) -> Result<(), NftGuardError> {
    let output = Command::new("nft")
        .arg(cmd)
        .output()
        .map_err(|e| NftGuardError(format!("nft: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NftGuardError(format!("nft {cmd}: {stderr}")));
    }
    Ok(())
}

fn run_nft_batch(script: &str) -> Result<(), NftGuardError> {
    let output = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(script.as_bytes())?;
            child.wait_with_output()
        })
        .map_err(|e| NftGuardError(format!("nft -f: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NftGuardError(format!("nft batch: {stderr}")));
    }
    Ok(())
}
