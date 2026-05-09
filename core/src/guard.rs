/// Report from cleanup_stale() — how many orphaned resources were removed.
#[derive(Debug, Clone, Default)]
pub struct CleanupReport {
    pub rules_removed: usize,
    pub routes_removed: usize,
}

/// Cross-platform firewall lifecycle contract.
///
/// Implementations: NfqGuard (Linux/iptables), pf (macOS), WinDivert (Windows).
///
/// Contract:
/// - `install()` sets up rules with bypass semantics (dead guard = traffic passes).
/// - Implementors MUST also impl `Drop` to remove all installed rules.
/// - `cleanup_stale()` removes orphaned rules without installing new ones.
pub trait TrafficGuard: Send + Sync + Sized {
    type Rules;
    type Error: std::error::Error;

    /// Install firewall rules with bypass semantics.
    /// If orphaned rules from a previous run are detected, remove them first.
    fn install(rules: Self::Rules) -> Result<Self, Self::Error>;

    /// Remove orphaned rules without installing new ones.
    /// For `--cleanup` CLI and startup recovery.
    fn cleanup_stale() -> Result<CleanupReport, Self::Error>;
}
