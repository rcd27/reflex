use std::ffi::CString;
use std::fmt;
use std::process::Command;

use reflex_core::guard::{CleanupReport, TrafficGuard};
use tracing::{info, warn};

use super::guard::{ConnmarkConfig, Direction, FirewallRule, MarkMatch, RuleAction, RuleProtocol};

const TABLE_NAME: &str = "geneva";
const TABLE_FAMILY: &str = "inet";
const MARK_TABLE: &str = "nevod_desync";

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
    /// System user whose outbound TCP/443 traffic is steered to this slot's
    /// queue. NftGuard ensures the user exists (creates it if needed) and
    /// resolves it to a uid for the `meta skuid` rule. Verify runners exec
    /// miniooni under this user.
    pub username: String,
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
        // Resolve every slot user to a uid (creating it if missing) BEFORE
        // writing any rule — failing late would leave a half-installed table.
        let slot_uids: Vec<u32> = config
            .slots
            .iter()
            .map(|s| ensure_user(&s.username))
            .collect::<Result<_, _>>()?;

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

        // Restore mark from conntrack — catches teardown/retransmit packets
        // emitted by the kernel after the owning socket has closed (no skuid
        // context). MUST come before the skuid rule so it doesn't overwrite a
        // fresh skuid match. Conntrack guarantees the mark persists for the
        // life of the flow.
        script.push_str(&format!(
            "add rule {TABLE_FAMILY} {TABLE_NAME} output tcp dport 443 ct mark != 0 meta mark set ct mark counter\n"
        ));

        // Per-slot skuid rules: outbound TCP/443 from this slot's uid gets the
        // slot's fwmark, and that fwmark is pinned onto the conntrack entry so
        // the rule above can restore it on later packets.
        for (slot, uid) in config.slots.iter().zip(slot_uids.iter()) {
            script.push_str(&format!(
                "add rule {TABLE_FAMILY} {TABLE_NAME} output tcp dport 443 meta skuid {} meta mark set 0x{:x} ct mark set meta mark counter\n",
                uid, slot.fwmark
            ));
        }

        // Per-slot routing: fwmark -> slot queue
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

/// Resolves a system user to its uid, creating it via `useradd` if missing.
///
/// useradd is best-effort: it can fail when the daemon runs without setuid
/// rights (e.g. with only CAP_NET_ADMIN). In that case we don't surface the
/// failure unless the user is *still* missing afterwards — operators may
/// pre-provision users out-of-band.
fn ensure_user(username: &str) -> Result<u32, NftGuardError> {
    if let Some(uid) = lookup_uid(username) {
        return Ok(uid);
    }

    let create_status = Command::new("useradd")
        .args(["-r", "-M", "-s", "/usr/sbin/nologin", username])
        .output();

    match create_status {
        Ok(o) if o.status.success() => {
            info!("[nft] created system user {username}");
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            warn!("[nft] useradd {username} exit {}: {stderr}", o.status);
        }
        Err(e) => {
            warn!("[nft] useradd {username} spawn failed: {e}");
        }
    }

    lookup_uid(username).ok_or_else(|| {
        NftGuardError(format!(
            "system user {username} does not exist and cannot be created \
             (provision it via useradd or grant the daemon enough privileges)"
        ))
    })
}

/// Wraps `getpwnam_r` — returns the uid if `name` resolves, None otherwise.
fn lookup_uid(name: &str) -> Option<u32> {
    let c_name = CString::new(name).ok()?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0u8; 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    loop {
        let rc = unsafe {
            libc::getpwnam_r(
                c_name.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };
        if rc == 0 {
            if result.is_null() {
                return None;
            }
            return Some(pwd.pw_uid as u32);
        }
        if rc == libc::ERANGE {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        return None;
    }
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

// ── NftMarkGuard: nft-нативный порт `NfqGuard` (SO_MARK-модель десинк-плоскости) ──
// Та же семантика (connmark save/restore + помеченная нога → очередь техники), но nft-нативными
// правилами: `ct mark set meta mark` вместо легаси `CONNMARK --save-mark` (последнего extension нет
// на nft-стеке коробки — iptables-nft роняет `--save-mark`). Держит таблицу; Drop её сносит (RAII).

/// nft-фрагмент mark-матча (Правило 4: exhaustive).
fn mark_expr(m: &MarkMatch) -> String {
    match m {
        MarkMatch::Exact(v) => format!("meta mark 0x{v:x} "),
        MarkMatch::NotEqual(v) => format!("meta mark != 0x{v:x} "),
        MarkMatch::Any => String::new(),
    }
}

/// nft-фрагмент протокол+порт по направлению (Output→dport, Input→sport).
fn proto_expr(p: &RuleProtocol, dir: &Direction) -> String {
    let kw = match dir {
        Direction::Output => "dport",
        Direction::Input => "sport",
    };
    match p {
        RuleProtocol::Tcp { port } => format!("tcp {kw} {port} "),
        RuleProtocol::Udp { port } => format!("udp {kw} {port} "),
    }
}

/// nft-фрагмент действия (Правило 4: exhaustive).
fn action_expr(a: &RuleAction) -> String {
    match a {
        RuleAction::Nfqueue(q) => format!("counter queue num {q} bypass"),
        RuleAction::Accept => "counter accept".to_string(),
        RuleAction::Drop => "counter drop".to_string(),
    }
}

/// Чистая сборка nft-батча из тех же `FirewallRule`+`ConnmarkConfig`, что ест `NfqGuard`. Юнит-тест
/// проверяет форму (nft-приёмку валидирует стенд). connmark ПЕРЕД слот-правилами в каждой цепочке
/// (restore на input даёт метку до слот-матча).
fn build_mark_script(rules: &[FirewallRule], connmark: &Option<ConnmarkConfig>) -> String {
    let mut s = String::new();
    s.push_str(&format!("add table {TABLE_FAMILY} {MARK_TABLE}\n"));
    s.push_str(&format!("flush table {TABLE_FAMILY} {MARK_TABLE}\n"));
    s.push_str(&format!(
        "add chain {TABLE_FAMILY} {MARK_TABLE} output {{ type filter hook output priority 0; policy accept; }}\n"
    ));
    s.push_str(&format!(
        "add chain {TABLE_FAMILY} {MARK_TABLE} input {{ type filter hook input priority 0; policy accept; }}\n"
    ));

    if let Some(cm) = connmark {
        if cm.save_output {
            s.push_str(&format!(
                "add rule {TABLE_FAMILY} {MARK_TABLE} output tcp dport 443 meta mark != 0 ct mark set meta mark counter\n"
            ));
        }
        if cm.restore_input {
            s.push_str(&format!(
                "add rule {TABLE_FAMILY} {MARK_TABLE} input tcp sport 443 ct mark != 0 meta mark set ct mark counter\n"
            ));
        }
    }

    for r in rules {
        let chain = match r.direction {
            Direction::Output => "output",
            Direction::Input => "input",
        };
        s.push_str(&format!(
            "add rule {TABLE_FAMILY} {MARK_TABLE} {chain} {}{}{}\n",
            mark_expr(&r.mark_match),
            proto_expr(&r.protocol, &r.direction),
            action_expr(&r.action),
        ));
    }
    s
}

/// nft-нативный guard десинк-плоскости (дроп-ин замена `NfqGuard::install` для nft-стека).
pub struct NftMarkGuard;

impl NftMarkGuard {
    pub fn install(
        rules: &[FirewallRule],
        connmark: Option<ConnmarkConfig>,
    ) -> Result<Self, NftGuardError> {
        run_nft_batch(&build_mark_script(rules, &connmark))?;
        info!(
            "nftables table {TABLE_FAMILY} {MARK_TABLE} installed (mark-dispatch, {} rules)",
            rules.len()
        );
        Ok(NftMarkGuard)
    }
}

impl Drop for NftMarkGuard {
    fn drop(&mut self) {
        match run_nft(&format!("delete table {TABLE_FAMILY} {MARK_TABLE}")) {
            Ok(()) => info!("nftables table {TABLE_FAMILY} {MARK_TABLE} removed"),
            Err(e) => warn!("nft cleanup: {e}"),
        }
    }
}

#[cfg(test)]
mod mark_tests {
    use super::*;

    fn out(m: u32, q: u16) -> FirewallRule {
        FirewallRule {
            direction: Direction::Output,
            mark_match: MarkMatch::Exact(m),
            action: RuleAction::Nfqueue(q),
            protocol: RuleProtocol::Tcp { port: 443 },
        }
    }

    #[test]
    fn connmark_nft_native_not_legacy_savemark() {
        // Замена легаси `CONNMARK --save-mark` (нет extension на nft) на nft-нативный ct mark.
        let s = build_mark_script(
            &[out(0x100, 200)],
            &Some(ConnmarkConfig {
                save_output: true,
                restore_input: true,
            }),
        );
        assert!(s.contains("output tcp dport 443 meta mark != 0 ct mark set meta mark"));
        assert!(s.contains("input tcp sport 443 ct mark != 0 meta mark set ct mark"));
        assert!(!s.contains("save-mark")); // легаси-синтаксиса быть НЕ должно
    }

    #[test]
    fn slot_marks_dispatch_to_queue_per_direction() {
        // Помеченная нога (SO_MARK) → очередь техники; Output=dport, Input=sport.
        let s = build_mark_script(
            &[
                out(0x101, 201),
                FirewallRule {
                    direction: Direction::Input,
                    mark_match: MarkMatch::Exact(0x101),
                    action: RuleAction::Nfqueue(201),
                    protocol: RuleProtocol::Tcp { port: 443 },
                },
            ],
            &None,
        );
        assert!(s.contains("output meta mark 0x101 tcp dport 443 counter queue num 201 bypass"));
        assert!(s.contains("input meta mark 0x101 tcp sport 443 counter queue num 201 bypass"));
    }
}
