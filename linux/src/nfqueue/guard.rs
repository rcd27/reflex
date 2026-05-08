use std::process::Command;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Rule types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Direction {
    Output,
    Input,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarkMatch {
    /// Match exact fwmark: `-m mark --mark 0xNN`
    Exact(u32),
    /// Match everything except: `-m mark ! --mark 0xNN`
    NotEqual(u32),
    /// No mark filter
    Any,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleAction {
    Nfqueue(u16),
    Accept,
    Drop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleProtocol {
    Tcp { port: u16 },
    Udp { port: u16 },
}

/// Single firewall rule declaration.
/// Port matching depends on Direction: Output → --dport, Input → --sport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallRule {
    pub direction: Direction,
    pub mark_match: MarkMatch,
    pub action: RuleAction,
    pub protocol: RuleProtocol,
}

#[derive(Debug, Clone)]
pub struct ConnmarkConfig {
    pub save_output: bool,
    pub restore_input: bool,
}

#[derive(Debug, Clone)]
pub struct PolicyRoute {
    pub fwmark: u32,
    pub table: String,
    pub priority: u32,
}

// ---------------------------------------------------------------------------
// FirewallGuard
// ---------------------------------------------------------------------------

pub struct FirewallGuard {
    rules: Vec<InstalledRule>,
    connmark_save: bool,
    connmark_restore: bool,
    policy_routes: Vec<PolicyRoute>,
}

struct InstalledRule {
    cmd: String,
    chain: String,
    args: Vec<String>,
}

impl FirewallGuard {
    /// Install all rules atomically. Returns guard that cleans up on Drop.
    ///
    /// Rules are inserted in order: first element = highest priority in iptables.
    /// (iptables -I inserts at top, so we insert in reverse order.)
    pub fn install(
        rules: Vec<FirewallRule>,
        connmark: Option<ConnmarkConfig>,
        routes: Vec<PolicyRoute>,
    ) -> Result<Self, String> {
        let mut installed = Vec::new();

        // Install connmark first (mangle table, lowest priority)
        let mut connmark_save = false;
        let mut connmark_restore = false;
        if let Some(ref cm) = connmark {
            if cm.save_output {
                Self::install_rule_table(
                    "iptables",
                    "mangle",
                    "OUTPUT",
                    &Self::connmark_save_args(),
                )?;
                connmark_save = true;
            }
            if cm.restore_input {
                Self::install_rule_table(
                    "iptables",
                    "mangle",
                    "INPUT",
                    &Self::connmark_restore_args(),
                )?;
                connmark_restore = true;
            }
        }

        // Install policy routes
        for route in &routes {
            Self::install_policy_route(route)?;
        }

        // Install filter rules in reverse order (iptables -I inserts at top)
        for rule in rules.iter().rev() {
            let (cmd, chain, args) = Self::rule_to_args(rule);
            Self::run_iptables_install(&cmd, &chain, &args)?;
            installed.push(InstalledRule { cmd, chain, args });
        }

        Ok(Self {
            rules: installed,
            connmark_save,
            connmark_restore,
            policy_routes: routes,
        })
    }

    // -----------------------------------------------------------------------
    // Rule → iptables args
    // -----------------------------------------------------------------------

    pub fn rule_to_args(rule: &FirewallRule) -> (String, String, Vec<String>) {
        let cmd = "iptables".to_string();
        let chain = match rule.direction {
            Direction::Output => "OUTPUT".to_string(),
            Direction::Input => "INPUT".to_string(),
        };

        let mut args = Vec::new();

        // Protocol and port
        match &rule.protocol {
            RuleProtocol::Tcp { port } => {
                args.extend(["-p".into(), "tcp".into()]);
                let port_flag = match rule.direction {
                    Direction::Output => "--dport",
                    Direction::Input => "--sport",
                };
                args.extend([port_flag.into(), port.to_string()]);
            }
            RuleProtocol::Udp { port } => {
                args.extend(["-p".into(), "udp".into()]);
                let port_flag = match rule.direction {
                    Direction::Output => "--dport",
                    Direction::Input => "--sport",
                };
                args.extend([port_flag.into(), port.to_string()]);
            }
        }

        // Mark match
        match &rule.mark_match {
            MarkMatch::Exact(mark) => {
                args.extend([
                    "-m".into(),
                    "mark".into(),
                    "--mark".into(),
                    format!("0x{mark:X}"),
                ]);
            }
            MarkMatch::NotEqual(mark) => {
                args.extend([
                    "-m".into(),
                    "mark".into(),
                    "!".into(),
                    "--mark".into(),
                    format!("0x{mark:X}"),
                ]);
            }
            MarkMatch::Any => {}
        }

        // Action
        match &rule.action {
            RuleAction::Nfqueue(queue_num) => {
                args.extend([
                    "-j".into(),
                    "NFQUEUE".into(),
                    "--queue-num".into(),
                    queue_num.to_string(),
                ]);
            }
            RuleAction::Accept => {
                args.extend(["-j".into(), "ACCEPT".into()]);
            }
            RuleAction::Drop => {
                args.extend(["-j".into(), "DROP".into()]);
            }
        }

        (cmd, chain, args)
    }

    pub fn connmark_save_args() -> Vec<String> {
        vec!["-j".into(), "CONNMARK".into(), "--save-mark".into()]
    }

    pub fn connmark_restore_args() -> Vec<String> {
        vec!["-j".into(), "CONNMARK".into(), "--restore-mark".into()]
    }

    // -----------------------------------------------------------------------
    // iptables execution
    // -----------------------------------------------------------------------

    fn run_iptables_install(cmd: &str, chain: &str, args: &[String]) -> Result<(), String> {
        let check = Command::new(cmd)
            .arg("-w")
            .arg("5")
            .arg("-C")
            .arg(chain)
            .args(args)
            .output()
            .map_err(|e| format!("{cmd} -C {chain}: {e}"))?;

        if check.status.success() {
            warn!("{cmd} {chain} rule already exists (orphaned?), removing");
            Self::run_iptables_remove(cmd, chain, args);
        }

        let insert = Command::new(cmd)
            .arg("-w")
            .arg("5")
            .arg("-I")
            .arg(chain)
            .args(args)
            .output()
            .map_err(|e| format!("{cmd} -I {chain}: {e}"))?;

        if !insert.status.success() {
            let stderr = String::from_utf8_lossy(&insert.stderr);
            return Err(format!("{cmd} -I {chain}: {stderr}"));
        }

        info!("{cmd} {chain} rule installed");
        Ok(())
    }

    fn run_iptables_remove(cmd: &str, chain: &str, args: &[String]) {
        match Command::new(cmd)
            .arg("-w")
            .arg("5")
            .arg("-D")
            .arg(chain)
            .args(args)
            .output()
        {
            Ok(o) if o.status.success() => info!("{cmd} {chain} rule removed"),
            Ok(o) => warn!("{cmd} -D {chain}: {}", String::from_utf8_lossy(&o.stderr)),
            Err(e) => warn!("{cmd} -D {chain}: {e}"),
        }
    }

    fn install_rule_table(
        cmd: &str,
        table: &str,
        chain: &str,
        args: &[String],
    ) -> Result<(), String> {
        let check = Command::new(cmd)
            .arg("-w")
            .arg("5")
            .arg("-t")
            .arg(table)
            .arg("-C")
            .arg(chain)
            .args(args)
            .output()
            .map_err(|e| format!("{cmd} -t {table} -C {chain}: {e}"))?;

        if check.status.success() {
            warn!("{cmd} -t {table} {chain} rule already exists (orphaned?), removing");
            Self::remove_rule_table(cmd, table, chain, args);
        }

        let insert = Command::new(cmd)
            .arg("-w")
            .arg("5")
            .arg("-t")
            .arg(table)
            .arg("-I")
            .arg(chain)
            .args(args)
            .output()
            .map_err(|e| format!("{cmd} -t {table} -I {chain}: {e}"))?;

        if !insert.status.success() {
            let stderr = String::from_utf8_lossy(&insert.stderr);
            return Err(format!("{cmd} -t {table} -I {chain}: {stderr}"));
        }

        info!("{cmd} -t {table} {chain} rule installed");
        Ok(())
    }

    fn remove_rule_table(cmd: &str, table: &str, chain: &str, args: &[String]) {
        match Command::new(cmd)
            .arg("-w")
            .arg("5")
            .arg("-t")
            .arg(table)
            .arg("-D")
            .arg(chain)
            .args(args)
            .output()
        {
            Ok(o) if o.status.success() => info!("{cmd} -t {table} {chain} rule removed"),
            Ok(o) => warn!(
                "{cmd} -t {table} -D {chain}: {}",
                String::from_utf8_lossy(&o.stderr)
            ),
            Err(e) => warn!("{cmd} -t {table} -D {chain}: {e}"),
        }
    }

    fn install_policy_route(route: &PolicyRoute) -> Result<(), String> {
        // Remove if exists (idempotent)
        let _ = Command::new("ip")
            .args([
                "rule",
                "del",
                "fwmark",
                &format!("0x{:X}", route.fwmark),
                "lookup",
                &route.table,
            ])
            .output();

        let output = Command::new("ip")
            .args([
                "rule",
                "add",
                "fwmark",
                &format!("0x{:X}", route.fwmark),
                "lookup",
                &route.table,
                "priority",
                &route.priority.to_string(),
            ])
            .output()
            .map_err(|e| format!("ip rule add: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "ip rule add fwmark 0x{:X}: {stderr}",
                route.fwmark
            ));
        }

        info!(
            "ip rule: fwmark 0x{:X} → table {} (priority {})",
            route.fwmark, route.table, route.priority
        );
        Ok(())
    }

    fn remove_policy_route(route: &PolicyRoute) {
        match Command::new("ip")
            .args([
                "rule",
                "del",
                "fwmark",
                &format!("0x{:X}", route.fwmark),
                "lookup",
                &route.table,
            ])
            .output()
        {
            Ok(o) if o.status.success() => {
                info!("ip rule removed: fwmark 0x{:X}", route.fwmark)
            }
            Ok(o) => warn!("ip rule del: {}", String::from_utf8_lossy(&o.stderr)),
            Err(e) => warn!("ip rule del: {e}"),
        }
    }
}

impl Drop for FirewallGuard {
    fn drop(&mut self) {
        for rule in &self.rules {
            Self::run_iptables_remove(&rule.cmd, &rule.chain, &rule.args);
        }
        if self.connmark_save {
            Self::remove_rule_table("iptables", "mangle", "OUTPUT", &Self::connmark_save_args());
        }
        if self.connmark_restore {
            Self::remove_rule_table(
                "iptables",
                "mangle",
                "INPUT",
                &Self::connmark_restore_args(),
            );
        }
        for route in &self.policy_routes {
            Self::remove_policy_route(route);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_output_tcp_exact_mark_nfqueue() {
        let rule = FirewallRule {
            direction: Direction::Output,
            mark_match: MarkMatch::Exact(0xBD),
            action: RuleAction::Nfqueue(201),
            protocol: RuleProtocol::Tcp { port: 443 },
        };
        let (cmd, chain, args) = FirewallGuard::rule_to_args(&rule);
        assert_eq!(cmd, "iptables");
        assert_eq!(chain, "OUTPUT");
        assert_eq!(
            args,
            vec![
                "-p", "tcp", "--dport", "443", "-m", "mark", "--mark", "0xBD", "-j", "NFQUEUE",
                "--queue-num", "201"
            ]
        );
    }

    #[test]
    fn rule_input_tcp_not_equal_mark_nfqueue() {
        let rule = FirewallRule {
            direction: Direction::Input,
            mark_match: MarkMatch::NotEqual(0xBB),
            action: RuleAction::Nfqueue(200),
            protocol: RuleProtocol::Tcp { port: 443 },
        };
        let (_, chain, args) = FirewallGuard::rule_to_args(&rule);
        assert_eq!(chain, "INPUT");
        assert_eq!(
            args,
            vec![
                "-p", "tcp", "--sport", "443", "-m", "mark", "!", "--mark", "0xBB", "-j",
                "NFQUEUE", "--queue-num", "200"
            ]
        );
    }

    #[test]
    fn rule_input_exact_mark_accept() {
        let rule = FirewallRule {
            direction: Direction::Input,
            mark_match: MarkMatch::Exact(0xBD),
            action: RuleAction::Accept,
            protocol: RuleProtocol::Tcp { port: 443 },
        };
        let (_, _, args) = FirewallGuard::rule_to_args(&rule);
        assert_eq!(
            args,
            vec![
                "-p", "tcp", "--sport", "443", "-m", "mark", "--mark", "0xBD", "-j", "ACCEPT"
            ]
        );
    }

    #[test]
    fn rule_output_udp_any_mark_drop() {
        let rule = FirewallRule {
            direction: Direction::Output,
            mark_match: MarkMatch::Any,
            action: RuleAction::Drop,
            protocol: RuleProtocol::Udp { port: 443 },
        };
        let (_, _, args) = FirewallGuard::rule_to_args(&rule);
        assert_eq!(args, vec!["-p", "udp", "--dport", "443", "-j", "DROP"]);
    }

    #[test]
    fn connmark_args() {
        assert_eq!(
            FirewallGuard::connmark_save_args(),
            vec!["-j", "CONNMARK", "--save-mark"]
        );
        assert_eq!(
            FirewallGuard::connmark_restore_args(),
            vec!["-j", "CONNMARK", "--restore-mark"]
        );
    }
}
