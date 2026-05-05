use std::process::Command;
use tracing::{info, warn};

pub(crate) struct FirewallRules {
    queue_num: u16,
    fwmark: u32,
    v4_output_installed: bool,
    v4_input_installed: bool,
    v6_output_installed: bool,
    v6_input_installed: bool,
}

impl FirewallRules {
    pub fn install(queue_num: u16, fwmark: u32) -> Result<Self, String> {
        let output_args = Self::output_args(queue_num, fwmark);
        let input_args = Self::input_args(queue_num, fwmark);

        let v4_output_installed = Self::install_rule("iptables", "OUTPUT", &output_args)?;
        let v4_input_installed = Self::install_rule("iptables", "INPUT", &input_args)?;
        let v6_output_installed = Self::install_rule("ip6tables", "OUTPUT", &output_args)?;
        let v6_input_installed = Self::install_rule("ip6tables", "INPUT", &input_args)?;

        Ok(Self {
            queue_num,
            fwmark,
            v4_output_installed,
            v4_input_installed,
            v6_output_installed,
            v6_input_installed,
        })
    }

    fn install_rule(cmd: &str, chain: &str, args: &[String]) -> Result<bool, String> {
        let check = Command::new(cmd)
            .arg("-C")
            .arg(chain)
            .args(args)
            .output()
            .map_err(|e| format!("{cmd} -C {chain}: {e}"))?;

        if check.status.success() {
            info!("{cmd} {chain} NFQUEUE rule already exists, reusing");
            return Ok(false);
        }

        let insert = Command::new(cmd)
            .arg("-I")
            .arg(chain)
            .args(args)
            .output()
            .map_err(|e| format!("{cmd} -I {chain}: {e}"))?;

        if !insert.status.success() {
            let stderr = String::from_utf8_lossy(&insert.stderr);
            return Err(format!("{cmd} -I {chain}: {stderr}"));
        }

        info!("{cmd} {chain} NFQUEUE rule installed");
        Ok(true)
    }

    fn remove_rule(cmd: &str, chain: &str, args: &[String]) {
        match Command::new(cmd).arg("-D").arg(chain).args(args).output() {
            Ok(o) if o.status.success() => info!("{cmd} {chain} rule removed"),
            Ok(o) => warn!("{cmd} -D {chain}: {}", String::from_utf8_lossy(&o.stderr)),
            Err(e) => warn!("{cmd} -D {chain}: {e}"),
        }
    }

    pub fn output_args(queue_num: u16, fwmark: u32) -> Vec<String> {
        vec![
            "-p".into(),
            "tcp".into(),
            "--dport".into(),
            "443".into(),
            "-m".into(),
            "mark".into(),
            "!".into(),
            "--mark".into(),
            format!("0x{fwmark:X}"),
            "-j".into(),
            "NFQUEUE".into(),
            "--queue-num".into(),
            queue_num.to_string(),
        ]
    }

    pub fn input_args(queue_num: u16, fwmark: u32) -> Vec<String> {
        vec![
            "-p".into(),
            "tcp".into(),
            "--sport".into(),
            "443".into(),
            "-m".into(),
            "mark".into(),
            "!".into(),
            "--mark".into(),
            format!("0x{fwmark:X}"),
            "-j".into(),
            "NFQUEUE".into(),
            "--queue-num".into(),
            queue_num.to_string(),
        ]
    }
}

impl Drop for FirewallRules {
    fn drop(&mut self) {
        let output_args = Self::output_args(self.queue_num, self.fwmark);
        let input_args = Self::input_args(self.queue_num, self.fwmark);

        if self.v4_output_installed {
            Self::remove_rule("iptables", "OUTPUT", &output_args);
        }
        if self.v4_input_installed {
            Self::remove_rule("iptables", "INPUT", &input_args);
        }
        if self.v6_output_installed {
            Self::remove_rule("ip6tables", "OUTPUT", &output_args);
        }
        if self.v6_input_installed {
            Self::remove_rule("ip6tables", "INPUT", &input_args);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_args_format() {
        let args = FirewallRules::output_args(200, 0xBB);
        assert_eq!(
            args,
            vec![
                "-p",
                "tcp",
                "--dport",
                "443",
                "-m",
                "mark",
                "!",
                "--mark",
                "0xBB",
                "-j",
                "NFQUEUE",
                "--queue-num",
                "200",
            ]
        );
    }

    #[test]
    fn input_args_format() {
        let args = FirewallRules::input_args(200, 0xBB);
        assert_eq!(
            args,
            vec![
                "-p",
                "tcp",
                "--sport",
                "443",
                "-m",
                "mark",
                "!",
                "--mark",
                "0xBB",
                "-j",
                "NFQUEUE",
                "--queue-num",
                "200",
            ]
        );
    }
}
