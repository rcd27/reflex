use aya::maps::HashMap;
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::Ebpf;
use reflex_linux_common::FlowAction;

pub struct TcProgram {
    bpf: Ebpf,
    interface: String,
}

impl TcProgram {
    /// Load and attach TC-BPF classifier on interface egress.
    pub fn attach(interface: &str, bpf_bytes: &[u8]) -> Result<Self, String> {
        let mut bpf = Ebpf::load(bpf_bytes).map_err(|e| format!("eBPF load failed: {e}"))?;

        // add clsact qdisc (required for tc-bpf)
        let _ = tc::qdisc_add_clsact(interface);

        let program: &mut SchedClassifier = bpf
            .program_mut("reflex_tc")
            .ok_or("TC program 'reflex_tc' not found in eBPF object")?
            .try_into()
            .map_err(|e| format!("not a SchedClassifier: {e}"))?;

        program
            .load()
            .map_err(|e| format!("TC program load failed: {e}"))?;

        program
            .attach(interface, TcAttachType::Egress)
            .map_err(|e| format!("TC attach to {interface} egress failed: {e}"))?;

        Ok(Self {
            bpf,
            interface: interface.to_string(),
        })
    }

    /// Set action for a flow in the BPF action table.
    pub fn set_flow_action(&mut self, flow_hash: u32, action: FlowAction) -> Result<(), String> {
        let mut action_table: HashMap<_, u32, u8> = HashMap::try_from(
            self.bpf
                .map_mut("ACTION_TABLE")
                .ok_or("ACTION_TABLE map not found")?,
        )
        .map_err(|e| format!("ACTION_TABLE type mismatch: {e}"))?;

        action_table
            .insert(flow_hash, action as u8, 0)
            .map_err(|e| format!("ACTION_TABLE insert failed: {e}"))?;

        Ok(())
    }

    /// Remove action for a flow.
    pub fn clear_flow_action(&mut self, flow_hash: u32) -> Result<(), String> {
        let mut action_table: HashMap<_, u32, u8> = HashMap::try_from(
            self.bpf
                .map_mut("ACTION_TABLE")
                .ok_or("ACTION_TABLE map not found")?,
        )
        .map_err(|e| format!("ACTION_TABLE type mismatch: {e}"))?;

        let _ = action_table.remove(&flow_hash);
        Ok(())
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }
}

/// Compute flow hash matching the eBPF program's hash_5tuple.
pub fn flow_hash(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, protocol: u8) -> u32 {
    const P: u32 = 0x0100_0193;
    let mut h: u32 = 0x811c_9dc5;

    for byte in src_ip
        .to_ne_bytes()
        .iter()
        .chain(dst_ip.to_ne_bytes().iter())
        .chain(src_port.to_ne_bytes().iter())
        .chain(dst_port.to_ne_bytes().iter())
        .chain(core::slice::from_ref(&protocol).iter())
    {
        h ^= *byte as u32;
        h = h.wrapping_mul(P);
    }

    h
}
