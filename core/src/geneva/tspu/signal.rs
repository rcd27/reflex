use crate::types::Flow;

#[derive(Debug, Clone)]
pub enum BlockageSignal {
    RstInjection {
        flow: Flow,
        sni: Option<String>,
        ttl_expected: u8,
        ttl_actual: u8,
        salvo_count: u32,
    },
    FinInjection {
        flow: Flow,
        sni: Option<String>,
        ttl_expected: u8,
        ttl_actual: u8,
    },
    WindowManipulation {
        flow: Flow,
        sni: Option<String>,
        window: u16,
    },
    IpBlackhole {
        flow: Flow,
        sni: Option<String>,
        syn_retransmits: u32,
    },
    SilentDrop {
        flow: Flow,
        sni: Option<String>,
        retransmit_count: u32,
    },
    ThrottleCliff {
        flow: Flow,
        sni: Option<String>,
        bytes_before: u64,
    },
    ThrottleProbabilistic {
        flow: Flow,
        sni: Option<String>,
        retransmit_ratio: f32,
    },
    AckDrop {
        flow: Flow,
        sni: Option<String>,
        server_retransmits: u32,
    },
}
