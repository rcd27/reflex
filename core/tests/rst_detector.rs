use futures::StreamExt;
use reflex_core::{Detector, DetectorEvent, ReflexExt};
use smallvec::SmallVec;

// --- domain types (application level, not framework) ---

#[derive(Debug, Clone)]
struct Packet {
    src_ip: u32,
    dst_ip: u32,
    dst_port: u16,
    ttl: u8,
    is_rst: bool,
    is_syn_ack: bool,
    sni: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
struct RstSignal {
    domain: String,
    ttl_delta: i16,
    rst_count: u8,
}

#[derive(Debug, Clone, PartialEq)]
enum Assessment {
    Disruption { domain: String, confidence: f32 },
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq)]
enum Strategy {
    Desync,
    Tunnel,
}

#[derive(Debug, Clone, PartialEq)]
enum Command {
    InjectFake { domain: String },
    Redirect { domain: String },
}

// --- detector (application level) ---

struct RstDetector {
    server_ttl: Option<u8>,
    current_sni: Option<String>,
    rst_count: u8,
}

impl RstDetector {
    fn new() -> Self {
        Self {
            server_ttl: None,
            current_sni: None,
            rst_count: 0,
        }
    }
}

impl Detector for RstDetector {
    type Input = Packet;
    type Signal = RstSignal;

    fn step(mut self, event: DetectorEvent<Packet>) -> (Self, SmallVec<[RstSignal; 2]>) {
        let mut signals = SmallVec::new();

        match event {
            DetectorEvent::Packet(pkt) => {
                if pkt.is_syn_ack {
                    self.server_ttl = Some(pkt.ttl);
                }

                if pkt.sni.is_some() {
                    self.current_sni = pkt.sni;
                }

                if pkt.is_rst {
                    self.rst_count += 1;
                    if let (Some(server_ttl), Some(ref domain)) =
                        (self.server_ttl, &self.current_sni)
                    {
                        let ttl_delta = pkt.ttl as i16 - server_ttl as i16;
                        if ttl_delta.abs() > 5 {
                            signals.push(RstSignal {
                                domain: domain.clone(),
                                ttl_delta,
                                rst_count: self.rst_count,
                            });
                        }
                    }
                }
            }
            DetectorEvent::Tick(_) => {}
        }

        (self, signals)
    }
}

// --- test ---

#[tokio::test(start_paused = true)]
async fn rst_injection_detected_and_strategy_selected() {
    // simulate packet stream: SYN+ACK (server ttl=52), ClientHello, RST (ttl=63, injected by DPI)
    let packets = futures::stream::iter(vec![
        Packet {
            src_ip: 1,
            dst_ip: 2,
            dst_port: 443,
            ttl: 52,
            is_rst: false,
            is_syn_ack: true,
            sni: None,
        },
        Packet {
            src_ip: 2,
            dst_ip: 1,
            dst_port: 443,
            ttl: 64,
            is_rst: false,
            is_syn_ack: false,
            sni: Some("rutracker.org".into()),
        },
        Packet {
            src_ip: 1,
            dst_ip: 2,
            dst_port: 443,
            ttl: 63,
            is_rst: true,
            is_syn_ack: false,
            sni: None,
        },
    ]);

    // Floor 1: detect
    let signals: Vec<RstSignal> = packets.detect(RstDetector::new()).collect().await;

    assert_eq!(signals.len(), 1);
    assert_eq!(signals[0].domain, "rutracker.org");
    assert_eq!(signals[0].ttl_delta, 11); // 63 - 52, injected RST has higher TTL
    assert_eq!(signals[0].rst_count, 1);
}

#[tokio::test(start_paused = true)]
async fn full_pipeline_rst_to_command() {
    let packets = futures::stream::iter(vec![
        Packet {
            src_ip: 1,
            dst_ip: 2,
            dst_port: 443,
            ttl: 52,
            is_rst: false,
            is_syn_ack: true,
            sni: None,
        },
        Packet {
            src_ip: 2,
            dst_ip: 1,
            dst_port: 443,
            ttl: 64,
            is_rst: false,
            is_syn_ack: false,
            sni: Some("rutracker.org".into()),
        },
        Packet {
            src_ip: 1,
            dst_ip: 2,
            dst_port: 443,
            ttl: 63,
            is_rst: true,
            is_syn_ack: false,
            sni: None,
        },
    ]);

    // Floor 1: detect
    // Floor 2: assess (simplified — no group_by/debounce for this unit test)
    // Floor 3: select strategy, materialize command
    let commands: Vec<Command> = packets
        .detect(RstDetector::new())
        // Floor 2: classify
        .map(|signal| {
            if signal.ttl_delta.abs() > 5 {
                Assessment::Disruption {
                    domain: signal.domain,
                    confidence: 0.9,
                }
            } else {
                Assessment::Inconclusive
            }
        })
        // Floor 3: react
        .filter_map(|a| async move {
            if let Assessment::Disruption { domain, confidence } = a {
                if confidence > 0.7 {
                    Some(Command::InjectFake { domain })
                } else {
                    Some(Command::Redirect { domain })
                }
            } else {
                None
            }
        })
        .collect()
        .await;

    assert_eq!(commands.len(), 1);
    assert_eq!(
        commands[0],
        Command::InjectFake {
            domain: "rutracker.org".into()
        }
    );
}
