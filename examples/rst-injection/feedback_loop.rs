use std::collections::HashMap;
use std::time::{Duration, Instant};

use futures::StreamExt;
use rand::rngs::SmallRng;
use rand::SeedableRng;
use reflex_core::geneva::domain::{DomainMode, DomainState, DomainTransition};
use reflex_core::geneva::executor::execute;
use reflex_core::geneva::ga::GaConfig;
use reflex_core::geneva::tspu::{BlockageSignal, TspuConfig, TspuDetector};
use reflex_core::parse::{ParseEthernetExt, ParseIpv4Ext, ParseTcpExt};
use reflex_core::types::{Flow, Mac, TcpSegment};
use reflex_core::{Command, Detector};
use reflex_core::detector::DetectorEvent;
use reflex_linux::AfPacketBackend;

/// A trial: we applied strategy #N to a flow and are watching the result.
struct Trial {
    strategy_index: usize,
    domain: String,
    applied_at: Instant,
    signal_seen: bool,
}

const TRIAL_OBSERVE_WINDOW: Duration = Duration::from_secs(3);

#[tokio::main]
async fn main() {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "br0".to_string());
    let timeout_secs: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    eprintln!("[geneva] opening AF_PACKET on {iface}, timeout={timeout_secs}s");

    let backend = AfPacketBackend::open(&iface, 65535).unwrap_or_else(|e| {
        eprintln!("[geneva] FAIL: {e}");
        std::process::exit(1);
    });

    let (stream, injector) = backend.split();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);

    let ga_config = GaConfig {
        population_size: 10,
        mutation_rate: 0.4,
        crossover_rate: 0.5,
        tournament_size: 3,
        elite_count: 2,
        max_generations: 50,
        fitness_threshold: 0.7,
    };

    let tspu_config = TspuConfig {
        post_hello_timeout: Duration::from_secs(5), // Faster for testing
        ..TspuConfig::default()
    };

    let mut rng = SmallRng::seed_from_u64(42);
    let mut domains: HashMap<String, DomainState> = HashMap::new();
    let mut signal_count = 0u32;
    let mut strategies_found = 0u32;
    let mut packets_injected = 0u32;
    let mut trials_completed = 0u32;
    let mut active_trials: Vec<Trial> = Vec::new();
    let mut next_strategy_index: HashMap<String, usize> = HashMap::new();

    // --- Reactive pipeline ---
    // We can't use the full .group_by_flow().detect() pipeline here because:
    // 1. We need a single TspuDetector per client_flow, but we don't know client_flow upfront
    // 2. We need to inject + evolve GA as side effects
    //
    // So we use TspuDetector::step() manually, but still parse through the reactive chain.
    // The pipeline: raw → ethernet → ipv4 → tcp (reactive parsing)
    // Then: per-flow TspuDetector::step() + domain state + GA (imperative side effects)

    let mut detectors: HashMap<Flow, TspuDetector> = HashMap::new();

    // Raw → Ethernet → IPv4 → TCP (fully reactive parsing pipeline)
    let mut tcp_stream = Box::pin(
        stream
            .filter(|pkt| {
                let big_enough = pkt.len() >= 14 + 20 + 20;
                let not_injected = pkt.len() < 23 || pkt[22] > 1; // TTL > 1
                futures::future::ready(big_enough && not_injected)
            })
            .parse_ethernet()
            .parse_ipv4()
            .parse_tcp(),
    );

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        // Evaluate completed trials
        let now = Instant::now();
        let mut completed: Vec<(String, usize, bool)> = Vec::new();
        active_trials.retain(|trial| {
            if now.duration_since(trial.applied_at) >= TRIAL_OBSERVE_WINDOW {
                completed.push((trial.domain.clone(), trial.strategy_index, trial.signal_seen));
                false
            } else {
                true
            }
        });

        for (domain, strategy_idx, signal_seen) in &completed {
            if let Some(state) = domains.get_mut(domain) {
                let fitness = if *signal_seen { 0.1 } else { 0.9 };
                state.set_individual_fitness(*strategy_idx, fitness);
                trials_completed += 1;
                eprintln!(
                    "[geneva] trial #{trials_completed}: {domain}[{strategy_idx}] \
                     fitness={fitness} (blocked={signal_seen})"
                );
            }
        }

        // Evolve domains with completed trials
        for (domain, _, _) in &completed {
            if let Some(state) = domains.get_mut(domain) {
                if matches!(state.mode(), DomainMode::Blackhole) {
                    let transition = state.evolve_step(&mut rng);
                    if let DomainTransition::SwitchToDesync(ref strategy) = transition {
                        strategies_found += 1;
                        eprintln!(
                            "[geneva] GA found strategy for {domain}! \
                             (#{strategies_found}, depth={})",
                            strategy.tree.depth()
                        );
                    }
                }
            }
        }

        // Poll next TCP segment from reactive pipeline
        let seg = match tokio::time::timeout(
            Duration::from_millis(100),
            tcp_stream.next(),
        )
        .await
        {
            Ok(Some(s)) => s,
            Ok(None) => break,
            Err(_) => {
                // Timeout — run Tick on all detectors
                let now_instant = Instant::now();
                let mut tick_signals = Vec::new();
                // Take all detectors out, step Tick, collect back
                let entries: Vec<(Flow, TspuDetector)> = detectors.drain().collect();
                for (flow, detector) in entries {
                    let (new_detector, sigs) = detector.step(DetectorEvent::Tick(now_instant));
                    for sig in sigs.iter() {
                        tick_signals.push(sig.clone());
                    }
                    detectors.insert(flow, new_detector);
                }
                for sig in tick_signals {
                    process_signal(
                        &sig, &mut domains, &ga_config, &mut active_trials,
                        &mut signal_count, &mut next_strategy_index,
                    );
                }
                continue;
            }
        };

        // Get or create per-flow detector
        let client_flow = normalize_flow(&seg.flow);
        let detector = detectors
            .remove(&client_flow)
            .unwrap_or_else(|| TspuDetector::new(tspu_config.clone(), client_flow.clone()));

        // Step detector with packet
        let (new_detector, signals) = detector.step(DetectorEvent::Packet(seg.clone()));
        detectors.insert(client_flow.clone(), new_detector);

        // Process signals
        for sig in signals.iter() {
            process_signal(
                sig, &mut domains, &ga_config, &mut active_trials,
                &mut signal_count, &mut next_strategy_index,
            );
        }

        // If domain in Blackhole/Desync and this is ClientHello → apply strategy
        if is_client_hello(&seg) {
            let domain = extract_domain_from_signal_or_seg(&domains, &seg);
            if let Some(domain) = domain {
                let strategy = if let Some(state) = domains.get(&domain) {
                    match state.mode() {
                        DomainMode::Blackhole => {
                            let pop_size = state.population_size();
                            if pop_size > 0 {
                                let idx = next_strategy_index.entry(domain.clone()).or_insert(0);
                                let i = *idx % pop_size;
                                *idx += 1;
                                state.strategy_at(i).cloned()
                            } else {
                                None
                            }
                        }
                        DomainMode::Desync => state.active_strategy().cloned(),
                        DomainMode::Clean => None,
                    }
                } else {
                    None
                };

                if let Some(strategy) = strategy {
                    let src_mac = Mac([0; 6]); // Bridge fills MACs
                    let dst_mac = Mac([0; 6]);
                    let commands = execute(&strategy, &seg, &src_mac, &dst_mac);

                    let mut injected_this = 0u32;
                    for cmd in &commands {
                        if let Command::Inject(injectable) = cmd {
                            let bytes = injectable.serialize();
                            if let Err(e) = injector.send(&bytes) {
                                eprintln!("[geneva] inject failed: {e}");
                            } else {
                                packets_injected += 1;
                                injected_this += 1;
                            }
                        }
                    }

                    if injected_this > 0 {
                        eprintln!(
                            "[geneva] applied strategy to {domain}: {injected_this} injected"
                        );
                        let idx = next_strategy_index.get(&domain).copied().unwrap_or(1) - 1;
                        active_trials.push(Trial {
                            strategy_index: idx % 10,
                            domain,
                            applied_at: Instant::now(),
                            signal_seen: false,
                        });
                    }
                }
            }
        }
    }

    eprintln!(
        "[geneva] done: signals={signal_count}, trials={trials_completed}, \
         strategies={strategies_found}, injected={packets_injected}"
    );

    for (domain, state) in &domains {
        eprintln!("[geneva] {domain}: mode={:?}", state.mode());
    }

    if signal_count > 0 {
        println!(
            "PASS: signals={signal_count}, trials={trials_completed}, \
             strategies={strategies_found}, injected={packets_injected}"
        );
    } else {
        println!("FAIL: no blockage signals detected");
        std::process::exit(1);
    }
}

fn process_signal(
    sig: &BlockageSignal,
    domains: &mut HashMap<String, DomainState>,
    ga_config: &GaConfig,
    active_trials: &mut Vec<Trial>,
    signal_count: &mut u32,
    _next_strategy_index: &mut HashMap<String, usize>,
) {
    let (domain, flow) = match sig {
        BlockageSignal::RstInjection { flow, sni, .. } => {
            (sni.clone().unwrap_or_else(|| "unknown".to_string()), flow)
        }
        BlockageSignal::SilentDrop { flow, sni, .. } => {
            (sni.clone().unwrap_or_else(|| "unknown".to_string()), flow)
        }
        BlockageSignal::IpBlackhole { flow, sni, .. } => {
            (sni.clone().unwrap_or_else(|| "unknown".to_string()), flow)
        }
        BlockageSignal::FinInjection { flow, sni, .. } => {
            (sni.clone().unwrap_or_else(|| "unknown".to_string()), flow)
        }
        BlockageSignal::WindowManipulation { flow, sni, .. } => {
            (sni.clone().unwrap_or_else(|| "unknown".to_string()), flow)
        }
        BlockageSignal::ThrottleCliff { flow, sni, .. } => {
            (sni.clone().unwrap_or_else(|| "unknown".to_string()), flow)
        }
        BlockageSignal::ThrottleProbabilistic { flow, sni, .. } => {
            (sni.clone().unwrap_or_else(|| "unknown".to_string()), flow)
        }
        BlockageSignal::AckDrop { flow, sni, .. } => {
            (sni.clone().unwrap_or_else(|| "unknown".to_string()), flow)
        }
    };

    *signal_count += 1;
    eprintln!("[geneva] signal #{signal_count}: {domain} — {:?}", std::mem::discriminant(sig));

    // Mark active trials
    for trial in active_trials.iter_mut() {
        if trial.domain == domain {
            trial.signal_seen = true;
        }
    }

    // Domain state transition
    let state = domains
        .entry(domain.clone())
        .or_insert_with(|| DomainState::new(domain.clone(), ga_config.clone()));
    let transition = state.on_rst_detected(flow);
    match transition {
        DomainTransition::ActivateBlackhole(_) => {
            eprintln!("[geneva] → {domain}: Blackhole activated");
        }
        DomainTransition::DesyncFailed => {
            eprintln!("[geneva] → {domain}: Desync failed, back to Blackhole");
        }
        _ => {}
    }
}

/// Normalize flow to client→server direction (client port > 1024, server port <= 1024 or 443)
fn normalize_flow(flow: &Flow) -> Flow {
    if flow.dst.port() < 1024 || flow.dst.port() == 443 {
        flow.clone()
    } else {
        flow.reversed()
    }
}

fn is_client_hello(seg: &TcpSegment) -> bool {
    seg.flags.is_psh_ack()
        && seg.payload.len() >= 6
        && seg.payload[0] == 0x16
        && seg.payload[5] == 0x01
}

fn extract_domain_from_signal_or_seg(
    domains: &HashMap<String, DomainState>,
    seg: &TcpSegment,
) -> Option<String> {
    // Try to find domain from existing domain states by flow
    for (domain, _state) in domains {
        return Some(domain.clone());
    }
    // Fallback: extract SNI from payload
    extract_sni(&seg.payload)
}

fn extract_sni(tls_data: &[u8]) -> Option<String> {
    if tls_data.len() < 43 {
        return None;
    }
    let mut pos = 43;
    if pos >= tls_data.len() { return None; }
    let session_id_len = tls_data[pos] as usize;
    pos += 1 + session_id_len;
    if pos + 2 > tls_data.len() { return None; }
    let cs_len = u16::from_be_bytes([tls_data[pos], tls_data[pos + 1]]) as usize;
    pos += 2 + cs_len;
    if pos >= tls_data.len() { return None; }
    let comp_len = tls_data[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > tls_data.len() { return None; }
    let ext_len = u16::from_be_bytes([tls_data[pos], tls_data[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_len).min(tls_data.len());
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([tls_data[pos], tls_data[pos + 1]]);
        let this_len = u16::from_be_bytes([tls_data[pos + 2], tls_data[pos + 3]]) as usize;
        pos += 4;
        if ext_type == 0x0000 && this_len >= 5 && pos + this_len <= ext_end {
            let d = &tls_data[pos..pos + this_len];
            if d.len() >= 5 && d[2] == 0 {
                let name_len = u16::from_be_bytes([d[3], d[4]]) as usize;
                if 5 + name_len <= d.len() {
                    return String::from_utf8(d[5..5 + name_len].to_vec()).ok();
                }
            }
        }
        pos += this_len;
    }
    None
}
