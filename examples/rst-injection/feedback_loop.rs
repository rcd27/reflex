use std::collections::HashMap;
use std::time::{Duration, Instant};

use futures::StreamExt;
use rand::rngs::SmallRng;
use rand::SeedableRng;
use reflex_core::geneva::domain::{DomainMode, DomainState, DomainTransition};
use reflex_core::geneva::executor::execute;
use reflex_core::geneva::ga::GaConfig;
use reflex_core::types::{Flow, Mac, Protocol, TcpFlags, TcpOptions, TcpSegment};
use reflex_core::Command;
use reflex_linux::AfPacketBackend;
use std::net::{Ipv4Addr, SocketAddr};

/// A trial: we applied strategy #N to a flow and are watching the result.
struct Trial {
    strategy_index: usize,
    domain: String,
    flow_key: (u16, u16), // (client_port, server_port=443)
    applied_at: Instant,
    rst_seen: bool,
}

const TRIAL_OBSERVE_WINDOW: Duration = Duration::from_secs(2);

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

    let (mut stream, injector) = backend.split();
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

    let mut rng = SmallRng::seed_from_u64(42);
    let mut domains: HashMap<String, DomainState> = HashMap::new();
    let mut rst_count = 0u32;
    let mut strategies_found = 0u32;
    let mut packets_injected = 0u32;
    let mut trials_completed = 0u32;

    // Track server TTLs: (client_port, server_port) -> TTL
    let mut server_ttls: HashMap<(u16, u16), u8> = HashMap::new();
    // Map flow to domain (learned from ClientHello SNI)
    let mut flow_to_domain: HashMap<(u16, u16), String> = HashMap::new();
    // Active trials
    let mut active_trials: Vec<Trial> = Vec::new();
    // Round-robin strategy index per domain
    let mut next_strategy_index: HashMap<String, usize> = HashMap::new();

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
                completed.push((trial.domain.clone(), trial.strategy_index, trial.rst_seen));
                false
            } else {
                true
            }
        });

        // Apply fitness from completed trials
        for (domain, strategy_idx, rst_seen) in &completed {
            if let Some(state) = domains.get_mut(domain) {
                let fitness = if *rst_seen { 0.1 } else { 0.9 };
                state.set_individual_fitness(*strategy_idx, fitness);
                trials_completed += 1;
                eprintln!(
                    "[geneva] trial #{trials_completed}: {domain} strategy[{strategy_idx}] \
                     fitness={fitness} (rst_seen={rst_seen})"
                );
            }
        }

        // Evolve domains that have completed trials
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

        let pkt =
            match tokio::time::timeout(Duration::from_millis(50), StreamExt::next(&mut stream))
                .await
            {
                Ok(Some(p)) => p,
                Ok(None) => break,
                Err(_) => continue,
            };

        // Parse: ethernet(14) + ip(20) + tcp(20) = 54 min
        if pkt.len() < 54 {
            continue;
        }
        if pkt[12] != 0x08 || pkt[13] != 0x00 {
            continue;
        }
        let ip_start = 14;
        if pkt[ip_start + 9] != 6 {
            continue;
        }
        // Skip our own injected packets (TTL <= 1)
        if pkt[ip_start + 8] <= 1 {
            continue;
        }

        let ip_ihl = (pkt[ip_start] & 0x0f) as usize * 4;
        let tcp_start = ip_start + ip_ihl;
        if pkt.len() < tcp_start + 20 {
            continue;
        }

        let src_port = u16::from_be_bytes([pkt[tcp_start], pkt[tcp_start + 1]]);
        let dst_port = u16::from_be_bytes([pkt[tcp_start + 2], pkt[tcp_start + 3]]);
        let tcp_flags = pkt[tcp_start + 13];
        let ttl = pkt[ip_start + 8];
        let tcp_data_offset = (pkt[tcp_start + 12] >> 4) as usize * 4;
        let payload_start = tcp_start + tcp_data_offset;

        let is_syn_ack = tcp_flags & 0x12 == 0x12 && tcp_flags & 0x04 == 0;
        let is_rst = tcp_flags & 0x04 != 0;

        // Track server TTL from SYN+ACK (from port 443)
        if is_syn_ack && src_port == 443 {
            server_ttls.insert((dst_port, src_port), ttl);
        }

        // On ClientHello: extract SNI, map flow → domain
        if dst_port == 443 && tcp_flags & 0x18 == 0x18 && pkt.len() > payload_start + 6 {
            if pkt[payload_start] == 0x16 && pkt[payload_start + 5] == 0x01 {
                let sni = extract_sni(&pkt[payload_start..]);
                if let Some(domain) = sni {
                    eprintln!("[geneva] ClientHello → {domain} (flow {src_port}→{dst_port})");
                    flow_to_domain.insert((src_port, dst_port), domain.clone());

                    // If domain in Blackhole or Desync → apply strategy
                    let strategy_to_apply = if let Some(state) = domains.get(&domain) {
                        match state.mode() {
                            DomainMode::Blackhole => {
                                let pop_size = state.population_size();
                                if pop_size > 0 {
                                    let idx_ref = next_strategy_index.entry(domain.clone()).or_insert(0);
                                    let idx = *idx_ref % pop_size;
                                    *idx_ref += 1;
                                    state.strategy_at(idx).cloned()
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

                    if let Some(strategy) = strategy_to_apply {
                        let seg = parse_tcp_segment(&pkt, ip_start, tcp_start, payload_start);
                        let src_mac = Mac([pkt[6], pkt[7], pkt[8], pkt[9], pkt[10], pkt[11]]);
                        let dst_mac = Mac([pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5]]);
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
                                "[geneva] applied strategy to {domain}: \
                                 {injected_this} packets injected"
                            );
                        }

                        // Record trial
                        let idx = next_strategy_index
                            .get(&domain)
                            .copied()
                            .unwrap_or(1)
                            .wrapping_sub(1)
                            % 10;
                        active_trials.push(Trial {
                            strategy_index: idx,
                            domain,
                            flow_key: (src_port, dst_port),
                            applied_at: Instant::now(),
                            rst_seen: false,
                        });
                    }
                }
            }
        }

        // Detect RST injection: RST from port 443 with anomalous TTL
        if is_rst && src_port == 443 {
            let flow_key = (dst_port, src_port);
            let server_ttl = server_ttls.get(&flow_key).copied();
            let is_anomalous = match server_ttl {
                Some(srv_ttl) => {
                    let delta = (ttl as i16 - srv_ttl as i16).abs();
                    delta > 3
                }
                None => ttl > 100,
            };

            if is_anomalous {
                rst_count += 1;
                let domain = flow_to_domain
                    .get(&flow_key)
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string());
                eprintln!(
                    "[geneva] RST injection #{rst_count} on {domain} (TTL={ttl})"
                );

                // Mark RST on active trials for this flow
                for trial in &mut active_trials {
                    if trial.flow_key == flow_key || trial.domain == domain {
                        trial.rst_seen = true;
                    }
                }

                // Transition domain to Blackhole
                let state = domains
                    .entry(domain.clone())
                    .or_insert_with(|| DomainState::new(domain, ga_config.clone()));
                let flow = parse_flow(&pkt, ip_start, src_port, dst_port);
                let transition = state.on_rst_detected(&flow);
                match transition {
                    DomainTransition::ActivateBlackhole(_) => {
                        eprintln!("[geneva] → Blackhole activated");
                    }
                    DomainTransition::DesyncFailed => {
                        eprintln!("[geneva] → Desync failed, back to Blackhole");
                    }
                    _ => {}
                }
            }
        }
    }

    // Evaluate remaining trials
    for trial in &active_trials {
        let fitness = if trial.rst_seen { 0.1 } else { 0.9 };
        if let Some(state) = domains.get_mut(&trial.domain) {
            state.set_individual_fitness(trial.strategy_index, fitness);
            trials_completed += 1;
        }
    }

    eprintln!(
        "[geneva] done: rst={rst_count}, trials={trials_completed}, \
         strategies={strategies_found}, injected={packets_injected}"
    );

    // Print per-domain summary
    for (domain, state) in &domains {
        eprintln!(
            "[geneva] {domain}: mode={:?}",
            state.mode()
        );
    }

    if rst_count > 0 {
        println!(
            "PASS: rst={rst_count}, trials={trials_completed}, \
             strategies={strategies_found}, injected={packets_injected}"
        );
    } else {
        println!("FAIL: no RST injection detected");
        std::process::exit(1);
    }
}

/// Extract SNI from TLS ClientHello payload.
fn extract_sni(tls_data: &[u8]) -> Option<String> {
    // TLS record: type(1) + version(2) + length(2) + handshake_type(1) + length(3)
    //           + client_version(2) + random(32) + session_id_len(1) + ...
    if tls_data.len() < 43 {
        return None;
    }
    // Skip: record header(5) + handshake type(1) + handshake length(3)
    //      + client version(2) + random(32) = 43
    let mut pos = 43;

    // Session ID
    if pos >= tls_data.len() {
        return None;
    }
    let session_id_len = tls_data[pos] as usize;
    pos += 1 + session_id_len;

    // Cipher suites
    if pos + 2 > tls_data.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([tls_data[pos], tls_data[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    // Compression methods
    if pos >= tls_data.len() {
        return None;
    }
    let comp_methods_len = tls_data[pos] as usize;
    pos += 1 + comp_methods_len;

    // Extensions length
    if pos + 2 > tls_data.len() {
        return None;
    }
    let extensions_len = u16::from_be_bytes([tls_data[pos], tls_data[pos + 1]]) as usize;
    pos += 2;

    let extensions_end = (pos + extensions_len).min(tls_data.len());

    // Walk extensions, find SNI (type 0x0000)
    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([tls_data[pos], tls_data[pos + 1]]);
        let ext_len = u16::from_be_bytes([tls_data[pos + 2], tls_data[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 && ext_len >= 5 && pos + ext_len <= extensions_end {
            let sni_data = &tls_data[pos..pos + ext_len];
            if sni_data.len() >= 5 {
                let name_type = sni_data[2];
                let name_len = u16::from_be_bytes([sni_data[3], sni_data[4]]) as usize;
                if name_type == 0 && 5 + name_len <= sni_data.len() {
                    return String::from_utf8(sni_data[5..5 + name_len].to_vec()).ok();
                }
            }
        }

        pos += ext_len;
    }

    None
}

fn parse_flow(pkt: &[u8], ip_start: usize, src_port: u16, dst_port: u16) -> Flow {
    Flow {
        src: SocketAddr::new(
            Ipv4Addr::new(
                pkt[ip_start + 12],
                pkt[ip_start + 13],
                pkt[ip_start + 14],
                pkt[ip_start + 15],
            )
            .into(),
            src_port,
        ),
        dst: SocketAddr::new(
            Ipv4Addr::new(
                pkt[ip_start + 16],
                pkt[ip_start + 17],
                pkt[ip_start + 18],
                pkt[ip_start + 19],
            )
            .into(),
            dst_port,
        ),
        protocol: Protocol::Tcp,
    }
}

fn parse_tcp_segment(
    pkt: &[u8],
    ip_start: usize,
    tcp_start: usize,
    payload_start: usize,
) -> TcpSegment {
    let src_port = u16::from_be_bytes([pkt[tcp_start], pkt[tcp_start + 1]]);
    let dst_port = u16::from_be_bytes([pkt[tcp_start + 2], pkt[tcp_start + 3]]);

    TcpSegment {
        flow: parse_flow(pkt, ip_start, src_port, dst_port),
        seq: u32::from_be_bytes([
            pkt[tcp_start + 4],
            pkt[tcp_start + 5],
            pkt[tcp_start + 6],
            pkt[tcp_start + 7],
        ]),
        ack: u32::from_be_bytes([
            pkt[tcp_start + 8],
            pkt[tcp_start + 9],
            pkt[tcp_start + 10],
            pkt[tcp_start + 11],
        ]),
        flags: TcpFlags::from_bits_truncate(pkt[tcp_start + 13]),
        window: u16::from_be_bytes([pkt[tcp_start + 14], pkt[tcp_start + 15]]),
        options: TcpOptions::default(),
        ttl: pkt[ip_start + 8],
        payload: pkt[payload_start..].to_vec(),
    }
}
