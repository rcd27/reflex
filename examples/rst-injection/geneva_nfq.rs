use std::collections::HashMap;
use std::time::{Duration, Instant};

use rand::rngs::SmallRng;
use rand::SeedableRng;
use reflex_core::checksum;
use reflex_core::detector::DetectorEvent;
use reflex_core::geneva::domain::{DomainMode, DomainState, DomainTransition};
use reflex_core::geneva::ga::GaConfig;
use reflex_core::geneva::tspu::{BlockageSignal, TspuConfig, TspuDetector};
use reflex_core::types::{Flow, Protocol, TcpFlags, TcpOptions, TcpSegment};
use reflex_core::Detector;
use reflex_linux::nfqueue::NfqueueBackend;
use reflex_linux::{AfPacketBackend, Injector};
use std::net::{Ipv4Addr, SocketAddr};

struct Trial {
    strategy_index: usize,
    domain: String,
    applied_at: Instant,
    signal_seen: bool,
}

const TRIAL_WINDOW: Duration = Duration::from_secs(3);

fn main() {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "br0".to_string());
    let queue_num: u16 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let timeout_secs: u64 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    eprintln!("[geneva-nfq] iface={iface}, queue={queue_num}, timeout={timeout_secs}s");

    let mut nfq = NfqueueBackend::open(queue_num).unwrap_or_else(|e| {
        eprintln!("[geneva-nfq] FAIL open nfqueue: {e}");
        std::process::exit(1);
    });

    // AF_PACKET for injecting fragments (NFQUEUE can't inject new packets, only verdict originals)
    let inject_backend = AfPacketBackend::open(&iface, 65535).unwrap_or_else(|e| {
        eprintln!("[geneva-nfq] FAIL open AF_PACKET: {e}");
        std::process::exit(1);
    });
    let (_, injector) = inject_backend.split();

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
        post_hello_timeout: Duration::from_secs(5),
        ..TspuConfig::default()
    };

    let mut rng = SmallRng::seed_from_u64(42);
    let mut domains: HashMap<String, DomainState> = HashMap::new();
    let mut detectors: HashMap<Flow, TspuDetector> = HashMap::new();
    let mut active_trials: Vec<Trial> = Vec::new();
    let mut next_strategy_index: HashMap<String, usize> = HashMap::new();

    let mut signal_count = 0u32;
    let mut strategies_found = 0u32;
    let mut packets_injected = 0u32;
    let mut trials_completed = 0u32;
    let mut accepted = 0u32;
    let mut dropped = 0u32;

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);

    loop {
        if Instant::now() >= deadline {
            break;
        }

        // Evaluate completed trials
        let now = Instant::now();
        let mut completed: Vec<(String, usize, bool)> = Vec::new();
        active_trials.retain(|t| {
            if now.duration_since(t.applied_at) >= TRIAL_WINDOW {
                completed.push((t.domain.clone(), t.strategy_index, t.signal_seen));
                false
            } else {
                true
            }
        });
        for (domain, idx, blocked) in &completed {
            if let Some(state) = domains.get_mut(domain) {
                let fitness = if *blocked { 0.1 } else { 0.9 };
                state.set_individual_fitness(*idx, fitness);
                trials_completed += 1;
                eprintln!(
                    "[geneva-nfq] trial #{trials_completed}: {domain}[{idx}] fitness={fitness}"
                );
            }
        }
        for (domain, _, _) in &completed {
            if let Some(state) = domains.get_mut(domain) {
                if matches!(state.mode(), DomainMode::Blackhole) {
                    if let DomainTransition::SwitchToDesync(ref s) = state.evolve_step(&mut rng) {
                        strategies_found += 1;
                        eprintln!(
                            "[geneva-nfq] GA found strategy for {domain}! depth={}",
                            s.tree.depth()
                        );
                    }
                }
            }
        }

        // Tick detectors periodically
        // (simplified: we tick on every iteration when no packet available)

        // Receive packet from NFQUEUE (with timeout via sleep)
        let msg = match nfq.recv() {
            Ok(m) => {
                eprintln!("[geneva-nfq] recv: {} bytes", m.get_payload().len());
                m
            }
            Err(e) => {
                // EAGAIN/EWOULDBLOCK expected in non-blocking mode
                let err_str = e.to_string();
                if err_str.contains("temporarily")
                    || err_str.contains("again")
                    || err_str.contains("11")
                {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
                eprintln!("[geneva-nfq] recv error: {e}");
                continue;
            }
        };

        let payload = msg.get_payload();
        if payload.len() < 40 {
            nfq.accept(msg);
            accepted += 1;
            continue;
        }

        // Parse IP + TCP from NFQUEUE payload (no ethernet header!)
        let seg = match parse_ip_tcp(payload) {
            Some(s) => s,
            None => {
                nfq.accept(msg);
                accepted += 1;
                continue;
            }
        };

        let client_flow = normalize_flow(&seg.flow);

        // Run detector
        let detector = detectors
            .remove(&client_flow)
            .unwrap_or_else(|| TspuDetector::new(tspu_config.clone(), client_flow.clone()));
        let (new_detector, signals) = detector.step(DetectorEvent::Packet(seg.clone()));
        detectors.insert(client_flow.clone(), new_detector);

        // Process signals
        for sig in signals.iter() {
            signal_count += 1;
            let domain = signal_domain(sig);
            eprintln!("[geneva-nfq] signal #{signal_count}: {domain}");

            for trial in active_trials.iter_mut() {
                if trial.domain == domain {
                    trial.signal_seen = true;
                }
            }

            let state = domains
                .entry(domain.clone())
                .or_insert_with(|| DomainState::new(domain.clone(), ga_config.clone()));
            let transition = state.on_rst_detected(signal_flow(sig));
            match transition {
                DomainTransition::ActivateBlackhole(_) => {
                    eprintln!("[geneva-nfq] → {domain}: Blackhole");
                }
                DomainTransition::DesyncFailed => {
                    eprintln!("[geneva-nfq] → {domain}: Desync failed");
                }
                _ => {}
            }
        }

        // Decision: what to do with this packet?
        if is_client_hello(&seg) {
            let sni = extract_sni(&seg.payload);
            let domain = sni.unwrap_or_else(|| "unknown".to_string());

            // PREEMPTIVE DESYNC: split ClientHello via NFQUEUE modify
            // Strategy: modify original to contain only first 3 bytes of payload,
            // then inject the rest as a second packet via raw socket
            let split_at = 1usize.min(seg.payload.len());
            if split_at > 0 && split_at < seg.payload.len() {
                eprintln!("[geneva-nfq] ClientHello → {domain}, disorder split at {split_at}");

                // Build first fragment: IP packet with truncated TCP payload
                let first_ip = build_ip_fragment(payload, split_at);

                // Build second fragment: IP packet with remaining payload, seq advanced
                let second_ip = build_ip_second_fragment(payload, split_at, seg.seq);

                // DISORDER: inject SECOND fragment FIRST (via raw socket)
                // Then send FIRST fragment via modify verdict
                // ТСПУ sees out-of-order segments and can't reassemble
                if let Err(e) = send_raw_ip(&second_ip) {
                    eprintln!("[geneva-nfq] inject second-first failed: {e}");
                } else {
                    packets_injected += 1;
                }

                // Release first fragment (arrives AFTER second = disorder)
                nfq.modify(msg, &first_ip);
                packets_injected += 1;

                dropped += 1;
                continue;
            }
        }

        // Default: accept
        nfq.accept(msg);
        accepted += 1;
    }

    eprintln!(
        "[geneva-nfq] done: signals={signal_count}, trials={trials_completed}, \
         strategies={strategies_found}, injected={packets_injected}, \
         accepted={accepted}, dropped={dropped}"
    );

    for (domain, state) in &domains {
        eprintln!("[geneva-nfq] {domain}: mode={:?}", state.mode());
    }

    if signal_count > 0 || strategies_found > 0 {
        println!(
            "PASS: signals={signal_count}, strategies={strategies_found}, \
             injected={packets_injected}"
        );
    } else {
        println!("PASS: no blockage detected (clean)");
    }
}

fn apply_strategy_nfq(
    seg: &TcpSegment,
    raw_ip_payload: &[u8],
    strategy: &reflex_core::geneva::GenevaStrategy,
    injector: &Injector,
    packets_injected: &mut u32,
) {
    use reflex_core::geneva::{GenevaAction, StrategyNode};

    match &strategy.tree {
        StrategyNode::Action { action, .. } => match action {
            GenevaAction::Fragment {
                offset, in_order, ..
            } => {
                // TCP segmentation: split ClientHello at offset
                // We need to build two Ethernet+IP+TCP packets from the original
                let split_at = (*offset).min(seg.payload.len());
                if split_at == 0 || split_at >= seg.payload.len() {
                    // Can't split meaningfully, just inject original
                    return;
                }

                let first = build_fragment_packet(
                    raw_ip_payload,
                    seg,
                    &seg.payload[..split_at],
                    seg.seq,
                    false,
                );
                let second = build_fragment_packet(
                    raw_ip_payload,
                    seg,
                    &seg.payload[split_at..],
                    seg.seq + split_at as u32,
                    true,
                );

                let (a, b) = if *in_order {
                    (first, second)
                } else {
                    (second, first)
                };

                if let Err(e) = injector.send(&a) {
                    eprintln!("[geneva-nfq] inject fragment 1 failed: {e}");
                } else {
                    *packets_injected += 1;
                }
                if let Err(e) = injector.send(&b) {
                    eprintln!("[geneva-nfq] inject fragment 2 failed: {e}");
                } else {
                    *packets_injected += 1;
                }
            }
            GenevaAction::Duplicate { modify } => {
                // Inject a modified copy, original will be accepted or dropped by caller
                let mut fake = raw_ip_payload.to_vec();
                if let Some(tamper) = modify {
                    if let GenevaAction::Tamper { field, op } = tamper.as_ref() {
                        use reflex_core::geneva::PacketField;
                        use reflex_core::geneva::TamperOp;
                        match field {
                            PacketField::IpTtl => {
                                if let TamperOp::Replace(v) = op {
                                    if let Some(&ttl) = v.first() {
                                        fake[8] = ttl; // IP TTL offset in IP header
                                    }
                                } else {
                                    fake[8] = 1;
                                }
                                // Recompute IP checksum
                                fake[10] = 0;
                                fake[11] = 0;
                                let ip_ihl = (fake[0] & 0x0f) as usize * 4;
                                let csum = checksum::ip_checksum(&fake[..ip_ihl]);
                                fake[10] = (csum >> 8) as u8;
                                fake[11] = (csum & 0xff) as u8;
                            }
                            _ => {}
                        }
                    }
                }
                // Wrap in ethernet frame for AF_PACKET injection
                // We don't have MACs from NFQUEUE, use zeros (bridge fills them)
                let mut eth_frame = vec![0u8; 14];
                eth_frame[12] = 0x08; // IPv4
                eth_frame[13] = 0x00;
                eth_frame.extend_from_slice(&fake);

                if let Err(e) = injector.send(&eth_frame) {
                    eprintln!("[geneva-nfq] inject fake failed: {e}");
                } else {
                    *packets_injected += 1;
                }
            }
            _ => {}
        },
        StrategyNode::Send => {
            // Nothing to do, original will be accepted
        }
    }
}

/// Build an Ethernet+IP+TCP fragment from parts.
/// `raw_ip` is the original IP packet (no ethernet).
fn build_fragment_packet(
    raw_ip: &[u8],
    seg: &TcpSegment,
    payload: &[u8],
    seq: u32,
    is_second: bool,
) -> Vec<u8> {
    let ip_ihl = (raw_ip[0] & 0x0f) as usize * 4;
    let tcp_header_len = 20; // We use minimal TCP header for fragments

    let ip_total_len = (ip_ihl + tcp_header_len + payload.len()) as u16;

    let mut pkt = Vec::with_capacity(14 + ip_ihl + tcp_header_len + payload.len());

    // Ethernet header (zeros — bridge fills MACs)
    pkt.extend_from_slice(&[0u8; 12]);
    pkt.extend_from_slice(&[0x08, 0x00]); // IPv4

    // IP header: copy from original, update total_length and checksum
    pkt.extend_from_slice(&raw_ip[..ip_ihl]);
    // Update total length
    pkt[14 + 2] = (ip_total_len >> 8) as u8;
    pkt[14 + 3] = (ip_total_len & 0xff) as u8;
    // Clear checksum
    pkt[14 + 10] = 0;
    pkt[14 + 11] = 0;
    // Recompute IP checksum
    let ip_csum = checksum::ip_checksum(&pkt[14..14 + ip_ihl]);
    pkt[14 + 10] = (ip_csum >> 8) as u8;
    pkt[14 + 11] = (ip_csum & 0xff) as u8;

    // TCP header
    let tcp_start = 14 + ip_ihl;
    let orig_tcp_start = ip_ihl;

    // src port, dst port from original
    pkt.extend_from_slice(&raw_ip[orig_tcp_start..orig_tcp_start + 2]); // src port
    pkt.extend_from_slice(&raw_ip[orig_tcp_start + 2..orig_tcp_start + 4]); // dst port
                                                                            // seq
    pkt.extend_from_slice(&seq.to_be_bytes());
    // ack from original
    pkt.extend_from_slice(&raw_ip[orig_tcp_start + 8..orig_tcp_start + 12]);
    // data offset (5 = 20 bytes) + flags from original
    pkt.push(0x50); // data offset = 5
    pkt.push(raw_ip[orig_tcp_start + 13]); // flags
                                           // window from original
    pkt.extend_from_slice(&raw_ip[orig_tcp_start + 14..orig_tcp_start + 16]);
    // checksum placeholder
    pkt.extend_from_slice(&[0, 0]);
    // urgent pointer
    pkt.extend_from_slice(&[0, 0]);

    // Payload
    pkt.extend_from_slice(payload);

    // TCP checksum
    let src_ip = &pkt[14 + 12..14 + 16];
    let dst_ip = &pkt[14 + 16..14 + 20];
    let tcp_data = &pkt[tcp_start..];
    let tcp_csum = checksum::tcp_checksum(
        src_ip.try_into().unwrap(),
        dst_ip.try_into().unwrap(),
        tcp_data,
    );
    let tcp_csum_offset = tcp_start + 16;
    pkt[tcp_csum_offset] = (tcp_csum >> 8) as u8;
    pkt[tcp_csum_offset + 1] = (tcp_csum & 0xff) as u8;

    pkt
}

/// Send raw IP packet via raw socket (goes through netfilter/NAT).
fn send_raw_ip(ip_packet: &[u8]) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW);
        if fd < 0 {
            return Err(format!("socket(): {}", std::io::Error::last_os_error()));
        }

        let one: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );

        // Mark packet so iptables NFQUEUE rule skips it (mark=0x1337)
        let mark: libc::c_int = 0x1337;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );

        // Destination address from IP header
        let dst_ip = &ip_packet[16..20];
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_addr.s_addr = u32::from_ne_bytes([dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]]);

        let ret = libc::sendto(
            fd,
            ip_packet.as_ptr() as *const libc::c_void,
            ip_packet.len(),
            0,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );

        libc::close(fd);

        if ret < 0 {
            Err(format!("sendto(): {}", std::io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }
}

/// Build first IP fragment: same as original but TCP payload truncated to `split_at` bytes.
fn build_ip_fragment(original_ip: &[u8], split_at: usize) -> Vec<u8> {
    let ip_ihl = (original_ip[0] & 0x0f) as usize * 4;
    let tcp_data_offset_byte = original_ip[ip_ihl + 12];
    let tcp_header_len = ((tcp_data_offset_byte >> 4) as usize) * 4;
    let tcp_start = ip_ihl;
    let payload_start = tcp_start + tcp_header_len;

    // New packet: IP header + TCP header + first `split_at` bytes of payload
    let new_ip_total = ip_ihl + tcp_header_len + split_at;
    let mut pkt = Vec::with_capacity(new_ip_total);
    pkt.extend_from_slice(&original_ip[..payload_start]); // IP + TCP headers
    pkt.extend_from_slice(&original_ip[payload_start..payload_start + split_at]); // truncated payload

    // Update IP total length
    let total_len = new_ip_total as u16;
    pkt[2] = (total_len >> 8) as u8;
    pkt[3] = (total_len & 0xff) as u8;

    // Recompute IP checksum
    pkt[10] = 0;
    pkt[11] = 0;
    let ip_csum = checksum::ip_checksum(&pkt[..ip_ihl]);
    pkt[10] = (ip_csum >> 8) as u8;
    pkt[11] = (ip_csum & 0xff) as u8;

    // Recompute TCP checksum
    let tcp_csum_offset = tcp_start + 16;
    pkt[tcp_csum_offset] = 0;
    pkt[tcp_csum_offset + 1] = 0;
    let src_ip = &pkt[12..16];
    let dst_ip = &pkt[16..20];
    let tcp_csum = checksum::tcp_checksum(
        src_ip.try_into().unwrap(),
        dst_ip.try_into().unwrap(),
        &pkt[tcp_start..],
    );
    pkt[tcp_csum_offset] = (tcp_csum >> 8) as u8;
    pkt[tcp_csum_offset + 1] = (tcp_csum & 0xff) as u8;

    pkt
}

/// Build second IP fragment: same headers, but seq advanced and payload = remainder.
fn build_ip_second_fragment(original_ip: &[u8], split_at: usize, original_seq: u32) -> Vec<u8> {
    let ip_ihl = (original_ip[0] & 0x0f) as usize * 4;
    let tcp_data_offset_byte = original_ip[ip_ihl + 12];
    let tcp_header_len = ((tcp_data_offset_byte >> 4) as usize) * 4;
    let tcp_start = ip_ihl;
    let payload_start = tcp_start + tcp_header_len;
    let remaining_payload = &original_ip[payload_start + split_at..];

    let new_ip_total = ip_ihl + tcp_header_len + remaining_payload.len();
    let mut pkt = Vec::with_capacity(new_ip_total);
    pkt.extend_from_slice(&original_ip[..payload_start]); // IP + TCP headers
    pkt.extend_from_slice(remaining_payload); // remaining payload

    // Update IP total length
    let total_len = new_ip_total as u16;
    pkt[2] = (total_len >> 8) as u8;
    pkt[3] = (total_len & 0xff) as u8;

    // Update TCP seq: advance by split_at
    let new_seq = original_seq.wrapping_add(split_at as u32);
    pkt[tcp_start + 4] = (new_seq >> 24) as u8;
    pkt[tcp_start + 5] = (new_seq >> 16) as u8;
    pkt[tcp_start + 6] = (new_seq >> 8) as u8;
    pkt[tcp_start + 7] = (new_seq & 0xff) as u8;

    // Recompute IP checksum
    pkt[10] = 0;
    pkt[11] = 0;
    let ip_csum = checksum::ip_checksum(&pkt[..ip_ihl]);
    pkt[10] = (ip_csum >> 8) as u8;
    pkt[11] = (ip_csum & 0xff) as u8;

    // Recompute TCP checksum
    let tcp_csum_offset = tcp_start + 16;
    pkt[tcp_csum_offset] = 0;
    pkt[tcp_csum_offset + 1] = 0;
    let src_ip = &pkt[12..16];
    let dst_ip = &pkt[16..20];
    let tcp_csum = checksum::tcp_checksum(
        src_ip.try_into().unwrap(),
        dst_ip.try_into().unwrap(),
        &pkt[tcp_start..],
    );
    pkt[tcp_csum_offset] = (tcp_csum >> 8) as u8;
    pkt[tcp_csum_offset + 1] = (tcp_csum & 0xff) as u8;

    pkt
}

fn parse_ip_tcp(data: &[u8]) -> Option<TcpSegment> {
    if data.len() < 40 {
        return None;
    }
    let version = data[0] >> 4;
    if version != 4 {
        return None;
    }
    let ip_ihl = (data[0] & 0x0f) as usize * 4;
    if data.len() < ip_ihl + 20 {
        return None;
    }
    let protocol = data[9];
    if protocol != 6 {
        return None; // TCP only
    }
    let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    let ttl = data[8];

    TcpSegment::parse(&data[ip_ihl..], src_ip, dst_ip, ttl)
}

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

fn signal_domain(sig: &BlockageSignal) -> String {
    match sig {
        BlockageSignal::RstInjection { sni, .. }
        | BlockageSignal::SilentDrop { sni, .. }
        | BlockageSignal::IpBlackhole { sni, .. }
        | BlockageSignal::FinInjection { sni, .. }
        | BlockageSignal::WindowManipulation { sni, .. }
        | BlockageSignal::ThrottleCliff { sni, .. }
        | BlockageSignal::ThrottleProbabilistic { sni, .. }
        | BlockageSignal::AckDrop { sni, .. } => {
            sni.clone().unwrap_or_else(|| "unknown".to_string())
        }
    }
}

fn signal_flow(sig: &BlockageSignal) -> &Flow {
    match sig {
        BlockageSignal::RstInjection { flow, .. }
        | BlockageSignal::SilentDrop { flow, .. }
        | BlockageSignal::IpBlackhole { flow, .. }
        | BlockageSignal::FinInjection { flow, .. }
        | BlockageSignal::WindowManipulation { flow, .. }
        | BlockageSignal::ThrottleCliff { flow, .. }
        | BlockageSignal::ThrottleProbabilistic { flow, .. }
        | BlockageSignal::AckDrop { flow, .. } => flow,
    }
}

fn extract_sni(tls_data: &[u8]) -> Option<String> {
    if tls_data.len() < 43 {
        return None;
    }
    let mut pos = 43;
    if pos >= tls_data.len() {
        return None;
    }
    pos += 1 + tls_data[pos] as usize;
    if pos + 2 > tls_data.len() {
        return None;
    }
    let cs = u16::from_be_bytes([tls_data[pos], tls_data[pos + 1]]) as usize;
    pos += 2 + cs;
    if pos >= tls_data.len() {
        return None;
    }
    pos += 1 + tls_data[pos] as usize;
    if pos + 2 > tls_data.len() {
        return None;
    }
    let ext = u16::from_be_bytes([tls_data[pos], tls_data[pos + 1]]) as usize;
    pos += 2;
    let end = (pos + ext).min(tls_data.len());
    while pos + 4 <= end {
        let t = u16::from_be_bytes([tls_data[pos], tls_data[pos + 1]]);
        let l = u16::from_be_bytes([tls_data[pos + 2], tls_data[pos + 3]]) as usize;
        pos += 4;
        if t == 0 && l >= 5 && pos + l <= end {
            let d = &tls_data[pos..pos + l];
            if d[2] == 0 {
                let nl = u16::from_be_bytes([d[3], d[4]]) as usize;
                if 5 + nl <= d.len() {
                    return String::from_utf8(d[5..5 + nl].to_vec()).ok();
                }
            }
        }
        pos += l;
    }
    None
}
