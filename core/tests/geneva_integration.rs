use std::net::{Ipv4Addr, SocketAddr};

use rand::rngs::SmallRng;
use rand::SeedableRng;
use reflex_core::geneva::domain::{DomainMode, DomainState, DomainTransition};
use reflex_core::geneva::executor::execute;
use reflex_core::geneva::fitness::{FitnessFunction, RstFitness, RstObservation};
use reflex_core::geneva::ga::GaConfig;
use reflex_core::types::{Flow, Mac, Protocol, TcpFlags, TcpOptions, TcpSegment};

fn test_flow() -> Flow {
    Flow {
        src: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 12345),
        dst: SocketAddr::new(Ipv4Addr::new(93, 184, 216, 34).into(), 443),
        protocol: Protocol::Tcp,
    }
}

fn test_segment() -> TcpSegment {
    TcpSegment {
        flow: test_flow(),
        seq: 1000,
        ack: 2000,
        flags: TcpFlags::PSH | TcpFlags::ACK,
        window: 65535,
        options: TcpOptions::default(),
        ttl: 64,
        payload: vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00],
    }
}

/// Full Geneva lifecycle:
/// 1. RST detected → Clean → Blackhole
/// 2. GA evolves, one strategy gets high fitness
/// 3. Blackhole → Desync
/// 4. Strategy executes and produces commands
/// 5. RST disappears → clean connections → Desync → Clean
#[test]
fn full_lifecycle_clean_blackhole_desync_clean() {
    let mut rng = SmallRng::seed_from_u64(42);
    let config = GaConfig {
        population_size: 10,
        fitness_threshold: 0.8,
        ..GaConfig::default()
    };
    let mut state = DomainState::new("example.com".to_string(), config);

    // Phase 0: Clean
    assert!(matches!(state.mode(), DomainMode::Clean));

    // Phase 1: RST detected → Blackhole
    let flow = test_flow();
    let transition = state.on_rst_detected(&flow);
    assert!(matches!(transition, DomainTransition::ActivateBlackhole(_)));
    assert!(matches!(state.mode(), DomainMode::Blackhole));

    // Phase 2: Simulate GA finding a strategy
    state.set_individual_fitness(0, 0.9);
    let transition = state.evolve_step(&mut rng);
    assert!(matches!(transition, DomainTransition::SwitchToDesync(_)));
    assert!(matches!(state.mode(), DomainMode::Desync));

    // Phase 3: Active strategy exists and can execute
    let strategy = state.active_strategy().unwrap();
    let seg = test_segment();
    let src_mac = Mac([0; 6]);
    let dst_mac = Mac([0; 6]);
    let _cmds = execute(strategy, &seg, &src_mac, &dst_mac);
    // Strategy should produce some commands (depends on random tree)

    // Phase 4: Fitness evaluation works
    let before = RstObservation {
        rst_count: 3,
        avg_confidence: 0.9,
    };
    let after = RstObservation {
        rst_count: 0,
        avg_confidence: 0.0,
    };
    let fitness = RstFitness.evaluate(&before, &after);
    assert!(fitness > 0.8);

    // Phase 5: Clean connections → Desync → Clean
    for _ in 0..10 {
        state.on_clean_connection();
    }
    assert!(matches!(state.mode(), DomainMode::Clean));
}

/// Strategy failure and recovery:
/// Blackhole → Desync → RST reappears → Blackhole → Evolve again
#[test]
fn desync_failure_recovery() {
    let mut rng = SmallRng::seed_from_u64(42);
    let config = GaConfig {
        population_size: 10,
        fitness_threshold: 0.8,
        ..GaConfig::default()
    };
    let mut state = DomainState::new("blocked.com".to_string(), config);
    let flow = test_flow();

    // RST → Blackhole
    state.on_rst_detected(&flow);
    assert!(matches!(state.mode(), DomainMode::Blackhole));

    // GA finds strategy → Desync
    state.set_individual_fitness(0, 0.9);
    state.evolve_step(&mut rng);
    assert!(matches!(state.mode(), DomainMode::Desync));

    // Strategy fails: RST reappears → back to Blackhole
    let transition = state.on_rst_detected(&flow);
    assert!(matches!(transition, DomainTransition::DesyncFailed));
    assert!(matches!(state.mode(), DomainMode::Blackhole));

    // GA continues evolving
    state.set_individual_fitness(1, 0.85);
    let transition = state.evolve_step(&mut rng);
    assert!(matches!(transition, DomainTransition::SwitchToDesync(_)));
    assert!(matches!(state.mode(), DomainMode::Desync));
}
