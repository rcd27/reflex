use std::net::{Ipv4Addr, SocketAddr};

use rand::rngs::SmallRng;
use rand::SeedableRng;
use reflex_core::geneva::domain::{DomainMode, DomainState, DomainTransition};
use reflex_core::geneva::ga::GaConfig;
use reflex_core::types::{Flow, Protocol};

fn test_flow() -> Flow {
    Flow {
        src: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 12345),
        dst: SocketAddr::new(Ipv4Addr::new(93, 184, 216, 34).into(), 443),
        protocol: Protocol::Tcp,
    }
}

#[test]
fn starts_clean() {
    let state = DomainState::new("example.com".to_string(), GaConfig::default());
    assert!(matches!(state.mode(), DomainMode::Clean));
}

#[test]
fn clean_to_blackhole_on_rst_detected() {
    let mut state = DomainState::new("example.com".to_string(), GaConfig::default());
    let flow = test_flow();
    let transition = state.on_rst_detected(&flow);
    assert!(matches!(transition, DomainTransition::ActivateBlackhole(_)));
    assert!(matches!(state.mode(), DomainMode::Blackhole));
}

#[test]
fn blackhole_stays_blackhole_on_more_rst() {
    let mut state = DomainState::new("example.com".to_string(), GaConfig::default());
    let flow = test_flow();
    state.on_rst_detected(&flow);
    let transition = state.on_rst_detected(&flow);
    assert!(matches!(transition, DomainTransition::AlreadyBlackholed));
}

#[test]
fn blackhole_to_desync_when_ga_finds_strategy() {
    let mut state = DomainState::new("example.com".to_string(), GaConfig::default());
    let flow = test_flow();
    state.on_rst_detected(&flow);
    let mut rng = SmallRng::seed_from_u64(42);
    state.set_individual_fitness(0, 0.9);
    let transition = state.evolve_step(&mut rng);
    assert!(matches!(transition, DomainTransition::SwitchToDesync(_)));
    assert!(matches!(state.mode(), DomainMode::Desync));
}

#[test]
fn desync_back_to_blackhole_on_failure() {
    let mut state = DomainState::new("example.com".to_string(), GaConfig::default());
    let flow = test_flow();
    state.on_rst_detected(&flow);
    let mut rng = SmallRng::seed_from_u64(42);
    state.set_individual_fitness(0, 0.9);
    state.evolve_step(&mut rng);
    let transition = state.on_rst_detected(&flow);
    assert!(matches!(transition, DomainTransition::DesyncFailed));
    assert!(matches!(state.mode(), DomainMode::Blackhole));
}

#[test]
fn desync_to_clean_when_no_rst() {
    let mut state = DomainState::new("example.com".to_string(), GaConfig::default());
    let flow = test_flow();
    state.on_rst_detected(&flow);
    let mut rng = SmallRng::seed_from_u64(42);
    state.set_individual_fitness(0, 0.9);
    state.evolve_step(&mut rng);
    for _ in 0..10 {
        state.on_clean_connection();
    }
    assert!(matches!(state.mode(), DomainMode::Clean));
}
