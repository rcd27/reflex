use rand::rngs::SmallRng;
use rand::SeedableRng;
use reflex_core::geneva::random_strategy::RandomStrategyGen;
use reflex_core::geneva::StrategyNode;

#[test]
fn generates_valid_strategy() {
    let mut rng = SmallRng::seed_from_u64(42);
    let gen = RandomStrategyGen { max_depth: 3 };
    let strategy = gen.generate(&mut rng);
    assert!(strategy.tree.depth() <= 3);
    assert!(strategy.tree.node_count() >= 1);
}

#[test]
fn deterministic_with_same_seed() {
    let mut rng1 = SmallRng::seed_from_u64(123);
    let mut rng2 = SmallRng::seed_from_u64(123);
    let gen = RandomStrategyGen { max_depth: 2 };
    let s1 = gen.generate(&mut rng1);
    let s2 = gen.generate(&mut rng2);
    assert_eq!(s1, s2);
}

#[test]
fn different_seeds_different_strategies() {
    let mut rng1 = SmallRng::seed_from_u64(1);
    let mut rng2 = SmallRng::seed_from_u64(2);
    let gen = RandomStrategyGen { max_depth: 3 };
    let s1 = gen.generate(&mut rng1);
    let s2 = gen.generate(&mut rng2);
    assert_ne!(s1, s2);
}

#[test]
fn max_depth_zero_produces_send() {
    let mut rng = SmallRng::seed_from_u64(42);
    let gen = RandomStrategyGen { max_depth: 0 };
    let strategy = gen.generate(&mut rng);
    assert!(matches!(strategy.tree, StrategyNode::Send));
}

#[test]
fn generates_population() {
    let mut rng = SmallRng::seed_from_u64(42);
    let gen = RandomStrategyGen { max_depth: 3 };
    let population: Vec<_> = (0..20).map(|_| gen.generate(&mut rng)).collect();
    assert_eq!(population.len(), 20);
    let first = &population[0];
    let any_different = population.iter().any(|s| s != first);
    assert!(any_different);
}
