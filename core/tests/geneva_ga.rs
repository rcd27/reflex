use rand::rngs::SmallRng;
use rand::SeedableRng;
use reflex_core::geneva::ga::{GaConfig, Individual, Population};
use reflex_core::geneva::random_strategy::RandomStrategyGen;

fn seed_population(seed: u64) -> Population {
    let mut rng = SmallRng::seed_from_u64(seed);
    let gen = RandomStrategyGen { max_depth: 2 };
    let individuals: Vec<Individual> = (0..10)
        .map(|_| Individual {
            strategy: gen.generate(&mut rng),
            fitness: 0.0,
        })
        .collect();
    Population {
        individuals,
        generation: 0,
        config: GaConfig::default(),
    }
}

#[test]
fn population_default_config() {
    let config = GaConfig::default();
    assert_eq!(config.population_size, 20);
    assert_eq!(config.tournament_size, 3);
    assert_eq!(config.elite_count, 2);
}

#[test]
fn tournament_select_returns_best() {
    let mut pop = seed_population(42);
    pop.individuals[5].fitness = 1.0;
    let mut rng = SmallRng::seed_from_u64(99);
    pop.config.tournament_size = 10;
    let selected = pop.tournament_select(&mut rng);
    assert!(selected.fitness >= 0.0);
}

#[test]
fn mutate_produces_valid_strategy() {
    let pop = seed_population(42);
    let original = pop.individuals[0].strategy.clone();
    let mut rng = SmallRng::seed_from_u64(99);
    let mutated = pop.mutate(&original, &mut rng);
    assert!(mutated.tree.node_count() >= 1);
}

#[test]
fn crossover_produces_valid_strategy() {
    let pop = seed_population(42);
    let mut rng = SmallRng::seed_from_u64(99);
    let child = pop.crossover(
        &pop.individuals[0].strategy,
        &pop.individuals[1].strategy,
        &mut rng,
    );
    assert!(child.tree.node_count() >= 1);
    assert!(child.tree.depth() <= 10);
}

#[test]
fn evolve_increments_generation() {
    let mut pop = seed_population(42);
    let mut rng = SmallRng::seed_from_u64(99);
    assert_eq!(pop.generation, 0);
    pop.evolve(&mut rng);
    assert_eq!(pop.generation, 1);
}

#[test]
fn evolve_preserves_elite() {
    let mut pop = seed_population(42);
    pop.individuals[0].fitness = 1.0;
    pop.individuals[1].fitness = 0.9;
    pop.config.elite_count = 2;

    let elite0 = pop.individuals[0].strategy.clone();
    let elite1 = pop.individuals[1].strategy.clone();

    let mut rng = SmallRng::seed_from_u64(99);
    pop.evolve(&mut rng);

    assert!(pop.individuals.iter().any(|i| i.strategy == elite0));
    assert!(pop.individuals.iter().any(|i| i.strategy == elite1));
}

#[test]
fn best_above_threshold_returns_none_when_all_low() {
    let pop = seed_population(42);
    assert!(pop.best_above_threshold().is_none());
}

#[test]
fn best_above_threshold_returns_some() {
    let mut pop = seed_population(42);
    pop.individuals[3].fitness = 0.85;
    let best = pop.best_above_threshold();
    assert!(best.is_some());
    assert_eq!(best.unwrap().fitness, 0.85);
}
