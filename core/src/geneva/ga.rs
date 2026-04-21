use rand::{Rng, RngExt};

use crate::geneva::action::{GenevaAction, PacketField, TamperOp};
use crate::geneva::random_strategy::RandomStrategyGen;
use crate::geneva::strategy::{GenevaStrategy, StrategyNode};

#[derive(Debug, Clone)]
pub struct GaConfig {
    pub population_size: usize,
    pub mutation_rate: f32,
    pub crossover_rate: f32,
    pub tournament_size: usize,
    pub elite_count: usize,
    pub max_generations: usize,
    pub fitness_threshold: f32,
}

impl Default for GaConfig {
    fn default() -> Self {
        Self {
            population_size: 20,
            mutation_rate: 0.3,
            crossover_rate: 0.5,
            tournament_size: 3,
            elite_count: 2,
            max_generations: 100,
            fitness_threshold: 0.8,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Individual {
    pub strategy: GenevaStrategy,
    pub fitness: f32,
}

#[derive(Debug, Clone)]
pub struct Population {
    pub individuals: Vec<Individual>,
    pub generation: u32,
    pub config: GaConfig,
}

impl Population {
    pub fn random(config: GaConfig, rng: &mut impl Rng) -> Self {
        let gen = RandomStrategyGen { max_depth: 3 };
        let individuals = (0..config.population_size)
            .map(|_| Individual {
                strategy: gen.generate(rng),
                fitness: 0.0,
            })
            .collect();
        Population {
            individuals,
            generation: 0,
            config,
        }
    }

    pub fn tournament_select(&self, rng: &mut impl Rng) -> &Individual {
        let size = self.config.tournament_size.min(self.individuals.len());
        let mut best: Option<&Individual> = None;
        for _ in 0..size {
            let idx = rng.random_range(0..self.individuals.len());
            let candidate = &self.individuals[idx];
            if best.is_none() || candidate.fitness > best.unwrap().fitness {
                best = Some(candidate);
            }
        }
        best.unwrap()
    }

    pub fn mutate(&self, strategy: &GenevaStrategy, rng: &mut impl Rng) -> GenevaStrategy {
        GenevaStrategy {
            trigger: strategy.trigger.clone(),
            tree: mutate_node(&strategy.tree, rng),
        }
    }

    pub fn crossover(
        &self,
        a: &GenevaStrategy,
        b: &GenevaStrategy,
        rng: &mut impl Rng,
    ) -> GenevaStrategy {
        GenevaStrategy {
            trigger: if rng.random_bool(0.5) {
                a.trigger.clone()
            } else {
                b.trigger.clone()
            },
            tree: crossover_nodes(&a.tree, &b.tree, rng),
        }
    }

    pub fn evolve(&mut self, rng: &mut impl Rng) {
        self.individuals
            .sort_by(|a, b| b.fitness.partial_cmp(&a.fitness).unwrap());

        let mut next_gen: Vec<Individual> = Vec::with_capacity(self.individuals.len());

        // Elitism
        for i in 0..self.config.elite_count.min(self.individuals.len()) {
            next_gen.push(self.individuals[i].clone());
        }

        // Fill rest with offspring
        while next_gen.len() < self.individuals.len() {
            let parent_a = self.tournament_select(rng);
            let parent_b = self.tournament_select(rng);

            let child_strategy = if rng.random_bool(self.config.crossover_rate as f64) {
                self.crossover(&parent_a.strategy.clone(), &parent_b.strategy.clone(), rng)
            } else {
                parent_a.strategy.clone()
            };

            let child_strategy = if rng.random_bool(self.config.mutation_rate as f64) {
                self.mutate(&child_strategy, rng)
            } else {
                child_strategy
            };

            next_gen.push(Individual {
                strategy: child_strategy,
                fitness: 0.0,
            });
        }

        self.individuals = next_gen;
        self.generation += 1;
    }

    pub fn best_above_threshold(&self) -> Option<&Individual> {
        self.individuals
            .iter()
            .filter(|i| i.fitness >= self.config.fitness_threshold)
            .max_by(|a, b| a.fitness.partial_cmp(&b.fitness).unwrap())
    }
}

fn mutate_node(node: &StrategyNode, rng: &mut impl Rng) -> StrategyNode {
    match node {
        StrategyNode::Send => {
            if rng.random_bool(0.3) {
                let gen = RandomStrategyGen { max_depth: 1 };
                gen.generate(rng).tree
            } else {
                StrategyNode::Send
            }
        }
        StrategyNode::Action { action, then } => {
            if rng.random_bool(0.4) {
                StrategyNode::Action {
                    action: mutate_action(action, rng),
                    then: then.clone(),
                }
            } else {
                StrategyNode::Action {
                    action: action.clone(),
                    then: then.iter().map(|n| mutate_node(n, rng)).collect(),
                }
            }
        }
    }
}

fn mutate_action(action: &GenevaAction, rng: &mut impl Rng) -> GenevaAction {
    match action {
        GenevaAction::Tamper { field, .. } => GenevaAction::Tamper {
            field: *field,
            op: if rng.random_bool(0.5) {
                TamperOp::Corrupt
            } else {
                TamperOp::Replace(vec![rng.random_range(1..255u8)])
            },
        },
        GenevaAction::Fragment {
            protocol,
            offset,
            in_order,
        } => GenevaAction::Fragment {
            protocol: *protocol,
            offset: (*offset as i64 + rng.random_range(-4..=4i64)).max(1) as usize,
            in_order: if rng.random_bool(0.3) {
                !in_order
            } else {
                *in_order
            },
        },
        GenevaAction::Duplicate { modify } => GenevaAction::Duplicate {
            modify: if rng.random_bool(0.5) {
                Some(Box::new(GenevaAction::Tamper {
                    field: random_field(rng),
                    op: if rng.random_bool(0.5) {
                        TamperOp::Corrupt
                    } else {
                        TamperOp::Replace(vec![rng.random_range(1..255u8)])
                    },
                }))
            } else {
                modify.clone()
            },
        },
        GenevaAction::Drop => {
            if rng.random_bool(0.5) {
                GenevaAction::Tamper {
                    field: random_field(rng),
                    op: TamperOp::Corrupt,
                }
            } else {
                GenevaAction::Drop
            }
        }
    }
}

fn random_field(rng: &mut impl Rng) -> PacketField {
    match rng.random_range(0..7u8) {
        0 => PacketField::TcpFlags,
        1 => PacketField::IpTtl,
        2 => PacketField::TcpChecksum,
        3 => PacketField::TcpSeq,
        4 => PacketField::TcpAck,
        5 => PacketField::TcpWindow,
        _ => PacketField::TcpOptions,
    }
}

fn crossover_nodes(a: &StrategyNode, b: &StrategyNode, rng: &mut impl Rng) -> StrategyNode {
    if rng.random_bool(0.5) {
        a.clone()
    } else {
        b.clone()
    }
}
