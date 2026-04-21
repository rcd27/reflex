use crate::geneva::ga::{GaConfig, Population};
use crate::geneva::strategy::GenevaStrategy;
use crate::types::Flow;

use rand::Rng;

const CLEAN_CONNECTIONS_THRESHOLD: usize = 10;

#[derive(Debug, Clone, PartialEq)]
pub enum DomainMode {
    Clean,
    Blackhole,
    Desync,
}

#[derive(Debug)]
pub enum DomainTransition {
    ActivateBlackhole(Flow),
    AlreadyBlackholed,
    SwitchToDesync(GenevaStrategy),
    DesyncFailed,
    Evolving,
    Noop,
}

pub struct DomainState {
    domain: String,
    mode: DomainMode,
    population: Population,
    clean_connections_count: usize,
    active_strategy: Option<GenevaStrategy>,
}

impl DomainState {
    pub fn new(domain: String, ga_config: GaConfig) -> Self {
        Self {
            domain,
            mode: DomainMode::Clean,
            population: Population {
                individuals: Vec::new(),
                generation: 0,
                config: ga_config,
            },
            clean_connections_count: 0,
            active_strategy: None,
        }
    }

    pub fn mode(&self) -> &DomainMode {
        &self.mode
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn active_strategy(&self) -> Option<&GenevaStrategy> {
        self.active_strategy.as_ref()
    }

    /// Get strategy by population index (for trial evaluation in Blackhole mode).
    pub fn strategy_at(&self, index: usize) -> Option<&GenevaStrategy> {
        self.population.individuals.get(index).map(|i| &i.strategy)
    }

    pub fn population_size(&self) -> usize {
        self.population.individuals.len()
    }

    pub fn on_rst_detected(&mut self, flow: &Flow) -> DomainTransition {
        self.clean_connections_count = 0;
        match self.mode {
            DomainMode::Clean => {
                self.mode = DomainMode::Blackhole;
                self.init_population_if_empty();
                DomainTransition::ActivateBlackhole(flow.clone())
            }
            DomainMode::Blackhole => DomainTransition::AlreadyBlackholed,
            DomainMode::Desync => {
                self.mode = DomainMode::Blackhole;
                self.active_strategy = None;
                DomainTransition::DesyncFailed
            }
        }
    }

    pub fn on_clean_connection(&mut self) {
        if self.mode == DomainMode::Desync {
            self.clean_connections_count += 1;
            if self.clean_connections_count >= CLEAN_CONNECTIONS_THRESHOLD {
                self.mode = DomainMode::Clean;
                self.active_strategy = None;
            }
        }
    }

    pub fn evolve_step(&mut self, rng: &mut impl Rng) -> DomainTransition {
        if self.mode != DomainMode::Blackhole {
            return DomainTransition::Noop;
        }
        self.population.evolve(rng);
        if let Some(best) = self.population.best_above_threshold() {
            let strategy = best.strategy.clone();
            self.mode = DomainMode::Desync;
            self.active_strategy = Some(strategy.clone());
            self.clean_connections_count = 0;
            DomainTransition::SwitchToDesync(strategy)
        } else {
            DomainTransition::Evolving
        }
    }

    pub fn set_individual_fitness(&mut self, index: usize, fitness: f32) {
        if index < self.population.individuals.len() {
            self.population.individuals[index].fitness = fitness;
        }
    }

    fn init_population_if_empty(&mut self) {
        if self.population.individuals.is_empty() {
            let mut rng = rand::rng();
            self.population = Population::seeded(self.population.config.clone(), &mut rng);
        }
    }
}
