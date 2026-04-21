/// Generic fitness function trait.
pub trait FitnessFunction {
    type Observation;
    fn evaluate(&self, before: &Self::Observation, after: &Self::Observation) -> f32;
}

/// Наблюдение RST-детектора за evaluation window.
#[derive(Debug, Clone)]
pub struct RstObservation {
    pub rst_count: u32,
    pub avg_confidence: f32,
}

/// Fitness для RST injection detector.
pub struct RstFitness;

impl FitnessFunction for RstFitness {
    type Observation = RstObservation;

    fn evaluate(&self, before: &RstObservation, after: &RstObservation) -> f32 {
        if before.rst_count == 0 && after.rst_count == 0 {
            return 1.0;
        }
        if before.rst_count > 0 && after.rst_count == 0 {
            return 1.0;
        }
        if before.rst_count == 0 && after.rst_count > 0 {
            return 0.0;
        }
        let count_ratio = 1.0 - (after.rst_count as f32 / before.rst_count as f32).min(1.0);
        let confidence_drop = (before.avg_confidence - after.avg_confidence).max(0.0);
        let fitness = count_ratio * 0.7 + confidence_drop * 0.3;
        fitness.clamp(0.0, 1.0)
    }
}
