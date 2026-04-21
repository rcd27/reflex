use reflex_core::geneva::fitness::{FitnessFunction, RstFitness, RstObservation};

#[test]
fn rst_disappeared_high_fitness() {
    let before = RstObservation {
        rst_count: 3,
        avg_confidence: 0.9,
    };
    let after = RstObservation {
        rst_count: 0,
        avg_confidence: 0.0,
    };
    let fitness = RstFitness.evaluate(&before, &after);
    assert!(fitness > 0.8, "fitness={fitness}, expected > 0.8");
}

#[test]
fn rst_remained_low_fitness() {
    let before = RstObservation {
        rst_count: 3,
        avg_confidence: 0.9,
    };
    let after = RstObservation {
        rst_count: 3,
        avg_confidence: 0.9,
    };
    let fitness = RstFitness.evaluate(&before, &after);
    assert!(fitness < 0.2, "fitness={fitness}, expected < 0.2");
}

#[test]
fn rst_reduced_medium_fitness() {
    let before = RstObservation {
        rst_count: 5,
        avg_confidence: 0.9,
    };
    let after = RstObservation {
        rst_count: 1,
        avg_confidence: 0.4,
    };
    let fitness = RstFitness.evaluate(&before, &after);
    assert!(
        fitness > 0.3 && fitness < 0.8,
        "fitness={fitness}, expected 0.3..0.8"
    );
}

#[test]
fn no_rst_before_or_after() {
    let before = RstObservation {
        rst_count: 0,
        avg_confidence: 0.0,
    };
    let after = RstObservation {
        rst_count: 0,
        avg_confidence: 0.0,
    };
    let fitness = RstFitness.evaluate(&before, &after);
    assert!(fitness >= 0.9, "fitness={fitness}, no RST at all = clean");
}

#[test]
fn connection_broken_negative_fitness() {
    let before = RstObservation {
        rst_count: 1,
        avg_confidence: 0.8,
    };
    let after = RstObservation {
        rst_count: 0,
        avg_confidence: 0.0,
    };
    let fitness = RstFitness.evaluate(&before, &after);
    assert!(fitness > 0.5);
}

#[test]
fn fitness_is_bounded() {
    let cases = vec![
        (
            RstObservation {
                rst_count: 100,
                avg_confidence: 1.0,
            },
            RstObservation {
                rst_count: 0,
                avg_confidence: 0.0,
            },
        ),
        (
            RstObservation {
                rst_count: 0,
                avg_confidence: 0.0,
            },
            RstObservation {
                rst_count: 100,
                avg_confidence: 1.0,
            },
        ),
    ];
    for (before, after) in cases {
        let fitness = RstFitness.evaluate(&before, &after);
        assert!(
            fitness >= 0.0 && fitness <= 1.0,
            "fitness={fitness} out of bounds"
        );
    }
}
