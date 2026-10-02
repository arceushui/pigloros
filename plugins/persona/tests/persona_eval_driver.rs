//! `PersonaEvalDriver` cycles through its preference pairs and emits one
//! Persona-owned prediction source per step (ADR-024 Revision 1 Decision 5).

use pos_core::ids::{EntityId, TimelineId};
use pos_plugin_persona::{
    PersonaEvalDriver, PersonaModel, PredictionOutcomeV1, PredictionSourceV1, PreferencePair,
    EVENT_TYPE_PREDICTION_SOURCE,
};
use pos_runtime::{Driver, ObservationView};

trait TestValueExt<T> {
    fn test_ok(self) -> T;
}

impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected persona error: {error:?}")))
        })
    }
}

fn pair(option_a: &str, prefers_a: bool) -> PreferencePair {
    PreferencePair {
        option_a: option_a.to_owned(),
        option_b: "neutral option".to_owned(),
        prefers_a,
    }
}

#[test]
fn the_driver_cycles_its_pairs_and_emits_one_source_per_step() {
    let entity = EntityId::new();
    let mut driver = PersonaEvalDriver::new(
        entity,
        PersonaModel::new(vec![("quiet".to_owned(), 1.0), ("busy".to_owned(), -1.0)]),
        vec![pair("quiet room", true), pair("busy room", false)],
    );

    let sources: Vec<PredictionSourceV1> = (0..5)
        .map(|_| {
            let output = driver
                .step(TimelineId::new(), ObservationView::empty())
                .test_ok();
            assert_eq!(output.drafts.len(), 2);
            let source = &output.drafts[1];
            assert_eq!(source.event_type.as_str(), EVENT_TYPE_PREDICTION_SOURCE);
            assert_eq!(source.entity, entity);
            ciborium::from_reader(source.payload.as_slice()).test_ok()
        })
        .collect();

    let outcomes: Vec<PredictionOutcomeV1> = sources.iter().map(|source| source.outcome).collect();
    assert_eq!(
        outcomes,
        vec![
            PredictionOutcomeV1::Observed(true),
            PredictionOutcomeV1::Observed(false),
            PredictionOutcomeV1::Observed(true),
            PredictionOutcomeV1::Observed(false),
            PredictionOutcomeV1::Observed(true),
        ]
    );
    let probabilities: Vec<f64> = sources.iter().map(|source| source.predicted_prob).collect();
    assert!((probabilities[0] - 1.0).abs() < f64::EPSILON);
    assert!(probabilities[1].abs() < f64::EPSILON);
    assert!((probabilities[2] - 1.0).abs() < f64::EPSILON);
}
