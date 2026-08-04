use pos_core::{event::Event, ids::EntityId, state::State, TimelineExport};
use pos_plugin_society::SocietyReducer;
use pos_state::ProjectionRegistry;
use ulid::Ulid;

const FIXED_ENTITY_ID: u128 = 2;

/// Stable, cross-target summary of the fixture-backed world projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProjectionDigest {
    pub signals: u64,
    pub trust_mean_bits: u64,
    pub landmark_x_bits: u64,
}

impl ProjectionDigest {
    /// Return the projected landmark coordinate as an `f32` for the renderer.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn landmark_x(self) -> f32 {
        f64::from_bits(self.landmark_x_bits) as f32
    }

    /// Return a deterministic BLAKE3 digest of the canonical field layout.
    #[must_use]
    pub fn digest_bytes(self) -> [u8; 32] {
        let mut bytes = [0u8; 24];
        bytes[0..8].copy_from_slice(&self.signals.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.trust_mean_bits.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.landmark_x_bits.to_le_bytes());
        *blake3::hash(&bytes).as_bytes()
    }
}

/// Fold a complete timeline through the shared society reducer.
///
/// # Errors
/// Returns [`crate::ClientError::Invalid`] when the timeline cannot produce a
/// finite, bounded trust projection for the fixed fixture entity.
pub fn project_fixture(export: &TimelineExport) -> Result<ProjectionDigest, crate::ClientError> {
    let events = sorted_events(&export.events);

    let mut registry = ProjectionRegistry::new();
    registry.register("society", Box::new(SocietyReducer));
    registry.fold_events(&events);

    let entity = EntityId::from_ulid(Ulid::from(FIXED_ENTITY_ID));
    let state = registry
        .state_for_reducer("society", &entity)
        .ok_or_else(|| crate::ClientError::Invalid("missing fixed entity state".to_owned()))?;
    digest_from_state(state)
}

fn sorted_events(events: &[Event]) -> Vec<Event> {
    let mut sorted = events.to_vec();
    sorted.sort_by_key(|event| event.seq.as_u64());
    sorted
}

fn digest_from_state(state: &State) -> Result<ProjectionDigest, crate::ClientError> {
    let signals = state
        .get("signals")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| crate::ClientError::Invalid("missing society signal count".to_owned()))?;
    let trust_mean = state
        .get("mean.trust")
        .and_then(serde_json::Value::as_f64)
        .ok_or_else(|| crate::ClientError::Invalid("missing trust mean".to_owned()))?;
    let landmark_x = trust_mean.mul_add(4.0, -2.0);
    digest_from_values(signals, trust_mean, landmark_x)
}

fn digest_from_values(
    signals: u64,
    trust_mean: f64,
    landmark_x: f64,
) -> Result<ProjectionDigest, crate::ClientError> {
    if !trust_mean.is_finite() || !(0.0..=1.0).contains(&trust_mean) {
        return Err(crate::ClientError::Invalid(
            "trust mean is outside [0, 1]".to_owned(),
        ));
    }
    if !landmark_x.is_finite() {
        return Err(crate::ClientError::Invalid(
            "landmark is not finite".to_owned(),
        ));
    }

    Ok(ProjectionDigest {
        signals,
        trust_mean_bits: trust_mean.to_bits(),
        landmark_x_bits: landmark_x.to_bits(),
    })
}

#[cfg(test)]
mod tests {
    use super::super::{decode_fixture, fixture_bytes, project_fixture};
    use super::{digest_from_state, digest_from_values, sorted_events};
    use crate::ClientError;
    use pos_core::state::State;
    use serde_json::json;

    #[test]
    fn projects_fixture_to_stable_digest() {
        let export = decode_fixture(&fixture_bytes()).unwrap();
        let digest = project_fixture(&export).unwrap();

        assert_eq!(digest.signals, 2);
        assert_eq!(digest.trust_mean_bits, 0.75f64.to_bits());
        assert_eq!(digest.landmark_x_bits, 1.0f64.to_bits());
        assert_eq!(
            digest.digest_bytes(),
            [
                179, 111, 48, 88, 213, 234, 83, 154, 148, 133, 42, 43, 48, 140, 142, 207, 213, 109,
                156, 92, 68, 255, 242, 164, 139, 148, 13, 116, 160, 96, 181, 179,
            ]
        );
        assert_eq!(digest.landmark_x().to_bits(), 1.0f32.to_bits());
        assert!(super::ProjectionDigest {
            signals: 2,
            trust_mean_bits: 0.75f64.to_bits(),
            landmark_x_bits: f64::NAN.to_bits(),
        }
        .landmark_x()
        .is_nan());
    }

    #[test]
    fn projects_events_in_sequence_order() {
        let mut export = decode_fixture(&fixture_bytes()).unwrap();
        export.events.reverse();

        let events = sorted_events(&export.events);
        assert_eq!(events[0].seq.as_u64(), 1);
        assert_eq!(events[1].seq.as_u64(), 2);

        let digest = project_fixture(&export).unwrap();
        assert_eq!(digest.trust_mean_bits, 0.75f64.to_bits());
        assert_eq!(digest.landmark_x_bits, 1.0f64.to_bits());
    }

    #[test]
    fn rejects_missing_fixed_entity_state() {
        let mut export = decode_fixture(&fixture_bytes()).unwrap();
        export.events.clear();

        let error = project_fixture(&export).unwrap_err();

        assert_invalid(error, "missing fixed entity state");
    }

    #[test]
    fn rejects_missing_signals() {
        let error = digest_from_state(&State::new()).unwrap_err();

        assert_invalid(error, "missing society signal count");
    }

    #[test]
    fn rejects_missing_trust_mean() {
        let mut state = State::new();
        state.set("signals", json!(2));

        let error = digest_from_state(&state).unwrap_err();

        assert_invalid(error, "missing trust mean");
    }

    #[test]
    fn rejects_non_numeric_signals() {
        let mut state = State::new();
        state.set("signals", json!("two"));
        state.set("mean.trust", json!(0.75));

        let error = digest_from_state(&state).unwrap_err();

        assert_invalid(error, "missing society signal count");
    }

    #[test]
    fn rejects_non_finite_and_out_of_range_projection_values() {
        for trust_mean in [f64::NAN, -0.1, 1.1] {
            let error = digest_from_values(2, trust_mean, 1.0).unwrap_err();
            assert_invalid(error, "trust mean is outside [0, 1]");
        }

        let error = digest_from_values(2, 0.75, f64::NAN).unwrap_err();
        assert_invalid(error, "landmark is not finite");
    }

    #[test]
    #[should_panic(expected = "expected ClientError::Invalid")]
    fn invalid_assertion_rejects_decode_errors() {
        assert_invalid(
            ClientError::Decode("decode failed".to_owned()),
            "decode failed",
        );
    }

    fn assert_invalid(error: ClientError, expected: &str) {
        match error {
            ClientError::Invalid(message) => assert_eq!(message, expected),
            ClientError::Decode(message) => {
                panic!("expected ClientError::Invalid, got Decode({message})")
            }
        }
    }
}
