use pos_core::{ids::EntityId, TimelineExport};
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
    pub fn landmark_x(self) -> f32 {
        f64::from_bits(self.landmark_x_bits)
            .to_string()
            .parse()
            .unwrap_or_default()
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
    let mut events = export.events.clone();
    events.sort_by_key(|event| event.seq.as_u64());

    let mut registry = ProjectionRegistry::new();
    registry.register("society", Box::new(SocietyReducer));
    registry.fold_events(&events);

    let entity = EntityId::from_ulid(Ulid::from(FIXED_ENTITY_ID));
    let state = registry
        .state_for_reducer("society", &entity)
        .ok_or_else(|| crate::ClientError::Invalid("missing fixed entity state".to_owned()))?;
    let signals = state
        .get("signals")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| crate::ClientError::Invalid("missing society signal count".to_owned()))?;
    let trust_mean = state
        .get("mean.trust")
        .and_then(serde_json::Value::as_f64)
        .ok_or_else(|| crate::ClientError::Invalid("missing trust mean".to_owned()))?;
    if !trust_mean.is_finite() || !(0.0..=1.0).contains(&trust_mean) {
        return Err(crate::ClientError::Invalid(
            "trust mean is outside [0, 1]".to_owned(),
        ));
    }
    let landmark_x = trust_mean.mul_add(4.0, -2.0);
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
    }
}
