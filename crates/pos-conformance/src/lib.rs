#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! Dependency-light Wave 8 conformance evidence.
//!
//! This crate deliberately does not depend on the experiment host or any
//! plugin. A second implementation can deserialize the JSON representation,
//! compare authoritative evidence, and classify a divergence without
//! importing the implementation under test.
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

use blake3::Hash;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Version of the first independent proof-evidence envelope.
pub const EVIDENCE_FORMAT_V1: u32 = 1;

/// Execution profile used by a proof run.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionModeV1 {
    /// In-process local execution.
    Local,
    /// Air-gapped execution with the same deterministic inputs and limits.
    AirGapped,
}

/// User-authored, declarative input for the Wave 8 proof kernel.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MoatProofInputV1 {
    pub scenario_id: String,
    pub ticks: u64,
    pub initial_position: [f64; 2],
    pub initial_velocity: [f64; 2],
    pub agent_response_threshold: f64,
    pub fork_velocity: [f64; 2],
    pub random_seed: u64,
    pub resource_limit: u64,
    pub network_enabled: bool,
}

impl MoatProofInputV1 {
    /// Validate the bounded input contract before any host state is created.
    ///
    /// # Errors
    /// Returns a stable reason for each rejected shape.
    pub fn validate(&self) -> Result<(), InputError> {
        if self.scenario_id.trim().is_empty() {
            return Err(InputError::EmptyScenarioId);
        }
        if self.ticks == 0 || self.ticks > 10_000 {
            return Err(InputError::TicksOutOfRange);
        }
        if !self
            .initial_position
            .iter()
            .chain(self.initial_velocity.iter())
            .chain(self.fork_velocity.iter())
            .all(|value| value.is_finite())
        {
            return Err(InputError::NonFiniteCoordinate);
        }
        if !self.agent_response_threshold.is_finite()
            || !(0.0..=1.0).contains(&self.agent_response_threshold)
        {
            return Err(InputError::ThresholdOutOfRange);
        }
        if self.resource_limit == 0 {
            return Err(InputError::ZeroResourceLimit);
        }
        Ok(())
    }

    /// Return a domain-separated digest of the exact input envelope.
    ///
    /// # Panics
    /// Panics only if the statically serializable input type cannot be encoded.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes = serde_json::to_vec(self).expect("input serialization is infallible");
        *blake3::hash(
            &[b'P', b'I', b'1', 0]
                .into_iter()
                .chain(bytes)
                .collect::<Vec<_>>(),
        )
        .as_bytes()
    }
}

/// Input validation failure.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InputError {
    #[error("scenario_id must not be empty")]
    EmptyScenarioId,
    #[error("ticks must be between 1 and 10000")]
    TicksOutOfRange,
    #[error("coordinates and velocities must be finite")]
    NonFiniteCoordinate,
    #[error("agent_response_threshold must be finite and between 0 and 1")]
    ThresholdOutOfRange,
    #[error("resource_limit must be greater than zero")]
    ZeroResourceLimit,
    #[error("network access must be disabled for an air-gapped execution")]
    NetworkNotAllowedInAirGapped,
}

/// Canonical event evidence; generated Event IDs and wall-clock metadata are
/// intentionally excluded so independent stores can compare authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeEventV1 {
    pub seq: u64,
    pub entity: String,
    pub event_type: String,
    pub payload_digest: [u8; 32],
    pub causation_seq: Option<u64>,
}

/// One projection state at the evidence boundary.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionEvidenceV1 {
    pub reducer: String,
    pub entity: String,
    pub state: serde_json::Value,
}

/// One causal edge visible to an evaluator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CausalTraceEntryV1 {
    pub cause_seq: u64,
    pub effect_seq: u64,
    pub relation: String,
    pub visibility: String,
}

/// An uncertainty claim attached to a result rather than hidden in prose.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UncertaintyV1 {
    pub label: String,
    pub lower: f64,
    pub upper: f64,
    pub confidence: f64,
}

/// Participant-scoped observation evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipantViewV1 {
    pub participant: String,
    pub visible_event_types: Vec<String>,
    pub hidden_event_types: Vec<String>,
}

/// Deterministic Plugin failure evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginFailureV1 {
    pub plugin: String,
    pub class: String,
    pub tick: u64,
    pub committed: bool,
}

/// Auditable consent revocation at a completed Tick Boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentAuditV1 {
    pub subject: String,
    pub requested_after_seq: u64,
    pub effective_after_seq: u64,
    pub halted_at_tick_boundary: bool,
}

/// Reproduction metadata pinned by every proof artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReproManifestV1 {
    pub format_version: u32,
    pub input_digest: [u8; 32],
    pub execution_mode: ExecutionModeV1,
    pub fork_cut_seq: Option<u64>,
    pub seed: u64,
    pub resource_limit: u64,
    pub network_enabled: bool,
    pub plugin_versions: BTreeMap<String, String>,
}

/// Complete, portable Wave 8 proof evidence.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MoatProofEvidenceV1 {
    pub format_version: u32,
    pub manifest: ReproManifestV1,
    pub authoritative_events: Vec<AuthoritativeEventV1>,
    pub projections: Vec<ProjectionEvidenceV1>,
    pub causal_trace: Vec<CausalTraceEntryV1>,
    pub uncertainty: Vec<UncertaintyV1>,
    pub participant_views: Vec<ParticipantViewV1>,
    pub plugin_failures: Vec<PluginFailureV1>,
    pub consent_audit: ConsentAuditV1,
}

impl MoatProofEvidenceV1 {
    /// Serialize to the portable evidence envelope.
    ///
    /// # Errors
    /// Returns a JSON serialization error if the envelope cannot be encoded.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize the portable evidence envelope.
    ///
    /// # Errors
    /// Returns a JSON deserialization error when the envelope is malformed or
    /// uses an unknown field.
    pub fn from_json(value: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(value)
    }

    /// Return the canonical digest of this evidence envelope.
    ///
    /// # Panics
    /// Panics only if the statically serializable evidence type cannot be encoded.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes = serde_json::to_vec(self).expect("evidence serialization is infallible");
        *blake3::hash(
            &[b'E', b'V', b'1', 0]
                .into_iter()
                .chain(bytes)
                .collect::<Vec<_>>(),
        )
        .as_bytes()
    }
}

/// Result of comparing two independent proof artifacts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DivergenceClassV1 {
    None,
    AuthoritativeEvents,
    Projections,
    CausalTrace,
    Observability,
    Metadata,
}

/// Independent comparison result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComparisonV1 {
    pub equal: bool,
    pub divergence: DivergenceClassV1,
    pub left_digest: [u8; 32],
    pub right_digest: [u8; 32],
}

/// Compare the authoritative and derived portions of two proof artifacts.
#[must_use]
pub fn compare(left: &MoatProofEvidenceV1, right: &MoatProofEvidenceV1) -> ComparisonV1 {
    let manifests_match = left.manifest.format_version == right.manifest.format_version
        && left.manifest.input_digest == right.manifest.input_digest
        && left.manifest.fork_cut_seq == right.manifest.fork_cut_seq
        && left.manifest.seed == right.manifest.seed
        && left.manifest.resource_limit == right.manifest.resource_limit
        && left.manifest.network_enabled == right.manifest.network_enabled
        && left.manifest.plugin_versions == right.manifest.plugin_versions;
    let divergence = if !manifests_match {
        DivergenceClassV1::Metadata
    } else if left.authoritative_events != right.authoritative_events {
        DivergenceClassV1::AuthoritativeEvents
    } else if left.projections != right.projections {
        DivergenceClassV1::Projections
    } else if left.causal_trace != right.causal_trace {
        DivergenceClassV1::CausalTrace
    } else if left.uncertainty != right.uncertainty
        || left.participant_views != right.participant_views
        || left.plugin_failures != right.plugin_failures
        || left.consent_audit != right.consent_audit
    {
        DivergenceClassV1::Observability
    } else {
        DivergenceClassV1::None
    };
    ComparisonV1 {
        equal: divergence == DivergenceClassV1::None,
        divergence,
        left_digest: left.digest(),
        right_digest: right.digest(),
    }
}

/// Validate the invariants an independent evaluator can check without the
/// simulation host or any privileged plugin implementation.
///
/// # Errors
/// Returns the first violated evidence invariant.
pub fn verify_evidence(evidence: &MoatProofEvidenceV1) -> Result<(), EvidenceError> {
    if evidence.format_version != EVIDENCE_FORMAT_V1
        || evidence.manifest.format_version != EVIDENCE_FORMAT_V1
    {
        return Err(EvidenceError::UnsupportedFormat);
    }
    if evidence.manifest.input_digest == [0; 32] {
        return Err(EvidenceError::MissingInputDigest);
    }
    let mut previous_seq: Option<u64> = None;
    let sequences = evidence
        .authoritative_events
        .iter()
        .map(|event| {
            if let Some(previous) = previous_seq {
                if event.seq != previous.saturating_add(1) {
                    return Err(EvidenceError::NonContiguousEventSequence);
                }
            }
            previous_seq = Some(event.seq);
            Ok(event.seq)
        })
        .collect::<Result<std::collections::BTreeSet<_>, EvidenceError>>()?;
    for event in &evidence.authoritative_events {
        if let Some(cause_seq) = event.causation_seq {
            if cause_seq >= event.seq
                || !sequences.contains(&cause_seq)
                || !sequences.contains(&event.seq)
            {
                return Err(EvidenceError::InvalidCausalEdge);
            }
        }
    }
    for edge in &evidence.causal_trace {
        if edge.cause_seq >= edge.effect_seq
            || !sequences.contains(&edge.cause_seq)
            || !sequences.contains(&edge.effect_seq)
        {
            return Err(EvidenceError::InvalidCausalEdge);
        }
    }
    for claim in &evidence.uncertainty {
        if !claim.lower.is_finite()
            || !claim.upper.is_finite()
            || !claim.confidence.is_finite()
            || claim.lower > claim.upper
            || !(0.0..=1.0).contains(&claim.lower)
            || !(0.0..=1.0).contains(&claim.upper)
            || !(0.0..=1.0).contains(&claim.confidence)
        {
            return Err(EvidenceError::InvalidUncertainty);
        }
    }
    if evidence
        .plugin_failures
        .iter()
        .any(|failure| failure.committed)
    {
        return Err(EvidenceError::CommittedPluginFailure);
    }
    if evidence.consent_audit.effective_after_seq != evidence.consent_audit.requested_after_seq
        || !evidence.consent_audit.halted_at_tick_boundary
    {
        return Err(EvidenceError::InvalidConsentAudit);
    }
    Ok(())
}

/// Independent evidence validation failure.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EvidenceError {
    #[error("unsupported evidence format")]
    UnsupportedFormat,
    #[error("input digest is missing")]
    MissingInputDigest,
    #[error("authoritative event sequence is not contiguous")]
    NonContiguousEventSequence,
    #[error("causal edge does not reference an earlier and present event")]
    InvalidCausalEdge,
    #[error("uncertainty interval is invalid")]
    InvalidUncertainty,
    #[error("plugin failure was marked committed")]
    CommittedPluginFailure,
    #[error("consent revocation was not effective at a tick boundary")]
    InvalidConsentAudit,
}

/// Return a hex digest for human-facing evidence reports.
#[must_use]
pub fn hex_digest(bytes: &[u8; 32]) -> String {
    let hash = Hash::from_bytes(*bytes);
    hash.to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> MoatProofInputV1 {
        MoatProofInputV1 {
            scenario_id: "parameterized".to_owned(),
            ticks: 3,
            initial_position: [0.0, 0.0],
            initial_velocity: [1.0, 0.0],
            agent_response_threshold: 0.5,
            fork_velocity: [2.0, 0.0],
            random_seed: 7,
            resource_limit: 100,
            network_enabled: false,
        }
    }

    fn evidence() -> MoatProofEvidenceV1 {
        let input = input();
        MoatProofEvidenceV1 {
            format_version: EVIDENCE_FORMAT_V1,
            manifest: ReproManifestV1 {
                format_version: EVIDENCE_FORMAT_V1,
                input_digest: input.digest(),
                execution_mode: ExecutionModeV1::Local,
                fork_cut_seq: Some(2),
                seed: input.random_seed,
                resource_limit: input.resource_limit,
                network_enabled: input.network_enabled,
                plugin_versions: BTreeMap::from([("world".to_owned(), "1".to_owned())]),
            },
            authoritative_events: vec![
                AuthoritativeEventV1 {
                    seq: 1,
                    entity: "body".to_owned(),
                    event_type: "world.observation.v1".to_owned(),
                    payload_digest: [1; 32],
                    causation_seq: None,
                },
                AuthoritativeEventV1 {
                    seq: 2,
                    entity: "agent".to_owned(),
                    event_type: "proof.agent.reaction.v1".to_owned(),
                    payload_digest: [2; 32],
                    causation_seq: Some(1),
                },
            ],
            projections: vec![ProjectionEvidenceV1 {
                reducer: "world".to_owned(),
                entity: "body".to_owned(),
                state: serde_json::json!({"x": 1}),
            }],
            causal_trace: vec![CausalTraceEntryV1 {
                cause_seq: 1,
                effect_seq: 2,
                relation: "physical_to_agent".to_owned(),
                visibility: "operator".to_owned(),
            }],
            uncertainty: vec![UncertaintyV1 {
                label: "agent_confidence".to_owned(),
                lower: 0.4,
                upper: 0.6,
                confidence: 0.9,
            }],
            participant_views: vec![ParticipantViewV1 {
                participant: "operator".to_owned(),
                visible_event_types: vec!["world.observation.v1".to_owned()],
                hidden_event_types: vec!["private.note".to_owned()],
            }],
            plugin_failures: Vec::new(),
            consent_audit: ConsentAuditV1 {
                subject: "subject".to_owned(),
                requested_after_seq: 1,
                effective_after_seq: 1,
                halted_at_tick_boundary: true,
            },
        }
    }

    #[test]
    fn validates_parameterized_input_and_hashes_it() {
        let value = input();
        assert!(value.validate().is_ok());
        assert_ne!(value.digest(), {
            let mut changed = value.clone();
            changed.random_seed += 1;
            changed.digest()
        });
    }

    #[test]
    fn rejects_invalid_input_shapes() {
        let mut value = input();
        value.scenario_id.clear();
        assert_eq!(value.validate(), Err(InputError::EmptyScenarioId));
        value = input();
        value.ticks = 0;
        assert_eq!(value.validate(), Err(InputError::TicksOutOfRange));
        value = input();
        value.initial_position[0] = f64::NAN;
        assert_eq!(value.validate(), Err(InputError::NonFiniteCoordinate));
        value = input();
        value.agent_response_threshold = 2.0;
        assert_eq!(value.validate(), Err(InputError::ThresholdOutOfRange));
        value = input();
        value.resource_limit = 0;
        assert_eq!(value.validate(), Err(InputError::ZeroResourceLimit));
    }

    #[test]
    fn compares_equal_and_classifies_event_divergence() {
        let left = evidence();
        let mut right = left.clone();
        assert_eq!(compare(&left, &right).divergence, DivergenceClassV1::None);
        right.authoritative_events[0].payload_digest = [2; 32];
        let comparison = compare(&left, &right);
        assert!(!comparison.equal);
        assert_eq!(
            comparison.divergence,
            DivergenceClassV1::AuthoritativeEvents
        );
        assert_ne!(comparison.left_digest, comparison.right_digest);
    }

    #[test]
    fn compares_metadata_projection_and_trace_divergence() {
        let left = evidence();
        let mut right = left.clone();
        right.manifest.seed += 1;
        assert_eq!(
            compare(&left, &right).divergence,
            DivergenceClassV1::Metadata
        );
        right = left.clone();
        right.projections[0].state = serde_json::json!({"x": 2});
        assert_eq!(
            compare(&left, &right).divergence,
            DivergenceClassV1::Projections
        );
        right = left;
        right.causal_trace[0].effect_seq += 1;
        assert_eq!(
            compare(&evidence(), &right).divergence,
            DivergenceClassV1::CausalTrace
        );
    }

    #[test]
    fn compares_observability_divergence() {
        let left = evidence();
        let mut right = left.clone();
        right.uncertainty[0].confidence = 0.8;
        assert_eq!(
            compare(&left, &right).divergence,
            DivergenceClassV1::Observability
        );
        right = left.clone();
        right.participant_views[0].hidden_event_types.clear();
        assert_eq!(
            compare(&left, &right).divergence,
            DivergenceClassV1::Observability
        );
        right = left.clone();
        right.plugin_failures.push(PluginFailureV1 {
            plugin: "plugin".to_owned(),
            class: "crash".to_owned(),
            tick: 1,
            committed: false,
        });
        assert_eq!(
            compare(&left, &right).divergence,
            DivergenceClassV1::Observability
        );
        right = left;
        right.consent_audit.halted_at_tick_boundary = false;
        assert_eq!(
            compare(&evidence(), &right).divergence,
            DivergenceClassV1::Observability
        );
    }

    #[test]
    fn independent_verifier_accepts_and_rejects_evidence() {
        let valid = evidence();
        assert_eq!(verify_evidence(&valid), Ok(()));

        let mut invalid = valid.clone();
        invalid.format_version += 1;
        assert_eq!(
            verify_evidence(&invalid),
            Err(EvidenceError::UnsupportedFormat)
        );
        let mut invalid = valid.clone();
        invalid.manifest.input_digest = [0; 32];
        assert_eq!(
            verify_evidence(&invalid),
            Err(EvidenceError::MissingInputDigest)
        );
        let mut invalid = valid.clone();
        invalid.authoritative_events[0].seq = 2;
        invalid.authoritative_events.push(AuthoritativeEventV1 {
            seq: 4,
            entity: "body".to_owned(),
            event_type: "world.observation.v1".to_owned(),
            payload_digest: [2; 32],
            causation_seq: None,
        });
        assert_eq!(
            verify_evidence(&invalid),
            Err(EvidenceError::NonContiguousEventSequence)
        );
        let mut invalid = valid.clone();
        invalid.causal_trace[0].cause_seq = 2;
        assert_eq!(
            verify_evidence(&invalid),
            Err(EvidenceError::InvalidCausalEdge)
        );
        let mut invalid = valid.clone();
        invalid.uncertainty[0].lower = 1.0;
        assert_eq!(
            verify_evidence(&invalid),
            Err(EvidenceError::InvalidUncertainty)
        );
        let mut invalid = valid.clone();
        invalid.plugin_failures.push(PluginFailureV1 {
            plugin: "plugin".to_owned(),
            class: "crash".to_owned(),
            tick: 1,
            committed: true,
        });
        assert_eq!(
            verify_evidence(&invalid),
            Err(EvidenceError::CommittedPluginFailure)
        );
        let mut invalid = valid;
        invalid.consent_audit.halted_at_tick_boundary = false;
        assert_eq!(
            verify_evidence(&invalid),
            Err(EvidenceError::InvalidConsentAudit)
        );
    }

    #[test]
    fn serializes_and_formats_digest() {
        let value = evidence();
        let json = value.to_json().unwrap();
        assert!(json.contains("world.observation.v1"));
        assert_eq!(MoatProofEvidenceV1::from_json(&json).unwrap(), value);
        assert_eq!(hex_digest(&value.digest()).len(), 64);
    }
}
