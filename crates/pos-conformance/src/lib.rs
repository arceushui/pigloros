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
use std::collections::{BTreeMap, BTreeSet};

/// Version of the first independent proof-evidence envelope.
pub const EVIDENCE_FORMAT_V1: u32 = 1;

/// The reproducibility claim made by a proof artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReproducibilityClassV1 {
    /// Fold committed history without executing Drivers.
    RecordedReplay,
    /// Recompute from the complete frozen input closure.
    ProfileRecomputation,
    /// Compare two named profiles against one expected fixture.
    CrossProfileConformance,
    /// A live run with no deterministic-future claim.
    LiveUnverified,
}

/// The replay claim that survives the available evidence and erasure state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayClaimV1 {
    Exact,
    ExactAuthoritativeWithRedactedViews,
    StructuralOnly,
    UnverifiableArtifactsMissing,
    IncompatibleProfile,
}

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
        if self.resource_limit < 3 || self.resource_limit > 10_000 {
            return Err(InputError::ResourceLimitOutOfRange);
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
    #[error("resource_limit must be between 3 and 10000")]
    ResourceLimitOutOfRange,
    #[error("network access must be disabled for an air-gapped execution")]
    NetworkNotAllowedInAirGapped,
    #[error("network access must be disabled for deterministic recomputation")]
    NetworkNotAllowedInDeterministicProfile,
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
    pub dependency_class: String,
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
    pub visible_events: Vec<ParticipantEventV1>,
}

/// One committed Event materialized in a participant's knowledge view.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipantEventV1 {
    pub seq: u64,
    pub event_type: String,
    pub payload_digest: [u8; 32],
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
    pub revocation_event_seq: u64,
    pub revocation_event_type: String,
    pub revocation_payload_digest: [u8; 32],
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
    pub reproducibility_class: ReproducibilityClassV1,
    pub execution_profile: String,
    pub execution_profile_digest: [u8; 32],
    pub trust_policy_snapshot_digest: [u8; 32],
    pub artifact_closure_digest: [u8; 32],
    pub evaluator_digest: [u8; 32],
    pub replay_claim: ReplayClaimV1,
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

    /// Export the complete evidence envelope as deterministic canonical CBOR.
    ///
    /// The bytes are suitable for hashing, durable fixture storage, and
    /// consumption by an evaluator that does not link the experiment host.
    ///
    /// # Errors
    /// Returns a canonical-CBOR serialization error when the envelope cannot
    /// be represented by the shared crypto codec.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, pos_core::CoreError> {
        pos_crypto::canonical::encode(self).map(|bytes| bytes.as_slice().to_vec())
    }

    /// Import an evidence envelope from deterministic canonical CBOR.
    ///
    /// # Errors
    /// Returns a serialization error when the bytes are malformed or the
    /// envelope does not satisfy the typed schema.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, pos_core::CoreError> {
        pos_crypto::canonical::decode(&pos_core::CanonicalBytes::from_vec(bytes.to_vec()))
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
        && left.manifest.reproducibility_class == right.manifest.reproducibility_class
        && left.manifest.execution_profile == right.manifest.execution_profile
        && left.manifest.execution_profile_digest == right.manifest.execution_profile_digest
        && left.manifest.trust_policy_snapshot_digest
            == right.manifest.trust_policy_snapshot_digest
        && left.manifest.artifact_closure_digest == right.manifest.artifact_closure_digest
        && left.manifest.evaluator_digest == right.manifest.evaluator_digest
        && left.manifest.replay_claim == right.manifest.replay_claim
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
    verify_manifest(&evidence.manifest)?;
    let sequences = event_sequences(&evidence.authoritative_events)?;
    verify_causal_trace(
        &evidence.authoritative_events,
        &evidence.causal_trace,
        &sequences,
    )?;
    verify_uncertainty(&evidence.uncertainty)?;
    verify_participant_views(
        &evidence.participant_views,
        &evidence.authoritative_events,
        &sequences,
    )?;
    verify_plugin_failures(&evidence.plugin_failures)?;
    verify_consent_audit(&evidence.consent_audit)?;
    Ok(())
}

fn verify_manifest(manifest: &ReproManifestV1) -> Result<(), EvidenceError> {
    if manifest.execution_profile.trim().is_empty()
        || manifest.execution_profile_digest == [0; 32]
        || manifest.trust_policy_snapshot_digest == [0; 32]
        || manifest.artifact_closure_digest == [0; 32]
        || manifest.evaluator_digest == [0; 32]
        || manifest.resource_limit == 0
        || manifest.plugin_versions.is_empty()
        || manifest
            .plugin_versions
            .iter()
            .any(|(name, version)| name.trim().is_empty() || version.trim().is_empty())
        || (matches!(manifest.execution_mode, ExecutionModeV1::AirGapped)
            && manifest.network_enabled)
    {
        Err(EvidenceError::InvalidManifest)
    } else {
        Ok(())
    }
}

fn event_sequences(events: &[AuthoritativeEventV1]) -> Result<BTreeSet<u64>, EvidenceError> {
    let mut previous_seq: Option<u64> = None;
    events
        .iter()
        .map(|event| {
            if previous_seq.is_some_and(|previous| event.seq != previous.saturating_add(1)) {
                return Err(EvidenceError::NonContiguousEventSequence);
            }
            previous_seq = Some(event.seq);
            Ok(event.seq)
        })
        .collect()
}

fn verify_causal_trace(
    events: &[AuthoritativeEventV1],
    trace: &[CausalTraceEntryV1],
    sequences: &BTreeSet<u64>,
) -> Result<(), EvidenceError> {
    if events.iter().any(|event| {
        event.causation_seq.is_some_and(|cause_seq| {
            cause_seq >= event.seq
                || !sequences.contains(&cause_seq)
                || !sequences.contains(&event.seq)
        })
    }) {
        return Err(EvidenceError::InvalidCausalEdge);
    }
    if trace.iter().any(|edge| {
        edge.cause_seq >= edge.effect_seq
            || !sequences.contains(&edge.cause_seq)
            || !sequences.contains(&edge.effect_seq)
            || !matches!(
                edge.relation.as_str(),
                "physical_to_agent" | "agent_to_society" | "intervention_to_physics" | "derived"
            )
            || !matches!(
                edge.visibility.as_str(),
                "operator" | "participant" | "public"
            )
            || !matches!(
                edge.dependency_class.as_str(),
                "exogenous_frozen"
                    | "intervention_assigned"
                    | "endogenous_recomputed"
                    | "fixed_policy"
                    | "presentation_only"
            )
    }) {
        return Err(EvidenceError::InvalidCausalEdge);
    }
    let authoritative_edges = events
        .iter()
        .filter_map(|event| event.causation_seq.map(|cause| (cause, event.seq)))
        .collect::<BTreeSet<_>>();
    let traced_edges = trace
        .iter()
        .map(|edge| (edge.cause_seq, edge.effect_seq))
        .collect::<BTreeSet<_>>();
    if authoritative_edges == traced_edges {
        Ok(())
    } else {
        Err(EvidenceError::IncompleteCausalTrace)
    }
}

fn verify_uncertainty(claims: &[UncertaintyV1]) -> Result<(), EvidenceError> {
    if claims.iter().any(|claim| {
        !claim.lower.is_finite()
            || !claim.upper.is_finite()
            || !claim.confidence.is_finite()
            || claim.lower > claim.upper
            || !(0.0..=1.0).contains(&claim.lower)
            || !(0.0..=1.0).contains(&claim.upper)
            || !(0.0..=1.0).contains(&claim.confidence)
    }) {
        Err(EvidenceError::InvalidUncertainty)
    } else {
        Ok(())
    }
}

fn verify_plugin_failures(failures: &[PluginFailureV1]) -> Result<(), EvidenceError> {
    if failures.iter().any(|failure| failure.committed) {
        Err(EvidenceError::CommittedPluginFailure)
    } else {
        Ok(())
    }
}

fn verify_consent_audit(audit: &ConsentAuditV1) -> Result<(), EvidenceError> {
    if audit.subject.trim().is_empty()
        || audit.revocation_event_type != "pos.host.consent.revoked.v1"
        || audit.revocation_payload_digest == [0; 32]
        || audit.effective_after_seq < audit.requested_after_seq
        || audit.revocation_event_seq != audit.effective_after_seq
        || !audit.halted_at_tick_boundary
    {
        Err(EvidenceError::InvalidConsentAudit)
    } else {
        Ok(())
    }
}

fn verify_participant_views(
    views: &[ParticipantViewV1],
    authoritative_events: &[AuthoritativeEventV1],
    sequences: &BTreeSet<u64>,
) -> Result<(), EvidenceError> {
    if views.is_empty() {
        return Err(EvidenceError::InvalidParticipantView);
    }
    let mut participants = BTreeSet::new();
    for view in views {
        if !participants.insert(view.participant.as_str())
            || view.visible_event_types.iter().any(|event_type| {
                view.visible_event_types
                    .iter()
                    .filter(|candidate| *candidate == event_type)
                    .count()
                    > 1
            })
            || view.hidden_event_types.iter().any(|event_type| {
                view.hidden_event_types
                    .iter()
                    .filter(|candidate| *candidate == event_type)
                    .count()
                    > 1
            })
        {
            return Err(EvidenceError::InvalidParticipantView);
        }
        if view
            .visible_event_types
            .iter()
            .any(|event_type| view.hidden_event_types.contains(event_type))
        {
            return Err(EvidenceError::InvalidParticipantView);
        }
        for event in &view.visible_events {
            if !view.visible_event_types.contains(&event.event_type)
                || view.hidden_event_types.contains(&event.event_type)
                || !sequences.contains(&event.seq)
            {
                return Err(EvidenceError::InvalidParticipantView);
            }
            let authoritative = authoritative_events
                .iter()
                .find(|candidate| candidate.seq == event.seq)
                .expect("visible event sequence is authoritative");
            if authoritative.event_type != event.event_type
                || authoritative.payload_digest != event.payload_digest
            {
                return Err(EvidenceError::InvalidParticipantView);
            }
        }
        for authoritative in authoritative_events {
            let classified =
                usize::from(view.visible_event_types.contains(&authoritative.event_type))
                    + usize::from(view.hidden_event_types.contains(&authoritative.event_type));
            if classified != 1 {
                return Err(EvidenceError::InvalidParticipantView);
            }
            let visible = view
                .visible_events
                .iter()
                .filter(|event| event.seq == authoritative.seq)
                .count();
            if view.visible_event_types.contains(&authoritative.event_type) && visible != 1 {
                return Err(EvidenceError::InvalidParticipantView);
            }
        }
        if view
            .visible_events
            .windows(2)
            .any(|pair| pair[0].seq >= pair[1].seq)
        {
            return Err(EvidenceError::InvalidParticipantView);
        }
    }
    Ok(())
}

/// Independently verify that a counterfactual contains a recomputed causal
/// suffix after the shared Fork prefix.
///
/// The verifier does not know the host's Timeline implementation. It checks
/// only the portable Event summaries: equal prefix, a post-cut intervention,
/// and a causal path from that intervention to a complete downstream causal
/// tail. Events before the tail may be tick-delayed observations of the
/// unchanged prefix; once the intervention's effects reach the endogenous
/// frontier, every later Event must remain connected to it.
///
/// # Errors
/// Returns [`EvidenceError::IncompleteForkSuffix`] when the artifacts do not
/// establish a shared prefix, intervention, or complete causal tail.
pub fn verify_counterfactual_fork(
    baseline: &MoatProofEvidenceV1,
    counterfactual: &MoatProofEvidenceV1,
    intervention_event_type: &str,
) -> Result<(), EvidenceError> {
    verify_evidence(baseline)?;
    verify_evidence(counterfactual)?;
    if baseline.manifest.input_digest != counterfactual.manifest.input_digest
        || baseline.manifest.fork_cut_seq != counterfactual.manifest.fork_cut_seq
    {
        return Err(EvidenceError::IncompleteForkSuffix);
    }
    let Some(cut) = counterfactual.manifest.fork_cut_seq else {
        return Err(EvidenceError::IncompleteForkSuffix);
    };
    let prefix = |events: &[AuthoritativeEventV1]| {
        events
            .iter()
            .filter(|event| event.seq <= cut)
            .cloned()
            .collect::<Vec<_>>()
    };
    if prefix(&baseline.authoritative_events) != prefix(&counterfactual.authoritative_events) {
        return Err(EvidenceError::IncompleteForkSuffix);
    }
    let baseline_suffix = baseline
        .authoritative_events
        .iter()
        .filter(|event| event.seq > cut)
        .collect::<Vec<_>>();
    let counterfactual_suffix = counterfactual
        .authoritative_events
        .iter()
        .filter(|event| event.seq > cut)
        .collect::<Vec<_>>();
    if baseline_suffix.is_empty() || counterfactual_suffix.len() < 2 {
        return Err(EvidenceError::IncompleteForkSuffix);
    }
    let Some(intervention) = counterfactual_suffix
        .iter()
        .find(|event| event.event_type == intervention_event_type)
    else {
        return Err(EvidenceError::IncompleteForkSuffix);
    };
    let intervention_seq = intervention.seq;
    let by_seq = counterfactual
        .authoritative_events
        .iter()
        .map(|event| (event.seq, event))
        .collect::<BTreeMap<_, _>>();
    let complete_endogenous_suffix = counterfactual_suffix
        .iter()
        .filter(|event| event.seq > intervention_seq)
        .find(|candidate| {
            let tail = counterfactual_suffix
                .iter()
                .filter(|event| event.seq >= candidate.seq)
                .collect::<Vec<_>>();
            !tail.is_empty()
                && tail
                    .iter()
                    .all(|event| event_reaches_intervention(event, intervention_seq, &by_seq))
        });
    if complete_endogenous_suffix.is_none() || baseline_suffix == counterfactual_suffix {
        return Err(EvidenceError::IncompleteForkSuffix);
    }
    Ok(())
}

fn event_reaches_intervention(
    event: &AuthoritativeEventV1,
    intervention_seq: u64,
    by_seq: &BTreeMap<u64, &AuthoritativeEventV1>,
) -> bool {
    let mut current = event;
    loop {
        if current.seq == intervention_seq {
            return true;
        }
        let Some(cause_seq) = current.causation_seq else {
            return false;
        };
        let cause = by_seq[&cause_seq];
        current = cause;
    }
}

/// Independent evidence validation failure.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EvidenceError {
    #[error("unsupported evidence format")]
    UnsupportedFormat,
    #[error("input digest is missing")]
    MissingInputDigest,
    #[error("reproducibility manifest is incomplete or incompatible")]
    InvalidManifest,
    #[error("authoritative event sequence is not contiguous")]
    NonContiguousEventSequence,
    #[error("causal edge does not reference an earlier and present event")]
    InvalidCausalEdge,
    #[error("causal trace does not exactly materialize authoritative causation")]
    IncompleteCausalTrace,
    #[error("uncertainty interval is invalid")]
    InvalidUncertainty,
    #[error("participant knowledge view contains an invalid or mismatched Event")]
    InvalidParticipantView,
    #[error("plugin failure was marked committed")]
    CommittedPluginFailure,
    #[error("consent revocation was not effective at a tick boundary")]
    InvalidConsentAudit,
    #[error("counterfactual Fork suffix is missing, copied, or causally incomplete")]
    IncompleteForkSuffix,
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

    type EvidenceMutation = Box<dyn Fn(&mut MoatProofEvidenceV1)>;

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
                reproducibility_class: ReproducibilityClassV1::ProfileRecomputation,
                execution_profile: "deterministic-v1".to_owned(),
                execution_profile_digest: [3; 32],
                trust_policy_snapshot_digest: [4; 32],
                artifact_closure_digest: [5; 32],
                evaluator_digest: [6; 32],
                replay_claim: ReplayClaimV1::Exact,
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
                dependency_class: "endogenous_recomputed".to_owned(),
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
                hidden_event_types: vec![
                    "private.note".to_owned(),
                    "proof.agent.reaction.v1".to_owned(),
                ],
                visible_events: vec![ParticipantEventV1 {
                    seq: 1,
                    event_type: "world.observation.v1".to_owned(),
                    payload_digest: [1; 32],
                }],
            }],
            plugin_failures: Vec::new(),
            consent_audit: ConsentAuditV1 {
                subject: "subject".to_owned(),
                requested_after_seq: 1,
                effective_after_seq: 1,
                revocation_event_seq: 1,
                revocation_event_type: "pos.host.consent.revoked.v1".to_owned(),
                revocation_payload_digest: [7; 32],
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
        value = input();
        value.ticks = 10_001;
        assert_eq!(value.validate(), Err(InputError::TicksOutOfRange));
        value = input();
        value.initial_velocity[1] = f64::INFINITY;
        assert_eq!(value.validate(), Err(InputError::NonFiniteCoordinate));
        value = input();
        value.agent_response_threshold = f64::NAN;
        assert_eq!(value.validate(), Err(InputError::ThresholdOutOfRange));
        value = input();
        value.resource_limit = 2;
        assert_eq!(value.validate(), Err(InputError::ResourceLimitOutOfRange));
        value = input();
        value.resource_limit = 10_001;
        assert_eq!(value.validate(), Err(InputError::ResourceLimitOutOfRange));
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
    fn verifier_rejects_unclassified_events_and_unbound_trace_edges() {
        let valid = evidence();
        let mut invalid = valid.clone();
        invalid.causal_trace.clear();
        assert_eq!(
            verify_evidence(&invalid),
            Err(EvidenceError::IncompleteCausalTrace)
        );

        let mut invalid = valid.clone();
        invalid.causal_trace[0].dependency_class = "secret_reasoning".to_owned();
        assert_eq!(
            verify_evidence(&invalid),
            Err(EvidenceError::InvalidCausalEdge)
        );

        let mut invalid = valid.clone();
        invalid.participant_views[0].hidden_event_types.pop();
        assert_eq!(
            verify_evidence(&invalid),
            Err(EvidenceError::InvalidParticipantView)
        );

        let mut invalid = valid;
        invalid.consent_audit.revocation_payload_digest = [0; 32];
        assert_eq!(
            verify_evidence(&invalid),
            Err(EvidenceError::InvalidConsentAudit)
        );
    }

    #[test]
    fn verifier_rejects_incomplete_manifest_before_event_checks() {
        let mut invalid = evidence();
        invalid.manifest.evaluator_digest = [0; 32];
        assert_eq!(
            verify_evidence(&invalid),
            Err(EvidenceError::InvalidManifest)
        );
    }

    #[test]
    fn verifier_rejects_each_manifest_contract_violation() {
        let cases: Vec<EvidenceMutation> = vec![
            Box::new(|value| value.manifest.execution_profile.clear()),
            Box::new(|value| value.manifest.execution_profile_digest = [0; 32]),
            Box::new(|value| value.manifest.trust_policy_snapshot_digest = [0; 32]),
            Box::new(|value| value.manifest.artifact_closure_digest = [0; 32]),
            Box::new(|value| value.manifest.evaluator_digest = [0; 32]),
            Box::new(|value| value.manifest.resource_limit = 0),
            Box::new(|value| value.manifest.plugin_versions.clear()),
            Box::new(|value| {
                value
                    .manifest
                    .plugin_versions
                    .insert(String::new(), "1".to_owned());
            }),
            Box::new(|value| {
                value
                    .manifest
                    .plugin_versions
                    .insert("world".to_owned(), String::new());
            }),
            Box::new(|value| {
                value.manifest.execution_mode = ExecutionModeV1::AirGapped;
                value.manifest.network_enabled = true;
            }),
        ];
        for mutate in cases {
            let mut invalid = evidence();
            mutate(&mut invalid);
            assert_eq!(
                verify_evidence(&invalid),
                Err(EvidenceError::InvalidManifest)
            );
        }
    }

    #[test]
    fn verifier_rejects_each_causal_edge_shape() {
        let cases: Vec<EvidenceMutation> = vec![
            Box::new(|value| value.authoritative_events[1].causation_seq = Some(2)),
            Box::new(|value| value.authoritative_events[1].causation_seq = Some(99)),
            Box::new(|value| value.causal_trace[0].cause_seq = 2),
            Box::new(|value| value.causal_trace[0].cause_seq = 99),
            Box::new(|value| value.causal_trace[0].relation = "other".to_owned()),
            Box::new(|value| value.causal_trace[0].visibility = "secret".to_owned()),
        ];
        for mutate in cases {
            let mut invalid = evidence();
            mutate(&mut invalid);
            assert_eq!(
                verify_evidence(&invalid),
                Err(EvidenceError::InvalidCausalEdge)
            );
        }
    }

    #[test]
    fn verifier_rejects_uncertainty_and_participant_boundaries() {
        let uncertainty_cases: Vec<EvidenceMutation> = vec![
            Box::new(|value| value.uncertainty[0].lower = -0.1),
            Box::new(|value| value.uncertainty[0].upper = 1.1),
            Box::new(|value| value.uncertainty[0].confidence = f64::NAN),
        ];
        for mutate in uncertainty_cases {
            let mut invalid = evidence();
            mutate(&mut invalid);
            assert_eq!(
                verify_evidence(&invalid),
                Err(EvidenceError::InvalidUncertainty)
            );
        }

        let participant_cases: Vec<EvidenceMutation> = vec![
            Box::new(|value| value.participant_views.clear()),
            Box::new(|value| {
                let view = value.participant_views[0].clone();
                value.participant_views.push(view);
            }),
            Box::new(|value| {
                value.participant_views[0]
                    .visible_event_types
                    .push("world.observation.v1".to_owned());
            }),
            Box::new(|value| {
                value.participant_views[0]
                    .hidden_event_types
                    .push("proof.agent.reaction.v1".to_owned());
            }),
            Box::new(|value| {
                value.participant_views[0]
                    .visible_event_types
                    .push("proof.agent.reaction.v1".to_owned());
            }),
            Box::new(|value| {
                value.participant_views[0].visible_events[0].event_type = "wrong".to_owned();
            }),
            Box::new(|value| value.participant_views[0].visible_events[0].payload_digest = [8; 32]),
            Box::new(|value| value.participant_views[0].visible_events[0].seq = 99),
            Box::new(|value| value.participant_views[0].visible_events.clear()),
        ];
        for mutate in participant_cases {
            let mut invalid = evidence();
            mutate(&mut invalid);
            assert_eq!(
                verify_evidence(&invalid),
                Err(EvidenceError::InvalidParticipantView)
            );
        }

        let mut invalid = evidence();
        invalid.participant_views[0].hidden_event_types[0] = "world.observation.v1".to_owned();
        assert_eq!(
            verify_evidence(&invalid),
            Err(EvidenceError::InvalidParticipantView)
        );

        let mut invalid = evidence();
        invalid.participant_views[0]
            .visible_event_types
            .push("proof.agent.reaction.v1".to_owned());
        invalid.participant_views[0]
            .hidden_event_types
            .retain(|event_type| event_type != "proof.agent.reaction.v1");
        invalid.participant_views[0]
            .visible_events
            .push(ParticipantEventV1 {
                seq: 2,
                event_type: "proof.agent.reaction.v1".to_owned(),
                payload_digest: [2; 32],
            });
        invalid.participant_views[0].visible_events.reverse();
        assert_eq!(
            verify_evidence(&invalid),
            Err(EvidenceError::InvalidParticipantView)
        );
    }

    #[test]
    fn verifier_rejects_each_consent_boundary() {
        let cases: Vec<Box<dyn Fn(&mut MoatProofEvidenceV1)>> = vec![
            Box::new(|value| value.consent_audit.subject.clear()),
            Box::new(|value| value.consent_audit.revocation_event_type = "other".to_owned()),
            Box::new(|value| value.consent_audit.effective_after_seq = 0),
            Box::new(|value| value.consent_audit.revocation_event_seq = 2),
            Box::new(|value| value.consent_audit.halted_at_tick_boundary = false),
        ];
        for mutate in cases {
            let mut invalid = evidence();
            mutate(&mut invalid);
            assert_eq!(
                verify_evidence(&invalid),
                Err(EvidenceError::InvalidConsentAudit)
            );
        }
    }

    fn fork_pair() -> (MoatProofEvidenceV1, MoatProofEvidenceV1) {
        let mut baseline = evidence();
        baseline.manifest.fork_cut_seq = Some(1);
        baseline.authoritative_events[1].event_type = "proof.agent.reaction.v1".to_owned();
        baseline.authoritative_events.push(AuthoritativeEventV1 {
            seq: 3,
            entity: "society".to_owned(),
            event_type: "society.signal".to_owned(),
            payload_digest: [3; 32],
            causation_seq: Some(2),
        });
        baseline.causal_trace.push(CausalTraceEntryV1 {
            cause_seq: 2,
            effect_seq: 3,
            relation: "agent_to_society".to_owned(),
            visibility: "public".to_owned(),
            dependency_class: "endogenous_recomputed".to_owned(),
        });
        baseline.participant_views[0]
            .hidden_event_types
            .push("society.signal".to_owned());
        let mut counterfactual = baseline.clone();
        counterfactual.authoritative_events[1].event_type = "world.action.v1".to_owned();
        counterfactual.authoritative_events[1].payload_digest = [4; 32];
        counterfactual.causal_trace[0].relation = "intervention_to_physics".to_owned();
        counterfactual.participant_views[0].hidden_event_types[1] = "world.action.v1".to_owned();
        (baseline, counterfactual)
    }

    #[test]
    fn verifies_and_rejects_counterfactual_fork_boundaries() {
        let (baseline, counterfactual) = fork_pair();
        assert_eq!(
            verify_counterfactual_fork(&baseline, &counterfactual, "world.action.v1"),
            Ok(())
        );

        let mut no_cut_baseline = baseline.clone();
        let mut no_cut_counterfactual = counterfactual.clone();
        no_cut_baseline.manifest.fork_cut_seq = None;
        no_cut_counterfactual.manifest.fork_cut_seq = None;
        assert_eq!(
            verify_counterfactual_fork(&no_cut_baseline, &no_cut_counterfactual, "world.action.v1"),
            Err(EvidenceError::IncompleteForkSuffix)
        );

        let short_baseline = evidence();
        let short_counterfactual = evidence();
        assert_eq!(
            verify_counterfactual_fork(&short_baseline, &short_counterfactual, "world.action.v1"),
            Err(EvidenceError::IncompleteForkSuffix)
        );
        let mut one_event_counterfactual = counterfactual.clone();
        one_event_counterfactual.authoritative_events.pop();
        one_event_counterfactual.causal_trace.pop();
        assert_eq!(
            verify_counterfactual_fork(&baseline, &one_event_counterfactual, "world.action.v1"),
            Err(EvidenceError::IncompleteForkSuffix)
        );

        let mut invalid = counterfactual.clone();
        invalid.manifest.input_digest[0] ^= 1;
        assert_eq!(
            verify_counterfactual_fork(&baseline, &invalid, "world.action.v1"),
            Err(EvidenceError::IncompleteForkSuffix)
        );
        let mut invalid = counterfactual.clone();
        invalid.manifest.fork_cut_seq = None;
        assert_eq!(
            verify_counterfactual_fork(&baseline, &invalid, "world.action.v1"),
            Err(EvidenceError::IncompleteForkSuffix)
        );
        let mut invalid = counterfactual.clone();
        invalid.authoritative_events[0].payload_digest = [9; 32];
        invalid.participant_views[0].visible_events[0].payload_digest = [9; 32];
        assert_eq!(
            verify_counterfactual_fork(&baseline, &invalid, "world.action.v1"),
            Err(EvidenceError::IncompleteForkSuffix)
        );
        let mut invalid = counterfactual.clone();
        invalid.authoritative_events[1].event_type = "proof.agent.reaction.v1".to_owned();
        invalid.participant_views[0].hidden_event_types[1] = "proof.agent.reaction.v1".to_owned();
        assert_eq!(
            verify_counterfactual_fork(&baseline, &invalid, "world.action.v1"),
            Err(EvidenceError::IncompleteForkSuffix)
        );
        let mut invalid = counterfactual.clone();
        invalid.authoritative_events[2].causation_seq = Some(1);
        invalid.causal_trace[1].cause_seq = 1;
        assert_eq!(
            verify_counterfactual_fork(&baseline, &invalid, "world.action.v1"),
            Err(EvidenceError::IncompleteForkSuffix)
        );
        let invalid = baseline.clone();
        assert_eq!(
            verify_counterfactual_fork(&baseline, &invalid, "proof.agent.reaction.v1"),
            Err(EvidenceError::IncompleteForkSuffix)
        );
    }

    #[test]
    fn serializes_and_formats_digest() {
        let value = evidence();
        let json = value.to_json().unwrap();
        assert!(json.contains("world.observation.v1"));
        assert_eq!(MoatProofEvidenceV1::from_json(&json).unwrap(), value);
        let cbor = value.to_canonical_cbor().unwrap();
        assert_eq!(
            MoatProofEvidenceV1::from_canonical_cbor(&cbor).unwrap(),
            value
        );
        assert_eq!(hex_digest(&value.digest()).len(), 64);
    }
}
