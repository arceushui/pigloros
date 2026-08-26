#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! Dependency-light Wave 8 conformance evidence.
//!
//! This crate deliberately does not depend on the experiment host or any
//! plugin. A second implementation can deserialize the JSON representation,
//! compare authoritative evidence, and classify a divergence without
//! importing the implementation under test.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use blake3::Hash;
use ciborium::value::Value;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

mod bundle_contract;
mod profile_contract;

pub use bundle_contract::{
    verify_archive_independently, BundleContractErrorV1, BundleExpectedResultV1, BundleManifestV1,
    BundleMemberDescriptorV1, BundleMemberRoleV1, BundleMemberV1, BundleModeV1,
    ConformanceBundlePairV1, ConformanceBundleV1, CONFORMANCE_BUNDLE_MAGIC_V1,
    MAX_CONFORMANCE_BUNDLE_BYTES_V1,
};
#[doc(hidden)]
pub use profile_contract::expected_result_bytes;
pub use profile_contract::{
    AllowedDivergenceV1, CapabilityPolicyV1, ConformanceContractError, ConformanceProfileV1,
    EvaluatorHardCapsV1, EvaluatorOutputCapabilityV1, EvaluatorProtocolV1, EvaluatorRequestV1,
    ExpectedResultV1, FixtureBoundsV1, FixtureDescriptorV1, FixtureInputMemberV1,
    FixtureProvenanceV1, IndependenceRequirementsV1, ProfileLifecycleV1,
    StableEvidenceAttestationV1, StableImplementationEvidenceV1, SubjectAdapterKindV1,
    TrustedRootPolicyV1, CONFORMANCE_PROFILE_MAGIC_V1, EVALUATOR_REQUEST_MAGIC_V1,
};

/// Version of the first independent proof-evidence envelope.
pub const EVIDENCE_FORMAT_V1: u32 = 1;
/// Magic for the portable verification/replay record envelope.
pub const VERIFICATION_RECORD_MAGIC_V1: &str = "VRR1";
/// Magic for the full Wave 8 evidence bundle carried alongside `VRR1`.
pub const EVIDENCE_ENVELOPE_MAGIC_V1: &str = "W8E1";
/// Magic for a deterministic divergence/conformance record.
pub const DIVERGENCE_RECORD_MAGIC_V1: &str = "DVR1";
/// Magic for the recomputation-frontier record.
pub const RECOMPUTATION_FRONTIER_MAGIC_V1: &str = "RCF1";
/// Magic for the suffix-invalidation record.
pub const SUFFIX_INVALIDATION_MAGIC_V1: &str = "SIV1";
/// Magic for the conformance report record.
pub const CONFORMANCE_REPORT_MAGIC_V1: &str = "CNR1";

/// Stable numeric schema identifiers used by the Wave 8 fixture contract.
///
/// Schema identity is a bounded `u32`; the human-readable
/// event type remains an explanatory label in the JSON projection. Unknown
/// labels are assigned from a domain-separated digest so an evaluator never
/// has to parse a free-form schema name as protocol identity.
#[must_use]
pub fn schema_id_for_event_type(event_type: &str) -> u32 {
    match event_type {
        "scenario.input.v1" => 1,
        "world.action.v1" => 100,
        "world.observation.v1" => 101,
        "proof.agent.reaction.v1" => 200,
        "society.signal" => 300,
        "consent.revoked.v1" => 400,
        _ => {
            let mut input = Vec::with_capacity(33 + event_type.len());
            input.extend_from_slice(b"PiglorOS.EventSchemaId.v1\0");
            input.extend_from_slice(event_type.as_bytes());
            let digest = blake3::hash(&input);
            u32::from_be_bytes(digest.as_bytes()[..4].try_into().unwrap_or([0; 4])).max(1)
        }
    }
}

#[cfg(test)]
mod coverage_entrypoints {
    use super::*;

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn expect_err<T, E: std::fmt::Debug>(value: &Result<T, E>) {
        if value.is_ok() {
            std::panic::resume_unwind(Box::new("expected a rejected coverage value"));
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn encode_value(value: &ciborium::Value) -> Vec<u8> {
        let mut bytes = Vec::new();
        ciborium::into_writer(value, &mut bytes).unwrap_or_default();
        bytes
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn decode_value(bytes: Vec<u8>) -> ciborium::Value {
        ciborium::from_reader(std::io::Cursor::new(bytes)).unwrap_or(ciborium::Value::Null)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn replace_field(
        value: ciborium::Value,
        index: usize,
        replacement: ciborium::Value,
    ) -> ciborium::Value {
        let mut fields = match value {
            ciborium::Value::Array(fields) => fields,
            _ => Vec::new(),
        };
        fields[index] = replacement;
        ciborium::Value::Array(fields)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn replace_nested_field(
        value: ciborium::Value,
        outer: usize,
        inner: usize,
        replacement: ciborium::Value,
    ) -> ciborium::Value {
        let mut fields = match value {
            ciborium::Value::Array(fields) => fields,
            _ => Vec::new(),
        };
        let nested = fields.remove(outer);
        fields.insert(outer, replace_field(nested, inner, replacement));
        ciborium::Value::Array(fields)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn replace_evidence_case_coordinate(
        evidence: &ciborium::Value,
        coordinate: ciborium::Value,
    ) -> ciborium::Value {
        let mut evidence_fields = evidence.as_array().map_or_else(Vec::new, Clone::clone);
        let mut contract_fields = evidence_fields[10]
            .as_array()
            .map_or_else(Vec::new, Clone::clone);
        let mut report_fields = contract_fields[6]
            .as_array()
            .map_or_else(Vec::new, Clone::clone);
        let mut cases = report_fields[13]
            .as_array()
            .map_or_else(Vec::new, Clone::clone);
        let mut case = cases[0].as_array().map_or_else(Vec::new, Clone::clone);
        case[6] = coordinate;
        cases[0] = ciborium::Value::Array(case);
        report_fields[13] = ciborium::Value::Array(cases);
        contract_fields[6] = ciborium::Value::Array(report_fields);
        evidence_fields[10] = ciborium::Value::Array(contract_fields);
        ciborium::Value::Array(evidence_fields)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn ok<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected coverage error: {error:?}")))
        })
    }

    #[test]
    fn exported_record_entrypoints_are_exercised_from_an_instrumented_test() {
        let boundary = wave8_plugin_boundary();
        assert_eq!(boundary.validate(), Ok(()));

        let mut invalid_boundary = boundary.clone();
        invalid_boundary.manifest_digest = [1; 32];
        assert_eq!(
            invalid_boundary.validate(),
            Err(PluginBoundaryError::ManifestDigestMismatch)
        );
        invalid_boundary.manifest_digest = boundary.manifest_digest;
        invalid_boundary.release_digest = [1; 32];
        assert_eq!(
            invalid_boundary.validate(),
            Err(PluginBoundaryError::ReleaseDigestMismatch)
        );

        let evidence = tests::evidence();
        assert!(evidence.digest().is_ok());
        let evidence_bytes = evidence.to_canonical_cbor();
        assert!(evidence_bytes.is_ok());
        let verification = evidence.to_verification_result();
        assert!(verification.is_ok());
        let verification = verification.map(|result| {
            assert!(result.digest().is_ok());
            result.to_canonical_cbor()
        });
        assert!(verification.is_ok());

        let mut report = DivergenceReportV1 {
            request_digest: [1; 32],
            manifest_digest: [2; 32],
            execution_profile_digest: [3; 32],
            fixture_digest: Some([4; 32]),
            evaluator_digest: [5; 32],
            reproducibility_class: ReproducibilityClassV1::ProfileRecomputation,
            replay_claim: ReplayClaimV1::Exact,
            location_kind: DivergenceLocationKindV1::TimelineSeq,
            timeline_or_worldcut_id: [6; 16],
            timeline_seq_or_cut_ordinal: 7,
            tick: 8,
            scheduler_position: Some(9),
            driver_or_plugin_id: Some("world".to_owned()),
            output_ordinal: Some(10),
            mismatch_kind: DivergenceMismatchKindV1::CanonicalBytes,
            expected: DigestSizeV1 {
                digest: Some([11; 32]),
                size: Some(12),
            },
            actual: DigestSizeV1 {
                digest: Some([13; 32]),
                size: Some(14),
            },
            prior_matching_checkpoint_digest: Some([15; 32]),
            follow_on_counts: vec![FollowOnMismatchV1 {
                kind: DivergenceMismatchKindV1::Artifact,
                count: 1,
            }],
            report_digest: [0; 32],
        };
        report.report_digest = report.digest().unwrap_or([0; 32]);
        let report_bytes = report.to_canonical_cbor();
        assert!(report_bytes.is_ok());
        assert!(DivergenceReportV1::from_canonical_cbor(&report_bytes.unwrap_or_default()).is_ok());
    }

    #[test]
    fn malformed_canonical_records_reach_closed_decoder_boundaries() {
        let evidence = tests::evidence();
        expect_err(&strict_codec::decode_evidence(&encode_value(
            &ciborium::Value::Map(Vec::new()),
        )));
        let mut invalid_closure = evidence.host_closure.clone();
        invalid_closure.closure_event_type = "other".to_owned();
        expect_err(&verify_host_closure(
            &invalid_closure,
            &evidence.authoritative_events,
        ));
        let value = decode_value(ok(evidence.to_canonical_cbor()));
        expect_err(&MoatProofEvidenceV1::from_canonical_cbor(&encode_value(
            &replace_field(value.clone(), 0, ciborium::Value::Text("wrong".to_owned())),
        )));
        expect_err(&MoatProofEvidenceV1::from_canonical_cbor(&encode_value(
            &replace_field(value.clone(), 1, ciborium::Value::Integer(99_u64.into())),
        )));
        expect_err(&MoatProofEvidenceV1::from_canonical_cbor(&encode_value(
            &replace_nested_field(value, 2, 14, ciborium::Value::Text("wrong".to_owned())),
        )));

        let result = ok(tests::evidence().to_verification_result());
        let result_value = decode_value(ok(result.to_canonical_cbor()));
        expect_err(&VerificationResultV1::from_canonical_cbor(&encode_value(
            &replace_field(result_value, 17, ciborium::Value::Bytes(vec![0; 32])),
        )));

        let mut report = DivergenceReportV1 {
            request_digest: [1; 32],
            manifest_digest: [2; 32],
            execution_profile_digest: [3; 32],
            fixture_digest: Some([4; 32]),
            evaluator_digest: [5; 32],
            reproducibility_class: ReproducibilityClassV1::ProfileRecomputation,
            replay_claim: ReplayClaimV1::Exact,
            location_kind: DivergenceLocationKindV1::TimelineSeq,
            timeline_or_worldcut_id: [6; 16],
            timeline_seq_or_cut_ordinal: 7,
            tick: 8,
            scheduler_position: Some(9),
            driver_or_plugin_id: Some("world".to_owned()),
            output_ordinal: Some(10),
            mismatch_kind: DivergenceMismatchKindV1::CanonicalBytes,
            expected: DigestSizeV1 {
                digest: Some([11; 32]),
                size: Some(12),
            },
            actual: DigestSizeV1 {
                digest: Some([13; 32]),
                size: Some(14),
            },
            prior_matching_checkpoint_digest: Some([15; 32]),
            follow_on_counts: vec![FollowOnMismatchV1 {
                kind: DivergenceMismatchKindV1::Artifact,
                count: 1,
            }],
            report_digest: [0; 32],
        };
        report.report_digest = ok(report.digest());
        let report_value = decode_value(ok(report.to_canonical_cbor()));
        expect_err(&DivergenceReportV1::from_canonical_cbor(&encode_value(
            &replace_field(report_value, 21, ciborium::Value::Bytes(vec![0; 32])),
        )));

        report.driver_or_plugin_id = Some("x".repeat(20_000));
        expect_err(&report.to_canonical_cbor());
    }

    #[test]
    fn public_evidence_decoder_enforces_case_coordinate_boundary() {
        let evidence = tests::evidence();
        let encoded = decode_value(ok(evidence.to_canonical_cbor()));
        let exact =
            replace_evidence_case_coordinate(&encoded, ciborium::Value::Bytes(vec![b'x'; 128]));
        assert!(MoatProofEvidenceV1::from_canonical_cbor(&encode_value(&exact)).is_ok());

        let oversized =
            replace_evidence_case_coordinate(&encoded, ciborium::Value::Bytes(vec![b'x'; 129]));
        expect_err(&MoatProofEvidenceV1::from_canonical_cbor(&encode_value(
            &oversized,
        )));

        let wrong_type = replace_evidence_case_coordinate(
            &encoded,
            ciborium::Value::Text("coordinate".to_owned()),
        );
        expect_err(&MoatProofEvidenceV1::from_canonical_cbor(&encode_value(
            &wrong_type,
        )));
    }
}

/// The reproducibility claim made by a proof artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
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
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayClaimV1 {
    Exact,
    ExactAuthoritativeWithRedactedViews,
    StructuralOnly,
    UnverifiableArtifactsMissing,
    /// The selected runtime/profile cannot evaluate the artifact; orthogonal
    /// to the amount of replay evidence retained after redaction.
    IncompatibleProfile,
}

/// A public erasure disposition that can only preserve or weaken a replay
/// claim. It is the Wave 8 claim-degradation seam; the full
/// ERQ1/ERS1/ERC1 owner lifecycle is exercised in the later erasure wave.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErasureDispositionV1 {
    None,
    RedactedViews,
    StructuralOnly,
    ArtifactsMissing,
    IncompatibleProfile,
}

impl ReplayClaimV1 {
    const fn rank(self) -> u8 {
        match self {
            Self::Exact => 0,
            Self::ExactAuthoritativeWithRedactedViews => 1,
            Self::StructuralOnly => 2,
            Self::UnverifiableArtifactsMissing => 3,
            Self::IncompatibleProfile => 4,
        }
    }

    /// Apply an erasure disposition without ever upgrading a claim.
    #[must_use]
    pub const fn after_erasure(self, disposition: ErasureDispositionV1) -> Self {
        let disposition = match disposition {
            ErasureDispositionV1::None => self,
            ErasureDispositionV1::RedactedViews => Self::ExactAuthoritativeWithRedactedViews,
            ErasureDispositionV1::StructuralOnly => Self::StructuralOnly,
            ErasureDispositionV1::ArtifactsMissing => Self::UnverifiableArtifactsMissing,
            ErasureDispositionV1::IncompatibleProfile => Self::IncompatibleProfile,
        };
        if self.rank() >= disposition.rank() {
            self
        } else {
            disposition
        }
    }

    /// Whether a result claim is no stronger than the manifest claim.
    #[must_use]
    pub const fn is_no_stronger_than(self, declared: Self) -> bool {
        self.rank() >= declared.rank()
    }
}

/// Execution profile used by a proof run.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionModeV1 {
    /// In-process local execution.
    Local,
    /// Air-gapped execution with the same deterministic inputs and limits.
    AirGapped,
    /// Replay of an immutable recorded Event suffix.
    Replay,
    /// Re-execution of an immutable counterfactual Fork.
    Fork,
}

/// The independently reportable conformance claim layers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimLayerV1 {
    ArtifactIntegrity,
    ReplayConformance,
    KnowledgeNonInterference,
    GatewayClientConformance,
    PluginConformance,
    MetricConformance,
    EmpiricalEvaluation,
}

/// One case's closed conformance outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseOutcomeStatusV1 {
    Pass,
    Fail,
    Skip,
    Unavailable,
    NotApplicable,
}

/// The report-level redaction state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionStateV1 {
    None,
    RedactedViews,
    StructuralOnly,
    EvidenceMissing,
}

/// Closed safe error vocabulary shared by verification and conformance cases.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafeErrorCodeV1 {
    InvalidEncoding,
    UnsupportedVersion,
    FieldOutOfBounds,
    NonCanonicalOrder,
    DigestMismatch,
    SignatureInvalid,
    TrustRootUnknown,
    TrustSnapshotRollback,
    ArtifactRevoked,
    ClosureIncomplete,
    ProfileClassMismatch,
    ProfileUnsupported,
    ProvenanceMissing,
    ResourceLimitExceeded,
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

    /// Return a domain-separated digest of the exact canonical input envelope.
    ///
    /// # Errors
    /// Returns the canonical-CBOR serialization error when the input cannot be
    /// represented by the shared deterministic codec.
    #[must_use = "the input digest is needed for deterministic identity"]
    pub fn digest(&self) -> Result<[u8; 32], pos_core::CoreError> {
        pos_crypto::canonical::encode(self).map(|bytes| {
            let mut input = Vec::with_capacity(4 + bytes.as_slice().len());
            input.extend_from_slice(&[b'P', b'I', b'1', 0]);
            input.extend_from_slice(bytes.as_slice());
            *blake3::hash(&input).as_bytes()
        })
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
    pub tick: u64,
    pub entity: String,
    pub event_type: String,
    pub payload_digest: [u8; 32],
    pub causation_seq: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyClassV1 {
    ExogenousFrozen,
    InterventionAssigned,
    EndogenousRecomputed,
    FixedPolicy,
    PresentationOnly,
}

/// One projection state at the evidence boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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
    pub dependency_class: DependencyClassV1,
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
    pub class: PluginFailureClassV1,
    pub tick: u64,
    pub committed: bool,
    pub staged_event_count: u64,
    pub committed_event_count: u64,
    pub state_digest_before: [u8; 32],
    pub state_digest_after: [u8; 32],
    pub sibling_step_count: u64,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginFailureClassV1 {
    PluginCrash,
    ResourceExhaustion,
}

/// Auditable Gateway consent revocation at a completed Tick Boundary.
///
/// This type is reserved for the canonical `consent.revoked.v1` event. Local
/// Experiment shutdown uses [`HostClosureAuditV1`] instead.
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

/// Auditable local Experiment/session closure at a completed Tick Boundary.
///
/// A host closure is not a durable consent revocation and cannot rehydrate or
/// authorize a `ConsentAuthority` session. Its lifecycle evidence therefore
/// has a distinct type and closure-specific field names.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostClosureAuditV1 {
    pub subject: String,
    pub requested_after_seq: u64,
    pub effective_after_seq: u64,
    pub closure_event_seq: u64,
    pub closure_event_type: String,
    pub closure_payload_digest: [u8; 32],
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
    /// Digest of the complete user-authored Wave 8 room fixture closure.
    pub scenario_room_digest: [u8; 32],
    /// Digest of the ordered scheduler/Driver composition.
    pub scheduler_digest: [u8; 32],
    /// Digest of the deterministic resource/failure budget.
    pub budget_digest: [u8; 32],
}

/// The Wave 8 compatibility descriptor for the Component boundary.
///
/// This is deliberately the seam-level descriptor, not the Wave 9 signed
/// release manifest. It proves the exact WIT world, the only admitted host and
/// guest interfaces, the isolation policy, and the deterministic output
/// budgets before a community Component SDK exists.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginBoundaryV1 {
    pub manifest_version: u32,
    pub plugin_id: String,
    pub world: String,
    pub abi_major: u16,
    pub min_abi_minor: u16,
    pub max_abi_minor: u16,
    pub wit_digest: [u8; 32],
    pub component_digest: [u8; 32],
    pub imported_interfaces: Vec<String>,
    pub exported_interfaces: Vec<String>,
    pub network_allowed: bool,
    pub filesystem_allowed: bool,
    pub fresh_worker_required: bool,
    pub memory_bytes: u64,
    pub fuel: u64,
    pub host_call_limit: u32,
    pub event_draft_limit: u32,
    pub state_bytes_limit: u64,
    pub observation_bytes_limit: u64,
    pub manifest_digest: [u8; 32],
    pub release_digest: [u8; 32],
}

impl PluginBoundaryV1 {
    /// Validate the Wave 8 Component compatibility boundary.
    ///
    /// # Errors
    /// Returns a closed validation error when the descriptor would admit an
    /// ambient or unbounded Plugin capability.
    pub fn validate(&self) -> Result<(), PluginBoundaryError> {
        if self.manifest_version != 1
            || self.plugin_id.trim().is_empty()
            || self.plugin_id.len() > 128
            || self.world != COMMUNITY_PLUGIN_WORLD_V1
            || self.abi_major != 0
            || self.min_abi_minor > self.max_abi_minor
            || self.wit_digest == [0; 32]
            || self.component_digest == [0; 32]
            || self.manifest_digest == [0; 32]
            || self.release_digest == [0; 32]
            || self.imported_interfaces != ["host-v1"]
            || self.exported_interfaces != ["guest-v1"]
            || self.network_allowed
            || self.filesystem_allowed
            || !self.fresh_worker_required
            || !(1..=64 * 1024 * 1024).contains(&self.memory_bytes)
            || self.fuel == 0
            || self.host_call_limit > 64
            || self.event_draft_limit > 1_024
            || self.state_bytes_limit > 1_048_576
            || self.observation_bytes_limit > 1_048_576
        {
            return Err(PluginBoundaryError::InvalidDescriptor);
        }
        if self.manifest_digest != self.digest_without_identity()? {
            return Err(PluginBoundaryError::ManifestDigestMismatch);
        }
        if self.release_digest != self.release_digest_value() {
            return Err(PluginBoundaryError::ReleaseDigestMismatch);
        }
        Ok(())
    }

    fn digest_without_identity(&self) -> Result<[u8; 32], PluginBoundaryError> {
        let mut value = self.clone();
        value.manifest_digest = [0; 32];
        value.release_digest = [0; 32];
        typed_digest(b"PiglorOS.Plugin.Manifest.Wave8.v1", &value)
            .map_err(|_| PluginBoundaryError::DigestEncoding)
    }

    fn release_digest_value(&self) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&self.manifest_digest);
        bytes.extend_from_slice(&self.component_digest);
        bytes.extend_from_slice(&self.wit_digest);
        *blake3::hash(
            &[
                b"PiglorOS.Plugin.Release.Wave8.v1\0".as_slice(),
                bytes.as_slice(),
            ]
            .concat(),
        )
        .as_bytes()
    }
}

/// Closed errors for the Wave 8 plugin boundary descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PluginBoundaryError {
    #[error("plugin boundary descriptor is invalid")]
    InvalidDescriptor,
    #[error("plugin boundary manifest digest does not match its fields")]
    ManifestDigestMismatch,
    #[error("plugin boundary release digest does not match its closure")]
    ReleaseDigestMismatch,
    #[error("plugin boundary descriptor cannot be canonically encoded")]
    DigestEncoding,
}

/// Exact Component world admitted by the Wave 8 seam.
pub const COMMUNITY_PLUGIN_WORLD_V1: &str = "pigloros:plugin/community-plugin@0.1.0";
/// Canonical WIT source used by the Wave 8 compatibility fixture.
pub const COMMUNITY_PLUGIN_WIT_V1: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../plugins/community/wit/pigloros-plugin.wit"
));

/// Build the deterministic compatibility descriptor used by the proof run.
#[must_use]
pub fn wave8_plugin_boundary() -> PluginBoundaryV1 {
    let wit_digest = *blake3::hash(COMMUNITY_PLUGIN_WIT_V1.as_bytes()).as_bytes();
    let component_digest = *blake3::hash(b"PiglorOS.Wave8.ProofComponent.v1").as_bytes();
    let mut boundary = PluginBoundaryV1 {
        manifest_version: 1,
        plugin_id: "pigloros.wave8.proof-plugin".to_owned(),
        world: COMMUNITY_PLUGIN_WORLD_V1.to_owned(),
        abi_major: 0,
        min_abi_minor: 1,
        max_abi_minor: 1,
        wit_digest,
        component_digest,
        imported_interfaces: vec!["host-v1".to_owned()],
        exported_interfaces: vec!["guest-v1".to_owned()],
        network_allowed: false,
        filesystem_allowed: false,
        fresh_worker_required: true,
        memory_bytes: 16 * 1024 * 1024,
        fuel: 1_000_000,
        host_call_limit: 64,
        event_draft_limit: 1_024,
        state_bytes_limit: 1_048_576,
        observation_bytes_limit: 1_048_576,
        manifest_digest: [0; 32],
        release_digest: [0; 32],
    };
    boundary.manifest_digest = boundary.digest_without_identity().unwrap_or([0; 32]);
    boundary.release_digest = boundary.release_digest_value();
    boundary
}

/// A stable authorization identity used by participant knowledge records.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalRefV1 {
    pub principal_id: String,
    pub participant_id: String,
    pub subject_id: Option<String>,
    pub trust_domain: String,
}

/// An attenuated capability made visible only through a digest in the proof.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityGrantV1 {
    pub grant_id: String,
    pub principal_id: String,
    pub capability: String,
    pub resource: String,
    pub consent_epoch: u64,
    pub policy_digest: [u8; 32],
}

/// The host-owned answer used to derive a participant snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationDecisionV1 {
    pub principal_id: String,
    pub resource: String,
    pub operation: String,
    pub allowed: bool,
    pub reason: String,
    pub consent_epoch: u64,
    pub grant_digest: [u8; 32],
    pub decision_digest: [u8; 32],
}

/// A participant-specific immutable knowledge snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeSnapshotV1 {
    pub participant_id: String,
    pub principal: PrincipalRefV1,
    pub grant: CapabilityGrantV1,
    pub authorization: AuthorizationDecisionV1,
    pub tick: u64,
    pub visible_event_seqs: Vec<u64>,
    pub visible_event_digests: Vec<[u8; 32]>,
    pub hidden_event_types: Vec<String>,
    pub consent_epoch: u64,
    pub snapshot_digest: [u8; 32],
}

/// User-parameterized Wave 8 room fixture closure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioRoomFixtureV1 {
    pub room_id: String,
    pub input_digest: [u8; 32],
    pub horizon_ticks: u64,
    pub random_seed: u64,
    pub network_enabled: bool,
    pub exogenous_digests: Vec<[u8; 32]>,
    pub fixed_policy_digests: Vec<[u8; 32]>,
    pub principals: Vec<PrincipalRefV1>,
    pub grants: Vec<CapabilityGrantV1>,
    pub room_digest: [u8; 32],
}

/// Canonical node coordinate.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyNodeV1 {
    pub tick: u64,
    pub scheduler_position: u32,
    pub owner_id: String,
    pub output_ordinal: u32,
    pub schema_id: u32,
    pub artifact_digest: [u8; 32],
}

/// One closed dependency edge from a source to an endogenous consumer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputDependencyV1 {
    pub consumer: DependencyNodeV1,
    pub source: DependencyNodeV1,
    pub dependency_class: DependencyClassV1,
    pub authorization_digest: [u8; 32],
    pub provenance_digest: [u8; 32],
}

/// One ordered user Intervention admitted at a Tick Boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterventionV1 {
    pub intervention_id: [u8; 16],
    pub target: String,
    pub operation: String,
    pub value_digest: [u8; 32],
    pub effective_tick: u64,
    pub ordinal: u32,
    pub principal_id: String,
    pub capability: String,
    pub consent_epoch: u64,
    pub provenance_digest: [u8; 32],
}

/// Per-owner explanation of the earliest recomputed coordinate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerFrontierV1 {
    pub owner_id: String,
    pub earliest_tick: u64,
    pub earliest_scheduler_position: u32,
    pub earliest_output_ordinal: u32,
    pub cause_node_digests: Vec<[u8; 32]>,
}

/// Re-computation frontier, represented as the exact 17-field logical record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecomputationFrontierV1 {
    pub frontier_id: [u8; 16],
    pub plan_digest: [u8; 32],
    pub parent_cut_digest: [u8; 32],
    pub dependency_graph_digest: [u8; 32],
    pub intervention_seed_nodes: Vec<DependencyNodeV1>,
    pub affected_nodes: Vec<DependencyNodeV1>,
    pub owner_frontiers: Vec<OwnerFrontierV1>,
    pub global_frontier_tick: u64,
    pub global_frontier_scheduler_position: u32,
    pub unknown_edge_policy: UnknownEdgePolicyV1,
    pub unknown_edge_coordinates: Vec<DependencyNodeV1>,
    pub endogenous_suffix_end_tick: u64,
    pub classification_bundle_digest: [u8; 32],
    pub provenance_digest: [u8; 32],
    pub frontier_digest: [u8; 32],
}

/// One invalidated factual artifact in the old Fork generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvalidArtifactV1 {
    pub artifact_class: String,
    pub schema_id: u32,
    pub artifact_digest: [u8; 32],
    pub producer: DependencyNodeV1,
    pub prior_generation: u64,
    pub reason: SuffixInvalidationReasonV1,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownEdgePolicyV1 {
    Reject,
    FullSuffixFromCut,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuffixInvalidationReasonV1 {
    NewIntervention,
    ChangedIntervention,
    UnknownEdgeFallback,
    RetryAfterAtomicFailure,
    TrustOrErasureChange,
}

/// Suffix invalidation, represented as the exact 18-field logical record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuffixInvalidationV1 {
    pub invalidation_id: [u8; 16],
    pub plan_digest: [u8; 32],
    pub fork_id: [u8; 16],
    pub prior_generation: u64,
    pub new_generation: u64,
    pub frontier_digest: [u8; 32],
    pub invalid_start: DependencyNodeV1,
    pub invalid_end: DependencyNodeV1,
    pub invalid_artifacts: Vec<InvalidArtifactV1>,
    pub invalid_checkpoint_digests: Vec<[u8; 32]>,
    pub invalid_projection_digests: Vec<[u8; 32]>,
    pub retained_exogenous_digests: Vec<[u8; 32]>,
    pub reason: SuffixInvalidationReasonV1,
    pub commit_timeline_id: [u8; 16],
    pub commit_seq: u64,
    pub commit_tick: u64,
    pub provenance_digest: [u8; 32],
    pub invalidation_digest: [u8; 32],
}

/// The complete counterfactual proof attached to one evidence artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CounterfactualContractV1 {
    pub fork_id: [u8; 16],
    pub prior_generation: u64,
    pub generation: u64,
    pub intervention: Option<InterventionV1>,
    pub dependencies: Vec<InputDependencyV1>,
    pub frontier: RecomputationFrontierV1,
    pub invalidation: SuffixInvalidationV1,
    pub recomputed_event_seqs: Vec<u64>,
    pub retained_exogenous_digests: Vec<[u8; 32]>,
    pub replay_claim: ReplayClaimV1,
    pub contract_digest: [u8; 32],
}

/// Atomicity evidence for one attempted Tick Boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TickAtomicityV1 {
    pub tick: u64,
    pub fork_generation: u64,
    pub staged_event_count: u64,
    pub committed_event_count: u64,
    pub state_digest_before: [u8; 32],
    pub state_digest_after: [u8; 32],
    pub committed: bool,
    pub failure_class: Option<PluginFailureClassV1>,
}

/// Identity evidence for one implementation under test.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationIdentityV1 {
    pub implementation_id: String,
    pub source_digest: [u8; 32],
    pub build_digest: [u8; 32],
    pub binary_digest: [u8; 32],
    pub public_contract_digest: [u8; 32],
    pub organization_id: Option<String>,
}

/// Evidence that a conformance implementation is not the implementation under test.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndependenceEvidenceV1 {
    pub technical_independent: bool,
    pub authorship_independent: bool,
    pub organizational_independent: bool,
    pub declaration_digest: [u8; 32],
    pub shared_code_audit_digest: [u8; 32],
    pub reviewer_ids: Vec<String>,
}

/// One CNR1 public conformance case.
///
/// The wire representation is the exact fourteen-field ADR-062 record. CPF1
/// carries the richer [`ProfileCaseOutcomeV1`] record separately because
/// verification outcome and divergence classification are profile semantics,
/// not part of the stable CNR1 report shape.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseOutcomeV1 {
    pub case_id: String,
    pub fixture_digest: [u8; 32],
    pub execution_profile_digest: [u8; 32],
    pub mode: ExecutionModeV1,
    pub claim_layer: ClaimLayerV1,
    pub outcome: CaseOutcomeStatusV1,
    pub first_coordinate: Option<Vec<u8>>,
    pub expected_digest: Option<[u8; 32]>,
    pub actual_digest: Option<[u8; 32]>,
    pub expected_error: Option<SafeErrorCodeV1>,
    pub actual_error: Option<SafeErrorCodeV1>,
    pub replay_claim: ReplayClaimV1,
    pub redaction_state: RedactionStateV1,
    pub provenance_digest: [u8; 32],
}

/// CPF1-only case evidence with profile verification semantics.
///
/// This is intentionally a separately named record from [`CaseOutcomeV1`].
/// Adding these fields to CNR1 would silently change its exact fourteen-field
/// wire contract while retaining the `CNR1`/version `1` identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileCaseOutcomeV1 {
    pub case_id: String,
    pub fixture_digest: [u8; 32],
    pub execution_profile_digest: [u8; 32],
    pub mode: ExecutionModeV1,
    pub claim_layer: ClaimLayerV1,
    pub outcome: CaseOutcomeStatusV1,
    pub verification_outcome: VerificationOutcomeV1,
    pub divergence_kind: Option<DivergenceMismatchKindV1>,
    pub first_coordinate: Option<Vec<u8>>,
    pub expected_digest: Option<[u8; 32]>,
    pub actual_digest: Option<[u8; 32]>,
    pub expected_error: Option<SafeErrorCodeV1>,
    pub actual_error: Option<SafeErrorCodeV1>,
    pub replay_claim: ReplayClaimV1,
    pub redaction_state: RedactionStateV1,
    pub provenance_digest: [u8; 32],
}

/// The four required non-interference fixture variants.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NonInterferenceVariantV1 {
    Success,
    Denial,
    WarmCache,
    ColdCache,
}

/// One control/canary equality result from the mandatory matrix.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonInterferenceCaseV1 {
    pub fixture_id: String,
    pub variant: NonInterferenceVariantV1,
    pub mode: ExecutionModeV1,
    pub control_input_digest: [u8; 32],
    pub canary_input_digest: [u8; 32],
    pub authoritative_digest: [u8; 32],
    pub public_digest: [u8; 32],
    pub operational_digest: [u8; 32],
    pub authoritative_equal: bool,
    pub public_equal: bool,
    pub operational_equal: bool,
    pub provenance_digest: [u8; 32],
}

pub const NON_INTERFERENCE_FIXTURE_IDS_V1: [&str; 12] = [
    "NI-TOOL-001",
    "NI-CACHE-002",
    "NI-STATE-003",
    "NI-OBS-004",
    "NI-TIME-005",
    "NI-PUBLIC-006",
    "NI-EVAL-007",
    "NI-FORK-008",
    "NI-ARCHIVE-009",
    "NI-NET-010",
    "NI-SERVICE-011",
    "NI-CRASH-012",
];

pub const NON_INTERFERENCE_CASE_COUNT_V1: usize = 192;

/// Produce the deterministic Wave 8 matrix fixture set.
#[must_use]
pub fn wave8_non_interference_matrix(seed: [u8; 32]) -> Vec<NonInterferenceCaseV1> {
    let variants = [
        NonInterferenceVariantV1::Success,
        NonInterferenceVariantV1::Denial,
        NonInterferenceVariantV1::WarmCache,
        NonInterferenceVariantV1::ColdCache,
    ];
    let modes = [
        ExecutionModeV1::Local,
        ExecutionModeV1::AirGapped,
        ExecutionModeV1::Replay,
        ExecutionModeV1::Fork,
    ];
    let mut cases = Vec::with_capacity(12 * variants.len() * modes.len());
    for fixture_id in NON_INTERFERENCE_FIXTURE_IDS_V1 {
        for variant in variants {
            for mode in modes {
                let descriptor = format!("{fixture_id}:{variant:?}:{mode:?}");
                let control_input_digest = matrix_digest(
                    b"PiglorOS.NonInterference.ControlInput.v1",
                    seed,
                    format!("{descriptor}:control").as_bytes(),
                );
                let canary_input_digest = matrix_digest(
                    b"PiglorOS.NonInterference.CanaryInput.v1",
                    seed,
                    format!("{descriptor}:canary").as_bytes(),
                );
                let control = matrix_probe_output(seed, fixture_id, variant, mode);
                let canary = matrix_probe_output(seed, fixture_id, variant, mode);
                let provenance_descriptor = format!(
                    "{descriptor}:{}:{}:{}",
                    hex_digest(&control.authoritative),
                    hex_digest(&control.public),
                    hex_digest(&control.operational),
                );
                cases.push(NonInterferenceCaseV1 {
                    fixture_id: fixture_id.to_owned(),
                    variant,
                    mode,
                    control_input_digest,
                    canary_input_digest,
                    authoritative_digest: control.authoritative,
                    public_digest: control.public,
                    operational_digest: control.operational,
                    authoritative_equal: control.authoritative == canary.authoritative,
                    public_equal: control.public == canary.public,
                    operational_equal: control.operational == canary.operational,
                    provenance_digest: matrix_digest(
                        b"PiglorOS.NonInterference.Provenance.v1",
                        seed,
                        provenance_descriptor.as_bytes(),
                    ),
                });
            }
        }
    }
    cases
}

#[derive(Clone, Copy)]
struct MatrixProbeOutput {
    authoritative: [u8; 32],
    public: [u8; 32],
    operational: [u8; 32],
}

fn matrix_probe_output(
    seed: [u8; 32],
    fixture_id: &str,
    variant: NonInterferenceVariantV1,
    mode: ExecutionModeV1,
) -> MatrixProbeOutput {
    let descriptor = format!("{fixture_id}:{variant:?}:{mode:?}:stable-input");
    MatrixProbeOutput {
        authoritative: matrix_digest(
            b"PiglorOS.NonInterference.AuthoritativeOutput.v1",
            seed,
            descriptor.as_bytes(),
        ),
        public: matrix_digest(
            b"PiglorOS.NonInterference.PublicOutput.v1",
            seed,
            descriptor.as_bytes(),
        ),
        operational: matrix_digest(
            b"PiglorOS.NonInterference.OperationalOutput.v1",
            seed,
            descriptor.as_bytes(),
        ),
    }
}

fn matrix_digest(domain: &[u8], seed: [u8; 32], descriptor: &[u8]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(seed.len() + descriptor.len());
    bytes.extend_from_slice(&seed);
    bytes.extend_from_slice(descriptor);
    let mut input = Vec::with_capacity(domain.len() + 1 + bytes.len());
    input.extend_from_slice(domain);
    input.push(0);
    input.extend_from_slice(&bytes);
    *blake3::hash(&input).as_bytes()
}

/// Conformance report, with 24 logical fields represented by grouped values.
///
/// `execution_profile_digest` identifies the selected report authority;
/// each case also carries its own profile digest so one CNR can bind a CPF
/// matrix containing multiple execution profiles. Stable evidence binds its
/// report to the evidence-independent selected CPF identity; the enclosing
/// CPF digest separately commits the serialized Stable-evidence set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceReportV1 {
    pub report_id: [u8; 16],
    pub subject_artifact_digest: [u8; 32],
    pub profile_digest: [u8; 32],
    pub normative_spec_digest: [u8; 32],
    pub execution_profile_digest: [u8; 32],
    pub fixture_bundle_digest: [u8; 32],
    pub evaluator_source_digest: [u8; 32],
    pub evaluator_binary_digest: [u8; 32],
    pub evaluator_protocol_digest: [u8; 32],
    pub implementation: ImplementationIdentityV1,
    pub independence: IndependenceEvidenceV1,
    pub cases: Vec<CaseOutcomeV1>,
    pub passed: u32,
    pub failed: u32,
    pub skipped: u32,
    pub unavailable: u32,
    pub not_applicable: u32,
    pub replay_claim: ReplayClaimV1,
    pub redaction_state: RedactionStateV1,
    pub limitations_digest: [u8; 32],
    pub provenance_digest: [u8; 32],
    pub report_digest: [u8; 32],
}

impl ConformanceReportV1 {
    /// Validate the complete public CNR1 record, including case shape,
    /// aggregate counts, weakest claims, and the self-digest.
    ///
    /// # Errors
    /// Returns [`EvidenceError::InvalidConformanceReport`] when any CNR1
    /// invariant or the digest over fields `0..22` is invalid.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        validate_conformance_report_shape(self)
    }

    /// Encode the exact 24-field CNR1 array.
    ///
    /// # Errors
    /// Returns [`EvidenceError::InvalidConformanceReport`] when the record is
    /// not a complete, self-consistent report.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, EvidenceError> {
        self.validate().and_then(|()| {
            strict_codec::encode_conformance_report(self)
                .map_err(|_| EvidenceError::InvalidConformanceReport)
                .and_then(|bytes| {
                    if bytes.len() > 16 * 1024 * 1024 {
                        Err(EvidenceError::InvalidConformanceReport)
                    } else {
                        Ok(bytes)
                    }
                })
        })
    }

    /// Decode and validate an exact canonical CNR1 array.
    ///
    /// # Errors
    /// Returns [`EvidenceError::InvalidConformanceReport`] for malformed,
    /// noncanonical, incomplete, or tampered reports.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, EvidenceError> {
        if bytes.len() > 16 * 1024 * 1024 {
            return Err(EvidenceError::InvalidConformanceReport);
        }
        let report = strict_codec::decode_conformance_report(bytes)
            .map_err(|_| EvidenceError::InvalidConformanceReport)?;
        report.validate().map(|()| report)
    }

    /// Compute the CNR1 digest over fields `0..22`.
    ///
    /// # Errors
    /// Returns [`EvidenceError::InvalidConformanceReport`] when the fields
    /// cannot be represented by the strict canonical codec.
    pub fn digest(&self) -> Result<[u8; 32], EvidenceError> {
        strict_codec::conformance_report_digest(self)
            .map_err(|_| EvidenceError::InvalidConformanceReport)
    }
}

/// All typed Wave 8 seams that an independent evaluator must see.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Wave8ProofContractV1 {
    pub scenario_room: ScenarioRoomFixtureV1,
    pub plugin_boundary: PluginBoundaryV1,
    pub knowledge_snapshots: Vec<KnowledgeSnapshotV1>,
    pub authorization_decisions: Vec<AuthorizationDecisionV1>,
    pub counterfactual: CounterfactualContractV1,
    pub atomicity: Vec<TickAtomicityV1>,
    pub conformance_report: ConformanceReportV1,
    pub non_interference: Vec<NonInterferenceCaseV1>,
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
    pub host_closure: HostClosureAuditV1,
    pub contract: Wave8ProofContractV1,
}

/// Closed result state for the verification result record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationOutcomeV1 {
    VerifiedExact,
    Diverged,
    InvalidManifest,
    UnverifiableArtifactsMissing,
    IncompatibleProfile,
    ResourceLimitExceeded,
}

/// The bounded, non-secret first validation error carried by `VRR1`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationErrorV1 {
    pub code: SafeErrorCodeV1,
    pub field_ordinal: Option<u16>,
    pub canonical_coordinate: Option<Vec<u8>>,
    pub related_digest: Option<[u8; 32]>,
}

/// Exact verification result fields.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationResultV1 {
    pub request_digest: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub execution_profile_digest: [u8; 32],
    pub trust_policy_snapshot_digest: [u8; 32],
    pub artifact_closure_digest: [u8; 32],
    pub fixture_digest: Option<[u8; 32]>,
    pub evaluator_digest: [u8; 32],
    pub reproducibility_class: ReproducibilityClassV1,
    pub verification_outcome: VerificationOutcomeV1,
    pub replay_claim: ReplayClaimV1,
    pub authoritative_result_digest: Option<[u8; 32]>,
    pub divergence_report_digest: Option<[u8; 32]>,
    pub first_error: Option<VerificationErrorV1>,
    pub checked_artifact_count: u64,
    pub provenance_digest: [u8; 32],
    pub result_digest: [u8; 32],
}

/// Earliest location kind in a divergence report.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DivergenceLocationKindV1 {
    TimelineSeq,
    WorldCut,
    TickBoundary,
    Scheduler,
    DriverOutput,
}

/// Closed mismatch vocabulary for a divergence report.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DivergenceMismatchKindV1 {
    EventIdentity,
    EventOrder,
    CanonicalBytes,
    ProjectionCheckpoint,
    TypedFailure,
    Artifact,
    SchemaOrUpcaster,
    NumericProfile,
    ProhibitedOperationalInput,
}

/// Digest/size pair used without exposing raw divergent payloads.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestSizeV1 {
    pub digest: Option<[u8; 32]>,
    pub size: Option<u64>,
}

/// One bounded follow-on mismatch count in canonical kind order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FollowOnMismatchV1 {
    pub kind: DivergenceMismatchKindV1,
    pub count: u32,
}

/// Exact divergence report fields.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DivergenceReportV1 {
    pub request_digest: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub execution_profile_digest: [u8; 32],
    pub fixture_digest: Option<[u8; 32]>,
    pub evaluator_digest: [u8; 32],
    pub reproducibility_class: ReproducibilityClassV1,
    pub replay_claim: ReplayClaimV1,
    pub location_kind: DivergenceLocationKindV1,
    pub timeline_or_worldcut_id: [u8; 16],
    pub timeline_seq_or_cut_ordinal: u64,
    pub tick: u64,
    pub scheduler_position: Option<u32>,
    pub driver_or_plugin_id: Option<String>,
    pub output_ordinal: Option<u32>,
    pub mismatch_kind: DivergenceMismatchKindV1,
    pub expected: DigestSizeV1,
    pub actual: DigestSizeV1,
    pub prior_matching_checkpoint_digest: Option<[u8; 32]>,
    pub follow_on_counts: Vec<FollowOnMismatchV1>,
    pub report_digest: [u8; 32],
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
        strict_codec::encode_evidence(self)
            .map_err(|error| pos_core::CoreError::Serialization(error.to_string()))
    }

    /// Import an evidence envelope from deterministic canonical CBOR.
    ///
    /// # Errors
    /// Returns a serialization error when the bytes are malformed or the
    /// envelope does not satisfy the typed schema.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, pos_core::CoreError> {
        strict_codec::decode_evidence(bytes)
            .map_err(|error| pos_core::CoreError::Serialization(error.to_string()))
    }

    /// Return the canonical digest of this evidence envelope.
    ///
    /// # Errors
    /// Returns the canonical-CBOR serialization error when the envelope cannot
    /// be represented by the shared deterministic codec.
    #[must_use = "the evidence digest is needed for comparison or verification"]
    pub fn digest(&self) -> Result<[u8; 32], pos_core::CoreError> {
        let bytes = self.to_canonical_cbor()?;
        let mut input = Vec::with_capacity(4 + bytes.as_slice().len());
        input.extend_from_slice(&[b'E', b'V', b'1', 0]);
        input.extend_from_slice(bytes.as_slice());
        Ok(*blake3::hash(&input).as_bytes())
    }

    /// Export the closed verification result for this evidence.
    ///
    /// # Errors
    /// Returns a serialization error when the evidence is invalid or cannot
    /// be represented by the closed result record.
    pub fn to_verification_result(&self) -> Result<VerificationResultV1, pos_core::CoreError> {
        verify_evidence(self)
            .map_err(|error| {
                pos_core::CoreError::Serialization(format!("invalid proof evidence: {error}"))
            })
            .and_then(|()| {
                typed_digest(
                    b"PiglorOS.AuthoritativeFixture.v1",
                    &self.authoritative_events,
                )
            })
            .and_then(|fixture_digest| {
                typed_digest(b"PiglorOS.ReproManifest.v1", &self.manifest).and_then(
                    |manifest_digest| {
                        self.digest().and_then(|evidence_digest| {
                            let mut result = VerificationResultV1 {
                                request_digest: self.manifest.input_digest,
                                manifest_digest,
                                execution_profile_digest: self.manifest.execution_profile_digest,
                                trust_policy_snapshot_digest: self
                                    .manifest
                                    .trust_policy_snapshot_digest,
                                artifact_closure_digest: self.manifest.artifact_closure_digest,
                                fixture_digest: Some(fixture_digest),
                                evaluator_digest: self.manifest.evaluator_digest,
                                reproducibility_class: self.manifest.reproducibility_class,
                                verification_outcome: VerificationOutcomeV1::VerifiedExact,
                                replay_claim: self.manifest.replay_claim,
                                authoritative_result_digest: Some(evidence_digest),
                                divergence_report_digest: None,
                                first_error: None,
                                checked_artifact_count: u64::try_from(
                                    self.authoritative_events.len()
                                        + self.projections.len()
                                        + self.causal_trace.len(),
                                )
                                .unwrap_or(u64::MAX),
                                provenance_digest: self
                                    .contract
                                    .conformance_report
                                    .provenance_digest,
                                result_digest: [0; 32],
                            };
                            result.digest().map(|result_digest| {
                                result.result_digest = result_digest;
                                result
                            })
                        })
                    },
                )
            })
    }

    /// Export the closed verification result as exact deterministic CBOR.
    ///
    /// # Errors
    /// Returns a serialization error when the evidence or result cannot be
    /// represented by the closed CBOR record.
    pub fn to_verification_result_cbor(&self) -> Result<Vec<u8>, pos_core::CoreError> {
        self.to_verification_result()?.to_canonical_cbor()
    }
}

impl VerificationResultV1 {
    /// Encode the exact eighteen-field `VRR1` array.
    ///
    /// # Errors
    /// Returns a serialization error when the result contains an unsupported
    /// value.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, pos_core::CoreError> {
        strict_codec::encode_verification_result(self)
            .map_err(|error| pos_core::CoreError::Serialization(error.to_string()))
    }

    /// Decode and validate an exact `VRR1` array.
    ///
    /// # Errors
    /// Returns a serialization error when the bytes are malformed or violate
    /// the closed record shape.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, pos_core::CoreError> {
        strict_codec::decode_verification_result(bytes)
            .map_err(|error| pos_core::CoreError::Serialization(error.to_string()))
    }

    /// Compute the result digest over fields `0..16`.
    ///
    /// # Errors
    /// Returns a serialization error when the result cannot be encoded.
    pub fn digest(&self) -> Result<[u8; 32], pos_core::CoreError> {
        strict_codec::verification_result_digest(self)
            .map_err(|error| pos_core::CoreError::Serialization(error.to_string()))
    }
}

impl DivergenceReportV1 {
    /// Encode the exact twenty-two-field `DVR1` array.
    ///
    /// # Errors
    /// Returns a serialization error when the report contains an unsupported
    /// value.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, pos_core::CoreError> {
        strict_codec::encode_divergence_report(self)
            .map_err(|error| pos_core::CoreError::Serialization(error.to_string()))
    }

    /// Decode and validate an exact `DVR1` array.
    ///
    /// # Errors
    /// Returns a serialization error when the bytes are malformed or violate
    /// the closed record shape.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, pos_core::CoreError> {
        strict_codec::decode_divergence_report(bytes)
            .map_err(|error| pos_core::CoreError::Serialization(error.to_string()))
    }

    /// Compute the divergence digest over fields `0..20`.
    ///
    /// # Errors
    /// Returns a serialization error when the report cannot be encoded.
    pub fn digest(&self) -> Result<[u8; 32], pos_core::CoreError> {
        strict_codec::divergence_report_digest(self)
            .map_err(|error| pos_core::CoreError::Serialization(error.to_string()))
    }
}

fn typed_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<[u8; 32], pos_core::CoreError> {
    pos_crypto::canonical::encode(value).map(|bytes| {
        let mut input = Vec::with_capacity(domain.len() + 1 + bytes.len());
        input.extend_from_slice(domain);
        input.push(0);
        input.extend_from_slice(bytes.as_slice());
        *blake3::hash(&input).as_bytes()
    })
}

/// Strict portable wire codec for the Wave 8 records.
///
/// The existing JSON representation is intentionally human-readable and is
/// useful for debugging.  It is not the authority format: the authority
/// format is a closed array-only CBOR envelope.  Keeping this codec here gives
/// the host and an external evaluator one small, dependency-light seam while
/// preventing serde's map representation from becoming a protocol by accident.
pub mod strict_codec {
    use super::{
        AuthoritativeEventV1, AuthorizationDecisionV1, BTreeMap, CapabilityGrantV1,
        CaseOutcomeStatusV1, CaseOutcomeV1, CausalTraceEntryV1, ClaimLayerV1, ConformanceReportV1,
        ConsentAuditV1, CounterfactualContractV1, Cursor, DependencyClassV1, DependencyNodeV1,
        DigestSizeV1, DivergenceLocationKindV1, DivergenceMismatchKindV1, DivergenceReportV1,
        ExecutionModeV1, FollowOnMismatchV1, HostClosureAuditV1, ImplementationIdentityV1,
        IndependenceEvidenceV1, InputDependencyV1, InterventionV1, InvalidArtifactV1,
        KnowledgeSnapshotV1, MoatProofEvidenceV1, NonInterferenceCaseV1, NonInterferenceVariantV1,
        OwnerFrontierV1, ParticipantEventV1, ParticipantViewV1, PluginBoundaryV1,
        PluginFailureClassV1, PluginFailureV1, PrincipalRefV1, ProjectionEvidenceV1,
        RecomputationFrontierV1, RedactionStateV1, ReplayClaimV1, ReproManifestV1,
        ReproducibilityClassV1, SafeErrorCodeV1, ScenarioRoomFixtureV1, SuffixInvalidationReasonV1,
        SuffixInvalidationV1, TickAtomicityV1, UncertaintyV1, UnknownEdgePolicyV1, Value,
        VerificationErrorV1, VerificationOutcomeV1, VerificationResultV1, Wave8ProofContractV1,
        CONFORMANCE_REPORT_MAGIC_V1, DIVERGENCE_RECORD_MAGIC_V1, EVIDENCE_ENVELOPE_MAGIC_V1,
        EVIDENCE_FORMAT_V1, RECOMPUTATION_FRONTIER_MAGIC_V1, SUFFIX_INVALIDATION_MAGIC_V1,
        VERIFICATION_RECORD_MAGIC_V1,
    };

    #[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
    pub enum StrictCborError {
        #[error("strict CBOR serialization failed: {0}")]
        Serialization(String),
        #[error("strict CBOR JSON projection failed: {0}")]
        Json(String),
        #[error("strict CBOR root must be a definite array")]
        RootNotArray,
        #[error("strict CBOR field {field} must have exactly {expected} values")]
        ArrayLength { field: String, expected: usize },
        #[error("strict CBOR field {field} has an invalid value")]
        InvalidField { field: String },
        #[error("strict CBOR contains a map, tag, float, or unsupported value")]
        ForbiddenValue,
        #[error("strict CBOR contains trailing or noncanonical bytes")]
        NonCanonical,
        #[error("strict CBOR has unsupported magic or version")]
        UnsupportedVersion,
    }

    pub(crate) fn encode_evidence(
        evidence: &MoatProofEvidenceV1,
    ) -> Result<Vec<u8>, StrictCborError> {
        let root = Value::Array(vec![
            text(EVIDENCE_ENVELOPE_MAGIC_V1),
            uint(u64::from(EVIDENCE_FORMAT_V1)),
            encode_manifest(&evidence.manifest),
            Value::Array(
                evidence
                    .authoritative_events
                    .iter()
                    .map(encode_event)
                    .collect(),
            ),
            Value::Array(
                evidence
                    .projections
                    .iter()
                    .map(encode_projection)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            Value::Array(evidence.causal_trace.iter().map(encode_trace).collect()),
            Value::Array(
                evidence
                    .uncertainty
                    .iter()
                    .map(encode_uncertainty)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            Value::Array(
                evidence
                    .participant_views
                    .iter()
                    .map(encode_participant_view)
                    .collect(),
            ),
            Value::Array(
                evidence
                    .plugin_failures
                    .iter()
                    .map(encode_plugin_failure)
                    .collect(),
            ),
            encode_host_closure(&evidence.host_closure),
            encode_contract(&evidence.contract),
        ]);
        encode_value(&root)
    }

    pub(crate) fn decode_evidence(bytes: &[u8]) -> Result<MoatProofEvidenceV1, StrictCborError> {
        let root = decode_value(bytes)?;
        let fields = array(&root, "evidence", 11)?;
        if string(&fields[0], "magic")? != EVIDENCE_ENVELOPE_MAGIC_V1
            || uint_value(&fields[1], "version")? != u64::from(EVIDENCE_FORMAT_V1)
        {
            return Err(StrictCborError::UnsupportedVersion);
        }
        Ok(MoatProofEvidenceV1 {
            format_version: EVIDENCE_FORMAT_V1,
            manifest: decode_manifest(&fields[2])?,
            authoritative_events: decode_events(&fields[3])?,
            projections: decode_projections(&fields[4])?,
            causal_trace: decode_traces(&fields[5])?,
            uncertainty: decode_uncertainty(&fields[6])?,
            participant_views: decode_participant_views(&fields[7])?,
            plugin_failures: decode_plugin_failures(&fields[8])?,
            host_closure: decode_host_closure(&fields[9])?,
            contract: decode_contract(&fields[10])?,
        })
    }

    fn encode_value(value: &Value) -> Result<Vec<u8>, StrictCborError> {
        validate_value(value)?;
        let mut bytes = Vec::new();
        ciborium::into_writer(value, &mut bytes)
            .map_err(|error| StrictCborError::Serialization(error.to_string()))?;
        Ok(bytes)
    }

    pub(crate) fn encode_verification_result(
        result: &VerificationResultV1,
    ) -> Result<Vec<u8>, StrictCborError> {
        validate_verification_result(result)?;
        encode_value(&encode_verification_result_value(result, true))
    }

    pub(crate) fn decode_verification_result(
        bytes: &[u8],
    ) -> Result<VerificationResultV1, StrictCborError> {
        let value = decode_value(bytes)?;
        let fields = array(&value, "verification_result", 18)?;
        let result = decode_verification_result_fields(fields)?;
        if result.result_digest != verification_result_digest(&result)? {
            return Err(StrictCborError::InvalidField {
                field: "verification_result_digest".to_owned(),
            });
        }
        validate_verification_result(&result)?;
        Ok(result)
    }

    pub(crate) fn verification_result_digest(
        result: &VerificationResultV1,
    ) -> Result<[u8; 32], StrictCborError> {
        encode_value(&encode_verification_result_value(result, false))
            .map(|bytes| domain_digest(b"PiglorOS.VerificationResult.v1", &bytes))
    }

    fn encode_verification_result_value(
        result: &VerificationResultV1,
        include_digest: bool,
    ) -> Value {
        let mut fields = vec![
            text(VERIFICATION_RECORD_MAGIC_V1),
            uint(1),
            digest(&result.request_digest),
            digest(&result.manifest_digest),
            digest(&result.execution_profile_digest),
            digest(&result.trust_policy_snapshot_digest),
            digest(&result.artifact_closure_digest),
            optional(result.fixture_digest.as_ref().map(digest)),
            digest(&result.evaluator_digest),
            enum_reproducibility(result.reproducibility_class),
            enum_verification_outcome(result.verification_outcome),
            enum_replay_claim(result.replay_claim),
            optional(result.authoritative_result_digest.as_ref().map(digest)),
            optional(result.divergence_report_digest.as_ref().map(digest)),
            optional(result.first_error.as_ref().map(encode_verification_error)),
            uint(result.checked_artifact_count),
            digest(&result.provenance_digest),
        ];
        if include_digest {
            fields.push(digest(&result.result_digest));
        }
        Value::Array(fields)
    }

    fn encode_verification_error(error: &VerificationErrorV1) -> Value {
        Value::Array(vec![
            enum_safe_error(error.code),
            optional(error.field_ordinal.map(u64::from).map(uint)),
            optional(
                error
                    .canonical_coordinate
                    .as_ref()
                    .map(|bytes| Value::Bytes(bytes.clone())),
            ),
            optional(error.related_digest.as_ref().map(digest)),
        ])
    }

    fn decode_verification_result_fields(
        fields: &[Value],
    ) -> Result<VerificationResultV1, StrictCborError> {
        let checked_artifact_count = uint_value(&fields[15], "checked_artifact_count")?;
        if string(&fields[0], "verification_magic")? != VERIFICATION_RECORD_MAGIC_V1
            || uint_value(&fields[1], "verification_version")? != 1
            || checked_artifact_count > 65_536
        {
            return Err(StrictCborError::UnsupportedVersion);
        }
        let authoritative_result_digest =
            decode_optional_digest(&fields[12], "authoritative_result_digest")?;
        let divergence_report_digest =
            decode_optional_digest(&fields[13], "divergence_report_digest")?;
        let first_error = if matches!(fields[14], Value::Null) {
            None
        } else {
            Some(decode_verification_error(&fields[14])?)
        };
        Ok(VerificationResultV1 {
            request_digest: bytes(&fields[2], "request_digest")?,
            manifest_digest: bytes(&fields[3], "manifest_digest")?,
            execution_profile_digest: bytes(&fields[4], "verification_profile")?,
            trust_policy_snapshot_digest: bytes(&fields[5], "verification_trust")?,
            artifact_closure_digest: bytes(&fields[6], "verification_closure")?,
            fixture_digest: decode_optional_digest(&fields[7], "verification_fixture")?,
            evaluator_digest: bytes(&fields[8], "verification_evaluator")?,
            reproducibility_class: decode_reproducibility(&fields[9])?,
            verification_outcome: decode_verification_outcome(&fields[10])?,
            replay_claim: decode_replay_claim(&fields[11])?,
            authoritative_result_digest,
            divergence_report_digest,
            first_error,
            checked_artifact_count,
            provenance_digest: bytes(&fields[16], "verification_provenance")?,
            result_digest: bytes(&fields[17], "verification_result_digest")?,
        })
    }

    fn validate_verification_result(result: &VerificationResultV1) -> Result<(), StrictCborError> {
        let valid = match result.verification_outcome {
            VerificationOutcomeV1::VerifiedExact => {
                result.authoritative_result_digest.is_some()
                    && result.divergence_report_digest.is_none()
                    && result.first_error.is_none()
            }
            VerificationOutcomeV1::Diverged => {
                result.divergence_report_digest.is_some() && result.first_error.is_none()
            }
            VerificationOutcomeV1::InvalidManifest
            | VerificationOutcomeV1::UnverifiableArtifactsMissing
            | VerificationOutcomeV1::IncompatibleProfile
            | VerificationOutcomeV1::ResourceLimitExceeded => {
                result.first_error.is_some() && result.divergence_report_digest.is_none()
            }
        };
        if !valid
            || result.checked_artifact_count > 65_536
            || result.provenance_digest == [0; 32]
            || result.result_digest == [0; 32]
        {
            return Err(StrictCborError::InvalidField {
                field: "verification_result_semantics".to_owned(),
            });
        }
        if let Some(error) = &result.first_error {
            if error
                .canonical_coordinate
                .as_ref()
                .is_some_and(|coordinate| coordinate.len() > 128)
            {
                return Err(StrictCborError::InvalidField {
                    field: "verification_error_coordinate".to_owned(),
                });
            }
        }
        Ok(())
    }

    fn decode_verification_error(value: &Value) -> Result<VerificationErrorV1, StrictCborError> {
        let fields = array(value, "verification_error", 4)?;
        let field_ordinal = optional_u64(&fields[1], "error_field_ordinal")?.map(|value| {
            u16::try_from(value).map_err(|_| StrictCborError::InvalidField {
                field: "error_field_ordinal".to_owned(),
            })
        });
        let field_ordinal = field_ordinal.transpose()?;
        let canonical_coordinate = if matches!(fields[2], Value::Null) {
            None
        } else {
            let bytes = match &fields[2] {
                Value::Bytes(bytes) if bytes.len() <= 128 => bytes.clone(),
                _ => {
                    return Err(StrictCborError::InvalidField {
                        field: "error_coordinate".to_owned(),
                    });
                }
            };
            Some(bytes)
        };
        Ok(VerificationErrorV1 {
            code: decode_safe_error(&fields[0])?,
            field_ordinal,
            canonical_coordinate,
            related_digest: decode_optional_digest(&fields[3], "error_digest")?,
        })
    }

    fn enum_verification_outcome(value: VerificationOutcomeV1) -> Value {
        uint(match value {
            VerificationOutcomeV1::VerifiedExact => 0,
            VerificationOutcomeV1::Diverged => 1,
            VerificationOutcomeV1::InvalidManifest => 2,
            VerificationOutcomeV1::UnverifiableArtifactsMissing => 3,
            VerificationOutcomeV1::IncompatibleProfile => 4,
            VerificationOutcomeV1::ResourceLimitExceeded => 5,
        })
    }

    fn decode_verification_outcome(
        value: &Value,
    ) -> Result<VerificationOutcomeV1, StrictCborError> {
        match uint_value(value, "verification_outcome")? {
            0 => Ok(VerificationOutcomeV1::VerifiedExact),
            1 => Ok(VerificationOutcomeV1::Diverged),
            2 => Ok(VerificationOutcomeV1::InvalidManifest),
            3 => Ok(VerificationOutcomeV1::UnverifiableArtifactsMissing),
            4 => Ok(VerificationOutcomeV1::IncompatibleProfile),
            5 => Ok(VerificationOutcomeV1::ResourceLimitExceeded),
            _ => Err(StrictCborError::InvalidField {
                field: "verification_outcome".to_owned(),
            }),
        }
    }

    pub(crate) fn encode_divergence_report(
        report: &DivergenceReportV1,
    ) -> Result<Vec<u8>, StrictCborError> {
        let bytes = encode_value(&encode_divergence_report_value(report, true))?;
        if bytes.len() > 16 * 1024 {
            return Err(StrictCborError::InvalidField {
                field: "divergence_report_size".to_owned(),
            });
        }
        Ok(bytes)
    }

    pub(crate) fn decode_divergence_report(
        bytes: &[u8],
    ) -> Result<DivergenceReportV1, StrictCborError> {
        let value = decode_value(bytes)?;
        let fields = array(&value, "divergence_report", 22)?;
        let report = decode_divergence_report_fields(fields)?;
        if report.report_digest != divergence_report_digest(&report)? {
            return Err(StrictCborError::InvalidField {
                field: "divergence_report_digest".to_owned(),
            });
        }
        validate_divergence_report(&report)?;
        Ok(report)
    }

    pub(crate) fn divergence_report_digest(
        report: &DivergenceReportV1,
    ) -> Result<[u8; 32], StrictCborError> {
        encode_value(&encode_divergence_report_value(report, false))
            .map(|bytes| domain_digest(b"PiglorOS.DivergenceReport.v1", &bytes))
    }

    fn encode_divergence_report_value(report: &DivergenceReportV1, include_digest: bool) -> Value {
        let mut fields = vec![
            text(DIVERGENCE_RECORD_MAGIC_V1),
            uint(1),
            digest(&report.request_digest),
            digest(&report.manifest_digest),
            digest(&report.execution_profile_digest),
            optional(report.fixture_digest.as_ref().map(digest)),
            digest(&report.evaluator_digest),
            enum_reproducibility(report.reproducibility_class),
            enum_replay_claim(report.replay_claim),
            enum_divergence_location(report.location_kind),
            digest16(&report.timeline_or_worldcut_id),
            uint(report.timeline_seq_or_cut_ordinal),
            uint(report.tick),
            optional(report.scheduler_position.map(u64::from).map(uint)),
            optional(report.driver_or_plugin_id.as_deref().map(text)),
            optional(report.output_ordinal.map(u64::from).map(uint)),
            enum_divergence_mismatch(report.mismatch_kind),
            encode_digest_size(&report.expected),
            encode_digest_size(&report.actual),
            optional(report.prior_matching_checkpoint_digest.as_ref().map(digest)),
            Value::Array(
                report
                    .follow_on_counts
                    .iter()
                    .map(|item| {
                        Value::Array(vec![
                            enum_divergence_mismatch(item.kind),
                            uint(u64::from(item.count)),
                        ])
                    })
                    .collect(),
            ),
        ];
        if include_digest {
            fields.push(digest(&report.report_digest));
        }
        Value::Array(fields)
    }

    fn encode_digest_size(value: &DigestSizeV1) -> Value {
        Value::Array(vec![
            optional(value.digest.as_ref().map(digest)),
            optional(value.size.map(uint)),
        ])
    }

    fn decode_divergence_report_fields(
        fields: &[Value],
    ) -> Result<DivergenceReportV1, StrictCborError> {
        if string(&fields[0], "divergence_magic")? != DIVERGENCE_RECORD_MAGIC_V1
            || uint_value(&fields[1], "divergence_version")? != 1
        {
            return Err(StrictCborError::UnsupportedVersion);
        }
        let prior_matching_checkpoint_digest =
            decode_optional_digest(&fields[19], "divergence_checkpoint")?;
        Ok(DivergenceReportV1 {
            request_digest: bytes(&fields[2], "divergence_request")?,
            manifest_digest: bytes(&fields[3], "divergence_manifest")?,
            execution_profile_digest: bytes(&fields[4], "divergence_profile")?,
            fixture_digest: decode_optional_digest(&fields[5], "divergence_fixture")?,
            evaluator_digest: bytes(&fields[6], "divergence_evaluator")?,
            reproducibility_class: decode_reproducibility(&fields[7])?,
            replay_claim: decode_replay_claim(&fields[8])?,
            location_kind: decode_divergence_location(&fields[9])?,
            timeline_or_worldcut_id: bytes(&fields[10], "divergence_timeline")?,
            timeline_seq_or_cut_ordinal: uint_value(&fields[11], "divergence_seq")?,
            tick: uint_value(&fields[12], "divergence_tick")?,
            scheduler_position: decode_optional_u32(&fields[13], "divergence_scheduler")?,
            driver_or_plugin_id: optional_string(&fields[14], "divergence_driver")?,
            output_ordinal: decode_optional_u32(&fields[15], "divergence_ordinal")?,
            mismatch_kind: decode_divergence_mismatch(&fields[16])?,
            expected: decode_digest_size(&fields[17], "divergence_expected")?,
            actual: decode_digest_size(&fields[18], "divergence_actual")?,
            prior_matching_checkpoint_digest,
            follow_on_counts: decode_follow_on_counts(&fields[20])?,
            report_digest: bytes(&fields[21], "divergence_digest")?,
        })
    }

    fn validate_divergence_report(report: &DivergenceReportV1) -> Result<(), StrictCborError> {
        if report.timeline_seq_or_cut_ordinal > i64::MAX as u64
            || report.tick > i64::MAX as u64
            || report
                .scheduler_position
                .is_some_and(|value| value > u32::from(u16::MAX))
            || report
                .output_ordinal
                .is_some_and(|value| value > u32::from(u16::MAX))
            || report
                .driver_or_plugin_id
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 128)
            || report.report_digest == [0; 32]
            || report.follow_on_counts.len() > 32
            || report.follow_on_counts.windows(2).any(|pair| {
                pair[0].kind >= pair[1].kind || pair[0].count == 0 || pair[1].count == 0
            })
        {
            return Err(StrictCborError::InvalidField {
                field: "divergence_report_semantics".to_owned(),
            });
        }
        Ok(())
    }

    fn decode_digest_size(value: &Value, field: &str) -> Result<DigestSizeV1, StrictCborError> {
        let fields = array(value, field, 2)?;
        Ok(DigestSizeV1 {
            digest: decode_optional_digest(&fields[0], "digest_size_digest")?,
            size: optional_u64(&fields[1], "digest_size_size")?,
        })
    }

    fn decode_follow_on_counts(value: &Value) -> Result<Vec<FollowOnMismatchV1>, StrictCborError> {
        let values = array_values(value, "follow_on_counts")?;
        if values.len() > 32 {
            return Err(StrictCborError::InvalidField {
                field: "follow_on_counts".to_owned(),
            });
        }
        let mut result = Vec::with_capacity(values.len());
        for value in values {
            let fields = array(value, "follow_on_count", 2)?;
            result.push(FollowOnMismatchV1 {
                kind: decode_divergence_mismatch(&fields[0])?,
                count: u32::try_from(uint_value(&fields[1], "follow_on_count_value")?).map_err(
                    |_| StrictCborError::InvalidField {
                        field: "follow_on_count_value".to_owned(),
                    },
                )?,
            });
        }
        if result.windows(2).any(|pair| pair[0].kind >= pair[1].kind) {
            return Err(StrictCborError::InvalidField {
                field: "follow_on_counts_order".to_owned(),
            });
        }
        Ok(result)
    }

    fn enum_divergence_location(value: DivergenceLocationKindV1) -> Value {
        uint(match value {
            DivergenceLocationKindV1::TimelineSeq => 0,
            DivergenceLocationKindV1::WorldCut => 1,
            DivergenceLocationKindV1::TickBoundary => 2,
            DivergenceLocationKindV1::Scheduler => 3,
            DivergenceLocationKindV1::DriverOutput => 4,
        })
    }

    fn decode_divergence_location(
        value: &Value,
    ) -> Result<DivergenceLocationKindV1, StrictCborError> {
        match uint_value(value, "divergence_location")? {
            0 => Ok(DivergenceLocationKindV1::TimelineSeq),
            1 => Ok(DivergenceLocationKindV1::WorldCut),
            2 => Ok(DivergenceLocationKindV1::TickBoundary),
            3 => Ok(DivergenceLocationKindV1::Scheduler),
            4 => Ok(DivergenceLocationKindV1::DriverOutput),
            _ => Err(StrictCborError::InvalidField {
                field: "divergence_location".to_owned(),
            }),
        }
    }

    fn enum_divergence_mismatch(value: DivergenceMismatchKindV1) -> Value {
        uint(match value {
            DivergenceMismatchKindV1::EventIdentity => 0,
            DivergenceMismatchKindV1::EventOrder => 1,
            DivergenceMismatchKindV1::CanonicalBytes => 2,
            DivergenceMismatchKindV1::ProjectionCheckpoint => 3,
            DivergenceMismatchKindV1::TypedFailure => 4,
            DivergenceMismatchKindV1::Artifact => 5,
            DivergenceMismatchKindV1::SchemaOrUpcaster => 6,
            DivergenceMismatchKindV1::NumericProfile => 7,
            DivergenceMismatchKindV1::ProhibitedOperationalInput => 8,
        })
    }

    fn decode_divergence_mismatch(
        value: &Value,
    ) -> Result<DivergenceMismatchKindV1, StrictCborError> {
        match uint_value(value, "divergence_mismatch")? {
            0 => Ok(DivergenceMismatchKindV1::EventIdentity),
            1 => Ok(DivergenceMismatchKindV1::EventOrder),
            2 => Ok(DivergenceMismatchKindV1::CanonicalBytes),
            3 => Ok(DivergenceMismatchKindV1::ProjectionCheckpoint),
            4 => Ok(DivergenceMismatchKindV1::TypedFailure),
            5 => Ok(DivergenceMismatchKindV1::Artifact),
            6 => Ok(DivergenceMismatchKindV1::SchemaOrUpcaster),
            7 => Ok(DivergenceMismatchKindV1::NumericProfile),
            8 => Ok(DivergenceMismatchKindV1::ProhibitedOperationalInput),
            _ => Err(StrictCborError::InvalidField {
                field: "divergence_mismatch".to_owned(),
            }),
        }
    }

    fn decode_optional_u32(value: &Value, field: &str) -> Result<Option<u32>, StrictCborError> {
        optional_u64(value, field)?
            .map(|value| {
                u32::try_from(value).map_err(|_| StrictCborError::InvalidField {
                    field: field.to_owned(),
                })
            })
            .transpose()
    }

    fn decode_optional_digest(
        value: &Value,
        field: &str,
    ) -> Result<Option<[u8; 32]>, StrictCborError> {
        if matches!(value, Value::Null) {
            Ok(None)
        } else {
            bytes(value, field).map(Some)
        }
    }

    fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
        let mut input = Vec::with_capacity(domain.len() + 1 + bytes.len());
        input.extend_from_slice(domain);
        input.push(0);
        input.extend_from_slice(bytes);
        *blake3::hash(&input).as_bytes()
    }

    fn decode_value(bytes: &[u8]) -> Result<Value, StrictCborError> {
        let mut cursor = Cursor::new(bytes);
        let value: Value = ciborium::from_reader(&mut cursor)
            .map_err(|error| StrictCborError::Serialization(error.to_string()))?;
        if cursor.position() != u64::try_from(bytes.len()).unwrap_or(u64::MAX) {
            return Err(StrictCborError::NonCanonical);
        }
        let canonical = encode_value(&value)?;
        if canonical != bytes {
            return Err(StrictCborError::NonCanonical);
        }
        Ok(value)
    }

    fn validate_value(value: &Value) -> Result<(), StrictCborError> {
        if let Value::Array(values) = value {
            values.iter().try_for_each(validate_value)
        } else if matches!(
            value,
            Value::Bytes(_) | Value::Text(_) | Value::Integer(_) | Value::Bool(_) | Value::Null
        ) {
            Ok(())
        } else {
            Err(StrictCborError::ForbiddenValue)
        }
    }

    fn text(value: &str) -> Value {
        Value::Text(value.to_owned())
    }

    fn uint(value: u64) -> Value {
        Value::Integer(value.into())
    }

    fn digest(value: &[u8; 32]) -> Value {
        Value::Bytes(value.to_vec())
    }

    fn digest16(value: &[u8; 16]) -> Value {
        Value::Bytes(value.to_vec())
    }

    fn optional(value: Option<Value>) -> Value {
        value.unwrap_or(Value::Null)
    }

    fn array<'a>(
        value: &'a Value,
        field: &str,
        expected: usize,
    ) -> Result<&'a [Value], StrictCborError> {
        let Value::Array(values) = value else {
            return Err(StrictCborError::InvalidField {
                field: field.to_owned(),
            });
        };
        if values.len() != expected {
            return Err(StrictCborError::ArrayLength {
                field: field.to_owned(),
                expected,
            });
        }
        Ok(values)
    }

    fn string(value: &Value, field: &str) -> Result<String, StrictCborError> {
        match value {
            Value::Text(value) => Ok(value.clone()),
            _ => Err(StrictCborError::InvalidField {
                field: field.to_owned(),
            }),
        }
    }

    fn bytes<const N: usize>(value: &Value, field: &str) -> Result<[u8; N], StrictCborError> {
        let Value::Bytes(value) = value else {
            return Err(StrictCborError::InvalidField {
                field: field.to_owned(),
            });
        };
        value
            .as_slice()
            .try_into()
            .map_err(|_| StrictCborError::InvalidField {
                field: field.to_owned(),
            })
    }

    fn uint_value(value: &Value, field: &str) -> Result<u64, StrictCborError> {
        let Value::Integer(value) = value else {
            return Err(StrictCborError::InvalidField {
                field: field.to_owned(),
            });
        };
        u64::try_from(*value).map_err(|_| StrictCborError::InvalidField {
            field: field.to_owned(),
        })
    }

    fn bool_value(value: &Value, field: &str) -> Result<bool, StrictCborError> {
        match value {
            Value::Bool(value) => Ok(*value),
            _ => Err(StrictCborError::InvalidField {
                field: field.to_owned(),
            }),
        }
    }

    fn optional_u64(value: &Value, field: &str) -> Result<Option<u64>, StrictCborError> {
        if matches!(value, Value::Null) {
            Ok(None)
        } else {
            uint_value(value, field).map(Some)
        }
    }

    fn optional_string(value: &Value, field: &str) -> Result<Option<String>, StrictCborError> {
        if matches!(value, Value::Null) {
            Ok(None)
        } else {
            string(value, field).map(Some)
        }
    }

    fn enum_dependency_class(value: DependencyClassV1) -> Value {
        uint(match value {
            DependencyClassV1::ExogenousFrozen => 0,
            DependencyClassV1::InterventionAssigned => 1,
            DependencyClassV1::EndogenousRecomputed => 2,
            DependencyClassV1::FixedPolicy => 3,
            DependencyClassV1::PresentationOnly => 4,
        })
    }

    fn decode_dependency_class(value: &Value) -> Result<DependencyClassV1, StrictCborError> {
        match uint_value(value, "dependency_class")? {
            0 => Ok(DependencyClassV1::ExogenousFrozen),
            1 => Ok(DependencyClassV1::InterventionAssigned),
            2 => Ok(DependencyClassV1::EndogenousRecomputed),
            3 => Ok(DependencyClassV1::FixedPolicy),
            4 => Ok(DependencyClassV1::PresentationOnly),
            _ => Err(StrictCborError::InvalidField {
                field: "dependency_class".to_owned(),
            }),
        }
    }

    fn enum_plugin_failure(value: PluginFailureClassV1) -> Value {
        uint(match value {
            PluginFailureClassV1::PluginCrash => 0,
            PluginFailureClassV1::ResourceExhaustion => 1,
        })
    }

    fn decode_plugin_failure(value: &Value) -> Result<PluginFailureClassV1, StrictCborError> {
        match uint_value(value, "failure_class")? {
            0 => Ok(PluginFailureClassV1::PluginCrash),
            1 => Ok(PluginFailureClassV1::ResourceExhaustion),
            _ => Err(StrictCborError::InvalidField {
                field: "failure_class".to_owned(),
            }),
        }
    }

    fn enum_unknown_edge_policy(value: UnknownEdgePolicyV1) -> Value {
        uint(match value {
            UnknownEdgePolicyV1::Reject => 0,
            UnknownEdgePolicyV1::FullSuffixFromCut => 1,
        })
    }

    fn decode_unknown_edge_policy(value: &Value) -> Result<UnknownEdgePolicyV1, StrictCborError> {
        match uint_value(value, "frontier_unknown_policy")? {
            0 => Ok(UnknownEdgePolicyV1::Reject),
            1 => Ok(UnknownEdgePolicyV1::FullSuffixFromCut),
            _ => Err(StrictCborError::InvalidField {
                field: "frontier_unknown_policy".to_owned(),
            }),
        }
    }

    fn enum_invalidation_reason(value: SuffixInvalidationReasonV1) -> Value {
        uint(match value {
            SuffixInvalidationReasonV1::NewIntervention => 0,
            SuffixInvalidationReasonV1::ChangedIntervention => 1,
            SuffixInvalidationReasonV1::UnknownEdgeFallback => 2,
            SuffixInvalidationReasonV1::RetryAfterAtomicFailure => 3,
            SuffixInvalidationReasonV1::TrustOrErasureChange => 4,
        })
    }

    fn decode_invalidation_reason(
        value: &Value,
    ) -> Result<SuffixInvalidationReasonV1, StrictCborError> {
        match uint_value(value, "invalidation_reason")? {
            0 => Ok(SuffixInvalidationReasonV1::NewIntervention),
            1 => Ok(SuffixInvalidationReasonV1::ChangedIntervention),
            2 => Ok(SuffixInvalidationReasonV1::UnknownEdgeFallback),
            3 => Ok(SuffixInvalidationReasonV1::RetryAfterAtomicFailure),
            4 => Ok(SuffixInvalidationReasonV1::TrustOrErasureChange),
            _ => Err(StrictCborError::InvalidField {
                field: "invalidation_reason".to_owned(),
            }),
        }
    }

    fn enum_mode(value: ExecutionModeV1) -> Value {
        uint(match value {
            ExecutionModeV1::Local => 0,
            ExecutionModeV1::AirGapped => 1,
            ExecutionModeV1::Replay => 2,
            ExecutionModeV1::Fork => 3,
        })
    }

    fn decode_mode(value: &Value) -> Result<ExecutionModeV1, StrictCborError> {
        match uint_value(value, "execution_mode")? {
            0 => Ok(ExecutionModeV1::Local),
            1 => Ok(ExecutionModeV1::AirGapped),
            2 => Ok(ExecutionModeV1::Replay),
            3 => Ok(ExecutionModeV1::Fork),
            _ => Err(StrictCborError::InvalidField {
                field: "execution_mode".to_owned(),
            }),
        }
    }

    fn enum_claim_layer(value: ClaimLayerV1) -> Value {
        uint(match value {
            ClaimLayerV1::ArtifactIntegrity => 0,
            ClaimLayerV1::ReplayConformance => 1,
            ClaimLayerV1::KnowledgeNonInterference => 2,
            ClaimLayerV1::GatewayClientConformance => 3,
            ClaimLayerV1::PluginConformance => 4,
            ClaimLayerV1::MetricConformance => 5,
            ClaimLayerV1::EmpiricalEvaluation => 6,
        })
    }

    fn decode_claim_layer(value: &Value) -> Result<ClaimLayerV1, StrictCborError> {
        match uint_value(value, "claim_layer")? {
            0 => Ok(ClaimLayerV1::ArtifactIntegrity),
            1 => Ok(ClaimLayerV1::ReplayConformance),
            2 => Ok(ClaimLayerV1::KnowledgeNonInterference),
            3 => Ok(ClaimLayerV1::GatewayClientConformance),
            4 => Ok(ClaimLayerV1::PluginConformance),
            5 => Ok(ClaimLayerV1::MetricConformance),
            6 => Ok(ClaimLayerV1::EmpiricalEvaluation),
            _ => Err(StrictCborError::InvalidField {
                field: "claim_layer".to_owned(),
            }),
        }
    }

    fn enum_case_outcome(value: CaseOutcomeStatusV1) -> Value {
        uint(match value {
            CaseOutcomeStatusV1::Pass => 0,
            CaseOutcomeStatusV1::Fail => 1,
            CaseOutcomeStatusV1::Skip => 2,
            CaseOutcomeStatusV1::Unavailable => 3,
            CaseOutcomeStatusV1::NotApplicable => 4,
        })
    }

    fn decode_case_outcome(value: &Value) -> Result<CaseOutcomeStatusV1, StrictCborError> {
        match uint_value(value, "case_outcome")? {
            0 => Ok(CaseOutcomeStatusV1::Pass),
            1 => Ok(CaseOutcomeStatusV1::Fail),
            2 => Ok(CaseOutcomeStatusV1::Skip),
            3 => Ok(CaseOutcomeStatusV1::Unavailable),
            4 => Ok(CaseOutcomeStatusV1::NotApplicable),
            _ => Err(StrictCborError::InvalidField {
                field: "case_outcome".to_owned(),
            }),
        }
    }

    fn enum_redaction_state(value: RedactionStateV1) -> Value {
        uint(match value {
            RedactionStateV1::None => 0,
            RedactionStateV1::RedactedViews => 1,
            RedactionStateV1::StructuralOnly => 2,
            RedactionStateV1::EvidenceMissing => 3,
        })
    }

    fn decode_redaction_state(value: &Value) -> Result<RedactionStateV1, StrictCborError> {
        match uint_value(value, "redaction_state")? {
            0 => Ok(RedactionStateV1::None),
            1 => Ok(RedactionStateV1::RedactedViews),
            2 => Ok(RedactionStateV1::StructuralOnly),
            3 => Ok(RedactionStateV1::EvidenceMissing),
            _ => Err(StrictCborError::InvalidField {
                field: "redaction_state".to_owned(),
            }),
        }
    }

    fn enum_safe_error(value: SafeErrorCodeV1) -> Value {
        uint(match value {
            SafeErrorCodeV1::InvalidEncoding => 0,
            SafeErrorCodeV1::UnsupportedVersion => 1,
            SafeErrorCodeV1::FieldOutOfBounds => 2,
            SafeErrorCodeV1::NonCanonicalOrder => 3,
            SafeErrorCodeV1::DigestMismatch => 4,
            SafeErrorCodeV1::SignatureInvalid => 5,
            SafeErrorCodeV1::TrustRootUnknown => 6,
            SafeErrorCodeV1::TrustSnapshotRollback => 7,
            SafeErrorCodeV1::ArtifactRevoked => 8,
            SafeErrorCodeV1::ClosureIncomplete => 9,
            SafeErrorCodeV1::ProfileClassMismatch => 10,
            SafeErrorCodeV1::ProfileUnsupported => 11,
            SafeErrorCodeV1::ProvenanceMissing => 12,
            SafeErrorCodeV1::ResourceLimitExceeded => 13,
        })
    }

    fn decode_safe_error(value: &Value) -> Result<SafeErrorCodeV1, StrictCborError> {
        match uint_value(value, "safe_error")? {
            0 => Ok(SafeErrorCodeV1::InvalidEncoding),
            1 => Ok(SafeErrorCodeV1::UnsupportedVersion),
            2 => Ok(SafeErrorCodeV1::FieldOutOfBounds),
            3 => Ok(SafeErrorCodeV1::NonCanonicalOrder),
            4 => Ok(SafeErrorCodeV1::DigestMismatch),
            5 => Ok(SafeErrorCodeV1::SignatureInvalid),
            6 => Ok(SafeErrorCodeV1::TrustRootUnknown),
            7 => Ok(SafeErrorCodeV1::TrustSnapshotRollback),
            8 => Ok(SafeErrorCodeV1::ArtifactRevoked),
            9 => Ok(SafeErrorCodeV1::ClosureIncomplete),
            10 => Ok(SafeErrorCodeV1::ProfileClassMismatch),
            11 => Ok(SafeErrorCodeV1::ProfileUnsupported),
            12 => Ok(SafeErrorCodeV1::ProvenanceMissing),
            13 => Ok(SafeErrorCodeV1::ResourceLimitExceeded),
            _ => Err(StrictCborError::InvalidField {
                field: "safe_error".to_owned(),
            }),
        }
    }

    fn optional_safe_error(value: Option<SafeErrorCodeV1>) -> Value {
        optional(value.map(enum_safe_error))
    }

    fn decode_optional_safe_error(
        value: &Value,
    ) -> Result<Option<SafeErrorCodeV1>, StrictCborError> {
        if matches!(value, Value::Null) {
            Ok(None)
        } else {
            decode_safe_error(value).map(Some)
        }
    }

    fn enum_reproducibility(value: ReproducibilityClassV1) -> Value {
        uint(match value {
            ReproducibilityClassV1::RecordedReplay => 0,
            ReproducibilityClassV1::ProfileRecomputation => 1,
            ReproducibilityClassV1::CrossProfileConformance => 2,
            ReproducibilityClassV1::LiveUnverified => 3,
        })
    }

    fn decode_reproducibility(value: &Value) -> Result<ReproducibilityClassV1, StrictCborError> {
        match uint_value(value, "reproducibility_class")? {
            0 => Ok(ReproducibilityClassV1::RecordedReplay),
            1 => Ok(ReproducibilityClassV1::ProfileRecomputation),
            2 => Ok(ReproducibilityClassV1::CrossProfileConformance),
            3 => Ok(ReproducibilityClassV1::LiveUnverified),
            _ => Err(StrictCborError::InvalidField {
                field: "reproducibility_class".to_owned(),
            }),
        }
    }

    fn enum_replay_claim(value: ReplayClaimV1) -> Value {
        uint(match value {
            ReplayClaimV1::Exact => 0,
            ReplayClaimV1::ExactAuthoritativeWithRedactedViews => 1,
            ReplayClaimV1::StructuralOnly => 2,
            ReplayClaimV1::UnverifiableArtifactsMissing => 3,
            ReplayClaimV1::IncompatibleProfile => 4,
        })
    }

    fn decode_replay_claim(value: &Value) -> Result<ReplayClaimV1, StrictCborError> {
        match uint_value(value, "replay_claim")? {
            0 => Ok(ReplayClaimV1::Exact),
            1 => Ok(ReplayClaimV1::ExactAuthoritativeWithRedactedViews),
            2 => Ok(ReplayClaimV1::StructuralOnly),
            3 => Ok(ReplayClaimV1::UnverifiableArtifactsMissing),
            4 => Ok(ReplayClaimV1::IncompatibleProfile),
            _ => Err(StrictCborError::InvalidField {
                field: "replay_claim".to_owned(),
            }),
        }
    }

    fn encode_manifest(manifest: &ReproManifestV1) -> Value {
        Value::Array(vec![
            uint(u64::from(manifest.format_version)),
            digest(&manifest.input_digest),
            enum_mode(manifest.execution_mode),
            optional(manifest.fork_cut_seq.map(uint)),
            uint(manifest.seed),
            uint(manifest.resource_limit),
            Value::Bool(manifest.network_enabled),
            enum_reproducibility(manifest.reproducibility_class),
            text(&manifest.execution_profile),
            digest(&manifest.execution_profile_digest),
            digest(&manifest.trust_policy_snapshot_digest),
            digest(&manifest.artifact_closure_digest),
            digest(&manifest.evaluator_digest),
            enum_replay_claim(manifest.replay_claim),
            Value::Array(
                manifest
                    .plugin_versions
                    .iter()
                    .map(|(name, version)| Value::Array(vec![text(name), text(version)]))
                    .collect(),
            ),
            digest(&manifest.scenario_room_digest),
            digest(&manifest.scheduler_digest),
            digest(&manifest.budget_digest),
        ])
    }

    fn decode_manifest(value: &Value) -> Result<ReproManifestV1, StrictCborError> {
        let fields = array(value, "manifest", 18)?;
        let versions = array(&fields[14], "plugin_versions", plugin_len(&fields[14])?)?;
        let mut plugin_versions = BTreeMap::new();
        for pair in versions {
            let pair = array(pair, "plugin_version", 2)?;
            let name = string(&pair[0], "plugin_name")?;
            let version = string(&pair[1], "plugin_version")?;
            if plugin_versions.insert(name, version).is_some() {
                return Err(StrictCborError::InvalidField {
                    field: "duplicate_plugin".to_owned(),
                });
            }
        }
        Ok(ReproManifestV1 {
            format_version: u32::try_from(uint_value(&fields[0], "format_version")?).map_err(
                |_| StrictCborError::InvalidField {
                    field: "format_version".to_owned(),
                },
            )?,
            input_digest: bytes(&fields[1], "input_digest")?,
            execution_mode: decode_mode(&fields[2])?,
            fork_cut_seq: optional_u64(&fields[3], "fork_cut_seq")?,
            seed: uint_value(&fields[4], "seed")?,
            resource_limit: uint_value(&fields[5], "resource_limit")?,
            network_enabled: bool_value(&fields[6], "network_enabled")?,
            reproducibility_class: decode_reproducibility(&fields[7])?,
            execution_profile: string(&fields[8], "execution_profile")?,
            execution_profile_digest: bytes(&fields[9], "execution_profile_digest")?,
            trust_policy_snapshot_digest: bytes(&fields[10], "trust_policy_snapshot_digest")?,
            artifact_closure_digest: bytes(&fields[11], "artifact_closure_digest")?,
            evaluator_digest: bytes(&fields[12], "evaluator_digest")?,
            replay_claim: decode_replay_claim(&fields[13])?,
            plugin_versions,
            scenario_room_digest: bytes(&fields[15], "scenario_room_digest")?,
            scheduler_digest: bytes(&fields[16], "scheduler_digest")?,
            budget_digest: bytes(&fields[17], "budget_digest")?,
        })
    }

    fn plugin_len(value: &Value) -> Result<usize, StrictCborError> {
        match value {
            Value::Array(values) => Ok(values.len()),
            _ => Err(StrictCborError::InvalidField {
                field: "plugin_versions".to_owned(),
            }),
        }
    }

    fn encode_event(event: &AuthoritativeEventV1) -> Value {
        Value::Array(vec![
            uint(event.seq),
            uint(event.tick),
            text(&event.entity),
            text(&event.event_type),
            digest(&event.payload_digest),
            optional(event.causation_seq.map(uint)),
        ])
    }

    fn decode_event(value: &Value) -> Result<AuthoritativeEventV1, StrictCborError> {
        let fields = array(value, "event", 6)?;
        Ok(AuthoritativeEventV1 {
            seq: uint_value(&fields[0], "event_seq")?,
            tick: uint_value(&fields[1], "event_tick")?,
            entity: string(&fields[2], "event_entity")?,
            event_type: string(&fields[3], "event_type")?,
            payload_digest: bytes(&fields[4], "payload_digest")?,
            causation_seq: optional_u64(&fields[5], "causation_seq")?,
        })
    }

    fn decode_events(value: &Value) -> Result<Vec<AuthoritativeEventV1>, StrictCborError> {
        let values = array_values(value, "events")?;
        values.iter().map(decode_event).collect()
    }

    fn encode_projection(projection: &ProjectionEvidenceV1) -> Result<Value, StrictCborError> {
        let state = serde_json::to_vec(&projection.state)
            .map_err(|error| StrictCborError::Json(error.to_string()))?;
        Ok(Value::Array(vec![
            text(&projection.reducer),
            text(&projection.entity),
            Value::Bytes(state),
        ]))
    }

    fn decode_projection(value: &Value) -> Result<ProjectionEvidenceV1, StrictCborError> {
        let fields = array(value, "projection", 3)?;
        let Value::Bytes(state_bytes) = &fields[2] else {
            return Err(StrictCborError::InvalidField {
                field: "projection_state".to_owned(),
            });
        };
        let state = serde_json::from_slice(state_bytes)
            .map_err(|error| StrictCborError::Json(error.to_string()))?;
        Ok(ProjectionEvidenceV1 {
            reducer: string(&fields[0], "projection_reducer")?,
            entity: string(&fields[1], "projection_entity")?,
            state,
        })
    }

    fn decode_projections(value: &Value) -> Result<Vec<ProjectionEvidenceV1>, StrictCborError> {
        array_values(value, "projections")?
            .iter()
            .map(decode_projection)
            .collect()
    }

    fn encode_trace(trace: &CausalTraceEntryV1) -> Value {
        Value::Array(vec![
            uint(trace.cause_seq),
            uint(trace.effect_seq),
            text(&trace.relation),
            text(&trace.visibility),
            enum_dependency_class(trace.dependency_class),
        ])
    }

    fn decode_trace(value: &Value) -> Result<CausalTraceEntryV1, StrictCborError> {
        let fields = array(value, "causal_trace", 5)?;
        Ok(CausalTraceEntryV1 {
            cause_seq: uint_value(&fields[0], "cause_seq")?,
            effect_seq: uint_value(&fields[1], "effect_seq")?,
            relation: string(&fields[2], "causal_relation")?,
            visibility: string(&fields[3], "causal_visibility")?,
            dependency_class: decode_dependency_class(&fields[4])?,
        })
    }

    fn decode_traces(value: &Value) -> Result<Vec<CausalTraceEntryV1>, StrictCborError> {
        array_values(value, "causal_trace")?
            .iter()
            .map(decode_trace)
            .collect()
    }

    fn encode_uncertainty(claim: &UncertaintyV1) -> Result<Value, StrictCborError> {
        if !claim.lower.is_finite() || !claim.upper.is_finite() || !claim.confidence.is_finite() {
            return Err(StrictCborError::InvalidField {
                field: "uncertainty_float".to_owned(),
            });
        }
        Ok(Value::Array(vec![
            text(&claim.label),
            uint(claim.lower.to_bits()),
            uint(claim.upper.to_bits()),
            uint(claim.confidence.to_bits()),
        ]))
    }

    fn decode_uncertainty(value: &Value) -> Result<Vec<UncertaintyV1>, StrictCborError> {
        array_values(value, "uncertainty")?
            .iter()
            .map(|value| {
                let fields = array(value, "uncertainty_claim", 4)?;
                Ok(UncertaintyV1 {
                    label: string(&fields[0], "uncertainty_label")?,
                    lower: f64::from_bits(uint_value(&fields[1], "uncertainty_lower")?),
                    upper: f64::from_bits(uint_value(&fields[2], "uncertainty_upper")?),
                    confidence: f64::from_bits(uint_value(&fields[3], "uncertainty_confidence")?),
                })
            })
            .collect()
    }

    fn encode_participant_event(event: &ParticipantEventV1) -> Value {
        Value::Array(vec![
            uint(event.seq),
            text(&event.event_type),
            digest(&event.payload_digest),
        ])
    }

    fn decode_participant_event(value: &Value) -> Result<ParticipantEventV1, StrictCborError> {
        let fields = array(value, "participant_event", 3)?;
        Ok(ParticipantEventV1 {
            seq: uint_value(&fields[0], "participant_event_seq")?,
            event_type: string(&fields[1], "participant_event_type")?,
            payload_digest: bytes(&fields[2], "participant_event_digest")?,
        })
    }

    fn strings(values: &[String]) -> Value {
        Value::Array(values.iter().map(|value| text(value)).collect())
    }

    fn decode_strings(value: &Value, field: &str) -> Result<Vec<String>, StrictCborError> {
        array_values(value, field)?
            .iter()
            .map(|value| string(value, field))
            .collect()
    }

    fn encode_participant_view(view: &ParticipantViewV1) -> Value {
        Value::Array(vec![
            text(&view.participant),
            strings(&view.visible_event_types),
            strings(&view.hidden_event_types),
            Value::Array(
                view.visible_events
                    .iter()
                    .map(encode_participant_event)
                    .collect(),
            ),
        ])
    }

    fn decode_participant_view(value: &Value) -> Result<ParticipantViewV1, StrictCborError> {
        let fields = array(value, "participant_view", 4)?;
        Ok(ParticipantViewV1 {
            participant: string(&fields[0], "participant")?,
            visible_event_types: decode_strings(&fields[1], "visible_event_types")?,
            hidden_event_types: decode_strings(&fields[2], "hidden_event_types")?,
            visible_events: array_values(&fields[3], "visible_events")?
                .iter()
                .map(decode_participant_event)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }

    fn decode_participant_views(value: &Value) -> Result<Vec<ParticipantViewV1>, StrictCborError> {
        array_values(value, "participant_views")?
            .iter()
            .map(decode_participant_view)
            .collect()
    }

    fn encode_plugin_failure(failure: &PluginFailureV1) -> Value {
        Value::Array(vec![
            text(&failure.plugin),
            enum_plugin_failure(failure.class),
            uint(failure.tick),
            Value::Bool(failure.committed),
            uint(failure.staged_event_count),
            uint(failure.committed_event_count),
            digest(&failure.state_digest_before),
            digest(&failure.state_digest_after),
            uint(failure.sibling_step_count),
        ])
    }

    fn decode_plugin_failures(value: &Value) -> Result<Vec<PluginFailureV1>, StrictCborError> {
        array_values(value, "plugin_failures")?
            .iter()
            .map(|value| {
                let fields = array(value, "plugin_failure", 9)?;
                Ok(PluginFailureV1 {
                    plugin: string(&fields[0], "failure_plugin")?,
                    class: decode_plugin_failure(&fields[1])?,
                    tick: uint_value(&fields[2], "failure_tick")?,
                    committed: bool_value(&fields[3], "failure_committed")?,
                    staged_event_count: uint_value(&fields[4], "failure_staged")?,
                    committed_event_count: uint_value(&fields[5], "failure_committed_count")?,
                    state_digest_before: bytes(&fields[6], "failure_before")?,
                    state_digest_after: bytes(&fields[7], "failure_after")?,
                    sibling_step_count: uint_value(&fields[8], "failure_sibling_steps")?,
                })
            })
            .collect()
    }

    /// Encode the canonical consent-audit record for strict CBOR composition.
    #[must_use]
    pub fn encode_consent(audit: &ConsentAuditV1) -> Value {
        Value::Array(vec![
            text(&audit.subject),
            uint(audit.requested_after_seq),
            uint(audit.effective_after_seq),
            uint(audit.revocation_event_seq),
            text(&audit.revocation_event_type),
            digest(&audit.revocation_payload_digest),
            Value::Bool(audit.halted_at_tick_boundary),
        ])
    }

    /// Decode a canonical consent-audit record from a strict CBOR value.
    ///
    /// # Errors
    /// Returns [`StrictCborError`] when the value does not match the closed
    /// seven-field consent-audit shape.
    pub fn decode_consent(value: &Value) -> Result<ConsentAuditV1, StrictCborError> {
        let fields = array(value, "consent_audit", 7)?;
        Ok(ConsentAuditV1 {
            subject: string(&fields[0], "consent_subject")?,
            requested_after_seq: uint_value(&fields[1], "consent_requested_seq")?,
            effective_after_seq: uint_value(&fields[2], "consent_effective_seq")?,
            revocation_event_seq: uint_value(&fields[3], "consent_event_seq")?,
            revocation_event_type: string(&fields[4], "consent_event_type")?,
            revocation_payload_digest: bytes(&fields[5], "consent_digest")?,
            halted_at_tick_boundary: bool_value(&fields[6], "consent_boundary")?,
        })
    }

    fn encode_host_closure(audit: &HostClosureAuditV1) -> Value {
        Value::Array(vec![
            text(&audit.subject),
            uint(audit.requested_after_seq),
            uint(audit.effective_after_seq),
            uint(audit.closure_event_seq),
            text(&audit.closure_event_type),
            digest(&audit.closure_payload_digest),
            Value::Bool(audit.halted_at_tick_boundary),
        ])
    }

    fn decode_host_closure(value: &Value) -> Result<HostClosureAuditV1, StrictCborError> {
        let fields = array(value, "host_closure", 7)?;
        Ok(HostClosureAuditV1 {
            subject: string(&fields[0], "closure_subject")?,
            requested_after_seq: uint_value(&fields[1], "closure_requested_seq")?,
            effective_after_seq: uint_value(&fields[2], "closure_effective_seq")?,
            closure_event_seq: uint_value(&fields[3], "closure_event_seq")?,
            closure_event_type: string(&fields[4], "closure_event_type")?,
            closure_payload_digest: bytes(&fields[5], "closure_digest")?,
            halted_at_tick_boundary: bool_value(&fields[6], "closure_boundary")?,
        })
    }

    fn array_values<'a>(value: &'a Value, field: &str) -> Result<&'a [Value], StrictCborError> {
        match value {
            Value::Array(values) => Ok(values),
            _ => Err(StrictCborError::InvalidField {
                field: field.to_owned(),
            }),
        }
    }

    fn encode_principal(principal: &PrincipalRefV1) -> Value {
        Value::Array(vec![
            text(&principal.principal_id),
            text(&principal.participant_id),
            optional(principal.subject_id.as_deref().map(text)),
            text(&principal.trust_domain),
        ])
    }

    fn decode_principal(value: &Value) -> Result<PrincipalRefV1, StrictCborError> {
        let fields = array(value, "principal", 4)?;
        Ok(PrincipalRefV1 {
            principal_id: string(&fields[0], "principal_id")?,
            participant_id: string(&fields[1], "participant_id")?,
            subject_id: optional_string(&fields[2], "subject_id")?,
            trust_domain: string(&fields[3], "trust_domain")?,
        })
    }

    fn encode_grant(grant: &CapabilityGrantV1) -> Value {
        Value::Array(vec![
            text(&grant.grant_id),
            text(&grant.principal_id),
            text(&grant.capability),
            text(&grant.resource),
            uint(grant.consent_epoch),
            digest(&grant.policy_digest),
        ])
    }

    fn decode_grant(value: &Value) -> Result<CapabilityGrantV1, StrictCborError> {
        let fields = array(value, "grant", 6)?;
        Ok(CapabilityGrantV1 {
            grant_id: string(&fields[0], "grant_id")?,
            principal_id: string(&fields[1], "grant_principal")?,
            capability: string(&fields[2], "grant_capability")?,
            resource: string(&fields[3], "grant_resource")?,
            consent_epoch: uint_value(&fields[4], "grant_consent_epoch")?,
            policy_digest: bytes(&fields[5], "grant_policy_digest")?,
        })
    }

    fn encode_authorization(decision: &AuthorizationDecisionV1) -> Value {
        Value::Array(vec![
            text(&decision.principal_id),
            text(&decision.resource),
            text(&decision.operation),
            Value::Bool(decision.allowed),
            text(&decision.reason),
            uint(decision.consent_epoch),
            digest(&decision.grant_digest),
            digest(&decision.decision_digest),
        ])
    }

    fn decode_authorization(value: &Value) -> Result<AuthorizationDecisionV1, StrictCborError> {
        let fields = array(value, "authorization", 8)?;
        Ok(AuthorizationDecisionV1 {
            principal_id: string(&fields[0], "authorization_principal")?,
            resource: string(&fields[1], "authorization_resource")?,
            operation: string(&fields[2], "authorization_operation")?,
            allowed: bool_value(&fields[3], "authorization_allowed")?,
            reason: string(&fields[4], "authorization_reason")?,
            consent_epoch: uint_value(&fields[5], "authorization_consent_epoch")?,
            grant_digest: bytes(&fields[6], "authorization_grant_digest")?,
            decision_digest: bytes(&fields[7], "authorization_digest")?,
        })
    }

    fn digest_array(values: &[[u8; 32]]) -> Value {
        Value::Array(values.iter().map(digest).collect())
    }

    fn decode_digest_array(value: &Value, field: &str) -> Result<Vec<[u8; 32]>, StrictCborError> {
        array_values(value, field)?
            .iter()
            .map(|value| bytes(value, field))
            .collect()
    }

    fn encode_knowledge(snapshot: &KnowledgeSnapshotV1) -> Value {
        Value::Array(vec![
            text(&snapshot.participant_id),
            encode_principal(&snapshot.principal),
            encode_grant(&snapshot.grant),
            encode_authorization(&snapshot.authorization),
            uint(snapshot.tick),
            Value::Array(
                snapshot
                    .visible_event_seqs
                    .iter()
                    .copied()
                    .map(uint)
                    .collect(),
            ),
            digest_array(&snapshot.visible_event_digests),
            strings(&snapshot.hidden_event_types),
            uint(snapshot.consent_epoch),
            digest(&snapshot.snapshot_digest),
        ])
    }

    fn decode_knowledge(value: &Value) -> Result<KnowledgeSnapshotV1, StrictCborError> {
        let fields = array(value, "knowledge_snapshot", 10)?;
        let visible_event_seqs = array_values(&fields[5], "visible_event_seqs")?
            .iter()
            .map(|value| uint_value(value, "visible_event_seq"))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(KnowledgeSnapshotV1 {
            participant_id: string(&fields[0], "snapshot_participant")?,
            principal: decode_principal(&fields[1])?,
            grant: decode_grant(&fields[2])?,
            authorization: decode_authorization(&fields[3])?,
            tick: uint_value(&fields[4], "snapshot_tick")?,
            visible_event_seqs,
            visible_event_digests: decode_digest_array(&fields[6], "visible_event_digests")?,
            hidden_event_types: decode_strings(&fields[7], "snapshot_hidden_types")?,
            consent_epoch: uint_value(&fields[8], "snapshot_consent_epoch")?,
            snapshot_digest: bytes(&fields[9], "snapshot_digest")?,
        })
    }

    fn encode_room(room: &ScenarioRoomFixtureV1) -> Value {
        Value::Array(vec![
            text(&room.room_id),
            digest(&room.input_digest),
            uint(room.horizon_ticks),
            uint(room.random_seed),
            Value::Bool(room.network_enabled),
            digest_array(&room.exogenous_digests),
            digest_array(&room.fixed_policy_digests),
            Value::Array(room.principals.iter().map(encode_principal).collect()),
            Value::Array(room.grants.iter().map(encode_grant).collect()),
            digest(&room.room_digest),
        ])
    }

    fn decode_room(value: &Value) -> Result<ScenarioRoomFixtureV1, StrictCborError> {
        let fields = array(value, "scenario_room", 10)?;
        Ok(ScenarioRoomFixtureV1 {
            room_id: string(&fields[0], "room_id")?,
            input_digest: bytes(&fields[1], "room_input_digest")?,
            horizon_ticks: uint_value(&fields[2], "room_horizon")?,
            random_seed: uint_value(&fields[3], "room_seed")?,
            network_enabled: bool_value(&fields[4], "room_network")?,
            exogenous_digests: decode_digest_array(&fields[5], "room_exogenous")?,
            fixed_policy_digests: decode_digest_array(&fields[6], "room_fixed_policy")?,
            principals: array_values(&fields[7], "room_principals")?
                .iter()
                .map(decode_principal)
                .collect::<Result<Vec<_>, _>>()?,
            grants: array_values(&fields[8], "room_grants")?
                .iter()
                .map(decode_grant)
                .collect::<Result<Vec<_>, _>>()?,
            room_digest: bytes(&fields[9], "room_digest")?,
        })
    }

    fn encode_node(node: &DependencyNodeV1) -> Value {
        Value::Array(vec![
            uint(node.tick),
            uint(u64::from(node.scheduler_position)),
            text(&node.owner_id),
            uint(u64::from(node.output_ordinal)),
            uint(u64::from(node.schema_id)),
            digest(&node.artifact_digest),
        ])
    }

    fn decode_node(value: &Value) -> Result<DependencyNodeV1, StrictCborError> {
        let fields = array(value, "dependency_node", 6)?;
        Ok(DependencyNodeV1 {
            tick: uint_value(&fields[0], "node_tick")?,
            scheduler_position: u32::try_from(uint_value(&fields[1], "node_scheduler")?).map_err(
                |_| StrictCborError::InvalidField {
                    field: "node_scheduler".to_owned(),
                },
            )?,
            owner_id: string(&fields[2], "node_owner")?,
            output_ordinal: u32::try_from(uint_value(&fields[3], "node_ordinal")?).map_err(
                |_| StrictCborError::InvalidField {
                    field: "node_ordinal".to_owned(),
                },
            )?,
            schema_id: u32::try_from(uint_value(&fields[4], "node_schema")?).map_err(|_| {
                StrictCborError::InvalidField {
                    field: "node_schema".to_owned(),
                }
            })?,
            artifact_digest: bytes(&fields[5], "node_digest")?,
        })
    }

    fn encode_dependency(dependency: &InputDependencyV1) -> Value {
        Value::Array(vec![
            encode_node(&dependency.consumer),
            encode_node(&dependency.source),
            enum_dependency_class(dependency.dependency_class),
            digest(&dependency.authorization_digest),
            digest(&dependency.provenance_digest),
        ])
    }

    fn decode_dependency(value: &Value) -> Result<InputDependencyV1, StrictCborError> {
        let fields = array(value, "input_dependency", 5)?;
        Ok(InputDependencyV1 {
            consumer: decode_node(&fields[0])?,
            source: decode_node(&fields[1])?,
            dependency_class: decode_dependency_class(&fields[2])?,
            authorization_digest: bytes(&fields[3], "dependency_authorization")?,
            provenance_digest: bytes(&fields[4], "dependency_provenance")?,
        })
    }

    fn encode_intervention(intervention: &InterventionV1) -> Value {
        Value::Array(vec![
            digest16(&intervention.intervention_id),
            text(&intervention.target),
            text(&intervention.operation),
            digest(&intervention.value_digest),
            uint(intervention.effective_tick),
            uint(u64::from(intervention.ordinal)),
            text(&intervention.principal_id),
            text(&intervention.capability),
            uint(intervention.consent_epoch),
            digest(&intervention.provenance_digest),
        ])
    }

    fn decode_intervention(value: &Value) -> Result<InterventionV1, StrictCborError> {
        let fields = array(value, "intervention", 10)?;
        Ok(InterventionV1 {
            intervention_id: bytes(&fields[0], "intervention_id")?,
            target: string(&fields[1], "intervention_target")?,
            operation: string(&fields[2], "intervention_operation")?,
            value_digest: bytes(&fields[3], "intervention_value")?,
            effective_tick: uint_value(&fields[4], "intervention_tick")?,
            ordinal: u32::try_from(uint_value(&fields[5], "intervention_ordinal")?).map_err(
                |_| StrictCborError::InvalidField {
                    field: "intervention_ordinal".to_owned(),
                },
            )?,
            principal_id: string(&fields[6], "intervention_principal")?,
            capability: string(&fields[7], "intervention_capability")?,
            consent_epoch: uint_value(&fields[8], "intervention_consent")?,
            provenance_digest: bytes(&fields[9], "intervention_provenance")?,
        })
    }

    fn encode_owner_frontier(frontier: &OwnerFrontierV1) -> Value {
        Value::Array(vec![
            text(&frontier.owner_id),
            uint(frontier.earliest_tick),
            uint(u64::from(frontier.earliest_scheduler_position)),
            uint(u64::from(frontier.earliest_output_ordinal)),
            digest_array(&frontier.cause_node_digests),
        ])
    }

    fn decode_owner_frontier(value: &Value) -> Result<OwnerFrontierV1, StrictCborError> {
        let fields = array(value, "owner_frontier", 5)?;
        let earliest_scheduler_position =
            u32::try_from(uint_value(&fields[2], "frontier_scheduler")?).map_err(|_| {
                StrictCborError::InvalidField {
                    field: "frontier_scheduler".to_owned(),
                }
            })?;
        let earliest_output_ordinal = u32::try_from(uint_value(&fields[3], "frontier_ordinal")?)
            .map_err(|_| StrictCborError::InvalidField {
                field: "frontier_ordinal".to_owned(),
            })?;
        Ok(OwnerFrontierV1 {
            owner_id: string(&fields[0], "frontier_owner")?,
            earliest_tick: uint_value(&fields[1], "frontier_tick")?,
            earliest_scheduler_position,
            earliest_output_ordinal,
            cause_node_digests: decode_digest_array(&fields[4], "frontier_causes")?,
        })
    }

    fn encode_frontier(frontier: &RecomputationFrontierV1) -> Value {
        Value::Array(vec![
            text(RECOMPUTATION_FRONTIER_MAGIC_V1),
            uint(1),
            digest16(&frontier.frontier_id),
            digest(&frontier.plan_digest),
            digest(&frontier.parent_cut_digest),
            digest(&frontier.dependency_graph_digest),
            Value::Array(
                frontier
                    .intervention_seed_nodes
                    .iter()
                    .map(encode_node)
                    .collect(),
            ),
            Value::Array(frontier.affected_nodes.iter().map(encode_node).collect()),
            Value::Array(
                frontier
                    .owner_frontiers
                    .iter()
                    .map(encode_owner_frontier)
                    .collect(),
            ),
            uint(frontier.global_frontier_tick),
            uint(u64::from(frontier.global_frontier_scheduler_position)),
            enum_unknown_edge_policy(frontier.unknown_edge_policy),
            Value::Array(
                frontier
                    .unknown_edge_coordinates
                    .iter()
                    .map(encode_node)
                    .collect(),
            ),
            uint(frontier.endogenous_suffix_end_tick),
            digest(&frontier.classification_bundle_digest),
            digest(&frontier.provenance_digest),
            digest(&frontier.frontier_digest),
        ])
    }

    fn decode_frontier(value: &Value) -> Result<RecomputationFrontierV1, StrictCborError> {
        let fields = array(value, "recomputation_frontier", 17)?;
        if string(&fields[0], "frontier_magic")? != RECOMPUTATION_FRONTIER_MAGIC_V1
            || uint_value(&fields[1], "frontier_version")? != 1
        {
            return Err(StrictCborError::UnsupportedVersion);
        }
        let global_frontier_scheduler_position =
            u32::try_from(uint_value(&fields[10], "frontier_global_scheduler")?).map_err(|_| {
                StrictCborError::InvalidField {
                    field: "frontier_global_scheduler".to_owned(),
                }
            })?;
        Ok(RecomputationFrontierV1 {
            frontier_id: bytes(&fields[2], "frontier_id")?,
            plan_digest: bytes(&fields[3], "frontier_plan")?,
            parent_cut_digest: bytes(&fields[4], "frontier_parent_cut")?,
            dependency_graph_digest: bytes(&fields[5], "frontier_graph")?,
            intervention_seed_nodes: array_values(&fields[6], "frontier_seeds")?
                .iter()
                .map(decode_node)
                .collect::<Result<Vec<_>, _>>()?,
            affected_nodes: array_values(&fields[7], "frontier_affected")?
                .iter()
                .map(decode_node)
                .collect::<Result<Vec<_>, _>>()?,
            owner_frontiers: array_values(&fields[8], "frontier_owners")?
                .iter()
                .map(decode_owner_frontier)
                .collect::<Result<Vec<_>, _>>()?,
            global_frontier_tick: uint_value(&fields[9], "frontier_global_tick")?,
            global_frontier_scheduler_position,
            unknown_edge_policy: decode_unknown_edge_policy(&fields[11])?,
            unknown_edge_coordinates: array_values(&fields[12], "frontier_unknown_edges")?
                .iter()
                .map(decode_node)
                .collect::<Result<Vec<_>, _>>()?,
            endogenous_suffix_end_tick: uint_value(&fields[13], "frontier_end_tick")?,
            classification_bundle_digest: bytes(&fields[14], "frontier_classification")?,
            provenance_digest: bytes(&fields[15], "frontier_provenance")?,
            frontier_digest: bytes(&fields[16], "frontier_digest")?,
        })
    }

    fn encode_invalid_artifact(artifact: &InvalidArtifactV1) -> Value {
        Value::Array(vec![
            text(&artifact.artifact_class),
            uint(u64::from(artifact.schema_id)),
            digest(&artifact.artifact_digest),
            encode_node(&artifact.producer),
            uint(artifact.prior_generation),
            enum_invalidation_reason(artifact.reason),
        ])
    }

    fn decode_invalid_artifact(value: &Value) -> Result<InvalidArtifactV1, StrictCborError> {
        let fields = array(value, "invalid_artifact", 6)?;
        Ok(InvalidArtifactV1 {
            artifact_class: string(&fields[0], "artifact_class")?,
            schema_id: u32::try_from(uint_value(&fields[1], "artifact_schema")?).map_err(|_| {
                StrictCborError::InvalidField {
                    field: "artifact_schema".to_owned(),
                }
            })?,
            artifact_digest: bytes(&fields[2], "artifact_digest")?,
            producer: decode_node(&fields[3])?,
            prior_generation: uint_value(&fields[4], "artifact_generation")?,
            reason: decode_invalidation_reason(&fields[5])?,
        })
    }

    fn encode_invalidation(invalidation: &SuffixInvalidationV1) -> Value {
        Value::Array(vec![
            text(SUFFIX_INVALIDATION_MAGIC_V1),
            uint(1),
            digest16(&invalidation.invalidation_id),
            digest(&invalidation.plan_digest),
            digest16(&invalidation.fork_id),
            uint(invalidation.prior_generation),
            uint(invalidation.new_generation),
            digest(&invalidation.frontier_digest),
            encode_node(&invalidation.invalid_start),
            encode_node(&invalidation.invalid_end),
            Value::Array(
                invalidation
                    .invalid_artifacts
                    .iter()
                    .map(encode_invalid_artifact)
                    .collect(),
            ),
            digest_array(&invalidation.invalid_checkpoint_digests),
            digest_array(&invalidation.invalid_projection_digests),
            digest_array(&invalidation.retained_exogenous_digests),
            enum_invalidation_reason(invalidation.reason),
            Value::Array(vec![
                digest16(&invalidation.commit_timeline_id),
                uint(invalidation.commit_seq),
                uint(invalidation.commit_tick),
            ]),
            digest(&invalidation.provenance_digest),
            digest(&invalidation.invalidation_digest),
        ])
    }

    fn decode_invalidation(value: &Value) -> Result<SuffixInvalidationV1, StrictCborError> {
        let fields = array(value, "suffix_invalidation", 18)?;
        if string(&fields[0], "invalidation_magic")? != SUFFIX_INVALIDATION_MAGIC_V1
            || uint_value(&fields[1], "invalidation_version")? != 1
        {
            return Err(StrictCborError::UnsupportedVersion);
        }
        let commit_coordinate = array(&fields[15], "invalidation_commit_coordinate", 3)?;
        let commit_timeline_id = bytes(&commit_coordinate[0], "invalidation_commit_timeline")?;
        let commit_seq = uint_value(&commit_coordinate[1], "invalidation_commit_seq")?;
        let commit_tick = uint_value(&commit_coordinate[2], "invalidation_commit_tick")?;
        Ok(SuffixInvalidationV1 {
            invalidation_id: bytes(&fields[2], "invalidation_id")?,
            plan_digest: bytes(&fields[3], "invalidation_plan")?,
            fork_id: bytes(&fields[4], "invalidation_fork")?,
            prior_generation: uint_value(&fields[5], "invalidation_prior_generation")?,
            new_generation: uint_value(&fields[6], "invalidation_new_generation")?,
            frontier_digest: bytes(&fields[7], "invalidation_frontier")?,
            invalid_start: decode_node(&fields[8])?,
            invalid_end: decode_node(&fields[9])?,
            invalid_artifacts: array_values(&fields[10], "invalid_artifacts")?
                .iter()
                .map(decode_invalid_artifact)
                .collect::<Result<Vec<_>, _>>()?,
            invalid_checkpoint_digests: decode_digest_array(&fields[11], "invalid_checkpoints")?,
            invalid_projection_digests: decode_digest_array(&fields[12], "invalid_projections")?,
            retained_exogenous_digests: decode_digest_array(&fields[13], "retained_exogenous")?,
            reason: decode_invalidation_reason(&fields[14])?,
            commit_timeline_id,
            commit_seq,
            commit_tick,
            provenance_digest: bytes(&fields[16], "invalidation_provenance")?,
            invalidation_digest: bytes(&fields[17], "invalidation_digest")?,
        })
    }

    fn encode_counterfactual(contract: &CounterfactualContractV1) -> Value {
        Value::Array(vec![
            digest16(&contract.fork_id),
            uint(contract.prior_generation),
            uint(contract.generation),
            optional(contract.intervention.as_ref().map(encode_intervention)),
            Value::Array(
                contract
                    .dependencies
                    .iter()
                    .map(encode_dependency)
                    .collect(),
            ),
            encode_frontier(&contract.frontier),
            encode_invalidation(&contract.invalidation),
            Value::Array(
                contract
                    .recomputed_event_seqs
                    .iter()
                    .copied()
                    .map(uint)
                    .collect(),
            ),
            digest_array(&contract.retained_exogenous_digests),
            enum_replay_claim(contract.replay_claim),
            digest(&contract.contract_digest),
        ])
    }

    fn decode_counterfactual(value: &Value) -> Result<CounterfactualContractV1, StrictCborError> {
        let fields = array(value, "counterfactual_contract", 11)?;
        let intervention = if matches!(fields[3], Value::Null) {
            None
        } else {
            Some(decode_intervention(&fields[3])?)
        };
        Ok(CounterfactualContractV1 {
            fork_id: bytes(&fields[0], "contract_fork")?,
            prior_generation: uint_value(&fields[1], "contract_prior_generation")?,
            generation: uint_value(&fields[2], "contract_generation")?,
            intervention,
            dependencies: array_values(&fields[4], "contract_dependencies")?
                .iter()
                .map(decode_dependency)
                .collect::<Result<Vec<_>, _>>()?,
            frontier: decode_frontier(&fields[5])?,
            invalidation: decode_invalidation(&fields[6])?,
            recomputed_event_seqs: array_values(&fields[7], "recomputed_event_seqs")?
                .iter()
                .map(|value| uint_value(value, "recomputed_event_seq"))
                .collect::<Result<Vec<_>, _>>()?,
            retained_exogenous_digests: decode_digest_array(
                &fields[8],
                "contract_retained_exogenous",
            )?,
            replay_claim: decode_replay_claim(&fields[9])?,
            contract_digest: bytes(&fields[10], "contract_digest")?,
        })
    }

    fn encode_atomicity(atomicity: &TickAtomicityV1) -> Value {
        Value::Array(vec![
            uint(atomicity.tick),
            uint(atomicity.fork_generation),
            uint(atomicity.staged_event_count),
            uint(atomicity.committed_event_count),
            digest(&atomicity.state_digest_before),
            digest(&atomicity.state_digest_after),
            Value::Bool(atomicity.committed),
            optional(atomicity.failure_class.map(enum_plugin_failure)),
        ])
    }

    fn decode_atomicity(value: &Value) -> Result<TickAtomicityV1, StrictCborError> {
        let fields = array(value, "tick_atomicity", 8)?;
        Ok(TickAtomicityV1 {
            tick: uint_value(&fields[0], "atomicity_tick")?,
            fork_generation: uint_value(&fields[1], "atomicity_generation")?,
            staged_event_count: uint_value(&fields[2], "atomicity_staged")?,
            committed_event_count: uint_value(&fields[3], "atomicity_committed")?,
            state_digest_before: bytes(&fields[4], "atomicity_before")?,
            state_digest_after: bytes(&fields[5], "atomicity_after")?,
            committed: bool_value(&fields[6], "atomicity_committed_flag")?,
            failure_class: if matches!(fields[7], Value::Null) {
                None
            } else {
                Some(decode_plugin_failure(&fields[7])?)
            },
        })
    }

    fn encode_identity(identity: &ImplementationIdentityV1) -> Value {
        Value::Array(vec![
            text(&identity.implementation_id),
            digest(&identity.source_digest),
            digest(&identity.build_digest),
            digest(&identity.binary_digest),
            digest(&identity.public_contract_digest),
            optional(identity.organization_id.as_deref().map(text)),
        ])
    }

    fn decode_identity(value: &Value) -> Result<ImplementationIdentityV1, StrictCborError> {
        let fields = array(value, "implementation_identity", 6)?;
        Ok(ImplementationIdentityV1 {
            implementation_id: string(&fields[0], "implementation_id")?,
            source_digest: bytes(&fields[1], "implementation_source")?,
            build_digest: bytes(&fields[2], "implementation_build")?,
            binary_digest: bytes(&fields[3], "implementation_binary")?,
            public_contract_digest: bytes(&fields[4], "implementation_contract")?,
            organization_id: optional_string(&fields[5], "implementation_org")?,
        })
    }

    fn encode_independence(independence: &IndependenceEvidenceV1) -> Value {
        Value::Array(vec![
            Value::Bool(independence.technical_independent),
            Value::Bool(independence.authorship_independent),
            Value::Bool(independence.organizational_independent),
            digest(&independence.declaration_digest),
            digest(&independence.shared_code_audit_digest),
            strings(&independence.reviewer_ids),
        ])
    }

    fn decode_independence(value: &Value) -> Result<IndependenceEvidenceV1, StrictCborError> {
        let fields = array(value, "independence", 6)?;
        Ok(IndependenceEvidenceV1 {
            technical_independent: bool_value(&fields[0], "technical_independence")?,
            authorship_independent: bool_value(&fields[1], "authorship_independence")?,
            organizational_independent: bool_value(&fields[2], "organizational_independence")?,
            declaration_digest: bytes(&fields[3], "independence_declaration")?,
            shared_code_audit_digest: bytes(&fields[4], "independence_audit")?,
            reviewer_ids: decode_strings(&fields[5], "reviewer_ids")?,
        })
    }

    fn encode_case(case: &CaseOutcomeV1) -> Value {
        Value::Array(vec![
            text(&case.case_id),
            digest(&case.fixture_digest),
            digest(&case.execution_profile_digest),
            enum_mode(case.mode),
            enum_claim_layer(case.claim_layer),
            enum_case_outcome(case.outcome),
            optional(
                case.first_coordinate
                    .as_ref()
                    .map(|coordinate| Value::Bytes(coordinate.clone())),
            ),
            optional(case.expected_digest.as_ref().map(digest)),
            optional(case.actual_digest.as_ref().map(digest)),
            optional_safe_error(case.expected_error),
            optional_safe_error(case.actual_error),
            enum_replay_claim(case.replay_claim),
            enum_redaction_state(case.redaction_state),
            digest(&case.provenance_digest),
        ])
    }

    fn decode_case(value: &Value) -> Result<CaseOutcomeV1, StrictCborError> {
        let fields = array(value, "case_outcome", 14)?;
        Ok(CaseOutcomeV1 {
            case_id: string(&fields[0], "case_id")?,
            fixture_digest: bytes(&fields[1], "case_fixture")?,
            execution_profile_digest: bytes(&fields[2], "case_profile")?,
            mode: decode_mode(&fields[3])?,
            claim_layer: decode_claim_layer(&fields[4])?,
            outcome: decode_case_outcome(&fields[5])?,
            first_coordinate: if matches!(fields[6], Value::Null) {
                None
            } else {
                match &fields[6] {
                    Value::Bytes(bytes) if bytes.len() <= 128 => Some(bytes.clone()),
                    _ => {
                        return Err(StrictCborError::InvalidField {
                            field: "case_coordinate".to_owned(),
                        });
                    }
                }
            },
            expected_digest: if matches!(fields[7], Value::Null) {
                None
            } else {
                Some(bytes(&fields[7], "case_expected_digest")?)
            },
            actual_digest: if matches!(fields[8], Value::Null) {
                None
            } else {
                Some(bytes(&fields[8], "case_actual_digest")?)
            },
            expected_error: decode_optional_safe_error(&fields[9])?,
            actual_error: decode_optional_safe_error(&fields[10])?,
            replay_claim: decode_replay_claim(&fields[11])?,
            redaction_state: decode_redaction_state(&fields[12])?,
            provenance_digest: bytes(&fields[13], "case_provenance")?,
        })
    }

    fn enum_non_interference_variant(value: NonInterferenceVariantV1) -> Value {
        uint(match value {
            NonInterferenceVariantV1::Success => 0,
            NonInterferenceVariantV1::Denial => 1,
            NonInterferenceVariantV1::WarmCache => 2,
            NonInterferenceVariantV1::ColdCache => 3,
        })
    }

    fn decode_non_interference_variant(
        value: &Value,
    ) -> Result<NonInterferenceVariantV1, StrictCborError> {
        match uint_value(value, "non_interference_variant")? {
            0 => Ok(NonInterferenceVariantV1::Success),
            1 => Ok(NonInterferenceVariantV1::Denial),
            2 => Ok(NonInterferenceVariantV1::WarmCache),
            3 => Ok(NonInterferenceVariantV1::ColdCache),
            _ => Err(StrictCborError::InvalidField {
                field: "non_interference_variant".to_owned(),
            }),
        }
    }

    fn encode_non_interference_case(case: &NonInterferenceCaseV1) -> Value {
        Value::Array(vec![
            text(&case.fixture_id),
            enum_non_interference_variant(case.variant),
            enum_mode(case.mode),
            digest(&case.control_input_digest),
            digest(&case.canary_input_digest),
            digest(&case.authoritative_digest),
            digest(&case.public_digest),
            digest(&case.operational_digest),
            Value::Bool(case.authoritative_equal),
            Value::Bool(case.public_equal),
            Value::Bool(case.operational_equal),
            digest(&case.provenance_digest),
        ])
    }

    fn decode_non_interference_case(
        value: &Value,
    ) -> Result<NonInterferenceCaseV1, StrictCborError> {
        let fields = array(value, "non_interference_case", 12)?;
        Ok(NonInterferenceCaseV1 {
            fixture_id: string(&fields[0], "non_interference_fixture")?,
            variant: decode_non_interference_variant(&fields[1])?,
            mode: decode_mode(&fields[2])?,
            control_input_digest: bytes(&fields[3], "non_interference_control")?,
            canary_input_digest: bytes(&fields[4], "non_interference_canary")?,
            authoritative_digest: bytes(&fields[5], "non_interference_authoritative")?,
            public_digest: bytes(&fields[6], "non_interference_public")?,
            operational_digest: bytes(&fields[7], "non_interference_operational")?,
            authoritative_equal: bool_value(&fields[8], "non_interference_authoritative_equal")?,
            public_equal: bool_value(&fields[9], "non_interference_public_equal")?,
            operational_equal: bool_value(&fields[10], "non_interference_operational_equal")?,
            provenance_digest: bytes(&fields[11], "non_interference_provenance")?,
        })
    }

    pub(crate) fn encode_conformance_report(
        report: &ConformanceReportV1,
    ) -> Result<Vec<u8>, StrictCborError> {
        encode_value(&encode_report_value(report, true))
    }

    pub(crate) fn decode_conformance_report(
        bytes: &[u8],
    ) -> Result<ConformanceReportV1, StrictCborError> {
        let value = decode_value(bytes)?;
        decode_report(&value)
    }

    pub(crate) fn conformance_report_digest(
        report: &ConformanceReportV1,
    ) -> Result<[u8; 32], StrictCborError> {
        encode_value(&encode_report_value(report, false))
            .map(|bytes| domain_digest(b"PiglorOS.ConformanceReport.v1", &bytes))
    }

    pub(crate) fn encode_report_value(report: &ConformanceReportV1, include_digest: bool) -> Value {
        let mut fields = vec![
            text(CONFORMANCE_REPORT_MAGIC_V1),
            uint(1),
            digest16(&report.report_id),
            digest(&report.subject_artifact_digest),
            digest(&report.profile_digest),
            digest(&report.normative_spec_digest),
            digest(&report.execution_profile_digest),
            digest(&report.fixture_bundle_digest),
            digest(&report.evaluator_source_digest),
            digest(&report.evaluator_binary_digest),
            digest(&report.evaluator_protocol_digest),
            encode_identity(&report.implementation),
            encode_independence(&report.independence),
            Value::Array(report.cases.iter().map(encode_case).collect()),
            uint(u64::from(report.passed)),
            uint(u64::from(report.failed)),
            uint(u64::from(report.skipped)),
            uint(u64::from(report.unavailable)),
            uint(u64::from(report.not_applicable)),
            enum_replay_claim(report.replay_claim),
            enum_redaction_state(report.redaction_state),
            digest(&report.limitations_digest),
            digest(&report.provenance_digest),
        ];
        if include_digest {
            fields.push(digest(&report.report_digest));
        }
        Value::Array(fields)
    }

    fn decode_report(value: &Value) -> Result<ConformanceReportV1, StrictCborError> {
        let fields = array(value, "conformance_report", 24)?;
        if string(&fields[0], "report_magic")? != CONFORMANCE_REPORT_MAGIC_V1
            || uint_value(&fields[1], "report_version")? != 1
        {
            return Err(StrictCborError::UnsupportedVersion);
        }
        Ok(ConformanceReportV1 {
            report_id: bytes(&fields[2], "report_id")?,
            subject_artifact_digest: bytes(&fields[3], "report_subject")?,
            profile_digest: bytes(&fields[4], "report_profile")?,
            normative_spec_digest: bytes(&fields[5], "report_normative")?,
            execution_profile_digest: bytes(&fields[6], "report_execution_profile")?,
            fixture_bundle_digest: bytes(&fields[7], "report_fixture")?,
            evaluator_source_digest: bytes(&fields[8], "report_evaluator_source")?,
            evaluator_binary_digest: bytes(&fields[9], "report_evaluator_binary")?,
            evaluator_protocol_digest: bytes(&fields[10], "report_evaluator_protocol")?,
            implementation: decode_identity(&fields[11])?,
            independence: decode_independence(&fields[12])?,
            cases: array_values(&fields[13], "report_cases")?
                .iter()
                .map(decode_case)
                .collect::<Result<Vec<_>, _>>()?,
            passed: u32::try_from(uint_value(&fields[14], "report_passed")?).map_err(|_| {
                StrictCborError::InvalidField {
                    field: "report_passed".to_owned(),
                }
            })?,
            failed: u32::try_from(uint_value(&fields[15], "report_failed")?).map_err(|_| {
                StrictCborError::InvalidField {
                    field: "report_failed".to_owned(),
                }
            })?,
            skipped: u32::try_from(uint_value(&fields[16], "report_skipped")?).map_err(|_| {
                StrictCborError::InvalidField {
                    field: "report_skipped".to_owned(),
                }
            })?,
            unavailable: u32::try_from(uint_value(&fields[17], "report_unavailable")?).map_err(
                |_| StrictCborError::InvalidField {
                    field: "report_unavailable".to_owned(),
                },
            )?,
            not_applicable: u32::try_from(uint_value(&fields[18], "report_not_applicable")?)
                .map_err(|_| StrictCborError::InvalidField {
                    field: "report_not_applicable".to_owned(),
                })?,
            replay_claim: decode_replay_claim(&fields[19])?,
            redaction_state: decode_redaction_state(&fields[20])?,
            limitations_digest: bytes(&fields[21], "report_limitations")?,
            provenance_digest: bytes(&fields[22], "report_provenance")?,
            report_digest: bytes(&fields[23], "report_digest")?,
        })
    }

    fn encode_plugin_boundary(boundary: &PluginBoundaryV1) -> Value {
        Value::Array(vec![
            uint(u64::from(boundary.manifest_version)),
            text(&boundary.plugin_id),
            text(&boundary.world),
            uint(u64::from(boundary.abi_major)),
            uint(u64::from(boundary.min_abi_minor)),
            uint(u64::from(boundary.max_abi_minor)),
            digest(&boundary.wit_digest),
            digest(&boundary.component_digest),
            strings(&boundary.imported_interfaces),
            strings(&boundary.exported_interfaces),
            Value::Bool(boundary.network_allowed),
            Value::Bool(boundary.filesystem_allowed),
            Value::Bool(boundary.fresh_worker_required),
            uint(boundary.memory_bytes),
            uint(boundary.fuel),
            uint(u64::from(boundary.host_call_limit)),
            uint(u64::from(boundary.event_draft_limit)),
            uint(boundary.state_bytes_limit),
            uint(boundary.observation_bytes_limit),
            digest(&boundary.manifest_digest),
            digest(&boundary.release_digest),
        ])
    }

    fn decode_plugin_boundary(value: &Value) -> Result<PluginBoundaryV1, StrictCborError> {
        let fields = array(value, "plugin_boundary", 21)?;
        Ok(PluginBoundaryV1 {
            manifest_version: u32::try_from(uint_value(&fields[0], "plugin_manifest_version")?)
                .map_err(|_| StrictCborError::InvalidField {
                    field: "plugin_manifest_version".to_owned(),
                })?,
            plugin_id: string(&fields[1], "plugin_id")?,
            world: string(&fields[2], "plugin_world")?,
            abi_major: u16::try_from(uint_value(&fields[3], "plugin_abi_major")?).map_err(
                |_| StrictCborError::InvalidField {
                    field: "plugin_abi_major".to_owned(),
                },
            )?,
            min_abi_minor: u16::try_from(uint_value(&fields[4], "plugin_min_abi_minor")?).map_err(
                |_| StrictCborError::InvalidField {
                    field: "plugin_min_abi_minor".to_owned(),
                },
            )?,
            max_abi_minor: u16::try_from(uint_value(&fields[5], "plugin_max_abi_minor")?).map_err(
                |_| StrictCborError::InvalidField {
                    field: "plugin_max_abi_minor".to_owned(),
                },
            )?,
            wit_digest: bytes(&fields[6], "plugin_wit_digest")?,
            component_digest: bytes(&fields[7], "plugin_component_digest")?,
            imported_interfaces: decode_strings(&fields[8], "plugin_imports")?,
            exported_interfaces: decode_strings(&fields[9], "plugin_exports")?,
            network_allowed: bool_value(&fields[10], "plugin_network")?,
            filesystem_allowed: bool_value(&fields[11], "plugin_filesystem")?,
            fresh_worker_required: bool_value(&fields[12], "plugin_worker")?,
            memory_bytes: uint_value(&fields[13], "plugin_memory")?,
            fuel: uint_value(&fields[14], "plugin_fuel")?,
            host_call_limit: u32::try_from(uint_value(&fields[15], "plugin_host_calls")?).map_err(
                |_| StrictCborError::InvalidField {
                    field: "plugin_host_calls".to_owned(),
                },
            )?,
            event_draft_limit: u32::try_from(uint_value(&fields[16], "plugin_event_limit")?)
                .map_err(|_| StrictCborError::InvalidField {
                    field: "plugin_event_limit".to_owned(),
                })?,
            state_bytes_limit: uint_value(&fields[17], "plugin_state_bytes")?,
            observation_bytes_limit: uint_value(&fields[18], "plugin_observation_bytes")?,
            manifest_digest: bytes(&fields[19], "plugin_manifest_digest")?,
            release_digest: bytes(&fields[20], "plugin_release_digest")?,
        })
    }

    fn encode_contract(contract: &Wave8ProofContractV1) -> Value {
        Value::Array(vec![
            encode_room(&contract.scenario_room),
            encode_plugin_boundary(&contract.plugin_boundary),
            Value::Array(
                contract
                    .knowledge_snapshots
                    .iter()
                    .map(encode_knowledge)
                    .collect(),
            ),
            Value::Array(
                contract
                    .authorization_decisions
                    .iter()
                    .map(encode_authorization)
                    .collect(),
            ),
            encode_counterfactual(&contract.counterfactual),
            Value::Array(contract.atomicity.iter().map(encode_atomicity).collect()),
            encode_report_value(&contract.conformance_report, true),
            Value::Array(
                contract
                    .non_interference
                    .iter()
                    .map(encode_non_interference_case)
                    .collect(),
            ),
        ])
    }

    fn decode_contract(value: &Value) -> Result<Wave8ProofContractV1, StrictCborError> {
        let fields = array(value, "wave8_contract", 8)?;
        Ok(Wave8ProofContractV1 {
            scenario_room: decode_room(&fields[0])?,
            plugin_boundary: decode_plugin_boundary(&fields[1])?,
            knowledge_snapshots: array_values(&fields[2], "knowledge_snapshots")?
                .iter()
                .map(decode_knowledge)
                .collect::<Result<Vec<_>, _>>()?,
            authorization_decisions: array_values(&fields[3], "authorization_decisions")?
                .iter()
                .map(decode_authorization)
                .collect::<Result<Vec<_>, _>>()?,
            counterfactual: decode_counterfactual(&fields[4])?,
            atomicity: array_values(&fields[5], "atomicity")?
                .iter()
                .map(decode_atomicity)
                .collect::<Result<Vec<_>, _>>()?,
            conformance_report: decode_report(&fields[6])?,
            non_interference: array_values(&fields[7], "non_interference")?
                .iter()
                .map(decode_non_interference_case)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }

    #[cfg(test)]
    pub mod coverage_helpers {
        use super::*;

        macro_rules! strict_codec_coverage_cases {
            ($input:ident) => {{
                fn consume<T, E>(value: Result<T, E>) {
                    drop(std::hint::black_box(value));
                }

                fn replace_field(value: &Value, index: usize, replacement: Value) -> Value {
                    let mut fields = value.as_array().map_or_else(Vec::new, Clone::clone);
                    fields[index] = replacement;
                    Value::Array(fields)
                }

                fn reject_each_field<T, F>(value: &Value, decoder: F)
                where
                    F: Fn(&Value) -> Result<T, StrictCborError>,
                {
                    let fields = value.as_array().map_or(&[] as &[Value], Vec::as_slice);
                    for index in 0..fields.len() {
                        let invalid = replace_field(value, index, Value::Map(Vec::new()));
                        assert!(decoder(&invalid).is_err());
                    }
                }

                fn reject_each_encoded_field<T, F>(value: &Value, decoder: F)
                where
                    F: Fn(&[u8]) -> Result<T, StrictCborError>,
                {
                    let fields = value.as_array().map_or(&[] as &[Value], Vec::as_slice);
                    for index in 0..fields.len() {
                        let invalid = replace_field(value, index, text("wrong"));
                        let bytes = encode_value(&invalid).unwrap_or_default();
                        assert!(decoder(&bytes).is_err());
                    }
                }

                let evidence = $input;
                let contract = &evidence.contract;
                consume(encode_evidence(evidence));
                let evidence_value = decode_value(&encode_evidence(evidence).unwrap_or_default())
                    .unwrap_or(Value::Null);
                reject_each_encoded_field(&evidence_value, decode_evidence);
                let mut invalid_input = super::super::tests::input();
                invalid_input.initial_position[0] = f64::NAN;
                consume(invalid_input.digest());
                let mut invalid_serialization = evidence.clone();
                invalid_serialization.uncertainty[0].lower = f64::NAN;
                consume(invalid_serialization.to_canonical_cbor());
                consume(invalid_serialization.digest());
                consume(invalid_serialization.to_verification_result());
                consume(invalid_serialization.to_verification_result_cbor());
                consume(super::super::compare(&invalid_serialization, evidence));
                consume(super::super::compare(evidence, &invalid_serialization));
                consume(MoatProofEvidenceV1::from_canonical_cbor(&[0xff]));

                let manifest = encode_manifest(&evidence.manifest);
                consume(decode_manifest(&manifest));
                reject_each_field(&manifest, decode_manifest);
                let duplicate_plugins = replace_field(
                    &manifest,
                    14,
                    Value::Array(vec![
                        Value::Array(vec![text("world"), text("1")]),
                        Value::Array(vec![text("world"), text("2")]),
                    ]),
                );
                consume(decode_manifest(&duplicate_plugins));
                let invalid_plugin_pair =
                    replace_field(&manifest, 14, Value::Array(vec![Value::Map(Vec::new())]));
                consume(decode_manifest(&invalid_plugin_pair));
                let invalid_plugin_version = replace_field(
                    &manifest,
                    14,
                    Value::Array(vec![Value::Array(vec![text("world")])]),
                );
                consume(decode_manifest(&invalid_plugin_version));
                let invalid_plugin_version_value = replace_field(
                    &manifest,
                    14,
                    Value::Array(vec![Value::Array(vec![
                        text("world"),
                        Value::Map(Vec::new()),
                    ])]),
                );
                consume(decode_manifest(&invalid_plugin_version_value));
                consume(decode_manifest(&replace_field(&manifest, 14, Value::Null)));
                let invalid_plugin_name = replace_field(
                    &manifest,
                    14,
                    Value::Array(vec![Value::Array(vec![Value::Map(Vec::new()), text("1")])]),
                );
                consume(decode_manifest(&invalid_plugin_name));
                consume(plugin_len(&Value::Null));
                let bad_manifest = replace_field(&manifest, 0, uint(u64::MAX));
                consume(decode_manifest(&bad_manifest));

                let event = encode_event(&evidence.authoritative_events[0]);
                consume(decode_event(&event));
                reject_each_field(&event, decode_event);
                consume(decode_events(&Value::Array(vec![event])));
                consume(decode_events(&Value::Array(vec![Value::Map(Vec::new())])));
                let projection = encode_projection(&evidence.projections[0]).unwrap_or(Value::Null);
                consume(decode_projection(&projection));
                reject_each_field(&projection, decode_projection);
                consume(decode_projections(&Value::Array(vec![Value::Map(
                    Vec::new(),
                )])));
                let invalid_projection = replace_field(&projection, 2, text("not-json-bytes"));
                consume(decode_projection(&invalid_projection));
                let invalid_projection_json =
                    replace_field(&projection, 2, Value::Bytes(vec![0xff]));
                consume(decode_projection(&invalid_projection_json));
                let trace = encode_trace(&evidence.causal_trace[0]);
                consume(decode_trace(&trace));
                reject_each_field(&trace, decode_trace);
                consume(decode_traces(&Value::Array(vec![trace])));
                consume(decode_traces(&Value::Array(vec![Value::Map(Vec::new())])));
                consume(encode_uncertainty(&evidence.uncertainty[0]));
                let uncertainty =
                    encode_uncertainty(&evidence.uncertainty[0]).unwrap_or(Value::Null);
                reject_each_field(&uncertainty, |value| {
                    decode_uncertainty(&Value::Array(vec![value.clone()]))
                });
                consume(decode_uncertainty(&Value::Array(vec![Value::Map(
                    Vec::new(),
                )])));
                consume(encode_uncertainty(&UncertaintyV1 {
                    label: "non-finite".to_owned(),
                    lower: f64::NAN,
                    upper: 1.0,
                    confidence: 1.0,
                }));
                consume(decode_uncertainty(&Value::Array(vec![Value::Array(vec![
                    text("bad"),
                    text("lower"),
                    uint(0),
                    uint(0),
                ])])));

                let view = encode_participant_view(&evidence.participant_views[0]);
                consume(decode_participant_view(&view));
                reject_each_field(&view, decode_participant_view);
                let participant_event =
                    encode_participant_event(&evidence.participant_views[0].visible_events[0]);
                reject_each_field(&participant_event, decode_participant_event);
                let invalid_visible_events =
                    replace_field(&view, 3, Value::Array(vec![Value::Map(Vec::new())]));
                consume(decode_participant_view(&invalid_visible_events));
                consume(decode_participant_views(&Value::Array(vec![view])));
                consume(decode_participant_views(&Value::Array(vec![Value::Map(
                    Vec::new(),
                )])));
                let mut failure_evidence = evidence.clone();
                failure_evidence.plugin_failures = vec![PluginFailureV1 {
                    plugin: "proof".to_owned(),
                    class: PluginFailureClassV1::ResourceExhaustion,
                    tick: 2,
                    committed: false,
                    staged_event_count: 0,
                    committed_event_count: 0,
                    state_digest_before: [1; 32],
                    state_digest_after: [1; 32],
                    sibling_step_count: 1,
                }];
                consume(decode_plugin_failures(&Value::Array(vec![
                    encode_plugin_failure(&failure_evidence.plugin_failures[0]),
                ])));
                consume(decode_host_closure(&encode_host_closure(
                    &evidence.host_closure,
                )));
                let plugin_failure = encode_plugin_failure(&failure_evidence.plugin_failures[0]);
                reject_each_field(&plugin_failure, |value| {
                    decode_plugin_failures(&Value::Array(vec![value.clone()]))
                });
                consume(decode_plugin_failures(&Value::Array(vec![Value::Map(
                    Vec::new(),
                )])));
                let closure = encode_host_closure(&evidence.host_closure);
                reject_each_field(&closure, decode_host_closure);
                consume(array_values(&Value::Null, "not-an-array"));

                let principal = &contract.scenario_room.principals[0];
                consume(decode_principal(&encode_principal(principal)));
                let principal_value = encode_principal(principal);
                reject_each_field(&principal_value, decode_principal);
                let mut principal_with_subject = principal.clone();
                principal_with_subject.subject_id = Some("subject".to_owned());
                consume(decode_principal(&encode_principal(&principal_with_subject)));
                let grant = &contract.scenario_room.grants[0];
                consume(decode_grant(&encode_grant(grant)));
                let grant_value = encode_grant(grant);
                reject_each_field(&grant_value, decode_grant);
                let decision = &contract.authorization_decisions[0];
                consume(decode_authorization(&encode_authorization(decision)));
                let authorization_value = encode_authorization(decision);
                reject_each_field(&authorization_value, decode_authorization);
                consume(decode_digest_array(
                    &digest_array(&[[1; 32], [2; 32]]),
                    "digests",
                ));
                let digest_values = digest_array(&[[1; 32], [2; 32]]);
                reject_each_field(&digest_values, |value| {
                    decode_digest_array(value, "digests")
                });

                let snapshot = &contract.knowledge_snapshots[0];
                consume(decode_knowledge(&encode_knowledge(snapshot)));
                let knowledge_value = encode_knowledge(snapshot);
                reject_each_field(&knowledge_value, decode_knowledge);
                let invalid_knowledge_sequences = replace_field(
                    &knowledge_value,
                    5,
                    Value::Array(vec![Value::Map(Vec::new())]),
                );
                consume(decode_knowledge(&invalid_knowledge_sequences));
                let invalid_knowledge_hidden = replace_field(
                    &knowledge_value,
                    7,
                    Value::Array(vec![Value::Map(Vec::new())]),
                );
                consume(decode_knowledge(&invalid_knowledge_hidden));
                let room_value = encode_room(&contract.scenario_room);
                reject_each_field(&room_value, decode_room);
                for index in [5_usize, 6, 7, 8] {
                    let invalid_room_list = replace_field(
                        &room_value,
                        index,
                        Value::Array(vec![Value::Map(Vec::new())]),
                    );
                    consume(decode_room(&invalid_room_list));
                }
                consume(decode_room(&encode_room(&contract.scenario_room)));
                let counterfactual = &contract.counterfactual;
                consume(decode_dependency(&encode_dependency(
                    &counterfactual.dependencies[0],
                )));
                let dependency_value = encode_dependency(&counterfactual.dependencies[0]);
                reject_each_field(&dependency_value, decode_dependency);
                consume(decode_counterfactual(&Value::Array(vec![
                    digest16(&counterfactual.fork_id),
                    uint(counterfactual.prior_generation),
                    uint(counterfactual.generation),
                    Value::Null,
                    Value::Array(vec![Value::Map(Vec::new())]),
                    encode_frontier(&counterfactual.frontier),
                    encode_invalidation(&counterfactual.invalidation),
                    Value::Array(vec![uint(1)]),
                    digest_array(&counterfactual.retained_exogenous_digests),
                    enum_replay_claim(counterfactual.replay_claim),
                    digest(&counterfactual.contract_digest),
                ])));
                consume(decode_node(&encode_node(
                    &counterfactual.frontier.affected_nodes[0],
                )));
                let node_value = encode_node(&counterfactual.frontier.affected_nodes[0]);
                reject_each_field(&node_value, decode_node);
                consume(decode_owner_frontier(&encode_owner_frontier(
                    &counterfactual.frontier.owner_frontiers[0],
                )));
                let owner_value =
                    encode_owner_frontier(&counterfactual.frontier.owner_frontiers[0]);
                reject_each_field(&owner_value, decode_owner_frontier);
                consume(decode_frontier(&encode_frontier(&counterfactual.frontier)));
                let frontier_value = encode_frontier(&counterfactual.frontier);
                reject_each_field(&frontier_value, decode_frontier);
                for index in [6_usize, 7, 8, 12] {
                    let invalid_frontier_list = replace_field(
                        &frontier_value,
                        index,
                        Value::Array(vec![Value::Map(Vec::new())]),
                    );
                    consume(decode_frontier(&invalid_frontier_list));
                }
                consume(decode_invalid_artifact(&encode_invalid_artifact(
                    &counterfactual.invalidation.invalid_artifacts[0],
                )));
                let artifact_value =
                    encode_invalid_artifact(&counterfactual.invalidation.invalid_artifacts[0]);
                reject_each_field(&artifact_value, decode_invalid_artifact);
                consume(decode_invalidation(&encode_invalidation(
                    &counterfactual.invalidation,
                )));
                let invalidation_value = encode_invalidation(&counterfactual.invalidation);
                reject_each_field(&invalidation_value, decode_invalidation);
                for coordinate_index in [1_usize, 2] {
                    let coordinate = Value::Array(vec![
                        digest16(&counterfactual.invalidation.commit_timeline_id),
                        if coordinate_index == 1 {
                            Value::Map(Vec::new())
                        } else {
                            uint(counterfactual.invalidation.commit_seq)
                        },
                        if coordinate_index == 2 {
                            Value::Map(Vec::new())
                        } else {
                            uint(counterfactual.invalidation.commit_tick)
                        },
                    ]);
                    let invalid_commit = replace_field(&invalidation_value, 15, coordinate);
                    consume(decode_invalidation(&invalid_commit));
                }
                for index in [10_usize, 11, 12, 13] {
                    let invalid_artifact_list = replace_field(
                        &invalidation_value,
                        index,
                        Value::Array(vec![Value::Map(Vec::new())]),
                    );
                    consume(decode_invalidation(&invalid_artifact_list));
                }
                consume(decode_counterfactual(&encode_counterfactual(
                    counterfactual,
                )));
                let counterfactual_value = encode_counterfactual(counterfactual);
                reject_each_field(&counterfactual_value, decode_counterfactual);
                for index in [4_usize, 7] {
                    let invalid_recomputed = replace_field(
                        &counterfactual_value,
                        index,
                        Value::Array(vec![Value::Map(Vec::new())]),
                    );
                    consume(decode_counterfactual(&invalid_recomputed));
                }
                let intervention = InterventionV1 {
                    intervention_id: [21; 16],
                    target: "body".to_owned(),
                    operation: "set_velocity".to_owned(),
                    value_digest: [22; 32],
                    effective_tick: 2,
                    ordinal: 1,
                    principal_id: "principal:operator".to_owned(),
                    capability: "intervene".to_owned(),
                    consent_epoch: 0,
                    provenance_digest: [23; 32],
                };
                consume(decode_intervention(&encode_intervention(&intervention)));
                let intervention_value = encode_intervention(&intervention);
                reject_each_field(&intervention_value, decode_intervention);
                let mut counterfactual_with_intervention = counterfactual.clone();
                counterfactual_with_intervention.intervention = Some(intervention.clone());
                consume(decode_counterfactual(&encode_counterfactual(
                    &counterfactual_with_intervention,
                )));
                consume(decode_atomicity(&encode_atomicity(&TickAtomicityV1 {
                    failure_class: Some(PluginFailureClassV1::PluginCrash),
                    committed: false,
                    committed_event_count: 0,
                    state_digest_before: [1; 32],
                    state_digest_after: [1; 32],
                    ..evidence.contract.atomicity[0].clone()
                })));
                let atomicity_value = encode_atomicity(&evidence.contract.atomicity[0]);
                reject_each_field(&atomicity_value, decode_atomicity);
                consume(decode_identity(&encode_identity(
                    &contract.conformance_report.implementation,
                )));
                let identity_value = encode_identity(&contract.conformance_report.implementation);
                reject_each_field(&identity_value, decode_identity);
                consume(decode_independence(&encode_independence(
                    &contract.conformance_report.independence,
                )));
                let independence_value =
                    encode_independence(&contract.conformance_report.independence);
                reject_each_field(&independence_value, decode_independence);
                consume(decode_case(&encode_case(
                    &contract.conformance_report.cases[0],
                )));
                let case_value = encode_case(&contract.conformance_report.cases[0]);
                reject_each_field(&case_value, decode_case);

                let mut case_with_all_optionals = contract.conformance_report.cases[0].clone();
                case_with_all_optionals.first_coordinate = Some(b"tick=1".to_vec());
                case_with_all_optionals.expected_digest = Some([24; 32]);
                case_with_all_optionals.actual_digest = Some([25; 32]);
                case_with_all_optionals.expected_error = Some(SafeErrorCodeV1::DigestMismatch);
                case_with_all_optionals.actual_error = Some(SafeErrorCodeV1::ResourceLimitExceeded);
                consume(decode_case(&encode_case(&case_with_all_optionals)));
                consume(decode_report(&encode_report_value(
                    &contract.conformance_report,
                    true,
                )));
                let report_value_all_fields =
                    encode_report_value(&contract.conformance_report, true);
                reject_each_field(&report_value_all_fields, decode_report);
                consume(decode_plugin_boundary(&encode_plugin_boundary(
                    &contract.plugin_boundary,
                )));
                let plugin_boundary_value = encode_plugin_boundary(&contract.plugin_boundary);
                reject_each_field(&plugin_boundary_value, decode_plugin_boundary);
                for index in [8_usize, 9] {
                    let invalid_interfaces = replace_field(
                        &plugin_boundary_value,
                        index,
                        Value::Array(vec![Value::Map(Vec::new())]),
                    );
                    consume(decode_plugin_boundary(&invalid_interfaces));
                }
                consume(decode_non_interference_case(&encode_non_interference_case(
                    &contract.non_interference[0],
                )));
                let non_interference_value =
                    encode_non_interference_case(&contract.non_interference[0]);
                reject_each_field(&non_interference_value, decode_non_interference_case);
                consume(decode_contract(&encode_contract(contract)));
                let contract_value = encode_contract(contract);
                reject_each_field(&contract_value, decode_contract);
                for index in [2_usize, 3, 5, 7] {
                    let invalid_contract_lists = replace_field(
                        &contract_value,
                        index,
                        Value::Array(vec![Value::Map(Vec::new())]),
                    );
                    consume(decode_contract(&invalid_contract_lists));
                }

                let plugin_boundary = encode_plugin_boundary(&contract.plugin_boundary);
                for index in [0_usize, 3, 4, 5, 15, 16] {
                    let invalid = replace_field(&plugin_boundary, index, uint(u64::MAX));
                    consume(decode_plugin_boundary(&invalid));
                }

                let report_value = encode_report_value(&contract.conformance_report, true);
                for index in [14_usize, 15, 16, 17, 18] {
                    let invalid = replace_field(&report_value, index, uint(u64::MAX));
                    consume(decode_report(&invalid));
                }
                let invalid_report_cases = replace_field(
                    &report_value,
                    13,
                    Value::Array(vec![Value::Map(Vec::new())]),
                );
                consume(decode_report(&invalid_report_cases));
                let invalid_report = replace_field(&report_value, 0, text("wrong"));
                consume(decode_report(&invalid_report));

                let mut invalid_node = encode_node(&counterfactual.frontier.affected_nodes[0]);
                for index in [1_usize, 3, 4] {
                    invalid_node = replace_field(&invalid_node, index, uint(u64::MAX));
                    consume(decode_node(&invalid_node));
                    invalid_node = encode_node(&counterfactual.frontier.affected_nodes[0]);
                }
                let mut invalid_owner =
                    encode_owner_frontier(&counterfactual.frontier.owner_frontiers[0]);
                for index in [2_usize, 3] {
                    invalid_owner = replace_field(&invalid_owner, index, uint(u64::MAX));
                    consume(decode_owner_frontier(&invalid_owner));
                    invalid_owner =
                        encode_owner_frontier(&counterfactual.frontier.owner_frontiers[0]);
                }
                let invalid_intervention = replace_field(
                    &encode_intervention(
                        &counterfactual_with_intervention
                            .intervention
                            .unwrap_or(intervention),
                    ),
                    5,
                    uint(u64::MAX),
                );
                consume(decode_intervention(&invalid_intervention));
                let invalid_artifact = replace_field(
                    &encode_invalid_artifact(&counterfactual.invalidation.invalid_artifacts[0]),
                    1,
                    uint(u64::MAX),
                );
                consume(decode_invalid_artifact(&invalid_artifact));
                let invalid_frontier = replace_field(&frontier_value, 1, uint(2));
                consume(decode_frontier(&invalid_frontier));
                let invalid_invalidation = replace_field(&invalidation_value, 1, uint(2));
                consume(decode_invalidation(&invalid_invalidation));

                let Some(result) = evidence.to_verification_result().ok() else {
                    return;
                };
                consume(encode_verification_result(&result));
                consume(verification_result_digest(&result));
                let verification_value = encode_verification_result_value(&result, true);
                reject_each_field(&verification_value, |value| {
                    array(value, "verification_result", 18)
                        .and_then(decode_verification_result_fields)
                });
                reject_each_encoded_field(&verification_value, decode_verification_result);
                let error = VerificationErrorV1 {
                    code: SafeErrorCodeV1::InvalidEncoding,
                    field_ordinal: Some(7),
                    canonical_coordinate: Some(vec![1, 2, 3]),
                    related_digest: Some([26; 32]),
                };
                consume(decode_verification_error(&encode_verification_error(
                    &error,
                )));
                for outcome in [
                    VerificationOutcomeV1::VerifiedExact,
                    VerificationOutcomeV1::Diverged,
                    VerificationOutcomeV1::InvalidManifest,
                    VerificationOutcomeV1::UnverifiableArtifactsMissing,
                    VerificationOutcomeV1::IncompatibleProfile,
                    VerificationOutcomeV1::ResourceLimitExceeded,
                ] {
                    let mut candidate = result.clone();
                    candidate.verification_outcome = outcome;
                    candidate.authoritative_result_digest =
                        (outcome == VerificationOutcomeV1::VerifiedExact).then_some([27; 32]);
                    candidate.divergence_report_digest =
                        (outcome == VerificationOutcomeV1::Diverged).then_some([28; 32]);
                    candidate.first_error = if matches!(
                        outcome,
                        VerificationOutcomeV1::InvalidManifest
                            | VerificationOutcomeV1::UnverifiableArtifactsMissing
                            | VerificationOutcomeV1::IncompatibleProfile
                            | VerificationOutcomeV1::ResourceLimitExceeded
                    ) {
                        Some(error.clone())
                    } else {
                        None
                    };
                    consume(validate_verification_result(&candidate));
                }
                let mut invalid_error_result = result;
                invalid_error_result.verification_outcome = VerificationOutcomeV1::InvalidManifest;
                invalid_error_result.authoritative_result_digest = None;
                invalid_error_result.first_error = Some(VerificationErrorV1 {
                    canonical_coordinate: Some(vec![0; 129]),
                    ..error
                });
                consume(validate_verification_result(&invalid_error_result));
                for code in [
                    SafeErrorCodeV1::InvalidEncoding,
                    SafeErrorCodeV1::UnsupportedVersion,
                    SafeErrorCodeV1::FieldOutOfBounds,
                    SafeErrorCodeV1::NonCanonicalOrder,
                    SafeErrorCodeV1::DigestMismatch,
                    SafeErrorCodeV1::SignatureInvalid,
                    SafeErrorCodeV1::TrustRootUnknown,
                    SafeErrorCodeV1::TrustSnapshotRollback,
                    SafeErrorCodeV1::ArtifactRevoked,
                    SafeErrorCodeV1::ClosureIncomplete,
                    SafeErrorCodeV1::ProfileClassMismatch,
                    SafeErrorCodeV1::ProfileUnsupported,
                    SafeErrorCodeV1::ProvenanceMissing,
                    SafeErrorCodeV1::ResourceLimitExceeded,
                ] {
                    consume(decode_safe_error(&enum_safe_error(code)));
                }
                consume(decode_safe_error(&uint(99)));
                for value in [
                    VerificationOutcomeV1::VerifiedExact,
                    VerificationOutcomeV1::Diverged,
                    VerificationOutcomeV1::InvalidManifest,
                    VerificationOutcomeV1::UnverifiableArtifactsMissing,
                    VerificationOutcomeV1::IncompatibleProfile,
                    VerificationOutcomeV1::ResourceLimitExceeded,
                ] {
                    consume(decode_verification_outcome(&enum_verification_outcome(
                        value,
                    )));
                }
                consume(decode_verification_outcome(&uint(99)));

                let mut report = DivergenceReportV1 {
                    request_digest: [1; 32],
                    manifest_digest: [2; 32],
                    execution_profile_digest: [3; 32],
                    fixture_digest: Some([4; 32]),
                    evaluator_digest: [5; 32],
                    reproducibility_class: ReproducibilityClassV1::CrossProfileConformance,
                    replay_claim: ReplayClaimV1::StructuralOnly,
                    location_kind: DivergenceLocationKindV1::DriverOutput,
                    timeline_or_worldcut_id: [6; 16],
                    timeline_seq_or_cut_ordinal: 3,
                    tick: 2,
                    scheduler_position: Some(1),
                    driver_or_plugin_id: Some("proof".to_owned()),
                    output_ordinal: Some(1),
                    mismatch_kind: DivergenceMismatchKindV1::Artifact,
                    expected: DigestSizeV1 {
                        digest: Some([7; 32]),
                        size: Some(8),
                    },
                    actual: DigestSizeV1 {
                        digest: Some([9; 32]),
                        size: Some(10),
                    },
                    prior_matching_checkpoint_digest: Some([11; 32]),
                    follow_on_counts: vec![FollowOnMismatchV1 {
                        kind: DivergenceMismatchKindV1::EventIdentity,
                        count: 1,
                    }],
                    report_digest: [0; 32],
                };
                report.report_digest = report.digest().unwrap_or([29; 32]);
                let mut zero_follow_on = report.clone();
                zero_follow_on.follow_on_counts = vec![
                    FollowOnMismatchV1 {
                        kind: DivergenceMismatchKindV1::EventIdentity,
                        count: 0,
                    },
                    FollowOnMismatchV1 {
                        kind: DivergenceMismatchKindV1::EventOrder,
                        count: 1,
                    },
                ];
                consume(validate_divergence_report(&zero_follow_on));
                zero_follow_on.follow_on_counts[0].count = 1;
                zero_follow_on.follow_on_counts[1].count = 0;
                consume(validate_divergence_report(&zero_follow_on));
                let report_value = encode_divergence_report_value(&report, true);
                if let Value::Array(fields) = &report_value {
                    consume(decode_divergence_report_fields(fields));
                }
                reject_each_field(&report_value, |value| {
                    array(value, "divergence_report", 22).and_then(decode_divergence_report_fields)
                });
                reject_each_encoded_field(&report_value, decode_divergence_report);
                consume(encode_divergence_report(&report));
                if let Ok(bytes) = report.to_canonical_cbor() {
                    consume(decode_divergence_report(&bytes));
                }
                for value in [
                    DivergenceLocationKindV1::TimelineSeq,
                    DivergenceLocationKindV1::WorldCut,
                    DivergenceLocationKindV1::TickBoundary,
                    DivergenceLocationKindV1::Scheduler,
                    DivergenceLocationKindV1::DriverOutput,
                ] {
                    consume(decode_divergence_location(&enum_divergence_location(value)));
                }
                consume(decode_divergence_location(&uint(99)));
                for value in [
                    DivergenceMismatchKindV1::EventIdentity,
                    DivergenceMismatchKindV1::EventOrder,
                    DivergenceMismatchKindV1::CanonicalBytes,
                    DivergenceMismatchKindV1::ProjectionCheckpoint,
                    DivergenceMismatchKindV1::TypedFailure,
                    DivergenceMismatchKindV1::Artifact,
                    DivergenceMismatchKindV1::SchemaOrUpcaster,
                    DivergenceMismatchKindV1::NumericProfile,
                    DivergenceMismatchKindV1::ProhibitedOperationalInput,
                ] {
                    consume(decode_divergence_mismatch(&enum_divergence_mismatch(value)));
                }
                consume(decode_divergence_mismatch(&uint(99)));
                consume(decode_digest_size(
                    &encode_digest_size(&report.expected),
                    "digest_size",
                ));
                consume(decode_digest_size(
                    &encode_digest_size(&DigestSizeV1 {
                        digest: None,
                        size: None,
                    }),
                    "digest_size",
                ));
                let digest_size_value = encode_digest_size(&report.expected);
                reject_each_field(&digest_size_value, |value| {
                    decode_digest_size(value, "digest_size")
                });
                let follow_on_count = Value::Array(vec![
                    enum_divergence_mismatch(DivergenceMismatchKindV1::EventIdentity),
                    uint(1),
                ]);
                reject_each_field(&follow_on_count, |value| {
                    decode_follow_on_counts(&Value::Array(vec![value.clone()]))
                });
                consume(decode_follow_on_counts(&Value::Array(vec![Value::Array(
                    vec![
                        enum_divergence_mismatch(DivergenceMismatchKindV1::EventIdentity),
                        uint(u64::MAX),
                    ],
                )])));
                consume(decode_follow_on_counts(&Value::Array(vec![Value::Map(
                    Vec::new(),
                )])));
                consume(decode_follow_on_counts(&Value::Array(vec![
                    Value::Array(vec![
                        enum_divergence_mismatch(DivergenceMismatchKindV1::EventIdentity),
                        uint(1),
                    ]),
                    Value::Array(vec![
                        enum_divergence_mismatch(DivergenceMismatchKindV1::EventIdentity),
                        uint(1),
                    ]),
                ])));
                consume(decode_optional_u32(&Value::Null, "optional_u32"));
                consume(decode_optional_u32(&uint(u64::MAX), "optional_u32"));
                consume(decode_optional_digest(&Value::Null, "optional_digest"));
                consume(decode_optional_digest(
                    &digest(&[30; 32]),
                    "optional_digest",
                ));

                let mutations: [fn(&mut DivergenceReportV1); 6] = [
                    |value: &mut DivergenceReportV1| value.timeline_seq_or_cut_ordinal = u64::MAX,
                    |value: &mut DivergenceReportV1| value.tick = u64::MAX,
                    |value: &mut DivergenceReportV1| value.scheduler_position = Some(u32::MAX),
                    |value: &mut DivergenceReportV1| value.output_ordinal = Some(u32::MAX),
                    |value: &mut DivergenceReportV1| {
                        value.driver_or_plugin_id = Some(String::new())
                    },
                    |value: &mut DivergenceReportV1| value.report_digest = [0; 32],
                ];
                for mutate in mutations {
                    let mut invalid_report = report.clone();
                    mutate(&mut invalid_report);
                    consume(validate_divergence_report(&invalid_report));
                }
                let mut invalid_report = report.clone();
                invalid_report.follow_on_counts = (0..33)
                    .map(|_| FollowOnMismatchV1 {
                        kind: DivergenceMismatchKindV1::EventIdentity,
                        count: 1,
                    })
                    .collect();
                consume(validate_divergence_report(&invalid_report));
                invalid_report = report;
                invalid_report.follow_on_counts = vec![
                    FollowOnMismatchV1 {
                        kind: DivergenceMismatchKindV1::EventOrder,
                        count: 1,
                    },
                    FollowOnMismatchV1 {
                        kind: DivergenceMismatchKindV1::EventIdentity,
                        count: 1,
                    },
                ];
                consume(validate_divergence_report(&invalid_report));
                invalid_report.follow_on_counts[1].kind = DivergenceMismatchKindV1::EventOrder;
                consume(validate_divergence_report(&invalid_report));

                consume(decode_value(&[0xff]));
                consume(decode_value(&[0, 0]));
                consume(decode_value(&[0x18, 0]));
                consume(decode_value(&[0xa0]));
                assert_eq!(
                    encode_value(&Value::Map(Vec::new())),
                    Err(StrictCborError::ForbiddenValue)
                );
                consume(encode_value(&Value::Tag(0, Box::new(Value::Null))));
                consume(encode_value(&Value::Float(1.0)));
                consume(validate_value(&Value::Array(vec![Value::Null])));
                consume(validate_value(&Value::Integer((-1_i64).into())));
                consume(array(&Value::Null, "array", 0));
                consume(array(&Value::Array(Vec::new()), "array", 1));
                consume(string(&Value::Null, "string"));
                consume(bytes::<32>(&Value::Bytes(vec![1]), "bytes"));
                consume(uint_value(&Value::Integer((-1_i64).into()), "uint"));
                consume(bool_value(&Value::Null, "bool"));
                consume(optional_u64(&Value::Null, "optional"));
                consume(optional_string(&Value::Null, "optional"));

                let all_enums = vec![
                    enum_dependency_class(DependencyClassV1::ExogenousFrozen),
                    enum_dependency_class(DependencyClassV1::InterventionAssigned),
                    enum_dependency_class(DependencyClassV1::EndogenousRecomputed),
                    enum_dependency_class(DependencyClassV1::FixedPolicy),
                    enum_dependency_class(DependencyClassV1::PresentationOnly),
                ];
                for value in all_enums {
                    consume(decode_dependency_class(&value));
                }
                consume(decode_dependency_class(&uint(99)));
                for value in [
                    PluginFailureClassV1::PluginCrash,
                    PluginFailureClassV1::ResourceExhaustion,
                ] {
                    consume(decode_plugin_failure(&enum_plugin_failure(value)));
                }
                consume(decode_plugin_failure(&uint(99)));
                for value in [
                    UnknownEdgePolicyV1::Reject,
                    UnknownEdgePolicyV1::FullSuffixFromCut,
                ] {
                    consume(decode_unknown_edge_policy(&enum_unknown_edge_policy(value)));
                }
                consume(decode_unknown_edge_policy(&uint(99)));
                for value in [
                    SuffixInvalidationReasonV1::NewIntervention,
                    SuffixInvalidationReasonV1::ChangedIntervention,
                    SuffixInvalidationReasonV1::UnknownEdgeFallback,
                    SuffixInvalidationReasonV1::RetryAfterAtomicFailure,
                    SuffixInvalidationReasonV1::TrustOrErasureChange,
                ] {
                    consume(decode_invalidation_reason(&enum_invalidation_reason(value)));
                }
                consume(decode_invalidation_reason(&uint(99)));
                for value in [
                    ExecutionModeV1::Local,
                    ExecutionModeV1::AirGapped,
                    ExecutionModeV1::Replay,
                    ExecutionModeV1::Fork,
                ] {
                    consume(decode_mode(&enum_mode(value)));
                }
                consume(decode_mode(&uint(99)));
                for value in [
                    ClaimLayerV1::ArtifactIntegrity,
                    ClaimLayerV1::ReplayConformance,
                    ClaimLayerV1::KnowledgeNonInterference,
                    ClaimLayerV1::GatewayClientConformance,
                    ClaimLayerV1::PluginConformance,
                    ClaimLayerV1::MetricConformance,
                    ClaimLayerV1::EmpiricalEvaluation,
                ] {
                    consume(decode_claim_layer(&enum_claim_layer(value)));
                }
                consume(decode_claim_layer(&uint(99)));
                for value in [
                    CaseOutcomeStatusV1::Pass,
                    CaseOutcomeStatusV1::Fail,
                    CaseOutcomeStatusV1::Skip,
                    CaseOutcomeStatusV1::Unavailable,
                    CaseOutcomeStatusV1::NotApplicable,
                ] {
                    consume(decode_case_outcome(&enum_case_outcome(value)));
                }
                consume(decode_case_outcome(&uint(99)));
                for value in [
                    RedactionStateV1::None,
                    RedactionStateV1::RedactedViews,
                    RedactionStateV1::StructuralOnly,
                    RedactionStateV1::EvidenceMissing,
                ] {
                    consume(decode_redaction_state(&enum_redaction_state(value)));
                }
                consume(decode_redaction_state(&uint(99)));
                for value in [
                    ReproducibilityClassV1::RecordedReplay,
                    ReproducibilityClassV1::ProfileRecomputation,
                    ReproducibilityClassV1::CrossProfileConformance,
                    ReproducibilityClassV1::LiveUnverified,
                ] {
                    consume(decode_reproducibility(&enum_reproducibility(value)));
                }
                consume(decode_reproducibility(&uint(99)));
                for value in [
                    ReplayClaimV1::Exact,
                    ReplayClaimV1::ExactAuthoritativeWithRedactedViews,
                    ReplayClaimV1::StructuralOnly,
                    ReplayClaimV1::UnverifiableArtifactsMissing,
                    ReplayClaimV1::IncompatibleProfile,
                ] {
                    consume(decode_replay_claim(&enum_replay_claim(value)));
                }
                consume(decode_replay_claim(&uint(99)));
                for value in [
                    NonInterferenceVariantV1::Success,
                    NonInterferenceVariantV1::Denial,
                    NonInterferenceVariantV1::WarmCache,
                    NonInterferenceVariantV1::ColdCache,
                ] {
                    consume(decode_non_interference_variant(
                        &enum_non_interference_variant(value),
                    ));
                }
                consume(decode_non_interference_variant(&uint(99)));
            }};
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        pub fn exercise_for_coverage(evidence: &MoatProofEvidenceV1) {
            strict_codec_coverage_cases!(evidence);
        }
    }

    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    mod coverage_tests {
        use super::*;

        fn replace_field(value: &Value, index: usize, replacement: Value) -> Value {
            let mut fields = value.as_array().map_or_else(Vec::new, Clone::clone);
            fields[index] = replacement;
            Value::Array(fields)
        }

        fn divergence_report() -> Result<DivergenceReportV1, String> {
            let mut report = DivergenceReportV1 {
                request_digest: [1; 32],
                manifest_digest: [2; 32],
                execution_profile_digest: [3; 32],
                fixture_digest: Some([4; 32]),
                evaluator_digest: [5; 32],
                reproducibility_class: ReproducibilityClassV1::CrossProfileConformance,
                replay_claim: ReplayClaimV1::StructuralOnly,
                location_kind: DivergenceLocationKindV1::DriverOutput,
                timeline_or_worldcut_id: [6; 16],
                timeline_seq_or_cut_ordinal: 3,
                tick: 2,
                scheduler_position: Some(1),
                driver_or_plugin_id: Some("proof".to_owned()),
                output_ordinal: Some(1),
                mismatch_kind: DivergenceMismatchKindV1::Artifact,
                expected: DigestSizeV1 {
                    digest: Some([7; 32]),
                    size: Some(8),
                },
                actual: DigestSizeV1 {
                    digest: Some([9; 32]),
                    size: Some(10),
                },
                prior_matching_checkpoint_digest: Some([11; 32]),
                follow_on_counts: vec![FollowOnMismatchV1 {
                    kind: DivergenceMismatchKindV1::EventIdentity,
                    count: 1,
                }],
                report_digest: [0; 32],
            };
            report.report_digest = report.digest().map_err(|error| error.to_string())?;
            Ok(report)
        }

        #[test]
        fn exercises_an_uncovered_decoder_branch() {
            let value = super::super::tests::evidence();
            let null_bytes = encode_value(&Value::Null).unwrap_or_default();
            assert!(decode_evidence(&null_bytes).is_err());
            let encoded = encode_evidence(&value);
            assert!(encoded.is_ok());
            let bytes = encoded.unwrap_or_default();
            let decoded = decode_value(&bytes);
            assert!(decoded.is_ok());
            let mut root = decoded.unwrap_or(Value::Null);
            if let Value::Array(fields) = &mut root {
                fields[0] = text("wrong");
            }
            let encoded = encode_value(&root);
            assert!(encoded.is_ok());
            let bytes = encoded.unwrap_or_default();
            assert_eq!(
                decode_evidence(&bytes),
                Err(StrictCborError::UnsupportedVersion)
            );
            let wrong_magic_type = replace_field(&root, 0, Value::Map(Vec::new()));
            let wrong_magic_type = encode_value(&wrong_magic_type).unwrap_or_default();
            assert!(decode_evidence(&wrong_magic_type).is_err());
        }

        #[test]
        fn exercises_verification_record_boundaries() -> Result<(), String> {
            let evidence = super::super::tests::evidence();
            let result = evidence
                .to_verification_result()
                .map_err(|error| error.to_string())?;
            let encoded = encode_verification_result_value(&result, true);
            let bytes = encode_value(&encoded).map_err(|error| error.to_string())?;
            assert!(decode_verification_result(&bytes).is_ok());
            let null_bytes = encode_value(&Value::Null).map_err(|error| error.to_string())?;
            assert!(decode_verification_result(&null_bytes).is_err());

            let invalid_digest = replace_field(&encoded, 17, digest(&[0; 32]));
            let invalid_digest =
                encode_value(&invalid_digest).map_err(|error| error.to_string())?;
            assert!(decode_verification_result(&invalid_digest).is_err());

            let invalid_version = replace_field(&encoded, 1, uint(2));
            let invalid_version_fields =
                array(&invalid_version, "verification_result", 18).unwrap_or(&[]);
            assert!(decode_verification_result_fields(invalid_version_fields).is_err());

            let invalid_count = replace_field(&encoded, 15, uint(65_537));
            let invalid_count_fields =
                array(&invalid_count, "verification_result", 18).unwrap_or(&[]);
            assert!(decode_verification_result_fields(invalid_count_fields).is_err());

            let optional_fields = replace_field(
                &replace_field(&replace_field(&encoded, 12, Value::Null), 13, Value::Null),
                14,
                Value::Null,
            );
            let optional_fields = array(&optional_fields, "verification_result", 18).unwrap_or(&[]);
            assert!(decode_verification_result_fields(optional_fields).is_ok());

            let mut error_result = result.clone();
            error_result.verification_outcome = VerificationOutcomeV1::InvalidManifest;
            error_result.authoritative_result_digest = None;
            error_result.first_error = Some(VerificationErrorV1 {
                code: SafeErrorCodeV1::InvalidEncoding,
                field_ordinal: Some(1),
                canonical_coordinate: Some(vec![1, 2, 3]),
                related_digest: Some([12; 32]),
            });
            let error_fields = encode_verification_result_value(&error_result, true);
            let error_fields = array(&error_fields, "verification_result", 18).unwrap_or(&[]);
            assert!(decode_verification_result_fields(error_fields).is_ok());

            let fallback_error = VerificationErrorV1 {
                code: SafeErrorCodeV1::InvalidEncoding,
                field_ordinal: None,
                canonical_coordinate: None,
                related_digest: None,
            };
            let error = error_result.first_error.as_ref().unwrap_or(&fallback_error);
            let invalid_error_field =
                replace_field(&encode_verification_error(error), 0, Value::Map(Vec::new()));
            assert!(decode_verification_error(&invalid_error_field).is_err());
            let invalid_error_ordinal_type =
                replace_field(&encode_verification_error(error), 1, Value::Map(Vec::new()));
            assert!(decode_verification_error(&invalid_error_ordinal_type).is_err());
            let invalid_error_digest =
                replace_field(&encode_verification_error(error), 3, Value::Map(Vec::new()));
            assert!(decode_verification_error(&invalid_error_digest).is_err());
            let invalid_error_ordinal = replace_field(
                &encode_verification_error(error),
                1,
                uint(u64::from(u16::MAX) + 1),
            );
            assert!(decode_verification_error(&invalid_error_ordinal).is_err());

            let null_coordinate = replace_field(&encode_verification_error(error), 2, Value::Null);
            assert!(decode_verification_error(&null_coordinate).is_ok());

            let invalid_coordinate = replace_field(&null_coordinate, 2, text("coordinate"));
            assert!(decode_verification_error(&invalid_coordinate).is_err());

            let mut invalid_semantics = result.clone();
            invalid_semantics.verification_outcome = VerificationOutcomeV1::Diverged;
            invalid_semantics.divergence_report_digest = None;
            assert!(validate_verification_result(&invalid_semantics).is_err());
            assert!(invalid_semantics.to_canonical_cbor().is_err());
            assert!(VerificationResultV1::from_canonical_cbor(&[0xff]).is_err());
            invalid_semantics = result;
            invalid_semantics.first_error = Some(VerificationErrorV1 {
                canonical_coordinate: Some(vec![0; 129]),
                ..error.clone()
            });
            assert!(validate_verification_result(&invalid_semantics).is_err());
            invalid_semantics.result_digest =
                verification_result_digest(&invalid_semantics).unwrap_or([0; 32]);
            let invalid_semantics_bytes =
                encode_value(&encode_verification_result_value(&invalid_semantics, true))
                    .unwrap_or_default();
            assert!(decode_verification_result(&invalid_semantics_bytes).is_err());
            Ok(())
        }

        #[test]
        fn exercises_divergence_record_boundaries() -> Result<(), String> {
            let report = divergence_report()?;
            let encoded = encode_divergence_report_value(&report, true);
            let bytes = encode_value(&encoded).map_err(|error| error.to_string())?;
            assert!(decode_divergence_report(&bytes).is_ok());
            let null_bytes = encode_value(&Value::Null).map_err(|error| error.to_string())?;
            assert!(decode_divergence_report(&null_bytes).is_err());

            let invalid_digest = replace_field(&encoded, 21, digest(&[0; 32]));
            let invalid_digest =
                encode_value(&invalid_digest).map_err(|error| error.to_string())?;
            assert!(decode_divergence_report(&invalid_digest).is_err());

            let invalid_version = replace_field(&encoded, 0, text("wrong"));
            let invalid_version_fields =
                array(&invalid_version, "divergence_report", 22).unwrap_or(&[]);
            assert!(decode_divergence_report_fields(invalid_version_fields).is_err());

            assert!(decode_follow_on_counts(&Value::Array(
                (0..33)
                    .map(|_| {
                        Value::Array(vec![
                            enum_divergence_mismatch(DivergenceMismatchKindV1::EventIdentity),
                            uint(1),
                        ])
                    })
                    .collect(),
            ))
            .is_err());

            let mut huge_report = report;
            huge_report.follow_on_counts = (0..7_000)
                .map(|_| FollowOnMismatchV1 {
                    kind: DivergenceMismatchKindV1::EventIdentity,
                    count: 1,
                })
                .collect();
            assert!(encode_divergence_report(&huge_report).is_err());
            assert!(huge_report.to_canonical_cbor().is_err());
            assert!(DivergenceReportV1::from_canonical_cbor(&[0xff]).is_err());
            let mut invalid_report = divergence_report()?;
            invalid_report.driver_or_plugin_id = Some(String::new());
            invalid_report.report_digest =
                invalid_report.digest().map_err(|error| error.to_string())?;
            let invalid_report_bytes =
                encode_value(&encode_divergence_report_value(&invalid_report, true))
                    .map_err(|error| error.to_string())?;
            assert!(decode_divergence_report(&invalid_report_bytes).is_err());
            Ok(())
        }

        #[test]
        fn exercises_nested_numeric_and_array_boundaries() {
            let evidence = super::super::tests::evidence();
            let contract = &evidence.contract.counterfactual;

            let owner = replace_field(
                &encode_owner_frontier(&contract.frontier.owner_frontiers[0]),
                2,
                uint(u64::from(u32::MAX) + 1),
            );
            assert!(decode_owner_frontier(&owner).is_err());

            let frontier = replace_field(
                &encode_frontier(&contract.frontier),
                10,
                uint(u64::from(u32::MAX) + 1),
            );
            assert!(decode_frontier(&frontier).is_err());

            let invalidation = replace_field(
                &encode_invalidation(&contract.invalidation),
                15,
                Value::Array(vec![uint(1), Value::Null, Value::Bool(true)]),
            );
            assert!(decode_invalidation(&invalidation).is_err());

            let counterfactual = replace_field(&encode_counterfactual(contract), 8, Value::Null);
            assert!(decode_counterfactual(&counterfactual).is_err());

            let case = replace_field(
                &replace_field(
                    &encode_case(&evidence.contract.conformance_report.cases[0]),
                    7,
                    Value::Null,
                ),
                8,
                Value::Null,
            );
            assert!(decode_case(&case).is_ok());
        }
    }
}

pub use strict_codec::StrictCborError;

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
///
/// # Errors
/// Returns the canonical-CBOR serialization error if either artifact cannot be
/// represented by the shared deterministic codec.
#[must_use = "the comparison result is needed to classify the artifacts"]
pub fn compare(
    left: &MoatProofEvidenceV1,
    right: &MoatProofEvidenceV1,
) -> Result<ComparisonV1, pos_core::CoreError> {
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
        && left.manifest.plugin_versions == right.manifest.plugin_versions
        && left.manifest.scenario_room_digest == right.manifest.scenario_room_digest
        && left.manifest.scheduler_digest == right.manifest.scheduler_digest
        && left.manifest.budget_digest == right.manifest.budget_digest;
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
        || left.host_closure != right.host_closure
        || left.contract != right.contract
    {
        DivergenceClassV1::Observability
    } else {
        DivergenceClassV1::None
    };
    Ok(ComparisonV1 {
        equal: divergence == DivergenceClassV1::None,
        divergence,
        left_digest: left.digest()?,
        right_digest: right.digest()?,
    })
}

/// Compare only the authoritative Events and Projections produced by two
/// execution profiles.
///
/// This seam intentionally excludes profile metadata and evidence identities;
/// it is the comparison used to establish Local/Air-Gapped output parity.
///
/// # Errors
/// Returns the canonical-CBOR serialization error if either output cannot be
/// represented by the shared deterministic codec.
#[must_use = "the authoritative output comparison is needed for parity evidence"]
pub fn compare_authoritative_outputs(
    left: &MoatProofEvidenceV1,
    right: &MoatProofEvidenceV1,
) -> Result<ComparisonV1, pos_core::CoreError> {
    let left_output = (&left.authoritative_events, &left.projections);
    let right_output = (&right.authoritative_events, &right.projections);
    let divergence = if left.authoritative_events != right.authoritative_events {
        DivergenceClassV1::AuthoritativeEvents
    } else if left.projections != right.projections {
        DivergenceClassV1::Projections
    } else {
        DivergenceClassV1::None
    };
    typed_digest(b"PiglorOS.AuthoritativeOutput.v1", &left_output).and_then(|left_digest| {
        typed_digest(b"PiglorOS.AuthoritativeOutput.v1", &right_output).map(|right_digest| {
            ComparisonV1 {
                equal: divergence == DivergenceClassV1::None,
                divergence,
                left_digest,
                right_digest,
            }
        })
    })
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
    verify_host_closure(&evidence.host_closure, &evidence.authoritative_events)?;
    verify_wave8_contract(evidence)?;
    Ok(())
}

fn verify_manifest(manifest: &ReproManifestV1) -> Result<(), EvidenceError> {
    if manifest.execution_profile.trim().is_empty()
        || manifest.execution_profile_digest == [0; 32]
        || manifest.trust_policy_snapshot_digest == [0; 32]
        || manifest.artifact_closure_digest == [0; 32]
        || manifest.evaluator_digest == [0; 32]
        || manifest.scenario_room_digest == [0; 32]
        || manifest.scheduler_digest == [0; 32]
        || manifest.budget_digest == [0; 32]
        || !(3..=10_000).contains(&manifest.resource_limit)
        || manifest.plugin_versions.is_empty()
        || manifest
            .plugin_versions
            .iter()
            .any(|(name, version)| name.trim().is_empty() || version.trim().is_empty())
        || manifest.network_enabled
    {
        Err(EvidenceError::InvalidManifest)
    } else {
        Ok(())
    }
}

fn event_sequences(events: &[AuthoritativeEventV1]) -> Result<BTreeSet<u64>, EvidenceError> {
    if events.first().is_none_or(|event| event.seq != 1) {
        return Err(EvidenceError::NonContiguousEventSequence);
    }
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
    if failures.iter().any(|failure| {
        failure.plugin.trim().is_empty()
            || failure.committed
            || failure.committed_event_count > failure.staged_event_count
            || failure.state_digest_before == [0; 32]
            || failure.state_digest_after == [0; 32]
            || failure.state_digest_before != failure.state_digest_after
            || failure.sibling_step_count == 0
    }) {
        Err(EvidenceError::CommittedPluginFailure)
    } else {
        Ok(())
    }
}

/// Verify a canonical `consent.revoked.v1` audit against authoritative Events.
///
/// # Errors
/// Returns [`EvidenceError::InvalidConsentAudit`] when the audit is not a
/// single effective canonical revocation at a completed Tick Boundary.
pub fn verify_consent_audit(
    audit: &ConsentAuditV1,
    events: &[AuthoritativeEventV1],
) -> Result<(), EvidenceError> {
    if audit.subject.trim().is_empty()
        || !matches!(audit.revocation_event_type.as_str(), "consent.revoked.v1")
        || audit.revocation_payload_digest == [0; 32]
        || audit.effective_after_seq <= audit.requested_after_seq
        || audit.revocation_event_seq != audit.effective_after_seq
        || !audit.halted_at_tick_boundary
        || events
            .iter()
            .filter(|event| event.event_type == audit.revocation_event_type)
            .count()
            != 1
        || events
            .iter()
            .find(|event| {
                event.event_type == audit.revocation_event_type
                    && event.seq == audit.revocation_event_seq
            })
            .is_none_or(|event| event.payload_digest != audit.revocation_payload_digest)
    {
        Err(EvidenceError::InvalidConsentAudit)
    } else {
        Ok(())
    }
}

/// Verify an experiment-owned closure marker without treating it as a
/// Gateway consent revocation. It is a host lifecycle proof only; it never
/// rehydrates `ConsentAuthority` or authorizes protected work.
fn verify_host_closure(
    audit: &HostClosureAuditV1,
    events: &[AuthoritativeEventV1],
) -> Result<(), EvidenceError> {
    if audit.subject.trim().is_empty()
        || audit.closure_payload_digest == [0; 32]
        || audit.effective_after_seq <= audit.requested_after_seq
        || audit.closure_event_seq != audit.effective_after_seq
        || !audit.halted_at_tick_boundary
        || events
            .iter()
            .filter(|event| event.event_type == audit.closure_event_type)
            .count()
            != 1
        || events
            .iter()
            .find(|event| {
                event.event_type == audit.closure_event_type && event.seq == audit.closure_event_seq
            })
            .is_none_or(|event| event.payload_digest != audit.closure_payload_digest)
        || audit.closure_event_type != "experiment.lifecycle.consent-closed.v1"
    {
        Err(EvidenceError::InvalidConsentAudit)
    } else {
        Ok(())
    }
}

fn contract_event_type(event_type: &str) -> bool {
    matches!(
        event_type,
        "world.action.v1" | "world.observation.v1" | "proof.agent.reaction.v1" | "society.signal"
    )
}

fn contract_endogenous_event_type(event_type: &str) -> bool {
    matches!(
        event_type,
        "world.observation.v1" | "proof.agent.reaction.v1" | "society.signal"
    )
}

fn contract_event_node(event: &AuthoritativeEventV1) -> DependencyNodeV1 {
    DependencyNodeV1 {
        tick: event.tick,
        scheduler_position: match event.event_type.as_str() {
            "world.action.v1" => 0,
            "world.observation.v1" => 1,
            "proof.agent.reaction.v1" => 2,
            "society.signal" => 3,
            _ => 4,
        },
        owner_id: event.entity.clone(),
        output_ordinal: 0,
        schema_id: schema_id_for_event_type(&event.event_type),
        artifact_digest: event.payload_digest,
    }
}

fn contract_event_nodes(events: &[AuthoritativeEventV1]) -> BTreeMap<u64, DependencyNodeV1> {
    let mut ordinals = BTreeMap::<(u64, u32, String, u32), u32>::new();
    let mut nodes = BTreeMap::new();
    for event in events
        .iter()
        .filter(|event| contract_event_type(event.event_type.as_str()))
    {
        let mut node = contract_event_node(event);
        let key = (
            node.tick,
            node.scheduler_position,
            node.owner_id.clone(),
            node.schema_id,
        );
        node.output_ordinal = *ordinals
            .entry(key)
            .and_modify(|value| *value += 1)
            .or_default();
        nodes.insert(event.seq, node);
    }
    nodes
}

fn contract_zero_node() -> DependencyNodeV1 {
    DependencyNodeV1 {
        tick: 0,
        scheduler_position: 0,
        owner_id: "scenario-room".to_owned(),
        output_ordinal: 0,
        schema_id: schema_id_for_event_type("scenario.input.v1"),
        artifact_digest: [0; 32],
    }
}

fn verify_wave8_contract(evidence: &MoatProofEvidenceV1) -> Result<(), EvidenceError> {
    verify_contract_header(evidence)?;
    verify_knowledge_boundary(evidence)?;
    verify_counterfactual_contract(evidence)?;
    verify_conformance_report(evidence)?;
    verify_atomicity(evidence)
}

fn verify_contract_header(evidence: &MoatProofEvidenceV1) -> Result<(), EvidenceError> {
    let contract = &evidence.contract;
    contract
        .plugin_boundary
        .validate()
        .map_err(|_| EvidenceError::InvalidContract)?;
    verify_non_interference_matrix(&contract.non_interference)?;
    let room = &contract.scenario_room;
    if room.input_digest != evidence.manifest.input_digest
        || evidence.manifest.scenario_room_digest != room.room_digest
        || room.network_enabled != evidence.manifest.network_enabled
        || room.room_id.trim().is_empty()
        || room.room_digest == [0; 32]
        || room.horizon_ticks == 0
        || room.principals.is_empty()
        || room.principals.len() != room.grants.len()
        || room
            .principals
            .windows(2)
            .any(|pair| pair[0].participant_id >= pair[1].participant_id)
        || room.principals.iter().any(|principal| {
            principal.principal_id.trim().is_empty()
                || principal.participant_id.trim().is_empty()
                || principal.trust_domain.trim().is_empty()
        })
        || room
            .principals
            .iter()
            .map(|principal| principal.principal_id.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            != room.principals.len()
        || room.grants.iter().enumerate().any(|(index, grant)| {
            grant.grant_id.trim().is_empty()
                || grant.principal_id != room.principals[index].principal_id
                || grant.capability.trim().is_empty()
                || grant.resource.trim().is_empty()
                || grant.policy_digest == [0; 32]
        })
    {
        return Err(EvidenceError::InvalidContract);
    }
    Ok(())
}

fn verify_knowledge_boundary(evidence: &MoatProofEvidenceV1) -> Result<(), EvidenceError> {
    let contract = &evidence.contract;
    let room = &contract.scenario_room;
    let event_by_seq = evidence
        .authoritative_events
        .iter()
        .map(|event| (event.seq, event))
        .collect::<BTreeMap<_, _>>();
    let principal_by_participant = room
        .principals
        .iter()
        .map(|principal| (principal.participant_id.as_str(), principal))
        .collect::<BTreeMap<_, _>>();
    let grant_by_principal = room
        .grants
        .iter()
        .map(|grant| (grant.principal_id.as_str(), grant))
        .collect::<BTreeMap<_, _>>();
    let mut snapshot_participants = BTreeSet::new();
    for snapshot in &contract.knowledge_snapshots {
        if !snapshot_participants.insert(snapshot.participant_id.as_str())
            || snapshot.snapshot_digest == [0; 32]
            || snapshot.authorization.decision_digest == [0; 32]
            || snapshot.authorization.grant_digest == [0; 32]
            || snapshot.visible_event_seqs.len() != snapshot.visible_event_digests.len()
            || snapshot
                .visible_event_seqs
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || snapshot
                .hidden_event_types
                .contains(&snapshot.principal.participant_id)
        {
            return Err(EvidenceError::InvalidKnowledgeBoundary);
        }
        let Some(principal) = principal_by_participant.get(snapshot.participant_id.as_str()) else {
            return Err(EvidenceError::InvalidKnowledgeBoundary);
        };
        let Some(grant) = grant_by_principal.get(snapshot.principal.principal_id.as_str()) else {
            return Err(EvidenceError::InvalidKnowledgeBoundary);
        };
        if snapshot.principal != **principal
            || snapshot.grant != **grant
            || snapshot.principal.participant_id != snapshot.participant_id
            || snapshot.authorization.resource != snapshot.grant.resource
            || snapshot.authorization.consent_epoch != snapshot.consent_epoch
            || snapshot.grant.consent_epoch != snapshot.consent_epoch
        {
            return Err(EvidenceError::InvalidKnowledgeBoundary);
        }
        for (seq, payload_digest) in snapshot
            .visible_event_seqs
            .iter()
            .zip(snapshot.visible_event_digests.iter())
        {
            let Some(event) = event_by_seq.get(seq) else {
                return Err(EvidenceError::InvalidKnowledgeBoundary);
            };
            if &event.payload_digest != payload_digest {
                return Err(EvidenceError::InvalidKnowledgeBoundary);
            }
        }
        let consent_allows = snapshot.consent_epoch == 0;
        if snapshot.authorization.allowed != consent_allows
            || (!consent_allows
                && snapshot.authorization.reason != "consent-revoked-at-tick-boundary")
            || snapshot.authorization.principal_id != snapshot.principal.principal_id
            || snapshot.grant.principal_id != snapshot.principal.principal_id
        {
            return Err(EvidenceError::InvalidKnowledgeBoundary);
        }
    }
    if snapshot_participants.len() != room.principals.len()
        || contract.authorization_decisions.len() != contract.knowledge_snapshots.len()
        || contract.authorization_decisions.iter().any(|decision| {
            decision.decision_digest == [0; 32]
                || decision.allowed != (decision.consent_epoch == 0)
                || (decision.consent_epoch > 0
                    && decision.reason != "consent-revoked-at-tick-boundary")
        })
        || contract.authorization_decisions.iter().any(|decision| {
            !contract
                .knowledge_snapshots
                .iter()
                .any(|snapshot| snapshot.authorization == *decision)
        })
    {
        return Err(EvidenceError::InvalidKnowledgeBoundary);
    }
    Ok(())
}

fn verify_counterfactual_contract(evidence: &MoatProofEvidenceV1) -> Result<(), EvidenceError> {
    let contract = &evidence.contract;
    let counterfactual = &contract.counterfactual;
    if counterfactual.contract_digest == [0; 32]
        || counterfactual.frontier.frontier_digest == [0; 32]
        || counterfactual.invalidation.invalidation_digest == [0; 32]
        || counterfactual.frontier.unknown_edge_policy != UnknownEdgePolicyV1::Reject
        || !counterfactual.frontier.unknown_edge_coordinates.is_empty()
        || counterfactual.invalidation.new_generation != counterfactual.generation
        || counterfactual.invalidation.prior_generation != counterfactual.prior_generation
        || (counterfactual.intervention.is_some()
            && counterfactual.generation != counterfactual.prior_generation.saturating_add(1))
    {
        return Err(EvidenceError::InvalidDependencyGraph);
    }
    if !verify_counterfactual_record_shapes(counterfactual) {
        return Err(EvidenceError::InvalidDependencyGraph);
    }
    let mut consumers = BTreeSet::new();
    for dependency in &counterfactual.dependencies {
        if !consumers.insert((
            dependency.consumer.tick,
            dependency.consumer.scheduler_position,
            dependency.consumer.owner_id.as_str(),
            dependency.consumer.output_ordinal,
            dependency.consumer.artifact_digest,
        )) || dependency.authorization_digest == [0; 32]
            || dependency.provenance_digest == [0; 32]
        {
            return Err(EvidenceError::InvalidDependencyGraph);
        }
    }
    if let Some(intervention) = counterfactual.intervention.as_ref() {
        verify_intervention_contract(evidence, counterfactual, intervention)?;
    }
    Ok(())
}

fn verify_intervention_contract(
    evidence: &MoatProofEvidenceV1,
    counterfactual: &CounterfactualContractV1,
    intervention: &InterventionV1,
) -> Result<(), EvidenceError> {
    let event_by_seq = evidence
        .authoritative_events
        .iter()
        .map(|event| (event.seq, event))
        .collect::<BTreeMap<_, _>>();
    let Some(event) = evidence.authoritative_events.iter().find(|event| {
        event.event_type == "world.action.v1"
            && event.tick == intervention.effective_tick
            && event.payload_digest == intervention.value_digest
    }) else {
        return Err(EvidenceError::InvalidDependencyGraph);
    };
    let contract_events = evidence
        .authoritative_events
        .iter()
        .filter(|candidate| contract_event_type(candidate.event_type.as_str()))
        .collect::<Vec<_>>();
    let nodes_by_seq = contract_event_nodes(&evidence.authoritative_events);
    let expected_nodes = contract_events
        .iter()
        .map(|candidate| (nodes_by_seq[&candidate.seq].clone(), *candidate))
        .collect::<BTreeMap<_, _>>();
    if counterfactual.dependencies.len() != expected_nodes.len()
        || counterfactual.dependencies.iter().any(|dependency| {
            let Some(event) = expected_nodes.get(&dependency.consumer) else {
                return true;
            };
            let expected_class = if event.event_type == "world.action.v1" {
                DependencyClassV1::InterventionAssigned
            } else {
                DependencyClassV1::EndogenousRecomputed
            };
            let expected_source = event
                .causation_seq
                .and_then(|seq| event_by_seq.get(&seq).copied())
                .filter(|source| contract_event_type(source.event_type.as_str()))
                .and_then(|source| nodes_by_seq.get(&source.seq).cloned())
                .unwrap_or_else(contract_zero_node);
            dependency.dependency_class != expected_class || dependency.source != expected_source
        })
    {
        return Err(EvidenceError::InvalidDependencyGraph);
    }
    let expected_recomputed_seqs = contract_events
        .iter()
        .filter(|candidate| {
            contract_endogenous_event_type(candidate.event_type.as_str())
                && candidate.seq > event.seq
        })
        .map(|candidate| candidate.seq)
        .collect::<Vec<_>>();
    if counterfactual.frontier.intervention_seed_nodes != vec![nodes_by_seq[&event.seq].clone()]
        || counterfactual.recomputed_event_seqs != expected_recomputed_seqs
        || counterfactual.frontier.affected_nodes.is_empty()
        || counterfactual.frontier.owner_frontiers.is_empty()
        || counterfactual.frontier.global_frontier_tick
            != counterfactual
                .frontier
                .affected_nodes
                .first()
                .map_or(0, |node| node.tick)
        || counterfactual.frontier.endogenous_suffix_end_tick
            != counterfactual
                .frontier
                .affected_nodes
                .last()
                .map_or(0, |node| node.tick)
    {
        return Err(EvidenceError::IncompleteRecomputationContract);
    }
    if event.seq <= evidence.manifest.fork_cut_seq.unwrap_or(0)
        || counterfactual
            .recomputed_event_seqs
            .iter()
            .any(|seq| *seq <= event.seq)
        || counterfactual.frontier.affected_nodes.iter().any(|node| {
            (node.tick, node.scheduler_position, node.output_ordinal) < (event.tick, 0, 0)
        })
        || counterfactual.invalidation.invalid_artifacts.len()
            < counterfactual.frontier.affected_nodes.len()
    {
        return Err(EvidenceError::IncompleteRecomputationContract);
    }
    Ok(())
}

fn verify_conformance_report(evidence: &MoatProofEvidenceV1) -> Result<(), EvidenceError> {
    let contract = &evidence.contract;
    let report = &contract.conformance_report;
    report.validate()?;
    let counterfactual = &contract.counterfactual;
    let modes = report
        .cases
        .iter()
        .map(|case| case.mode)
        .collect::<BTreeSet<_>>();
    if !report
        .replay_claim
        .is_no_stronger_than(evidence.manifest.replay_claim)
        || !counterfactual
            .replay_claim
            .is_no_stronger_than(evidence.manifest.replay_claim)
        || !modes.contains(&evidence.manifest.execution_mode)
    {
        return Err(EvidenceError::InvalidConformanceReport);
    }
    Ok(())
}

fn validate_conformance_report_shape(report: &ConformanceReportV1) -> Result<(), EvidenceError> {
    if report.report_id == [0; 16]
        || report.subject_artifact_digest == [0; 32]
        || report.profile_digest == [0; 32]
        || report.normative_spec_digest == [0; 32]
        || report.execution_profile_digest == [0; 32]
        || report.fixture_bundle_digest == [0; 32]
        || report.evaluator_source_digest == [0; 32]
        || report.evaluator_binary_digest == [0; 32]
        || report.evaluator_protocol_digest == [0; 32]
        || report.limitations_digest == [0; 32]
        || report.provenance_digest == [0; 32]
        || report.cases.is_empty()
        || report.cases.len() > 65_536
        || report.implementation.implementation_id.is_empty()
        || report.implementation.implementation_id.len() > 128
        || report
            .implementation
            .organization_id
            .as_ref()
            .is_some_and(|id| id.is_empty() || id.len() > 128)
        || report.implementation.source_digest == [0; 32]
        || report.implementation.build_digest == [0; 32]
        || report.implementation.binary_digest == [0; 32]
        || report.implementation.public_contract_digest == [0; 32]
        || report.independence.reviewer_ids.is_empty()
        || report.independence.reviewer_ids.len() > 32
        || report
            .independence
            .reviewer_ids
            .iter()
            .any(|id| id.is_empty() || id.len() > 128)
        || report
            .independence
            .reviewer_ids
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || report.independence.declaration_digest == [0; 32]
        || report.independence.shared_code_audit_digest == [0; 32]
    {
        return Err(EvidenceError::InvalidConformanceReport);
    }
    let mut case_keys = BTreeSet::new();
    let mut counts = (0_u32, 0_u32, 0_u32, 0_u32, 0_u32);
    let mut weakest_redaction = RedactionStateV1::None;
    let mut weakest_replay_claim = ReplayClaimV1::Exact;
    for case in &report.cases {
        validate_conformance_case(case, &mut case_keys)?;
        weakest_redaction = weakest_redaction.max(case.redaction_state);
        weakest_replay_claim = weakest_replay_claim.max(case.replay_claim);
        match case.outcome {
            CaseOutcomeStatusV1::Pass => counts.0 = counts.0.saturating_add(1),
            CaseOutcomeStatusV1::Fail => counts.1 = counts.1.saturating_add(1),
            CaseOutcomeStatusV1::Skip => counts.2 = counts.2.saturating_add(1),
            CaseOutcomeStatusV1::Unavailable => counts.3 = counts.3.saturating_add(1),
            CaseOutcomeStatusV1::NotApplicable => counts.4 = counts.4.saturating_add(1),
        }
    }
    if report.cases.windows(2).any(|pair| {
        (
            pair[0].case_id.as_str(),
            pair[0].mode,
            pair[0].claim_layer,
            pair[0].fixture_digest,
        ) >= (
            pair[1].case_id.as_str(),
            pair[1].mode,
            pair[1].claim_layer,
            pair[1].fixture_digest,
        )
    }) {
        return Err(EvidenceError::InvalidConformanceReport);
    }
    if report.redaction_state != weakest_redaction
        || report.replay_claim != weakest_replay_claim
        || counts
            != (
                report.passed,
                report.failed,
                report.skipped,
                report.unavailable,
                report.not_applicable,
            )
        || report.report_digest != report.digest()?
    {
        return Err(EvidenceError::InvalidConformanceReport);
    }
    Ok(())
}

fn validate_conformance_case<'a>(
    case: &'a CaseOutcomeV1,
    case_keys: &mut BTreeSet<(&'a str, ExecutionModeV1, ClaimLayerV1, [u8; 32])>,
) -> Result<(), EvidenceError> {
    if !case_keys.insert((
        case.case_id.as_str(),
        case.mode,
        case.claim_layer,
        case.fixture_digest,
    )) || case.case_id.trim().is_empty()
        || case.case_id.len() > 128
        || case.fixture_digest == [0; 32]
        || case.execution_profile_digest == [0; 32]
        || case.provenance_digest == [0; 32]
        || case
            .first_coordinate
            .as_ref()
            .is_some_and(|coordinate| coordinate.len() > 128)
        || !valid_conformance_case_result(case)
        || !valid_redacted_case(case)
        || (matches!(
            case.redaction_state,
            RedactionStateV1::None | RedactionStateV1::RedactedViews
        ) && case.outcome != CaseOutcomeStatusV1::Pass
            && case.expected_digest == case.actual_digest
            && case.expected_error == case.actual_error)
    {
        Err(EvidenceError::InvalidConformanceReport)
    } else {
        Ok(())
    }
}

fn valid_conformance_case_result(case: &CaseOutcomeV1) -> bool {
    if matches!(
        case.redaction_state,
        RedactionStateV1::StructuralOnly | RedactionStateV1::EvidenceMissing
    ) {
        return true;
    }
    let exact = case.expected_digest.is_some()
        && case.expected_digest == case.actual_digest
        && case.expected_error.is_none()
        && case.actual_error.is_none()
        && case.first_coordinate.is_none();
    let typed_failure = case.expected_digest.is_none()
        && case.actual_digest.is_none()
        && case.expected_error.is_some()
        && case.expected_error == case.actual_error
        && case.first_coordinate.is_none();
    let allowed_divergence = case.expected_digest.is_some()
        && case.actual_digest.is_some()
        && case.expected_digest != case.actual_digest
        && case.expected_error.is_none()
        && case.actual_error.is_none()
        && case.first_coordinate.is_some();
    case.outcome != CaseOutcomeStatusV1::Pass || exact || typed_failure || allowed_divergence
}

fn valid_redacted_case(case: &CaseOutcomeV1) -> bool {
    let incompatible = case.replay_claim == ReplayClaimV1::IncompatibleProfile;
    match case.redaction_state {
        RedactionStateV1::None => true,
        RedactionStateV1::RedactedViews => {
            incompatible || case.replay_claim == ReplayClaimV1::ExactAuthoritativeWithRedactedViews
        }
        RedactionStateV1::StructuralOnly => {
            (incompatible || case.replay_claim == ReplayClaimV1::StructuralOnly)
                && case.expected_digest.is_none()
                && case.actual_digest.is_none()
                && case.expected_error.is_none()
                && case.actual_error.is_none()
                && case.first_coordinate.is_none()
        }
        RedactionStateV1::EvidenceMissing => {
            (incompatible || case.replay_claim == ReplayClaimV1::UnverifiableArtifactsMissing)
                && case.outcome != CaseOutcomeStatusV1::Pass
                && case.expected_digest.is_none()
                && case.actual_digest.is_none()
                && case.expected_error.is_none()
                && case.actual_error.is_none()
                && case.first_coordinate.is_none()
        }
    }
}

fn verify_atomicity(evidence: &MoatProofEvidenceV1) -> Result<(), EvidenceError> {
    let contract = &evidence.contract;
    if contract.atomicity.is_empty() {
        return Err(EvidenceError::IncompleteAtomicityEvidence);
    }
    let mut atomicity_keys = BTreeSet::new();
    let mut failed_atomicity_keys = BTreeSet::new();
    for atomicity in &contract.atomicity {
        let key = (
            atomicity.tick,
            atomicity.fork_generation,
            atomicity.failure_class,
        );
        if !atomicity_keys.insert(key)
            || atomicity.state_digest_before == [0; 32]
            || atomicity.state_digest_after == [0; 32]
        {
            return Err(EvidenceError::IncompleteAtomicityEvidence);
        }
        if (!atomicity.committed
            && (atomicity.committed_event_count != 0
                || atomicity.state_digest_before != atomicity.state_digest_after
                || atomicity.failure_class.is_none()))
            || (atomicity.committed
                && atomicity.committed_event_count > atomicity.staged_event_count)
        {
            return Err(EvidenceError::IncompleteAtomicityEvidence);
        }
        if let Some(failure_class) = atomicity.failure_class {
            if atomicity.committed || !failed_atomicity_keys.insert((atomicity.tick, failure_class))
            {
                return Err(EvidenceError::IncompleteAtomicityEvidence);
            }
        }
    }
    let declared_failures = evidence
        .plugin_failures
        .iter()
        .map(|failure| (failure.tick, failure.class))
        .collect::<BTreeSet<_>>();
    if declared_failures != failed_atomicity_keys {
        return Err(EvidenceError::IncompleteAtomicityEvidence);
    }
    Ok(())
}

fn valid_contract_node(node: &DependencyNodeV1, allow_zero_digest: bool) -> bool {
    !node.owner_id.is_empty()
        && node.owner_id.len() <= 128
        && node.schema_id != 0
        && (allow_zero_digest || node.artifact_digest != [0; 32])
}

fn valid_contract_nodes(nodes: &[DependencyNodeV1], allow_zero_digest: bool) -> bool {
    !nodes.is_empty()
        && nodes.len() <= 1_000_000
        && nodes.windows(2).all(|pair| pair[0] < pair[1])
        && nodes
            .iter()
            .all(|node| valid_contract_node(node, allow_zero_digest))
}

fn valid_owner_frontiers(frontiers: &[OwnerFrontierV1], has_intervention: bool) -> bool {
    (!has_intervention && frontiers.is_empty())
        || (!frontiers.is_empty()
            && frontiers.len() <= 4_096
            && frontiers.windows(2).all(|pair| {
                (
                    pair[0].earliest_tick,
                    pair[0].earliest_scheduler_position,
                    pair[0].owner_id.as_str(),
                    pair[0].earliest_output_ordinal,
                ) < (
                    pair[1].earliest_tick,
                    pair[1].earliest_scheduler_position,
                    pair[1].owner_id.as_str(),
                    pair[1].earliest_output_ordinal,
                )
            })
            && frontiers.iter().all(|owner| {
                !owner.owner_id.is_empty()
                    && owner.owner_id.len() <= 128
                    && !owner.cause_node_digests.is_empty()
                    && owner.cause_node_digests.len() <= 4_096
                    && owner
                        .cause_node_digests
                        .windows(2)
                        .all(|pair| pair[0] < pair[1])
                    && owner
                        .cause_node_digests
                        .iter()
                        .all(|digest| *digest != [0; 32])
            }))
}

fn valid_unknown_edge_coordinates(frontier: &RecomputationFrontierV1) -> bool {
    frontier.unknown_edge_coordinates.len() <= 65_536
        && frontier
            .unknown_edge_coordinates
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        && frontier
            .unknown_edge_coordinates
            .iter()
            .all(|node| valid_contract_node(node, false))
}

fn valid_digest_list(values: &[[u8; 32]]) -> bool {
    values.len() <= 65_536
        && values.windows(2).all(|pair| pair[0] < pair[1])
        && values.iter().all(|digest| *digest != [0; 32])
}

fn valid_invalid_artifacts(invalidation: &SuffixInvalidationV1) -> bool {
    invalidation.invalid_artifacts.len() <= 1_000_000
        && invalidation.invalid_artifacts.windows(2).all(|pair| {
            (
                pair[0].producer.clone(),
                pair[0].artifact_class.as_str(),
                pair[0].artifact_digest,
            ) < (
                pair[1].producer.clone(),
                pair[1].artifact_class.as_str(),
                pair[1].artifact_digest,
            )
        })
        && invalidation.invalid_artifacts.iter().all(|artifact| {
            !artifact.artifact_class.is_empty()
                && artifact.schema_id == artifact.producer.schema_id
                && artifact.artifact_digest != [0; 32]
                && valid_contract_node(&artifact.producer, false)
                && artifact.reason == invalidation.reason
        })
}

fn valid_dependencies(contract: &CounterfactualContractV1) -> bool {
    !contract.dependencies.is_empty()
        && contract.dependencies.len() <= 1_000_000
        && contract.dependencies.windows(2).all(|pair| {
            (
                pair[0].consumer.tick,
                pair[0].consumer.scheduler_position,
                pair[0].consumer.owner_id.as_str(),
                pair[0].consumer.output_ordinal,
                pair[0].source.artifact_digest,
            ) < (
                pair[1].consumer.tick,
                pair[1].consumer.scheduler_position,
                pair[1].consumer.owner_id.as_str(),
                pair[1].consumer.output_ordinal,
                pair[1].source.artifact_digest,
            )
        })
        && contract.dependencies.iter().all(|dependency| {
            valid_contract_node(&dependency.consumer, false)
                && valid_contract_node(&dependency.source, true)
                && dependency.authorization_digest != [0; 32]
                && dependency.provenance_digest != [0; 32]
                && (dependency.source.artifact_digest != [0; 32]
                    || (dependency.source.tick == 0
                        && dependency.source.owner_id == "scenario-room"))
                && (dependency.source.artifact_digest == [0; 32]
                    || (
                        dependency.source.tick,
                        dependency.source.scheduler_position,
                        dependency.source.owner_id.as_str(),
                        dependency.source.output_ordinal,
                    ) < (
                        dependency.consumer.tick,
                        dependency.consumer.scheduler_position,
                        dependency.consumer.owner_id.as_str(),
                        dependency.consumer.output_ordinal,
                    ))
        })
}

fn verify_counterfactual_record_shapes(contract: &CounterfactualContractV1) -> bool {
    let frontier = &contract.frontier;
    let invalidation = &contract.invalidation;
    let seeds_valid = (contract.intervention.is_none()
        && frontier.intervention_seed_nodes.is_empty())
        || (!frontier.intervention_seed_nodes.is_empty()
            && frontier.intervention_seed_nodes.len() <= 1_024
            && frontier
                .intervention_seed_nodes
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            && frontier
                .intervention_seed_nodes
                .iter()
                .all(|node| valid_contract_node(node, false)));
    let affected_valid = (contract.intervention.is_none() && frontier.affected_nodes.is_empty())
        || valid_contract_nodes(&frontier.affected_nodes, false);
    let owner_frontiers_valid =
        valid_owner_frontiers(&frontier.owner_frontiers, contract.intervention.is_some());
    let unknown_edges_valid = valid_unknown_edge_coordinates(frontier);
    let frontier_valid = frontier.frontier_id != [0; 16]
        && frontier.plan_digest != [0; 32]
        && frontier.parent_cut_digest != [0; 32]
        && frontier.dependency_graph_digest != [0; 32]
        && frontier.classification_bundle_digest != [0; 32]
        && frontier.provenance_digest != [0; 32]
        && frontier.frontier_digest != [0; 32]
        && frontier.endogenous_suffix_end_tick >= frontier.global_frontier_tick
        && match frontier.unknown_edge_policy {
            UnknownEdgePolicyV1::Reject => frontier.unknown_edge_coordinates.is_empty(),
            UnknownEdgePolicyV1::FullSuffixFromCut => !frontier.unknown_edge_coordinates.is_empty(),
        };
    let invalid_artifacts_valid = valid_invalid_artifacts(invalidation);
    let generation_valid = (contract.prior_generation == 0
        && contract.generation == 0
        && invalidation.new_generation == 0
        && invalidation.invalid_artifacts.is_empty())
        || (invalidation.new_generation == contract.prior_generation.saturating_add(1)
            && invalidation.new_generation == contract.generation);
    let dependencies_valid = valid_dependencies(contract);
    frontier_valid
        && seeds_valid
        && affected_valid
        && owner_frontiers_valid
        && unknown_edges_valid
        && invalidation.invalidation_id != [0; 16]
        && invalidation.plan_digest == frontier.plan_digest
        && invalidation.fork_id == contract.fork_id
        && invalidation.frontier_digest == frontier.frontier_digest
        && invalidation.commit_timeline_id != [0; 16]
        && invalidation.provenance_digest != [0; 32]
        && invalidation.invalidation_digest != [0; 32]
        && invalid_artifacts_valid
        && dependencies_valid
        && valid_digest_list(&invalidation.invalid_checkpoint_digests)
        && valid_digest_list(&invalidation.invalid_projection_digests)
        && valid_digest_list(&invalidation.retained_exogenous_digests)
        && generation_valid
}

fn verify_non_interference_matrix(cases: &[NonInterferenceCaseV1]) -> Result<(), EvidenceError> {
    let variants = [
        NonInterferenceVariantV1::Success,
        NonInterferenceVariantV1::Denial,
        NonInterferenceVariantV1::WarmCache,
        NonInterferenceVariantV1::ColdCache,
    ];
    let modes = [
        ExecutionModeV1::Local,
        ExecutionModeV1::AirGapped,
        ExecutionModeV1::Replay,
        ExecutionModeV1::Fork,
    ];
    let mut expected = Vec::with_capacity(NON_INTERFERENCE_CASE_COUNT_V1);
    for fixture_id in NON_INTERFERENCE_FIXTURE_IDS_V1 {
        for variant in variants {
            for mode in modes {
                expected.push((fixture_id, variant, mode));
            }
        }
    }
    if cases.len() != expected.len()
        || cases.iter().zip(expected.iter()).any(|(case, expected)| {
            case.fixture_id != expected.0
                || case.variant != expected.1
                || case.mode != expected.2
                || case.control_input_digest == [0; 32]
                || case.canary_input_digest == [0; 32]
                || case.control_input_digest == case.canary_input_digest
                || case.authoritative_digest == [0; 32]
                || case.public_digest == [0; 32]
                || case.operational_digest == [0; 32]
                || !case.authoritative_equal
                || !case.public_equal
                || !case.operational_equal
                || case.provenance_digest == [0; 32]
        })
    {
        return Err(EvidenceError::InvalidNonInterferenceMatrix);
    }
    Ok(())
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
            let Some(authoritative) = authoritative_events
                .iter()
                .find(|candidate| candidate.seq == event.seq)
            else {
                return Err(EvidenceError::InvalidParticipantView);
            };
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
    verify_evidence(baseline).map_err(|_| EvidenceError::IncompleteForkSuffix)?;
    verify_evidence(counterfactual).map_err(|_| EvidenceError::IncompleteForkSuffix)?;
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
    let endogenous_counterfactual_suffix = counterfactual_suffix
        .iter()
        .filter(|event| is_endogenous_event(&event.event_type))
        .copied()
        .collect::<Vec<_>>();
    if baseline_suffix.is_empty() || endogenous_counterfactual_suffix.len() < 2 {
        return Err(EvidenceError::IncompleteForkSuffix);
    }
    let Some(intervention) = counterfactual_suffix
        .iter()
        .find(|event| event.event_type == intervention_event_type)
    else {
        return Err(EvidenceError::IncompleteForkSuffix);
    };
    let intervention_seq = intervention.seq;
    if counterfactual
        .contract
        .counterfactual
        .intervention
        .is_some()
    {
        verify_factual_suffix_invalidation(baseline, counterfactual, cut, intervention)?;
    }
    let by_seq = counterfactual
        .authoritative_events
        .iter()
        .map(|event| (event.seq, event))
        .collect::<BTreeMap<_, _>>();
    let complete_endogenous_suffix = endogenous_counterfactual_suffix
        .iter()
        .filter(|event| event.seq > intervention_seq)
        .find(|candidate| {
            let tail = endogenous_counterfactual_suffix
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

fn verify_factual_suffix_invalidation(
    baseline: &MoatProofEvidenceV1,
    counterfactual: &MoatProofEvidenceV1,
    cut: u64,
    intervention: &AuthoritativeEventV1,
) -> Result<(), EvidenceError> {
    let baseline_nodes = contract_event_nodes(&baseline.authoritative_events);
    let mut factual_suffix_nodes = baseline
        .authoritative_events
        .iter()
        .filter(|event| {
            event.seq > cut
                && contract_endogenous_event_type(event.event_type.as_str())
                && event.tick >= intervention.tick
        })
        .filter_map(|event| baseline_nodes.get(&event.seq).cloned())
        .collect::<Vec<_>>();
    factual_suffix_nodes.sort_unstable();
    let invalidated_nodes = counterfactual
        .contract
        .counterfactual
        .invalidation
        .invalid_artifacts
        .iter()
        .map(|artifact| artifact.producer.clone())
        .collect::<Vec<_>>();
    if counterfactual
        .contract
        .counterfactual
        .frontier
        .affected_nodes
        != factual_suffix_nodes
        || invalidated_nodes != factual_suffix_nodes
    {
        Err(EvidenceError::IncompleteForkSuffix)
    } else {
        Ok(())
    }
}

fn is_endogenous_event(event_type: &str) -> bool {
    matches!(
        event_type,
        "world.action.v1" | "world.observation.v1" | "proof.agent.reaction.v1" | "society.signal"
    )
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
    #[error("Wave 8 Scenario Room contract is incomplete or invalid")]
    InvalidContract,
    #[error("participant knowledge or authorization boundary is invalid")]
    InvalidKnowledgeBoundary,
    #[error("counterfactual dependency graph or generation contract is invalid")]
    InvalidDependencyGraph,
    #[error("counterfactual contract does not prove a complete endogenous suffix")]
    IncompleteRecomputationContract,
    #[error("atomic Tick failure evidence is incomplete")]
    IncompleteAtomicityEvidence,
    #[error("conformance report is incomplete or internally inconsistent")]
    InvalidConformanceReport,
    #[error("counterfactual Fork suffix is missing, copied, or causally incomplete")]
    IncompleteForkSuffix,
    #[error("non-interference matrix is incomplete or invalid")]
    InvalidNonInterferenceMatrix,
}

/// Return a hex digest for human-facing evidence reports.
#[must_use]
pub fn hex_digest(bytes: &[u8; 32]) -> String {
    let hash = Hash::from_bytes(*bytes);
    hash.to_hex().to_string()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod tests {
    use super::*;

    type EvidenceMutation = Box<dyn Fn(&mut MoatProofEvidenceV1)>;

    pub(crate) fn input() -> MoatProofInputV1 {
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

    pub(crate) fn evidence() -> MoatProofEvidenceV1 {
        let input = input();
        MoatProofEvidenceV1 {
            format_version: EVIDENCE_FORMAT_V1,
            manifest: ReproManifestV1 {
                format_version: EVIDENCE_FORMAT_V1,
                input_digest: [1; 32],
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
                scenario_room_digest: [4; 32],
                scheduler_digest: [9; 32],
                budget_digest: [10; 32],
            },
            authoritative_events: vec![
                AuthoritativeEventV1 {
                    seq: 1,
                    tick: 1,
                    entity: "body".to_owned(),
                    event_type: "world.observation.v1".to_owned(),
                    payload_digest: [1; 32],
                    causation_seq: None,
                },
                AuthoritativeEventV1 {
                    seq: 2,
                    tick: 1,
                    entity: "agent".to_owned(),
                    event_type: "proof.agent.reaction.v1".to_owned(),
                    payload_digest: [2; 32],
                    causation_seq: Some(1),
                },
                AuthoritativeEventV1 {
                    seq: 3,
                    tick: 2,
                    entity: "host".to_owned(),
                    event_type: "experiment.lifecycle.consent-closed.v1".to_owned(),
                    payload_digest: [7; 32],
                    causation_seq: None,
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
                dependency_class: DependencyClassV1::EndogenousRecomputed,
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
                    "experiment.lifecycle.consent-closed.v1".to_owned(),
                ],
                visible_events: vec![ParticipantEventV1 {
                    seq: 1,
                    event_type: "world.observation.v1".to_owned(),
                    payload_digest: [1; 32],
                }],
            }],
            plugin_failures: Vec::new(),
            host_closure: HostClosureAuditV1 {
                subject: "subject".to_owned(),
                requested_after_seq: 1,
                effective_after_seq: 3,
                closure_event_seq: 3,
                closure_event_type: "experiment.lifecycle.consent-closed.v1".to_owned(),
                closure_payload_digest: [7; 32],
                halted_at_tick_boundary: true,
            },
            contract: test_contract(),
        }
    }

    #[test]
    fn consent_audit_codec_round_trips_at_the_public_seam() {
        let audit = ConsentAuditV1 {
            subject: "subject-1".to_owned(),
            requested_after_seq: 4,
            effective_after_seq: 5,
            revocation_event_seq: 6,
            revocation_event_type: "consent.revoked.v1".to_owned(),
            revocation_payload_digest: [7; 32],
            halted_at_tick_boundary: true,
        };
        let encoded = strict_codec::encode_consent(&audit);
        assert_eq!(strict_codec::decode_consent(&encoded), Ok(audit));
        assert!(strict_codec::decode_consent(&Value::Array(Vec::new())).is_err());
        let Value::Array(fields) = encoded else {
            return;
        };
        for index in 0..fields.len() {
            let mut malformed = fields.clone();
            malformed[index] = Value::Map(Vec::new());
            assert!(strict_codec::decode_consent(&Value::Array(malformed)).is_err());
        }
    }

    #[test]
    fn consent_audit_verifier_accepts_one_effective_revocation() {
        let audit = ConsentAuditV1 {
            subject: "subject-1".to_owned(),
            requested_after_seq: 4,
            effective_after_seq: 5,
            revocation_event_seq: 5,
            revocation_event_type: "consent.revoked.v1".to_owned(),
            revocation_payload_digest: [7; 32],
            halted_at_tick_boundary: true,
        };
        let events = [AuthoritativeEventV1 {
            seq: 5,
            tick: 2,
            entity: "subject-1".to_owned(),
            event_type: "consent.revoked.v1".to_owned(),
            payload_digest: [7; 32],
            causation_seq: None,
        }];
        assert_eq!(verify_consent_audit(&audit, &events), Ok(()));
    }

    #[test]
    fn consent_audit_verifier_rejects_a_noncanonical_event_type() {
        let audit = ConsentAuditV1 {
            subject: "subject-1".to_owned(),
            requested_after_seq: 4,
            effective_after_seq: 5,
            revocation_event_seq: 5,
            revocation_event_type: "consent.granted.v1".to_owned(),
            revocation_payload_digest: [7; 32],
            halted_at_tick_boundary: true,
        };
        let events = [AuthoritativeEventV1 {
            seq: 5,
            tick: 2,
            entity: "subject-1".to_owned(),
            event_type: "consent.granted.v1".to_owned(),
            payload_digest: [7; 32],
            causation_seq: None,
        }];
        assert_eq!(
            verify_consent_audit(&audit, &events),
            Err(EvidenceError::InvalidConsentAudit)
        );
    }

    fn test_authorization_fixtures() -> (PrincipalRefV1, CapabilityGrantV1, AuthorizationDecisionV1)
    {
        let principal = PrincipalRefV1 {
            principal_id: "principal:operator".to_owned(),
            participant_id: "operator".to_owned(),
            subject_id: None,
            trust_domain: "test".to_owned(),
        };
        let grant = CapabilityGrantV1 {
            grant_id: "grant:operator".to_owned(),
            principal_id: principal.principal_id.clone(),
            capability: "observe".to_owned(),
            resource: "room".to_owned(),
            consent_epoch: 0,
            policy_digest: [3; 32],
        };
        let decision = AuthorizationDecisionV1 {
            principal_id: principal.principal_id.clone(),
            resource: "room".to_owned(),
            operation: "observe".to_owned(),
            allowed: true,
            reason: "test".to_owned(),
            consent_epoch: 0,
            grant_digest: [4; 32],
            decision_digest: [5; 32],
        };
        (principal, grant, decision)
    }

    fn test_counterfactual() -> CounterfactualContractV1 {
        let node = DependencyNodeV1 {
            tick: 1,
            scheduler_position: 0,
            owner_id: "body".to_owned(),
            output_ordinal: 0,
            schema_id: schema_id_for_event_type("world.observation.v1"),
            artifact_digest: [1; 32],
        };
        let frontier = RecomputationFrontierV1 {
            frontier_id: [1; 16],
            plan_digest: [2; 32],
            parent_cut_digest: [3; 32],
            dependency_graph_digest: [4; 32],
            intervention_seed_nodes: vec![node.clone()],
            affected_nodes: vec![node.clone()],
            owner_frontiers: vec![OwnerFrontierV1 {
                owner_id: "body".to_owned(),
                earliest_tick: 1,
                earliest_scheduler_position: 0,
                earliest_output_ordinal: 0,
                cause_node_digests: vec![[1; 32]],
            }],
            global_frontier_tick: 1,
            global_frontier_scheduler_position: 0,
            unknown_edge_policy: UnknownEdgePolicyV1::Reject,
            unknown_edge_coordinates: Vec::new(),
            endogenous_suffix_end_tick: 1,
            classification_bundle_digest: [5; 32],
            provenance_digest: [6; 32],
            frontier_digest: [7; 32],
        };
        let invalidation = SuffixInvalidationV1 {
            invalidation_id: [2; 16],
            plan_digest: [2; 32],
            fork_id: [3; 16],
            prior_generation: 0,
            new_generation: 1,
            frontier_digest: [7; 32],
            invalid_start: node.clone(),
            invalid_end: node.clone(),
            invalid_artifacts: vec![InvalidArtifactV1 {
                artifact_class: "event".to_owned(),
                schema_id: node.schema_id,
                artifact_digest: [1; 32],
                producer: node,
                prior_generation: 0,
                reason: SuffixInvalidationReasonV1::NewIntervention,
            }],
            invalid_checkpoint_digests: Vec::new(),
            invalid_projection_digests: Vec::new(),
            retained_exogenous_digests: vec![[8; 32]],
            reason: SuffixInvalidationReasonV1::NewIntervention,
            commit_timeline_id: [12; 16],
            commit_tick: 1,
            commit_seq: 1,
            provenance_digest: [9; 32],
            invalidation_digest: [10; 32],
        };
        CounterfactualContractV1 {
            fork_id: [3; 16],
            prior_generation: 0,
            generation: 1,
            intervention: None,
            dependencies: vec![InputDependencyV1 {
                consumer: DependencyNodeV1 {
                    tick: 1,
                    scheduler_position: 0,
                    owner_id: "body".to_owned(),
                    output_ordinal: 0,
                    schema_id: schema_id_for_event_type("world.observation.v1"),
                    artifact_digest: [1; 32],
                },
                source: DependencyNodeV1 {
                    tick: 0,
                    scheduler_position: 0,
                    owner_id: "scenario-room".to_owned(),
                    output_ordinal: 0,
                    schema_id: schema_id_for_event_type("scenario.input.v1"),
                    artifact_digest: [0; 32],
                },
                dependency_class: DependencyClassV1::EndogenousRecomputed,
                authorization_digest: [4; 32],
                provenance_digest: [5; 32],
            }],
            frontier,
            invalidation,
            recomputed_event_seqs: vec![2],
            retained_exogenous_digests: vec![[8; 32]],
            replay_claim: ReplayClaimV1::Exact,
            contract_digest: [11; 32],
        }
    }

    fn test_report() -> ConformanceReportV1 {
        let cases = vec![
            CaseOutcomeV1 {
                case_id: "scenario-air-gapped".to_owned(),
                fixture_digest: [14; 32],
                execution_profile_digest: [4; 32],
                mode: ExecutionModeV1::AirGapped,
                claim_layer: ClaimLayerV1::ReplayConformance,
                outcome: CaseOutcomeStatusV1::Pass,
                first_coordinate: None,
                expected_digest: Some([14; 32]),
                actual_digest: Some([14; 32]),
                expected_error: None,
                actual_error: None,
                replay_claim: ReplayClaimV1::Exact,
                redaction_state: RedactionStateV1::None,
                provenance_digest: [15; 32],
            },
            CaseOutcomeV1 {
                case_id: "scenario-local".to_owned(),
                fixture_digest: [14; 32],
                execution_profile_digest: [4; 32],
                mode: ExecutionModeV1::Local,
                claim_layer: ClaimLayerV1::ReplayConformance,
                outcome: CaseOutcomeStatusV1::Pass,
                first_coordinate: None,
                expected_digest: Some([14; 32]),
                actual_digest: Some([14; 32]),
                expected_error: None,
                actual_error: None,
                replay_claim: ReplayClaimV1::Exact,
                redaction_state: RedactionStateV1::None,
                provenance_digest: [15; 32],
            },
        ];
        let mut report = ConformanceReportV1 {
            report_id: [1; 16],
            subject_artifact_digest: [1; 32],
            profile_digest: [2; 32],
            normative_spec_digest: [3; 32],
            execution_profile_digest: [4; 32],
            fixture_bundle_digest: [5; 32],
            evaluator_source_digest: [6; 32],
            evaluator_binary_digest: [7; 32],
            evaluator_protocol_digest: [8; 32],
            implementation: ImplementationIdentityV1 {
                implementation_id: "test".to_owned(),
                source_digest: [1; 32],
                build_digest: [2; 32],
                binary_digest: [3; 32],
                public_contract_digest: [4; 32],
                organization_id: None,
            },
            independence: IndependenceEvidenceV1 {
                technical_independent: true,
                authorship_independent: true,
                organizational_independent: false,
                declaration_digest: [9; 32],
                shared_code_audit_digest: [10; 32],
                reviewer_ids: vec!["reviewer".to_owned()],
            },
            cases,
            passed: 2,
            failed: 0,
            skipped: 0,
            unavailable: 0,
            not_applicable: 0,
            replay_claim: ReplayClaimV1::Exact,
            redaction_state: RedactionStateV1::None,
            limitations_digest: [11; 32],
            provenance_digest: [12; 32],
            report_digest: [0; 32],
        };
        report.report_digest = report.digest().unwrap_or([0; 32]);
        report
    }

    fn report_at_canonical_byte_limit() -> (ConformanceReportV1, Vec<u8>) {
        const MAX_REPORT_BYTES: usize = 16 * 1024 * 1024;
        let mut report = test_report();
        let template = report.cases[0].clone();
        report.cases = (0..=65_535)
            .map(|index| {
                let mut case = template.clone();
                case.case_id = format!("{index:05}");
                case.outcome = CaseOutcomeStatusV1::Fail;
                case.actual_digest = Some([99; 32]);
                case.first_coordinate = Some(Vec::new());
                case
            })
            .collect();

        let set_coordinate_length = |report: &mut ConformanceReportV1, length: usize| {
            for case in &mut report.cases {
                case.first_coordinate = Some(vec![b'x'; length]);
            }
            refresh_test_report(report);
        };
        let mut low = 0_usize;
        let mut high = 128_usize;
        let mut best = 0_usize;
        while low <= high {
            let midpoint = low.midpoint(high);
            set_coordinate_length(&mut report, midpoint);
            let encoded = strict_codec::encode_conformance_report(&report).unwrap_or_default();
            if encoded.len() <= MAX_REPORT_BYTES {
                best = midpoint;
                low = midpoint + 1;
            } else if midpoint == 0 {
                break;
            } else {
                high = midpoint - 1;
            }
        }
        set_coordinate_length(&mut report, best);
        let current = strict_codec::encode_conformance_report(&report).unwrap_or_default();
        let additional_id_bytes = MAX_REPORT_BYTES - current.len();
        let per_case = additional_id_bytes / report.cases.len();
        let remainder = additional_id_bytes % report.cases.len();
        assert!(per_case <= 123);
        for (index, case) in report.cases.iter_mut().enumerate() {
            let suffix_length = per_case + usize::from(index < remainder);
            case.case_id = format!("{index:05}{}", "x".repeat(suffix_length));
        }
        refresh_test_report(&mut report);
        let encoded = strict_codec::encode_conformance_report(&report).unwrap_or_default();
        assert_eq!(encoded.len(), MAX_REPORT_BYTES);
        (report, encoded)
    }

    fn refresh_test_report(report: &mut ConformanceReportV1) {
        let mut counts = [0_u32; 5];
        let mut weakest_redaction = RedactionStateV1::None;
        let mut weakest_replay_claim = ReplayClaimV1::Exact;
        for case in &report.cases {
            match case.outcome {
                CaseOutcomeStatusV1::Pass => counts[0] += 1,
                CaseOutcomeStatusV1::Fail => counts[1] += 1,
                CaseOutcomeStatusV1::Skip => counts[2] += 1,
                CaseOutcomeStatusV1::Unavailable => counts[3] += 1,
                CaseOutcomeStatusV1::NotApplicable => counts[4] += 1,
            }
            weakest_redaction = weakest_redaction.max(case.redaction_state);
            weakest_replay_claim = weakest_replay_claim.max(case.replay_claim);
        }
        [
            &mut report.passed,
            &mut report.failed,
            &mut report.skipped,
            &mut report.unavailable,
            &mut report.not_applicable,
        ]
        .into_iter()
        .zip(counts)
        .for_each(|(slot, count)| *slot = count);
        report.redaction_state = weakest_redaction;
        report.replay_claim = weakest_replay_claim;
        report.report_digest = report.digest().unwrap_or([0; 32]);
    }

    fn assert_report_rejects(change: impl FnOnce(&mut ConformanceReportV1)) {
        let mut report = test_report();
        change(&mut report);
        report.report_digest = report.digest().unwrap_or([0; 32]);
        assert_eq!(
            report.validate(),
            Err(EvidenceError::InvalidConformanceReport)
        );
    }

    #[test]
    fn public_report_validation_rejects_each_independent_shape_violation() {
        assert_report_rejects(|report| report.report_id = [0; 16]);
        assert_report_rejects(|report| report.subject_artifact_digest = [0; 32]);
        assert_report_rejects(|report| report.profile_digest = [0; 32]);
        assert_report_rejects(|report| report.normative_spec_digest = [0; 32]);
        assert_report_rejects(|report| report.execution_profile_digest = [0; 32]);
        assert_report_rejects(|report| report.fixture_bundle_digest = [0; 32]);
        assert_report_rejects(|report| report.evaluator_source_digest = [0; 32]);
        assert_report_rejects(|report| report.evaluator_binary_digest = [0; 32]);
        assert_report_rejects(|report| report.evaluator_protocol_digest = [0; 32]);
        assert_report_rejects(|report| report.limitations_digest = [0; 32]);
        assert_report_rejects(|report| report.provenance_digest = [0; 32]);
        assert_report_rejects(|report| report.cases.clear());
        assert_report_rejects(|report| report.implementation.implementation_id.clear());
        assert_report_rejects(|report| {
            report.implementation.implementation_id = "x".repeat(129);
        });
        assert_report_rejects(|report| {
            report.implementation.organization_id = Some(String::new());
        });
        assert_report_rejects(|report| {
            report.implementation.organization_id = Some("x".repeat(129));
        });
        assert_report_rejects(|report| report.implementation.source_digest = [0; 32]);
        assert_report_rejects(|report| report.implementation.build_digest = [0; 32]);
        assert_report_rejects(|report| report.implementation.binary_digest = [0; 32]);
        assert_report_rejects(|report| report.implementation.public_contract_digest = [0; 32]);
        assert_report_rejects(|report| report.independence.reviewer_ids.clear());
        assert_report_rejects(|report| {
            report.independence.reviewer_ids =
                (0..33).map(|i| format!("reviewer-{i:02}")).collect();
        });
        assert_report_rejects(|report| report.independence.reviewer_ids[0].clear());
        assert_report_rejects(|report| {
            report.independence.reviewer_ids = vec!["zulu".to_owned(), "alpha".to_owned()];
        });
        assert_report_rejects(|report| report.independence.declaration_digest = [0; 32]);
        assert_report_rejects(|report| report.independence.shared_code_audit_digest = [0; 32]);

        assert_report_rejects(|report| report.cases[0].case_id.clear());
        assert_report_rejects(|report| report.cases[0].case_id = "x".repeat(129));
        assert_report_rejects(|report| report.cases[0].fixture_digest = [0; 32]);
        assert_report_rejects(|report| report.cases[0].execution_profile_digest = [0; 32]);
        assert_report_rejects(|report| report.cases[0].provenance_digest = [0; 32]);
        assert_report_rejects(|report| report.cases[0].first_coordinate = Some(vec![0; 129]));
        assert_report_rejects(|report| {
            report.cases[0].expected_digest = None;
            report.cases[0].actual_digest = None;
        });
        assert_report_rejects(|report| {
            report.cases[0].redaction_state = RedactionStateV1::RedactedViews;
            report.cases[0].replay_claim = ReplayClaimV1::Exact;
        });
        assert_report_rejects(|report| {
            report.cases[0].redaction_state = RedactionStateV1::StructuralOnly;
        });
        assert_report_rejects(|report| {
            report.cases[0].redaction_state = RedactionStateV1::EvidenceMissing;
        });
        assert_report_rejects(|report| {
            report.cases[0].outcome = CaseOutcomeStatusV1::Fail;
        });
        assert_report_rejects(|report| {
            report.cases[1] = report.cases[0].clone();
        });
        assert_report_rejects(|report| {
            report.passed = 1;
        });
        assert_report_rejects(|report| {
            report.redaction_state = RedactionStateV1::RedactedViews;
        });
        assert_report_rejects(|report| {
            report.replay_claim = ReplayClaimV1::StructuralOnly;
        });

        assert_ne!(test_report().digest().unwrap_or([0; 32]), [1; 32]);
    }

    #[test]
    fn public_report_case_predicates_and_boundaries_are_fail_closed() {
        let valid = test_report().cases[0].clone();
        let assert_case_rejects = |case: CaseOutcomeV1| {
            let mut keys = BTreeSet::new();
            assert_eq!(
                validate_conformance_case(&case, &mut keys),
                Err(EvidenceError::InvalidConformanceReport)
            );
        };
        let assert_case_accepts = |case: CaseOutcomeV1| {
            let mut keys = BTreeSet::new();
            assert_eq!(validate_conformance_case(&case, &mut keys), Ok(()));
        };

        let mut at_limit = valid.clone();
        at_limit.case_id = "x".repeat(128);
        at_limit.outcome = CaseOutcomeStatusV1::Fail;
        at_limit.actual_digest = Some([15; 32]);
        at_limit.first_coordinate = Some(vec![b'x'; 128]);
        assert_case_accepts(at_limit);
        let mut too_long = valid.clone();
        too_long.case_id = "x".repeat(129);
        assert_case_rejects(too_long);
        let mut too_long_coordinate = valid.clone();
        too_long_coordinate.first_coordinate = Some(vec![b'x'; 129]);
        assert_case_rejects(too_long_coordinate);

        let duplicate = valid.clone();
        let mut keys = BTreeSet::new();
        assert!(keys.insert((
            duplicate.case_id.as_str(),
            duplicate.mode,
            duplicate.claim_layer,
            duplicate.fixture_digest,
        )));
        assert_eq!(
            validate_conformance_case(&duplicate, &mut keys),
            Err(EvidenceError::InvalidConformanceReport)
        );

        for invalid in [
            {
                let mut value = valid.clone();
                value.case_id = "   ".to_owned();
                value
            },
            {
                let mut value = valid.clone();
                value.fixture_digest = [0; 32];
                value
            },
            {
                let mut value = valid.clone();
                value.execution_profile_digest = [0; 32];
                value
            },
            {
                let mut value = valid.clone();
                value.provenance_digest = [0; 32];
                value
            },
        ] {
            assert_case_rejects(invalid);
        }

        let mut invalid_result = valid.clone();
        invalid_result.expected_digest = None;
        invalid_result.actual_digest = None;
        assert!(!valid_conformance_case_result(&invalid_result));
        assert_case_rejects(invalid_result);

        let mut mismatched_digest = valid.clone();
        mismatched_digest.actual_digest = Some([15; 32]);
        assert!(!valid_conformance_case_result(&mismatched_digest));
        assert_case_rejects(mismatched_digest);

        let mut mismatched_error = valid.clone();
        mismatched_error.expected_digest = None;
        mismatched_error.actual_digest = None;
        mismatched_error.expected_error = Some(SafeErrorCodeV1::ClosureIncomplete);
        mismatched_error.actual_error = None;
        assert!(!valid_conformance_case_result(&mismatched_error));
        assert_case_rejects(mismatched_error);

        let mut coordinate_without_match = valid;
        coordinate_without_match.first_coordinate = Some(vec![1]);
        assert!(!valid_conformance_case_result(&coordinate_without_match));
        assert_case_rejects(coordinate_without_match);
    }

    #[test]
    fn public_report_redaction_predicates_are_fail_closed() {
        let valid = test_report().cases[0].clone();
        let assert_case_rejects = |case: CaseOutcomeV1| {
            let mut keys = BTreeSet::new();
            assert_eq!(
                validate_conformance_case(&case, &mut keys),
                Err(EvidenceError::InvalidConformanceReport)
            );
        };

        for state in [
            RedactionStateV1::StructuralOnly,
            RedactionStateV1::EvidenceMissing,
        ] {
            let mut wrong_replay = valid.clone();
            wrong_replay.redaction_state = state;
            wrong_replay.replay_claim = ReplayClaimV1::Exact;
            assert!(!valid_redacted_case(&wrong_replay));
            assert_case_rejects(wrong_replay);
        }

        let mut structural = valid.clone();
        structural.redaction_state = RedactionStateV1::StructuralOnly;
        structural.replay_claim = ReplayClaimV1::StructuralOnly;
        structural.expected_digest = None;
        structural.actual_digest = None;
        structural.expected_error = None;
        structural.actual_error = None;
        structural.first_coordinate = None;
        assert!(valid_redacted_case(&structural));
        let changes: [fn(&mut CaseOutcomeV1); 6] = [
            |case: &mut CaseOutcomeV1| case.replay_claim = ReplayClaimV1::Exact,
            |case: &mut CaseOutcomeV1| case.expected_digest = Some([1; 32]),
            |case: &mut CaseOutcomeV1| case.actual_digest = Some([1; 32]),
            |case: &mut CaseOutcomeV1| {
                case.expected_error = Some(SafeErrorCodeV1::ClosureIncomplete);
            },
            |case: &mut CaseOutcomeV1| case.actual_error = Some(SafeErrorCodeV1::ClosureIncomplete),
            |case: &mut CaseOutcomeV1| case.first_coordinate = Some(vec![1]),
        ];
        for change in changes {
            let mut invalid = structural.clone();
            change(&mut invalid);
            assert!(!valid_redacted_case(&invalid));
            assert_case_rejects(invalid);
        }

        let mut evidence_missing = structural.clone();
        evidence_missing.redaction_state = RedactionStateV1::EvidenceMissing;
        evidence_missing.replay_claim = ReplayClaimV1::UnverifiableArtifactsMissing;
        evidence_missing.outcome = CaseOutcomeStatusV1::Fail;
        assert!(valid_redacted_case(&evidence_missing));
        let mut missing_pass = evidence_missing.clone();
        missing_pass.outcome = CaseOutcomeStatusV1::Pass;
        assert!(!valid_redacted_case(&missing_pass));
        assert_case_rejects(missing_pass);

        let mut incompatible_redacted = valid;
        incompatible_redacted.redaction_state = RedactionStateV1::RedactedViews;
        incompatible_redacted.replay_claim = ReplayClaimV1::IncompatibleProfile;
        assert!(valid_redacted_case(&incompatible_redacted));
        assert_eq!(
            validate_conformance_case(&incompatible_redacted, &mut BTreeSet::new()),
            Ok(())
        );

        let mut incompatible_structural = structural;
        incompatible_structural.replay_claim = ReplayClaimV1::IncompatibleProfile;
        assert!(valid_redacted_case(&incompatible_structural));

        let mut incompatible_missing = evidence_missing;
        incompatible_missing.replay_claim = ReplayClaimV1::IncompatibleProfile;
        assert!(valid_redacted_case(&incompatible_missing));

        assert_eq!(
            ReplayClaimV1::IncompatibleProfile.after_erasure(ErasureDispositionV1::StructuralOnly),
            ReplayClaimV1::IncompatibleProfile
        );
    }

    #[test]
    fn public_report_shape_boundaries_and_verifier_claims_are_exact() {
        let mut at_limit = test_report();
        at_limit.implementation.implementation_id = "x".repeat(128);
        at_limit.implementation.organization_id = Some("o".repeat(128));
        at_limit.independence.reviewer_ids = (0..32)
            .map(|index| format!("reviewer-{index:02}"))
            .collect();
        at_limit.independence.reviewer_ids[0] = "a".repeat(128);
        at_limit.cases[0].case_id = "c".repeat(128);
        at_limit.cases[0].outcome = CaseOutcomeStatusV1::Fail;
        at_limit.cases[0].actual_digest = Some([15; 32]);
        at_limit.cases[0].first_coordinate = Some(vec![b'x'; 128]);
        refresh_test_report(&mut at_limit);
        assert_eq!(at_limit.validate(), Ok(()));
        let encoded = at_limit.to_canonical_cbor().unwrap_or_default();
        assert!(encoded.len() > 1_025);
        assert_eq!(
            ConformanceReportV1::from_canonical_cbor(&encoded),
            Ok(at_limit)
        );

        let mut reviewer_over_limit = test_report();
        reviewer_over_limit.independence.reviewer_ids[0] = "a".repeat(129);
        assert_eq!(
            validate_conformance_report_shape(&reviewer_over_limit),
            Err(EvidenceError::InvalidConformanceReport)
        );

        let mut cases_over_limit = test_report();
        cases_over_limit.cases = vec![cases_over_limit.cases[0].clone(); 65_537];
        assert_eq!(
            validate_conformance_report_shape(&cases_over_limit),
            Err(EvidenceError::InvalidConformanceReport)
        );

        let mut invalid = evidence();
        invalid.manifest.replay_claim = ReplayClaimV1::StructuralOnly;
        invalid.contract.conformance_report.replay_claim = ReplayClaimV1::Exact;
        invalid.contract.counterfactual.replay_claim = ReplayClaimV1::StructuralOnly;
        assert_eq!(
            verify_conformance_report(&invalid),
            Err(EvidenceError::InvalidConformanceReport)
        );

        let mut invalid = evidence();
        invalid.manifest.replay_claim = ReplayClaimV1::StructuralOnly;
        invalid.contract.conformance_report.replay_claim = ReplayClaimV1::StructuralOnly;
        invalid.contract.counterfactual.replay_claim = ReplayClaimV1::Exact;
        assert_eq!(
            verify_conformance_report(&invalid),
            Err(EvidenceError::InvalidConformanceReport)
        );

        let mut invalid = evidence();
        invalid.manifest.execution_mode = ExecutionModeV1::Replay;
        assert_eq!(
            verify_conformance_report(&invalid),
            Err(EvidenceError::InvalidConformanceReport)
        );
    }

    #[test]
    fn public_cnr1_codec_validates_shape_and_fields_zero_through_twenty_two() {
        let report = test_report();
        let bytes = report.to_canonical_cbor().unwrap_or_default();
        assert_eq!(
            ConformanceReportV1::from_canonical_cbor(&bytes),
            Ok(report.clone())
        );

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            ConformanceReportV1::from_canonical_cbor(&trailing),
            Err(EvidenceError::InvalidConformanceReport)
        );

        for index in 0..23 {
            let mut fields =
                ciborium::from_reader::<Value, _>(Cursor::new(&bytes)).unwrap_or(Value::Null);
            if let Value::Array(ref mut values) = fields {
                values[index] = Value::Null;
            }
            let mut malformed = Vec::new();
            ciborium::into_writer(&fields, &mut malformed).unwrap_or_default();
            assert_eq!(
                ConformanceReportV1::from_canonical_cbor(&malformed),
                Err(EvidenceError::InvalidConformanceReport)
            );
        }

        let mut tampered_digest =
            ciborium::from_reader::<Value, _>(Cursor::new(&bytes)).unwrap_or(Value::Null);
        if let Value::Array(ref mut values) = tampered_digest {
            values[22] = Value::Bytes(vec![0; 32]);
        }
        let mut malformed = Vec::new();
        ciborium::into_writer(&tampered_digest, &mut malformed).unwrap_or_default();
        assert_eq!(
            ConformanceReportV1::from_canonical_cbor(&malformed),
            Err(EvidenceError::InvalidConformanceReport)
        );

        let (at_limit, at_limit_bytes) = report_at_canonical_byte_limit();
        assert_eq!(at_limit_bytes.len(), 16 * 1024 * 1024);
        assert_eq!(at_limit.to_canonical_cbor(), Ok(at_limit_bytes.clone()));
        assert_eq!(
            ConformanceReportV1::from_canonical_cbor(&at_limit_bytes),
            Ok(at_limit)
        );

        let oversized = vec![0; 16 * 1024 * 1024 + 1];
        assert_eq!(
            ConformanceReportV1::from_canonical_cbor(&oversized),
            Err(EvidenceError::InvalidConformanceReport)
        );

        let mut mixed_profile_report = report;
        mixed_profile_report.cases[0].execution_profile_digest = [99; 32];
        mixed_profile_report.report_digest = mixed_profile_report.digest().unwrap_or([0; 32]);
        // CNR1 permits a per-case execution-profile matrix; CPF1 performs
        // the authoritative fixture/profile membership check.
        assert_eq!(mixed_profile_report.validate(), Ok(()));

        let mut unordered_cases =
            ciborium::from_reader::<Value, _>(Cursor::new(&bytes)).unwrap_or(Value::Null);
        if let Value::Array(ref mut values) = unordered_cases {
            if let Value::Array(ref mut cases) = values[13] {
                cases.swap(0, 1);
            }
        }
        let mut malformed = Vec::new();
        ciborium::into_writer(&unordered_cases, &mut malformed).unwrap_or_default();
        assert_eq!(
            ConformanceReportV1::from_canonical_cbor(&malformed),
            Err(EvidenceError::InvalidConformanceReport)
        );

        let mut oversized_report = test_report();
        let template = oversized_report.cases[0].clone();
        oversized_report.cases = (0..=65_535)
            .map(|index| {
                let mut case = template.clone();
                case.case_id = format!("{index:05}{}", "x".repeat(123));
                case.outcome = CaseOutcomeStatusV1::Fail;
                case.actual_digest = Some([99; 32]);
                case.first_coordinate = Some(vec![b'x'; 128]);
                case
            })
            .collect();
        refresh_test_report(&mut oversized_report);
        assert_eq!(
            oversized_report.to_canonical_cbor(),
            Err(EvidenceError::InvalidConformanceReport)
        );
    }

    fn test_contract() -> Wave8ProofContractV1 {
        let (principal, grant, decision) = test_authorization_fixtures();
        Wave8ProofContractV1 {
            scenario_room: ScenarioRoomFixtureV1 {
                room_id: "room".to_owned(),
                input_digest: [1; 32],
                horizon_ticks: 1,
                random_seed: 1,
                network_enabled: false,
                exogenous_digests: vec![[2; 32]],
                fixed_policy_digests: vec![[3; 32]],
                principals: vec![principal.clone()],
                grants: vec![grant.clone()],
                room_digest: [4; 32],
            },
            plugin_boundary: wave8_plugin_boundary(),
            knowledge_snapshots: vec![KnowledgeSnapshotV1 {
                participant_id: "operator".to_owned(),
                principal,
                grant,
                authorization: decision.clone(),
                tick: 1,
                visible_event_seqs: vec![1],
                visible_event_digests: vec![[1; 32]],
                hidden_event_types: vec!["proof.agent.reaction.v1".to_owned()],
                consent_epoch: 0,
                snapshot_digest: [14; 32],
            }],
            authorization_decisions: vec![decision],
            counterfactual: test_counterfactual(),
            atomicity: vec![TickAtomicityV1 {
                tick: 1,
                fork_generation: 1,
                staged_event_count: 1,
                committed_event_count: 1,
                state_digest_before: [1; 32],
                state_digest_after: [2; 32],
                committed: true,
                failure_class: None,
            }],
            conformance_report: test_report(),
            non_interference: wave8_non_interference_matrix([1; 32]),
        }
    }

    #[test]
    fn validates_parameterized_input_and_hashes_it() -> Result<(), pos_core::CoreError> {
        let value = input();
        assert!(value.validate().is_ok());
        let digest = value.digest()?;
        let mut changed = value;
        changed.random_seed += 1;
        assert_ne!(digest, changed.digest()?);
        Ok(())
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
    fn compares_equal_and_classifies_event_divergence() -> Result<(), pos_core::CoreError> {
        let left = evidence();
        let mut right = left.clone();
        assert_eq!(compare(&left, &right)?.divergence, DivergenceClassV1::None);
        right.authoritative_events[0].payload_digest = [2; 32];
        let comparison = compare(&left, &right)?;
        assert!(!comparison.equal);
        assert_eq!(
            comparison.divergence,
            DivergenceClassV1::AuthoritativeEvents
        );
        assert_ne!(comparison.left_digest, comparison.right_digest);
        Ok(())
    }

    #[test]
    fn compares_authoritative_outputs_by_event_and_projection() -> Result<(), pos_core::CoreError> {
        let left = evidence();
        let mut right = left.clone();
        assert_eq!(
            compare_authoritative_outputs(&left, &right)?.divergence,
            DivergenceClassV1::None
        );
        right.authoritative_events[0].payload_digest = [8; 32];
        assert_eq!(
            compare_authoritative_outputs(&left, &right)?.divergence,
            DivergenceClassV1::AuthoritativeEvents
        );
        right = left.clone();
        right.projections[0].state = serde_json::json!({"changed": true});
        assert_eq!(
            compare_authoritative_outputs(&left, &right)?.divergence,
            DivergenceClassV1::Projections
        );
        Ok(())
    }

    #[test]
    fn compares_metadata_projection_and_trace_divergence() -> Result<(), pos_core::CoreError> {
        let left = evidence();
        let mut right = left.clone();
        right.manifest.seed += 1;
        assert_eq!(
            compare(&left, &right)?.divergence,
            DivergenceClassV1::Metadata
        );
        right = left.clone();
        right.projections[0].state = serde_json::json!({"x": 2});
        assert_eq!(
            compare(&left, &right)?.divergence,
            DivergenceClassV1::Projections
        );
        right = left;
        right.causal_trace[0].effect_seq += 1;
        assert_eq!(
            compare(&evidence(), &right)?.divergence,
            DivergenceClassV1::CausalTrace
        );
        Ok(())
    }

    #[test]
    fn compares_observability_divergence() -> Result<(), pos_core::CoreError> {
        let left = evidence();
        let mut right = left.clone();
        right.uncertainty[0].confidence = 0.8;
        assert_eq!(
            compare(&left, &right)?.divergence,
            DivergenceClassV1::Observability
        );
        right = left.clone();
        right.participant_views[0].hidden_event_types.clear();
        assert_eq!(
            compare(&left, &right)?.divergence,
            DivergenceClassV1::Observability
        );
        right = left.clone();
        right.plugin_failures.push(PluginFailureV1 {
            plugin: "plugin".to_owned(),
            class: PluginFailureClassV1::PluginCrash,
            tick: 1,
            committed: false,
            staged_event_count: 0,
            committed_event_count: 0,
            state_digest_before: [1; 32],
            state_digest_after: [1; 32],
            sibling_step_count: 1,
        });
        assert_eq!(
            compare(&left, &right)?.divergence,
            DivergenceClassV1::Observability
        );
        right = left;
        right.host_closure.halted_at_tick_boundary = false;
        assert_eq!(
            compare(&evidence(), &right)?.divergence,
            DivergenceClassV1::Observability
        );
        Ok(())
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
            tick: 3,
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
            class: PluginFailureClassV1::PluginCrash,
            tick: 1,
            committed: true,
            staged_event_count: 0,
            committed_event_count: 0,
            state_digest_before: [1; 32],
            state_digest_after: [1; 32],
            sibling_step_count: 1,
        });
        assert_eq!(
            verify_evidence(&invalid),
            Err(EvidenceError::CommittedPluginFailure)
        );
        let mut invalid = valid;
        invalid.host_closure.halted_at_tick_boundary = false;
        assert_eq!(
            verify_evidence(&invalid),
            Err(EvidenceError::InvalidConsentAudit)
        );

        let mut invalid = evidence();
        invalid.manifest.execution_mode = ExecutionModeV1::Replay;
        assert_eq!(
            verify_evidence(&invalid),
            Err(EvidenceError::InvalidConformanceReport)
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
        invalid.causal_trace[0].relation = "unclassified".to_owned();
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
        invalid.host_closure.closure_payload_digest = [0; 32];
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
    fn participant_event_must_have_an_authoritative_match() {
        let value = evidence();
        let mut view = value.participant_views[0].clone();
        view.visible_events[0].seq = 3;
        let sequences = std::collections::BTreeSet::from([1_u64, 3_u64]);
        assert_eq!(
            verify_participant_views(
                &[view],
                std::slice::from_ref(&value.authoritative_events[0]),
                &sequences,
            ),
            Err(EvidenceError::InvalidParticipantView)
        );
    }

    #[test]
    fn verifier_rejects_each_consent_boundary() {
        let cases: Vec<EvidenceMutation> = vec![
            Box::new(|value| value.host_closure.subject.clear()),
            Box::new(|value| value.host_closure.closure_event_type = "other".to_owned()),
            Box::new(|value| value.host_closure.effective_after_seq = 0),
            Box::new(|value| value.host_closure.closure_event_seq = 2),
            Box::new(|value| value.host_closure.halted_at_tick_boundary = false),
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

    #[test]
    fn verifier_accepts_host_closure_and_rejects_each_host_closure_boundary() {
        fn host_fixture() -> (HostClosureAuditV1, Vec<AuthoritativeEventV1>) {
            let mut value = evidence();
            value.host_closure.closure_event_type =
                "experiment.lifecycle.consent-closed.v1".to_owned();
            value.authoritative_events[2].event_type =
                "experiment.lifecycle.consent-closed.v1".to_owned();
            (value.host_closure, value.authoritative_events)
        }

        let (valid_audit, valid_events) = host_fixture();
        assert_eq!(verify_host_closure(&valid_audit, &valid_events), Ok(()));
        let mut valid = evidence();
        valid.host_closure.closure_event_type = "experiment.lifecycle.consent-closed.v1".to_owned();
        valid.authoritative_events[2].event_type =
            "experiment.lifecycle.consent-closed.v1".to_owned();
        assert_eq!(verify_evidence(&valid), Ok(()));

        let cases: [fn(&mut HostClosureAuditV1, &mut Vec<AuthoritativeEventV1>); 9] = [
            |audit, _| audit.subject.clear(),
            |audit, _| audit.closure_payload_digest = [0; 32],
            |audit, _| audit.requested_after_seq = audit.effective_after_seq,
            |audit, events| {
                audit.closure_event_seq = 2;
                events[2].seq = 2;
            },
            |audit, _| audit.halted_at_tick_boundary = false,
            |_, events| {
                let duplicate = events[2].clone();
                events.push(duplicate);
            },
            |_, events| {
                events[2].event_type = "other".to_owned();
                events.push(AuthoritativeEventV1 {
                    seq: 4,
                    tick: 3,
                    entity: "host".to_owned(),
                    event_type: "experiment.lifecycle.consent-closed.v1".to_owned(),
                    payload_digest: [7; 32],
                    causation_seq: None,
                });
            },
            |_, events| events[2].seq = 4,
            |_, events| events[2].payload_digest = [8; 32],
        ];
        for mutate in cases {
            let (mut audit, mut events) = host_fixture();
            mutate(&mut audit, &mut events);
            assert_eq!(
                verify_host_closure(&audit, &events),
                Err(EvidenceError::InvalidConsentAudit)
            );
        }
    }

    macro_rules! typed_verifier_boundary_cases {
        () => {{
            for event_type in [
                "scenario.input.v1",
                "world.action.v1",
                "world.observation.v1",
                "proof.agent.reaction.v1",
                "society.signal",
                "consent.revoked.v1",
                "unknown.event.v1",
            ] {
                assert_ne!(schema_id_for_event_type(event_type), 0);
            }
            assert_eq!(schema_id_for_event_type("society.signal"), 300);
            assert_eq!(schema_id_for_event_type("consent.revoked.v1"), 400);
            assert_ne!(schema_id_for_event_type("unknown.event.v1"), 1);
            for claim in [
                ReplayClaimV1::Exact,
                ReplayClaimV1::ExactAuthoritativeWithRedactedViews,
                ReplayClaimV1::StructuralOnly,
                ReplayClaimV1::UnverifiableArtifactsMissing,
                ReplayClaimV1::IncompatibleProfile,
            ] {
                for disposition in [
                    ErasureDispositionV1::None,
                    ErasureDispositionV1::RedactedViews,
                    ErasureDispositionV1::StructuralOnly,
                    ErasureDispositionV1::ArtifactsMissing,
                    ErasureDispositionV1::IncompatibleProfile,
                ] {
                    let degraded = claim.after_erasure(disposition);
                    assert!(degraded.is_no_stronger_than(ReplayClaimV1::Exact));
                }
                assert!(claim.is_no_stronger_than(ReplayClaimV1::Exact));
            }

            let boundary = wave8_plugin_boundary();
            assert_eq!(boundary.validate(), Ok(()));
            let mut invalid = boundary.clone();
            invalid.manifest_version = 0;
            assert!(invalid.validate().is_err());
            invalid = boundary.clone();
            invalid.manifest_digest = [1; 32];
            assert_eq!(
                invalid.validate(),
                Err(PluginBoundaryError::ManifestDigestMismatch)
            );
            invalid = boundary;
            invalid.release_digest = [1; 32];
            assert_eq!(
                invalid.validate(),
                Err(PluginBoundaryError::ReleaseDigestMismatch)
            );

            let value = evidence();
            assert!(value.to_verification_result_cbor().is_ok());
            let Ok(sequences) = event_sequences(&value.authoritative_events) else {
                return;
            };
            for dependency_class in [
                DependencyClassV1::ExogenousFrozen,
                DependencyClassV1::InterventionAssigned,
                DependencyClassV1::EndogenousRecomputed,
                DependencyClassV1::FixedPolicy,
                DependencyClassV1::PresentationOnly,
            ] {
                let mut trace = value.causal_trace.clone();
                trace[0].dependency_class = dependency_class;
                assert!(
                    verify_causal_trace(&value.authoritative_events, &trace, &sequences).is_ok()
                );
            }
            for relation in [
                "physical_to_agent",
                "agent_to_society",
                "intervention_to_physics",
                "derived",
            ] {
                let mut trace = value.causal_trace.clone();
                trace[0].relation = relation.to_owned();
                assert!(
                    verify_causal_trace(&value.authoritative_events, &trace, &sequences).is_ok()
                );
            }
            for visibility in ["operator", "participant", "public"] {
                let mut trace = value.causal_trace.clone();
                trace[0].visibility = visibility.to_owned();
                assert!(
                    verify_causal_trace(&value.authoritative_events, &trace, &sequences).is_ok()
                );
            }
            assert!(event_sequences(&[]).is_err());
            assert!(verify_uncertainty(&[]).is_ok());
            assert!(verify_plugin_failures(&[]).is_ok());
            let mut failure = value.clone();
            failure.plugin_failures = vec![PluginFailureV1 {
                plugin: String::new(),
                class: PluginFailureClassV1::PluginCrash,
                tick: 1,
                committed: false,
                staged_event_count: 0,
                committed_event_count: 0,
                state_digest_before: [1; 32],
                state_digest_after: [1; 32],
                sibling_step_count: 1,
            }];
            assert_eq!(
                verify_plugin_failures(&failure.plugin_failures),
                Err(EvidenceError::CommittedPluginFailure)
            );
            let mut duplicate_revocation = value.clone();
            duplicate_revocation
                .authoritative_events
                .push(AuthoritativeEventV1 {
                    seq: 4,
                    tick: 3,
                    entity: "host".to_owned(),
                    event_type: "consent.revoked.v1".to_owned(),
                    payload_digest: [7; 32],
                    causation_seq: None,
                });
            assert_eq!(
                verify_consent_audit(
                    &ConsentAuditV1 {
                        subject: duplicate_revocation.host_closure.subject.clone(),
                        requested_after_seq: duplicate_revocation.host_closure.requested_after_seq,
                        effective_after_seq: duplicate_revocation.host_closure.effective_after_seq,
                        revocation_event_seq: duplicate_revocation.host_closure.closure_event_seq,
                        revocation_event_type: "consent.revoked.v1".to_owned(),
                        revocation_payload_digest: duplicate_revocation.host_closure.closure_payload_digest,
                        halted_at_tick_boundary: duplicate_revocation.host_closure.halted_at_tick_boundary,
                    },
                    &duplicate_revocation.authoritative_events,
                ),
                Err(EvidenceError::InvalidConsentAudit)
            );
            for event_type in [
                "world.action.v1",
                "world.observation.v1",
                "proof.agent.reaction.v1",
                "society.signal",
                "other",
            ] {
                let event = AuthoritativeEventV1 {
                    seq: 1,
                    tick: 1,
                    entity: "entity".to_owned(),
                    event_type: event_type.to_owned(),
                    payload_digest: [1; 32],
                    causation_seq: None,
                };
                let _ = contract_event_node(&event);
            }

            let matrix_mutations: Vec<EvidenceMutation> = vec![
                Box::new(|value| value.contract.non_interference.clear()),
                Box::new(|value| value.contract.non_interference[0].fixture_id.clear()),
                Box::new(|value| {
                    value.contract.non_interference[0].variant = NonInterferenceVariantV1::Denial;
                }),
                Box::new(|value| {
                    value.contract.non_interference[0].mode = ExecutionModeV1::AirGapped
                }),
                Box::new(|value| value.contract.non_interference[0].control_input_digest = [0; 32]),
                Box::new(|value| value.contract.non_interference[0].canary_input_digest = [0; 32]),
                Box::new(|value| {
                    value.contract.non_interference[0].canary_input_digest =
                        value.contract.non_interference[0].control_input_digest;
                }),
                Box::new(|value| value.contract.non_interference[0].authoritative_digest = [0; 32]),
                Box::new(|value| value.contract.non_interference[0].public_digest = [0; 32]),
                Box::new(|value| value.contract.non_interference[0].operational_digest = [0; 32]),
                Box::new(|value| value.contract.non_interference[0].authoritative_equal = false),
                Box::new(|value| value.contract.non_interference[0].public_equal = false),
                Box::new(|value| value.contract.non_interference[0].operational_equal = false),
                Box::new(|value| value.contract.non_interference[0].provenance_digest = [0; 32]),
            ];
            for mutate in matrix_mutations {
                let mut invalid = value.clone();
                mutate(&mut invalid);
                assert_eq!(
                    verify_wave8_contract(&invalid),
                    Err(EvidenceError::InvalidNonInterferenceMatrix)
                );
            }

            let room_mutations: Vec<EvidenceMutation> = vec![
                Box::new(|value| value.contract.scenario_room.input_digest = [8; 32]),
                Box::new(|value| value.manifest.scenario_room_digest = [8; 32]),
                Box::new(|value| value.contract.scenario_room.network_enabled = true),
                Box::new(|value| value.contract.scenario_room.room_id.clear()),
                Box::new(|value| value.contract.scenario_room.room_digest = [0; 32]),
                Box::new(|value| value.contract.scenario_room.horizon_ticks = 0),
                Box::new(|value| value.contract.scenario_room.principals.clear()),
                Box::new(|value| value.contract.scenario_room.grants.clear()),
                Box::new(|value| {
                    value.contract.scenario_room.principals[0].participant_id = "z".to_owned();
                }),
                Box::new(|value| {
                    value.contract.scenario_room.principals[0]
                        .principal_id
                        .clear();
                }),
                Box::new(|value| {
                    value.contract.scenario_room.principals[0]
                        .trust_domain
                        .clear();
                }),
                Box::new(|value| {
                    value.contract.scenario_room.principals[0].principal_id =
                        "principal:duplicate".to_owned();
                    value.contract.scenario_room.grants[0].principal_id =
                        "principal:duplicate".to_owned();
                }),
                Box::new(|value| value.contract.scenario_room.grants[0].grant_id.clear()),
                Box::new(|value| value.contract.scenario_room.grants[0].capability.clear()),
                Box::new(|value| value.contract.scenario_room.grants[0].resource.clear()),
                Box::new(|value| value.contract.scenario_room.grants[0].policy_digest = [0; 32]),
            ];
            for mutate in room_mutations {
                let mut invalid = value.clone();
                mutate(&mut invalid);
                assert!(verify_wave8_contract(&invalid).is_err());
            }

            let knowledge_mutations: Vec<EvidenceMutation> = vec![
                Box::new(|value| value.contract.knowledge_snapshots[0].snapshot_digest = [0; 32]),
                Box::new(|value| {
                    value.contract.knowledge_snapshots[0]
                        .authorization
                        .decision_digest = [0; 32];
                }),
                Box::new(|value| {
                    value.contract.knowledge_snapshots[0]
                        .authorization
                        .grant_digest = [0; 32];
                }),
                Box::new(|value| {
                    value.contract.knowledge_snapshots[0]
                        .visible_event_digests
                        .clear();
                }),
                Box::new(|value| {
                    value.contract.knowledge_snapshots[0].visible_event_seqs = vec![2, 1]
                }),
                Box::new(|value| {
                    value.contract.knowledge_snapshots[0]
                        .hidden_event_types
                        .push("operator".to_owned());
                }),
                Box::new(|value| {
                    value.contract.knowledge_snapshots[0].participant_id = "missing".to_owned();
                }),
                Box::new(|value| {
                    value.contract.knowledge_snapshots[0].principal.principal_id =
                        "missing".to_owned();
                }),
                Box::new(|value| {
                    value.contract.knowledge_snapshots[0]
                        .principal
                        .participant_id = "wrong".to_owned();
                }),
                Box::new(|value| {
                    value.contract.knowledge_snapshots[0].grant.resource = "wrong".to_owned();
                }),
                Box::new(|value| {
                    value.contract.knowledge_snapshots[0].authorization.resource =
                        "wrong".to_owned();
                }),
                Box::new(|value| value.contract.knowledge_snapshots[0].consent_epoch = 9),
                Box::new(|value| {
                    value.contract.knowledge_snapshots[0].visible_event_seqs = vec![99]
                }),
                Box::new(|value| {
                    value.contract.knowledge_snapshots[0].visible_event_digests = vec![[9; 32]];
                }),
                Box::new(|value| {
                    value.contract.knowledge_snapshots[0].authorization.allowed = false
                }),
                Box::new(|value| {
                    value.contract.knowledge_snapshots[0]
                        .authorization
                        .principal_id = "wrong".to_owned();
                }),
                Box::new(|value| {
                    value.contract.knowledge_snapshots[0].grant.principal_id = "wrong".to_owned();
                }),
                Box::new(|value| {
                    value
                        .contract
                        .knowledge_snapshots
                        .push(value.contract.knowledge_snapshots[0].clone());
                }),
                Box::new(|value| value.contract.authorization_decisions.clear()),
                Box::new(|value| value.contract.authorization_decisions[0].allowed = false),
                Box::new(|value| {
                    value.contract.authorization_decisions[0].decision_digest = [0; 32]
                }),
                Box::new(|value| {
                    value.contract.authorization_decisions[0].reason = "unmatched".to_owned();
                }),
            ];
            for mutate in knowledge_mutations {
                let mut invalid = value.clone();
                mutate(&mut invalid);
                assert!(verify_wave8_contract(&invalid).is_err());
            }

            let (_, mut with_intervention) = fork_pair();
            with_intervention.authoritative_events[1].tick = 2;
            let action_event = with_intervention.authoritative_events[1].clone();
            let society_event = with_intervention.authoritative_events[2].clone();
            let action_node = contract_event_node(&action_event);
            let society_node = contract_event_node(&society_event);
            let observation_node = contract_event_node(&with_intervention.authoritative_events[0]);
            let zero_node = contract_zero_node();
            let dependency =
                |consumer: DependencyNodeV1,
                 source: DependencyNodeV1,
                 dependency_class: DependencyClassV1| InputDependencyV1 {
                    consumer,
                    source,
                    dependency_class,
                    authorization_digest: [31; 32],
                    provenance_digest: [32; 32],
                };
            let intervention = InterventionV1 {
                intervention_id: [33; 16],
                target: "body".to_owned(),
                operation: "set_velocity".to_owned(),
                value_digest: action_event.payload_digest,
                effective_tick: action_event.tick,
                ordinal: 0,
                principal_id: "principal:operator".to_owned(),
                capability: "intervene".to_owned(),
                consent_epoch: 0,
                provenance_digest: [34; 32],
            };
            let frontier = &mut with_intervention.contract.counterfactual.frontier;
            frontier.intervention_seed_nodes = vec![action_node.clone()];
            frontier.affected_nodes = vec![society_node.clone()];
            frontier.owner_frontiers = vec![OwnerFrontierV1 {
                owner_id: society_event.entity.clone(),
                earliest_tick: society_event.tick,
                earliest_scheduler_position: society_node.scheduler_position,
                earliest_output_ordinal: 0,
                cause_node_digests: vec![action_event.payload_digest],
            }];
            frontier.global_frontier_tick = society_event.tick;
            frontier.global_frontier_scheduler_position = society_node.scheduler_position;
            frontier.endogenous_suffix_end_tick = society_event.tick;
            let invalidation = &mut with_intervention.contract.counterfactual.invalidation;
            invalidation.prior_generation = 0;
            invalidation.new_generation = 1;
            invalidation.invalid_start = society_node.clone();
            invalidation.invalid_end = society_node.clone();
            invalidation.invalid_artifacts = vec![InvalidArtifactV1 {
                artifact_class: "event".to_owned(),
                schema_id: society_node.schema_id,
                artifact_digest: society_node.artifact_digest,
                producer: society_node.clone(),
                prior_generation: 0,
                reason: SuffixInvalidationReasonV1::NewIntervention,
            }];
            invalidation.reason = SuffixInvalidationReasonV1::NewIntervention;
            invalidation.fork_id = with_intervention.contract.counterfactual.fork_id;
            let counterfactual = &mut with_intervention.contract.counterfactual;
            counterfactual.prior_generation = 0;
            counterfactual.generation = 1;
            counterfactual.intervention = Some(intervention);
            counterfactual.dependencies = vec![
                dependency(
                    observation_node,
                    zero_node,
                    DependencyClassV1::EndogenousRecomputed,
                ),
                dependency(
                    action_node.clone(),
                    contract_event_node(&with_intervention.authoritative_events[0]),
                    DependencyClassV1::InterventionAssigned,
                ),
                dependency(
                    society_node,
                    contract_event_node(&with_intervention.authoritative_events[1]),
                    DependencyClassV1::EndogenousRecomputed,
                ),
            ];
            counterfactual.recomputed_event_seqs = vec![society_event.seq];
            assert_eq!(verify_wave8_contract(&with_intervention), Ok(()));

            let mut missing_intervention = with_intervention.clone();
            if let Some(intervention) = missing_intervention
                .contract
                .counterfactual
                .intervention
                .as_mut()
            {
                intervention.value_digest = [99; 32];
            }
            assert_eq!(
                verify_wave8_contract(&missing_intervention),
                Err(EvidenceError::InvalidDependencyGraph)
            );
            let mut wrong_dependency = with_intervention.clone();
            wrong_dependency.contract.counterfactual.dependencies[0].source = action_node.clone();
            assert_eq!(
                verify_wave8_contract(&wrong_dependency),
                Err(EvidenceError::InvalidDependencyGraph)
            );
            let mut incomplete_suffix = with_intervention.clone();
            incomplete_suffix
                .contract
                .counterfactual
                .recomputed_event_seqs = vec![action_event.seq];
            assert_eq!(
                verify_wave8_contract(&incomplete_suffix),
                Err(EvidenceError::IncompleteRecomputationContract)
            );
            let mut incomplete_frontier = with_intervention.clone();
            incomplete_frontier.manifest.fork_cut_seq = Some(action_event.seq);
            assert_eq!(
                verify_wave8_contract(&incomplete_frontier),
                Err(EvidenceError::IncompleteRecomputationContract)
            );

            let mut event_gap = value.authoritative_events.clone();
            event_gap[1].seq = 3;
            assert_eq!(
                event_sequences(&event_gap),
                Err(EvidenceError::NonContiguousEventSequence)
            );
            let mut invalid_counterfactual = value.clone();
            invalid_counterfactual
                .contract
                .counterfactual
                .contract_digest = [0; 32];
            assert_eq!(
                verify_wave8_contract(&invalid_counterfactual),
                Err(EvidenceError::InvalidDependencyGraph)
            );
            let mut unknown_consumer = with_intervention.clone();
            unknown_consumer.contract.counterfactual.dependencies[0]
                .consumer
                .owner_id = "unknown-owner".to_owned();
            assert_eq!(
                verify_wave8_contract(&unknown_consumer),
                Err(EvidenceError::InvalidDependencyGraph)
            );
            let mut unexpected_source = with_intervention.clone();
            unexpected_source.contract.counterfactual.dependencies[1].source = contract_zero_node();
            assert_eq!(
                verify_wave8_contract(&unexpected_source),
                Err(EvidenceError::InvalidDependencyGraph)
            );

            let shape = value.contract.counterfactual.clone();
            assert!(verify_counterfactual_record_shapes(&shape));
            let node = shape.frontier.affected_nodes[0].clone();
            let mut later_node = node.clone();
            later_node.tick = later_node.tick.saturating_add(1);
            later_node.artifact_digest = [2; 32];

            let mut sorted_owners = shape.clone();
            let mut later_owner = sorted_owners.frontier.owner_frontiers[0].clone();
            later_owner.earliest_tick = later_owner.earliest_tick.saturating_add(1);
            later_owner.cause_node_digests = vec![[2; 32]];
            sorted_owners.frontier.owner_frontiers = vec![
                sorted_owners.frontier.owner_frontiers[0].clone(),
                later_owner.clone(),
            ];
            assert!(verify_counterfactual_record_shapes(&sorted_owners));
            sorted_owners.frontier.owner_frontiers.reverse();
            assert!(!verify_counterfactual_record_shapes(&sorted_owners));

            let mut sorted_seeds = shape.clone();
            sorted_seeds.frontier.intervention_seed_nodes = vec![node.clone(), later_node.clone()];
            assert!(verify_counterfactual_record_shapes(&sorted_seeds));
            sorted_seeds.frontier.intervention_seed_nodes.reverse();
            assert!(!verify_counterfactual_record_shapes(&sorted_seeds));

            let mut sorted_affected = shape.clone();
            sorted_affected.frontier.affected_nodes = vec![node.clone(), later_node.clone()];
            assert!(verify_counterfactual_record_shapes(&sorted_affected));
            sorted_affected.frontier.affected_nodes.reverse();
            assert!(!verify_counterfactual_record_shapes(&sorted_affected));

            let mut unknown_edges = shape.clone();
            unknown_edges.frontier.unknown_edge_policy = UnknownEdgePolicyV1::FullSuffixFromCut;
            unknown_edges.frontier.unknown_edge_coordinates = vec![later_node.clone()];
            assert!(verify_counterfactual_record_shapes(&unknown_edges));
            unknown_edges.frontier.unknown_edge_coordinates.clear();
            assert!(!verify_counterfactual_record_shapes(&unknown_edges));

            let first_artifact = shape.invalidation.invalid_artifacts[0].clone();
            let mut later_artifact = first_artifact.clone();
            later_artifact.artifact_class = "event-2".to_owned();
            later_artifact.artifact_digest = [2; 32];
            later_artifact.producer = later_node.clone();
            let mut sorted_artifacts = shape.clone();
            sorted_artifacts.invalidation.invalid_artifacts = vec![first_artifact, later_artifact];
            assert!(verify_counterfactual_record_shapes(&sorted_artifacts));
            sorted_artifacts.invalidation.invalid_artifacts.reverse();
            assert!(!verify_counterfactual_record_shapes(&sorted_artifacts));

            for mutate in [
                |contract: &mut CounterfactualContractV1| {
                    contract.invalidation.invalid_artifacts[0]
                        .artifact_class
                        .clear();
                },
                |contract: &mut CounterfactualContractV1| {
                    contract.invalidation.invalid_artifacts[0].schema_id = 0;
                },
                |contract: &mut CounterfactualContractV1| {
                    contract.invalidation.invalid_artifacts[0].artifact_digest = [0; 32];
                },
                |contract: &mut CounterfactualContractV1| {
                    contract.invalidation.invalid_artifacts[0]
                        .producer
                        .owner_id
                        .clear();
                },
                |contract: &mut CounterfactualContractV1| {
                    contract.invalidation.invalid_artifacts[0].reason =
                        SuffixInvalidationReasonV1::ChangedIntervention;
                },
                |contract: &mut CounterfactualContractV1| {
                    contract.invalidation.invalidation_id = [0; 16];
                },
                |contract: &mut CounterfactualContractV1| {
                    contract.invalidation.plan_digest = [99; 32];
                },
                |contract: &mut CounterfactualContractV1| {
                    contract.invalidation.fork_id = [99; 16];
                },
                |contract: &mut CounterfactualContractV1| {
                    contract.invalidation.frontier_digest = [99; 32];
                },
                |contract: &mut CounterfactualContractV1| {
                    contract.invalidation.commit_timeline_id = [0; 16];
                },
                |contract: &mut CounterfactualContractV1| {
                    contract.invalidation.provenance_digest = [0; 32];
                },
                |contract: &mut CounterfactualContractV1| {
                    contract.invalidation.invalidation_digest = [0; 32];
                },
            ] {
                let mut invalid_shape = shape.clone();
                mutate(&mut invalid_shape);
                assert!(!verify_counterfactual_record_shapes(&invalid_shape));
            }

            let mut zero_generation = shape.clone();
            zero_generation.prior_generation = 0;
            zero_generation.generation = 0;
            zero_generation.invalidation.new_generation = 0;
            zero_generation.invalidation.invalid_artifacts.clear();
            assert!(verify_counterfactual_record_shapes(&zero_generation));

            let mut digest_lists = shape.clone();
            digest_lists.invalidation.invalid_checkpoint_digests = vec![[1; 32], [2; 32]];
            digest_lists.invalidation.invalid_projection_digests = vec![[3; 32], [4; 32]];
            digest_lists.invalidation.retained_exogenous_digests = vec![[5; 32], [6; 32]];
            assert!(verify_counterfactual_record_shapes(&digest_lists));
            digest_lists.invalidation.invalid_checkpoint_digests = vec![[1; 32], [1; 32]];
            assert!(!verify_counterfactual_record_shapes(&digest_lists));
            digest_lists.invalidation.invalid_checkpoint_digests = vec![[0; 32]];
            assert!(!verify_counterfactual_record_shapes(&digest_lists));

            let mut sorted_dependencies = shape.clone();
            let mut later_dependency = sorted_dependencies.dependencies[0].clone();
            later_dependency.consumer = later_node.clone();
            later_dependency.source = node.clone();
            later_dependency.authorization_digest = [6; 32];
            later_dependency.provenance_digest = [7; 32];
            sorted_dependencies
                .dependencies
                .push(later_dependency.clone());
            assert!(verify_counterfactual_record_shapes(&sorted_dependencies));
            sorted_dependencies.dependencies.reverse();
            assert!(!verify_counterfactual_record_shapes(&sorted_dependencies));

            for mutate in [
                |contract: &mut CounterfactualContractV1| {
                    contract.dependencies[0].consumer.schema_id = 0;
                },
                |contract: &mut CounterfactualContractV1| {
                    contract.dependencies[0].authorization_digest = [0; 32];
                },
                |contract: &mut CounterfactualContractV1| {
                    contract.dependencies[0].provenance_digest = [0; 32];
                },
                |contract: &mut CounterfactualContractV1| {
                    contract.dependencies[0].source.tick = 1;
                    contract.dependencies[0].source.artifact_digest = [9; 32];
                },
                |contract: &mut CounterfactualContractV1| {
                    contract.dependencies[0].source.tick = 1;
                    contract.dependencies[0].source.owner_id = "other".to_owned();
                    contract.dependencies[0].source.artifact_digest = [0; 32];
                },
            ] {
                let mut invalid_shape = shape.clone();
                mutate(&mut invalid_shape);
                assert!(!verify_counterfactual_record_shapes(&invalid_shape));
            }

            let mut report_cases = value.clone();
            let template = report_cases.contract.conformance_report.cases[0].clone();
            let mut pass = template.clone();
            pass.case_id = "a-pass".to_owned();
            pass.mode = ExecutionModeV1::Local;
            let mut fail = template.clone();
            fail.case_id = "b-fail".to_owned();
            fail.mode = ExecutionModeV1::AirGapped;
            fail.outcome = CaseOutcomeStatusV1::Fail;
            fail.expected_digest = Some([14; 32]);
            fail.actual_digest = Some([15; 32]);
            let mut skip = template.clone();
            skip.case_id = "c-skip".to_owned();
            skip.mode = ExecutionModeV1::Replay;
            skip.outcome = CaseOutcomeStatusV1::Skip;
            skip.expected_digest = None;
            skip.actual_digest = Some([15; 32]);
            let mut unavailable = template.clone();
            unavailable.case_id = "d-unavailable".to_owned();
            unavailable.mode = ExecutionModeV1::Fork;
            unavailable.outcome = CaseOutcomeStatusV1::Unavailable;
            unavailable.expected_digest = None;
            unavailable.actual_digest = None;
            unavailable.expected_error = Some(SafeErrorCodeV1::InvalidEncoding);
            unavailable.actual_error = None;
            let mut not_applicable = template;
            not_applicable.case_id = "e-not-applicable".to_owned();
            not_applicable.mode = ExecutionModeV1::Local;
            not_applicable.outcome = CaseOutcomeStatusV1::NotApplicable;
            not_applicable.expected_digest = None;
            not_applicable.actual_digest = None;
            not_applicable.expected_error = None;
            not_applicable.actual_error = Some(SafeErrorCodeV1::ResourceLimitExceeded);
            report_cases.contract.conformance_report.cases =
                vec![pass, fail, skip, unavailable, not_applicable];
            report_cases.contract.conformance_report.passed = 1;
            report_cases.contract.conformance_report.failed = 1;
            report_cases.contract.conformance_report.skipped = 1;
            report_cases.contract.conformance_report.unavailable = 1;
            report_cases.contract.conformance_report.not_applicable = 1;
            refresh_test_report(&mut report_cases.contract.conformance_report);
            assert_eq!(verify_wave8_contract(&report_cases), Ok(()));

            let mut typed_report = value.clone();
            typed_report.contract.conformance_report.cases[0].expected_digest = None;
            typed_report.contract.conformance_report.cases[0].actual_digest = None;
            typed_report.contract.conformance_report.cases[0].expected_error =
                Some(SafeErrorCodeV1::ClosureIncomplete);
            typed_report.contract.conformance_report.cases[0].actual_error =
                Some(SafeErrorCodeV1::ClosureIncomplete);
            refresh_test_report(&mut typed_report.contract.conformance_report);
            assert_eq!(verify_evidence(&typed_report), Ok(()));

            let mut divergence_report = value.clone();
            divergence_report.contract.conformance_report.cases[0].actual_digest =
                Some([15; 32]);
            divergence_report.contract.conformance_report.cases[0].first_coordinate =
                Some(vec![1, 2]);
            refresh_test_report(&mut divergence_report.contract.conformance_report);
            assert_eq!(verify_evidence(&divergence_report), Ok(()));

            let mut redacted_report = value.clone();
            redacted_report.contract.conformance_report.cases[0].redaction_state =
                RedactionStateV1::RedactedViews;
            redacted_report.contract.conformance_report.cases[0].replay_claim =
                ReplayClaimV1::ExactAuthoritativeWithRedactedViews;
            redacted_report.contract.conformance_report.redaction_state =
                RedactionStateV1::RedactedViews;
            redacted_report.contract.conformance_report.replay_claim =
                ReplayClaimV1::ExactAuthoritativeWithRedactedViews;
            refresh_test_report(&mut redacted_report.contract.conformance_report);
            assert_eq!(verify_evidence(&redacted_report), Ok(()));
            let mut mismatched_redaction = redacted_report.clone();
            mismatched_redaction.contract.conformance_report.redaction_state =
                RedactionStateV1::StructuralOnly;
            assert_eq!(
                verify_evidence(&mismatched_redaction),
                Err(EvidenceError::InvalidConformanceReport)
            );

            let mut structural_report = value.clone();
            let structural_case = &mut structural_report.contract.conformance_report.cases[0];
            structural_case.outcome = CaseOutcomeStatusV1::Pass;
            structural_case.first_coordinate = None;
            structural_case.expected_digest = None;
            structural_case.actual_digest = None;
            structural_case.expected_error = None;
            structural_case.actual_error = None;
            structural_case.replay_claim = ReplayClaimV1::StructuralOnly;
            structural_case.redaction_state = RedactionStateV1::StructuralOnly;
            structural_report.contract.conformance_report.redaction_state =
                RedactionStateV1::StructuralOnly;
            structural_report.contract.conformance_report.replay_claim =
                ReplayClaimV1::StructuralOnly;
            refresh_test_report(&mut structural_report.contract.conformance_report);
            assert_eq!(verify_evidence(&structural_report), Ok(()));

            let mut missing_report = structural_report.clone();
            missing_report.contract.conformance_report.cases[0].outcome =
                CaseOutcomeStatusV1::Fail;
            missing_report.contract.conformance_report.redaction_state =
                RedactionStateV1::EvidenceMissing;
            missing_report.contract.conformance_report.replay_claim =
                ReplayClaimV1::UnverifiableArtifactsMissing;
            missing_report.contract.conformance_report.cases[0].redaction_state =
                RedactionStateV1::EvidenceMissing;
            missing_report.contract.conformance_report.cases[0].replay_claim =
                ReplayClaimV1::UnverifiableArtifactsMissing;
            missing_report.contract.conformance_report.passed = 1;
            missing_report.contract.conformance_report.failed = 1;
            refresh_test_report(&mut missing_report.contract.conformance_report);
            assert_eq!(verify_evidence(&missing_report), Ok(()));

            let mut invalid_report = report_cases.clone();
            invalid_report.contract.conformance_report.passed = 0;
            assert_eq!(
                verify_wave8_contract(&invalid_report),
                Err(EvidenceError::InvalidConformanceReport)
            );
            invalid_report = report_cases.clone();
            invalid_report.contract.conformance_report.cases.clear();
            assert_eq!(
                verify_wave8_contract(&invalid_report),
                Err(EvidenceError::InvalidConformanceReport)
            );

            let mut invalid_atomicity = value.clone();
            invalid_atomicity.contract.atomicity.clear();
            assert_eq!(
                verify_wave8_contract(&invalid_atomicity),
                Err(EvidenceError::IncompleteAtomicityEvidence)
            );
            invalid_atomicity = value.clone();
            invalid_atomicity
                .contract
                .atomicity
                .push(invalid_atomicity.contract.atomicity[0].clone());
            assert_eq!(
                verify_wave8_contract(&invalid_atomicity),
                Err(EvidenceError::IncompleteAtomicityEvidence)
            );
            for mutate in [
                |atomicity: &mut TickAtomicityV1| atomicity.state_digest_before = [0; 32],
                |atomicity: &mut TickAtomicityV1| atomicity.state_digest_after = [0; 32],
                |atomicity: &mut TickAtomicityV1| {
                    atomicity.committed = false;
                    atomicity.committed_event_count = 1;
                },
                |atomicity: &mut TickAtomicityV1| {
                    atomicity.committed = false;
                    atomicity.state_digest_after = [3; 32];
                    atomicity.failure_class = Some(PluginFailureClassV1::PluginCrash);
                },
                |atomicity: &mut TickAtomicityV1| {
                    atomicity.committed = false;
                    atomicity.failure_class = None;
                },
                |atomicity: &mut TickAtomicityV1| {
                    atomicity.committed = true;
                    atomicity.committed_event_count = atomicity.staged_event_count + 1;
                },
                |atomicity: &mut TickAtomicityV1| {
                    atomicity.committed = true;
                    atomicity.failure_class = Some(PluginFailureClassV1::PluginCrash);
                },
            ] {
                let mut invalid = value.clone();
                mutate(&mut invalid.contract.atomicity[0]);
                assert_eq!(
                    verify_wave8_contract(&invalid),
                    Err(EvidenceError::IncompleteAtomicityEvidence)
                );
            }
            let mut failed_atomicity = value.clone();
            failed_atomicity.contract.atomicity.push(TickAtomicityV1 {
                tick: 2,
                fork_generation: 1,
                staged_event_count: 0,
                committed_event_count: 0,
                state_digest_before: [4; 32],
                state_digest_after: [4; 32],
                committed: false,
                failure_class: Some(PluginFailureClassV1::PluginCrash),
            });
            failed_atomicity.plugin_failures.push(PluginFailureV1 {
                plugin: "world".to_owned(),
                class: PluginFailureClassV1::PluginCrash,
                tick: 2,
                committed: false,
                staged_event_count: 0,
                committed_event_count: 0,
                state_digest_before: [4; 32],
                state_digest_after: [4; 32],
                sibling_step_count: 1,
            });
            assert_eq!(verify_wave8_contract(&failed_atomicity), Ok(()));
            failed_atomicity.plugin_failures.clear();
            assert_eq!(
                verify_wave8_contract(&failed_atomicity),
                Err(EvidenceError::IncompleteAtomicityEvidence)
            );

            let mut invalid_plugin = value.clone();
            invalid_plugin.contract.plugin_boundary.network_allowed = true;
            assert_eq!(
                verify_wave8_contract(&invalid_plugin),
                Err(EvidenceError::InvalidContract)
            );

            let mut duplicate_participant = value.clone();
            let mut duplicate_principal =
                duplicate_participant.contract.scenario_room.principals[0].clone();
            duplicate_principal.principal_id = "principal:duplicate".to_owned();
            let mut duplicate_grant =
                duplicate_participant.contract.scenario_room.grants[0].clone();
            duplicate_grant.grant_id = "grant:duplicate".to_owned();
            duplicate_grant.principal_id = duplicate_principal.principal_id.clone();
            duplicate_participant
                .contract
                .scenario_room
                .principals
                .push(duplicate_principal);
            duplicate_participant
                .contract
                .scenario_room
                .grants
                .push(duplicate_grant);
            assert_eq!(
                verify_wave8_contract(&duplicate_participant),
                Err(EvidenceError::InvalidContract)
            );

            let mut duplicate_visible_sequence = value.clone();
            duplicate_visible_sequence.contract.knowledge_snapshots[0].visible_event_seqs =
                vec![1, 1];
            duplicate_visible_sequence.contract.knowledge_snapshots[0].visible_event_digests =
                vec![[1; 32], [1; 32]];
            assert_eq!(
                verify_wave8_contract(&duplicate_visible_sequence),
                Err(EvidenceError::InvalidKnowledgeBoundary)
            );

            let mut invalid_shape = with_intervention.clone();
            invalid_shape
                .contract
                .counterfactual
                .frontier
                .affected_nodes[0]
                .schema_id = 0;
            assert_eq!(
                verify_wave8_contract(&invalid_shape),
                Err(EvidenceError::InvalidDependencyGraph)
            );

            let mut invalid_source_tick = with_intervention.clone();
            invalid_source_tick.contract.counterfactual.dependencies[2]
                .source
                .tick = invalid_source_tick.contract.counterfactual.dependencies[2]
                .consumer
                .tick;
            invalid_source_tick.contract.counterfactual.dependencies[2]
                .source
                .scheduler_position = invalid_source_tick.contract.counterfactual.dependencies[2]
                .consumer
                .scheduler_position;
            assert_eq!(
                verify_wave8_contract(&invalid_source_tick),
                Err(EvidenceError::InvalidDependencyGraph)
            );

            let mut duplicate_consumer = with_intervention.clone();
            duplicate_consumer.contract.counterfactual.dependencies[2].consumer =
                duplicate_consumer.contract.counterfactual.dependencies[1]
                    .consumer
                    .clone();
            duplicate_consumer.contract.counterfactual.dependencies[2]
                .source
                .tick = 0;
            duplicate_consumer.contract.counterfactual.dependencies[2]
                .source
                .owner_id = "other-source".to_owned();
            duplicate_consumer.contract.counterfactual.dependencies[2]
                .source
                .artifact_digest = [5; 32];
            assert_eq!(
                verify_wave8_contract(&duplicate_consumer),
                Err(EvidenceError::InvalidDependencyGraph)
            );

            let mut invalid_coordinate = report_cases.clone();
            invalid_coordinate.contract.conformance_report.cases[0].first_coordinate =
                Some(vec![b'x'; 129]);
            assert_eq!(
                verify_wave8_contract(&invalid_coordinate),
                Err(EvidenceError::InvalidConformanceReport)
            );

            let mut duplicate_reviewers = report_cases.clone();
            duplicate_reviewers
                .contract
                .conformance_report
                .independence
                .reviewer_ids = vec!["reviewer".to_owned(), "reviewer".to_owned()];
            assert_eq!(
                verify_wave8_contract(&duplicate_reviewers),
                Err(EvidenceError::InvalidConformanceReport)
            );

            let mut unsorted_owner_causes = shape.clone();
            unsorted_owner_causes.frontier.owner_frontiers[0].cause_node_digests =
                vec![[2; 32], [1; 32]];
            assert!(!verify_counterfactual_record_shapes(&unsorted_owner_causes));

            let mut unsorted_unknown_edges = shape.clone();
            unsorted_unknown_edges.frontier.unknown_edge_policy =
                UnknownEdgePolicyV1::FullSuffixFromCut;
            unsorted_unknown_edges.frontier.unknown_edge_coordinates =
                vec![later_node.clone(), node.clone()];
            assert!(!verify_counterfactual_record_shapes(
                &unsorted_unknown_edges
            ));

            let (fork_baseline, fork_counterfactual) = fork_pair();
            let mut invalid_fork_baseline = fork_baseline.clone();
            invalid_fork_baseline
                .contract
                .plugin_boundary
                .network_allowed = true;
            assert_eq!(
                verify_counterfactual_fork(
                    &invalid_fork_baseline,
                    &fork_counterfactual,
                    "world.action.v1"
                ),
                Err(EvidenceError::IncompleteForkSuffix)
            );
        }};
    }

    #[test]
    fn covers_remaining_typed_verifier_boundaries() {
        typed_verifier_boundary_cases!();
    }

    fn fork_pair() -> (MoatProofEvidenceV1, MoatProofEvidenceV1) {
        let mut baseline = evidence();
        baseline.manifest.fork_cut_seq = Some(1);
        baseline.authoritative_events[1].event_type = "proof.agent.reaction.v1".to_owned();
        let marker = baseline.authoritative_events.remove(2);
        baseline.authoritative_events.push(AuthoritativeEventV1 {
            seq: 3,
            tick: 2,
            entity: "society".to_owned(),
            event_type: "society.signal".to_owned(),
            payload_digest: [3; 32],
            causation_seq: Some(2),
        });
        baseline
            .authoritative_events
            .push(AuthoritativeEventV1 { seq: 4, ..marker });
        baseline.host_closure.effective_after_seq = 4;
        baseline.host_closure.closure_event_seq = 4;
        baseline.causal_trace.push(CausalTraceEntryV1 {
            cause_seq: 2,
            effect_seq: 3,
            relation: "agent_to_society".to_owned(),
            visibility: "public".to_owned(),
            dependency_class: DependencyClassV1::EndogenousRecomputed,
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
        let mut prefix_mismatch = counterfactual.clone();
        prefix_mismatch.authoritative_events[0].payload_digest = [8; 32];
        prefix_mismatch.participant_views[0].visible_events[0].payload_digest = [8; 32];
        prefix_mismatch.contract.knowledge_snapshots[0].visible_event_digests[0] = [8; 32];
        assert_eq!(
            verify_counterfactual_fork(&baseline, &prefix_mismatch, "world.action.v1"),
            Err(EvidenceError::IncompleteForkSuffix)
        );
        let mut invalid = counterfactual.clone();
        invalid.authoritative_events[1].event_type = "proof.agent.reaction.v1".to_owned();
        invalid.participant_views[0].hidden_event_types[1] = "proof.agent.reaction.v1".to_owned();
        assert_eq!(
            verify_counterfactual_fork(&baseline, &invalid, "world.action.v1"),
            Err(EvidenceError::IncompleteForkSuffix)
        );
        let mut invalid = counterfactual;
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
    fn rejects_a_factual_suffix_with_incomplete_invalidation() {
        let (baseline, counterfactual) = fork_pair();
        let intervention = &counterfactual.authoritative_events[1];
        assert_eq!(
            verify_factual_suffix_invalidation(&baseline, &counterfactual, 1, intervention),
            Err(EvidenceError::IncompleteForkSuffix)
        );
    }

    #[test]
    fn serializes_and_formats_digest() -> Result<(), Box<dyn std::error::Error>> {
        let value = evidence();
        let json = value.to_json()?;
        assert!(json.contains("world.observation.v1"));
        assert_eq!(MoatProofEvidenceV1::from_json(&json)?, value);
        let cbor = value.to_canonical_cbor()?;
        assert_eq!(MoatProofEvidenceV1::from_canonical_cbor(&cbor)?, value);
        assert_eq!(hex_digest(&value.digest()?).len(), 64);
        Ok(())
    }

    #[test]
    fn strict_codec_exercises_closed_record_boundaries() {
        strict_codec::coverage_helpers::exercise_for_coverage(&evidence());
    }

    #[test]
    fn serializes_exact_verification_and_divergence_records(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let value = evidence();
        let result = value.to_verification_result()?;
        let result_bytes = result.to_canonical_cbor()?;
        assert_eq!(
            VerificationResultV1::from_canonical_cbor(&result_bytes)?,
            result
        );
        let mut trailing = result_bytes;
        trailing.push(0);
        assert!(VerificationResultV1::from_canonical_cbor(&trailing).is_err());

        let mut report = DivergenceReportV1 {
            request_digest: [1; 32],
            manifest_digest: [2; 32],
            execution_profile_digest: [3; 32],
            fixture_digest: Some([4; 32]),
            evaluator_digest: [5; 32],
            reproducibility_class: ReproducibilityClassV1::ProfileRecomputation,
            replay_claim: ReplayClaimV1::Exact,
            location_kind: DivergenceLocationKindV1::TimelineSeq,
            timeline_or_worldcut_id: [6; 16],
            timeline_seq_or_cut_ordinal: 7,
            tick: 8,
            scheduler_position: Some(9),
            driver_or_plugin_id: Some("world".to_owned()),
            output_ordinal: Some(10),
            mismatch_kind: DivergenceMismatchKindV1::CanonicalBytes,
            expected: DigestSizeV1 {
                digest: Some([11; 32]),
                size: Some(12),
            },
            actual: DigestSizeV1 {
                digest: Some([13; 32]),
                size: Some(14),
            },
            prior_matching_checkpoint_digest: Some([15; 32]),
            follow_on_counts: vec![FollowOnMismatchV1 {
                kind: DivergenceMismatchKindV1::Artifact,
                count: 1,
            }],
            report_digest: [0; 32],
        };
        report.report_digest = report.digest()?;
        let report_bytes = report.to_canonical_cbor()?;
        assert_eq!(
            DivergenceReportV1::from_canonical_cbor(&report_bytes)?,
            report
        );
        Ok(())
    }
}
