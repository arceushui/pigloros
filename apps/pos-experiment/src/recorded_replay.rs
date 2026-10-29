//! `RecordedReplay` execution of one `RVR1` request to one `VRR1`.
//!
//! ADR-062 Revision 8 slice R2 (#1220). [`execute_recorded_replay_v1`] is the
//! execution step after [`preflight_verification_v1`]: it rebuilds Projection
//! State from the exported Timeline artifact, compares the result with the
//! expected authoritative stream through
//! [`first_divergence_v1`],
//! and emits one sealed [`VerificationResultV1`]. It takes no Driver, provider
//! or store: it invokes no Driver, contacts no provider and appends no Event.
//!
//! # Order
//!
//! 1. The `ArtifactClosure` check (ADR-062 Revision 8, Q5): the closure is
//!    complete only when the deployment boundary reports it complete **and**
//!    the exported Timeline member and the licence member are both supplied.
//!    The result is the `artifact_closure` evidence of the unchanged
//!    [`preflight_verification_v1`]; there is no separate licence coordinate.
//! 2. [`preflight_verification_v1`]. Its first error becomes the result's
//!    first error: a closure or provenance error is
//!    `UnverifiableArtifactsMissing`, a profile error is
//!    `IncompatibleProfile`, and every other error is `InvalidManifest`.
//! 3. The reproducibility class must be `RecordedReplay`.
//! 4. ADR-060 `ReplayClaim` degradation: the admitted claim is weakened by the
//!    host-owned [`ReplayClaimEvaluationV1`], never strengthened. A weakened
//!    `IncompatibleProfile` claim is `IncompatibleProfile`; a structural or
//!    missing claim, or an exported Timeline the evaluation does not admit for
//!    authoritative use, is `UnverifiableArtifactsMissing`. A claim with
//!    redacted views stays exact (Q4: `VerifiedExact` with a degraded
//!    `replay_claim`).
//! 5. The Event count of the export must not exceed the manifest
//!    `resource_limit`, checked before any fold.
//! 6. The exported Events are folded into the caller's
//!    [`ProjectionRegistry`] from empty State, and its Snapshot is read under
//!    the registry's erasure fence; a denied fence is
//!    `UnverifiableArtifactsMissing`.
//! 7. The rebuilt stream is compared with the expected stream: no divergence
//!    is `VerifiedExact`; otherwise the result is `Diverged` and carries the
//!    `DVR1` digest.
//!
//! # Rebuilt stream
//!
//! A recorded export carries no Tick numbering, so every Event and the one
//! Projection checkpoint have tick 0. Each digest is BLAKE3 over a domain
//! string, a zero byte and the listed fields:
//!
//! | Field | Domain | Fields |
//! |---|---|---|
//! | Event identity | `PiglorOS.RecordedReplayEventIdentity.v1` | Event id bytes, entity id bytes, Event type |
//! | Event schema | `PiglorOS.RecordedReplayEventSchema.v1` | Event type, zero byte, schema version (`u32`, big endian) |
//! | Checkpoint | `PiglorOS.RecordedReplayCheckpoint.v1` | canonical CBOR of the Projection Snapshot |
//! | Authoritative result | `PiglorOS.RecordedReplayResult.v1` | per Event in Timeline Order: Timeline id, sequence (`u64`, big endian), identity digest, schema digest, BLAKE3 of the payload; then per checkpoint: Timeline id, Fold Cursor, tick (`u64`, big endian), digest, size (`u64`, big endian) |
//!
//! The checkpoint is keyed by the export's Timeline id and the Fold Cursor of
//! the last exported Event (0 when the export is empty); its size is the
//! canonical CBOR length. Event payloads are compared as canonical bytes.

use std::collections::{BTreeMap, HashMap};

use pos_conformance::{
    preflight_verification_v1, ArtifactClosureStatusV1, DivergenceReportV1, ReplayClaimV1,
    ReproducibilityClassV1, SafeErrorCodeV1, VerificationErrorV1, VerificationOutcomeV1,
    VerificationPreflightCoordinateV1, VerificationPreflightErrorV1,
    VerificationPreflightEvidenceV1, VerificationPreflightInputV1, VerificationResultV1,
};
use pos_core::{
    CoreError, ErasureArtifactClassV1, ErasureReferenceV1, Event, ReplayClaimEvaluationV1,
    StateRegistry, TimelineExport,
};
use pos_state::ProjectionRegistry;

use crate::authoritative_comparison::{
    first_divergence_v1, AuthoritativeStreamV1, CheckpointDigestV1, ComparedEventV1,
    DivergenceContextV1, TickBoundaryCoordinateV1, TimelinePositionV1,
};

const EVENT_IDENTITY_DOMAIN_V1: &[u8] = b"PiglorOS.RecordedReplayEventIdentity.v1";
const EVENT_SCHEMA_DOMAIN_V1: &[u8] = b"PiglorOS.RecordedReplayEventSchema.v1";
const CHECKPOINT_DOMAIN_V1: &[u8] = b"PiglorOS.RecordedReplayCheckpoint.v1";
const AUTHORITATIVE_RESULT_DOMAIN_V1: &[u8] = b"PiglorOS.RecordedReplayResult.v1";
const PROVENANCE_DOMAIN_V1: &[u8] = b"PiglorOS.RecordedReplayProvenance.v1";

/// The exported Timeline member of a `RecordedReplay` closure.
#[derive(Clone, Copy, Debug)]
pub struct ExportedTimelineMemberV1<'a> {
    /// The exported Timeline artifact.
    pub export: &'a TimelineExport,
    /// ADR-060 identity of the export, as registered for evaluation.
    pub artifact_digest: ErasureReferenceV1,
}

/// The materialized closure members a `RecordedReplay` run reads.
#[derive(Clone, Copy, Debug)]
pub struct RecordedReplayClosureV1<'a> {
    /// The exported Timeline, when it is materialized.
    pub timeline_export: Option<ExportedTimelineMemberV1<'a>>,
    /// The licence member bytes, when they are materialized.
    pub licence: Option<&'a [u8]>,
}

/// Inputs to one `RecordedReplay` execution.
pub struct RecordedReplayInputV1<'a> {
    /// The preflight input. Its `artifact_closure` evidence is combined with
    /// the closure member check; it is never overridden to complete.
    pub preflight: VerificationPreflightInputV1<'a>,
    /// The materialized closure members.
    pub closure: RecordedReplayClosureV1<'a>,
    /// The host-owned ADR-060 evaluation of the closure artifacts.
    pub replay_claim_evaluation: &'a ReplayClaimEvaluationV1,
    /// The expected authoritative stream.
    pub expected: &'a AuthoritativeStreamV1,
    /// Digest of the fixture, when the run has one.
    pub fixture_digest: Option<[u8; 32]>,
}

/// The result of one `RecordedReplay` execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedReplayOutcomeV1 {
    /// The sealed `VRR1`, validated by the pos-conformance codec.
    pub result: VerificationResultV1,
    /// The `DVR1` whose digest the result carries, when it diverged.
    pub divergence: Option<DivergenceReportV1>,
}

/// Execute one `RecordedReplay` verification and emit one `VRR1`.
///
/// Every refusal is a sealed result with one closed first error, not an
/// `Err`. `projections` must hold the Reducers named by the manifest and a
/// host-bound erasure gate; its State is cleared and rebuilt from the export.
///
/// # Errors
/// Returns the codec error when the Projection Snapshot cannot be encoded as
/// canonical CBOR, when the first divergence has a coordinate the closed
/// `DVR1` shape rejects, or when the result cannot be sealed as a `VRR1`.
pub fn execute_recorded_replay_v1(
    input: RecordedReplayInputV1<'_>,
    projections: &mut ProjectionRegistry,
) -> Result<RecordedReplayOutcomeV1, CoreError> {
    let RecordedReplayInputV1 {
        preflight,
        closure,
        replay_claim_evaluation,
        expected,
        fixture_digest,
    } = input;
    let header = ResultHeader::new(&preflight, closure, fixture_digest);
    let declared_claim = preflight.manifest.replay_claim;
    let resource_limit = preflight.manifest.resource_limit;
    let complete = closure.licence.and(closure.timeline_export);
    let closure_status = if matches!(
        preflight.evidence.artifact_closure,
        ArtifactClosureStatusV1::Complete
    ) && complete.is_some()
    {
        ArtifactClosureStatusV1::Complete
    } else {
        ArtifactClosureStatusV1::Incomplete
    };
    let preflight = VerificationPreflightInputV1 {
        evidence: VerificationPreflightEvidenceV1 {
            artifact_closure: closure_status,
            ..preflight.evidence
        },
        ..preflight
    };
    let rebuilt = preflight_verification_v1(&preflight)
        .map_err(|error| preflight_refusal(error, declared_claim))
        // A complete closure always has both members; preflight admits only
        // a complete closure.
        .and_then(|admitted| {
            complete
                .map(|export| (admitted, export))
                .ok_or_else(missing)
        })
        .and_then(|(admitted, export)| {
            admit_class(admitted.reproducibility_class, admitted.replay_claim)
                .and_then(|claim| degrade_claim(claim, replay_claim_evaluation, export))
                .and_then(|claim| admit_budget(claim, export.export, resource_limit))
                .and_then(|claim| {
                    rebuild_projections(projections, export.export)
                        .map(|snapshot| (claim, export.export, snapshot))
                })
        });
    match rebuilt {
        Ok((claim, export, snapshot)) => rebuilt_stream(export, &snapshot)
            .and_then(|actual| header.compare(claim, expected, &actual)),
        Err(refusal) => header.refuse(refusal),
    }
}

/// One closed refusal before or during execution.
#[derive(Clone, Copy)]
struct Refusal {
    outcome: VerificationOutcomeV1,
    replay_claim: ReplayClaimV1,
    code: SafeErrorCodeV1,
    coordinate: Option<VerificationPreflightCoordinateV1>,
}

const fn missing() -> Refusal {
    Refusal {
        outcome: VerificationOutcomeV1::UnverifiableArtifactsMissing,
        replay_claim: ReplayClaimV1::UnverifiableArtifactsMissing,
        code: SafeErrorCodeV1::ProvenanceMissing,
        coordinate: Some(VerificationPreflightCoordinateV1::ReplayClaim),
    }
}

const fn incompatible(
    code: SafeErrorCodeV1,
    coordinate: VerificationPreflightCoordinateV1,
) -> Refusal {
    Refusal {
        outcome: VerificationOutcomeV1::IncompatibleProfile,
        replay_claim: ReplayClaimV1::IncompatibleProfile,
        code,
        coordinate: Some(coordinate),
    }
}

const fn preflight_refusal(
    error: VerificationPreflightErrorV1,
    declared_claim: ReplayClaimV1,
) -> Refusal {
    let (outcome, replay_claim) = match error.code() {
        SafeErrorCodeV1::ClosureIncomplete | SafeErrorCodeV1::ProvenanceMissing => (
            VerificationOutcomeV1::UnverifiableArtifactsMissing,
            ReplayClaimV1::UnverifiableArtifactsMissing,
        ),
        SafeErrorCodeV1::ProfileUnsupported | SafeErrorCodeV1::ProfileClassMismatch => (
            VerificationOutcomeV1::IncompatibleProfile,
            ReplayClaimV1::IncompatibleProfile,
        ),
        _ => (VerificationOutcomeV1::InvalidManifest, declared_claim),
    };
    Refusal {
        outcome,
        replay_claim,
        code: error.code(),
        coordinate: Some(error.coordinate()),
    }
}

const fn admit_class(
    class: ReproducibilityClassV1,
    claim: ReplayClaimV1,
) -> Result<ReplayClaimV1, Refusal> {
    if matches!(class, ReproducibilityClassV1::RecordedReplay) {
        Ok(claim)
    } else {
        Err(incompatible(
            SafeErrorCodeV1::ProfileClassMismatch,
            VerificationPreflightCoordinateV1::ProfileClass,
        ))
    }
}

fn degrade_claim(
    claim: ReplayClaimV1,
    evaluation: &ReplayClaimEvaluationV1,
    export: ExportedTimelineMemberV1<'_>,
) -> Result<ReplayClaimV1, Refusal> {
    let claim = claim.after_artifact_evaluation(evaluation);
    match claim {
        ReplayClaimV1::Exact | ReplayClaimV1::ExactAuthoritativeWithRedactedViews => evaluation
            .require_authoritative_use(ErasureArtifactClassV1::Export, export.artifact_digest)
            .map(|()| claim)
            .map_err(|_| missing()),
        ReplayClaimV1::StructuralOnly | ReplayClaimV1::UnverifiableArtifactsMissing => {
            Err(missing())
        }
        ReplayClaimV1::IncompatibleProfile => Err(incompatible(
            SafeErrorCodeV1::ProfileUnsupported,
            VerificationPreflightCoordinateV1::ReplayClaim,
        )),
    }
}

fn admit_budget(
    claim: ReplayClaimV1,
    export: &TimelineExport,
    resource_limit: u64,
) -> Result<ReplayClaimV1, Refusal> {
    if u64::try_from(export.events.len()).unwrap_or(u64::MAX) <= resource_limit {
        Ok(claim)
    } else {
        Err(Refusal {
            outcome: VerificationOutcomeV1::ResourceLimitExceeded,
            replay_claim: claim,
            code: SafeErrorCodeV1::ResourceLimitExceeded,
            coordinate: None,
        })
    }
}

fn rebuild_projections(
    projections: &mut ProjectionRegistry,
    export: &TimelineExport,
) -> Result<HashMap<String, StateRegistry>, Refusal> {
    let timeline = export.timeline.id();
    projections.clear_state();
    projections.fold_events(timeline, &export.events);
    projections.state_snapshot(timeline).map_err(|_| missing())
}

fn rebuilt_stream(
    export: &TimelineExport,
    snapshot: &HashMap<String, StateRegistry>,
) -> Result<AuthoritativeStreamV1, CoreError> {
    let timeline_id = export.timeline.id().inner().to_bytes();
    pos_crypto::canonical::encode(snapshot).map(|bytes| {
        let bytes = bytes.as_slice();
        let mut digest = domain_hasher(CHECKPOINT_DOMAIN_V1);
        digest.update(bytes);
        let coordinate = TickBoundaryCoordinateV1 {
            timeline_id,
            fold_cursor: export.events.last().map_or(0, |event| event.seq.as_u64()),
            tick: 0,
        };
        let checkpoint = CheckpointDigestV1 {
            digest: *digest.finalize().as_bytes(),
            size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        };
        AuthoritativeStreamV1 {
            events: export
                .events
                .iter()
                .map(|event| recorded_event(timeline_id, event))
                .collect(),
            checkpoints: BTreeMap::from([(coordinate, checkpoint)]),
            ..AuthoritativeStreamV1::default()
        }
    })
}

fn recorded_event(timeline_id: [u8; 16], event: &Event) -> (TimelinePositionV1, ComparedEventV1) {
    let event_type = event.event_type.as_str().as_bytes();
    let mut identity = domain_hasher(EVENT_IDENTITY_DOMAIN_V1);
    identity.update(&event.id.inner().to_bytes());
    identity.update(&event.entity.inner().to_bytes());
    identity.update(event_type);
    let mut schema = domain_hasher(EVENT_SCHEMA_DOMAIN_V1);
    schema.update(event_type);
    schema.update(&[0]);
    schema.update(&event.schema_version.as_u32().to_be_bytes());
    let position = TimelinePositionV1 {
        timeline_id,
        seq: event.seq.as_u64(),
    };
    let compared = ComparedEventV1 {
        tick: 0,
        identity: *identity.finalize().as_bytes(),
        schema: *schema.finalize().as_bytes(),
        payload: event.payload.as_slice().to_vec(),
    };
    (position, compared)
}

fn authoritative_result_digest(actual: &AuthoritativeStreamV1) -> [u8; 32] {
    let mut digest = domain_hasher(AUTHORITATIVE_RESULT_DOMAIN_V1);
    for (position, event) in &actual.events {
        digest.update(&position.timeline_id);
        digest.update(&position.seq.to_be_bytes());
        digest.update(&event.identity);
        digest.update(&event.schema);
        digest.update(blake3::hash(&event.payload).as_bytes());
    }
    for (coordinate, checkpoint) in &actual.checkpoints {
        digest.update(&coordinate.timeline_id);
        digest.update(&coordinate.fold_cursor.to_be_bytes());
        digest.update(&coordinate.tick.to_be_bytes());
        digest.update(&checkpoint.digest);
        digest.update(&checkpoint.size.to_be_bytes());
    }
    *digest.finalize().as_bytes()
}

fn domain_hasher(domain: &[u8]) -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    hasher
}

/// The identity fields every result of one run carries.
struct ResultHeader {
    request_digest: [u8; 32],
    manifest_digest: [u8; 32],
    execution_profile_digest: [u8; 32],
    trust_policy_snapshot_digest: [u8; 32],
    artifact_closure_digest: [u8; 32],
    fixture_digest: Option<[u8; 32]>,
    evaluator_digest: [u8; 32],
    reproducibility_class: ReproducibilityClassV1,
    checked_artifact_count: u64,
    provenance_digest: [u8; 32],
}

/// The outcome-specific fields of one result.
struct Verdict {
    outcome: VerificationOutcomeV1,
    replay_claim: ReplayClaimV1,
    authoritative_result_digest: Option<[u8; 32]>,
    divergence_report_digest: Option<[u8; 32]>,
    first_error: Option<VerificationErrorV1>,
}

impl ResultHeader {
    fn new(
        preflight: &VerificationPreflightInputV1<'_>,
        closure: RecordedReplayClosureV1<'_>,
        fixture_digest: Option<[u8; 32]>,
    ) -> Self {
        let request = preflight.request;
        let export_digest = closure
            .timeline_export
            .map_or([0; 32], |member| member.artifact_digest.digest());
        let licence_digest = closure
            .licence
            .map_or([0; 32], |bytes| *blake3::hash(bytes).as_bytes());
        let mut provenance = domain_hasher(PROVENANCE_DOMAIN_V1);
        provenance.update(&preflight.canonical_request_digest);
        provenance.update(&export_digest);
        provenance.update(&licence_digest);
        Self {
            request_digest: preflight.canonical_request_digest,
            manifest_digest: request.manifest_digest,
            execution_profile_digest: request.execution_profile_digest,
            trust_policy_snapshot_digest: request.trust_policy_snapshot_digest,
            artifact_closure_digest: request.artifact_closure_digest,
            fixture_digest,
            evaluator_digest: request.evaluator_digest,
            reproducibility_class: request.reproducibility_class,
            checked_artifact_count: u64::from(closure.timeline_export.is_some())
                + u64::from(closure.licence.is_some()),
            provenance_digest: *provenance.finalize().as_bytes(),
        }
    }

    fn refuse(&self, refusal: Refusal) -> Result<RecordedReplayOutcomeV1, CoreError> {
        let first_error = VerificationErrorV1 {
            code: refusal.code,
            field_ordinal: None,
            canonical_coordinate: refusal
                .coordinate
                .map(|coordinate| coordinate.to_string().into_bytes()),
            related_digest: None,
        };
        self.seal(Verdict {
            outcome: refusal.outcome,
            replay_claim: refusal.replay_claim,
            authoritative_result_digest: None,
            divergence_report_digest: None,
            first_error: Some(first_error),
        })
        .map(|result| RecordedReplayOutcomeV1 {
            result,
            divergence: None,
        })
    }

    fn compare(
        &self,
        replay_claim: ReplayClaimV1,
        expected: &AuthoritativeStreamV1,
        actual: &AuthoritativeStreamV1,
    ) -> Result<RecordedReplayOutcomeV1, CoreError> {
        let context = DivergenceContextV1 {
            request_digest: self.request_digest,
            manifest_digest: self.manifest_digest,
            execution_profile_digest: self.execution_profile_digest,
            fixture_digest: self.fixture_digest,
            evaluator_digest: self.evaluator_digest,
            reproducibility_class: self.reproducibility_class,
            replay_claim,
        };
        let authoritative_result_digest = Some(authoritative_result_digest(actual));
        first_divergence_v1(&context, expected, actual).and_then(|divergence| {
            let outcome = if divergence.is_some() {
                VerificationOutcomeV1::Diverged
            } else {
                VerificationOutcomeV1::VerifiedExact
            };
            self.seal(Verdict {
                outcome,
                replay_claim,
                authoritative_result_digest,
                divergence_report_digest: divergence.as_ref().map(|report| report.report_digest),
                first_error: None,
            })
            .map(|result| RecordedReplayOutcomeV1 { result, divergence })
        })
    }

    /// Set the result digest and pass the result through the `VRR1` codec.
    fn seal(&self, verdict: Verdict) -> Result<VerificationResultV1, CoreError> {
        let mut result = VerificationResultV1 {
            request_digest: self.request_digest,
            manifest_digest: self.manifest_digest,
            execution_profile_digest: self.execution_profile_digest,
            trust_policy_snapshot_digest: self.trust_policy_snapshot_digest,
            artifact_closure_digest: self.artifact_closure_digest,
            fixture_digest: self.fixture_digest,
            evaluator_digest: self.evaluator_digest,
            reproducibility_class: self.reproducibility_class,
            verification_outcome: verdict.outcome,
            replay_claim: verdict.replay_claim,
            authoritative_result_digest: verdict.authoritative_result_digest,
            divergence_report_digest: verdict.divergence_report_digest,
            first_error: verdict.first_error,
            checked_artifact_count: self.checked_artifact_count,
            provenance_digest: self.provenance_digest,
            result_digest: [0; 32],
        };
        result
            .digest()
            .and_then(|digest| {
                result.result_digest = digest;
                result.to_canonical_cbor()
            })
            .and_then(|bytes| VerificationResultV1::from_canonical_cbor(&bytes))
    }
}
