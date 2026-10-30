//! Shared machinery of the ADR-062 Revision 8 execution steps.
//!
//! [`crate::recorded_replay`] (slice R2, #1220) and
//! [`crate::profile_recomputation`] (slice R3, #1221) share one result shape,
//! one refusal vocabulary, one `VRR1` sealing path and one digest scheme. The
//! digest scheme is the accepted `RecordedReplay` scheme of the ADR-062
//! Revision 8 note "Recorded Replay Digests" (2026-10-30, section 2); it is
//! not the `pos-conformance` `AuthoritativeFixture` / EV1 scheme.
//!
//! Each digest is BLAKE3 over a domain string, a zero byte and the listed
//! fields; integers are big endian:
//!
//! | Field | Domain | Fields |
//! |---|---|---|
//! | Event identity | `PiglorOS.RecordedReplayEventIdentity.v1` | Event id bytes, entity id bytes, Event type |
//! | Event schema | `PiglorOS.RecordedReplayEventSchema.v1` | Event type, zero byte, schema version (`u32`) |
//! | Checkpoint | `PiglorOS.RecordedReplayCheckpoint.v1` | canonical CBOR of the Projection Snapshot |
//! | Authoritative result | `PiglorOS.RecordedReplayResult.v1` | the Event count (`u64`), then per Event in Timeline Order: Timeline id, sequence (`u64`), identity digest, schema digest, BLAKE3 of the payload; then the checkpoint count (`u64`) and per checkpoint: Timeline id, Fold Cursor, tick (`u64`), digest, size (`u64`); then the typed-failure count (`u64`) and per typed failure in coordinate order: Timeline id, Fold Cursor (`u64`), tick (`u64`), scheduler position (`u32`), Driver id length (`u64`), Driver id UTF-8 bytes, output ordinal (`u32`), the outcome tag (one byte: 0 output, 1 typed failure), the canonical byte length (`u64`), the canonical bytes (for a host failure, the code `u16` then the sub-code `u16`) |
//! | Provenance | `PiglorOS.RecordedReplayProvenance.v1` | canonical request digest, the primary closure member's artifact digest (32 zero bytes if absent), BLAKE3 of the licence member (32 zero bytes if absent or empty) |
//!
//! Every Event and the one Projection checkpoint have tick 0. The checkpoint
//! is keyed by the stream's Timeline id (for `RecordedReplay`, the export's
//! Timeline id) and the Fold Cursor of the last Event (0 when there is
//! none); its size is the canonical CBOR length. Every Driver output a
//! built stream carries is a typed failure. A `RecordedReplay` stream has
//! none, so its typed-failure count is 0. The scheme is recorded on the
//! wiki page `ADR-062_R8_Recorded_Replay_Digests`, sections 2 and 6.
//!
//! # Closure binding
//!
//! ADR-062 Revision 8 slice R4 (#1222) binds the closure members to the
//! request's `artifact_closure_digest`. The composition, proposed for section
//! 4 of the note, is BLAKE3 over `PiglorOS.RecordedReplayClosure.v1`, a zero
//! byte, the member count (`u64`, always 2) and then each member in role
//! order as its one-byte role and its 32-byte artifact digest:
//!
//! | Role | Member | Artifact digest |
//! |---|---|---|
//! | 1 | exported Timeline (`RecordedReplay`) | the export's ADR-060 artifact digest |
//! | 2 | recomputation subject (`ProfileRecomputation`, `CrossProfileConformance`, `LiveUnverified`) | the subject's artifact digest |
//! | 3 | licence | BLAKE3 of the licence member bytes |
//!
//! The execution member is exactly one of roles 1 and 2: the two are never
//! both present, and the same digest under different roles gives different
//! closures. A present but empty licence counts as absent: it is refused at
//! closure presence (`ClosureIncomplete`) and never hashed. The composition
//! is recorded on the wiki note `ADR-062_R8_Recorded_Replay_Digests`,
//! section 4.
//!
//! A complete member set whose composition is not the request's digest is
//! refused at `artifact_closure` with `DigestMismatch` (`InvalidManifest`),
//! unless the preflight reports an earlier coordinate first: the preflight
//! is run with `Incomplete` closure evidence, and its `ClosureIncomplete` is
//! replaced by the mismatch.

use std::collections::{BTreeMap, HashMap};

use pos_conformance::{
    preflight_verification_v1, ArtifactClosureStatusV1, DivergenceReportV1, ReplayClaimV1,
    ReproducibilityClassV1, SafeErrorCodeV1, VerificationErrorV1, VerificationOutcomeV1,
    VerificationPreflightCoordinateV1, VerificationPreflightErrorV1,
    VerificationPreflightEvidenceV1, VerificationPreflightInputV1, VerificationPreflightResultV1,
    VerificationResultV1,
};
use pos_core::{CoreError, Event, StateRegistry, TimelineId};
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
const CLOSURE_DOMAIN_V1: &[u8] = b"PiglorOS.RecordedReplayClosure.v1";
const EXPORTED_TIMELINE_ROLE_V1: u8 = 1;
const RECOMPUTATION_SUBJECT_ROLE_V1: u8 = 2;
const LICENCE_ROLE_V1: u8 = 3;

/// The `artifact_closure_digest` of a `RecordedReplay` closure: the exported
/// Timeline's ADR-060 artifact digest and the licence member bytes, composed
/// as the module documentation states.
#[must_use]
pub fn recorded_replay_closure_digest_v1(export_digest: [u8; 32], licence: &[u8]) -> [u8; 32] {
    closure_digest(EXPORTED_TIMELINE_ROLE_V1, export_digest, licence)
}

/// The `artifact_closure_digest` of a recomputation closure: the frozen
/// subject's artifact digest and the licence member bytes, composed as the
/// module documentation states.
#[must_use]
pub fn recomputation_closure_digest_v1(subject_digest: [u8; 32], licence: &[u8]) -> [u8; 32] {
    closure_digest(RECOMPUTATION_SUBJECT_ROLE_V1, subject_digest, licence)
}

fn closure_digest(role: u8, primary: [u8; 32], licence: &[u8]) -> [u8; 32] {
    let mut digest = domain_hasher(CLOSURE_DOMAIN_V1);
    digest.update(&2_u64.to_be_bytes());
    digest.update(&[role]);
    digest.update(&primary);
    digest.update(&[LICENCE_ROLE_V1]);
    digest.update(blake3::hash(licence).as_bytes());
    *digest.finalize().as_bytes()
}

/// The result of one verification execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationExecutionOutcomeV1 {
    /// The sealed `VRR1`, validated by the pos-conformance codec.
    pub result: VerificationResultV1,
    /// The `DVR1` whose digest the result carries, when it diverged.
    pub divergence: Option<DivergenceReportV1>,
}

/// One closed refusal before or during execution.
#[derive(Clone, Copy)]
pub(crate) struct Refusal {
    pub(crate) outcome: VerificationOutcomeV1,
    pub(crate) replay_claim: ReplayClaimV1,
    pub(crate) code: SafeErrorCodeV1,
    pub(crate) coordinate: Option<VerificationPreflightCoordinateV1>,
}

/// The preflight's closure refusal, reported when a closure member is missing.
const CLOSURE_INCOMPLETE: Refusal = Refusal {
    outcome: VerificationOutcomeV1::UnverifiableArtifactsMissing,
    replay_claim: ReplayClaimV1::UnverifiableArtifactsMissing,
    code: SafeErrorCodeV1::ClosureIncomplete,
    coordinate: Some(VerificationPreflightCoordinateV1::ArtifactClosure),
};

/// The claim an `UnverifiableArtifactsMissing` result reports: a
/// `StructuralOnly` claim stays distinct, every other claim is missing.
const fn missing_claim(claim: ReplayClaimV1) -> ReplayClaimV1 {
    match claim {
        ReplayClaimV1::StructuralOnly => ReplayClaimV1::StructuralOnly,
        ReplayClaimV1::Exact
        | ReplayClaimV1::ExactAuthoritativeWithRedactedViews
        | ReplayClaimV1::UnverifiableArtifactsMissing
        | ReplayClaimV1::IncompatibleProfile => ReplayClaimV1::UnverifiableArtifactsMissing,
    }
}

/// An `UnverifiableArtifactsMissing` refusal at `replay_claim`.
pub(crate) const fn missing(claim: ReplayClaimV1) -> Refusal {
    Refusal {
        outcome: VerificationOutcomeV1::UnverifiableArtifactsMissing,
        replay_claim: missing_claim(claim),
        code: SafeErrorCodeV1::ProvenanceMissing,
        coordinate: Some(VerificationPreflightCoordinateV1::ReplayClaim),
    }
}

/// An `IncompatibleProfile` refusal.
pub(crate) const fn incompatible(
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

/// A `ResourceLimitExceeded` refusal; the manifest `resource_limit` counts
/// Events.
pub(crate) const fn resource_limit_exceeded(claim: ReplayClaimV1) -> Refusal {
    Refusal {
        outcome: VerificationOutcomeV1::ResourceLimitExceeded,
        replay_claim: claim,
        code: SafeErrorCodeV1::ResourceLimitExceeded,
        coordinate: None,
    }
}

/// Map the preflight's first error to a refusal. A closure or provenance
/// error is `UnverifiableArtifactsMissing`, a profile error is
/// `IncompatibleProfile`, and every other code is `InvalidManifest`.
pub(crate) const fn preflight_refusal(
    error: VerificationPreflightErrorV1,
    declared_claim: ReplayClaimV1,
) -> Refusal {
    let (outcome, replay_claim) = match error.code() {
        SafeErrorCodeV1::ClosureIncomplete | SafeErrorCodeV1::ProvenanceMissing => (
            VerificationOutcomeV1::UnverifiableArtifactsMissing,
            missing_claim(declared_claim),
        ),
        SafeErrorCodeV1::ProfileUnsupported | SafeErrorCodeV1::ProfileClassMismatch => (
            VerificationOutcomeV1::IncompatibleProfile,
            ReplayClaimV1::IncompatibleProfile,
        ),
        SafeErrorCodeV1::InvalidEncoding
        | SafeErrorCodeV1::UnsupportedVersion
        | SafeErrorCodeV1::FieldOutOfBounds
        | SafeErrorCodeV1::NonCanonicalOrder
        | SafeErrorCodeV1::DigestMismatch
        | SafeErrorCodeV1::SignatureInvalid
        | SafeErrorCodeV1::TrustRootUnknown
        | SafeErrorCodeV1::TrustSnapshotRollback
        | SafeErrorCodeV1::ArtifactRevoked
        // The preflight never reports a resource limit; it is listed so that
        // a new safe error code fails to compile here.
        | SafeErrorCodeV1::ResourceLimitExceeded => {
            (VerificationOutcomeV1::InvalidManifest, declared_claim)
        }
    };
    Refusal {
        outcome,
        replay_claim,
        code: error.code(),
        coordinate: Some(error.coordinate()),
    }
}

/// Run the unchanged preflight with `Incomplete` closure evidence and
/// return its refusal; used when a closure member is missing. There is no
/// licence coordinate (ADR-062 Revision 8, Q5).
pub(crate) fn refuse_incomplete_closure(preflight: VerificationPreflightInputV1<'_>) -> Refusal {
    let declared_claim = preflight.manifest.replay_claim;
    let preflight = VerificationPreflightInputV1 {
        evidence: VerificationPreflightEvidenceV1 {
            artifact_closure: ArtifactClosureStatusV1::Incomplete,
            ..preflight.evidence
        },
        ..preflight
    };
    // An incomplete closure always fails the preflight, at the latest with
    // `ClosureIncomplete` at `artifact_closure`.
    preflight_verification_v1(&preflight)
        .err()
        .map_or(CLOSURE_INCOMPLETE, |error| {
            preflight_refusal(error, declared_claim)
        })
}

/// Run the preflight for a complete member set whose composition is
/// `closure_digest`. When it is not the request's `artifact_closure_digest`,
/// the set is refused at `artifact_closure` with `DigestMismatch`, after any
/// error the preflight reports at an earlier coordinate.
pub(crate) fn preflight_bound_closure(
    preflight: &VerificationPreflightInputV1<'_>,
    closure_digest: [u8; 32],
) -> Result<VerificationPreflightResultV1, Refusal> {
    let declared_claim = preflight.manifest.replay_claim;
    if closure_digest == preflight.request.artifact_closure_digest {
        preflight_verification_v1(preflight)
            .map_err(|error| preflight_refusal(error, declared_claim))
    } else {
        // The ordering is the preflight's own, not this function's: the
        // unchanged preflight runs with `Incomplete` closure evidence, so any
        // error at a coordinate it checks before `artifact_closure` is its
        // first error, and only its `ClosureIncomplete` becomes the mismatch.
        // `closure_members_that_do_not_compose_the_request_digest_are_refused`
        // in `tests/recorded_replay.rs` pins this with a format-version error.
        let refusal = refuse_incomplete_closure(VerificationPreflightInputV1 {
            evidence: preflight.evidence.clone(),
            ..*preflight
        });
        Err(if refusal.code == SafeErrorCodeV1::ClosureIncomplete {
            Refusal {
                outcome: VerificationOutcomeV1::InvalidManifest,
                replay_claim: declared_claim,
                code: SafeErrorCodeV1::DigestMismatch,
                coordinate: Some(VerificationPreflightCoordinateV1::ArtifactClosure),
            }
        } else {
            refusal
        })
    }
}

/// Admit only the listed reproducibility classes; any other class is
/// `IncompatibleProfile` at `profile_class`.
pub(crate) fn admit_class(
    admitted: VerificationPreflightResultV1,
    classes: &[ReproducibilityClassV1],
) -> Result<VerificationPreflightResultV1, Refusal> {
    if classes.contains(&admitted.reproducibility_class) {
        Ok(admitted)
    } else {
        Err(incompatible(
            SafeErrorCodeV1::ProfileClassMismatch,
            VerificationPreflightCoordinateV1::ProfileClass,
        ))
    }
}

/// The number of Events, saturating at `u64::MAX`.
pub(crate) fn event_count(events: &[Event]) -> u64 {
    u64::try_from(events.len()).unwrap_or(u64::MAX)
}

/// Fold `events` into `projections` from empty State and read its Snapshot
/// under the registry's erasure fence; a denied fence is
/// `UnverifiableArtifactsMissing`.
pub(crate) fn rebuild_projections(
    projections: &mut ProjectionRegistry,
    claim: ReplayClaimV1,
    timeline: TimelineId,
    events: &[Event],
) -> Result<HashMap<String, StateRegistry>, Refusal> {
    projections.clear_state();
    projections.fold_events(timeline, events);
    projections
        .state_snapshot(timeline)
        .map_err(|_| missing(claim))
}

/// The authoritative stream of `events` and their Projection `snapshot`,
/// addressed by `timeline_id`; `event_id` gives the Event id bytes the
/// identity digest covers.
pub(crate) fn authoritative_stream(
    timeline_id: [u8; 16],
    events: &[Event],
    snapshot: &HashMap<String, StateRegistry>,
    event_id: impl Fn(&Event) -> [u8; 16],
) -> Result<AuthoritativeStreamV1, CoreError> {
    pos_crypto::canonical::encode(snapshot).map(|bytes| {
        let bytes = bytes.as_slice();
        let mut digest = domain_hasher(CHECKPOINT_DOMAIN_V1);
        digest.update(bytes);
        let coordinate = TickBoundaryCoordinateV1 {
            timeline_id,
            fold_cursor: events.last().map_or(0, |event| event.seq.as_u64()),
            tick: 0,
        };
        let checkpoint = CheckpointDigestV1 {
            digest: *digest.finalize().as_bytes(),
            size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        };
        AuthoritativeStreamV1 {
            events: events
                .iter()
                .map(|event| compared_event(timeline_id, event_id(event), event))
                .collect(),
            checkpoints: BTreeMap::from([(coordinate, checkpoint)]),
            ..AuthoritativeStreamV1::default()
        }
    })
}

fn compared_event(
    timeline_id: [u8; 16],
    event_id: [u8; 16],
    event: &Event,
) -> (TimelinePositionV1, ComparedEventV1) {
    let event_type = event.event_type.as_str().as_bytes();
    let mut identity = domain_hasher(EVENT_IDENTITY_DOMAIN_V1);
    identity.update(&event_id);
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
    digest.update(&count(actual.events.len()));
    for (position, event) in &actual.events {
        digest.update(&position.timeline_id);
        digest.update(&position.seq.to_be_bytes());
        digest.update(&event.identity);
        digest.update(&event.schema);
        digest.update(blake3::hash(&event.payload).as_bytes());
    }
    digest.update(&count(actual.checkpoints.len()));
    for (coordinate, checkpoint) in &actual.checkpoints {
        digest.update(&coordinate.timeline_id);
        digest.update(&coordinate.fold_cursor.to_be_bytes());
        digest.update(&coordinate.tick.to_be_bytes());
        digest.update(&checkpoint.digest);
        digest.update(&checkpoint.size.to_be_bytes());
    }
    digest_typed_failures(&mut digest, actual);
    *digest.finalize().as_bytes()
}

/// Append the typed-failure count and each typed failure's coordinate and
/// canonical bytes to the result digest.
fn digest_typed_failures(digest: &mut blake3::Hasher, actual: &AuthoritativeStreamV1) {
    digest.update(&count(actual.driver_outputs.len()));
    for (coordinate, output) in &actual.driver_outputs {
        digest.update(&coordinate.timeline_id);
        digest.update(&coordinate.fold_cursor.to_be_bytes());
        digest.update(&coordinate.tick.to_be_bytes());
        digest.update(&coordinate.scheduler_position.to_be_bytes());
        digest.update(&count(coordinate.driver_id.len()));
        digest.update(coordinate.driver_id.as_bytes());
        digest.update(&coordinate.output_ordinal.to_be_bytes());
        let bytes = output.outcome.canonical_bytes();
        digest.update(&[output.outcome.tag_v1()]);
        digest.update(&count(bytes.len()));
        digest.update(bytes);
    }
}

fn count(length: usize) -> [u8; 8] {
    u64::try_from(length).unwrap_or(u64::MAX).to_be_bytes()
}

fn domain_hasher(domain: &[u8]) -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    hasher
}

/// The identity fields every result of one run carries.
pub(crate) struct ResultHeader {
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

fn first_error(
    code: SafeErrorCodeV1,
    coordinate: Option<VerificationPreflightCoordinateV1>,
) -> VerificationErrorV1 {
    VerificationErrorV1 {
        code,
        field_ordinal: None,
        canonical_coordinate: coordinate.map(|coordinate| coordinate.to_string().into_bytes()),
        related_digest: None,
    }
}

impl ResultHeader {
    /// The header of one run. `member_digest` is the artifact digest of the
    /// closure's primary member (the exported Timeline or the recomputation
    /// subject), when it is supplied.
    pub(crate) fn new(
        preflight: &VerificationPreflightInputV1<'_>,
        member_digest: Option<[u8; 32]>,
        licence: Option<&[u8]>,
        fixture_digest: Option<[u8; 32]>,
    ) -> Self {
        let request = preflight.request;
        let licence_digest = licence
            .filter(|bytes| !bytes.is_empty())
            .map_or([0; 32], |bytes| *blake3::hash(bytes).as_bytes());
        let mut provenance = domain_hasher(PROVENANCE_DOMAIN_V1);
        provenance.update(&preflight.canonical_request_digest);
        provenance.update(&member_digest.unwrap_or([0; 32]));
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
            checked_artifact_count: u64::from(member_digest.is_some())
                + u64::from(licence_digest != [0; 32]),
            provenance_digest: *provenance.finalize().as_bytes(),
        }
    }

    /// Seal a refusal: one closed first error and no comparison.
    pub(crate) fn refuse(
        &self,
        refusal: Refusal,
    ) -> Result<VerificationExecutionOutcomeV1, CoreError> {
        self.seal(Verdict {
            outcome: refusal.outcome,
            replay_claim: refusal.replay_claim,
            authoritative_result_digest: None,
            divergence_report_digest: None,
            first_error: Some(first_error(refusal.code, refusal.coordinate)),
        })
        .map(|result| VerificationExecutionOutcomeV1 {
            result,
            divergence: None,
        })
    }

    /// Seal a run whose admitted claim cannot be exact: the actual result is
    /// recorded but never compared, so the outcome is
    /// `UnverifiableArtifactsMissing` with the admitted claim.
    pub(crate) fn unverified(
        &self,
        replay_claim: ReplayClaimV1,
        actual: &AuthoritativeStreamV1,
    ) -> Result<VerificationExecutionOutcomeV1, CoreError> {
        self.seal(Verdict {
            outcome: VerificationOutcomeV1::UnverifiableArtifactsMissing,
            replay_claim: missing_claim(replay_claim),
            authoritative_result_digest: Some(authoritative_result_digest(actual)),
            divergence_report_digest: None,
            first_error: Some(first_error(
                SafeErrorCodeV1::ProvenanceMissing,
                Some(VerificationPreflightCoordinateV1::ReplayClaim),
            )),
        })
        .map(|result| VerificationExecutionOutcomeV1 {
            result,
            divergence: None,
        })
    }

    /// Compare the actual stream with the expected one: `VerifiedExact`, or
    /// `Diverged` with the `DVR1` of the first divergence.
    pub(crate) fn compare(
        &self,
        replay_claim: ReplayClaimV1,
        expected: &AuthoritativeStreamV1,
        actual: &AuthoritativeStreamV1,
    ) -> Result<VerificationExecutionOutcomeV1, CoreError> {
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
            .map(|result| VerificationExecutionOutcomeV1 { result, divergence })
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
