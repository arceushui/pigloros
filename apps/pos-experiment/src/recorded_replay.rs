//! `RecordedReplay` execution of one `RVR1` request to one `VRR1`.
//!
//! ADR-062 Revision 8 slice R2 (#1220). [`execute_recorded_replay_v1`] is the
//! execution step after [`preflight_verification_v1`]: it rebuilds Projection
//! State from the exported Timeline artifact, compares the result with the
//! expected authoritative stream through
//! [`first_divergence_v1`](crate::authoritative_comparison::first_divergence_v1),
//! and emits one sealed
//! [`VerificationResultV1`](pos_conformance::VerificationResultV1). It takes
//! no Driver, provider or store: it invokes no Driver, contacts no provider
//! and appends no Event.
//!
//! # Order
//!
//! 1. The `ArtifactClosure` members (ADR-062 Revision 8, Q5): the exported
//!    Timeline and a non-empty licence member must both be supplied. When
//!    either is missing, the `artifact_closure` evidence passed to the
//!    unchanged [`preflight_verification_v1`] is `Incomplete`; otherwise it is
//!    the deployment boundary's own report. There is no licence coordinate.
//! 2. [`preflight_verification_v1`]. Its first error becomes the result's
//!    first error, so a missing closure member is the preflight's own
//!    `ClosureIncomplete` at `artifact_closure`. A closure or provenance
//!    error is `UnverifiableArtifactsMissing`, a profile error is
//!    `IncompatibleProfile`, and every other code (encoding, digest, trust,
//!    signature, revocation) is `InvalidManifest`. The closure members bind
//!    the request's `artifact_closure_digest` (slice R4, #1222): when the
//!    composition of the export's artifact digest and the licence
//!    ([`recorded_replay_closure_digest_v1`]) is not that digest, the closure
//!    is refused at `artifact_closure` with `DigestMismatch`
//!    (`InvalidManifest`), after any earlier preflight coordinate.
//! 3. The reproducibility class must be `RecordedReplay`.
//! 4. ADR-060 `ReplayClaim` degradation: the admitted claim is weakened by the
//!    host-owned [`ReplayClaimEvaluationV1`], never strengthened. A weakened
//!    `IncompatibleProfile` claim is `IncompatibleProfile`; a `StructuralOnly`
//!    or `UnverifiableArtifactsMissing` claim, or an exported Timeline the
//!    evaluation does not admit for authoritative use, is
//!    `UnverifiableArtifactsMissing`. The result keeps a `StructuralOnly`
//!    claim distinct (ADR-058: the result is the class, outcome and claim
//!    tuple); every other missing case reports
//!    `UnverifiableArtifactsMissing`. A claim with redacted views stays exact
//!    (Q4: `VerifiedExact` with a degraded `replay_claim`).
//! 5. The number of Events in the export must not exceed the manifest
//!    `resource_limit`, read as an Event budget (as the Tick draft budget
//!    the proof kernel derives from it), checked before any Event is read.
//! 6. The export's sequences must be strictly increasing (Timeline Order);
//!    otherwise the export is an invalid closure member: `InvalidManifest`
//!    with `NonCanonicalOrder` at `artifact_closure`.
//! 7. The exported Events are folded into the caller's
//!    [`ProjectionRegistry`] from empty State, and its Snapshot is read under
//!    the registry's erasure fence; a denied fence is
//!    `UnverifiableArtifactsMissing`.
//! 8. The rebuilt stream is compared with the expected stream: no divergence
//!    is `VerifiedExact`; otherwise the result is `Diverged` and carries the
//!    `DVR1` digest.
//!
//! # Rebuilt stream
//!
//! A recorded export carries no Tick numbering, so every Event and the one
//! Projection checkpoint have tick 0; an expected stream for `RecordedReplay`
//! must use tick 0 too. The stream is addressed by the export's Timeline id
//! and each Event identity covers the recorded Event id. The Event schema
//! digest covers only the Event type and schema version, not a payload schema
//! or upcaster chain. The digests follow the accepted `RecordedReplay`
//! scheme documented in [`crate::verification_execution`]; Event payloads are
//! compared as canonical bytes.
//!
//! [`preflight_verification_v1`]: pos_conformance::preflight_verification_v1

use pos_conformance::{
    ReplayClaimV1, ReproducibilityClassV1, SafeErrorCodeV1, VerificationOutcomeV1,
    VerificationPreflightCoordinateV1, VerificationPreflightInputV1,
};
use pos_core::{
    CoreError, ErasureArtifactClassV1, ErasureReferenceV1, ReplayClaimEvaluationV1, TimelineExport,
};
use pos_state::ProjectionRegistry;

use crate::authoritative_comparison::AuthoritativeStreamV1;
use crate::verification_execution::{
    admit_class, authoritative_stream, event_count, incompatible, missing, preflight_bound_closure,
    rebuild_projections, recorded_replay_closure_digest_v1, refuse_incomplete_closure,
    resource_limit_exceeded, Refusal, ResultHeader, VerificationExecutionOutcomeV1,
};

/// The exported Timeline member of a `RecordedReplay` closure.
///
/// The host binds `artifact_digest` to the export's content; this step checks
/// that the ADR-060 evaluation admits that identity and that the digest,
/// composed with the licence, is the request's `artifact_closure_digest`.
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
    /// The licence member bytes, when they are materialized; empty bytes
    /// count as missing.
    pub licence: Option<&'a [u8]>,
}

/// Inputs to one `RecordedReplay` execution.
pub struct RecordedReplayInputV1<'a> {
    /// The preflight input. Its `artifact_closure` evidence is replaced by
    /// `Incomplete` when a closure member is missing, and is otherwise used
    /// as given; it is never overridden to complete.
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
) -> Result<VerificationExecutionOutcomeV1, CoreError> {
    let RecordedReplayInputV1 {
        preflight,
        closure,
        replay_claim_evaluation,
        expected,
        fixture_digest,
    } = input;
    let header = ResultHeader::new(
        &preflight,
        closure
            .timeline_export
            .map(|member| member.artifact_digest.digest()),
        closure.licence,
        fixture_digest,
    );
    let resource_limit = preflight.manifest.resource_limit;
    let rebuilt = match (closure.timeline_export, closure.licence) {
        (Some(export), Some(licence)) if !licence.is_empty() => {
            let closure_digest =
                recorded_replay_closure_digest_v1(export.artifact_digest.digest(), licence);
            preflight_bound_closure(&preflight, closure_digest)
                .and_then(|admitted| {
                    admit_class(admitted, &[ReproducibilityClassV1::RecordedReplay])
                })
                .and_then(|admitted| {
                    degrade_claim(admitted.replay_claim, replay_claim_evaluation, export)
                })
                .and_then(|claim| admit_budget(claim, export.export, resource_limit))
                .and_then(|claim| admit_order(claim, export.export))
                .and_then(|claim| {
                    rebuild_projections(
                        projections,
                        claim,
                        export.export.timeline.id(),
                        &export.export.events,
                    )
                    .map(|snapshot| (claim, export.export, snapshot))
                })
        }
        _ => Err(refuse_incomplete_closure(preflight)),
    };
    match rebuilt {
        Ok((claim, export, snapshot)) => authoritative_stream(
            export.timeline.id().inner().to_bytes(),
            &export.events,
            &snapshot,
            |event| event.id.inner().to_bytes(),
        )
        .and_then(|actual| header.compare(claim, expected, &actual)),
        Err(refusal) => header.refuse(refusal),
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
            .map_err(|_| missing(claim)),
        ReplayClaimV1::StructuralOnly | ReplayClaimV1::UnverifiableArtifactsMissing => {
            Err(missing(claim))
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
    if event_count(&export.events) <= resource_limit {
        Ok(claim)
    } else {
        Err(resource_limit_exceeded(claim))
    }
}

fn admit_order(claim: ReplayClaimV1, export: &TimelineExport) -> Result<ReplayClaimV1, Refusal> {
    if export
        .events
        .windows(2)
        .all(|pair| pair[0].seq < pair[1].seq)
    {
        Ok(claim)
    } else {
        Err(Refusal {
            outcome: VerificationOutcomeV1::InvalidManifest,
            replay_claim: claim,
            code: SafeErrorCodeV1::NonCanonicalOrder,
            coordinate: Some(VerificationPreflightCoordinateV1::ArtifactClosure),
        })
    }
}
