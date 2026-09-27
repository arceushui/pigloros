//! Erasure-aware Timeline verification and ADR-060 `ReplayClaim` reporting.
//!
//! Artifact availability comes from the host-owned erasure record. This
//! module retains no Event bytes and never treats a structural commitment as
//! cryptographic verification.

use pos_core::{
    ArtifactClaimInputV1, ArtifactOptionalityV1, ArtifactStateV1, ArtifactTransitionRuleV1,
    ErasureArtifactClassV1, ErasureErrorV1, ErasureReplayClaimV1, Event, KeyIdentityV1,
    KeyRegistryStateV1, KeyRoleV1, PublicKey, ReplayClaimEvaluatorV1, TimelineEventVerificationV1,
};

use crate::{
    key_roles::verify_committed_timeline_event_v1, signing::verifying_key_from_public_key,
};

/// Host-owned evidence for one Event's two required artifacts.
///
/// The payload and signed-context inputs must be distinct required
/// `TimelineReplay` registrations fixed before erasure. The context artifact
/// covers availability of the signature, public key, trust anchor, and every
/// signed metadata field; the exact trust anchor is still supplied separately.
/// An originally absent optional ID is authenticated null. Loss of an
/// originally present ID requires a missing context state.
#[derive(Clone, Copy)]
pub struct TimelineEventErasureInputV1<'a> {
    pub event: Option<&'a Event>,
    pub registry: Option<&'a KeyRegistryStateV1>,
    pub trust_anchor: Option<(KeyIdentityV1, PublicKey)>,
    pub enclosing_claim: ErasureReplayClaimV1,
    pub payload_artifact: ArtifactClaimInputV1,
    pub signed_context_artifact: ArtifactClaimInputV1,
}

/// Separate cryptographic and artifact-level outcomes for one Timeline Event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimelineEventErasureReportV1 {
    verification: TimelineEventVerificationV1,
    replay_claim: ErasureReplayClaimV1,
}

impl TimelineEventErasureReportV1 {
    /// Exact per-Event cryptographic result; this never claims range completeness.
    #[must_use]
    pub const fn verification(self) -> TimelineEventVerificationV1 {
        self.verification
    }

    /// ADR-060 claim after required-artifact evaluation and conservative caps.
    #[must_use]
    pub const fn replay_claim(self) -> ErasureReplayClaimV1 {
        self.replay_claim
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RetainedContext {
    Present,
    Missing,
    Invalid,
}

const fn artifact_bytes_available(input: ArtifactClaimInputV1) -> bool {
    match input.state {
        ArtifactStateV1::Retained => true,
        ArtifactStateV1::TransitionApplied => matches!(
            input.registration.transition_rule(),
            ArtifactTransitionRuleV1::PreserveExact | ArtifactTransitionRuleV1::RedactViews
        ),
        _ => false,
    }
}

fn retained_context(
    event: &Event,
    registry: Option<&KeyRegistryStateV1>,
    trust_anchor: Option<(KeyIdentityV1, PublicKey)>,
) -> RetainedContext {
    let Some(identity) = event.signature_identity else {
        return RetainedContext::Missing;
    };
    if identity.role != KeyRoleV1::TimelineIntegritySigning || identity.epoch == 0 {
        return RetainedContext::Invalid;
    }
    if event.signature.is_none() || event.origin.is_none() {
        return RetainedContext::Missing;
    }
    let (Some(registry), Some((anchor_identity, anchor_key))) = (registry, trust_anchor) else {
        return RetainedContext::Missing;
    };
    if anchor_identity != identity {
        return RetainedContext::Invalid;
    }
    let Some(public_key) = registry
        .key_record(identity)
        .and_then(|record| record.public_verification_key)
    else {
        return RetainedContext::Missing;
    };
    if public_key != anchor_key || verifying_key_from_public_key(&public_key).is_err() {
        return RetainedContext::Invalid;
    }
    RetainedContext::Present
}

/// Evaluate erasure without upgrading either cryptographic or `ReplayClaim` evidence.
///
/// If payload bytes are unavailable but signed context and exact trust remain,
/// the cryptographic result is `MissingRequiredContext` and the `ReplayClaim` is
/// at most `StructuralOnly`. Loss of signed context, public key, or trust anchor
/// caps the `ReplayClaim` at `UnverifiableArtifactsMissing`. A present invalid
/// signature remains `Invalid`; its artifact-level claim is reported separately.
/// No field is retained solely for this report.
///
/// # Errors
/// Returns a closed erasure policy error for an optional or wrong-class input,
/// duplicate registration, or an invalid artifact evaluation.
pub fn evaluate_timeline_event_erasure_v1(
    input: TimelineEventErasureInputV1<'_>,
) -> Result<TimelineEventErasureReportV1, ErasureErrorV1> {
    let artifacts = [input.payload_artifact, input.signed_context_artifact];
    if artifacts.iter().any(|artifact| {
        artifact.registration.artifact_class() != ErasureArtifactClassV1::TimelineReplay
            || artifact.registration.optionality() != ArtifactOptionalityV1::Required
    }) {
        return Err(ErasureErrorV1::PolicyConflict);
    }
    let evaluation = ReplayClaimEvaluatorV1::evaluate(input.enclosing_claim, &artifacts)?;
    let context_available = artifact_bytes_available(input.signed_context_artifact);
    let payload_available = artifact_bytes_available(input.payload_artifact);
    let (verification, cap) = input.event.filter(|_| context_available).map_or(
        (
            TimelineEventVerificationV1::MissingRequiredContext,
            ErasureReplayClaimV1::UnverifiableArtifactsMissing,
        ),
        |event| {
            if payload_available {
                let verification =
                    verify_committed_timeline_event_v1(event, input.registry, input.trust_anchor);
                let cap = if verification == TimelineEventVerificationV1::MissingRequiredContext {
                    ErasureReplayClaimV1::UnverifiableArtifactsMissing
                } else {
                    evaluation.replay_claim()
                };
                (verification, cap)
            } else {
                match retained_context(event, input.registry, input.trust_anchor) {
                    RetainedContext::Present => (
                        TimelineEventVerificationV1::MissingRequiredContext,
                        ErasureReplayClaimV1::StructuralOnly,
                    ),
                    RetainedContext::Missing => (
                        TimelineEventVerificationV1::MissingRequiredContext,
                        ErasureReplayClaimV1::UnverifiableArtifactsMissing,
                    ),
                    RetainedContext::Invalid => (
                        TimelineEventVerificationV1::Invalid,
                        ErasureReplayClaimV1::UnverifiableArtifactsMissing,
                    ),
                }
            }
        },
    );
    Ok(TimelineEventErasureReportV1 {
        verification,
        replay_claim: evaluation.replay_claim().weakened_to(cap),
    })
}
