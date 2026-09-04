//! Focused ERQ1 fixture builders for evidence codec integration tests.

use pos_core::{
    ErasureArtifactClassV1, ErasureErrorV1, ErasureKeyRoleV1, ErasureReferenceV1,
    ErasureRequestInputV1, ErasureRequestV1, ErasureRequiredTargetV1, ErasureScopeV1,
};

/// Build a deterministic test-only digest reference.
#[must_use]
pub(super) const fn reference(value: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([value; 32])
}

/// Build the stable TimelineReplay/DataEncryption target used by codec tests.
#[must_use]
pub(super) const fn replay_target(seed: u8) -> ErasureRequiredTargetV1 {
    ErasureRequiredTargetV1 {
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: reference(seed),
        key_role: ErasureKeyRoleV1::DataEncryption,
        key_digest: reference(seed.wrapping_add(1)),
        replica_set: reference(seed.wrapping_add(2)),
        replica_id: reference(seed.wrapping_add(3)),
    }
}

/// Named fields for a public ERQ1 fixture.
pub(super) struct RequestFixtureInput {
    pub(super) request: ErasureReferenceV1,
    pub(super) subject: ErasureReferenceV1,
    pub(super) scope: ErasureScopeV1,
    pub(super) selectors: Vec<ErasureReferenceV1>,
    pub(super) requester: ErasureReferenceV1,
    pub(super) authorization: ErasureReferenceV1,
    pub(super) policy: ErasureReferenceV1,
    pub(super) request_position: u64,
    pub(super) horizon_position: u64,
    pub(super) provenance: ErasureReferenceV1,
}

/// Construct an ERQ1 through the public constructor used by callers.
///
/// # Errors
///
/// Returns [`ErasureErrorV1`] when the fixture fields violate ERQ1 invariants.
pub(super) fn request(input: RequestFixtureInput) -> Result<ErasureRequestV1, ErasureErrorV1> {
    ErasureRequestV1::new(ErasureRequestInputV1 {
        request: input.request,
        subject: input.subject,
        scope: input.scope,
        selectors: input.selectors,
        requester: input.requester,
        authorization: input.authorization,
        policy: input.policy,
        request_position: input.request_position,
        horizon_position: input.horizon_position,
        provenance: input.provenance,
    })
}
