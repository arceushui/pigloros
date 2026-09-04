//! Focused ERQ1/ERRA1 fixture builders for the store integration tests.

use std::collections::BTreeMap;

use pos_core::{
    destruction_command_reference, ErasureApplicabilityDecisionV1, ErasureArtifactClassV1,
    ErasureErrorV1, ErasureFreezeAdmissionEvidenceInputV1, ErasureFreezeAdmissionEvidenceV1,
    ErasureFreezeApplicabilityRowV1, ErasureFreezeAuthorizationEvidenceInputV1,
    ErasureFreezeAuthorizationEvidenceV1, ErasureInventoryCategoryV1, ErasureKeyRoleV1,
    ErasureObligationInputV1, ErasureObligationSetV1, ErasureObligationV1, ErasureReferenceV1,
    ErasureRequestInputV1, ErasureRequestV1, ErasureRequiredTargetV1, ErasureRetryAdmissionInputV1,
    ErasureRetryAdmissionV1, ErasureScopeV1,
};

/// Build a deterministic test-only digest reference.
#[must_use]
pub(super) const fn reference(value: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([value; 32])
}

/// Build the stable TimelineReplay/DataEncryption target used by store tests.
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

/// Build one category-scoped obligation for an ERQ1 target.
///
/// # Errors
///
/// Returns [`ErasureErrorV1`] when the target or derived command identity is
/// not valid for an ERRA1 obligation.
pub(super) fn obligation_for_category(
    request: ErasureReferenceV1,
    category: ErasureInventoryCategoryV1,
    target: ErasureRequiredTargetV1,
) -> Result<ErasureObligationV1, ErasureErrorV1> {
    ErasureObligationV1::new(ErasureObligationInputV1 {
        category,
        target,
        owner: target.replica_id,
        command_identity: destruction_command_reference(request, target),
    })
}

/// Build the common artifact obligation for an ERQ1 target.
pub(super) fn obligation(
    request: ErasureReferenceV1,
    target: ErasureRequiredTargetV1,
) -> Result<ErasureObligationV1, ErasureErrorV1> {
    obligation_for_category(request, ErasureInventoryCategoryV1::Artifact, target)
}

/// Named fields for a retry-admission fixture built from validated obligations.
#[derive(Clone, Copy)]
pub(super) struct RetryAdmissionFixture<'a> {
    pub(super) request: ErasureReferenceV1,
    pub(super) attempt_ordinal: u64,
    pub(super) source_receipt: Option<ErasureReferenceV1>,
    pub(super) obligations: &'a [ErasureObligationV1],
    pub(super) policy: ErasureReferenceV1,
    pub(super) trust: ErasureReferenceV1,
    pub(super) admitted_position: u64,
    pub(super) deadline_position: u64,
    pub(super) authorization_provenance: ErasureReferenceV1,
}

/// Construct a retry admission through the public ERRA1 constructor.
///
/// # Errors
///
/// Returns [`ErasureErrorV1`] when the supplied obligation identities do not
/// form a valid ERRA1 admission.
pub(super) fn retry_admission(
    input: RetryAdmissionFixture<'_>,
) -> Result<ErasureRetryAdmissionV1, ErasureErrorV1> {
    ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
        request: input.request,
        attempt_ordinal: input.attempt_ordinal,
        source_receipt: input.source_receipt,
        unresolved_obligations: input
            .obligations
            .iter()
            .map(ErasureObligationV1::reference)
            .collect(),
        command_identities: input
            .obligations
            .iter()
            .map(ErasureObligationV1::command_identity)
            .collect(),
        policy: input.policy,
        trust: input.trust,
        admitted_position: input.admitted_position,
        deadline_position: input.deadline_position,
        authorization_provenance: input.authorization_provenance,
    })
}

/// Named inputs for one mutually bound admission/authorization fixture.
#[derive(Clone, Copy)]
pub(super) struct FreezeEvidenceFixtureInput<'a> {
    pub(super) request: ErasureReferenceV1,
    pub(super) scope_commitment: ErasureReferenceV1,
    pub(super) obligation_set: &'a ErasureObligationSetV1,
    pub(super) targets: &'a [ErasureRequiredTargetV1],
    pub(super) obligations: &'a [ErasureObligationV1],
    pub(super) freeze_position: u64,
    pub(super) evidence: &'a [u8],
}

/// Build mutually bound admission and authorization evidence for a test freeze.
///
/// # Errors
///
/// Returns [`ErasureErrorV1`] when the fixture inputs violate an erasure
/// evidence invariant or canonical encoding fails.
pub(super) fn freeze_evidence_fixture(
    input: FreezeEvidenceFixtureInput<'_>,
) -> Result<
    (
        ErasureFreezeAdmissionEvidenceV1,
        ErasureFreezeAuthorizationEvidenceV1,
    ),
    ErasureErrorV1,
> {
    let owners_by_obligation = input
        .obligations
        .iter()
        .map(|obligation| {
            (
                (obligation.category(), obligation.target()),
                obligation.owner(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut applicability_matrix = Vec::with_capacity(
        input
            .targets
            .len()
            .saturating_mul(ErasureInventoryCategoryV1::CANONICAL.len()),
    );
    for category in ErasureInventoryCategoryV1::CANONICAL {
        for (target_index, target) in input.targets.iter().enumerate() {
            let owner = owners_by_obligation.get(&(category, *target)).copied();
            applicability_matrix.push(ErasureFreezeApplicabilityRowV1::new(
                category,
                target_index as u64,
                if owner.is_some() {
                    ErasureApplicabilityDecisionV1::Applicable
                } else {
                    ErasureApplicabilityDecisionV1::Inapplicable
                },
                owner,
            )?);
        }
    }
    let admission_input = ErasureFreezeAdmissionEvidenceInputV1 {
        request: input.request,
        scope_commitment: input.scope_commitment,
        obligation_set: input.obligation_set.reference(),
        applicability_matrix,
        freeze_position: input.freeze_position,
        policy: input.obligation_set.policy(),
        trust: input.obligation_set.trust(),
        authorization_provenance: reference(0),
    };
    let provisional = ErasureFreezeAdmissionEvidenceV1::new(admission_input.clone())?;
    let authorization =
        ErasureFreezeAuthorizationEvidenceV1::new(ErasureFreezeAuthorizationEvidenceInputV1 {
            admission_body_digest: provisional.authorization_body_digest()?,
            policy: input.obligation_set.policy(),
            trust: input.obligation_set.trust(),
            evidence: input.evidence.to_vec(),
        })?;
    let admission = ErasureFreezeAdmissionEvidenceV1::new(ErasureFreezeAdmissionEvidenceInputV1 {
        authorization_provenance: authorization.reference(),
        ..admission_input
    })?;
    Ok((admission, authorization))
}
