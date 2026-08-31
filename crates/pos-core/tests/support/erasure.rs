//! Shared builders for public ADR-060 integration-test fixtures.

use pos_core::{
    ErasureApplicabilityDecisionV1, ErasureErrorV1, ErasureFreezeAdmissionEvidenceInputV1,
    ErasureFreezeAdmissionEvidenceV1, ErasureFreezeApplicabilityRowV1,
    ErasureFreezeAuthorizationEvidenceInputV1, ErasureFreezeAuthorizationEvidenceV1,
    ErasureInventoryCategoryV1, ErasureObligationSetV1, ErasureObligationV1, ErasureReferenceV1,
    ErasureRequiredTargetV1,
};

const fn reference(value: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([value; 32])
}

/// Builds mutually bound admission and authorization evidence for a test freeze.
///
/// # Errors
///
/// Returns [`ErasureErrorV1`] when the fixture inputs violate an erasure
/// evidence invariant or canonical encoding fails.
pub fn freeze_evidence_fixture(
    request: ErasureReferenceV1,
    scope_commitment: ErasureReferenceV1,
    obligation_set: &ErasureObligationSetV1,
    targets: &[ErasureRequiredTargetV1],
    obligations: &[ErasureObligationV1],
    freeze_position: u64,
    evidence: &[u8],
) -> Result<
    (
        ErasureFreezeAdmissionEvidenceV1,
        ErasureFreezeAuthorizationEvidenceV1,
    ),
    ErasureErrorV1,
> {
    let mut applicability_matrix = Vec::with_capacity(targets.len().saturating_mul(4));
    for category in [
        ErasureInventoryCategoryV1::Artifact,
        ErasureInventoryCategoryV1::Key,
        ErasureInventoryCategoryV1::Replica,
        ErasureInventoryCategoryV1::Backup,
    ] {
        for (target_index, target) in targets.iter().enumerate() {
            let owner = obligations
                .iter()
                .find(|obligation| {
                    obligation.category() == category && obligation.target() == *target
                })
                .map(ErasureObligationV1::owner);
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
    let input = ErasureFreezeAdmissionEvidenceInputV1 {
        request,
        scope_commitment,
        obligation_set: obligation_set.reference(),
        applicability_matrix,
        freeze_position,
        policy: obligation_set.policy(),
        trust: obligation_set.trust(),
        authorization_provenance: reference(0),
    };
    let provisional = ErasureFreezeAdmissionEvidenceV1::new(input.clone())?;
    let authorization =
        ErasureFreezeAuthorizationEvidenceV1::new(ErasureFreezeAuthorizationEvidenceInputV1 {
            admission_body_digest: provisional.authorization_body_digest()?,
            policy: obligation_set.policy(),
            trust: obligation_set.trust(),
            evidence: evidence.to_vec(),
        })?;
    let admission = ErasureFreezeAdmissionEvidenceV1::new(ErasureFreezeAdmissionEvidenceInputV1 {
        authorization_provenance: authorization.reference(),
        ..input
    })?;
    Ok((admission, authorization))
}
