//! Shared builders for public ADR-060 integration-test fixtures.

use std::collections::BTreeMap;

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

/// Named inputs for one mutually bound admission/authorization fixture.
pub struct FreezeEvidenceFixtureInput<'a> {
    pub request: ErasureReferenceV1,
    pub scope_commitment: ErasureReferenceV1,
    pub obligation_set: &'a ErasureObligationSetV1,
    pub targets: &'a [ErasureRequiredTargetV1],
    pub obligations: &'a [ErasureObligationV1],
    pub freeze_position: u64,
    pub evidence: &'a [u8],
}

/// Builds mutually bound admission and authorization evidence for a test freeze.
///
/// # Errors
///
/// Returns [`ErasureErrorV1`] when the fixture inputs violate an erasure
/// evidence invariant or canonical encoding fails.
pub fn freeze_evidence_fixture(
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
    let mut applicability_matrix = Vec::with_capacity(input.targets.len().saturating_mul(4));
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
