//! Shared builders for public ADR-060 integration-test fixtures.

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
pub(crate) const fn reference(value: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([value; 32])
}

/// Build the common TimelineReplay/DataEncryption target used by persistence
/// lifecycle scenarios.
#[must_use]
pub(crate) const fn replay_target(seed: u8) -> ErasureRequiredTargetV1 {
    ErasureRequiredTargetV1 {
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: reference(seed),
        key_role: ErasureKeyRoleV1::DataEncryption,
        key_digest: reference(seed.wrapping_add(1)),
        replica_set: reference(seed.wrapping_add(2)),
        replica_id: reference(seed.wrapping_add(3)),
    }
}

/// Build the varied target matrix used by codec and receipt scenarios.
#[must_use]
pub(crate) const fn target(seed: u8) -> ErasureRequiredTargetV1 {
    ErasureRequiredTargetV1 {
        artifact_class: match seed % 7 {
            0 => ErasureArtifactClassV1::TimelineReplay,
            1 => ErasureArtifactClassV1::ReproManifest,
            2 => ErasureArtifactClassV1::CausalTrace,
            3 => ErasureArtifactClassV1::CalibrationReport,
            4 => ErasureArtifactClassV1::Export,
            5 => ErasureArtifactClassV1::ForkOrSnapshot,
            _ => ErasureArtifactClassV1::ConformanceReport,
        },
        artifact_digest: reference(seed),
        key_role: match seed % 4 {
            0 => ErasureKeyRoleV1::DataEncryption,
            1 => ErasureKeyRoleV1::Signing,
            2 => ErasureKeyRoleV1::BackupEnvelope,
            _ => ErasureKeyRoleV1::ReplicaTransport,
        },
        key_digest: reference(seed.wrapping_add(1)),
        replica_set: reference(seed.wrapping_add(2)),
        replica_id: reference(seed.wrapping_add(3)),
    }
}

/// Named fields for a public ERQ1 fixture.
pub(crate) struct RequestFixtureInput {
    pub(crate) request: ErasureReferenceV1,
    pub(crate) subject: ErasureReferenceV1,
    pub(crate) scope: ErasureScopeV1,
    pub(crate) selectors: Vec<ErasureReferenceV1>,
    pub(crate) requester: ErasureReferenceV1,
    pub(crate) authorization: ErasureReferenceV1,
    pub(crate) policy: ErasureReferenceV1,
    pub(crate) request_position: u64,
    pub(crate) horizon_position: u64,
    pub(crate) provenance: ErasureReferenceV1,
}

/// Construct an ERQ1 through the same public constructor used by callers.
///
/// # Errors
///
/// Returns [`ErasureErrorV1`] when the fixture fields violate ERQ1 invariants.
pub(crate) fn request(input: RequestFixtureInput) -> Result<ErasureRequestV1, ErasureErrorV1> {
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
pub(crate) fn obligation_for_category(
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
pub(crate) fn obligation(
    request: ErasureReferenceV1,
    target: ErasureRequiredTargetV1,
) -> Result<ErasureObligationV1, ErasureErrorV1> {
    obligation_for_category(request, ErasureInventoryCategoryV1::Artifact, target)
}

/// Named fields for a retry-admission fixture built from validated obligations.
#[derive(Clone, Copy)]
pub(crate) struct RetryAdmissionFixture<'a> {
    pub(crate) request: ErasureReferenceV1,
    pub(crate) attempt_ordinal: u64,
    pub(crate) source_receipt: Option<ErasureReferenceV1>,
    pub(crate) obligations: &'a [ErasureObligationV1],
    pub(crate) policy: ErasureReferenceV1,
    pub(crate) trust: ErasureReferenceV1,
    pub(crate) admitted_position: u64,
    pub(crate) deadline_position: u64,
    pub(crate) authorization_provenance: ErasureReferenceV1,
}

/// Construct a retry admission while keeping obligation/command ordering
/// aligned through the public ERRA1 constructor.
///
/// # Errors
///
/// Returns [`ErasureErrorV1`] when the supplied obligation identities do not
/// form a valid ERRA1 admission.
pub(crate) fn retry_admission(
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
pub(crate) struct FreezeEvidenceFixtureInput<'a> {
    pub(crate) request: ErasureReferenceV1,
    pub(crate) scope_commitment: ErasureReferenceV1,
    pub(crate) obligation_set: &'a ErasureObligationSetV1,
    pub(crate) targets: &'a [ErasureRequiredTargetV1],
    pub(crate) obligations: &'a [ErasureObligationV1],
    pub(crate) freeze_position: u64,
    pub(crate) evidence: &'a [u8],
}

/// Builds mutually bound admission and authorization evidence for a test freeze.
///
/// # Errors
///
/// Returns [`ErasureErrorV1`] when the fixture inputs violate an erasure
/// evidence invariant or canonical encoding fails.
pub(crate) fn freeze_evidence_fixture(
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
