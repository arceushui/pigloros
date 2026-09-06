//! Shared builders for public ADR-060 integration-test fixtures.
//!
//! Store integration tests include this file by path so these public fixture
//! builders have one test-only owner.

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

/// Expand the persistence-port methods that are identical for test hosts.
///
/// Hosts retain their scenario-specific manifest/object/CAS behavior locally;
/// this shared forwarding block keeps the public read/index surface in one
/// place for backend-parity tests.
#[macro_export]
macro_rules! impl_erasure_persistence_forwarding {
    () => {
        fn read_effect(
            &self,
            manifest: pos_core::ErasureReferenceV1,
        ) -> Result<pos_core::ErasureCasEffectV1, pos_core::ErasureErrorV1> {
            self.store.borrow().read_effect(manifest)
        }

        fn effect_manifest(
            &self,
            subject: pos_core::ErasureReferenceV1,
        ) -> Result<Option<pos_core::ErasureReferenceV1>, pos_core::ErasureErrorV1> {
            self.store.borrow().effect_manifest(subject)
        }

        fn attempt_page_ref(
            &self,
            request: pos_core::ErasureReferenceV1,
            ordinal: u64,
        ) -> Result<Option<pos_core::ErasureReferenceV1>, pos_core::ErasureErrorV1> {
            self.store.borrow().attempt_page_ref(request, ordinal)
        }

        fn attempt_index_count(
            &self,
            request: pos_core::ErasureReferenceV1,
        ) -> Result<u64, pos_core::ErasureErrorV1> {
            self.store.borrow().attempt_index_count(request)
        }

        fn scope_node_ref(
            &self,
            request: pos_core::ErasureReferenceV1,
            ordinal: u64,
        ) -> Result<Option<pos_core::ErasureReferenceV1>, pos_core::ErasureErrorV1> {
            self.store.borrow().scope_node_ref(request, ordinal)
        }

        fn scope_index_count(
            &self,
            request: pos_core::ErasureReferenceV1,
        ) -> Result<u64, pos_core::ErasureErrorV1> {
            self.store.borrow().scope_index_count(request)
        }

        fn administrative_resolution_ref(
            &self,
            request: pos_core::ErasureReferenceV1,
            ordinal: u64,
        ) -> Result<Option<pos_core::ErasureReferenceV1>, pos_core::ErasureErrorV1> {
            self.store
                .borrow()
                .administrative_resolution_ref(request, ordinal)
        }

        fn administrative_resolution_index_count(
            &self,
            request: pos_core::ErasureReferenceV1,
        ) -> Result<u64, pos_core::ErasureErrorV1> {
            self.store
                .borrow()
                .administrative_resolution_index_count(request)
        }

        fn recovery_error_refs(
            &self,
            request: pos_core::ErasureReferenceV1,
        ) -> Result<Vec<pos_core::ErasureReferenceV1>, pos_core::ErasureErrorV1> {
            self.store.borrow().recovery_error_refs(request)
        }

        fn append_recovery_error(
            &mut self,
            object: pos_core::PreparedErasureRecoveryErrorV1,
        ) -> Result<(), pos_core::ErasureErrorV1> {
            self.store.borrow_mut().append_recovery_error(object)
        }
    };
}

/// Build a deterministic test-only digest reference.
#[must_use]
pub const fn reference(value: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([value; 32])
}

/// Build the common TimelineReplay/DataEncryption target used by persistence
/// lifecycle scenarios.
#[must_use]
pub const fn replay_target(seed: u8) -> ErasureRequiredTargetV1 {
    let varied = target(seed);
    ErasureRequiredTargetV1 {
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        key_role: ErasureKeyRoleV1::DataEncryption,
        ..varied
    }
}

/// Build the varied target matrix used by codec and receipt scenarios.
#[must_use]
pub const fn target(seed: u8) -> ErasureRequiredTargetV1 {
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
pub struct RequestFixtureInput {
    pub request: ErasureReferenceV1,
    pub subject: ErasureReferenceV1,
    pub scope: ErasureScopeV1,
    pub selectors: Vec<ErasureReferenceV1>,
    pub requester: ErasureReferenceV1,
    pub authorization: ErasureReferenceV1,
    pub policy: ErasureReferenceV1,
    pub request_position: u64,
    pub horizon_position: u64,
    pub provenance: ErasureReferenceV1,
}

/// Construct an ERQ1 through the same public constructor used by callers.
///
/// # Errors
///
/// Returns [`ErasureErrorV1`] when the fixture fields violate ERQ1 invariants.
pub fn request(input: RequestFixtureInput) -> Result<ErasureRequestV1, ErasureErrorV1> {
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

/// Build the deterministic ERQ1 shared by the persistence integration suites.
///
/// Keeping this fixture here prevents the backend tests from silently drifting
/// apart while they exercise the same public persistence contract.
///
/// # Errors
///
/// Returns [`ErasureErrorV1`] if the shared fixture violates an ERQ1 invariant.
pub fn persistence_request() -> Result<ErasureRequestV1, ErasureErrorV1> {
    request(RequestFixtureInput {
        request: reference(1),
        subject: reference(2),
        scope: ErasureScopeV1::PrivateSubjectData,
        selectors: vec![reference(3)],
        requester: reference(4),
        authorization: reference(5),
        policy: reference(6),
        request_position: 9,
        horizon_position: 20,
        provenance: reference(7),
    })
}

/// Build the deterministic `TimelineReplay` target shared by persistence tests.
#[must_use]
pub const fn persistence_target() -> ErasureRequiredTargetV1 {
    replay_target(10)
}

/// Build one category-scoped obligation for an ERQ1 target.
///
/// # Errors
///
/// Returns [`ErasureErrorV1`] when the target or derived command identity is
/// not valid for an ERRA1 obligation.
pub fn obligation_for_category(
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
///
/// # Errors
///
/// Returns [`ErasureErrorV1`] when the target or derived command identity is
/// not valid for an ERRA1 obligation.
pub fn obligation(
    request: ErasureReferenceV1,
    target: ErasureRequiredTargetV1,
) -> Result<ErasureObligationV1, ErasureErrorV1> {
    obligation_for_category(request, ErasureInventoryCategoryV1::Artifact, target)
}

/// Named fields for a retry-admission fixture built from validated obligations.
#[derive(Clone, Copy)]
pub struct RetryAdmissionFixture<'a> {
    pub request: ErasureReferenceV1,
    pub attempt_ordinal: u64,
    pub source_receipt: Option<ErasureReferenceV1>,
    pub obligations: &'a [ErasureObligationV1],
    pub policy: ErasureReferenceV1,
    pub trust: ErasureReferenceV1,
    pub admitted_position: u64,
    pub deadline_position: u64,
    pub authorization_provenance: ErasureReferenceV1,
}

/// Construct a retry admission while keeping obligation/command ordering
/// aligned through the public ERRA1 constructor.
///
/// # Errors
///
/// Returns [`ErasureErrorV1`] when the supplied obligation identities do not
/// form a valid ERRA1 admission.
pub fn retry_admission(
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
