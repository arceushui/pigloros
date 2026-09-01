//! Black-box parity contracts for durable ERQ1/ERS1/ERC1 persistence.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

#[path = "../../pos-core/tests/support/erasure.rs"]
mod freeze_fixture_support;

use freeze_fixture_support::{freeze_evidence_fixture, FreezeEvidenceFixtureInput};

use pos_core::erasure::{destruction_command_reference, target_closure_digest};
use pos_core::{
    CanonicalBytes, EntityId, ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementV1,
    ErasureAdministrativeResolutionActionV1, ErasureAdministrativeResolutionInputV1,
    ErasureAdministrativeResolutionV1, ErasureArtifactClassV1, ErasureArtifactTransitionV1,
    ErasureAtomicFreezeAdmissionInputV1, ErasureAtomicFreezeAdmissionV1,
    ErasureAtomicFreezeResultV1, ErasureCoordinatorPortV1, ErasureCoordinatorRecordPartsV1,
    ErasureCoordinatorRecordV1, ErasureCoordinatorStateMachineV1,
    ErasureCorrectionProvenanceInputV1, ErasureCorrectionProvenanceV1, ErasureErrorV1,
    ErasureFreezeAdmissionEvidenceV1, ErasureFreezeAuthorizationEvidenceV1,
    ErasureFreezeAuthorizationVerifierV1, ErasureInventoryCategoryV1, ErasureInventoryResultV1,
    ErasureKeyRoleV1, ErasureLifecycleV1, ErasureObligationInputV1, ErasureObligationSetInputV1,
    ErasureObligationSetV1, ErasureObligationV1, ErasurePersistencePortV1, ErasureReceiptInputV1,
    ErasureReceiptInventoriesV1, ErasureReceiptV1, ErasureReferenceV1, ErasureReplayClaimV1,
    ErasureRequestInputV1, ErasureRequestV1, ErasureRequiredTargetV1, ErasureRetryAdmissionV1,
    ErasureScopeCommitmentInputV1, ErasureScopeCommitmentV1, ErasureScopeExtensionInputV1,
    ErasureScopeExtensionLedgerInputV1, ErasureScopeExtensionLedgerV1, ErasureScopeExtensionV1,
    ErasureScopeV1, ErasureStateResolverV1, ErasureStateTransitionV1, ErasureStateV1,
    ErasureSupportingRecordsInputV1, ErasureSupportingRecordsV1, EventDraft, EventStore, Kind,
    VerifiedErasureCoordinatorRecordV1,
};
use pos_store::memory::MemoryStore;
use std::cell::RefCell;
use std::rc::Rc;

struct TestFreezeAuthorizationVerifier;

const TEST_FREEZE_AUTHORIZATION_VERIFIER: TestFreezeAuthorizationVerifier =
    TestFreezeAuthorizationVerifier;

impl ErasureFreezeAuthorizationVerifierV1 for TestFreezeAuthorizationVerifier {
    fn validate_freeze_authorization(
        &self,
        admission: &ErasureFreezeAdmissionEvidenceV1,
        authorization: &ErasureFreezeAuthorizationEvidenceV1,
    ) -> Result<(), ErasureErrorV1> {
        authorization.verify_admission_body_binding(admission)
    }
}

struct RejectingFreezeAuthorizationVerifier;

impl ErasureFreezeAuthorizationVerifierV1 for RejectingFreezeAuthorizationVerifier {
    fn validate_freeze_authorization(
        &self,
        _admission: &ErasureFreezeAdmissionEvidenceV1,
        _authorization: &ErasureFreezeAuthorizationEvidenceV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(ErasureErrorV1::Unauthorized)
    }
}

fn verified_record(
    record: ErasureCoordinatorRecordV1,
) -> Result<VerifiedErasureCoordinatorRecordV1, ErasureErrorV1> {
    VerifiedErasureCoordinatorRecordV1::new(record, &TEST_FREEZE_AUTHORIZATION_VERIFIER)
}

#[cfg(feature = "sqlite")]
use pos_store::sqlite::SqliteStore;

const fn reference(value: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([value; 32])
}

fn request() -> Result<ErasureRequestV1, ErasureErrorV1> {
    ErasureRequestV1::new(ErasureRequestInputV1 {
        request: reference(1),
        subject: reference(2),
        scope: ErasureScopeV1::PrivateSubjectData,
        selectors: vec![reference(3)],
        requester: reference(4),
        authorization: reference(5),
        policy: reference(6),
        request_position: 10,
        horizon_position: 20,
        provenance: reference(7),
    })
}

fn submitted_record() -> Result<ErasureCoordinatorRecordV1, ErasureErrorV1> {
    let request = request()?;
    let state = ErasureStateV1::submitted(request.reference(), reference(8), reference(9))?;
    ErasureCoordinatorRecordV1::from_parts(
        ErasureCoordinatorRecordPartsV1 {
            request,
            state,
            targets: Vec::new(),
            acknowledgements: Vec::new(),
            receipt: None,
            receipt_input: None,
            authorize_provenance: None,
            freeze_provenance: None,
            dispatch_provenance: None,
            scope_extension_ledger: None,
            administrative_resolution_head: None,
            supporting_records: ErasureSupportingRecordsV1::default(),
        },
        reference(8),
    )
}

fn record_parts(record: &ErasureCoordinatorRecordV1) -> ErasureCoordinatorRecordPartsV1 {
    ErasureCoordinatorRecordPartsV1 {
        request: record.request().clone(),
        state: record.state().clone(),
        targets: record.targets().to_vec(),
        acknowledgements: record.acknowledgements().to_vec(),
        receipt: record.receipt().cloned(),
        receipt_input: record.receipt_input().cloned(),
        authorize_provenance: record.authorize_provenance(),
        freeze_provenance: record.freeze_provenance(),
        dispatch_provenance: record.dispatch_provenance(),
        scope_extension_ledger: record.scope_extension_ledger(),
        administrative_resolution_head: record.administrative_resolution_head(),
        supporting_records: record.supporting_records().clone(),
    }
}

fn rejected_and_corrected_records() -> Result<
    (
        ErasureCoordinatorRecordV1,
        ErasureCoordinatorRecordV1,
        ErasureCoordinatorRecordV1,
    ),
    ErasureErrorV1,
> {
    let source = Rc::new(RefCell::new(MemoryStore::new()));
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(
        CoordinatorHost {
            store: Rc::clone(&source),
            targets: Vec::new(),
        },
        reference(8),
    );
    let request = request()?;
    let request_digest = request.reference();
    coordinator.submit(request, reference(7))?;
    let submitted = source
        .borrow()
        .load_record(request_digest, &TEST_FREEZE_AUTHORIZATION_VERIFIER)?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    coordinator.reject(reference(1), reference(30))?;
    let predecessor = source
        .borrow()
        .load_record(request_digest, &TEST_FREEZE_AUTHORIZATION_VERIFIER)?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let correction = ErasureCorrectionProvenanceV1::new(ErasureCorrectionProvenanceInputV1 {
        rejected_request: predecessor.request().reference(),
        rejected_terminal_state: predecessor.state().state_digest(),
        correction_reason: reference(31),
        authorization_provenance: reference(32),
    })?;
    let request = ErasureRequestV1::new(ErasureRequestInputV1 {
        request: reference(40),
        subject: reference(2),
        scope: ErasureScopeV1::PrivateSubjectData,
        selectors: vec![reference(3)],
        requester: reference(4),
        authorization: reference(5),
        policy: reference(6),
        request_position: 11,
        horizon_position: 20,
        provenance: correction.reference(),
    })?;
    let corrected_request = request.reference();
    coordinator.submit_corrected(request, correction)?;
    let corrected = source
        .borrow()
        .load_record(corrected_request, &TEST_FREEZE_AUTHORIZATION_VERIFIER)?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    Ok((submitted, predecessor, corrected))
}

fn assert_correction_chain<S: ErasurePersistencePortV1>(
    mut store: S,
) -> Result<(), ErasureErrorV1> {
    let (submitted, predecessor, corrected) = rejected_and_corrected_records()?;
    let corrected_request = corrected.request().reference();
    assert_eq!(
        store.commit_record(verified_record(corrected.clone())?),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    store.commit_record(verified_record(submitted)?)?;
    store.commit_record(verified_record(predecessor)?)?;
    store.commit_record(verified_record(corrected.clone())?)?;
    assert_eq!(
        store.load_record(corrected_request, &TEST_FREEZE_AUTHORIZATION_VERIFIER)?,
        Some(corrected)
    );
    Ok(())
}

fn with_replacement_receipt(
    records: &ErasureSupportingRecordsV1,
    receipt: ErasureReceiptV1,
) -> Result<ErasureSupportingRecordsV1, ErasureErrorV1> {
    let mut receipts = records.receipts().to_vec();
    let Some(latest) = receipts.last_mut() else {
        return Err(ErasureErrorV1::ProvenanceMissing);
    };
    *latest = receipt;
    supporting_records_with(
        records,
        records.scope_extensions().to_vec(),
        records.scope_extension_ledgers().to_vec(),
        receipts,
        records.administrative_resolutions().to_vec(),
    )
}

fn supporting_records_with(
    records: &ErasureSupportingRecordsV1,
    scope_extensions: Vec<ErasureScopeExtensionV1>,
    scope_extension_ledgers: Vec<ErasureScopeExtensionLedgerV1>,
    receipts: Vec<ErasureReceiptV1>,
    administrative_resolutions: Vec<ErasureAdministrativeResolutionV1>,
) -> Result<ErasureSupportingRecordsV1, ErasureErrorV1> {
    ErasureSupportingRecordsV1::new(ErasureSupportingRecordsInputV1 {
        correction_provenance: records.correction_provenance().cloned(),
        authorization_rejection: records.authorization_rejection(),
        scope_commitment: records.scope_commitment().cloned(),
        freeze_admission_evidence: records.freeze_admission_evidence().cloned(),
        freeze_authorization_evidence: records.freeze_authorization_evidence().cloned(),
        freeze_provenance: records.freeze_provenance(),
        freeze_failure: records.freeze_failure(),
        obligations: records.obligations().to_vec(),
        obligation_set: records.obligation_set().cloned(),
        scope_extensions,
        scope_extension_ledgers,
        retry_admissions: records.retry_admissions().to_vec(),
        acknowledgement_provenance: records.acknowledgement_provenance().to_vec(),
        attempt_outcomes: records.attempt_outcomes().to_vec(),
        receipts,
        receipt_provenance: records.receipt_provenance().to_vec(),
        administrative_resolutions,
    })
}

const fn category_scoped_owner(_target: ErasureRequiredTargetV1) -> ErasureReferenceV1 {
    reference(90)
}

const fn target(value: u8) -> ErasureRequiredTargetV1 {
    ErasureRequiredTargetV1 {
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: reference(value),
        key_role: ErasureKeyRoleV1::DataEncryption,
        key_digest: reference(value.saturating_add(1)),
        replica_set: reference(40),
        replica_id: reference(value.saturating_add(2)),
    }
}

fn acknowledgement(
    target: ErasureRequiredTargetV1,
    evidence: u8,
) -> Result<ErasureAcknowledgementV1, ErasureErrorV1> {
    let obligation = ErasureObligationV1::new(ErasureObligationInputV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target,
        owner: category_scoped_owner(target),
        command_identity: destruction_command_reference(reference(1), target),
    })?;
    Ok(ErasureAcknowledgementV1 {
        obligation: obligation.reference(),
        target,
        owner: category_scoped_owner(target),
        evidence: reference(evidence),
        outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
    })
}

const fn inventory(target: ErasureRequiredTargetV1) -> ErasureInventoryResultV1 {
    ErasureInventoryResultV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target,
        transition: ErasureArtifactTransitionV1 {
            from: ErasureReplayClaimV1::Exact,
            to: ErasureReplayClaimV1::StructuralOnly,
            reason: reference(50),
            owner: category_scoped_owner(target),
            acknowledgements: reference(52),
            provenance: reference(53),
        },
        retained_disclosure: reference(54),
    }
}

const fn transition() -> ErasureStateTransitionV1 {
    ErasureStateTransitionV1 {
        lifecycle: ErasureLifecycleV1::AccessFrozen,
        freeze_position: Some(10),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        acknowledged_targets: Vec::new(),
        replay_claim: ErasureReplayClaimV1::Exact,
        provenance: reference(9),
    }
}

struct CoordinatorHost<S> {
    store: Rc<RefCell<S>>,
    targets: Vec<ErasureRequiredTargetV1>,
}

impl<S: ErasurePersistencePortV1> ErasureStateResolverV1 for CoordinatorHost<S> {
    fn resolve_state(
        &self,
        digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureStateV1>, ErasureErrorV1> {
        self.store.borrow().resolve_state(digest)
    }
}

impl<S: ErasurePersistencePortV1> ErasurePersistencePortV1 for CoordinatorHost<S> {
    fn load_record(
        &self,
        request: ErasureReferenceV1,
        verifier: &dyn ErasureFreezeAuthorizationVerifierV1,
    ) -> Result<Option<ErasureCoordinatorRecordV1>, ErasureErrorV1> {
        self.store.borrow().load_record(request, verifier)
    }

    fn commit_record(
        &mut self,
        record: pos_core::VerifiedErasureCoordinatorRecordV1,
    ) -> Result<(), ErasureErrorV1> {
        self.store.borrow_mut().commit_record(record)
    }

    fn commit_records(
        &mut self,
        records: &[pos_core::VerifiedErasureCoordinatorRecordV1],
    ) -> Result<(), ErasureErrorV1> {
        self.store.borrow_mut().commit_records(records)
    }

    fn compare_and_swap_scope_extension(
        &mut self,
        request: ErasureReferenceV1,
        expected_ledger: ErasureReferenceV1,
        record: pos_core::VerifiedErasureCoordinatorRecordV1,
    ) -> Result<(), ErasureErrorV1> {
        self.store
            .borrow_mut()
            .compare_and_swap_scope_extension(request, expected_ledger, record)
    }

    fn compare_and_swap_administrative_resolution(
        &mut self,
        request: ErasureReferenceV1,
        expected_head: Option<ErasureReferenceV1>,
        record: pos_core::VerifiedErasureCoordinatorRecordV1,
    ) -> Result<(), ErasureErrorV1> {
        self.store
            .borrow_mut()
            .compare_and_swap_administrative_resolution(request, expected_head, record)
    }
}

impl<S: ErasurePersistencePortV1> ErasureFreezeAuthorizationVerifierV1 for CoordinatorHost<S> {
    fn validate_freeze_authorization(
        &self,
        admission: &ErasureFreezeAdmissionEvidenceV1,
        authorization: &ErasureFreezeAuthorizationEvidenceV1,
    ) -> Result<(), ErasureErrorV1> {
        authorization.verify_admission_body_binding(admission)
    }
}

impl<S: ErasurePersistencePortV1> ErasureCoordinatorPortV1 for CoordinatorHost<S> {
    fn authenticate(&self, _request: &ErasureRequestV1) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_authorization(
        &self,
        _request: ErasureReferenceV1,
        _provenance: ErasureReferenceV1,
        _decision: pos_core::erasure::ErasureAuthorizationDecisionV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_corrected_submission(
        &self,
        _request: &ErasureRequestV1,
        _correction: &ErasureCorrectionProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_atomic_freeze(
        &self,
        request: ErasureReferenceV1,
        requested: &ErasureStateTransitionV1,
    ) -> Result<ErasureAtomicFreezeResultV1, ErasureErrorV1> {
        let mut targets = self.targets.clone();
        targets.sort_unstable();
        let mut obligations = targets
            .iter()
            .map(|target| {
                ErasureObligationV1::new(ErasureObligationInputV1 {
                    category: ErasureInventoryCategoryV1::Artifact,
                    target: *target,
                    owner: category_scoped_owner(*target),
                    command_identity: destruction_command_reference(request, *target),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        obligations.sort_unstable_by_key(ErasureObligationV1::reference);
        let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
            request,
            obligations: obligations
                .iter()
                .map(ErasureObligationV1::reference)
                .collect(),
            policy: reference(6),
            trust: reference(71),
        })?;
        let scope = ErasureScopeCommitmentInputV1 {
            request,
            scope_members: vec![reference(3)],
            target_closure: target_closure_digest(&targets),
            lineage_rule: Some(reference(55)),
        };
        let freeze_position = requested.freeze_position.unwrap_or(10);
        let (freeze_admission_evidence, freeze_authorization_evidence) =
            freeze_evidence_fixture(FreezeEvidenceFixtureInput {
                request,
                scope_commitment: ErasureScopeCommitmentV1::new(scope.clone())?.reference(),
                obligation_set: &obligation_set,
                targets: &targets,
                obligations: &obligations,
                freeze_position,
                evidence: &requested.provenance.digest(),
            })?;
        let admission = ErasureAtomicFreezeAdmissionV1::new(ErasureAtomicFreezeAdmissionInputV1 {
            targets: targets.clone(),
            scope,
            obligations,
            obligation_set,
            freeze_position,
            freeze_admission_evidence,
            freeze_authorization_evidence,
        })?;
        Ok(ErasureAtomicFreezeResultV1::Admitted(Box::new(admission)))
    }

    fn dispatch_destruction(
        &self,
        _request: ErasureReferenceV1,
        _commands: &[pos_core::ErasureDestructionCommandV1],
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }
    fn admit_attempt(&self, _admission: &ErasureRetryAdmissionV1) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_acknowledgement(
        &self,
        _acknowledgement: &pos_core::ErasureAcknowledgementProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_receipt(&self, _input: &ErasureReceiptInputV1) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_scope_extension(
        &self,
        _extension: &ErasureScopeExtensionV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_administrative_resolution(
        &self,
        _resolution: &ErasureAdministrativeResolutionV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }
}

fn run_frozen_lifecycle<S: ErasurePersistencePortV1>(
    store: S,
) -> Result<Rc<RefCell<S>>, ErasureErrorV1> {
    let shared = Rc::new(RefCell::new(store));
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(
        CoordinatorHost {
            store: Rc::clone(&shared),
            targets: vec![target(10), target(20)],
        },
        reference(30),
    );
    coordinator.submit(request()?, reference(7))?;
    coordinator.authorize(reference(1), reference(8))?;
    coordinator.freeze_inventory(reference(1), transition())?;
    Ok(shared)
}

fn assert_recovery_requires_freeze_authorization<S: ErasurePersistencePortV1>(
    store: S,
) -> Result<(), ErasureErrorV1> {
    let shared = run_frozen_lifecycle(store)?;
    assert_eq!(
        shared
            .borrow()
            .load_record(reference(1), &RejectingFreezeAuthorizationVerifier),
        Err(ErasureErrorV1::Unauthorized)
    );
    Ok(())
}

fn scope_extension(
    record: &ErasureCoordinatorRecordV1,
    fork: ErasureReferenceV1,
) -> Result<ErasureScopeExtensionV1, ErasureErrorV1> {
    let scope = record
        .supporting_records()
        .scope_commitment()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let lineage_rule = scope.lineage_rule().ok_or(ErasureErrorV1::PolicyConflict)?;
    ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
        request: record.request().reference(),
        scope_commitment: scope.reference(),
        fork,
        lineage_rule,
        predecessor_extension: None,
        admission_provenance: reference(56),
    })
}

fn scope_extension_successor(
    record: &ErasureCoordinatorRecordV1,
    extension: ErasureScopeExtensionV1,
) -> Result<ErasureCoordinatorRecordV1, ErasureErrorV1> {
    let current_ledger = record
        .scope_extension_ledger()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let scope = record
        .supporting_records()
        .scope_commitment()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let current = record
        .supporting_records()
        .scope_extension_ledgers()
        .iter()
        .find(|ledger| ledger.reference() == current_ledger)
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let mut extensions = current.extensions().to_vec();
    extensions.push(extension.reference());
    let successor = ErasureScopeExtensionLedgerV1::new(ErasureScopeExtensionLedgerInputV1 {
        scope_commitment: scope.reference(),
        extensions,
        head: Some(extension.reference()),
    })?;
    let mut parts = record_parts(record);
    parts.scope_extension_ledger = Some(successor.reference());
    let mut scope_extensions = record.supporting_records().scope_extensions().to_vec();
    scope_extensions.push(extension);
    let mut ledgers = record
        .supporting_records()
        .scope_extension_ledgers()
        .to_vec();
    ledgers.push(successor);
    parts.supporting_records = supporting_records_with(
        record.supporting_records(),
        scope_extensions,
        ledgers,
        record.supporting_records().receipts().to_vec(),
        record
            .supporting_records()
            .administrative_resolutions()
            .to_vec(),
    )?;
    ErasureCoordinatorRecordV1::from_parts(parts, reference(30))
}

fn administrative_resolution(
    record: &ErasureCoordinatorRecordV1,
    affected_digest: ErasureReferenceV1,
) -> Result<ErasureAdministrativeResolutionV1, ErasureErrorV1> {
    let scope = record
        .supporting_records()
        .scope_commitment()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let obligation_set = record
        .supporting_records()
        .obligation_set()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    ErasureAdministrativeResolutionV1::new(ErasureAdministrativeResolutionInputV1 {
        request: record.request().reference(),
        affected_digests: vec![affected_digest],
        action: ErasureAdministrativeResolutionActionV1::RecoverExactEvidence,
        scope_commitment: scope.reference(),
        policy: record.request().policy(),
        trust: obligation_set.trust(),
        principal: reference(23),
        authorization_provenance: reference(24),
        reason: reference(25),
        issue_position: 11,
        predecessor_resolution: None,
    })
}

fn administrative_resolution_successor(
    record: &ErasureCoordinatorRecordV1,
    resolution: ErasureAdministrativeResolutionV1,
) -> Result<ErasureCoordinatorRecordV1, ErasureErrorV1> {
    let mut parts = record_parts(record);
    parts.administrative_resolution_head = Some(resolution.reference());
    let mut resolutions = record
        .supporting_records()
        .administrative_resolutions()
        .to_vec();
    resolutions.push(resolution);
    parts.supporting_records = supporting_records_with(
        record.supporting_records(),
        record.supporting_records().scope_extensions().to_vec(),
        record
            .supporting_records()
            .scope_extension_ledgers()
            .to_vec(),
        record.supporting_records().receipts().to_vec(),
        resolutions,
    )?;
    ErasureCoordinatorRecordV1::from_parts(parts, reference(30))
}

fn assert_scope_extension_cas<S: ErasurePersistencePortV1>(store: S) -> Result<(), ErasureErrorV1> {
    let shared = run_frozen_lifecycle(store)?;
    let record = shared
        .borrow()
        .load_record(reference(1), &TEST_FREEZE_AUTHORIZATION_VERIFIER)?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let expected_ledger = record
        .scope_extension_ledger()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let winner = scope_extension_successor(&record, scope_extension(&record, reference(60))?)?;
    let competing = scope_extension_successor(&record, scope_extension(&record, reference(61))?)?;

    shared.borrow_mut().compare_and_swap_scope_extension(
        reference(1),
        expected_ledger,
        verified_record(winner.clone())?,
    )?;
    shared.borrow_mut().compare_and_swap_scope_extension(
        reference(1),
        expected_ledger,
        verified_record(winner.clone())?,
    )?;
    assert_eq!(
        shared.borrow_mut().compare_and_swap_scope_extension(
            reference(1),
            expected_ledger,
            verified_record(competing)?,
        ),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        shared
            .borrow()
            .load_record(reference(1), &TEST_FREEZE_AUTHORIZATION_VERIFIER)?,
        Some(winner)
    );
    Ok(())
}

fn assert_administrative_resolution_cas<S: ErasurePersistencePortV1>(
    store: S,
) -> Result<(), ErasureErrorV1> {
    let shared = run_frozen_lifecycle(store)?;
    let record = shared
        .borrow()
        .load_record(reference(1), &TEST_FREEZE_AUTHORIZATION_VERIFIER)?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let winner = administrative_resolution_successor(
        &record,
        administrative_resolution(&record, reference(62))?,
    )?;
    let competing = administrative_resolution_successor(
        &record,
        administrative_resolution(&record, reference(63))?,
    )?;

    shared
        .borrow_mut()
        .compare_and_swap_administrative_resolution(
            reference(1),
            None,
            verified_record(winner.clone())?,
        )?;
    shared
        .borrow_mut()
        .compare_and_swap_administrative_resolution(
            reference(1),
            None,
            verified_record(winner.clone())?,
        )?;
    assert_eq!(
        shared
            .borrow_mut()
            .compare_and_swap_administrative_resolution(
                reference(1),
                None,
                verified_record(competing)?,
            ),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        shared
            .borrow()
            .load_record(reference(1), &TEST_FREEZE_AUTHORIZATION_VERIFIER)?,
        Some(winner)
    );
    Ok(())
}

fn run_full_lifecycle<S: ErasurePersistencePortV1>(
    store: S,
) -> Result<(Rc<RefCell<S>>, ErasureReceiptV1), ErasureErrorV1> {
    let shared = Rc::new(RefCell::new(store));
    let first = target(10);
    let second = target(20);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(
        CoordinatorHost {
            store: Rc::clone(&shared),
            targets: vec![first, second],
        },
        reference(30),
    );
    let request = request()?;
    coordinator.submit(request, reference(7))?;
    coordinator.authorize(reference(1), reference(8))?;
    coordinator.freeze_inventory(reference(1), transition())?;
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    let second_ack = acknowledgement(second, 61)?;
    let first_ack = acknowledgement(first, 60)?;
    coordinator.acknowledge(reference(1), second_ack)?;
    coordinator.acknowledge(reference(1), first_ack)?;
    let receipt = coordinator.finalize(reference(1), full_receipt_input(first, second)?)?;
    Ok((shared, receipt))
}

fn assert_unrelated_event_store_remains_available<S>(
    store: S,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: ErasurePersistencePortV1 + EventStore,
{
    let (shared, _) = run_full_lifecycle(store)?;
    let timeline = shared.borrow_mut().create_timeline("unrelated")?;
    let timeline_id = timeline.id();
    let draft = EventDraft::new(
        EntityId::new(),
        Kind::new("test.event"),
        CanonicalBytes::from_static(b"payload"),
    );

    let appended = shared.borrow_mut().append(timeline_id, &[draft])?;
    assert_eq!(appended.len(), 1);
    assert_eq!(
        shared
            .borrow()
            .read(timeline_id, pos_core::SeqRange::all())?
            .len(),
        1
    );
    assert_eq!(
        pos_store::export_timeline(&*shared.borrow(), timeline_id)?
            .events
            .len(),
        1
    );

    // Administrative rollback/deletion remains distinct from subject erasure.
    shared.borrow_mut().delete_timeline(timeline_id)?;
    Ok(())
}

fn full_receipt_input(
    first: ErasureRequiredTargetV1,
    second: ErasureRequiredTargetV1,
) -> Result<ErasureReceiptInputV1, ErasureErrorV1> {
    Ok(ErasureReceiptInputV1 {
        request: reference(99),
        terminal_state: reference(98),
        coordinator: reference(97),
        lifecycle: ErasureLifecycleV1::Complete,
        freeze_position: 0,
        acknowledgements: vec![acknowledgement(first, 60)?, acknowledgement(second, 61)?],
        frozen_targets: vec![second, first],
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        inventories: ErasureReceiptInventoriesV1 {
            // Keep the caller input intentionally noncanonical. The state
            // machine must normalize it before persisting and comparing a
            // retry after SQLite rehydration.
            artifacts: vec![inventory(second), inventory(first)],
            keys: Vec::new(),
            replicas: Vec::new(),
            backups: Vec::new(),
        },
        replay_claim: ErasureReplayClaimV1::Exact,
        policy: reference(70),
        trust: reference(71),
        provenance: reference(72),
        issue_position: 11,
        signature: reference(73),
        receipt_digest: reference(74),
    })
}

fn run_partial_lifecycle<S: ErasurePersistencePortV1>(
    store: S,
) -> Result<(Rc<RefCell<S>>, ErasureReceiptV1), ErasureErrorV1> {
    let shared = Rc::new(RefCell::new(store));
    let target = target(10);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(
        CoordinatorHost {
            store: Rc::clone(&shared),
            targets: vec![target],
        },
        reference(30),
    );
    coordinator.submit(request()?, reference(7))?;
    coordinator.authorize(reference(1), reference(8))?;
    coordinator.freeze_inventory(reference(1), transition())?;
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    let receipt = coordinator.finalize(
        reference(1),
        ErasureReceiptInputV1 {
            request: reference(99),
            terminal_state: reference(98),
            coordinator: reference(97),
            lifecycle: ErasureLifecycleV1::PartialFailure,
            freeze_position: 0,
            acknowledgements: Vec::new(),
            frozen_targets: vec![target],
            pending_owners: vec![target.replica_id],
            failed_owners: Vec::new(),
            inventories: ErasureReceiptInventoriesV1 {
                artifacts: vec![inventory(target)],
                keys: Vec::new(),
                replicas: Vec::new(),
                backups: Vec::new(),
            },
            replay_claim: ErasureReplayClaimV1::Exact,
            policy: reference(70),
            trust: reference(71),
            provenance: reference(72),
            issue_position: 20,
            signature: reference(73),
            receipt_digest: reference(74),
        },
    )?;
    Ok((shared, receipt))
}

fn assert_public_contract<S: ErasurePersistencePortV1>(
    store: &mut S,
) -> Result<(), ErasureErrorV1> {
    let record = submitted_record()?;
    let request = record.request().reference();
    let state_digest = record.state().state_digest();
    store.commit_records(&[])?;
    assert_eq!(
        store.load_record(request, &TEST_FREEZE_AUTHORIZATION_VERIFIER)?,
        None
    );
    assert_eq!(store.resolve_state(state_digest)?, None);

    store.commit_record(verified_record(record.clone())?)?;
    assert_eq!(
        store.load_record(request, &TEST_FREEZE_AUTHORIZATION_VERIFIER)?,
        Some(record.clone())
    );
    assert_eq!(
        store.resolve_state(state_digest)?,
        Some(record.state().clone())
    );

    // Exact retries are idempotent and do not alter the loaded record.
    store.commit_record(verified_record(record.clone())?)?;
    assert_eq!(
        store.load_record(request, &TEST_FREEZE_AUTHORIZATION_VERIFIER)?,
        Some(record)
    );
    Ok(())
}

fn assert_missing_cas_record<S: ErasurePersistencePortV1>(
    mut store: S,
) -> Result<(), ErasureErrorV1> {
    let record = submitted_record()?;
    let request = record.request().reference();
    assert_eq!(
        store.compare_and_swap_scope_extension(
            request,
            reference(90),
            verified_record(record.clone())?,
        ),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        store.compare_and_swap_administrative_resolution(request, None, verified_record(record)?,),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn memory_erasure_persistence_exposes_the_public_contract() -> Result<(), ErasureErrorV1> {
    assert_public_contract(&mut MemoryStore::new())
}

#[test]
fn memory_erasure_cas_rejects_a_missing_record() -> Result<(), ErasureErrorV1> {
    assert_missing_cas_record(MemoryStore::new())
}

#[test]
fn memory_erasure_recovery_requires_freeze_authorization() -> Result<(), ErasureErrorV1> {
    assert_recovery_requires_freeze_authorization(MemoryStore::new())
}

#[test]
fn memory_erasure_persistence_recovers_supporting_records() -> Result<(), ErasureErrorV1> {
    let store = run_frozen_lifecycle(MemoryStore::new())?;
    let initial = store
        .borrow()
        .load_record(reference(1), &TEST_FREEZE_AUTHORIZATION_VERIFIER)?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let expected = administrative_resolution_successor(
        &initial,
        administrative_resolution(&initial, reference(20))?,
    )?;
    let expected_head = expected
        .administrative_resolution_head()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    store
        .borrow_mut()
        .compare_and_swap_administrative_resolution(
            reference(1),
            None,
            verified_record(expected.clone())?,
        )?;
    let request = expected.request().reference();
    let expected_supporting_records = expected.supporting_records().clone();
    let loaded = store
        .borrow()
        .load_record(request, &TEST_FREEZE_AUTHORIZATION_VERIFIER)?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    assert_eq!(loaded.supporting_records(), &expected_supporting_records);
    assert_eq!(loaded.administrative_resolution_head(), Some(expected_head));
    assert_eq!(
        store.borrow_mut().commit_record(verified_record(initial)?),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn memory_erasure_persistence_validates_correction_predecessors() -> Result<(), ErasureErrorV1> {
    assert_correction_chain(MemoryStore::new())
}

#[test]
fn memory_erasure_persistence_compares_scope_extension_cas() -> Result<(), ErasureErrorV1> {
    assert_scope_extension_cas(MemoryStore::new())
}

#[test]
fn memory_erasure_persistence_compares_administrative_resolution_cas() -> Result<(), ErasureErrorV1>
{
    assert_administrative_resolution_cas(MemoryStore::new())
}

#[test]
fn memory_erasure_persistence_commits_canonical_acknowledgement_and_receipt_state(
) -> Result<(), ErasureErrorV1> {
    let (store, receipt) = run_full_lifecycle(MemoryStore::new())?;
    let record = store
        .borrow()
        .load_record(reference(1), &TEST_FREEZE_AUTHORIZATION_VERIFIER)?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    assert_eq!(record.state().lifecycle(), ErasureLifecycleV1::Complete);
    assert_eq!(record.receipt(), Some(&receipt));
    assert_eq!(record.acknowledgements().len(), 2);
    assert_eq!(receipt.acknowledgements().len(), 2);
    let mut expected_acknowledgements = vec![
        acknowledgement(target(10), 60)?,
        acknowledgement(target(20), 61)?,
    ];
    expected_acknowledgements.sort_unstable();
    assert_eq!(
        receipt.acknowledgements(),
        expected_acknowledgements.as_slice()
    );
    Ok(())
}

#[test]
fn memory_keeps_unrelated_event_store_available_after_erasure(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_unrelated_event_store_remains_available(MemoryStore::new())
}

#[test]
fn memory_erasure_persistence_commits_intermediate_and_partial_receipt_atomically(
) -> Result<(), ErasureErrorV1> {
    let (store, receipt) = run_partial_lifecycle(MemoryStore::new())?;
    let record = store
        .borrow()
        .load_record(reference(1), &TEST_FREEZE_AUTHORIZATION_VERIFIER)?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    assert_eq!(
        record.state().lifecycle(),
        ErasureLifecycleV1::PartialFailure
    );
    assert_eq!(record.receipt(), Some(&receipt));
    assert_eq!(record.state().pending_owners(), &[reference(90)]);
    Ok(())
}

#[test]
fn memory_erasure_persistence_rejects_orphans_and_keeps_batches_atomic(
) -> Result<(), ErasureErrorV1> {
    let (completed, receipt) = run_full_lifecycle(MemoryStore::new())?;
    let terminal = completed
        .borrow()
        .load_record(reference(1), &TEST_FREEZE_AUTHORIZATION_VERIFIER)?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    drop(completed);
    let mut store = MemoryStore::new();
    assert_eq!(
        store.commit_record(verified_record(terminal.clone())?),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        store.load_record(reference(1), &TEST_FREEZE_AUTHORIZATION_VERIFIER)?,
        None
    );

    let root = verified_record(submitted_record()?)?;
    let terminal = verified_record(terminal)?;
    assert_eq!(
        store.commit_records(&[root, terminal]),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        store.load_record(reference(1), &TEST_FREEZE_AUTHORIZATION_VERIFIER)?,
        None
    );
    assert_eq!(receipt.lifecycle(), ErasureLifecycleV1::Complete);
    Ok(())
}

#[test]
fn memory_erasure_persistence_rejects_a_conflicting_terminal_retry() -> Result<(), ErasureErrorV1> {
    let (shared, _) = run_full_lifecycle(MemoryStore::new())?;
    let record = shared
        .borrow()
        .load_record(reference(1), &TEST_FREEZE_AUTHORIZATION_VERIFIER)?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let mut parts = record_parts(&record);
    let input = parts
        .receipt_input
        .as_mut()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    input.signature = reference(99);
    let receipt = ErasureReceiptV1::new(input.clone())?;
    parts.receipt = Some(receipt.clone());
    parts.supporting_records = with_replacement_receipt(&parts.supporting_records, receipt)?;
    let conflicting = ErasureCoordinatorRecordV1::from_parts(parts, reference(30))?;
    assert_eq!(
        shared
            .borrow_mut()
            .commit_record(verified_record(conflicting)?),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_erasure_persistence_rejects_a_conflicting_terminal_retry() -> Result<(), ErasureErrorV1> {
    let store = SqliteStore::open_in_memory().map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
    let (shared, _) = run_full_lifecycle(store)?;
    let record = shared
        .borrow()
        .load_record(reference(1), &TEST_FREEZE_AUTHORIZATION_VERIFIER)?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let mut parts = record_parts(&record);
    let input = parts
        .receipt_input
        .as_mut()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    input.signature = reference(99);
    let receipt = ErasureReceiptV1::new(input.clone())?;
    parts.receipt = Some(receipt.clone());
    parts.supporting_records = with_replacement_receipt(&parts.supporting_records, receipt)?;
    let conflicting = ErasureCoordinatorRecordV1::from_parts(parts, reference(30))?;
    assert_eq!(
        shared
            .borrow_mut()
            .commit_record(verified_record(conflicting)?),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn memory_erasure_persistence_rejects_noncanonical_acknowledgement_and_provenance_shapes(
) -> Result<(), ErasureErrorV1> {
    let (store, _) = run_full_lifecycle(MemoryStore::new())?;
    let record = store
        .borrow()
        .load_record(reference(1), &TEST_FREEZE_AUTHORIZATION_VERIFIER)?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;

    let mut unsorted = record_parts(&record);
    unsorted.acknowledgements.reverse();
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(unsorted, reference(30)),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let mut missing_authorization = record_parts(&record);
    missing_authorization.authorize_provenance = None;
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(missing_authorization, reference(30)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_erasure_persistence_matches_memory_contract() -> Result<(), ErasureErrorV1> {
    let mut store =
        SqliteStore::open_in_memory().map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
    assert_public_contract(&mut store)
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_erasure_cas_rejects_a_missing_record() -> Result<(), ErasureErrorV1> {
    let store = SqliteStore::open_in_memory().map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
    assert_missing_cas_record(store)
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_erasure_recovery_requires_freeze_authorization() -> Result<(), ErasureErrorV1> {
    let store = SqliteStore::open_in_memory().map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
    assert_recovery_requires_freeze_authorization(store)
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_erasure_persistence_validates_correction_predecessors() -> Result<(), ErasureErrorV1> {
    let store = SqliteStore::open_in_memory().map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
    assert_correction_chain(store)
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_erasure_persistence_compares_scope_extension_cas() -> Result<(), ErasureErrorV1> {
    let store = SqliteStore::open_in_memory().map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
    assert_scope_extension_cas(store)
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_erasure_persistence_compares_administrative_resolution_cas() -> Result<(), ErasureErrorV1>
{
    let store = SqliteStore::open_in_memory().map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
    assert_administrative_resolution_cas(store)
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_erasure_persistence_commits_canonical_acknowledgement_and_receipt_state(
) -> Result<(), ErasureErrorV1> {
    let store = SqliteStore::open_in_memory().map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
    let (store, receipt) = run_full_lifecycle(store)?;
    let record = store
        .borrow()
        .load_record(reference(1), &TEST_FREEZE_AUTHORIZATION_VERIFIER)?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    assert_eq!(record.state().lifecycle(), ErasureLifecycleV1::Complete);
    assert_eq!(record.receipt(), Some(&receipt));
    let mut expected_acknowledgements = vec![
        acknowledgement(target(10), 60)?,
        acknowledgement(target(20), 61)?,
    ];
    expected_acknowledgements.sort_unstable();
    assert_eq!(
        receipt.acknowledgements(),
        expected_acknowledgements.as_slice()
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_erasure_persistence_commits_intermediate_and_partial_receipt_atomically(
) -> Result<(), ErasureErrorV1> {
    let store = SqliteStore::open_in_memory().map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
    let (store, receipt) = run_partial_lifecycle(store)?;
    let record = store
        .borrow()
        .load_record(reference(1), &TEST_FREEZE_AUTHORIZATION_VERIFIER)?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    assert_eq!(
        record.state().lifecycle(),
        ErasureLifecycleV1::PartialFailure
    );
    assert_eq!(record.receipt(), Some(&receipt));
    assert_eq!(record.state().pending_owners(), &[reference(90)]);
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_erasure_persistence_rejects_orphans_and_keeps_batches_atomic(
) -> Result<(), ErasureErrorV1> {
    let (completed, terminal) = run_full_lifecycle(
        SqliteStore::open_in_memory().map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?,
    )?;
    let terminal_record = completed
        .borrow()
        .load_record(reference(1), &TEST_FREEZE_AUTHORIZATION_VERIFIER)?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    drop(completed);
    let mut store =
        SqliteStore::open_in_memory().map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
    assert_eq!(
        store.commit_record(verified_record(terminal_record.clone())?),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        store.load_record(reference(1), &TEST_FREEZE_AUTHORIZATION_VERIFIER)?,
        None
    );

    let root = verified_record(submitted_record()?)?;
    let terminal_record = verified_record(terminal_record)?;
    assert_eq!(
        store.commit_records(&[root, terminal_record]),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        store.load_record(reference(1), &TEST_FREEZE_AUTHORIZATION_VERIFIER)?,
        None
    );
    assert_eq!(terminal.lifecycle(), ErasureLifecycleV1::Complete);
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_erasure_persistence_survives_reopen() -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or("temporary database path is not UTF-8")?;
    let record = submitted_record()?;
    let request = record.request().reference();

    let mut store = SqliteStore::open(path)?;
    store.commit_record(verified_record(record.clone())?)?;
    drop(store);

    let reopened = SqliteStore::open(path)?;
    assert_eq!(
        reopened.load_record(request, &TEST_FREEZE_AUTHORIZATION_VERIFIER)?,
        Some(record)
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_erasure_persistence_recovers_supporting_records_after_reopen(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or("temporary database path is not UTF-8")?;
    let store = run_frozen_lifecycle(SqliteStore::open(path)?)?;
    let initial = store
        .borrow()
        .load_record(reference(1), &TEST_FREEZE_AUTHORIZATION_VERIFIER)?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let record = administrative_resolution_successor(
        &initial,
        administrative_resolution(&initial, reference(20))?,
    )?;
    let request = record.request().reference();
    let expected = record.supporting_records().clone();
    store
        .borrow_mut()
        .compare_and_swap_administrative_resolution(reference(1), None, verified_record(record)?)?;
    drop(store);

    let reopened = SqliteStore::open(path)?;
    let loaded = reopened
        .load_record(request, &TEST_FREEZE_AUTHORIZATION_VERIFIER)?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    assert_eq!(loaded.supporting_records(), &expected);
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_erasure_lifecycle_and_receipt_survive_reopen() -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or("temporary database path is not UTF-8")?;
    let (store, receipt) = run_full_lifecycle(SqliteStore::open(path)?)?;
    drop(store);

    let reopened = SqliteStore::open(path)?;
    let record = reopened
        .load_record(reference(1), &TEST_FREEZE_AUTHORIZATION_VERIFIER)?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    assert_eq!(record.receipt(), Some(&receipt));
    assert_eq!(record.state().lifecycle(), ErasureLifecycleV1::Complete);
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_erasure_terminal_retry_survives_reopen_with_noncanonical_inventory_order(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or("temporary database path is not UTF-8")?;
    let (store, receipt) = run_full_lifecycle(SqliteStore::open(path)?)?;
    drop(store);

    let reopened = Rc::new(RefCell::new(SqliteStore::open(path)?));
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(
        CoordinatorHost {
            store: Rc::clone(&reopened),
            targets: vec![target(10), target(20)],
        },
        reference(30),
    );

    assert_eq!(
        coordinator.finalize(reference(1), full_receipt_input(target(10), target(20))?,)?,
        receipt
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_keeps_unrelated_event_store_available_after_erasure(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_unrelated_event_store_remains_available(SqliteStore::open_in_memory()?)
}
