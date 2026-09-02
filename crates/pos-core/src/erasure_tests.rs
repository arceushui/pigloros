//! Crate-local invariant tests supplement the public integration suites.
//!
//! Tests in this module may use internal seams to construct corrupted states
//! that public constructors intentionally reject. They verify fail-closed
//! validation branches; externally observable lifecycle behavior remains
//! covered through `ErasureCoordinator` in `tests/`.

#[path = "../tests/support/erasure.rs"]
pub mod freeze_fixture_support;

use freeze_fixture_support::{freeze_evidence_fixture, FreezeEvidenceFixtureInput};

fn test_uint(value: u64) -> Value {
    Value::Integer(value.into())
}
fn test_digest(reference: ErasureReferenceV1) -> Value {
    Value::Bytes(reference.digest().to_vec())
}
fn test_text(value: &str) -> Value {
    Value::Text(value.to_owned())
}
use super::*;
use crate::erasure::codec::{
    array, cbor_argument, cbor_argument_bytes, cbor_item_end, cbor_shape_is_bounded,
    has_duplicate_by_inventory_target,
};
use ciborium::value::Value;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

#[derive(Clone)]
pub(super) struct TestCoordinatorPort {
    accepted: bool,
    authorization_admitted: bool,
    authorization_decisions: Rc<
        RefCell<
            Vec<(
                ErasureReferenceV1,
                ErasureReferenceV1,
                ErasureAuthorizationDecisionV1,
            )>,
        >,
    >,
    acknowledgement_admitted: bool,
    acknowledgement_admissions: Rc<RefCell<Vec<ErasureAcknowledgementProvenanceV1>>>,
    attempt_admissions: Rc<RefCell<Vec<ErasureRetryAdmissionV1>>>,
    freeze_error: Option<ErasureErrorV1>,
    frozen_targets_error: Option<ErasureErrorV1>,
    admitted_freeze_provenance: Option<ErasureReferenceV1>,
    admitted_freeze_position: Option<u64>,
    admitted_freeze_closure: Option<ErasureReferenceV1>,
    freeze_reservation: Rc<RefCell<Option<ErasureAtomicFreezeAdmissionV1>>>,
    dispatch_error: Option<ErasureErrorV1>,
    receipt_error: Option<ErasureErrorV1>,
    receipt_inputs: Rc<RefCell<Vec<ErasureReceiptInputV1>>>,
    load_error: Option<ErasureErrorV1>,
    commit_error: Option<ErasureErrorV1>,
    commit_error_on_call: Option<usize>,
    commit_calls: Rc<RefCell<usize>>,
    targets: Vec<ErasureRequiredTargetV1>,
    records: Rc<RefCell<Vec<ErasureCoordinatorRecordV1>>>,
    state_history: Rc<RefCell<Vec<ErasureStateV1>>>,
}
struct TestResolver {
    states: Vec<ErasureStateV1>,
    unavailable: bool,
}
struct ReplyResolver {
    terminal: ErasureStateV1,
    previous: ErasureStateV1,
}
struct FailingPredecessorResolver {
    terminal: ErasureStateV1,
}
impl ErasureStateResolverV1 for TestResolver {
    fn resolve_state(
        &self,
        digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureStateV1>, ErasureErrorV1> {
        if self.unavailable {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        Ok(self
            .states
            .iter()
            .find(|state| state.state_digest() == digest)
            .cloned())
    }
}
impl ErasureStateResolverV1 for ReplyResolver {
    fn resolve_state(
        &self,
        digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureStateV1>, ErasureErrorV1> {
        if digest == self.terminal.state_digest() {
            Ok(Some(self.terminal.clone()))
        } else {
            Ok(Some(self.previous.clone()))
        }
    }
}
impl ErasureStateResolverV1 for FailingPredecessorResolver {
    fn resolve_state(
        &self,
        digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureStateV1>, ErasureErrorV1> {
        if digest == self.terminal.state_digest() {
            Ok(Some(self.terminal.clone()))
        } else {
            Err(ErasureErrorV1::ProvenanceMissing)
        }
    }
}
impl ErasureFreezeAuthorizationVerifierV1 for TestCoordinatorPort {
    fn validate_freeze_authorization(
        &self,
        admission: &ErasureFreezeAdmissionEvidenceV1,
        authorization: &ErasureFreezeAuthorizationEvidenceV1,
    ) -> Result<(), ErasureErrorV1> {
        authorization.verify_admission_body_binding(admission)
    }
}

impl ErasureCoordinatorPortV1 for TestCoordinatorPort {
    fn authenticate(&self, _request: &ErasureRequestV1) -> Result<(), ErasureErrorV1> {
        if self.accepted {
            Ok(())
        } else {
            Err(ErasureErrorV1::Unauthorized)
        }
    }
    fn admit_authorization(
        &self,
        request: ErasureReferenceV1,
        provenance: ErasureReferenceV1,
        decision: ErasureAuthorizationDecisionV1,
    ) -> Result<(), ErasureErrorV1> {
        self.authorization_decisions
            .borrow_mut()
            .push((request, provenance, decision));
        if self.authorization_admitted {
            Ok(())
        } else {
            Err(ErasureErrorV1::Unauthorized)
        }
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
        if let Some(error) = self.freeze_error {
            return Err(error);
        }
        if let Some(admission) = self.freeze_reservation.borrow().as_ref().cloned() {
            return Ok(ErasureAtomicFreezeResultV1::Admitted(Box::new(admission)));
        }
        if self.frozen_targets_error.is_some() {
            return Err(self
                .frozen_targets_error
                .unwrap_or(ErasureErrorV1::ScopeInvalid));
        }
        let mut targets = self.targets.clone();
        targets.sort_unstable();
        let mut obligations = targets
            .iter()
            .map(|target| {
                ErasureObligationV1::new(ErasureObligationInputV1 {
                    category: ErasureInventoryCategoryV1::Artifact,
                    target: *target,
                    owner: target.replica_id,
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
            policy: reference(5),
            trust: reference(3),
        })?;
        let scope = ErasureScopeCommitmentInputV1 {
            request,
            scope_members: vec![reference(7), reference(8)],
            target_closure: self
                .admitted_freeze_closure
                .unwrap_or_else(|| target_closure_digest(&targets)),
            lineage_rule: None,
        };
        let scope_reference = ErasureScopeCommitmentV1::new(scope.clone())?.reference();
        let freeze_position = self
            .admitted_freeze_position
            .unwrap_or_else(|| requested.freeze_position.unwrap_or(10));
        let (freeze_admission_evidence, freeze_authorization_evidence) =
            freeze_evidence_fixture(FreezeEvidenceFixtureInput {
                request,
                scope_commitment: scope_reference,
                obligation_set: &obligation_set,
                targets: &targets,
                obligations: &obligations,
                freeze_position,
                evidence: &self
                    .admitted_freeze_provenance
                    .unwrap_or(requested.provenance)
                    .digest(),
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
        self.freeze_reservation
            .borrow_mut()
            .replace(admission.clone());
        Ok(ErasureAtomicFreezeResultV1::Admitted(Box::new(admission)))
    }
    fn dispatch_destruction(
        &self,
        _request: ErasureReferenceV1,
        _commands: &[ErasureDestructionCommandV1],
    ) -> Result<(), ErasureErrorV1> {
        if let Some(error) = self.dispatch_error {
            return Err(error);
        }
        Ok(())
    }
    fn admit_attempt(&self, admission: &ErasureRetryAdmissionV1) -> Result<(), ErasureErrorV1> {
        self.attempt_admissions.borrow_mut().push(admission.clone());
        Ok(())
    }
    fn admit_acknowledgement(
        &self,
        acknowledgement: &ErasureAcknowledgementProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        self.acknowledgement_admissions
            .borrow_mut()
            .push(*acknowledgement);
        if self.acknowledgement_admitted {
            Ok(())
        } else {
            Err(ErasureErrorV1::Unauthorized)
        }
    }
    fn admit_receipt(&self, input: &ErasureReceiptInputV1) -> Result<(), ErasureErrorV1> {
        self.receipt_inputs.borrow_mut().push(input.clone());
        if let Some(error) = self.receipt_error {
            return Err(error);
        }
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

impl ErasurePersistencePortV1 for TestCoordinatorPort {
    fn load_record(
        &self,
        request: ErasureReferenceV1,
        verifier: &dyn ErasureFreezeAuthorizationVerifierV1,
    ) -> Result<Option<ErasureCoordinatorRecordV1>, ErasureErrorV1> {
        if let Some(error) = self.load_error {
            return Err(error);
        }
        self.records
            .borrow()
            .iter()
            .find(|record| record.request.reference() == request)
            .cloned()
            .map(|record| {
                record
                    .state()
                    .verify_predecessor_chain(self)
                    .and_then(|()| record.verify_recovered_freeze_authorization(verifier))
                    .map(|()| record)
            })
            .transpose()
    }

    fn commit_records(
        &mut self,
        records: &[VerifiedErasureCoordinatorRecordV1],
    ) -> Result<(), ErasureErrorV1> {
        let mut staged_records = self.records.borrow().clone();
        let mut staged_states = self.state_history.borrow().clone();
        for verified in records {
            let record = verified.record();
            *self.commit_calls.borrow_mut() += 1;
            if self
                .commit_error_on_call
                .is_some_and(|call| call == *self.commit_calls.borrow())
            {
                return Err(ErasureErrorV1::ReceiptCommitFailed);
            }
            if let Some(error) = self.commit_error {
                return Err(error);
            }
            if let Some(existing) = staged_records
                .iter()
                .find(|existing| existing.request.reference() == record.request.reference())
            {
                if existing != record {
                    existing.validate_replacement(record)?;
                }
            } else if record.state().previous_state().is_some() {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
            if let Some(existing) = staged_records
                .iter_mut()
                .find(|existing| existing.request.reference() == record.request.reference())
            {
                *existing = record.clone();
            } else {
                staged_records.push(record.clone());
            }
            staged_states.push(record.state().clone());
        }
        self.records.replace(staged_records);
        self.state_history.replace(staged_states);
        Ok(())
    }

    fn compare_and_swap_scope_extension(
        &mut self,
        request: ErasureReferenceV1,
        expected_ledger: ErasureReferenceV1,
        record: VerifiedErasureCoordinatorRecordV1,
    ) -> Result<(), ErasureErrorV1> {
        let current = self.load_record(request, self)?;
        if current.and_then(|saved| saved.scope_extension_ledger()) != Some(expected_ledger) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        self.commit_record(record)
    }

    fn compare_and_swap_administrative_resolution(
        &mut self,
        request: ErasureReferenceV1,
        expected_head: Option<ErasureReferenceV1>,
        record: VerifiedErasureCoordinatorRecordV1,
    ) -> Result<(), ErasureErrorV1> {
        let current = self.load_record(request, self)?;
        if current.and_then(|saved| saved.administrative_resolution_head()) != expected_head {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        self.commit_record(record)
    }
}

impl ErasureStateResolverV1 for TestCoordinatorPort {
    fn resolve_state(
        &self,
        digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureStateV1>, ErasureErrorV1> {
        Ok(self
            .state_history
            .borrow()
            .iter()
            .find(|state| state.state_digest() == digest)
            .cloned())
    }
}

pub(super) fn test_port(
    accepted: bool,
    targets: Vec<ErasureRequiredTargetV1>,
) -> TestCoordinatorPort {
    TestCoordinatorPort {
        accepted,
        authorization_admitted: true,
        authorization_decisions: Rc::new(RefCell::new(Vec::new())),
        acknowledgement_admitted: true,
        acknowledgement_admissions: Rc::new(RefCell::new(Vec::new())),
        attempt_admissions: Rc::new(RefCell::new(Vec::new())),
        freeze_error: None,
        frozen_targets_error: None,
        admitted_freeze_provenance: None,
        admitted_freeze_position: None,
        admitted_freeze_closure: None,
        freeze_reservation: Rc::new(RefCell::new(None)),
        dispatch_error: None,
        receipt_error: None,
        receipt_inputs: Rc::new(RefCell::new(Vec::new())),
        load_error: None,
        commit_error: None,
        commit_error_on_call: None,
        commit_calls: Rc::new(RefCell::new(0)),
        targets,
        records: Rc::new(RefCell::new(Vec::new())),
        state_history: Rc::new(RefCell::new(Vec::new())),
    }
}
fn reference(value: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([value; 32])
}

fn freeze_evidence_with_matrix(
    request: ErasureReferenceV1,
    scope_commitment: ErasureReferenceV1,
    obligation_set: &ErasureObligationSetV1,
    applicability_matrix: Vec<ErasureFreezeApplicabilityRowV1>,
    freeze_position: u64,
    proof: ErasureReferenceV1,
) -> Result<
    (
        ErasureFreezeAdmissionEvidenceV1,
        ErasureFreezeAuthorizationEvidenceV1,
    ),
    ErasureErrorV1,
> {
    let provisional =
        ErasureFreezeAdmissionEvidenceV1::new(ErasureFreezeAdmissionEvidenceInputV1 {
            request,
            scope_commitment,
            obligation_set: obligation_set.reference(),
            applicability_matrix,
            freeze_position,
            policy: obligation_set.policy(),
            trust: obligation_set.trust(),
            authorization_provenance: reference_zero(),
        })?;
    let authorization =
        ErasureFreezeAuthorizationEvidenceV1::new(ErasureFreezeAuthorizationEvidenceInputV1 {
            admission_body_digest: provisional.authorization_body_digest()?,
            policy: obligation_set.policy(),
            trust: obligation_set.trust(),
            evidence: proof.digest().to_vec(),
        })?;
    let admission = ErasureFreezeAdmissionEvidenceV1::new(ErasureFreezeAdmissionEvidenceInputV1 {
        authorization_provenance: authorization.reference(),
        ..provisional.input
    })?;
    Ok((admission, authorization))
}
fn indexed_reference(index: usize) -> ErasureReferenceV1 {
    let mut digest = [0; 32];
    let index = index.to_be_bytes();
    digest[32 - index.len()..].copy_from_slice(&index);
    ErasureReferenceV1::from_digest(digest)
}
fn indexed_target(index: usize) -> ErasureRequiredTargetV1 {
    ErasureRequiredTargetV1 {
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: indexed_reference(index),
        key_role: ErasureKeyRoleV1::DataEncryption,
        key_digest: indexed_reference(index + 1),
        replica_set: reference(30),
        replica_id: indexed_reference(index + 2),
    }
}
fn references(count: usize) -> Vec<ErasureReferenceV1> {
    (0..count).map(indexed_reference).collect()
}
pub(super) fn request_input(selectors: Vec<ErasureReferenceV1>) -> ErasureRequestInputV1 {
    ErasureRequestInputV1 {
        request: reference(1),
        subject: reference(2),
        scope: ErasureScopeV1::PrivateSubjectData,
        selectors,
        requester: reference(3),
        authorization: reference(4),
        policy: reference(5),
        request_position: 9,
        horizon_position: 10,
        provenance: reference(6),
    }
}

pub(super) fn request() -> Result<ErasureRequestV1, ErasureErrorV1> {
    ErasureRequestV1::new(request_input(vec![reference(8), reference(7)]))
}
pub(super) fn state_transition(
    lifecycle: ErasureLifecycleV1,
    freeze_position: Option<u64>,
    pending_owners: Vec<ErasureReferenceV1>,
    failed_owners: Vec<ErasureReferenceV1>,
) -> ErasureStateTransitionV1 {
    ErasureStateTransitionV1 {
        lifecycle,
        freeze_position,
        pending_owners,
        failed_owners,
        acknowledged_targets: Vec::new(),
        replay_claim: ErasureReplayClaimV1::StructuralOnly,
        provenance: reference(9),
    }
}
pub(super) fn acknowledgement(
    owner: u8,
    outcome: ErasureAcknowledgementOutcomeV1,
) -> ErasureAcknowledgementV1 {
    let target = ErasureRequiredTargetV1 {
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: reference(owner),
        key_role: ErasureKeyRoleV1::DataEncryption,
        key_digest: reference(owner + 10),
        replica_set: reference(owner + 30),
        replica_id: reference(owner + 40),
    };
    let obligation = ErasureObligationV1::new(ErasureObligationInputV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target,
        owner: reference(owner + 40),
        command_identity: destruction_command_reference(reference(1), target),
    })
    .map_or_else(|_| reference(0), |obligation| obligation.reference());
    ErasureAcknowledgementV1 {
        obligation,
        target,
        owner: reference(owner + 40),
        evidence: reference(owner + 20),
        outcome,
    }
}
fn inventory_result(target: ErasureRequiredTargetV1) -> ErasureInventoryResultV1 {
    ErasureInventoryResultV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target,
        transition: ErasureArtifactTransitionV1 {
            from: ErasureReplayClaimV1::Exact,
            to: ErasureReplayClaimV1::StructuralOnly,
            reason: reference(50),
            owner: target.replica_id,
            acknowledgements: reference(52),
            provenance: reference(53),
        },
        retained_disclosure: reference(54),
    }
}
fn receipt_input(
    lifecycle: ErasureLifecycleV1,
    acknowledgements: Vec<ErasureAcknowledgementV1>,
    pending_owners: Vec<ErasureReferenceV1>,
    failed_owners: Vec<ErasureReferenceV1>,
) -> ErasureReceiptInputV1 {
    let frozen_targets = acknowledgements
        .iter()
        .map(|acknowledgement| acknowledgement.target)
        .collect();
    let artifacts = acknowledgements
        .iter()
        .map(|acknowledgement| inventory_result(acknowledgement.target))
        .collect();
    ErasureReceiptInputV1 {
        request: reference(1),
        terminal_state: reference(6),
        coordinator: reference(2),
        lifecycle,
        freeze_position: 10,
        frozen_targets,
        acknowledgements,
        pending_owners,
        failed_owners,
        inventories: ErasureReceiptInventoriesV1 {
            artifacts,
            keys: Vec::new(),
            replicas: Vec::new(),
            backups: Vec::new(),
        },
        replay_claim: ErasureReplayClaimV1::StructuralOnly,
        policy: reference(2),
        trust: reference(3),
        provenance: reference(4),
        issue_position: 11,
        signature: reference(5),
        receipt_digest: reference(0),
    }
}
fn receipt() -> Result<ErasureReceiptV1, ErasureErrorV1> {
    ErasureReceiptV1::new(receipt_input(
        ErasureLifecycleV1::Complete,
        vec![
            acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged),
            acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged),
        ],
        Vec::new(),
        Vec::new(),
    ))
}

#[test]
fn receipt_accepts_an_empty_inapplicable_obligation_set_and_rejects_mismatches(
) -> Result<(), ErasureErrorV1> {
    let empty = ErasureReceiptV1::new(receipt_input(
        ErasureLifecycleV1::Complete,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    ))?;
    assert_eq!(empty.validate_frozen_obligations(&[]), Ok(()));

    let acknowledgement = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let obligation = ErasureObligationV1::new(ErasureObligationInputV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target: acknowledgement.target,
        owner: acknowledgement.owner,
        command_identity: destruction_command_reference(reference(1), acknowledgement.target),
    })?;
    assert_eq!(
        receipt()?.validate_frozen_obligations(&[obligation]),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}
fn dispatched() -> Result<ErasureStateV1, ErasureErrorV1> {
    ErasureStateV1::submitted(reference(1), reference(2), reference(3))?
        .transition(state_transition(
            ErasureLifecycleV1::Authorized,
            None,
            Vec::new(),
            Vec::new(),
        ))?
        .transition(state_transition(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ))?
        .transition(state_transition(
            ErasureLifecycleV1::DestructionDispatched,
            Some(10),
            Vec::new(),
            Vec::new(),
        ))
}
fn decode_request(value: &Value) -> Result<ErasureRequestV1, ErasureErrorV1> {
    ErasureRequestV1::from_canonical_cbor(&public_value_bytes(value)?)
}
fn decode_state(value: &Value) -> Result<ErasureStateV1, ErasureErrorV1> {
    ErasureStateV1::from_canonical_cbor(&public_value_bytes(value)?)
}
fn decode_receipt(value: &Value) -> Result<ErasureReceiptV1, ErasureErrorV1> {
    ErasureReceiptV1::from_canonical_cbor(&public_value_bytes(value)?)
}
fn public_value_bytes(value: &Value) -> Result<Vec<u8>, ErasureErrorV1> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).map_err(|_| ErasureErrorV1::InvalidEncoding)?;
    Ok(bytes)
}
fn public_request_value(request: &ErasureRequestV1) -> Result<Value, ErasureErrorV1> {
    ciborium::from_reader(request.to_canonical_cbor()?.as_slice())
        .map_err(|_| ErasureErrorV1::InvalidEncoding)
}
fn public_state_value(state: &ErasureStateV1) -> Result<Value, ErasureErrorV1> {
    ciborium::from_reader(state.to_canonical_cbor()?.as_slice())
        .map_err(|_| ErasureErrorV1::InvalidEncoding)
}
fn public_receipt_value(receipt: &ErasureReceiptV1) -> Result<Value, ErasureErrorV1> {
    ciborium::from_reader(receipt.to_canonical_cbor()?.as_slice())
        .map_err(|_| ErasureErrorV1::InvalidEncoding)
}
pub(super) fn record_parts(record: &ErasureCoordinatorRecordV1) -> ErasureCoordinatorRecordPartsV1 {
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

fn supporting_records_input(
    records: &ErasureSupportingRecordsV1,
) -> ErasureSupportingRecordsInputV1 {
    ErasureSupportingRecordsInputV1 {
        correction_provenance: records.correction_provenance.clone(),
        authorization_rejection: records.authorization_rejection,
        scope_commitment: records.scope_commitment.clone(),
        freeze_admission_evidence: records.freeze_admission_evidence.clone(),
        freeze_authorization_evidence: records.freeze_authorization_evidence.clone(),
        freeze_provenance: records.freeze_provenance,
        freeze_failure: records.freeze_failure,
        obligations: records.obligations.clone(),
        obligation_set: records.obligation_set.clone(),
        scope_extensions: records.scope_extensions.clone(),
        scope_extension_ledgers: records.scope_extension_ledgers.clone(),
        retry_admissions: records.retry_admissions.clone(),
        acknowledgement_provenance: records.acknowledgement_provenance.clone(),
        attempt_outcomes: records.attempt_outcomes.clone(),
        receipts: records.receipts.clone(),
        receipt_provenance: records.receipt_provenance.clone(),
        administrative_resolutions: records.administrative_resolutions.clone(),
    }
}

fn retry_admission_at(
    base: &ErasureRetryAdmissionV1,
    ordinal: u64,
    marker: u8,
) -> Result<ErasureRetryAdmissionV1, ErasureErrorV1> {
    let mut input = base.input.clone();
    input.attempt_ordinal = ordinal;
    input.source_receipt = (ordinal != 0).then(|| reference(marker));
    input.admitted_position = 9 + ordinal;
    input.deadline_position = 10 + ordinal;
    input.authorization_provenance = reference(marker);
    ErasureRetryAdmissionV1::new(input)
}

fn acknowledgement_provenance_for(
    base: &ErasureAcknowledgementProvenanceV1,
    admission: &ErasureRetryAdmissionV1,
    outcome: ErasureAcknowledgementOutcomeV1,
    marker: u8,
) -> Result<ErasureAcknowledgementProvenanceV1, ErasureErrorV1> {
    let mut input = base.input;
    input.attempt = admission.reference();
    input.outcome = outcome;
    input.evidence = reference(marker);
    ErasureAcknowledgementProvenanceV1::new(input)
}

pub(super) fn record_after_freeze(
    targets: Vec<ErasureRequiredTargetV1>,
) -> Result<ErasureCoordinatorRecordV1, ErasureErrorV1> {
    let port = test_port(true, targets);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        state_transition(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    let record = coordinator
        .port
        .records
        .borrow()
        .first()
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing);
    record
}

pub(super) fn record_after_submit() -> Result<ErasureCoordinatorRecordV1, ErasureErrorV1> {
    let port = test_port(true, Vec::new());
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    let record = coordinator
        .port
        .records
        .borrow()
        .first()
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing);
    record
}

pub(super) fn record_after_acknowledgement() -> Result<ErasureCoordinatorRecordV1, ErasureErrorV1> {
    let ack = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let port = test_port(true, vec![ack.target]);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        state_transition(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    coordinator.acknowledge(reference(1), ack)?;
    let record = coordinator
        .port
        .records
        .borrow()
        .first()
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing);
    record
}

pub(super) fn record_after_dispatch_intent(
    target: ErasureRequiredTargetV1,
) -> Result<ErasureCoordinatorRecordV1, ErasureErrorV1> {
    let mut port = test_port(true, vec![target]);
    port.dispatch_error = Some(ErasureErrorV1::KeyDestructionFailed);
    let persisted = port.clone();
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        state_transition(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    assert_eq!(
        coordinator.dispatch_destruction(reference(1), reference(9)),
        Err(ErasureErrorV1::KeyDestructionFailed)
    );
    persisted
        .load_record(reference(1), &persisted)?
        .ok_or(ErasureErrorV1::ProvenanceMissing)
}

pub(super) fn complete_record() -> Result<ErasureCoordinatorRecordV1, ErasureErrorV1> {
    let ack = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let port = test_port(true, vec![ack.target]);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        state_transition(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    coordinator.acknowledge(reference(1), ack)?;
    let awaiting = coordinator
        .existing(reference(1))
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let terminal = awaiting.transition({
        let mut transition = state_transition(
            ErasureLifecycleV1::Complete,
            awaiting.freeze_position(),
            Vec::new(),
            Vec::new(),
        );
        transition.acknowledged_targets = vec![ack.target];
        transition.provenance = reference(4);
        transition
    })?;
    let mut input = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![ack],
        Vec::new(),
        Vec::new(),
    );
    input.terminal_state = terminal.state_digest();
    input.inventories.artifacts = vec![inventory_result(ack.target)];
    coordinator.finalize(reference(1), input)?;
    let record = coordinator
        .port
        .records
        .borrow()
        .first()
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing);
    record
}

fn completed_coordinator(
) -> Result<ErasureCoordinatorStateMachineV1<TestCoordinatorPort>, ErasureErrorV1> {
    let ack = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let port = test_port(true, vec![ack.target]);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        state_transition(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    coordinator.acknowledge(reference(1), ack)?;
    let awaiting = coordinator
        .existing(reference(1))
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let mut terminal_change = state_transition(
        ErasureLifecycleV1::Complete,
        awaiting.freeze_position(),
        Vec::new(),
        Vec::new(),
    );
    terminal_change.acknowledged_targets = vec![ack.target];
    terminal_change.provenance = reference(4);
    let terminal = awaiting.transition(terminal_change)?;
    let mut input = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![ack],
        Vec::new(),
        Vec::new(),
    );
    input.terminal_state = terminal.state_digest();
    input.inventories.artifacts = vec![inventory_result(ack.target)];
    coordinator.finalize(reference(1), input)?;
    Ok(coordinator)
}

fn assert_conflicting_receipt_retry(
    mutate: impl FnOnce(&mut ErasureReceiptInputV1),
) -> Result<(), ErasureErrorV1> {
    let mut coordinator = completed_coordinator()?;
    let mut input = coordinator
        .port
        .records
        .borrow()
        .first()
        .and_then(ErasureCoordinatorRecordV1::receipt_input)
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    mutate(&mut input);
    assert_eq!(
        coordinator.finalize(reference(1), input),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

fn reject_terminal_receipt_mutation(
    record: &ErasureCoordinatorRecordV1,
    mutate: impl FnOnce(&mut ErasureReceiptV1),
) -> Result<(), ErasureErrorV1> {
    let mut parts = record_parts(record);
    mutate(
        parts
            .receipt
            .as_mut()
            .ok_or(ErasureErrorV1::ProvenanceMissing)?,
    );
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(parts, reference(2)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

fn reject_terminal_input_mutation(
    record: &ErasureCoordinatorRecordV1,
    mutate: impl FnOnce(&mut ErasureReceiptInputV1),
) -> Result<(), ErasureErrorV1> {
    let mut parts = record_parts(record);
    let rebuilt = {
        let input = parts
            .receipt_input
            .as_mut()
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        mutate(input);
        ErasureReceiptV1::new(input.clone())?
    };
    parts.receipt = Some(rebuilt);
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(parts, reference(2)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

fn exercise_lifecycle_edge_cases() {
    for (current, next, permitted) in [
        (
            ErasureLifecycleV1::Submitted,
            ErasureLifecycleV1::Authorized,
            true,
        ),
        (
            ErasureLifecycleV1::Submitted,
            ErasureLifecycleV1::Rejected,
            true,
        ),
        (
            ErasureLifecycleV1::Authorized,
            ErasureLifecycleV1::AccessFrozen,
            true,
        ),
        (
            ErasureLifecycleV1::AccessFrozen,
            ErasureLifecycleV1::DestructionDispatched,
            true,
        ),
        (
            ErasureLifecycleV1::DestructionDispatched,
            ErasureLifecycleV1::AwaitingAcknowledgements,
            true,
        ),
        (
            ErasureLifecycleV1::AwaitingAcknowledgements,
            ErasureLifecycleV1::Complete,
            true,
        ),
        (
            ErasureLifecycleV1::AwaitingAcknowledgements,
            ErasureLifecycleV1::PartialFailure,
            true,
        ),
        (
            ErasureLifecycleV1::AwaitingAcknowledgements,
            ErasureLifecycleV1::Submitted,
            false,
        ),
        (
            ErasureLifecycleV1::Complete,
            ErasureLifecycleV1::Authorized,
            false,
        ),
    ] {
        assert_eq!(
            std::hint::black_box(current).permits(std::hint::black_box(next)),
            permitted
        );
    }
}

fn exercise_receipt_record_edges() -> Result<(), ErasureErrorV1> {
    let first = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let second = acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let mut outside_closure = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![first],
        Vec::new(),
        Vec::new(),
    );
    outside_closure.frozen_targets = vec![second.target];
    assert_eq!(
        ErasureReceiptV1::new(outside_closure),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let awaiting = record_after_acknowledgement()?;
    let mut invalid_owner = record_parts(&awaiting);
    invalid_owner.acknowledgements[0].owner = reference(99);
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(invalid_owner, reference(2)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let complete = complete_record()?;
    reject_terminal_input_mutation(&complete, |input| input.terminal_state = reference(99))?;
    reject_terminal_input_mutation(&complete, |input| {
        input.lifecycle = ErasureLifecycleV1::PartialFailure;
        input.acknowledgements[0].outcome = ErasureAcknowledgementOutcomeV1::Negative;
        input.failed_owners = vec![first.target.replica_id];
    })?;
    reject_terminal_input_mutation(&complete, |input| input.coordinator = reference(99))?;
    reject_terminal_input_mutation(&complete, |input| input.request = reference(99))?;
    reject_terminal_input_mutation(&complete, |input| {
        input.frozen_targets = vec![second.target];
        input.acknowledgements = vec![second];
        input.inventories.artifacts = vec![inventory_result(second.target)];
    })?;
    reject_terminal_input_mutation(&complete, |input| {
        input.acknowledgements[0].evidence = reference(99);
    })?;

    let mut invalid_receipt_input = record_parts(&complete);
    invalid_receipt_input.receipt_input = Some(receipt_input(
        ErasureLifecycleV1::Submitted,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    ));
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(invalid_receipt_input, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

fn exercise_state_machine_edges() -> Result<(), ErasureErrorV1> {
    let first = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let persisted = record_after_submit()?;
    let mut mismatched_request_input = request_input(vec![reference(8), reference(7)]);
    mismatched_request_input.subject = reference(99);
    let mismatched_request = ErasureRequestV1::new(mismatched_request_input)?;
    let mismatch_port = test_port(true, Vec::new());
    mismatch_port.records.replace(vec![persisted]);
    let mut mismatch = ErasureCoordinatorStateMachineV1::new(mismatch_port, reference(2));
    assert_eq!(
        mismatch.submit(mismatched_request, reference(3)),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut rejected_port = test_port(true, Vec::new());
    rejected_port.authorization_admitted = false;
    let mut rejected = ErasureCoordinatorStateMachineV1::new(rejected_port, reference(2));
    rejected.submit(request()?, reference(3))?;
    assert_eq!(
        rejected.reject(reference(1), reference(9)),
        Err(ErasureErrorV1::Unauthorized)
    );

    let mut missing_targets_port = test_port(true, vec![first.target]);
    missing_targets_port.frozen_targets_error = Some(ErasureErrorV1::AccessFreezeFailed);
    let mut missing_targets =
        ErasureCoordinatorStateMachineV1::new(missing_targets_port, reference(2));
    missing_targets.submit(request()?, reference(3))?;
    missing_targets.authorize(reference(1), reference(9))?;
    assert_eq!(
        missing_targets.freeze_inventory(
            reference(1),
            state_transition(
                ErasureLifecycleV1::AccessFrozen,
                Some(10),
                Vec::new(),
                Vec::new(),
            ),
        ),
        Err(ErasureErrorV1::AccessFreezeFailed)
    );

    let mut reservation_commit_port = test_port(true, vec![first.target]);
    reservation_commit_port.commit_error_on_call = Some(3);
    let mut reservation_commit =
        ErasureCoordinatorStateMachineV1::new(reservation_commit_port, reference(2));
    reservation_commit.submit(request()?, reference(3))?;
    reservation_commit.authorize(reference(1), reference(9))?;
    assert_eq!(
        reservation_commit.freeze_inventory(
            reference(1),
            state_transition(
                ErasureLifecycleV1::AccessFrozen,
                Some(10),
                Vec::new(),
                Vec::new(),
            ),
        ),
        Err(ErasureErrorV1::ReceiptCommitFailed)
    );
    Ok(())
}

fn exercise_normalization_and_trait_edges() -> Result<(), ErasureErrorV1> {
    let first = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let submitted = record_after_submit()?;
    assert_eq!(
        ErasureCoordinatorStateMachineV1::<TestCoordinatorPort>::normalize_receipt_input(
            reference(1),
            reference(2),
            &submitted,
            receipt_input(
                ErasureLifecycleV1::Complete,
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
        ),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let frozen = record_after_freeze(vec![first.target])?;
    assert_eq!(
        ErasureCoordinatorStateMachineV1::<TestCoordinatorPort>::normalize_receipt_input(
            reference(1),
            reference(2),
            &frozen,
            receipt_input(
                ErasureLifecycleV1::Complete,
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
        ),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut trait_coordinator =
        ErasureCoordinatorStateMachineV1::new(test_port(true, Vec::new()), reference(2));
    let api: &mut dyn ErasureCoordinator = &mut trait_coordinator;
    api.submit(request()?)?;
    assert_eq!(
        api.reject(reference(1), reference(9))?.lifecycle(),
        ErasureLifecycleV1::Rejected
    );

    let mut malformed = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    malformed.lifecycle = ErasureLifecycleV1::Authorized;
    malformed.previous_state = None;
    assert_eq!(
        malformed.verify_predecessor_chain(&test_port(true, Vec::new())),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn lifecycle_edges_are_exercised() {
    exercise_lifecycle_edge_cases();
}

#[test]
fn receipt_record_edges_are_exercised() -> Result<(), ErasureErrorV1> {
    exercise_receipt_record_edges()
}

#[test]
fn state_machine_edges_are_exercised() -> Result<(), ErasureErrorV1> {
    exercise_state_machine_edges()
}

#[test]
fn normalization_and_trait_edges_are_exercised() -> Result<(), ErasureErrorV1> {
    exercise_normalization_and_trait_edges()
}

#[test]
fn coordinator_public_retries_reject_injection_and_query_existing() -> Result<(), ErasureErrorV1> {
    let acknowledgement = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let port = test_port(true, vec![acknowledgement.target]);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    let submitted = coordinator.submit(request()?, reference(3))?;
    assert_eq!(coordinator.submit(request()?, reference(3))?, submitted);
    assert_eq!(coordinator.existing(reference(1)), Some(&submitted));
    Ok(())
}

#[test]
fn coordinator_authorization_and_rejection_use_public_host_seams() -> Result<(), ErasureErrorV1> {
    let mut unauthorized =
        ErasureCoordinatorStateMachineV1::new(test_port(true, Vec::new()), reference(2));
    unauthorized.port.authorization_admitted = false;
    unauthorized.submit(request()?, reference(3))?;
    assert_eq!(
        unauthorized.authorize(reference(1), reference(9)),
        Err(ErasureErrorV1::Unauthorized)
    );

    let mut coordinator =
        ErasureCoordinatorStateMachineV1::new(test_port(true, Vec::new()), reference(2));
    coordinator.submit(request()?, reference(3))?;
    let rejected = coordinator.reject(reference(1), reference(9))?;
    assert_eq!(rejected.lifecycle(), ErasureLifecycleV1::Rejected);
    assert_eq!(
        coordinator.reject(reference(1), reference(8)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(coordinator.reject(reference(1), reference(9))?, rejected);
    assert_eq!(
        coordinator.port.authorization_decisions.borrow().as_slice(),
        &[(
            reference(1),
            reference(9),
            ErasureAuthorizationDecisionV1::Rejected,
        ),]
    );
    Ok(())
}

#[test]
fn coordinator_reloads_durable_identity_after_restart() -> Result<(), ErasureErrorV1> {
    let port = test_port(true, Vec::new());
    let restart_port = port.clone();
    let request = request()?;
    let mut first = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    let submitted = first.submit(request.clone(), reference(3))?;
    drop(first);
    let mut restarted = ErasureCoordinatorStateMachineV1::new(restart_port, reference(2));
    assert_eq!(restarted.submit(request, reference(99))?, submitted);
    Ok(())
}

#[test]
fn coordinator_corrected_submission_persists_and_retries_through_unit_port(
) -> Result<(), ErasureErrorV1> {
    let port = test_port(true, Vec::new());
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.reject(reference(1), reference(9))?;
    let predecessor = coordinator
        .port
        .records
        .borrow()
        .first()
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let correction = ErasureCorrectionProvenanceV1::new(ErasureCorrectionProvenanceInputV1 {
        rejected_request: predecessor.request().reference(),
        rejected_terminal_state: predecessor.state().state_digest(),
        correction_reason: reference(70),
        authorization_provenance: reference(71),
    })?;
    let mut corrected_input = request_input(vec![reference(8), reference(7)]);
    corrected_input.request = reference(11);
    corrected_input.provenance = correction.reference();
    let corrected = ErasureRequestV1::new(corrected_input)?;

    let submitted = coordinator.submit_corrected(corrected.clone(), correction.clone())?;
    assert_eq!(submitted.lifecycle(), ErasureLifecycleV1::Submitted);
    assert_eq!(
        coordinator.submit_corrected(corrected, correction)?,
        submitted
    );
    Ok(())
}

#[test]
fn corrected_submission_rejects_each_predecessor_and_retry_conflict() -> Result<(), ErasureErrorV1>
{
    let port = test_port(true, Vec::new());
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    let submitted = coordinator.submit(request()?, reference(3))?;
    let correction = ErasureCorrectionProvenanceV1::new(ErasureCorrectionProvenanceInputV1 {
        rejected_request: reference(1),
        rejected_terminal_state: submitted.state_digest(),
        correction_reason: reference(70),
        authorization_provenance: reference(71),
    })?;
    assert_eq!(
        coordinator.submit_corrected(request()?, correction.clone()),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut missing_predecessor_input = request_input(vec![reference(8), reference(7)]);
    missing_predecessor_input.request = reference(11);
    let missing_predecessor =
        ErasureCorrectionProvenanceV1::new(ErasureCorrectionProvenanceInputV1 {
            rejected_request: reference(99),
            rejected_terminal_state: reference(98),
            correction_reason: reference(70),
            authorization_provenance: reference(71),
        })?;
    missing_predecessor_input.provenance = missing_predecessor.reference();
    assert_eq!(
        coordinator.submit_corrected(
            ErasureRequestV1::new(missing_predecessor_input)?,
            missing_predecessor,
        ),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut wrong_lifecycle_input = request_input(vec![reference(8), reference(7)]);
    wrong_lifecycle_input.request = reference(12);
    wrong_lifecycle_input.provenance = correction.reference();
    assert_eq!(
        coordinator.submit_corrected(ErasureRequestV1::new(wrong_lifecycle_input)?, correction,),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    coordinator.reject(reference(1), reference(9))?;
    let predecessor = coordinator
        .port
        .records
        .borrow()
        .first()
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let accepted_correction =
        ErasureCorrectionProvenanceV1::new(ErasureCorrectionProvenanceInputV1 {
            rejected_request: predecessor.request().reference(),
            rejected_terminal_state: predecessor.state().state_digest(),
            correction_reason: reference(72),
            authorization_provenance: reference(73),
        })?;
    let mut corrected_input = request_input(vec![reference(8), reference(7)]);
    corrected_input.request = reference(13);
    corrected_input.provenance = accepted_correction.reference();
    let corrected = ErasureRequestV1::new(corrected_input.clone())?;
    coordinator.submit_corrected(corrected, accepted_correction.clone())?;
    corrected_input.subject = reference(74);
    assert_eq!(
        coordinator.submit_corrected(ErasureRequestV1::new(corrected_input)?, accepted_correction,),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

fn lineage_freeze_admission(
    target: ErasureRequiredTargetV1,
    lineage_rule: ErasureReferenceV1,
) -> Result<(ErasureAtomicFreezeAdmissionV1, ErasureReferenceV1), ErasureErrorV1> {
    let request_reference = reference(1);
    let targets = vec![target];
    let obligation = ErasureObligationV1::new(ErasureObligationInputV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target,
        owner: target.replica_id,
        command_identity: destruction_command_reference(request_reference, target),
    })?;
    let obligations = vec![obligation];
    let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
        request: request_reference,
        obligations: vec![obligation.reference()],
        policy: reference(5),
        trust: reference(3),
    })?;
    let scope = ErasureScopeCommitmentInputV1 {
        request: request_reference,
        scope_members: vec![reference(7), reference(8)],
        target_closure: target_closure_digest(&targets),
        lineage_rule: Some(lineage_rule),
    };
    let scope_reference = ErasureScopeCommitmentV1::new(scope.clone())?.reference();
    let (freeze_admission_evidence, freeze_authorization_evidence) =
        freeze_evidence_fixture(FreezeEvidenceFixtureInput {
            request: request_reference,
            scope_commitment: scope_reference,
            obligation_set: &obligation_set,
            targets: &targets,
            obligations: &obligations,
            freeze_position: 10,
            evidence: &reference(9).digest(),
        })?;
    ErasureAtomicFreezeAdmissionV1::new(ErasureAtomicFreezeAdmissionInputV1 {
        targets,
        scope,
        obligations,
        obligation_set,
        freeze_position: 10,
        freeze_admission_evidence,
        freeze_authorization_evidence,
    })
    .map(|admission| (admission, scope_reference))
}

#[test]
fn coordinator_lineage_and_resolution_successors_run_through_unit_port(
) -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let lineage_rule = reference(72);
    let (admission, scope_commitment) = lineage_freeze_admission(target, lineage_rule)?;
    let port = test_port(true, vec![target]);
    port.freeze_reservation.borrow_mut().replace(admission);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    let frozen = coordinator.freeze_inventory(
        reference(1),
        state_transition(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;

    let extension = ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
        request: reference(1),
        scope_commitment,
        fork: reference(73),
        lineage_rule,
        predecessor_extension: None,
        admission_provenance: reference(74),
    })?;
    let extended = coordinator.append_scope_extension(reference(1), extension)?;
    assert_eq!(extended, frozen);
    assert_eq!(
        coordinator.append_scope_extension(reference(1), extension)?,
        frozen
    );

    let resolution =
        ErasureAdministrativeResolutionV1::new(ErasureAdministrativeResolutionInputV1 {
            request: reference(1),
            affected_digests: vec![frozen.state_digest()],
            action: ErasureAdministrativeResolutionActionV1::RecoverExactEvidence,
            scope_commitment,
            policy: reference(5),
            trust: reference(3),
            principal: reference(75),
            authorization_provenance: reference(76),
            reason: reference(77),
            issue_position: 11,
            predecessor_resolution: None,
        })?;
    let resolved = coordinator.resolve_administratively(reference(1), resolution.clone())?;
    assert_eq!(resolved, frozen);
    assert_eq!(
        coordinator.resolve_administratively(reference(1), resolution)?,
        frozen
    );
    Ok(())
}

#[test]
fn freeze_authorization_binding_rejects_a_different_admission_body() -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let (admission, scope_commitment) = lineage_freeze_admission(target, reference(72))?;
    let input = admission.input;
    assert_eq!(
        input
            .freeze_authorization_evidence
            .verify_admission_body_binding(&input.freeze_admission_evidence),
        Ok(())
    );

    let (different_admission, _) = freeze_evidence_fixture(FreezeEvidenceFixtureInput {
        request: reference(1),
        scope_commitment,
        obligation_set: &input.obligation_set,
        targets: &input.targets,
        obligations: &input.obligations,
        freeze_position: input.freeze_position + 1,
        evidence: &reference(9).digest(),
    })?;
    assert_eq!(
        input
            .freeze_authorization_evidence
            .verify_admission_body_binding(&different_admission),
        Err(ErasureErrorV1::Unauthorized)
    );
    Ok(())
}

#[test]
fn atomic_freeze_rejects_complete_but_inconsistent_applicability_matrices(
) -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let (admission, scope_commitment) = lineage_freeze_admission(target, reference(72))?;
    let base = admission.input;

    let extra_target = acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let (oversized_matrix, oversized_authorization) =
        freeze_evidence_fixture(FreezeEvidenceFixtureInput {
            request: reference(1),
            scope_commitment,
            obligation_set: &base.obligation_set,
            targets: &[target, extra_target],
            obligations: &base.obligations,
            freeze_position: 10,
            evidence: &reference(9).digest(),
        })?;
    let mut wrong_cardinality = base.clone();
    wrong_cardinality.freeze_admission_evidence = oversized_matrix;
    wrong_cardinality.freeze_authorization_evidence = oversized_authorization;
    assert_eq!(
        ErasureAtomicFreezeAdmissionV1::new(wrong_cardinality),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let matrix = ErasureInventoryCategoryV1::CANONICAL
        .into_iter()
        .map(|category| {
            ErasureFreezeApplicabilityRowV1::new(
                category,
                0,
                ErasureApplicabilityDecisionV1::Inapplicable,
                None,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (inapplicable_matrix, inapplicable_authorization) = freeze_evidence_with_matrix(
        reference(1),
        scope_commitment,
        &base.obligation_set,
        matrix,
        10,
        reference(9),
    )?;
    let mut omitted_obligation = base;
    omitted_obligation.freeze_admission_evidence = inapplicable_matrix;
    omitted_obligation.freeze_authorization_evidence = inapplicable_authorization;
    assert_eq!(
        ErasureAtomicFreezeAdmissionV1::new(omitted_obligation),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn all_inapplicable_matrix_commits_a_complete_empty_receipt() -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let request_reference = reference(1);
    let targets = vec![target];
    let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
        request: request_reference,
        obligations: Vec::new(),
        policy: reference(5),
        trust: reference(3),
    })?;
    let scope = ErasureScopeCommitmentInputV1 {
        request: request_reference,
        scope_members: vec![reference(7), reference(8)],
        target_closure: target_closure_digest(&targets),
        lineage_rule: None,
    };
    let scope_reference = ErasureScopeCommitmentV1::new(scope.clone())?.reference();
    let matrix = ErasureInventoryCategoryV1::CANONICAL
        .into_iter()
        .map(|category| {
            ErasureFreezeApplicabilityRowV1::new(
                category,
                0,
                ErasureApplicabilityDecisionV1::Inapplicable,
                None,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (freeze_admission_evidence, freeze_authorization_evidence) = freeze_evidence_with_matrix(
        request_reference,
        scope_reference,
        &obligation_set,
        matrix,
        10,
        reference(9),
    )?;
    let admission = ErasureAtomicFreezeAdmissionV1::new(ErasureAtomicFreezeAdmissionInputV1 {
        targets,
        scope,
        obligations: Vec::new(),
        obligation_set,
        freeze_position: 10,
        freeze_admission_evidence,
        freeze_authorization_evidence,
    })?;
    let port = test_port(true, vec![target]);
    port.freeze_reservation.borrow_mut().replace(admission);
    let attempts = Rc::clone(&port.attempt_admissions);
    let receipt_inputs = Rc::clone(&port.receipt_inputs);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(request_reference, reference(9))?;
    coordinator.freeze_inventory(
        request_reference,
        state_transition(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    let awaiting = coordinator.dispatch_destruction(request_reference, reference(10))?;

    assert_eq!(
        awaiting.lifecycle(),
        ErasureLifecycleV1::AwaitingAcknowledgements
    );
    assert_eq!(attempts.borrow()[0].unresolved_obligations(), &[]);
    assert_eq!(attempts.borrow()[0].command_identities(), &[]);
    assert_eq!(
        coordinator.dispatch_destruction(request_reference, reference(10))?,
        awaiting
    );
    assert_eq!(attempts.borrow().len(), 1);
    let receipt = coordinator.finalize(
        request_reference,
        receipt_input(
            ErasureLifecycleV1::Complete,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    assert_eq!(receipt.lifecycle(), ErasureLifecycleV1::Complete);
    assert!(receipt.acknowledgements().is_empty());
    assert!(receipt_inputs.borrow()[0].inventories.artifacts.is_empty());
    assert_eq!(receipt_inputs.borrow().len(), 1);
    Ok(())
}

#[test]
fn verified_record_capability_rejects_frozen_unauthorized_commits() -> Result<(), ErasureErrorV1> {
    struct RejectingVerifier;

    impl ErasureFreezeAuthorizationVerifierV1 for RejectingVerifier {
        fn validate_freeze_authorization(
            &self,
            _admission: &ErasureFreezeAdmissionEvidenceV1,
            _authorization: &ErasureFreezeAuthorizationEvidenceV1,
        ) -> Result<(), ErasureErrorV1> {
            Err(ErasureErrorV1::Unauthorized)
        }
    }

    let frozen = record_after_freeze(vec![
        acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target,
    ])?;
    assert_eq!(
        VerifiedErasureCoordinatorRecordV1::new(frozen, &RejectingVerifier),
        Err(ErasureErrorV1::Unauthorized)
    );
    assert!(VerifiedErasureCoordinatorRecordV1::new(
        ErasureCoordinatorRecordV1::from_parts(
            ErasureCoordinatorRecordPartsV1 {
                request: request()?,
                state: ErasureStateV1::submitted(reference(1), reference(2), reference(3))?,
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
            reference(2),
        )?,
        &RejectingVerifier,
    )
    .is_ok());
    Ok(())
}

#[test]
fn normalized_persistence_round_trips_and_rejects_missing_evidence() -> Result<(), ErasureErrorV1> {
    let record = record_after_freeze(vec![
        acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target,
    ])?;
    let bundle = record.to_persistence_bundle()?;
    let mut evidence = bundle
        .evidence()
        .iter()
        .map(|object| (object.reference(), object.canonical_cbor().to_vec()))
        .collect::<BTreeMap<_, _>>();
    let recovered = ErasureCoordinatorRecordV1::from_persistence_manifest(
        bundle.manifest_cbor(),
        &mut |reference| {
            evidence
                .get(&reference)
                .cloned()
                .ok_or(ErasureErrorV1::ProvenanceMissing)
        },
    )?;
    assert_eq!(recovered, record);

    let missing = bundle
        .evidence()
        .first()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .reference();
    evidence.remove(&missing);
    assert_eq!(
        ErasureCoordinatorRecordV1::from_persistence_manifest(
            bundle.manifest_cbor(),
            &mut |reference| evidence
                .get(&reference)
                .cloned()
                .ok_or(ErasureErrorV1::ProvenanceMissing),
        ),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn durable_record_reconstructs_through_public_parts_api() -> Result<(), ErasureErrorV1> {
    let request = request()?;
    let port = test_port(true, Vec::new());
    let restart_port = port.clone();
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request.clone(), reference(3))?;
    let persisted = restart_port
        .records
        .borrow()
        .first()
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let reconstructed =
        ErasureCoordinatorRecordV1::from_parts(record_parts(&persisted), reference(2))?;
    restart_port.records.replace(vec![reconstructed]);
    let mut restarted = ErasureCoordinatorStateMachineV1::new(restart_port, reference(2));
    assert_eq!(
        restarted.submit(request, reference(99))?.lifecycle(),
        ErasureLifecycleV1::Submitted
    );
    Ok(())
}

#[test]
fn submit_rehydration_verifies_the_persisted_predecessor_chain() -> Result<(), ErasureErrorV1> {
    let request = request()?;
    let port = test_port(true, Vec::new());
    let restart_port = port.clone();
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request.clone(), reference(3))?;
    let persisted = restart_port
        .records
        .borrow()
        .first()
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let authorized = persisted.state().transition(state_transition(
        ErasureLifecycleV1::Authorized,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    let mut parts = record_parts(&persisted);
    parts.state = authorized;
    parts.authorize_provenance = Some(reference(9));
    let reconstructed = ErasureCoordinatorRecordV1::from_parts(parts, reference(2))?;
    restart_port.records.replace(vec![reconstructed]);
    restart_port.state_history.borrow_mut().clear();

    let mut restarted = ErasureCoordinatorStateMachineV1::new(restart_port, reference(2));
    assert_eq!(
        restarted.submit(request, reference(99)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn durable_record_parts_reject_inconsistent_public_inputs() -> Result<(), ErasureErrorV1> {
    let port = test_port(true, Vec::new());
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    let persisted = coordinator
        .port
        .records
        .borrow()
        .first()
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;

    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(record_parts(&persisted), reference(99)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let mut invalid_scope = record_parts(&persisted);
    invalid_scope.targets = vec![target, target];
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(invalid_scope, reference(2)),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let mut invalid_policy = record_parts(&persisted);
    invalid_policy.targets = vec![target];
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(invalid_policy, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let authorized = persisted.state().transition(state_transition(
        ErasureLifecycleV1::Authorized,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    let mut missing_authorization = record_parts(&persisted);
    missing_authorization.state = authorized.clone();
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(missing_authorization, reference(2)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let frozen = authorized.transition(state_transition(
        ErasureLifecycleV1::AccessFrozen,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let mut invalid_frozen = record_parts(&persisted);
    invalid_frozen.state = frozen;
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(invalid_frozen, reference(2)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let dispatched = persisted
        .state()
        .transition(state_transition(
            ErasureLifecycleV1::Authorized,
            None,
            Vec::new(),
            Vec::new(),
        ))?
        .transition(state_transition(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ))?
        .transition(state_transition(
            ErasureLifecycleV1::DestructionDispatched,
            Some(10),
            Vec::new(),
            Vec::new(),
        ))?;
    let mut invalid_dispatched = record_parts(&persisted);
    invalid_dispatched.state = dispatched;
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(invalid_dispatched, reference(2)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn durable_record_scope_checks_reject_independent_closure_conflicts() -> Result<(), ErasureErrorV1>
{
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let valid_frozen = record_after_freeze(vec![
        target,
        acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged).target,
    ])?;
    let mut frozen_parts = record_parts(&valid_frozen);
    frozen_parts.targets = vec![target, target];
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(frozen_parts, reference(2)),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let mut unsorted_parts = record_parts(&valid_frozen);
    unsorted_parts.targets.reverse();
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(unsorted_parts, reference(2)),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let awaiting = record_after_acknowledgement()?;
    let mut duplicate_acknowledgements = record_parts(&awaiting);
    duplicate_acknowledgements.acknowledgements.push(
        duplicate_acknowledgements
            .acknowledgements
            .first()
            .copied()
            .ok_or(ErasureErrorV1::ProvenanceMissing)?,
    );
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(duplicate_acknowledgements, reference(2)),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let foreign = acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let mut outside_closure = record_parts(&awaiting);
    outside_closure.acknowledgements = vec![foreign];
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(outside_closure, reference(2)),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn durable_frozen_record_bounds_frozen_targets() -> Result<(), ErasureErrorV1> {
    let target = indexed_target(0);
    let frozen = record_after_freeze(vec![target])?;
    let mut oversized = record_parts(&frozen);
    oversized.targets = vec![target; ERASURE_MAX_TARGETS + 1];
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(oversized, reference(2)),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn target_count_bound_accepts_below_and_at_ceiling_then_rejects_next() {
    assert!(target_count_is_bounded(0));
    assert!(target_count_is_bounded(ERASURE_MAX_TARGETS));
    assert!(!target_count_is_bounded(ERASURE_MAX_TARGETS + 1));
}

#[test]
#[ignore = "exact maximum is a baseline stress case, not a per-mutant fixture"]
fn durable_frozen_record_accepts_the_exact_target_limit() -> Result<(), ErasureErrorV1> {
    let targets = (0..ERASURE_MAX_TARGETS).map(indexed_target).collect();
    let frozen = record_after_freeze(targets)?;
    assert_eq!(frozen.targets().len(), ERASURE_MAX_TARGETS);
    Ok(())
}

#[test]
fn durable_record_atomic_freeze_evidence_bindings_are_checked() -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let frozen = record_after_freeze(vec![target])?;
    let mut frozen_without_scope = record_parts(&frozen);
    frozen_without_scope.supporting_records.scope_commitment = None;
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(frozen_without_scope, reference(2)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let mut frozen_without_matrix = record_parts(&frozen);
    frozen_without_matrix.supporting_records.obligation_set = None;
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(frozen_without_matrix, reference(2)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let mut frozen_without_obligations = record_parts(&frozen);
    frozen_without_obligations
        .supporting_records
        .obligations
        .clear();
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(frozen_without_obligations, reference(2)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let mut frozen_without_admission = record_parts(&frozen);
    frozen_without_admission
        .supporting_records
        .freeze_admission_evidence = None;
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(frozen_without_admission, reference(2)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let mut frozen_without_authorization = record_parts(&frozen);
    frozen_without_authorization
        .supporting_records
        .freeze_authorization_evidence = None;
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(frozen_without_authorization, reference(2)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let mut orphaned_admission = record_parts(&record_after_submit()?);
    orphaned_admission
        .supporting_records
        .freeze_admission_evidence = frozen.supporting_records.freeze_admission_evidence.clone();
    orphaned_admission
        .supporting_records
        .freeze_authorization_evidence = frozen
        .supporting_records
        .freeze_authorization_evidence
        .clone();
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(orphaned_admission, reference(2)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let mut changed_targets = record_parts(&frozen);
    changed_targets.targets =
        vec![acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged).target];
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(changed_targets, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let complete = complete_record()?;
    let mut terminal_without_receipt = record_parts(&complete);
    terminal_without_receipt.receipt = None;
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(terminal_without_receipt, reference(2)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let mut terminal_without_input = record_parts(&complete);
    terminal_without_input.receipt_input = None;
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(terminal_without_input, reference(2)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn durable_authorized_shape_checks_each_persisted_field() -> Result<(), ErasureErrorV1> {
    let submitted = record_after_submit()?;
    let authorized_state = submitted.state().transition(state_transition(
        ErasureLifecycleV1::Authorized,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let acknowledgement = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let mut authorized = record_parts(&submitted);
    authorized.state = authorized_state;
    authorized.authorize_provenance = Some(reference(9));

    let mut with_targets = authorized.clone();
    with_targets.targets = vec![target];
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(with_targets, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut with_acknowledgements = authorized.clone();
    with_acknowledgements.acknowledgements = vec![acknowledgement];
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(with_acknowledgements, reference(2)),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let mut with_receipt = authorized.clone();
    with_receipt.receipt = Some(receipt()?);
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(with_receipt, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut with_receipt_input = authorized;
    with_receipt_input.receipt_input = Some(receipt_input(
        ErasureLifecycleV1::Complete,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    ));
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(with_receipt_input, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn durable_record_lifecycle_checks_reject_independent_receipt_fields() -> Result<(), ErasureErrorV1>
{
    let submitted = record_after_submit()?;
    let mut submitted_receipt = record_parts(&submitted);
    submitted_receipt.receipt = Some(receipt()?);
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(submitted_receipt, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let mut submitted_input = record_parts(&submitted);
    submitted_input.receipt_input = Some(receipt_input(
        ErasureLifecycleV1::Complete,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    ));
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(submitted_input, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let frozen = record_after_freeze(vec![
        acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target,
    ])?;
    let mut frozen_receipt = record_parts(&frozen);
    frozen_receipt.receipt = Some(receipt()?);
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(frozen_receipt, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let mut frozen_input = record_parts(&frozen);
    frozen_input.receipt_input = Some(receipt_input(
        ErasureLifecycleV1::Complete,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    ));
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(frozen_input, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let dispatched = record_after_acknowledgement()?;
    let mut dispatched_receipt = record_parts(&dispatched);
    dispatched_receipt.receipt = Some(receipt()?);
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(dispatched_receipt, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let mut dispatched_input = record_parts(&dispatched);
    dispatched_input.receipt_input = Some(receipt_input(
        ErasureLifecycleV1::Complete,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    ));
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(dispatched_input, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn durable_terminal_record_checks_reject_independent_receipt_mismatches(
) -> Result<(), ErasureErrorV1> {
    let record = complete_record()?;
    reject_terminal_receipt_mutation(&record, |receipt| {
        receipt.0.terminal_state = reference(99);
    })?;
    reject_terminal_receipt_mutation(&record, |receipt| {
        receipt.0.lifecycle = ErasureLifecycleV1::PartialFailure;
    })?;
    reject_terminal_receipt_mutation(&record, |receipt| {
        receipt.0.coordinator = reference(99);
    })?;
    reject_terminal_receipt_mutation(&record, |receipt| {
        receipt.0.request = reference(99);
    })?;
    reject_terminal_receipt_mutation(&record, |receipt| {
        receipt.0.frozen_targets.clear();
    })?;
    reject_terminal_receipt_mutation(&record, |receipt| {
        receipt.0.acknowledgements.clear();
    })?;

    let mut altered_state = record_parts(&record);
    altered_state.state.pending_owners = vec![reference(99)];
    altered_state
        .receipt
        .as_mut()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .0
        .terminal_state = altered_state.state.state_digest();
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(altered_state, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

fn assert_complete_trait_record(
    persisted: &ErasureCoordinatorRecordV1,
    submitted_request: &ErasureRequestV1,
    acknowledgement: &ErasureAcknowledgementV1,
) -> Result<(), ErasureErrorV1> {
    assert_eq!(persisted.request(), submitted_request);
    assert_eq!(persisted.state().lifecycle(), ErasureLifecycleV1::Complete);
    assert_eq!(persisted.targets(), &[acknowledgement.target]);
    assert_eq!(persisted.acknowledgements(), &[*acknowledgement]);
    assert!(persisted.receipt().is_some());
    assert!(persisted.receipt_input().is_some());
    assert_eq!(persisted.authorize_provenance(), Some(reference(9)));
    let freeze = persisted
        .supporting_records()
        .freeze_provenance()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let freeze_admission = persisted
        .supporting_records()
        .freeze_admission_evidence()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let freeze_authorization = persisted
        .supporting_records()
        .freeze_authorization_evidence()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let admission = persisted
        .supporting_records()
        .retry_admissions()
        .first()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    assert_eq!(freeze.host_evidence(), freeze_admission.reference());
    assert_eq!(freeze_authorization.evidence(), reference(9).digest());
    assert_eq!(persisted.freeze_provenance(), Some(freeze.reference()));
    assert_eq!(admission.authorization_provenance(), reference(9));
    assert_eq!(admission.trust(), reference(9));
    assert_eq!(persisted.dispatch_provenance(), Some(admission.reference()));
    Ok(())
}

#[test]
fn coordinator_trait_interface_covers_each_lifecycle_operation() -> Result<(), ErasureErrorV1> {
    let acknowledgement = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let port = test_port(true, vec![acknowledgement.target]);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    let submitted_request = request()?;
    let admission = ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
        request: reference(1),
        attempt_ordinal: 0,
        source_receipt: None,
        unresolved_obligations: vec![acknowledgement.obligation],
        command_identities: vec![destruction_command_reference(
            reference(1),
            acknowledgement.target,
        )],
        policy: reference(5),
        trust: reference(9),
        admitted_position: 9,
        deadline_position: u64::MAX,
        authorization_provenance: reference(9),
    })?;
    let submitted = {
        let api: &mut dyn ErasureCoordinator = &mut coordinator;
        let submitted = api.submit(submitted_request.clone())?;
        assert_eq!(
            api.authorize(reference(1), reference(9))?.lifecycle(),
            ErasureLifecycleV1::Authorized
        );
        assert_eq!(
            api.freeze_access(
                reference(1),
                state_transition(
                    ErasureLifecycleV1::AccessFrozen,
                    Some(10),
                    Vec::new(),
                    Vec::new(),
                ),
            )?
            .lifecycle(),
            ErasureLifecycleV1::AccessFrozen
        );
        assert_eq!(
            api.dispatch_destruction(reference(1), admission)?
                .lifecycle(),
            ErasureLifecycleV1::AwaitingAcknowledgements
        );
        assert_eq!(
            api.acknowledge(reference(1), acknowledgement)?.lifecycle(),
            ErasureLifecycleV1::AwaitingAcknowledgements
        );
        submitted
    };
    assert_eq!(submitted.lifecycle(), ErasureLifecycleV1::Submitted);
    let awaiting = coordinator
        .existing(reference(1))
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let terminal = awaiting.transition({
        let mut transition = state_transition(
            ErasureLifecycleV1::Complete,
            awaiting.freeze_position(),
            Vec::new(),
            Vec::new(),
        );
        transition.acknowledged_targets = vec![acknowledgement.target];
        transition.provenance = reference(4);
        transition
    })?;
    let mut input = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![acknowledgement],
        Vec::new(),
        Vec::new(),
    );
    input.terminal_state = terminal.state_digest();
    input.inventories.artifacts = vec![inventory_result(acknowledgement.target)];
    let api: &mut dyn ErasureCoordinator = &mut coordinator;
    assert_eq!(
        api.finalize(reference(1), input)?.lifecycle(),
        ErasureLifecycleV1::Complete
    );
    let persisted = coordinator
        .port
        .records
        .borrow()
        .first()
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    assert_complete_trait_record(&persisted, &submitted_request, &acknowledgement)
}

#[test]
fn coordinator_finalize_from_awaiting_state_rechecks_authority() -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let mut coordinator =
        ErasureCoordinatorStateMachineV1::new(test_port(true, vec![target]), reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        state_transition(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    let awaiting = coordinator
        .existing(reference(1))
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let terminal = awaiting.transition(state_transition(
        ErasureLifecycleV1::PartialFailure,
        awaiting.freeze_position(),
        vec![target.replica_id],
        Vec::new(),
    ))?;
    let mut input = receipt_input(
        ErasureLifecycleV1::PartialFailure,
        Vec::new(),
        vec![target.replica_id],
        Vec::new(),
    );
    input.terminal_state = terminal.state_digest();
    input.frozen_targets = vec![target];
    input.provenance = reference(9);
    input.inventories.artifacts = vec![inventory_result(target)];
    coordinator.port.receipt_error = Some(ErasureErrorV1::PolicyConflict);
    assert_eq!(
        coordinator.finalize(reference(1), input),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        coordinator
            .existing(reference(1))
            .map(ErasureStateV1::lifecycle),
        Some(ErasureLifecycleV1::AwaitingAcknowledgements)
    );
    Ok(())
}

#[test]
fn coordinator_persists_host_freeze_provenance() -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let mut port = test_port(true, vec![target]);
    port.admitted_freeze_provenance = Some(reference(42));
    port.admitted_freeze_position = Some(42);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    let frozen = coordinator.freeze_inventory(
        reference(1),
        state_transition(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    {
        let records = coordinator.port.records.borrow();
        let persisted = records.first().ok_or(ErasureErrorV1::ProvenanceMissing)?;
        let freeze = persisted
            .supporting_records()
            .freeze_provenance()
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        let admission = persisted
            .supporting_records()
            .freeze_admission_evidence()
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        let authorization = persisted
            .supporting_records()
            .freeze_authorization_evidence()
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        assert_eq!(freeze.host_evidence(), admission.reference());
        assert_eq!(authorization.evidence(), reference(42).digest());
        assert_eq!(persisted.freeze_provenance(), Some(freeze.reference()));
        assert_eq!(persisted.state().provenance(), freeze.reference());
        assert_eq!(persisted.state().freeze_position(), Some(42));
    }
    assert_eq!(
        coordinator.freeze_inventory(
            reference(1),
            state_transition(
                ErasureLifecycleV1::AccessFrozen,
                Some(10),
                Vec::new(),
                Vec::new(),
            ),
        )?,
        frozen
    );
    Ok(())
}

#[test]
fn coordinator_exposes_unknown_and_port_failure_contracts() -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let mut unknown =
        ErasureCoordinatorStateMachineV1::new(test_port(true, vec![target]), reference(2));
    assert_eq!(
        unknown.authorize(reference(1), reference(9)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        unknown.freeze_inventory(
            reference(1),
            state_transition(
                ErasureLifecycleV1::AccessFrozen,
                Some(10),
                Vec::new(),
                Vec::new()
            )
        ),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        unknown.dispatch_destruction(reference(1), reference(9)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        unknown.acknowledge(
            reference(1),
            acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged)
        ),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        unknown.finalize(
            reference(1),
            receipt_input(
                ErasureLifecycleV1::Complete,
                Vec::new(),
                Vec::new(),
                Vec::new()
            )
        ),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut load_failed = test_port(true, Vec::new());
    load_failed.load_error = Some(ErasureErrorV1::KeyRegistryUnavailable);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(load_failed, reference(2));
    assert_eq!(
        coordinator.submit(request()?, reference(3)),
        Err(ErasureErrorV1::KeyRegistryUnavailable)
    );

    let mut commit_failed = test_port(true, Vec::new());
    commit_failed.commit_error = Some(ErasureErrorV1::ReceiptCommitFailed);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(commit_failed, reference(2));
    assert_eq!(
        coordinator.submit(request()?, reference(3)),
        Err(ErasureErrorV1::ReceiptCommitFailed)
    );

    let mut freeze_failed = test_port(true, vec![target]);
    freeze_failed.freeze_error = Some(ErasureErrorV1::AccessFreezeFailed);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(freeze_failed, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    assert_eq!(
        coordinator.freeze_inventory(
            reference(1),
            state_transition(
                ErasureLifecycleV1::AccessFrozen,
                Some(10),
                Vec::new(),
                Vec::new(),
            ),
        ),
        Err(ErasureErrorV1::AccessFreezeFailed)
    );

    let mut dispatch_failed = test_port(true, vec![target]);
    dispatch_failed.dispatch_error = Some(ErasureErrorV1::KeyDestructionFailed);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(dispatch_failed, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        state_transition(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    assert_eq!(
        coordinator.dispatch_destruction(reference(1), reference(9)),
        Err(ErasureErrorV1::KeyDestructionFailed)
    );

    Ok(())
}

#[test]
fn dispatch_intent_is_persisted_before_host_dispatch() -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let mut port = test_port(true, vec![target]);
    port.dispatch_error = Some(ErasureErrorV1::KeyDestructionFailed);
    let restart_port = port.clone();
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        state_transition(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    assert_eq!(
        coordinator.dispatch_destruction(reference(1), reference(9)),
        Err(ErasureErrorV1::KeyDestructionFailed)
    );
    let persisted = restart_port
        .load_record(reference(1), &restart_port)?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    assert_eq!(
        persisted.state().lifecycle(),
        ErasureLifecycleV1::AccessFrozen
    );
    let admission = persisted
        .supporting_records()
        .retry_admissions()
        .last()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    assert_eq!(admission.authorization_provenance(), reference(9));
    assert_eq!(admission.trust(), reference(3));
    assert_eq!(persisted.dispatch_provenance(), Some(admission.reference()));

    let mut retry_port = restart_port;
    retry_port.dispatch_error = None;
    let mut restarted = ErasureCoordinatorStateMachineV1::new(retry_port, reference(2));
    assert_eq!(
        restarted
            .dispatch_destruction(reference(1), reference(9))?
            .lifecycle(),
        ErasureLifecycleV1::AwaitingAcknowledgements
    );
    Ok(())
}

#[test]
fn durable_record_envelope_round_trips_every_persisted_shape() -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let submitted = record_after_submit()?;
    let records = [
        submitted,
        record_after_freeze(vec![target])?,
        record_after_acknowledgement()?,
        complete_record()?,
    ];
    for record in records {
        let bytes = record.to_canonical_cbor()?;
        let decoded = ErasureCoordinatorRecordV1::from_canonical_cbor(&bytes)?;
        assert_eq!(decoded, record);
        assert_eq!(decoded.to_canonical_cbor()?, bytes);
    }
    Ok(())
}

#[test]
fn coordinator_rehydration_surfaces_port_load_failure() -> Result<(), ErasureErrorV1> {
    let mut coordinator =
        ErasureCoordinatorStateMachineV1::new(test_port(true, Vec::new()), reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.port.load_error = Some(ErasureErrorV1::KeyRegistryUnavailable);
    assert_eq!(
        coordinator.authorize(reference(1), reference(9)),
        Err(ErasureErrorV1::KeyRegistryUnavailable)
    );
    Ok(())
}

#[test]
fn coordinator_rejects_a_host_freeze_closure_mismatch() -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let mut port = test_port(true, vec![target]);
    port.admitted_freeze_closure = Some(reference(99));
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;

    assert_eq!(
        coordinator.freeze_inventory(
            reference(1),
            state_transition(
                ErasureLifecycleV1::AccessFrozen,
                Some(10),
                Vec::new(),
                Vec::new(),
            ),
        ),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn freeze_retry_reuses_the_atomic_host_admission_after_restart() -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let mut port = test_port(true, vec![target]);
    port.commit_error_on_call = Some(3);
    let restart_port = port.clone();
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;

    let requested = state_transition(
        ErasureLifecycleV1::AccessFrozen,
        Some(10),
        Vec::new(),
        Vec::new(),
    );
    assert_eq!(
        coordinator.freeze_inventory(reference(1), requested.clone()),
        Err(ErasureErrorV1::ReceiptCommitFailed)
    );
    assert_eq!(
        coordinator
            .port
            .records
            .borrow()
            .first()
            .map(ErasureCoordinatorRecordV1::targets),
        Some([].as_slice())
    );

    let later_target = acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    drop(coordinator);
    let mut restarted = ErasureCoordinatorStateMachineV1::new(restart_port, reference(2));
    restarted.port.targets = vec![later_target];
    restarted.port.admitted_freeze_position = Some(99);
    restarted.port.admitted_freeze_provenance = Some(reference(99));
    let retry = restarted.freeze_inventory(reference(1), requested)?;
    assert_eq!(retry.lifecycle(), ErasureLifecycleV1::AccessFrozen);
    assert_eq!(retry.freeze_position(), Some(10));
    let records = restarted.port.records.borrow();
    let freeze = records[0]
        .supporting_records()
        .freeze_provenance()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let admission = records[0]
        .supporting_records()
        .freeze_admission_evidence()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let authorization = records[0]
        .supporting_records()
        .freeze_authorization_evidence()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    assert_eq!(freeze.host_evidence(), admission.reference());
    assert_eq!(authorization.evidence(), reference(9).digest());
    assert_eq!(retry.provenance(), freeze.reference());
    assert_eq!(records[0].targets, vec![target]);
    Ok(())
}

#[test]
fn coordinator_rejects_receipt_admission_after_terminal_derivation() -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let mut port = test_port(true, vec![target]);
    port.receipt_error = Some(ErasureErrorV1::TrustSnapshotInvalid);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        state_transition(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    let mut negative = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Negative);
    negative.target = target;
    coordinator.acknowledge(reference(1), negative)?;
    let awaiting = coordinator
        .existing(reference(1))
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let mut terminal_change = state_transition(
        ErasureLifecycleV1::PartialFailure,
        awaiting.freeze_position(),
        Vec::new(),
        vec![negative.owner],
    );
    terminal_change.provenance = reference(4);
    let terminal = awaiting.transition(terminal_change)?;
    let mut input = receipt_input(
        ErasureLifecycleV1::PartialFailure,
        vec![negative],
        Vec::new(),
        vec![negative.owner],
    );
    input.terminal_state = terminal.state_digest();
    input.frozen_targets = vec![target];
    input.inventories.artifacts = vec![inventory_result(target)];
    input.receipt_digest = reference(99);
    assert_eq!(
        coordinator.finalize(reference(1), input),
        Err(ErasureErrorV1::TrustSnapshotInvalid)
    );
    assert_eq!(
        coordinator
            .port
            .receipt_inputs
            .borrow()
            .last()
            .map(|input| input.receipt_digest),
        Some(reference(0))
    );
    Ok(())
}

#[test]
fn coordinator_freezes_closure_and_commits_only_derived_terminal_outcomes(
) -> Result<(), ErasureErrorV1> {
    let ack = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let port = test_port(true, vec![ack.target]);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    assert_eq!(
        coordinator
            .authorize(reference(1), reference(9))?
            .lifecycle(),
        ErasureLifecycleV1::Authorized
    );
    assert_eq!(
        coordinator.authorize(reference(1), reference(8)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let frozen = coordinator.freeze_inventory(
        reference(1),
        state_transition(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    assert_eq!(
        coordinator.freeze_inventory(
            reference(1),
            state_transition(
                ErasureLifecycleV1::AccessFrozen,
                Some(10),
                Vec::new(),
                Vec::new(),
            ),
        )?,
        frozen
    );
    assert_eq!(
        coordinator
            .authorize(reference(1), reference(9))?
            .lifecycle(),
        ErasureLifecycleV1::AccessFrozen
    );
    let mut conflicting_freeze = state_transition(
        ErasureLifecycleV1::Authorized,
        Some(11),
        Vec::new(),
        Vec::new(),
    );
    conflicting_freeze.provenance = reference(8);
    assert_eq!(
        coordinator.freeze_inventory(reference(1), conflicting_freeze),
        Err(ErasureErrorV1::PolicyConflict)
    );
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    assert_eq!(
        coordinator
            .authorize(reference(1), reference(9))?
            .lifecycle(),
        ErasureLifecycleV1::AwaitingAcknowledgements
    );
    assert_eq!(
        coordinator
            .dispatch_destruction(reference(1), reference(9))?
            .lifecycle(),
        ErasureLifecycleV1::AwaitingAcknowledgements
    );
    assert_eq!(
        coordinator.dispatch_destruction(reference(1), reference(8)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        coordinator.acknowledge(reference(1), ack)?,
        coordinator.acknowledge(reference(1), ack)?
    );
    assert_eq!(
        coordinator.port.acknowledgement_admissions.borrow().len(),
        1
    );
    assert_eq!(
        coordinator
            .authorize(reference(1), reference(9))?
            .lifecycle(),
        ErasureLifecycleV1::AwaitingAcknowledgements
    );
    let injected = acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged);
    assert_eq!(
        coordinator.acknowledge(reference(1), injected),
        Err(ErasureErrorV1::Unauthorized)
    );
    let mut conflicting = ack;
    conflicting.outcome = ErasureAcknowledgementOutcomeV1::Negative;
    assert_eq!(
        coordinator.acknowledge(reference(1), conflicting),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        coordinator.port.acknowledgement_admissions.borrow().len(),
        1
    );
    Ok(())
}

#[test]
fn coordinator_rejects_conflicting_non_positive_acknowledgements_before_host_admission(
) -> Result<(), ErasureErrorV1> {
    for outcome in [
        ErasureAcknowledgementOutcomeV1::Negative,
        ErasureAcknowledgementOutcomeV1::Stale,
    ] {
        let acknowledgement = acknowledgement(1, outcome);
        let mut coordinator = ErasureCoordinatorStateMachineV1::new(
            test_port(true, vec![acknowledgement.target]),
            reference(2),
        );
        coordinator.submit(request()?, reference(3))?;
        coordinator.authorize(reference(1), reference(9))?;
        coordinator.freeze_inventory(
            reference(1),
            state_transition(
                ErasureLifecycleV1::AccessFrozen,
                Some(10),
                Vec::new(),
                Vec::new(),
            ),
        )?;
        coordinator.dispatch_destruction(reference(1), reference(9))?;
        coordinator.acknowledge(reference(1), acknowledgement)?;

        let mut conflicting = acknowledgement;
        conflicting.evidence = reference(99);
        assert_eq!(
            coordinator.acknowledge(reference(1), conflicting),
            Err(ErasureErrorV1::PolicyConflict)
        );
        assert_eq!(
            coordinator.port.acknowledgement_admissions.borrow().len(),
            1
        );
    }
    Ok(())
}

#[test]
fn coordinator_normalizes_core_derived_finalize_fields_and_retries() -> Result<(), ErasureErrorV1> {
    let ack = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let mut coordinator =
        ErasureCoordinatorStateMachineV1::new(test_port(true, vec![ack.target]), reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        state_transition(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    coordinator.acknowledge(reference(1), ack)?;
    let awaiting = coordinator
        .existing(reference(1))
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let mut terminal_change = state_transition(
        ErasureLifecycleV1::Complete,
        awaiting.freeze_position(),
        Vec::new(),
        Vec::new(),
    );
    terminal_change.acknowledged_targets = vec![ack.target];
    terminal_change.provenance = reference(4);
    let terminal = awaiting.transition(terminal_change)?;
    let mut complete_input = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![ack],
        Vec::new(),
        Vec::new(),
    );
    complete_input.terminal_state = terminal.state_digest();
    complete_input.inventories.artifacts = vec![inventory_result(ack.target)];
    complete_input.replay_claim = ErasureReplayClaimV1::Exact;
    let mut conflicting_first_finalize = complete_input.clone();
    conflicting_first_finalize.frozen_targets.clear();
    let committed = coordinator.finalize(reference(1), conflicting_first_finalize)?;
    assert_eq!(committed.lifecycle(), ErasureLifecycleV1::Complete);
    assert_eq!(
        committed.replay_claim(),
        ErasureReplayClaimV1::StructuralOnly
    );
    let mut conflicting_identity = complete_input.clone();
    conflicting_identity.terminal_state = reference(99);
    assert_eq!(
        coordinator.finalize(reference(1), complete_input)?,
        committed
    );
    let terminal_state = coordinator
        .existing(reference(1))
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    assert_eq!(coordinator.acknowledge(reference(1), ack)?, terminal_state);
    assert_eq!(
        coordinator.finalize(reference(1), conflicting_identity),
        Ok(committed)
    );
    assert_eq!(
        coordinator
            .existing(reference(1))
            .map(ErasureStateV1::lifecycle),
        Some(ErasureLifecycleV1::Complete)
    );
    Ok(())
}

#[test]
fn coordinator_rejects_each_conflicting_receipt_evidence_retry() -> Result<(), ErasureErrorV1> {
    assert_conflicting_receipt_retry(|input| {
        input.inventories.artifacts[0].transition.reason = reference(99);
    })?;
    assert_conflicting_receipt_retry(|input| input.issue_position = 99)?;
    assert_conflicting_receipt_retry(|input| input.signature = reference(99))?;
    Ok(())
}

#[test]
fn coordinator_derives_partial_failure_for_a_missing_frozen_target() -> Result<(), ErasureErrorV1> {
    let missing = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let mut negative = missing;
    negative.outcome = ErasureAcknowledgementOutcomeV1::Negative;
    let port = test_port(true, vec![missing.target]);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        state_transition(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    coordinator.acknowledge(reference(1), negative)?;
    let awaiting = coordinator
        .existing(reference(1))
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let mut terminal_change = state_transition(
        ErasureLifecycleV1::PartialFailure,
        awaiting.freeze_position(),
        Vec::new(),
        vec![negative.owner],
    );
    terminal_change.provenance = reference(4);
    let terminal = awaiting.transition(terminal_change)?;
    let mut input = receipt_input(
        ErasureLifecycleV1::PartialFailure,
        vec![negative],
        Vec::new(),
        vec![negative.owner],
    );
    input.terminal_state = terminal.state_digest();
    input.frozen_targets = vec![missing.target];
    input.inventories.artifacts = vec![inventory_result(missing.target)];
    assert_eq!(
        coordinator.finalize(reference(1), input)?.lifecycle(),
        ErasureLifecycleV1::PartialFailure
    );
    Ok(())
}
#[test]
fn coordinator_rejects_premature_finalize_and_preserves_awaiting_acknowledgements(
) -> Result<(), ErasureErrorV1> {
    let first = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let mut second = acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged);
    second.owner = second.target.replica_id;
    let port = test_port(true, vec![first.target, second.target]);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        state_transition(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    assert_eq!(
        coordinator.finalize(
            reference(1),
            receipt_input(
                ErasureLifecycleV1::Complete,
                vec![first],
                Vec::new(),
                Vec::new(),
            ),
        ),
        Err(ErasureErrorV1::PolicyConflict)
    );
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    coordinator.acknowledge(reference(1), first)?;
    assert_eq!(
        coordinator.acknowledge(reference(1), second)?.lifecycle(),
        ErasureLifecycleV1::AwaitingAcknowledgements
    );
    Ok(())
}
#[test]
fn coordinator_rejects_unauthenticated_submission_and_unsupported_version(
) -> Result<(), ErasureErrorV1> {
    let port = test_port(false, Vec::new());
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    assert_eq!(
        coordinator.submit(request()?, reference(3)),
        Err(ErasureErrorV1::Unauthorized)
    );
    let mut value = public_receipt_value(&receipt()?)?;
    let Value::Array(fields) = &mut value else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    fields[1] = test_uint(2);
    assert_eq!(
        decode_receipt(&value),
        Err(ErasureErrorV1::UnsupportedVersion)
    );
    Ok(())
}
#[test]
fn receipt_history_requires_a_resolved_monotonic_terminal_chain() -> Result<(), ErasureErrorV1> {
    let submitted = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    let authorized = submitted.transition(state_transition(
        ErasureLifecycleV1::Authorized,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    let frozen = authorized.transition(state_transition(
        ErasureLifecycleV1::AccessFrozen,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let dispatched = frozen.transition(state_transition(
        ErasureLifecycleV1::DestructionDispatched,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let waiting = dispatched.transition(state_transition(
        ErasureLifecycleV1::AwaitingAcknowledgements,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let terminal = waiting.transition(ErasureStateTransitionV1 {
        lifecycle: ErasureLifecycleV1::Complete,
        freeze_position: Some(10),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        acknowledged_targets: vec![
            acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target,
        ],
        replay_claim: ErasureReplayClaimV1::StructuralOnly,
        provenance: reference(9),
    })?;
    let mut input = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![acknowledgement(
            1,
            ErasureAcknowledgementOutcomeV1::Acknowledged,
        )],
        Vec::new(),
        Vec::new(),
    );
    input.terminal_state = terminal.state_digest();
    let receipt = ErasureReceiptV1::new(input)?;
    assert_eq!(
        receipt.verify_history(&TestResolver {
            states: vec![terminal.clone()],
            unavailable: false,
        }),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let resolver = TestResolver {
        states: vec![submitted, authorized, frozen, dispatched, waiting, terminal],
        unavailable: false,
    };
    receipt.verify_history(&resolver)?;
    assert_eq!(
        receipt.verify_history(&FailingPredecessorResolver {
            terminal: resolver
                .states
                .last()
                .cloned()
                .ok_or(ErasureErrorV1::ProvenanceMissing)?,
        }),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        receipt.verify_history(&TestResolver {
            states: Vec::new(),
            unavailable: false,
        }),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        receipt.verify_history(&TestResolver {
            states: Vec::new(),
            unavailable: true,
        }),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}
#[test]
fn receipt_inventory_codes_and_strict_decoder_paths_are_publicly_exercised(
) -> Result<(), ErasureErrorV1> {
    let encoded = receipt_inventory_encoding()?;
    receipt_inventory_decoder_rejections(&encoded)
}

fn receipt_inventory_encoding() -> Result<Vec<u8>, ErasureErrorV1> {
    let mut acknowledgements = vec![
        acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged),
        acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged),
        acknowledgement(3, ErasureAcknowledgementOutcomeV1::Acknowledged),
        acknowledgement(4, ErasureAcknowledgementOutcomeV1::Acknowledged),
        acknowledgement(5, ErasureAcknowledgementOutcomeV1::Acknowledged),
        acknowledgement(6, ErasureAcknowledgementOutcomeV1::Acknowledged),
        acknowledgement(7, ErasureAcknowledgementOutcomeV1::Acknowledged),
    ];
    acknowledgements[1].target.artifact_class = ErasureArtifactClassV1::ReproManifest;
    acknowledgements[1].target.key_role = ErasureKeyRoleV1::Signing;
    acknowledgements[2].target.artifact_class = ErasureArtifactClassV1::CausalTrace;
    acknowledgements[2].target.key_role = ErasureKeyRoleV1::BackupEnvelope;
    acknowledgements[3].target.artifact_class = ErasureArtifactClassV1::ConformanceReport;
    acknowledgements[3].target.key_role = ErasureKeyRoleV1::ReplicaTransport;
    acknowledgements[4].target.artifact_class = ErasureArtifactClassV1::CalibrationReport;
    acknowledgements[5].target.artifact_class = ErasureArtifactClassV1::Export;
    acknowledgements[6].target.artifact_class = ErasureArtifactClassV1::ForkOrSnapshot;
    for (acknowledgement, category) in acknowledgements.iter_mut().zip(
        ErasureInventoryCategoryV1::CANONICAL
            .into_iter()
            .chain([ErasureInventoryCategoryV1::Artifact; 3]),
    ) {
        acknowledgement.obligation = ErasureObligationV1::new(ErasureObligationInputV1 {
            category,
            target: acknowledgement.target,
            owner: acknowledgement.owner,
            command_identity: destruction_command_reference(reference(1), acknowledgement.target),
        })?
        .reference();
    }
    let mut input = receipt_input(
        ErasureLifecycleV1::Complete,
        acknowledgements.clone(),
        Vec::new(),
        Vec::new(),
    );
    input.inventories.artifacts = vec![
        inventory_result(acknowledgements[0].target),
        inventory_result(acknowledgements[4].target),
        inventory_result(acknowledgements[5].target),
        inventory_result(acknowledgements[6].target),
    ];
    input.inventories.keys = vec![inventory_result(acknowledgements[1].target)];
    input.inventories.keys[0].category = ErasureInventoryCategoryV1::Key;
    input.inventories.replicas = vec![inventory_result(acknowledgements[2].target)];
    input.inventories.replicas[0].category = ErasureInventoryCategoryV1::Replica;
    input.inventories.backups = vec![inventory_result(acknowledgements[3].target)];
    input.inventories.backups[0].category = ErasureInventoryCategoryV1::Backup;
    let expected = ErasureReceiptV1::new(input)?;
    let encoded = expected.to_canonical_cbor()?;
    assert_eq!(ErasureReceiptV1::from_canonical_cbor(&encoded)?, expected);
    Ok(encoded)
}

fn receipt_inventory_decoder_rejections(encoded: &[u8]) -> Result<(), ErasureErrorV1> {
    let mut unknown_codes = public_receipt_value(&ErasureReceiptV1::from_canonical_cbor(encoded)?)?;
    let mut tampered_digest = unknown_codes.clone();
    let Value::Array(fields) = &mut tampered_digest else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    fields[16] = test_digest(reference(99));
    assert_eq!(
        decode_receipt(&tampered_digest),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let Value::Array(fields) = &mut unknown_codes else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(targets) = &mut fields[6] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(target) = &mut targets[0] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    target[0] = test_uint(7);
    assert_eq!(
        decode_receipt(&unknown_codes),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    let mut unknown_role = public_receipt_value(&ErasureReceiptV1::from_canonical_cbor(encoded)?)?;
    let Value::Array(fields) = &mut unknown_role else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(targets) = &mut fields[6] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(target) = &mut targets[0] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    target[2] = test_uint(4);
    assert_eq!(
        decode_receipt(&unknown_role),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    let mut unordered_targets =
        public_receipt_value(&ErasureReceiptV1::from_canonical_cbor(encoded)?)?;
    let Value::Array(fields) = &mut unordered_targets else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(targets) = &mut fields[6] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    targets.swap(0, 1);
    assert_eq!(
        decode_receipt(&unordered_targets),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert_eq!(
        ErasureReceiptV1::from_canonical_cbor(&trailing),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    let noncanonical = [&[0x98, 18][..], &encoded[1..]].concat();
    assert_eq!(
        ErasureReceiptV1::from_canonical_cbor(&noncanonical),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    for invalid in [
        &[0x9f, 0xff][..],
        &[0xbf, 0xff][..],
        &[0x19, 0, 1][..],
        &[0x1b, 0, 0, 0, 0, 0, 0, 0, 1][..],
        &[0x9a, 0xff, 0xff, 0xff, 0xff][..],
        &[
            0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81,
            0x81, 0x81, 0x81, 0x00,
        ][..],
    ] {
        assert_eq!(
            ErasureReceiptV1::from_canonical_cbor(invalid),
            Err(ErasureErrorV1::InvalidEncoding)
        );
    }
    Ok(())
}
#[test]
fn coordinator_and_receipt_reject_each_public_injected_or_stale_seam() -> Result<(), ErasureErrorV1>
{
    coordinator_public_seam_rejections()?;
    receipt_public_seam_rejections();
    Ok(())
}

fn coordinator_public_seam_rejections() -> Result<(), ErasureErrorV1> {
    let ack = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let port = test_port(true, vec![ack.target]);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    assert_eq!(
        coordinator
            .authorize(reference(1), reference(9))?
            .lifecycle(),
        ErasureLifecycleV1::Authorized
    );
    let frozen = coordinator.freeze_inventory(
        reference(1),
        state_transition(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    assert_eq!(frozen.lifecycle(), ErasureLifecycleV1::AccessFrozen);
    assert_eq!(
        coordinator.freeze_inventory(
            reference(1),
            state_transition(
                ErasureLifecycleV1::AccessFrozen,
                Some(10),
                Vec::new(),
                Vec::new(),
            ),
        )?,
        frozen
    );
    assert_eq!(
        coordinator.acknowledge(reference(1), ack),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        coordinator.finalize(
            reference(1),
            receipt_input(
                ErasureLifecycleV1::Complete,
                vec![ack],
                Vec::new(),
                Vec::new(),
            ),
        ),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

fn receipt_public_seam_rejections() {
    let ack = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let mut stale_issue = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![ack],
        Vec::new(),
        Vec::new(),
    );
    stale_issue.issue_position = 9;
    assert_eq!(
        ErasureReceiptV1::new(stale_issue),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let mut invented_ack = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![ack],
        Vec::new(),
        Vec::new(),
    );
    invented_ack.acknowledgements[0].target =
        acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    assert_eq!(
        ErasureReceiptV1::new(invented_ack),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let mut mismatched_owner = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![ack],
        Vec::new(),
        Vec::new(),
    );
    mismatched_owner.acknowledgements[0].owner = reference(99);
    assert_eq!(
        ErasureReceiptV1::new(mismatched_owner),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let mut missing_inventory = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![ack],
        Vec::new(),
        Vec::new(),
    );
    missing_inventory.inventories.artifacts.clear();
    assert_eq!(
        ErasureReceiptV1::new(missing_inventory),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let mut oversized = receipt_input(
        ErasureLifecycleV1::PartialFailure,
        Vec::new(),
        vec![reference(8)],
        Vec::new(),
    );
    oversized.acknowledgements = vec![ack; ERASURE_MAX_INVENTORY_RESULTS + 1];
    assert_eq!(
        ErasureReceiptV1::new(oversized),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let mut strengthened = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![ack],
        Vec::new(),
        Vec::new(),
    );
    strengthened.inventories.artifacts[0].transition.from = ErasureReplayClaimV1::StructuralOnly;
    strengthened.inventories.artifacts[0].transition.to = ErasureReplayClaimV1::Exact;
    assert_eq!(
        ErasureReceiptV1::new(strengthened),
        Err(ErasureErrorV1::PolicyConflict)
    );
    for invalid in [&[0x18, 0][..], &[0x1a, 0, 0, 0, 1][..], &[0x60, 0][..]] {
        assert_eq!(
            ErasureReceiptV1::from_canonical_cbor(invalid),
            Err(ErasureErrorV1::InvalidEncoding)
        );
    }
}

#[test]
fn receipt_public_inventory_and_closure_boundaries() {
    let ack = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let mut oversized_inventory = receipt_input(
        ErasureLifecycleV1::PartialFailure,
        Vec::new(),
        vec![reference(8)],
        Vec::new(),
    );
    oversized_inventory.inventories.artifacts =
        vec![inventory_result(ack.target); ERASURE_MAX_INVENTORY_RESULTS + 1];
    assert_eq!(
        ErasureReceiptV1::new(oversized_inventory),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let second_target = acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let mut incomplete_closure = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![ack],
        vec![second_target.owner],
        Vec::new(),
    );
    incomplete_closure.frozen_targets.push(second_target.target);
    incomplete_closure
        .inventories
        .artifacts
        .push(inventory_result(second_target.target));
    assert_eq!(
        ErasureReceiptV1::new(incomplete_closure),
        Err(ErasureErrorV1::PolicyConflict)
    );
}

#[test]
fn codec_predicates_and_cbor_argument_widths_are_closed_at_the_public_boundary() {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let inventory = inventory_result(target);
    let mut inventories = ErasureReceiptInventoriesV1 {
        artifacts: Vec::new(),
        keys: Vec::new(),
        replicas: Vec::new(),
        backups: Vec::new(),
    };
    inventories.artifacts.push(inventory);
    inventories.keys.push(ErasureInventoryResultV1 {
        category: ErasureInventoryCategoryV1::Key,
        ..inventory
    });
    inventories.replicas.push(ErasureInventoryResultV1 {
        category: ErasureInventoryCategoryV1::Replica,
        ..inventory
    });
    inventories.backups.push(ErasureInventoryResultV1 {
        category: ErasureInventoryCategoryV1::Backup,
        ..inventory
    });
    assert!(!inventories_exceed_bound(&inventories));

    inventories.artifacts =
        std::iter::repeat_n(inventory_result(target), ERASURE_MAX_INVENTORY_RESULTS).collect();
    assert!(!inventories_exceed_bound(&inventories));
    inventories.artifacts.clear();
    inventories.keys =
        std::iter::repeat_n(inventory_result(target), ERASURE_MAX_INVENTORY_RESULTS).collect();
    assert!(!inventories_exceed_bound(&inventories));
    inventories.keys.clear();
    inventories.replicas =
        std::iter::repeat_n(inventory_result(target), ERASURE_MAX_INVENTORY_RESULTS).collect();
    assert!(!inventories_exceed_bound(&inventories));
    inventories.replicas.clear();
    inventories.backups =
        std::iter::repeat_n(inventory_result(target), ERASURE_MAX_INVENTORY_RESULTS).collect();
    assert!(!inventories_exceed_bound(&inventories));
    inventories.backups.clear();
    inventories.artifacts.push(inventory);
    inventories.keys.push(inventory);
    inventories.replicas.push(inventory);
    inventories.backups.push(inventory);

    for inventory in [
        &mut inventories.artifacts,
        &mut inventories.keys,
        &mut inventories.replicas,
        &mut inventories.backups,
    ] {
        let first = inventory[0];
        inventory.push(first);
        assert!(has_duplicate_by_inventory_target(inventory));
        inventory.clear();
    }
    inventories.artifacts =
        std::iter::repeat_n(inventory_result(target), ERASURE_MAX_INVENTORY_RESULTS + 1).collect();
    assert!(inventories_exceed_bound(&inventories));
    inventories.artifacts.clear();
    inventories.keys =
        std::iter::repeat_n(inventory_result(target), ERASURE_MAX_INVENTORY_RESULTS + 1).collect();
    assert!(inventories_exceed_bound(&inventories));
    inventories.keys.clear();
    inventories.replicas =
        std::iter::repeat_n(inventory_result(target), ERASURE_MAX_INVENTORY_RESULTS + 1).collect();
    assert!(inventories_exceed_bound(&inventories));
    inventories.replicas.clear();
    inventories.backups =
        std::iter::repeat_n(inventory_result(target), ERASURE_MAX_INVENTORY_RESULTS + 1).collect();
    assert!(inventories_exceed_bound(&inventories));
    inventories.backups.clear();
}

#[test]
fn inventory_category_duplicates_are_rejected() {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    assert!(inventories_have_duplicate_targets(
        &ErasureReceiptInventoriesV1 {
            artifacts: vec![inventory_result(target), inventory_result(target)],
            keys: Vec::new(),
            replicas: Vec::new(),
            backups: Vec::new(),
        }
    ));
    assert!(inventories_have_duplicate_targets(
        &ErasureReceiptInventoriesV1 {
            artifacts: Vec::new(),
            keys: vec![inventory_result(target), inventory_result(target)],
            replicas: Vec::new(),
            backups: Vec::new(),
        }
    ));
    assert!(inventories_have_duplicate_targets(
        &ErasureReceiptInventoriesV1 {
            artifacts: Vec::new(),
            keys: Vec::new(),
            replicas: vec![inventory_result(target), inventory_result(target)],
            backups: Vec::new(),
        }
    ));
    assert!(inventories_have_duplicate_targets(
        &ErasureReceiptInventoriesV1 {
            artifacts: Vec::new(),
            keys: Vec::new(),
            replicas: Vec::new(),
            backups: vec![inventory_result(target), inventory_result(target)],
        }
    ));
}

#[test]
fn owner_sets_are_closed_at_the_public_boundary() {
    let owner = reference(70);
    assert!(invalid_owner_sets(&[owner], &[owner]));
    assert!(!invalid_owner_sets(&[reference(70)], &[reference(71)]));
}

#[test]
fn cbor_argument_widths_are_closed_at_the_public_boundary() {
    assert_eq!(cbor_argument(&[0x01, 0x00], 0, 25), Ok((256, 2)));
    assert_eq!(
        cbor_argument(&[0x00, 0x01, 0x00, 0x00], 0, 26),
        Ok((65_536, 4))
    );
    assert_eq!(
        cbor_argument(&[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00], 0, 27),
        Ok((4_294_967_296, 8))
    );
    assert_eq!(
        cbor_argument(&[0x00, 0x00], 0, 25),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        cbor_argument_bytes(&[0x00, 0x00, 0x00, 0x00], 0, 4, 65_536),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        cbor_item_end(&[0x01], 0, 16, ERASURE_MAX_INVENTORY_RESULTS),
        Ok(1)
    );
    assert_eq!(
        cbor_item_end(&[0x42, 0xaa], 0, 0, ERASURE_MAX_INVENTORY_RESULTS),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        cbor_shape_is_bounded(&[0x83, 0x01, 0x01, 0x01], 2,),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        cbor_item_end(&[0xf8, 0x17], 0, 0, ERASURE_MAX_INVENTORY_RESULTS),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        cbor_item_end(&[0xf7], 0, 0, ERASURE_MAX_INVENTORY_RESULTS),
        Err(ErasureErrorV1::InvalidEncoding)
    );
}

#[test]
fn coordinator_requires_host_admission_for_acknowledgements() -> Result<(), ErasureErrorV1> {
    let ack = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let mut port = test_port(true, vec![ack.target]);
    port.acknowledgement_admitted = false;
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        state_transition(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    assert_eq!(
        coordinator.acknowledge(reference(1), ack),
        Err(ErasureErrorV1::Unauthorized)
    );

    let valid_ack = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let port = test_port(true, vec![valid_ack.target]);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        state_transition(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    coordinator
        .port
        .records
        .borrow_mut()
        .first_mut()
        .and_then(|record| record.supporting_records.retry_admissions.last_mut())
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .input
        .command_identities[0] = reference(99);
    assert_eq!(
        coordinator.acknowledge(reference(1), valid_ack),
        Err(ErasureErrorV1::Unauthorized)
    );
    Ok(())
}
#[test]
fn public_erasure_failure_seams_cover_history_ordering_and_cbor_tails() -> Result<(), ErasureErrorV1>
{
    let receipt = receipt()?;
    assert_eq!(
        receipt.verify_history(&TestResolver {
            states: Vec::new(),
            unavailable: false,
        }),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        receipt.verify_history(&TestResolver {
            states: Vec::new(),
            unavailable: true,
        }),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let mut unordered = public_receipt_value(&receipt)?;
    let Value::Array(fields) = &mut unordered else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(inventories) = &mut fields[10] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(artifacts) = &mut inventories[0] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    artifacts.push(artifacts[0].clone());
    assert_eq!(
        decode_receipt(&unordered),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    for malformed in [
        &[0x58, 1][..],
        &[0x81, 0x58, 2, 0][..],
        &[0x81, 0x1a, 0, 0, 0][..],
        &[0x81, 0x58, 2, 0, 0][..],
        &[0x81, 0x1b, 0, 0, 0, 0, 0, 0, 0, 1][..],
        &[0x81, 0x78, 2, 0][..],
        &[0x81, 0x98, 24][..],
        &[0x81, 0x7f, 0xff][..],
    ] {
        assert_eq!(
            ErasureReceiptV1::from_canonical_cbor(malformed),
            Err(ErasureErrorV1::InvalidEncoding)
        );
    }
    Ok(())
}

#[test]
fn codec_size_and_shape_limits_return_closed_errors() {
    assert_eq!(
        encode_limited(&Value::Text("oversized".to_owned()), 0),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        array(&Value::Array(vec![Value::Null, Value::Null]), 1),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(array(&Value::Null, 1), Err(ErasureErrorV1::InvalidEncoding));
    assert_eq!(
        decode_limited(
            &[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            32,
            4,
        ),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        decode_limited(&[0xf7], 32, 4),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        decode_limited(&[0xe0], 32, 4),
        Err(ErasureErrorV1::InvalidEncoding)
    );
}

#[test]
fn request_is_canonical_and_bounded() -> Result<(), ErasureErrorV1> {
    let first = request()?;
    let second = ErasureRequestV1::new(request_input(vec![reference(7), reference(8)]))?;
    let bytes = first.to_canonical_cbor()?;
    assert_eq!(bytes, second.to_canonical_cbor()?);
    assert_eq!(ErasureRequestV1::from_canonical_cbor(&bytes)?, first);
    assert_eq!(first.reference(), reference(1));
    assert_eq!(
        ErasureRequestV1::new(request_input(Vec::new())),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        ErasureRequestV1::new(request_input(vec![reference(7), reference(7)])),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let mut impossible = request_input(vec![reference(7)]);
    impossible.request_position = 11;
    assert_eq!(
        ErasureRequestV1::new(impossible),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}
#[test]
fn public_constants_display_and_state_digests_are_observable() -> Result<(), ErasureErrorV1> {
    assert_eq!(ERASURE_REQUEST_OR_STATE_MAX_BYTES, 1_048_576);
    assert_eq!(ERASURE_RECEIPT_MAX_BYTES, 16_777_216);
    assert_eq!(ERASURE_COORDINATOR_RECORD_MAX_BYTES, 67_108_864);
    assert_eq!(ERASURE_PORTABLE_RECORD_MAX_BYTES, 1_048_576);
    assert_eq!(ERASURE_SCOPE_LEDGER_MAX_BYTES, 16_777_216);
    assert_eq!(ERASURE_OBLIGATION_SET_MAX_BYTES, 16_777_216);
    assert_eq!(ERASURE_FREEZE_ADMISSION_EVIDENCE_MAX_BYTES, 16_777_216);
    assert_eq!(ERASURE_RETRY_ADMISSION_MAX_BYTES, 16_777_216);
    assert_eq!(
        ErasureErrorV1::PolicyConflict.to_string(),
        "erasure contract error 4"
    );
    let first = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    let second = ErasureStateV1::submitted(reference(4), reference(2), reference(3))?;
    assert_ne!(first.state_digest(), second.state_digest());
    Ok(())
}

#[test]
fn applicability_matrix_cardinality_accepts_only_complete_bounded_categories() {
    assert!(!applicability_matrix_cardinality_is_valid(0));
    assert!(!applicability_matrix_cardinality_is_valid(1));
    assert!(applicability_matrix_cardinality_is_valid(4));
    assert!(applicability_matrix_cardinality_is_valid(
        ERASURE_MAX_OBLIGATIONS
    ));
    assert!(!applicability_matrix_cardinality_is_valid(
        ERASURE_MAX_OBLIGATIONS + 1
    ));
}

#[test]
fn evidence_cardinality_predicates_accept_their_exact_limits() {
    assert!(obligation_count_is_bounded(ERASURE_MAX_OBLIGATIONS));
    assert!(!obligation_count_is_bounded(ERASURE_MAX_OBLIGATIONS + 1));
    assert!(category_obligation_count_is_bounded(
        ERASURE_MAX_OBLIGATIONS_PER_CATEGORY
    ));
    assert!(!category_obligation_count_is_bounded(
        ERASURE_MAX_OBLIGATIONS_PER_CATEGORY + 1
    ));
    assert!(scope_extension_count_is_bounded(
        ERASURE_MAX_SCOPE_EXTENSIONS
    ));
    assert!(!scope_extension_count_is_bounded(
        ERASURE_MAX_SCOPE_EXTENSIONS + 1
    ));
}

#[test]
fn freeze_evidence_references_are_content_addresses() -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let (admission, _) = lineage_freeze_admission(target, reference(72))?;
    let admission_evidence = admission.freeze_admission_evidence();
    let authorization_evidence = admission.freeze_authorization_evidence();

    assert_ne!(admission_evidence.reference(), reference_zero());
    assert_ne!(authorization_evidence.reference(), reference_zero());
    assert_eq!(
        ErasureFreezeAdmissionEvidenceV1::from_canonical_cbor(
            &admission_evidence.to_canonical_cbor()?
        )?
        .reference(),
        admission_evidence.reference()
    );
    assert_eq!(
        ErasureFreezeAuthorizationEvidenceV1::from_canonical_cbor(
            &authorization_evidence.to_canonical_cbor()?
        )?
        .reference(),
        authorization_evidence.reference()
    );
    Ok(())
}

#[test]
fn exclusive_supporting_records_reject_every_individual_conflict() -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let frozen = record_after_freeze(vec![target])?;
    let source = supporting_records_input(frozen.supporting_records());
    let scope = source
        .scope_commitment
        .as_ref()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let extension = ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
        request: reference(1),
        scope_commitment: scope.reference(),
        fork: reference(73),
        lineage_rule: reference(72),
        predecessor_extension: None,
        admission_provenance: reference(74),
    })?;
    let ledger = ErasureScopeExtensionLedgerV1::new(ErasureScopeExtensionLedgerInputV1 {
        scope_commitment: scope.reference(),
        extensions: Vec::new(),
        head: None,
    })?;
    let rejection = ErasureAuthorizationRejectionV1::new(ErasureAuthorizationRejectionInputV1 {
        request: reference(1),
        authorization_provenance: reference(9),
    })?;
    let failure = ErasureFreezeFailureV1::new(ErasureFreezeFailureInputV1 {
        request: reference(1),
        error: ErasureErrorV1::AccessFreezeFailed,
        authorization_provenance: reference(9),
        evidence: reference(10),
    })?;

    let mut conflicts = Vec::new();
    for rejected in [true, false] {
        let mut base = ErasureSupportingRecordsInputV1::default();
        if rejected {
            base.authorization_rejection = Some(rejection);
        } else {
            base.freeze_failure = Some(failure);
        }

        let mut input = base.clone();
        input.scope_commitment = source.scope_commitment.clone();
        conflicts.push(input);
        let mut input = base.clone();
        input.freeze_admission_evidence = source.freeze_admission_evidence.clone();
        conflicts.push(input);
        let mut input = base.clone();
        input.freeze_authorization_evidence = source.freeze_authorization_evidence.clone();
        conflicts.push(input);
        let mut input = base.clone();
        input.freeze_provenance = source.freeze_provenance;
        conflicts.push(input);
        let mut input = base.clone();
        input.obligation_set = source.obligation_set.clone();
        conflicts.push(input);
        let mut input = base.clone();
        input.obligations = source.obligations.clone();
        conflicts.push(input);
        let mut input = base.clone();
        input.scope_extensions = vec![extension];
        conflicts.push(input);
        let mut input = base;
        input.scope_extension_ledgers = vec![ledger.clone()];
        conflicts.push(input);
    }
    for conflict in conflicts {
        assert_eq!(
            ErasureSupportingRecordsV1::new(conflict),
            Err(ErasureErrorV1::PolicyConflict)
        );
    }

    Ok(())
}

#[test]
fn supporting_records_reject_each_independent_missing_scope_dependency(
) -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let frozen = record_after_freeze(vec![target])?;
    let source = supporting_records_input(frozen.supporting_records());
    let extension = ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
        request: reference(1),
        scope_commitment: reference(70),
        fork: reference(73),
        lineage_rule: reference(72),
        predecessor_extension: None,
        admission_provenance: reference(74),
    })?;
    let ledger = ErasureScopeExtensionLedgerV1::new(ErasureScopeExtensionLedgerInputV1 {
        scope_commitment: reference(70),
        extensions: Vec::new(),
        head: None,
    })?;

    let missing_scope_cases = [
        ErasureSupportingRecordsInputV1 {
            obligation_set: source.obligation_set,
            ..ErasureSupportingRecordsInputV1::default()
        },
        ErasureSupportingRecordsInputV1 {
            scope_extensions: vec![extension],
            ..ErasureSupportingRecordsInputV1::default()
        },
        ErasureSupportingRecordsInputV1 {
            scope_extension_ledgers: vec![ledger],
            ..ErasureSupportingRecordsInputV1::default()
        },
    ];
    for missing_scope in missing_scope_cases {
        assert_eq!(
            ErasureSupportingRecordsV1::new(missing_scope),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
    }
    Ok(())
}

#[test]
fn supporting_records_require_provenance_for_partial_freeze_evidence() -> Result<(), ErasureErrorV1>
{
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let frozen = record_after_freeze(vec![target])?;
    let mut input = supporting_records_input(frozen.supporting_records());
    input.freeze_provenance = None;
    input.freeze_authorization_evidence = None;

    assert_eq!(
        ErasureSupportingRecordsV1::new(input),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn obligation_evidence_rejects_duplicate_command_owner_across_categories(
) -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let frozen = record_after_freeze(vec![target])?;
    let mut records = frozen.supporting_records().clone();
    let artifact = records.obligations[0];
    let key = ErasureObligationV1::new(ErasureObligationInputV1 {
        category: ErasureInventoryCategoryV1::Key,
        target,
        owner: artifact.owner(),
        command_identity: artifact.command_identity(),
    })?;
    records.obligations.push(key);
    records
        .obligations
        .sort_unstable_by_key(ErasureObligationV1::reference);
    records.obligation_set = Some(ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
        request: reference(1),
        obligations: records
            .obligations
            .iter()
            .map(ErasureObligationV1::reference)
            .collect(),
        policy: reference(5),
        trust: reference(3),
    })?);

    assert_eq!(
        records.validate_obligation_evidence(),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn scope_extension_ledger_rejects_an_independently_wrong_extension_prefix(
) -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let (admission, _) = lineage_freeze_admission(target, reference(72))?;
    let port = test_port(true, vec![target]);
    port.freeze_reservation.borrow_mut().replace(admission);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        state_transition(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    let mut records = coordinator.record(reference(1))?.supporting_records;
    records.scope_extension_ledgers[0].input.extensions = vec![reference(99)];

    assert_eq!(
        records.validate_scope_extension_evidence(),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn acknowledgement_validation_rejects_each_independent_binding_mismatch(
) -> Result<(), ErasureErrorV1> {
    let acknowledged = record_after_acknowledgement()?;
    let baseline = acknowledged.supporting_records().clone();

    let mut wrong_request = baseline.clone();
    wrong_request.acknowledgement_provenance[0].input.request = reference(90);
    assert_eq!(
        wrong_request.validate_acknowledgements(),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut missing_pair = baseline.clone();
    missing_pair.obligations[0].input.command_identity = reference(90);
    missing_pair.acknowledgement_provenance[0].input.command = reference(90);
    assert_eq!(
        missing_pair.validate_acknowledgements(),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut wrong_obligation_command = baseline.clone();
    wrong_obligation_command.obligations[0]
        .input
        .command_identity = reference(90);
    assert_eq!(
        wrong_obligation_command.validate_acknowledgements(),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut wrong_owner = baseline.clone();
    wrong_owner.acknowledgement_provenance[0].input.owner = reference(90);
    assert_eq!(
        wrong_owner.validate_acknowledgements(),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut wrong_scope = baseline.clone();
    wrong_scope.acknowledgement_provenance[0].input.scope = reference(90);
    assert_eq!(
        wrong_scope.validate_acknowledgements(),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut wrong_policy = baseline.clone();
    wrong_policy.acknowledgement_provenance[0].input.policy = reference(90);
    assert_eq!(
        wrong_policy.validate_acknowledgements(),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut wrong_trust = baseline;
    wrong_trust.acknowledgement_provenance[0].input.trust = reference(90);
    assert_eq!(
        wrong_trust.validate_acknowledgements(),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn effective_acknowledgements_select_only_the_earliest_matching_positive_evidence(
) -> Result<(), ErasureErrorV1> {
    let acknowledged = record_after_acknowledgement()?;
    let baseline = acknowledged.supporting_records().clone();
    let admission_0 = baseline.retry_admissions[0].clone();
    let admission_1 = retry_admission_at(&admission_0, 1, 81)?;
    let admission_2 = retry_admission_at(&admission_0, 2, 82)?;
    let provenance_0 = acknowledgement_provenance_for(
        &baseline.acknowledgement_provenance[0],
        &admission_0,
        ErasureAcknowledgementOutcomeV1::Acknowledged,
        83,
    )?;
    let provenance_1 = acknowledgement_provenance_for(
        &baseline.acknowledgement_provenance[0],
        &admission_1,
        ErasureAcknowledgementOutcomeV1::Acknowledged,
        84,
    )?;

    let mut records = baseline;
    records.retry_admissions = vec![admission_0.clone(), admission_1.clone()];
    records.acknowledgement_provenance = vec![provenance_0];
    let selected = records.effective_acknowledgement_provenance(&admission_1);
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].1.reference(), provenance_0.reference());

    let mut wrong_obligation = provenance_0;
    wrong_obligation.input.obligation = reference(90);
    wrong_obligation = wrong_obligation.with_digest()?;
    records.acknowledgement_provenance = vec![wrong_obligation];
    assert!(records
        .effective_acknowledgement_provenance(&admission_1)
        .is_empty());

    let mut wrong_owner = provenance_0;
    wrong_owner.input.owner = reference(91);
    wrong_owner = wrong_owner.with_digest()?;
    records.acknowledgement_provenance = vec![wrong_owner];
    assert!(records
        .effective_acknowledgement_provenance(&admission_1)
        .is_empty());

    let negative = acknowledgement_provenance_for(
        &provenance_0,
        &admission_0,
        ErasureAcknowledgementOutcomeV1::Negative,
        85,
    )?;
    records.acknowledgement_provenance = vec![negative];
    assert!(records
        .effective_acknowledgement_provenance(&admission_1)
        .is_empty());

    records.acknowledgement_provenance = vec![provenance_1];
    assert!(records
        .effective_acknowledgement_provenance(&admission_0)
        .is_empty());

    records.acknowledgement_provenance = vec![provenance_0, provenance_1];
    let selected = records.effective_acknowledgement_provenance(&admission_1);
    assert_eq!(selected[0].1.reference(), provenance_0.reference());

    let equal_ordinal_query = retry_admission_at(&admission_0, 0, 86)?;
    records.retry_admissions = vec![admission_0.clone()];
    records.acknowledgement_provenance = vec![provenance_0];
    assert_eq!(
        records.effective_acknowledgement_provenance(&equal_ordinal_query)[0]
            .1
            .reference(),
        provenance_0.reference()
    );

    records.retry_admissions = vec![admission_1, admission_0.clone()];
    records.acknowledgement_provenance = vec![provenance_0, provenance_1];
    assert_eq!(
        records.effective_acknowledgement_provenance(&admission_2)[0]
            .1
            .reference(),
        provenance_0.reference()
    );

    records.retry_admissions = vec![admission_0];
    records.acknowledgement_provenance = vec![provenance_0, provenance_0];
    let selected = records.effective_acknowledgement_provenance(&admission_2);
    assert!(std::ptr::eq(
        selected[0].1,
        records.acknowledgement_provenance.as_ptr()
    ));
    Ok(())
}

#[test]
fn supporting_record_prefix_rejects_removal_and_replacement() -> Result<(), ErasureErrorV1> {
    assert!(!option_is_unchanged(Some(&1_u8), None));
    assert!(!option_is_unchanged(Some(&1_u8), Some(&2_u8)));
    assert!(option_is_unchanged(None::<&u8>, Some(&2_u8)));

    let current = record_after_acknowledgement()?.supporting_records().clone();
    let mut next = current.clone();
    next.retry_admissions.clear();
    assert!(!current.is_prefix_of(&next));
    Ok(())
}

#[test]
fn lifecycle_and_rejection_guards_reject_each_independent_conflict() -> Result<(), ErasureErrorV1> {
    let submitted = record_after_submit()?;
    let mut submitted_with_resolution = submitted.clone();
    submitted_with_resolution.administrative_resolution_head = Some(reference(80));
    assert_eq!(
        submitted_with_resolution.validate_lifecycle_shape(ErasureLifecycleV1::Submitted),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut authorized = submitted;
    authorized.state = authorized.state().transition(state_transition(
        ErasureLifecycleV1::Authorized,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    authorized.authorize_provenance = Some(reference(9));
    let mut authorized_with_resolution = authorized.clone();
    authorized_with_resolution.administrative_resolution_head = Some(reference(81));
    assert_eq!(
        authorized_with_resolution.validate_lifecycle_shape(ErasureLifecycleV1::Authorized),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let rejection = ErasureAuthorizationRejectionV1::new(ErasureAuthorizationRejectionInputV1 {
        request: reference(1),
        authorization_provenance: reference(9),
    })?;
    let mut authorized_with_rejection = authorized.clone();
    authorized_with_rejection
        .supporting_records
        .authorization_rejection = Some(rejection);
    assert_eq!(
        authorized_with_rejection.validate_provenance(ErasureLifecycleV1::Authorized),
        Ok(())
    );

    let failure = ErasureFreezeFailureV1::new(ErasureFreezeFailureInputV1 {
        request: reference(1),
        error: ErasureErrorV1::AccessFreezeFailed,
        authorization_provenance: reference(9),
        evidence: reference(10),
    })?;
    let mut rejected = authorized;
    rejected.state = rejected.state().transition(ErasureStateTransitionV1 {
        lifecycle: ErasureLifecycleV1::Rejected,
        freeze_position: None,
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        acknowledged_targets: Vec::new(),
        replay_claim: ErasureReplayClaimV1::StructuralOnly,
        provenance: failure.reference(),
    })?;
    rejected.supporting_records.freeze_failure = Some(failure);

    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let frozen = record_after_freeze(vec![target])?;
    let mut scope_conflict = rejected.clone();
    scope_conflict.supporting_records.scope_commitment =
        frozen.supporting_records().scope_commitment.clone();
    assert_eq!(
        scope_conflict.validate_supporting_evidence_shape(ErasureLifecycleV1::Rejected),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut obligation_set_conflict = rejected;
    obligation_set_conflict.supporting_records.obligation_set =
        frozen.supporting_records().obligation_set.clone();
    assert_eq!(
        obligation_set_conflict.validate_supporting_evidence_shape(ErasureLifecycleV1::Rejected),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn correction_predecessor_accepts_the_exact_rejected_record() -> Result<(), ErasureErrorV1> {
    let port = test_port(true, Vec::new());
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.reject(reference(1), reference(9))?;
    let predecessor = coordinator.record(reference(1))?;
    let correction = ErasureCorrectionProvenanceV1::new(ErasureCorrectionProvenanceInputV1 {
        rejected_request: predecessor.request().reference(),
        rejected_terminal_state: predecessor.state().state_digest(),
        correction_reason: reference(72),
        authorization_provenance: reference(73),
    })?;
    let mut corrected = record_after_submit()?;
    corrected.supporting_records.correction_provenance = Some(correction);

    assert_eq!(
        corrected.validate_correction_predecessor(&predecessor),
        Ok(())
    );

    let mut freeze_predecessor = record_after_submit()?;
    freeze_predecessor.state = freeze_predecessor.state().transition(state_transition(
        ErasureLifecycleV1::Authorized,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    freeze_predecessor.authorize_provenance = Some(reference(9));
    let failure = ErasureFreezeFailureV1::new(ErasureFreezeFailureInputV1 {
        request: reference(1),
        error: ErasureErrorV1::AccessFreezeFailed,
        authorization_provenance: reference(9),
        evidence: reference(10),
    })?;
    freeze_predecessor.state = freeze_predecessor
        .state()
        .transition(ErasureStateTransitionV1 {
            lifecycle: ErasureLifecycleV1::Rejected,
            freeze_position: None,
            pending_owners: Vec::new(),
            failed_owners: Vec::new(),
            acknowledged_targets: Vec::new(),
            replay_claim: ErasureReplayClaimV1::StructuralOnly,
            provenance: failure.reference(),
        })?;
    freeze_predecessor.supporting_records.freeze_failure = Some(failure);
    let freeze_correction =
        ErasureCorrectionProvenanceV1::new(ErasureCorrectionProvenanceInputV1 {
            rejected_request: freeze_predecessor.request().reference(),
            rejected_terminal_state: freeze_predecessor.state().state_digest(),
            correction_reason: reference(74),
            authorization_provenance: reference(75),
        })?;
    let mut freeze_corrected = record_after_submit()?;
    freeze_corrected.supporting_records.correction_provenance = Some(freeze_correction);
    assert_eq!(
        freeze_corrected.validate_correction_predecessor(&freeze_predecessor),
        Ok(())
    );
    Ok(())
}

#[test]
fn freeze_retry_accepts_only_a_persisted_freeze_failure() -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let mut coordinator =
        ErasureCoordinatorStateMachineV1::new(test_port(true, vec![target]), reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.reject(reference(1), reference(9))?;

    assert_eq!(
        coordinator.freeze_inventory(
            reference(1),
            state_transition(
                ErasureLifecycleV1::AccessFrozen,
                Some(10),
                Vec::new(),
                Vec::new(),
            ),
        ),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn freeze_persistence_rejects_each_independent_identity_mismatch() -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let (admission, _) = lineage_freeze_admission(target, reference(72))?;
    let mut coordinator =
        ErasureCoordinatorStateMachineV1::new(test_port(true, vec![target]), reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    let baseline = coordinator.record(reference(1))?;

    let mut scope_mismatch = admission.clone();
    scope_mismatch.input.scope.request = reference(99);
    let mut record = baseline.clone();
    assert_eq!(
        coordinator.persist_atomic_freeze(&mut record, &scope_mismatch),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut obligation_set_mismatch = admission;
    obligation_set_mismatch.input.obligation_set.input.request = reference(99);
    let mut record = baseline.clone();
    assert_eq!(
        coordinator.persist_atomic_freeze(&mut record, &obligation_set_mismatch),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let failure = ErasureFreezeFailureV1::new(ErasureFreezeFailureInputV1 {
        request: reference(1),
        error: ErasureErrorV1::ScopeInvalid,
        authorization_provenance: reference(8),
        evidence: reference(10),
    })?;
    let mut record = baseline;
    assert_eq!(
        coordinator.persist_freeze_rejection(&mut record, failure),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(record.state().lifecycle(), ErasureLifecycleV1::Authorized);
    assert!(record.supporting_records().freeze_failure().is_none());
    Ok(())
}

#[test]
fn dispatch_attempt_rejects_a_wrong_source_receipt_before_admission() -> Result<(), ErasureErrorV1>
{
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let mut coordinator =
        ErasureCoordinatorStateMachineV1::new(test_port(true, vec![target]), reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        state_transition(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    let frozen = coordinator.record(reference(1))?;
    let obligation = frozen.supporting_records().obligations()[0];
    let mut admission = ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
        request: reference(1),
        attempt_ordinal: 0,
        source_receipt: None,
        unresolved_obligations: vec![obligation.reference()],
        command_identities: vec![obligation.command_identity()],
        policy: frozen.request().policy(),
        trust: frozen
            .supporting_records()
            .obligation_set()
            .ok_or(ErasureErrorV1::ProvenanceMissing)?
            .trust(),
        admitted_position: frozen.request().request_position(),
        deadline_position: frozen.request().horizon_position(),
        authorization_provenance: reference(9),
    })?;
    admission.input.source_receipt = Some(reference(99));
    assert_eq!(
        coordinator.dispatch_attempt(reference(1), &admission),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert!(coordinator.port.attempt_admissions.borrow().is_empty());
    Ok(())
}

#[test]
fn commands_for_admission_preserve_owner_specific_intents() -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let mut record = record_after_freeze(vec![target])?;
    let artifact = record.supporting_records.obligations[0];
    let key = ErasureObligationV1::new(ErasureObligationInputV1 {
        category: ErasureInventoryCategoryV1::Key,
        target,
        owner: reference(99),
        command_identity: artifact.command_identity(),
    })?;
    record.supporting_records.obligations.push(key);
    let admission = ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
        request: reference(1),
        attempt_ordinal: 0,
        source_receipt: None,
        unresolved_obligations: vec![artifact.reference(), key.reference()],
        command_identities: vec![artifact.command_identity(), key.command_identity()],
        policy: reference(5),
        trust: reference(3),
        admitted_position: record.request().request_position(),
        deadline_position: record.request().horizon_position(),
        authorization_provenance: reference(9),
    })?;

    let commands = ErasureCoordinatorStateMachineV1::<TestCoordinatorPort>::commands_for_admission(
        &record, &admission,
    )?;
    assert_eq!(commands.len(), 2);
    assert_eq!(commands[0].obligation, artifact.reference());
    assert_eq!(commands[0].category, ErasureInventoryCategoryV1::Artifact);
    assert_eq!(commands[0].target, target);
    assert_eq!(commands[0].owner, artifact.owner());
    assert_eq!(commands[0].command, artifact.command_identity());
    assert_eq!(commands[1].obligation, key.reference());
    assert_eq!(commands[1].category, ErasureInventoryCategoryV1::Key);
    assert_eq!(commands[1].owner, key.owner());
    assert_eq!(commands[1].command, key.command_identity());
    Ok(())
}
#[test]
fn codecs_refuse_trailing_unknown_and_maps() -> Result<(), ErasureErrorV1> {
    let mut trailing = request()?.to_canonical_cbor()?;
    trailing.push(0);
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&trailing),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    let mut unsupported = public_request_value(&request()?)?;
    let Value::Array(fields) = &mut unsupported else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    fields[1] = test_uint(2);
    let mut bytes = Vec::new();
    ciborium::into_writer(&unsupported, &mut bytes).map_err(|_| ErasureErrorV1::InvalidEncoding)?;
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&bytes),
        Err(ErasureErrorV1::UnsupportedVersion)
    );
    let map = Value::Map(vec![(test_text("request"), test_digest(reference(1)))]);
    let mut map_bytes = Vec::new();
    ciborium::into_writer(&map, &mut map_bytes).map_err(|_| ErasureErrorV1::InvalidEncoding)?;
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&map_bytes),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}
#[test]
fn decoders_refuse_unknown_closed_codes() -> Result<(), ErasureErrorV1> {
    let mut invalid_scope = public_request_value(&request()?)?;
    {
        let Value::Array(fields) = &mut invalid_scope else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[4] = test_uint(5);
    }
    assert_eq!(
        decode_request(&invalid_scope),
        Err(ErasureErrorV1::InvalidEncoding)
    );

    let submitted = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    let mut invalid_lifecycle = public_state_value(&submitted)?;
    {
        let Value::Array(fields) = &mut invalid_lifecycle else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[3] = test_uint(8);
    }
    assert_eq!(
        decode_state(&invalid_lifecycle),
        Err(ErasureErrorV1::InvalidEncoding)
    );

    let mut invalid_claim = public_state_value(&submitted)?;
    {
        let Value::Array(fields) = &mut invalid_claim else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[8] = test_uint(5);
    }
    assert_eq!(
        decode_state(&invalid_claim),
        Err(ErasureErrorV1::InvalidEncoding)
    );

    let canonical = receipt()?;
    let mut invalid_outcome = public_receipt_value(&canonical)?;
    {
        let Value::Array(fields) = &mut invalid_outcome else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        let Value::Array(acknowledgements) = &mut fields[7] else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        let Value::Array(acknowledgement) = &mut acknowledgements[0] else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        acknowledgement[3] = test_uint(3);
    }
    assert_eq!(
        decode_receipt(&invalid_outcome),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}
#[test]
fn public_decoders_reject_terminal_and_inventory_conflicts() -> Result<(), ErasureErrorV1> {
    let mut invalid_category = public_receipt_value(&receipt()?)?;
    let Value::Array(fields) = &mut invalid_category else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(inventories) = &mut fields[10] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(artifacts) = &mut inventories[0] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(inventory) = &mut artifacts[0] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    inventory[0] = test_uint(99);
    assert_eq!(
        decode_receipt(&invalid_category),
        Err(ErasureErrorV1::InvalidEncoding)
    );

    let mut mismatched_category = public_receipt_value(&receipt()?)?;
    let Value::Array(fields) = &mut mismatched_category else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(inventories) = &mut fields[10] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(artifacts) = &mut inventories[0] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(inventory) = &mut artifacts[0] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    inventory[0] = test_uint(1);
    assert_eq!(
        decode_receipt(&mismatched_category),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let waiting = dispatched()?.transition(state_transition(
        ErasureLifecycleV1::AwaitingAcknowledgements,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let mut complete_change = state_transition(
        ErasureLifecycleV1::Complete,
        Some(10),
        Vec::new(),
        Vec::new(),
    );
    complete_change.acknowledged_targets =
        vec![acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target];
    let complete = waiting.transition(complete_change)?;
    let mut invalid_complete = public_state_value(&complete)?;
    let Value::Array(fields) = &mut invalid_complete else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    fields[6] = Value::Array(vec![test_digest(reference(7))]);
    assert_eq!(
        decode_state(&invalid_complete),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let partial = waiting.transition(state_transition(
        ErasureLifecycleV1::PartialFailure,
        Some(10),
        vec![reference(7)],
        Vec::new(),
    ))?;
    let mut invalid_partial = public_state_value(&partial)?;
    let Value::Array(fields) = &mut invalid_partial else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    fields[6] = Value::Array(Vec::new());
    fields[7] = Value::Array(Vec::new());
    assert_eq!(
        decode_state(&invalid_partial),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}
#[test]
fn request_decoder_refuses_noncanonical_and_wrong_shapes() -> Result<(), ErasureErrorV1> {
    let mut wrong_tag_type = public_request_value(&request()?)?;
    {
        let Value::Array(fields) = &mut wrong_tag_type else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[0] = Value::Bool(false);
    }
    assert_eq!(
        decode_request(&wrong_tag_type),
        Err(ErasureErrorV1::InvalidEncoding)
    );

    let mut wrong_scope_type = public_request_value(&request()?)?;
    {
        let Value::Array(fields) = &mut wrong_scope_type else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[4] = Value::Bool(false);
    }
    assert_eq!(
        decode_request(&wrong_scope_type),
        Err(ErasureErrorV1::InvalidEncoding)
    );

    let mut empty_selectors = public_request_value(&request()?)?;
    {
        let Value::Array(fields) = &mut empty_selectors else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[5] = Value::Array(Vec::new());
    }
    assert_eq!(
        decode_request(&empty_selectors),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    assert_eq!(
        decode_request(&Value::Array(vec![Value::Null; 13])),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        decode_request(&Value::Null),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        decode_request(&Value::Array(Vec::new())),
        Err(ErasureErrorV1::InvalidEncoding)
    );

    let canonical = request()?.to_canonical_cbor()?;
    let noncanonical = [&[0x98, 12][..], &canonical[1..]].concat();
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&noncanonical),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}
#[test]
fn receipt_decoder_refuses_unsorted_acknowledgements() -> Result<(), ErasureErrorV1> {
    let canonical = receipt()?;
    let mut unsorted = public_receipt_value(&canonical)?;
    {
        let Value::Array(fields) = &mut unsorted else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        let Value::Array(acknowledgements) = &mut fields[7] else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        acknowledgements.swap(0, 1);
    }
    assert_eq!(decode_receipt(&unsorted), Err(ErasureErrorV1::ScopeInvalid));
    Ok(())
}
#[test]
fn receipt_decoder_exercises_each_public_field_boundary() -> Result<(), ErasureErrorV1> {
    for index in [2_usize, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 18] {
        let mut malformed = public_receipt_value(&receipt()?)?;
        let Value::Array(fields) = &mut malformed else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[index] = Value::Null;
        assert_eq!(
            decode_receipt(&malformed),
            Err(ErasureErrorV1::InvalidEncoding)
        );
    }
    for (index, value) in [(4_usize, test_uint(99)), (11, test_uint(99))] {
        let mut malformed = public_receipt_value(&receipt()?)?;
        let Value::Array(fields) = &mut malformed else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[index] = value;
        assert_eq!(
            decode_receipt(&malformed),
            Err(ErasureErrorV1::InvalidEncoding)
        );
    }

    let canonical = receipt()?.to_canonical_cbor()?;
    let mut trailing = canonical.clone();
    trailing.push(0);
    assert_eq!(
        ErasureReceiptV1::from_canonical_cbor(&trailing),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    let noncanonical = [&[0x99, 0, 19][..], &canonical[1..]].concat();
    assert_eq!(
        ErasureReceiptV1::from_canonical_cbor(&noncanonical),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}
#[test]
fn receipt_constructor_bounds_acknowledgements() {
    assert_eq!(
        ErasureReceiptV1::new(receipt_input(
            ErasureLifecycleV1::PartialFailure,
            vec![
                acknowledgement(1, ErasureAcknowledgementOutcomeV1::Negative);
                ERASURE_MAX_REFERENCES + 1
            ],
            Vec::new(),
            Vec::new(),
        )),
        Err(ErasureErrorV1::ScopeInvalid)
    );
}
#[test]
fn lifecycle_public_edges_and_terminality_are_closed() {
    assert!(ErasureLifecycleV1::Submitted.permits(ErasureLifecycleV1::Authorized));
    assert!(ErasureLifecycleV1::Authorized.permits(ErasureLifecycleV1::AccessFrozen));
    assert!(ErasureLifecycleV1::AccessFrozen.permits(ErasureLifecycleV1::DestructionDispatched));
    assert!(ErasureLifecycleV1::DestructionDispatched
        .permits(ErasureLifecycleV1::AwaitingAcknowledgements));
    assert!(ErasureLifecycleV1::AwaitingAcknowledgements.permits(ErasureLifecycleV1::Complete));
    assert!(
        ErasureLifecycleV1::AwaitingAcknowledgements.permits(ErasureLifecycleV1::PartialFailure)
    );
    assert!(!ErasureLifecycleV1::Rejected.permits(ErasureLifecycleV1::Submitted));
    assert!(ErasureLifecycleV1::Complete.is_terminal());
    assert!(!ErasureLifecycleV1::PartialFailure.is_terminal());
    assert!(ErasureLifecycleV1::PartialFailure.is_attempt_terminal());
    assert!(ErasureLifecycleV1::Rejected.is_terminal());
    assert!(!ErasureLifecycleV1::Authorized.is_terminal());
    assert!(ErasureLifecycleV1::Submitted.permits(ErasureLifecycleV1::Rejected));
    assert!(!ErasureLifecycleV1::Complete.permits(ErasureLifecycleV1::Authorized));
    assert!(ErasureLifecycleV1::PartialFailure.permits(ErasureLifecycleV1::PartialFailure));
    assert!(ErasureLifecycleV1::PartialFailure.permits(ErasureLifecycleV1::Complete));
}
#[test]
fn lifecycle_is_monotonic_and_digest_linked() -> Result<(), ErasureErrorV1> {
    let submitted = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    assert_eq!(
        submitted.transition(state_transition(
            ErasureLifecycleV1::Submitted,
            None,
            Vec::new(),
            Vec::new()
        )),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        submitted.transition(state_transition(
            ErasureLifecycleV1::Rejected,
            None,
            vec![reference(7)],
            Vec::new()
        )),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let authorized = submitted.transition(state_transition(
        ErasureLifecycleV1::Authorized,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    assert_eq!(
        authorized.transition(state_transition(
            ErasureLifecycleV1::AccessFrozen,
            None,
            Vec::new(),
            Vec::new()
        )),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let frozen = authorized.transition(state_transition(
        ErasureLifecycleV1::AccessFrozen,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    assert_eq!(
        frozen.transition(state_transition(
            ErasureLifecycleV1::DestructionDispatched,
            Some(11),
            Vec::new(),
            Vec::new(),
        )),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let dispatched = frozen.transition(state_transition(
        ErasureLifecycleV1::DestructionDispatched,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let waiting = dispatched.transition(state_transition(
        ErasureLifecycleV1::AwaitingAcknowledgements,
        Some(10),
        vec![reference(7)],
        Vec::new(),
    ))?;
    assert_eq!(
        waiting.transition(state_transition(
            ErasureLifecycleV1::Complete,
            Some(10),
            vec![reference(7)],
            Vec::new()
        )),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let partial = waiting.transition(state_transition(
        ErasureLifecycleV1::PartialFailure,
        Some(10),
        Vec::new(),
        vec![reference(7)],
    ))?;
    let partial_bytes = partial.to_canonical_cbor()?;
    assert_eq!(
        ErasureStateV1::from_canonical_cbor(&partial_bytes)?,
        partial
    );
    let authorized_bytes = authorized.to_canonical_cbor()?;
    assert_eq!(
        ErasureStateV1::from_canonical_cbor(&authorized_bytes)?,
        authorized
    );
    let mut tampered = authorized_bytes;
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_eq!(
        ErasureStateV1::from_canonical_cbor(&tampered),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}
#[test]
fn owner_evidence_bounds_are_enforced_at_the_public_transition() -> Result<(), ErasureErrorV1> {
    let dispatched = dispatched()?;
    assert!(dispatched
        .transition(state_transition(
            ErasureLifecycleV1::AwaitingAcknowledgements,
            Some(10),
            references(ERASURE_MAX_REFERENCES),
            Vec::new(),
        ))
        .is_ok());
    assert!(dispatched
        .transition(state_transition(
            ErasureLifecycleV1::AwaitingAcknowledgements,
            Some(10),
            Vec::new(),
            references(ERASURE_MAX_REFERENCES),
        ))
        .is_ok());
    assert_eq!(
        dispatched.transition(state_transition(
            ErasureLifecycleV1::AwaitingAcknowledgements,
            Some(10),
            references(ERASURE_MAX_REFERENCES + 1),
            Vec::new(),
        )),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        dispatched.transition(state_transition(
            ErasureLifecycleV1::AwaitingAcknowledgements,
            Some(10),
            Vec::new(),
            references(ERASURE_MAX_REFERENCES + 1),
        )),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}
#[test]
fn receipt_order_is_arrival_independent_and_completion_is_strict() -> Result<(), ErasureErrorV1> {
    let low = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let high = acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let first = ErasureReceiptV1::new(receipt_input(
        ErasureLifecycleV1::Complete,
        vec![high, low],
        Vec::new(),
        Vec::new(),
    ))?;
    let second = ErasureReceiptV1::new(receipt_input(
        ErasureLifecycleV1::Complete,
        vec![low, high],
        Vec::new(),
        Vec::new(),
    ))?;
    let bytes = first.to_canonical_cbor()?;
    assert_eq!(bytes, second.to_canonical_cbor()?);
    assert_eq!(ErasureReceiptV1::from_canonical_cbor(&bytes)?, first);
    let negative = acknowledgement(3, ErasureAcknowledgementOutcomeV1::Negative);
    let negative_owner = negative.owner;
    assert_eq!(
        ErasureReceiptV1::new(receipt_input(
            ErasureLifecycleV1::Complete,
            vec![negative],
            Vec::new(),
            vec![negative_owner]
        )),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        ErasureReceiptV1::new(receipt_input(
            ErasureLifecycleV1::PartialFailure,
            vec![low],
            Vec::new(),
            Vec::new()
        )),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        ErasureReceiptV1::new(receipt_input(
            ErasureLifecycleV1::PartialFailure,
            vec![low],
            vec![reference(9)],
            Vec::new()
        )),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}
#[test]
fn safe_errors_are_closed_and_payload_free() {
    for code in 0..16 {
        assert_eq!(
            ErasureErrorV1::from_code(code).map(ErasureErrorV1::code),
            Ok(code)
        );
    }
    assert_eq!(
        ErasureErrorV1::from_code(16),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert!(!ErasureErrorV1::ArtifactDeletionFailed
        .to_string()
        .contains("payload"));
}

#[test]
fn every_closed_wire_enum_round_trips_at_its_public_seam() -> Result<(), ErasureErrorV1> {
    request_wire_enum_roundtrip()?;
    state_wire_enum_roundtrip()?;
    receipt_wire_enum_roundtrip()
}

fn request_wire_enum_roundtrip() -> Result<(), ErasureErrorV1> {
    for scope in [
        ErasureScopeV1::PrivateSubjectData,
        ErasureScopeV1::ConsentedSharedData,
        ErasureScopeV1::PublicRecord,
        ErasureScopeV1::Aggregate,
        ErasureScopeV1::StructuralAuditMetadata,
    ] {
        let mut input = request_input(vec![reference(7)]);
        input.scope = scope;
        let request = ErasureRequestV1::new(input)?;
        assert_eq!(
            ErasureRequestV1::from_canonical_cbor(&request.to_canonical_cbor()?)?,
            request
        );
    }
    Ok(())
}

fn state_wire_enum_roundtrip() -> Result<(), ErasureErrorV1> {
    let submitted = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    let authorized = submitted.transition(state_transition(
        ErasureLifecycleV1::Authorized,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    let frozen = authorized.transition(state_transition(
        ErasureLifecycleV1::AccessFrozen,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let dispatched = frozen.transition(state_transition(
        ErasureLifecycleV1::DestructionDispatched,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let waiting = dispatched.transition(state_transition(
        ErasureLifecycleV1::AwaitingAcknowledgements,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let complete = waiting.transition(ErasureStateTransitionV1 {
        lifecycle: ErasureLifecycleV1::Complete,
        freeze_position: Some(10),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        acknowledged_targets: vec![
            acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target,
        ],
        replay_claim: ErasureReplayClaimV1::StructuralOnly,
        provenance: reference(9),
    })?;
    let partial = waiting.transition(state_transition(
        ErasureLifecycleV1::PartialFailure,
        Some(10),
        vec![reference(44)],
        Vec::new(),
    ))?;
    let rejected = submitted.transition(state_transition(
        ErasureLifecycleV1::Rejected,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    for state in [
        submitted, authorized, frozen, dispatched, waiting, complete, partial, rejected,
    ] {
        let encoded = state.to_canonical_cbor()?;
        assert_eq!(ErasureStateV1::from_canonical_cbor(&encoded)?, state);
        assert_ne!(state.state_digest(), reference(0));
    }

    for claim in [
        ErasureReplayClaimV1::Exact,
        ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews,
        ErasureReplayClaimV1::StructuralOnly,
        ErasureReplayClaimV1::UnverifiableArtifactsMissing,
        ErasureReplayClaimV1::IncompatibleProfile,
    ] {
        let mut transition =
            state_transition(ErasureLifecycleV1::Authorized, None, Vec::new(), Vec::new());
        transition.replay_claim = claim;
        let state = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?
            .transition(transition)?;
        assert_eq!(
            ErasureStateV1::from_canonical_cbor(&state.to_canonical_cbor()?)?,
            state
        );
    }
    Ok(())
}

fn receipt_wire_enum_roundtrip() -> Result<(), ErasureErrorV1> {
    let receipt = ErasureReceiptV1::new(receipt_input(
        ErasureLifecycleV1::PartialFailure,
        vec![
            acknowledgement(1, ErasureAcknowledgementOutcomeV1::Negative),
            acknowledgement(2, ErasureAcknowledgementOutcomeV1::Stale),
        ],
        Vec::new(),
        vec![reference(41), reference(42)],
    ))?;
    assert_eq!(
        ErasureReceiptV1::from_canonical_cbor(&receipt.to_canonical_cbor()?)?,
        receipt
    );
    Ok(())
}

#[test]
fn request_decoder_rejects_retained_wire_boundaries() -> Result<(), ErasureErrorV1> {
    let request = request()?;
    let mut malformed = public_request_value(&request)?;
    {
        let Value::Array(fields) = &mut malformed else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[0] = test_text("other-contract");
    }
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&public_value_bytes(&malformed)?),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    {
        let Value::Array(fields) = &mut malformed else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[0] = test_text("ERQ1");
        fields[2] = Value::Bool(false);
    }
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&public_value_bytes(&malformed)?),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    {
        let Value::Array(fields) = &mut malformed else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[2] = test_digest(reference(1));
        fields[5] = Value::Array(vec![test_digest(reference(9)), test_digest(reference(8))]);
    }
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&public_value_bytes(&malformed)?),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        ErasureRequestV1::new(request_input(vec![
            reference(7);
            ERASURE_MAX_REFERENCES + 1
        ])),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&vec![0; ERASURE_REQUEST_OR_STATE_MAX_BYTES + 1]),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&vec![0; ERASURE_REQUEST_OR_STATE_MAX_BYTES]),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn state_decoder_rejects_retained_wire_boundaries() -> Result<(), ErasureErrorV1> {
    let submitted = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    assert_eq!(
        submitted.transition(state_transition(
            ErasureLifecycleV1::Authorized,
            None,
            vec![reference(7), reference(7)],
            Vec::new()
        )),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let mut invalid_state = public_state_value(&submitted)?;
    {
        let Value::Array(state_fields) = &mut invalid_state else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        state_fields[6] = Value::Array(vec![test_digest(reference(7)), test_digest(reference(7))]);
    }
    assert_eq!(
        ErasureStateV1::from_canonical_cbor(&public_value_bytes(&invalid_state)?),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    {
        let Value::Array(state_fields) = &mut invalid_state else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        state_fields[6] = Value::Array(Vec::new());
        state_fields[9] = test_digest(reference(8));
    }
    assert_eq!(
        ErasureStateV1::from_canonical_cbor(&public_value_bytes(&invalid_state)?),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    {
        let Value::Array(state_fields) = &mut invalid_state else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        state_fields[3] = test_uint(ErasureLifecycleV1::PartialFailure.code());
        state_fields[4] = test_uint(10);
    }
    assert_eq!(
        ErasureStateV1::from_canonical_cbor(&public_value_bytes(&invalid_state)?),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn receipt_constructor_rejects_retained_wire_boundaries() {
    assert_eq!(
        ErasureReceiptV1::new(receipt_input(
            ErasureLifecycleV1::Authorized,
            Vec::new(),
            Vec::new(),
            Vec::new()
        )),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        ErasureReceiptV1::new(receipt_input(
            ErasureLifecycleV1::PartialFailure,
            vec![acknowledgement(1, ErasureAcknowledgementOutcomeV1::Stale)],
            vec![reference(8)],
            vec![reference(8)]
        )),
        Err(ErasureErrorV1::ScopeInvalid)
    );
}

#[test]
fn public_state_owner_accessors_and_freeze_rejection_remain_exact() -> Result<(), ErasureErrorV1> {
    let dispatched = dispatched()?;
    let pending = vec![reference(7)];
    let failed = vec![reference(8)];
    let awaiting = dispatched.transition(state_transition(
        ErasureLifecycleV1::AwaitingAcknowledgements,
        Some(10),
        pending.clone(),
        failed.clone(),
    ))?;
    assert_eq!(awaiting.pending_owners(), pending);
    assert_eq!(awaiting.failed_owners(), failed);

    let acknowledgement = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let port = test_port(true, vec![acknowledgement.target, acknowledgement.target]);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    assert_eq!(
        coordinator.freeze_inventory(
            reference(1),
            state_transition(
                ErasureLifecycleV1::AccessFrozen,
                Some(10),
                Vec::new(),
                Vec::new(),
            ),
        ),
        Err(ErasureErrorV1::PolicyConflict)
    );
    coordinator.authorize(reference(1), reference(9))?;
    assert_eq!(
        coordinator.freeze_inventory(
            reference(1),
            state_transition(ErasureLifecycleV1::Authorized, None, Vec::new(), Vec::new(),),
        ),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        coordinator.freeze_inventory(
            reference(1),
            state_transition(
                ErasureLifecycleV1::AccessFrozen,
                Some(10),
                Vec::new(),
                Vec::new(),
            ),
        ),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    Ok(())
}

#[test]
fn public_freeze_rejects_a_required_target_closure_over_the_bound() -> Result<(), ErasureErrorV1> {
    let target = indexed_target(0);
    let port = test_port(true, vec![target]);
    let freeze_reservation = Rc::clone(&port.freeze_reservation);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        state_transition(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    let mut oversized = freeze_reservation
        .borrow()
        .as_ref()
        .cloned()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .input;
    oversized.targets = vec![target; ERASURE_MAX_TARGETS + 1];
    assert_eq!(
        ErasureAtomicFreezeAdmissionV1::new(oversized),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn public_receipt_history_rejects_each_terminal_and_predecessor_mismatch(
) -> Result<(), ErasureErrorV1> {
    let submitted = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    let authorized = submitted.transition(state_transition(
        ErasureLifecycleV1::Authorized,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    let frozen = authorized.transition(state_transition(
        ErasureLifecycleV1::AccessFrozen,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let dispatched = frozen.transition(state_transition(
        ErasureLifecycleV1::DestructionDispatched,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let waiting = dispatched.transition(state_transition(
        ErasureLifecycleV1::AwaitingAcknowledgements,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let acknowledgement = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let terminal = waiting.transition(ErasureStateTransitionV1 {
        lifecycle: ErasureLifecycleV1::Complete,
        freeze_position: Some(10),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        acknowledged_targets: vec![acknowledgement.target],
        replay_claim: ErasureReplayClaimV1::StructuralOnly,
        provenance: reference(9),
    })?;
    let mut input = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![acknowledgement],
        Vec::new(),
        Vec::new(),
    );
    input.terminal_state = terminal.state_digest();
    let receipt = ErasureReceiptV1::new(input.clone())?;
    let resolver = TestResolver {
        states: vec![
            submitted.clone(),
            authorized.clone(),
            frozen.clone(),
            dispatched.clone(),
            waiting.clone(),
            terminal.clone(),
        ],
        unavailable: false,
    };
    receipt.verify_history(&resolver)?;

    history_terminal_mismatches(&input, &resolver, waiting.state_digest())?;
    history_predecessor_mismatches(
        &input,
        &submitted,
        &authorized,
        &frozen,
        &dispatched,
        &terminal,
    )?;
    Ok(())
}

fn history_terminal_mismatches(
    input: &ErasureReceiptInputV1,
    resolver: &TestResolver,
    waiting: ErasureReferenceV1,
) -> Result<(), ErasureErrorV1> {
    for mismatch in 0..4 {
        let mut altered = input.clone();
        match mismatch {
            0 => altered.request = reference(99),
            1 => {
                altered.lifecycle = ErasureLifecycleV1::PartialFailure;
                altered.acknowledgements[0].outcome = ErasureAcknowledgementOutcomeV1::Negative;
                altered.failed_owners = vec![reference(41)];
            }
            2 => {
                altered.freeze_position = 11;
                altered.issue_position = 11;
            }
            _ => altered.terminal_state = waiting,
        }
        assert_eq!(
            ErasureReceiptV1::new(altered)?.verify_history(resolver),
            Err(ErasureErrorV1::PolicyConflict)
        );
    }
    Ok(())
}

fn history_predecessor_mismatches(
    input: &ErasureReceiptInputV1,
    submitted: &ErasureStateV1,
    authorized: &ErasureStateV1,
    frozen: &ErasureStateV1,
    dispatched: &ErasureStateV1,
    terminal: &ErasureStateV1,
) -> Result<(), ErasureErrorV1> {
    for previous in [submitted, authorized, frozen, dispatched] {
        assert_eq!(
            ErasureReceiptV1::new(input.clone())?.verify_history(&ReplyResolver {
                terminal: terminal.clone(),
                previous: previous.clone(),
            }),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
    }
    Ok(())
}

#[test]
fn finalization_persists_the_atomic_batch_across_restart() -> Result<(), ErasureErrorV1> {
    let ack = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let port = test_port(true, vec![ack.target]);
    let restart_port = port.clone();
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        state_transition(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    let mut input = receipt_input(
        ErasureLifecycleV1::PartialFailure,
        Vec::new(),
        vec![ack.target.replica_id],
        Vec::new(),
    );
    input.inventories.artifacts = vec![inventory_result(ack.target)];
    coordinator.finalize(reference(1), input)?;
    drop(coordinator);

    let mut restarted = ErasureCoordinatorStateMachineV1::new(restart_port, reference(2));
    assert_eq!(
        restarted.submit(request()?, reference(99))?.lifecycle(),
        ErasureLifecycleV1::PartialFailure
    );
    Ok(())
}

#[test]
fn coordinator_rejects_storage_and_lifecycle_seams() -> Result<(), ErasureErrorV1> {
    let mut load_failed =
        ErasureCoordinatorStateMachineV1::new(test_port(true, Vec::new()), reference(2));
    load_failed.submit(request()?, reference(3))?;
    load_failed.port.load_error = Some(ErasureErrorV1::KeyRegistryUnavailable);
    assert_eq!(
        load_failed.authorize(reference(1), reference(9)),
        Err(ErasureErrorV1::KeyRegistryUnavailable)
    );

    let mut invalid_dispatch =
        ErasureCoordinatorStateMachineV1::new(test_port(true, Vec::new()), reference(2));
    invalid_dispatch.submit(request()?, reference(3))?;
    assert_eq!(
        invalid_dispatch.dispatch_destruction(reference(1), reference(9)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn dispatch_rejects_an_empty_closure_after_freeze() -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let mut frozen = record_after_freeze(vec![target])?;
    frozen.targets.clear();
    let port = test_port(true, vec![target]);
    port.records.borrow_mut().push(frozen);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    assert_eq!(
        coordinator.dispatch_destruction(reference(1), reference(9)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn acknowledgement_requires_both_the_admitted_obligation_and_command() -> Result<(), ErasureErrorV1>
{
    let mut ack = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let port = test_port(true, vec![ack.target]);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        state_transition(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    ack.obligation = reference(99);
    assert_eq!(
        coordinator.acknowledge(reference(1), ack),
        Err(ErasureErrorV1::Unauthorized)
    );
    Ok(())
}

#[test]
fn finalization_accepts_the_exact_attempt_deadline() -> Result<(), ErasureErrorV1> {
    let ack = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let port = test_port(true, vec![ack.target]);
    let persisted = port.records.clone();
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        state_transition(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    persisted
        .borrow_mut()
        .first_mut()
        .and_then(|record| record.supporting_records.retry_admissions.last_mut())
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .input
        .deadline_position = 11;
    let mut input = receipt_input(
        ErasureLifecycleV1::PartialFailure,
        Vec::new(),
        vec![ack.target.replica_id],
        Vec::new(),
    );
    input.inventories.artifacts = vec![inventory_result(ack.target)];
    input.issue_position = 11;
    assert!(coordinator.finalize(reference(1), input).is_ok());
    Ok(())
}

#[test]
fn replacement_validation_accepts_idempotent_and_same_state_extensions(
) -> Result<(), ErasureErrorV1> {
    let submitted = record_after_submit()?;
    assert_eq!(submitted.validate_replacement(&submitted), Ok(()));

    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let authorized_state = submitted.state().transition(state_transition(
        ErasureLifecycleV1::Authorized,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    let mut authorized_parts = record_parts(&submitted);
    authorized_parts.state = authorized_state;
    authorized_parts.authorize_provenance = Some(reference(9));
    let authorized = ErasureCoordinatorRecordV1::from_parts(authorized_parts, reference(2))?;
    assert_eq!(submitted.validate_replacement(&authorized), Ok(()));

    let frozen = record_after_freeze(vec![target])?;
    let intent = record_after_dispatch_intent(target)?;
    assert_eq!(frozen.validate_replacement(&intent), Ok(()));
    Ok(())
}

#[test]
fn replacement_validation_rejects_each_non_monotonic_record_dimension() -> Result<(), ErasureErrorV1>
{
    let submitted = record_after_submit()?;
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let frozen = record_after_freeze(vec![target])?;

    let mut changed_identity = frozen.clone();
    changed_identity.targets.clear();
    assert_eq!(
        frozen.validate_replacement(&changed_identity),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut changed_dispatch = submitted.clone();
    changed_dispatch.dispatch_provenance = Some(reference(80));
    assert_eq!(
        submitted.validate_replacement(&changed_dispatch),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut premature_ledger = submitted.clone();
    premature_ledger.scope_extension_ledger = Some(reference(81));
    assert_eq!(
        submitted.validate_replacement(&premature_ledger),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut premature_resolution = submitted.clone();
    premature_resolution.administrative_resolution_head = Some(reference(82));
    assert_eq!(
        submitted.validate_same_state_replacement(&premature_resolution),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut premature_acknowledgement = frozen.clone();
    premature_acknowledgement.acknowledgements = vec![acknowledgement(
        1,
        ErasureAcknowledgementOutcomeV1::Acknowledged,
    )];
    assert_eq!(
        frozen.validate_replacement(&premature_acknowledgement),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let authorized_state = submitted.state().transition(state_transition(
        ErasureLifecycleV1::Authorized,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    let mut authorized = submitted.clone();
    authorized.state = authorized_state;
    authorized.authorize_provenance = Some(reference(9));

    let mut rejected = authorized.clone();
    rejected.state = authorized.state().transition(state_transition(
        ErasureLifecycleV1::Rejected,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    rejected.targets = vec![target];
    assert_eq!(
        authorized.validate_advanced_replacement(&rejected),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut rejected_with_ledger = rejected;
    rejected_with_ledger.targets.clear();
    rejected_with_ledger.scope_extension_ledger = Some(reference(83));
    assert_eq!(
        authorized.validate_advanced_replacement(&rejected_with_ledger),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut target_on_authorization = authorized.clone();
    target_on_authorization.targets = vec![target];
    assert_eq!(
        submitted.validate_replacement(&target_on_authorization),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut ledger_on_authorization = authorized.clone();
    ledger_on_authorization.scope_extension_ledger = Some(reference(82));
    assert_eq!(
        submitted.validate_replacement(&ledger_on_authorization),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut changed_authorization = frozen;
    changed_authorization.authorize_provenance = Some(reference(83));
    assert_eq!(
        authorized.validate_replacement(&changed_authorization),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

fn awaiting_record() -> Result<ErasureCoordinatorRecordV1, ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let port = test_port(true, vec![target]);
    let persisted = port.clone();
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        state_transition(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    persisted
        .load_record(reference(1), &persisted)?
        .ok_or(ErasureErrorV1::ProvenanceMissing)
}

#[test]
fn replacement_validation_rejects_invalid_lifecycle_and_target_updates(
) -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let submitted = record_after_submit()?;
    let authorized_state = submitted.state().transition(state_transition(
        ErasureLifecycleV1::Authorized,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    let mut authorized_parts = record_parts(&submitted);
    authorized_parts.state = authorized_state;
    authorized_parts.authorize_provenance = Some(reference(9));
    let authorized = ErasureCoordinatorRecordV1::from_parts(authorized_parts, reference(2))?;
    let frozen = record_after_freeze(vec![target])?;
    let dispatched = awaiting_record()?;
    let mut backward_state = frozen.state().clone();
    backward_state.previous_state = Some(dispatched.state().state_digest());
    backward_state.state_digest = reference_zero();
    let backward_state = backward_state.with_digest()?;
    let mut backward_parts = record_parts(&frozen);
    backward_parts.state = backward_state;
    assert_eq!(
        dispatched.validate_replacement(&ErasureCoordinatorRecordV1::from_parts(
            backward_parts,
            reference(2),
        )?),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let wrong_target = acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let wrong_frozen = record_after_freeze(vec![wrong_target])?;
    assert_eq!(
        authorized.validate_replacement(&wrong_frozen),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let different_target = {
        let port = test_port(true, vec![wrong_target]);
        let persisted = port.clone();
        let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
        coordinator.submit(request()?, reference(3))?;
        coordinator.authorize(reference(1), reference(9))?;
        coordinator.freeze_inventory(
            reference(1),
            state_transition(
                ErasureLifecycleV1::AccessFrozen,
                Some(10),
                Vec::new(),
                Vec::new(),
            ),
        )?;
        coordinator.dispatch_destruction(reference(1), reference(9))?;
        persisted
            .load_record(reference(1), &persisted)?
            .ok_or(ErasureErrorV1::ProvenanceMissing)?
    };
    assert_eq!(
        frozen.validate_replacement(&different_target),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn atomic_admission_helpers_reject_each_malformed_matrix_shape() -> Result<(), ErasureErrorV1> {
    assert_eq!(
        ErasureApplicabilityDecisionV1::from_code(2),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        ErasureFreezeAuthorizationEvidenceV1::new(ErasureFreezeAuthorizationEvidenceInputV1 {
            admission_body_digest: reference(1),
            policy: reference(2),
            trust: reference(3),
            evidence: Vec::new(),
        },),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let (admission, _) = lineage_freeze_admission(target, reference(72))?;
    let base = admission.input;
    let obligation = base.obligations[0];
    let matrix = base
        .freeze_admission_evidence
        .applicability_matrix()
        .to_vec();

    let mut wrong_freeze_position = base.clone();
    wrong_freeze_position.freeze_position = 11;
    assert_eq!(
        ErasureAtomicFreezeAdmissionV1::new(wrong_freeze_position),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        validate_applicability_obligations(&matrix, &base.targets, &[obligation, obligation],),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let mut out_of_range = matrix.clone();
    out_of_range[0].target_index = 1;
    assert_eq!(
        validate_applicability_obligations(&out_of_range, &base.targets, &base.obligations),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let mut wrong_owner = matrix.clone();
    wrong_owner[0].owner = Some(reference(99));
    assert_eq!(
        validate_applicability_obligations(&wrong_owner, &base.targets, &base.obligations),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let mut overcounted = matrix;
    overcounted[1].category = ErasureInventoryCategoryV1::Artifact;
    overcounted[1].decision = ErasureApplicabilityDecisionV1::Applicable;
    overcounted[1].owner = Some(obligation.owner());
    assert_eq!(
        validate_applicability_obligations(&overcounted, &base.targets, &base.obligations),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn replacement_helpers_reject_each_non_monotonic_dimension() -> Result<(), ErasureErrorV1> {
    let submitted = record_after_submit()?;
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let frozen = record_after_freeze(vec![target])?;

    let mut changed_identity = frozen.clone();
    changed_identity.targets.clear();
    assert_eq!(
        frozen.validate_same_state_replacement(&changed_identity),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut changed_dispatch = submitted.clone();
    changed_dispatch.dispatch_provenance = Some(reference(80));
    assert_eq!(
        submitted.validate_same_state_replacement(&changed_dispatch),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut premature_ledger = submitted.clone();
    premature_ledger.scope_extension_ledger = Some(reference(81));
    assert_eq!(
        submitted.validate_same_state_replacement(&premature_ledger),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut premature_acknowledgement = frozen.clone();
    premature_acknowledgement.acknowledgements = vec![acknowledgement(
        1,
        ErasureAcknowledgementOutcomeV1::Acknowledged,
    )];
    assert_eq!(
        frozen.validate_same_state_replacement(&premature_acknowledgement),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let authorized_state = submitted.state().transition(state_transition(
        ErasureLifecycleV1::Authorized,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    let mut authorized = submitted;
    authorized.state = authorized_state;
    authorized.authorize_provenance = Some(reference(9));

    let wrong_target = acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let wrong_frozen = record_after_freeze(vec![wrong_target])?;
    assert_eq!(
        authorized.validate_advanced_replacement(&wrong_frozen),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut changed_ledger = frozen.clone();
    changed_ledger.scope_extension_ledger = Some(reference(82));
    assert_eq!(
        authorized.validate_advanced_replacement(&changed_ledger),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut dispatched = frozen.clone();
    dispatched.state = frozen.state().transition(state_transition(
        ErasureLifecycleV1::DestructionDispatched,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    dispatched.scope_extension_ledger = Some(reference(84));
    assert_eq!(
        frozen.validate_advanced_replacement(&dispatched),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut changed_resolution = frozen.clone();
    changed_resolution.administrative_resolution_head = Some(reference(85));
    assert_eq!(
        authorized.validate_advanced_replacement(&changed_resolution),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let mut changed_authorization = frozen;
    changed_authorization.authorize_provenance = Some(reference(83));
    assert_eq!(
        authorized.validate_advanced_replacement(&changed_authorization),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

fn administrative_resolution_for(
    frozen: &ErasureCoordinatorRecordV1,
    policy: ErasureReferenceV1,
) -> Result<ErasureAdministrativeResolutionV1, ErasureErrorV1> {
    let scope_commitment = frozen
        .supporting_records
        .scope_commitment()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .reference();
    let trust = frozen
        .supporting_records
        .obligation_set()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .trust();
    ErasureAdministrativeResolutionV1::new(ErasureAdministrativeResolutionInputV1 {
        request: frozen.request.reference(),
        affected_digests: vec![frozen.state.state_digest()],
        action: ErasureAdministrativeResolutionActionV1::RecoverExactEvidence,
        scope_commitment,
        policy,
        trust,
        principal: reference(88),
        authorization_provenance: reference(89),
        reason: reference(90),
        issue_position: 11,
        predecessor_resolution: None,
    })
}

#[test]
fn administrative_resolution_validation_rejects_incomplete_bindings() -> Result<(), ErasureErrorV1>
{
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let frozen = record_after_freeze(vec![target])?;
    let matching_resolution = administrative_resolution_for(&frozen, frozen.request.policy())?;

    let mut resolution_without_scope = frozen.clone();
    resolution_without_scope.administrative_resolution_head = Some(matching_resolution.reference());
    resolution_without_scope
        .supporting_records
        .administrative_resolutions
        .push(matching_resolution);
    resolution_without_scope.supporting_records.scope_commitment = None;
    assert_eq!(
        resolution_without_scope.validate_administrative_resolution_head(),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mismatched_resolution = administrative_resolution_for(&frozen, reference(91))?;
    let mut resolution_with_wrong_policy = frozen;
    resolution_with_wrong_policy.administrative_resolution_head =
        Some(mismatched_resolution.reference());
    resolution_with_wrong_policy
        .supporting_records
        .administrative_resolutions
        .push(mismatched_resolution);
    assert_eq!(
        resolution_with_wrong_policy.validate_administrative_resolution_head(),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn durable_validation_helpers_reject_each_incomplete_evidence_shape() -> Result<(), ErasureErrorV1>
{
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let frozen = record_after_freeze(vec![target])?;

    let mut missing_scope = frozen.clone();
    missing_scope.supporting_records.scope_commitment = None;
    assert_eq!(
        missing_scope.validate_frozen_evidence(ErasureLifecycleV1::AccessFrozen),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut malformed_obligation = frozen.clone();
    malformed_obligation.supporting_records.obligations[0]
        .input
        .command_identity = reference(84);
    assert_eq!(
        malformed_obligation.validate_frozen_evidence(ErasureLifecycleV1::AccessFrozen),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut wrong_ledger = frozen.clone();
    wrong_ledger.scope_extension_ledger = Some(reference(85));
    assert_eq!(
        wrong_ledger.validate_frozen_evidence(ErasureLifecycleV1::AccessFrozen),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut complete = complete_record()?;
    complete.acknowledgements.clear();
    assert_eq!(
        complete.validate_terminal(ErasureLifecycleV1::Complete, reference(2)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let mut missing_outcome = complete_record()?;
    missing_outcome.supporting_records.attempt_outcomes.clear();
    assert_eq!(
        missing_outcome.validate_terminal(ErasureLifecycleV1::Complete, reference(2)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let mut wrong_terminal_provenance = complete_record()?;
    wrong_terminal_provenance
        .supporting_records
        .receipt_provenance
        .last_mut()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .input
        .terminal_state = reference(86);
    assert_eq!(
        wrong_terminal_provenance.validate_terminal(ErasureLifecycleV1::Complete, reference(2)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let verifier = test_port(true, vec![target]);
    let mut partial_authorization = frozen;
    partial_authorization
        .supporting_records
        .freeze_authorization_evidence = None;
    assert_eq!(
        partial_authorization.verify_recovered_freeze_authorization(&verifier),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut conflicting_intents = record_after_dispatch_intent(target)?;
    let duplicate_intent = conflicting_intents.supporting_records.retry_admissions[0].clone();
    conflicting_intents
        .supporting_records
        .retry_admissions
        .push(duplicate_intent);
    assert_eq!(
        conflicting_intents.validate_attempt_evidence_shape(ErasureLifecycleV1::AccessFrozen),
        Err(ErasureErrorV1::PolicyConflict)
    );

    let awaiting = awaiting_record()?;
    let mut missing_intent = awaiting.clone();
    missing_intent.supporting_records.retry_admissions.clear();
    assert_eq!(
        missing_intent
            .validate_attempt_evidence_shape(ErasureLifecycleV1::AwaitingAcknowledgements),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let mut wrong_intent = awaiting;
    wrong_intent.state.provenance = reference(87);
    assert_eq!(
        wrong_intent.validate_attempt_evidence_shape(ErasureLifecycleV1::AwaitingAcknowledgements),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn finalization_helpers_reject_missing_or_unbalanced_attempts() -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let coordinator =
        ErasureCoordinatorStateMachineV1::new(test_port(true, vec![target]), reference(2));
    let input = receipt_input(
        ErasureLifecycleV1::Complete,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    let mut missing_attempt = awaiting_record()?;
    missing_attempt.supporting_records.retry_admissions.clear();
    assert_eq!(
        coordinator.prepare_finalization(reference(1), &mut missing_attempt, &input),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut unbalanced_attempt = awaiting_record()?;
    let duplicate = unbalanced_attempt.supporting_records.retry_admissions[0].clone();
    unbalanced_attempt
        .supporting_records
        .retry_admissions
        .push(duplicate);
    assert_eq!(
        coordinator.prepare_finalization(reference(1), &mut unbalanced_attempt, &input),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn durable_validation_rejects_removed_acknowledgements() -> Result<(), ErasureErrorV1> {
    let acknowledged = record_after_acknowledgement()?;
    let mut missing_ack_parts = record_parts(&acknowledged);
    missing_ack_parts.acknowledgements.clear();
    assert_eq!(
        ErasureCoordinatorRecordV1::from_parts(missing_ack_parts, reference(2)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn dispatch_retry_rejects_a_different_intent_provenance() -> Result<(), ErasureErrorV1> {
    let target = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    let mut port = test_port(true, vec![target]);
    port.dispatch_error = Some(ErasureErrorV1::KeyDestructionFailed);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        state_transition(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    assert_eq!(
        coordinator.dispatch_destruction(reference(1), reference(9)),
        Err(ErasureErrorV1::KeyDestructionFailed)
    );
    assert_eq!(
        coordinator.dispatch_destruction(reference(1), reference(8)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn predecessor_validation_rejects_an_exhausted_chain_budget() -> Result<(), ErasureErrorV1> {
    let state = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    assert_eq!(
        verify_predecessor_chain_bounded(
            state,
            &TestResolver {
                states: Vec::new(),
                unavailable: false,
            },
            0,
        ),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn state_predecessor_validation_enforces_the_shared_transition_contract(
) -> Result<(), ErasureErrorV1> {
    let previous = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    let current = previous.transition(state_transition(
        ErasureLifecycleV1::Authorized,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    current.validate_predecessor(&previous)?;
    assert_eq!(
        previous.validate_predecessor(&previous),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut wrong_digest = previous.clone();
    wrong_digest.state_digest = reference(99);
    assert_eq!(
        current.validate_predecessor(&wrong_digest),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut wrong_request = previous.clone();
    wrong_request.request = reference(99);
    assert_eq!(
        current.validate_predecessor(&wrong_request),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut wrong_coordinator = previous.clone();
    wrong_coordinator.coordinator = reference(99);
    assert_eq!(
        current.validate_predecessor(&wrong_coordinator),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut wrong_lifecycle = previous.clone();
    wrong_lifecycle.lifecycle = ErasureLifecycleV1::AccessFrozen;
    assert_eq!(
        current.validate_predecessor(&wrong_lifecycle),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut wrong_freeze = previous.clone();
    wrong_freeze.freeze_position = Some(11);
    assert_eq!(
        current.validate_predecessor(&wrong_freeze),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let mut wrong_claim = previous;
    wrong_claim.replay_claim = ErasureReplayClaimV1::StructuralOnly;
    let mut exact_current = current;
    exact_current.replay_claim = ErasureReplayClaimV1::Exact;
    assert_eq!(
        exact_current.validate_predecessor(&wrong_claim),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn canonical_record_decoder_rejects_a_noncanonical_integer() -> Result<(), ErasureErrorV1> {
    let record = complete_record()?;
    let mut bytes = record.to_canonical_cbor()?;
    bytes[7] = 0x18;
    bytes.insert(8, 1);
    assert_eq!(
        ErasureCoordinatorRecordV1::from_canonical_cbor(&bytes),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}
