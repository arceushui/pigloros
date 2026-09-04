//! Public adapter coverage for the erasure persistence CAS boundaries.
//!
//! The tests keep the coordinator and the adapters on opposite sides of the
//! public port. SQLite-only corruption is performed through a second public
//! `rusqlite::Connection` so the adapter must still classify the resulting
//! durable state through its normal public methods.

use std::cell::RefCell;
use std::rc::Rc;

#[path = "../../pos-core/tests/support/erasure.rs"]
pub mod erasure_support;

use erasure_support::{freeze_evidence_fixture, FreezeEvidenceFixtureInput};
use pos_core::erasure::{
    destruction_command_reference, target_closure_digest, ErasureAuthorizationDecisionV1,
};
use pos_core::{
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementProvenanceV1, ErasureAcknowledgementV1,
    ErasureAdministrativeResolutionActionV1, ErasureAdministrativeResolutionInputV1,
    ErasureAdministrativeResolutionV1, ErasureArtifactTransitionV1,
    ErasureAtomicFreezeAdmissionInputV1, ErasureAtomicFreezeAdmissionV1,
    ErasureAtomicFreezeResultV1, ErasureAttemptQuotaReservationV1, ErasureCasOutcomeV1,
    ErasureCoordinatorPortV1, ErasureDestructionCommandV1, ErasureErrorV1,
    ErasureFreezeAdmissionEvidenceV1, ErasureFreezeAuthorizationEvidenceV1,
    ErasureFreezeAuthorizationVerifierV1, ErasureIndexInsertV1, ErasureInventoryCategoryV1,
    ErasureInventoryResultV1, ErasureLifecycleV1, ErasureObligationInputV1,
    ErasureObligationSetInputV1, ErasureObligationSetV1, ErasureObligationV1,
    ErasurePersistencePortV1, ErasureReceiptInputV1, ErasureReceiptInventoriesV1,
    ErasureRecoveryAuthorizationVerifierV1, ErasureReferenceV1, ErasureReplayClaimV1,
    ErasureRequestInputV1, ErasureRequestV1, ErasureRequiredTargetV1, ErasureRetryAdmissionInputV1,
    ErasureRetryAdmissionV1, ErasureScopeCommitmentInputV1, ErasureScopeCommitmentV1,
    ErasureScopeExtensionInputV1, ErasureScopeExtensionV1, ErasureScopeV1, ErasureStateResolverV1,
    ErasureStateTransitionV1, ErasureStateV1, PreparedErasureCasV1,
};
use pos_store::memory::MemoryStore;

#[cfg(feature = "sqlite")]
use pos_store::sqlite::SqliteStore;

const fn reference(value: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([value; 32])
}

const fn target() -> ErasureRequiredTargetV1 {
    ErasureRequiredTargetV1 {
        artifact_class: pos_core::ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: reference(10),
        key_role: pos_core::ErasureKeyRoleV1::DataEncryption,
        key_digest: reference(11),
        replica_set: reference(12),
        replica_id: reference(13),
    }
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
        request_position: 9,
        horizon_position: 20,
        provenance: reference(7),
    })
}

const fn freeze_transition() -> ErasureStateTransitionV1 {
    ErasureStateTransitionV1 {
        lifecycle: pos_core::ErasureLifecycleV1::AccessFrozen,
        freeze_position: Some(10),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        acknowledged_targets: Vec::new(),
        replay_claim: pos_core::ErasureReplayClaimV1::Exact,
        provenance: reference(14),
    }
}

fn scope(
    request: ErasureReferenceV1,
    targets: &[ErasureRequiredTargetV1],
    lineage_rule: ErasureReferenceV1,
) -> Result<ErasureScopeCommitmentV1, ErasureErrorV1> {
    ErasureScopeCommitmentV1::new(ErasureScopeCommitmentInputV1 {
        request,
        scope_members: vec![reference(15)],
        target_closure: target_closure_digest(targets),
        lineage_rule: Some(lineage_rule),
    })
}

fn extension(
    request: ErasureReferenceV1,
    scope: &ErasureScopeCommitmentV1,
    lineage_rule: ErasureReferenceV1,
) -> Result<ErasureScopeExtensionV1, ErasureErrorV1> {
    ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
        request,
        scope_commitment: scope.reference(),
        fork: reference(16),
        lineage_rule,
        predecessor_extension: None,
        admission_provenance: reference(17),
    })
}

fn resolution(
    request: ErasureReferenceV1,
    state: &ErasureStateV1,
    scope: &ErasureScopeCommitmentV1,
) -> Result<ErasureAdministrativeResolutionV1, ErasureErrorV1> {
    ErasureAdministrativeResolutionV1::new(ErasureAdministrativeResolutionInputV1 {
        request,
        affected_digests: vec![state.state_digest()],
        action: ErasureAdministrativeResolutionActionV1::RecoverExactEvidence,
        scope_commitment: scope.reference(),
        policy: reference(6),
        trust: reference(8),
        principal: reference(18),
        authorization_provenance: reference(19),
        reason: reference(20),
        issue_position: 21,
        predecessor_resolution: None,
    })
}

fn retry_admission(
    request: ErasureReferenceV1,
    target: ErasureRequiredTargetV1,
    attempt_ordinal: u64,
    source_receipt: Option<ErasureReferenceV1>,
) -> Result<ErasureRetryAdmissionV1, ErasureErrorV1> {
    let obligation = ErasureObligationV1::new(ErasureObligationInputV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target,
        owner: target.replica_id,
        command_identity: destruction_command_reference(request, target),
    })?;
    ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
        request,
        attempt_ordinal,
        source_receipt,
        unresolved_obligations: vec![obligation.reference()],
        command_identities: vec![obligation.command_identity()],
        policy: reference(6),
        trust: reference(8),
        admitted_position: 11 + attempt_ordinal,
        deadline_position: 20 + attempt_ordinal,
        authorization_provenance: reference(44),
    })
}

fn acknowledgement(
    request: ErasureReferenceV1,
    target: ErasureRequiredTargetV1,
    evidence: ErasureReferenceV1,
    outcome: ErasureAcknowledgementOutcomeV1,
) -> Result<ErasureAcknowledgementV1, ErasureErrorV1> {
    let obligation = ErasureObligationV1::new(ErasureObligationInputV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target,
        owner: target.replica_id,
        command_identity: destruction_command_reference(request, target),
    })?;
    Ok(ErasureAcknowledgementV1 {
        obligation: obligation.reference(),
        target,
        owner: target.replica_id,
        evidence,
        outcome,
    })
}

fn receipt_input(target: ErasureRequiredTargetV1, issue_position: u64) -> ErasureReceiptInputV1 {
    ErasureReceiptInputV1 {
        request: reference(0),
        terminal_state: reference(0),
        coordinator: reference(0),
        lifecycle: ErasureLifecycleV1::Complete,
        freeze_position: 0,
        acknowledgements: Vec::new(),
        frozen_targets: vec![target],
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        inventories: ErasureReceiptInventoriesV1 {
            artifacts: vec![ErasureInventoryResultV1 {
                category: ErasureInventoryCategoryV1::Artifact,
                target,
                transition: ErasureArtifactTransitionV1 {
                    from: ErasureReplayClaimV1::Exact,
                    to: ErasureReplayClaimV1::StructuralOnly,
                    reason: reference(46),
                    owner: target.replica_id,
                    acknowledgements: reference(47),
                    provenance: reference(48),
                },
                retained_disclosure: reference(49),
            }],
            keys: Vec::new(),
            replicas: Vec::new(),
            backups: Vec::new(),
        },
        replay_claim: ErasureReplayClaimV1::StructuralOnly,
        policy: reference(0),
        trust: reference(0),
        provenance: reference(0),
        issue_position,
        signature: reference(50),
        receipt_digest: reference(0),
    }
}

#[derive(Clone, Copy)]
enum RetryExpectation {
    Exact,
    Propagate,
}

trait RetryHook<S: ErasurePersistencePortV1> {
    fn before_retry(
        &mut self,
        store: &Rc<RefCell<S>>,
        mutation: &PreparedErasureCasV1,
    ) -> Result<RetryExpectation, ErasureErrorV1>;
}

#[derive(Default)]
struct ExactRetryHook;

impl<S: ErasurePersistencePortV1> RetryHook<S> for ExactRetryHook {
    fn before_retry(
        &mut self,
        _store: &Rc<RefCell<S>>,
        _mutation: &PreparedErasureCasV1,
    ) -> Result<RetryExpectation, ErasureErrorV1> {
        Ok(RetryExpectation::Exact)
    }
}

struct AdapterHost<S, H> {
    store: Rc<RefCell<S>>,
    targets: Vec<ErasureRequiredTargetV1>,
    lineage_rule: ErasureReferenceV1,
    freeze_evidence: ErasureReferenceV1,
    retry_hook: H,
}

impl<S, H> ErasureStateResolverV1 for AdapterHost<S, H>
where
    S: ErasurePersistencePortV1,
    H: RetryHook<S>,
{
    fn resolve_state(
        &self,
        digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureStateV1>, ErasureErrorV1> {
        self.store.borrow().resolve_state(digest)
    }
}

impl<S, H> ErasurePersistencePortV1 for AdapterHost<S, H>
where
    S: ErasurePersistencePortV1,
    H: RetryHook<S>,
{
    fn read_manifest(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Option<pos_core::StoredErasureManifestV1>, ErasureErrorV1> {
        self.store.borrow().read_manifest(request)
    }

    fn read_object(&self, reference: ErasureReferenceV1) -> Result<Vec<u8>, ErasureErrorV1> {
        self.store.borrow().read_object(reference)
    }

    fn read_effect(
        &self,
        manifest: ErasureReferenceV1,
    ) -> Result<pos_core::ErasureCasEffectV1, ErasureErrorV1> {
        self.store.borrow().read_effect(manifest)
    }

    fn effect_manifest(
        &self,
        subject: ErasureReferenceV1,
    ) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1> {
        self.store.borrow().effect_manifest(subject)
    }

    fn attempt_page_ref(
        &self,
        request: ErasureReferenceV1,
        ordinal: u64,
    ) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1> {
        self.store.borrow().attempt_page_ref(request, ordinal)
    }

    fn attempt_index_count(&self, request: ErasureReferenceV1) -> Result<u64, ErasureErrorV1> {
        self.store.borrow().attempt_index_count(request)
    }

    fn scope_node_ref(
        &self,
        request: ErasureReferenceV1,
        ordinal: u64,
    ) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1> {
        self.store.borrow().scope_node_ref(request, ordinal)
    }

    fn scope_index_count(&self, request: ErasureReferenceV1) -> Result<u64, ErasureErrorV1> {
        self.store.borrow().scope_index_count(request)
    }

    fn administrative_resolution_ref(
        &self,
        request: ErasureReferenceV1,
        ordinal: u64,
    ) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1> {
        self.store
            .borrow()
            .administrative_resolution_ref(request, ordinal)
    }

    fn administrative_resolution_index_count(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<u64, ErasureErrorV1> {
        self.store
            .borrow()
            .administrative_resolution_index_count(request)
    }

    fn recovery_error_refs(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Vec<ErasureReferenceV1>, ErasureErrorV1> {
        self.store.borrow().recovery_error_refs(request)
    }

    fn append_recovery_error(
        &mut self,
        request: ErasureReferenceV1,
        object: pos_core::ErasurePersistenceObjectV1,
    ) -> Result<(), ErasureErrorV1> {
        self.store
            .borrow_mut()
            .append_recovery_error(request, object)
    }

    fn compare_and_swap(
        &mut self,
        mutation: PreparedErasureCasV1,
    ) -> Result<ErasureCasOutcomeV1, ErasureErrorV1> {
        let retry = mutation.clone();
        let outcome = self.store.borrow_mut().compare_and_swap(mutation)?;
        let expectation = self.retry_hook.before_retry(&self.store, &retry)?;
        let retry_outcome = self.store.borrow_mut().compare_and_swap(retry);
        match expectation {
            RetryExpectation::Exact => {
                if retry_outcome != Ok(ErasureCasOutcomeV1::ExactRetry) {
                    return Err(ErasureErrorV1::PolicyConflict);
                }
            }
            RetryExpectation::Propagate => {
                retry_outcome.map(|_| ())?;
            }
        }
        Ok(outcome)
    }
}

impl<S, H> ErasureFreezeAuthorizationVerifierV1 for AdapterHost<S, H>
where
    S: ErasurePersistencePortV1,
    H: RetryHook<S>,
{
    fn validate_freeze_authorization(
        &self,
        admission: &ErasureFreezeAdmissionEvidenceV1,
        authorization: &ErasureFreezeAuthorizationEvidenceV1,
    ) -> Result<(), ErasureErrorV1> {
        authorization.verify_admission_body_binding(admission)
    }
}

impl<S, H> ErasureRecoveryAuthorizationVerifierV1 for AdapterHost<S, H>
where
    S: ErasurePersistencePortV1,
    H: RetryHook<S>,
{
    fn validate_scope_extension(
        &self,
        _extension: &ErasureScopeExtensionV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn validate_administrative_resolution(
        &self,
        _resolution: &ErasureAdministrativeResolutionV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }
}

impl<S, H> ErasureCoordinatorPortV1 for AdapterHost<S, H>
where
    S: ErasurePersistencePortV1,
    H: RetryHook<S>,
{
    fn authenticate(&self, _request: &ErasureRequestV1) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_authorization(
        &self,
        _request: ErasureReferenceV1,
        _provenance: ErasureReferenceV1,
        _decision: ErasureAuthorizationDecisionV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_corrected_submission(
        &self,
        _request: &ErasureRequestV1,
        _correction: &pos_core::ErasureCorrectionProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_atomic_freeze(
        &self,
        request: ErasureReferenceV1,
        _requested: &ErasureStateTransitionV1,
    ) -> Result<ErasureAtomicFreezeResultV1, ErasureErrorV1> {
        let mut obligations = self
            .targets
            .iter()
            .copied()
            .map(|target| {
                ErasureObligationV1::new(ErasureObligationInputV1 {
                    category: ErasureInventoryCategoryV1::Artifact,
                    target,
                    owner: target.replica_id,
                    command_identity: destruction_command_reference(request, target),
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
            trust: reference(8),
        })?;
        let scope_input = ErasureScopeCommitmentInputV1 {
            request,
            scope_members: vec![reference(15)],
            target_closure: target_closure_digest(&self.targets),
            lineage_rule: Some(self.lineage_rule),
        };
        let scope_reference = ErasureScopeCommitmentV1::new(scope_input.clone())?.reference();
        let evidence = self.freeze_evidence.digest();
        let (freeze_admission_evidence, freeze_authorization_evidence) =
            freeze_evidence_fixture(FreezeEvidenceFixtureInput {
                request,
                scope_commitment: scope_reference,
                obligation_set: &obligation_set,
                targets: &self.targets,
                obligations: &obligations,
                freeze_position: 10,
                evidence: &evidence,
            })?;
        ErasureAtomicFreezeAdmissionV1::new(ErasureAtomicFreezeAdmissionInputV1 {
            targets: self.targets.clone(),
            scope: scope_input,
            obligations,
            obligation_set,
            freeze_position: 10,
            freeze_admission_evidence,
            freeze_authorization_evidence,
        })
        .map(Box::new)
        .map(ErasureAtomicFreezeResultV1::Admitted)
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

    fn dispatch_destruction(
        &self,
        _request: ErasureReferenceV1,
        _commands: &[ErasureDestructionCommandV1],
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_attempt(
        &self,
        admission: &ErasureRetryAdmissionV1,
    ) -> Result<ErasureAttemptQuotaReservationV1, ErasureErrorV1> {
        Ok(ErasureAttemptQuotaReservationV1::new(
            admission.reference(),
            admission.reference(),
        ))
    }

    fn admit_acknowledgement(
        &self,
        _acknowledgement: &ErasureAcknowledgementProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_receipt(
        &self,
        _input: &pos_core::ErasureReceiptInputV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }
}

fn exact_coordinator<S>(
    store: &Rc<RefCell<S>>,
    target: ErasureRequiredTargetV1,
    lineage_rule: ErasureReferenceV1,
) -> pos_core::ErasureCoordinatorStateMachineV1<AdapterHost<S, ExactRetryHook>>
where
    S: ErasurePersistencePortV1,
{
    pos_core::ErasureCoordinatorStateMachineV1::new(
        AdapterHost {
            store: Rc::clone(store),
            targets: vec![target],
            lineage_rule,
            freeze_evidence: reference(41),
            retry_hook: ExactRetryHook,
        },
        reference(42),
    )
}

fn exercise_complete_attempt<S>(
    shared: &Rc<RefCell<S>>,
    request: &ErasureRequestV1,
    target: ErasureRequiredTargetV1,
    lineage_rule: ErasureReferenceV1,
) -> Result<(), ErasureErrorV1>
where
    S: ErasurePersistencePortV1,
{
    let admission = retry_admission(request.reference(), target, 0, None)?;
    let mut coordinator = exact_coordinator(shared, target, lineage_rule);
    assert_eq!(
        coordinator.dispatch_attempt(request.reference(), &admission)?,
        coordinator.dispatch_attempt(request.reference(), &admission)?
    );
    let acknowledgement = || {
        acknowledgement(
            request.reference(),
            target,
            reference(45),
            ErasureAcknowledgementOutcomeV1::Acknowledged,
        )
    };
    let mut coordinator = exact_coordinator(shared, target, lineage_rule);
    let acknowledged = coordinator.acknowledge(request.reference(), acknowledgement()?)?;
    assert_eq!(
        acknowledged.lifecycle(),
        ErasureLifecycleV1::AwaitingAcknowledgements
    );
    let mut coordinator = exact_coordinator(shared, target, lineage_rule);
    assert_eq!(
        coordinator.acknowledge(request.reference(), acknowledgement()?)?,
        acknowledged
    );
    let receipt = coordinator.finalize(request.reference(), receipt_input(target, 21))?;
    assert_eq!(receipt.lifecycle(), ErasureLifecycleV1::Complete);
    assert_eq!(
        exact_coordinator(shared, target, lineage_rule)
            .finalize(request.reference(), receipt_input(target, 21))?,
        receipt
    );
    Ok(())
}

fn exercise_scope_and_resolution<S>(store: S) -> Result<(), Box<dyn std::error::Error>>
where
    S: ErasurePersistencePortV1,
{
    let shared = Rc::new(RefCell::new(store));
    let request = request()?;
    let target = target();
    let lineage_rule = reference(40);
    let submitted = exact_coordinator(&shared, target, lineage_rule)
        .submit(request.clone(), request.provenance())?;
    assert_eq!(
        submitted.lifecycle(),
        pos_core::ErasureLifecycleV1::Submitted
    );

    let mut coordinator = exact_coordinator(&shared, target, lineage_rule);
    assert_eq!(
        coordinator.submit(request.clone(), request.provenance())?,
        submitted
    );
    let authorized = coordinator.authorize(request.reference(), reference(43))?;
    assert_eq!(
        authorized.lifecycle(),
        pos_core::ErasureLifecycleV1::Authorized
    );

    let mut coordinator = exact_coordinator(&shared, target, lineage_rule);
    assert_eq!(
        coordinator.authorize(request.reference(), reference(43))?,
        authorized
    );
    let frozen = coordinator.freeze_inventory(request.reference(), &freeze_transition())?;
    assert_eq!(
        frozen.lifecycle(),
        pos_core::ErasureLifecycleV1::AccessFrozen
    );

    exercise_complete_attempt(&shared, &request, target, lineage_rule)?;

    let scope = scope(request.reference(), &[target], lineage_rule)?;
    let extension = extension(request.reference(), &scope, lineage_rule)?;
    let mut coordinator = exact_coordinator(&shared, target, lineage_rule);
    let recovered_terminal =
        coordinator.freeze_inventory(request.reference(), &freeze_transition())?;
    assert_eq!(recovered_terminal.lifecycle(), ErasureLifecycleV1::Complete);
    let extended = coordinator.append_scope_extension(request.reference(), extension)?;
    {
        let adapter = shared.borrow();
        assert_eq!(adapter.scope_index_count(request.reference())?, 1);
        assert!(adapter.scope_node_ref(request.reference(), 0)?.is_some());
    }

    let resolution = resolution(request.reference(), &recovered_terminal, &scope)?;
    let mut coordinator = exact_coordinator(&shared, target, lineage_rule);
    assert_eq!(
        coordinator.append_scope_extension(request.reference(), extension)?,
        extended
    );
    let resolved = coordinator.resolve_administratively(request.reference(), &resolution)?;
    let mut coordinator = exact_coordinator(&shared, target, lineage_rule);
    assert_eq!(
        coordinator.resolve_administratively(request.reference(), &resolution)?,
        resolved
    );
    let adapter = shared.borrow();
    assert_eq!(
        adapter.administrative_resolution_index_count(request.reference())?,
        1
    );
    assert!(adapter
        .administrative_resolution_ref(request.reference(), 0)?
        .is_some());
    Ok(())
}

fn exercise_partial_retry_recovery<S>(store: S) -> Result<(), Box<dyn std::error::Error>>
where
    S: ErasurePersistencePortV1,
{
    let shared = Rc::new(RefCell::new(store));
    let request = request()?;
    let target = target();
    let lineage_rule = reference(40);
    let mut coordinator = exact_coordinator(&shared, target, lineage_rule);
    coordinator.submit(request.clone(), request.provenance())?;
    coordinator.authorize(request.reference(), reference(43))?;
    coordinator.freeze_inventory(request.reference(), &freeze_transition())?;

    let first_admission = retry_admission(request.reference(), target, 0, None)?;
    exact_coordinator(&shared, target, lineage_rule)
        .dispatch_attempt(request.reference(), &first_admission)?;
    exact_coordinator(&shared, target, lineage_rule).acknowledge(
        request.reference(),
        acknowledgement(
            request.reference(),
            target,
            reference(51),
            ErasureAcknowledgementOutcomeV1::Negative,
        )?,
    )?;
    let partial = exact_coordinator(&shared, target, lineage_rule)
        .finalize(request.reference(), receipt_input(target, 20))?;
    assert_eq!(partial.lifecycle(), ErasureLifecycleV1::PartialFailure);

    let retry = retry_admission(
        request.reference(),
        target,
        1,
        Some(partial.receipt_digest()),
    )?;
    let retry_state = exact_coordinator(&shared, target, lineage_rule)
        .dispatch_attempt(request.reference(), &retry)?;
    assert_eq!(retry_state.lifecycle(), ErasureLifecycleV1::PartialFailure);
    exact_coordinator(&shared, target, lineage_rule).acknowledge(
        request.reference(),
        acknowledgement(
            request.reference(),
            target,
            reference(52),
            ErasureAcknowledgementOutcomeV1::Acknowledged,
        )?,
    )?;
    let complete = exact_coordinator(&shared, target, lineage_rule)
        .finalize(request.reference(), receipt_input(target, 30))?;
    assert_eq!(complete.lifecycle(), ErasureLifecycleV1::Complete);
    assert_eq!(shared.borrow().attempt_index_count(request.reference())?, 2);
    Ok(())
}

#[test]
fn memory_public_scope_and_resolution_indexes_are_idempotent(
) -> Result<(), Box<dyn std::error::Error>> {
    exercise_scope_and_resolution(MemoryStore::new())
}

#[test]
fn memory_public_attempt_history_recovers_across_partial_retry(
) -> Result<(), Box<dyn std::error::Error>> {
    exercise_partial_retry_recovery(MemoryStore::new())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_public_scope_and_resolution_indexes_are_idempotent(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or(ErasureErrorV1::InvalidEncoding)?
        .to_owned();
    exercise_scope_and_resolution(SqliteStore::open(&path)?)
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_public_attempt_history_recovers_across_partial_retry(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or(ErasureErrorV1::InvalidEncoding)?;
    exercise_partial_retry_recovery(SqliteStore::open(path)?)
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_public_reads_map_missing_schema_to_closed_storage_errors(
) -> Result<(), Box<dyn std::error::Error>> {
    for operation in [
        SqliteReadOperation::Manifest,
        SqliteReadOperation::Object,
        SqliteReadOperation::Effect,
        SqliteReadOperation::EffectManifest,
        SqliteReadOperation::AttemptRef,
        SqliteReadOperation::AttemptCount,
        SqliteReadOperation::ScopeRef,
        SqliteReadOperation::ScopeCount,
        SqliteReadOperation::ResolutionRef,
        SqliteReadOperation::ResolutionCount,
        SqliteReadOperation::RecoveryErrorRefs,
        SqliteReadOperation::State,
    ] {
        let database = tempfile::NamedTempFile::new()?;
        let path = database
            .path()
            .to_str()
            .ok_or(ErasureErrorV1::InvalidEncoding)?;
        let store = SqliteStore::open(path)?;
        let connection = rusqlite::Connection::open(path)?;
        let table = operation.table();
        connection.execute_batch(&format!("DROP TABLE {table}"))?;
        assert_eq!(
            operation.invoke(&store),
            Err(ErasureErrorV1::ReceiptCommitFailed)
        );
    }
    Ok(())
}

#[cfg(feature = "sqlite")]
#[derive(Clone, Copy)]
enum SqliteFaultKind {
    MissingObject,
    MismatchedState,
    MissingIndex,
    MismatchedEffect,
    ApplyWithMismatchedState,
}

#[cfg(feature = "sqlite")]
#[derive(Clone, Copy)]
enum SqliteReadOperation {
    Manifest,
    Object,
    Effect,
    EffectManifest,
    AttemptRef,
    AttemptCount,
    ScopeRef,
    ScopeCount,
    ResolutionRef,
    ResolutionCount,
    RecoveryErrorRefs,
    State,
}

#[cfg(feature = "sqlite")]
impl SqliteReadOperation {
    const fn table(self) -> &'static str {
        match self {
            Self::Manifest => "erasure_records",
            Self::Object => "erasure_evidence",
            Self::Effect | Self::EffectManifest => "erasure_effects",
            Self::AttemptRef | Self::AttemptCount => "erasure_attempt_pages",
            Self::ScopeRef | Self::ScopeCount => "erasure_scope_nodes",
            Self::ResolutionRef | Self::ResolutionCount => "erasure_administrative_resolutions",
            Self::RecoveryErrorRefs => "erasure_recovery_errors",
            Self::State => "erasure_states",
        }
    }

    fn invoke(self, store: &SqliteStore) -> Result<(), ErasureErrorV1> {
        match self {
            Self::Manifest => store.read_manifest(reference(1)).map(|_| ()),
            Self::Object => store.read_object(reference(1)).map(|_| ()),
            Self::Effect => store.read_effect(reference(1)).map(|_| ()),
            Self::EffectManifest => store.effect_manifest(reference(1)).map(|_| ()),
            Self::AttemptRef => store.attempt_page_ref(reference(1), 0).map(|_| ()),
            Self::AttemptCount => store.attempt_index_count(reference(1)).map(|_| ()),
            Self::ScopeRef => store.scope_node_ref(reference(1), 0).map(|_| ()),
            Self::ScopeCount => store.scope_index_count(reference(1)).map(|_| ()),
            Self::ResolutionRef => store
                .administrative_resolution_ref(reference(1), 0)
                .map(|_| ()),
            Self::ResolutionCount => store
                .administrative_resolution_index_count(reference(1))
                .map(|_| ()),
            Self::RecoveryErrorRefs => store.recovery_error_refs(reference(1)).map(|_| ()),
            Self::State => store.resolve_state(reference(1)).map(|_| ()),
        }
    }
}

#[cfg(feature = "sqlite")]
impl SqliteFaultKind {
    const fn fail_on(self) -> usize {
        match self {
            Self::MissingIndex => 4,
            Self::MissingObject
            | Self::MismatchedState
            | Self::MismatchedEffect
            | Self::ApplyWithMismatchedState => 1,
        }
    }

    const fn expected_error(self) -> ErasureErrorV1 {
        match self {
            Self::ApplyWithMismatchedState => ErasureErrorV1::ProvenanceMissing,
            Self::MissingObject
            | Self::MismatchedState
            | Self::MissingIndex
            | Self::MismatchedEffect => ErasureErrorV1::PolicyConflict,
        }
    }

    const fn uses_scope_operation(self) -> bool {
        matches!(self, Self::MissingIndex)
    }
}

#[cfg(feature = "sqlite")]
struct SqliteFaultHook {
    path: std::path::PathBuf,
    kind: SqliteFaultKind,
    call: usize,
}

#[cfg(feature = "sqlite")]
impl SqliteFaultHook {
    fn new(path: &str, kind: SqliteFaultKind) -> Self {
        Self {
            path: std::path::PathBuf::from(path),
            kind,
            call: 0,
        }
    }

    fn corrupt(&self, mutation: &PreparedErasureCasV1) -> Result<(), ErasureErrorV1> {
        let connection = rusqlite::Connection::open(&self.path)
            .map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
        match self.kind {
            SqliteFaultKind::MissingObject => {
                let object = mutation
                    .new_objects()
                    .first()
                    .ok_or(ErasureErrorV1::ProvenanceMissing)?;
                let digest = object.reference().digest();
                connection
                    .execute(
                        "DELETE FROM erasure_evidence WHERE reference_digest=?1",
                        rusqlite::params![digest.as_slice()],
                    )
                    .map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
            }
            SqliteFaultKind::MismatchedState | SqliteFaultKind::ApplyWithMismatchedState => {
                let state = mutation
                    .new_states()
                    .first()
                    .ok_or(ErasureErrorV1::ProvenanceMissing)?;
                let digest = state.reference().digest();
                connection
                    .execute(
                        "UPDATE erasure_states SET state_cbor=?1 WHERE state_digest=?2",
                        rusqlite::params![vec![0xff_u8], digest.as_slice()],
                    )
                    .map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
                if matches!(self.kind, SqliteFaultKind::ApplyWithMismatchedState) {
                    if mutation.expected_manifest_digest().is_some() {
                        return Err(ErasureErrorV1::PolicyConflict);
                    }
                    let request = mutation.request().digest();
                    connection
                        .execute(
                            "DELETE FROM erasure_records WHERE request_digest=?1",
                            rusqlite::params![request.as_slice()],
                        )
                        .map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
                }
            }
            SqliteFaultKind::MissingIndex => {
                let index = mutation
                    .index_inserts()
                    .first()
                    .copied()
                    .ok_or(ErasureErrorV1::ProvenanceMissing)?;
                let request = mutation.request().digest();
                match index {
                    ErasureIndexInsertV1::AttemptPage { ordinal, .. } => {
                        connection
                            .execute(
                                "DELETE FROM erasure_attempt_pages WHERE request_digest=?1 AND ordinal=?2",
                                rusqlite::params![request.as_slice(), i64::try_from(ordinal).map_err(|_| ErasureErrorV1::PolicyConflict)?],
                            )
                            .map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
                    }
                    ErasureIndexInsertV1::ScopeNode { ordinal, .. } => {
                        connection
                            .execute(
                                "DELETE FROM erasure_scope_nodes WHERE request_digest=?1 AND ordinal=?2",
                                rusqlite::params![request.as_slice(), i64::try_from(ordinal).map_err(|_| ErasureErrorV1::PolicyConflict)?],
                            )
                            .map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
                    }
                    ErasureIndexInsertV1::AdministrativeResolution { ordinal, .. } => {
                        connection
                            .execute(
                                "DELETE FROM erasure_administrative_resolutions WHERE request_digest=?1 AND ordinal=?2",
                                rusqlite::params![request.as_slice(), i64::try_from(ordinal).map_err(|_| ErasureErrorV1::PolicyConflict)?],
                            )
                            .map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
                    }
                }
            }
            SqliteFaultKind::MismatchedEffect => {
                let manifest = mutation.next_manifest().digest().digest();
                connection
                    .execute(
                        "UPDATE erasure_effects SET effect_cbor=?1 WHERE manifest_digest=?2",
                        rusqlite::params![vec![0xff_u8], manifest.as_slice()],
                    )
                    .map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
            }
        }
        Ok(())
    }
}

#[cfg(feature = "sqlite")]
impl RetryHook<SqliteStore> for SqliteFaultHook {
    fn before_retry(
        &mut self,
        _store: &Rc<RefCell<SqliteStore>>,
        mutation: &PreparedErasureCasV1,
    ) -> Result<RetryExpectation, ErasureErrorV1> {
        self.call = self.call.saturating_add(1);
        if self.call == self.kind.fail_on() {
            self.corrupt(mutation)?;
            Ok(RetryExpectation::Propagate)
        } else {
            Ok(RetryExpectation::Exact)
        }
    }
}

#[cfg(feature = "sqlite")]
fn exercise_sqlite_fault(kind: SqliteFaultKind) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or(ErasureErrorV1::InvalidEncoding)?
        .to_owned();
    let shared = Rc::new(RefCell::new(SqliteStore::open(&path)?));
    let request = request()?;
    let target = target();
    let lineage_rule = reference(40);
    let mut coordinator = pos_core::ErasureCoordinatorStateMachineV1::new(
        AdapterHost {
            store: Rc::clone(&shared),
            targets: vec![target],
            lineage_rule,
            freeze_evidence: reference(41),
            retry_hook: SqliteFaultHook::new(&path, kind),
        },
        reference(42),
    );

    let result = if kind.uses_scope_operation() {
        coordinator.submit(request.clone(), request.provenance())?;
        coordinator.authorize(request.reference(), reference(43))?;
        coordinator.freeze_inventory(request.reference(), &freeze_transition())?;
        let scope = scope(request.reference(), &[target], lineage_rule)?;
        let extension = extension(request.reference(), &scope, lineage_rule)?;
        coordinator
            .append_scope_extension(request.reference(), extension)
            .map(|_| ())
    } else {
        coordinator
            .submit(request.clone(), request.provenance())
            .map(|_| ())
    };
    assert_eq!(result, Err(kind.expected_error()));
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_exact_retry_rechecks_each_public_durable_component(
) -> Result<(), Box<dyn std::error::Error>> {
    for kind in [
        SqliteFaultKind::MissingObject,
        SqliteFaultKind::MismatchedState,
        SqliteFaultKind::MissingIndex,
        SqliteFaultKind::MismatchedEffect,
    ] {
        exercise_sqlite_fault(kind)?;
    }
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_apply_rejects_a_mismatched_state_row() -> Result<(), Box<dyn std::error::Error>> {
    exercise_sqlite_fault(SqliteFaultKind::ApplyWithMismatchedState)
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_state_resolution_rejects_a_foreign_request_binding(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or(ErasureErrorV1::InvalidEncoding)?
        .to_owned();
    let shared = Rc::new(RefCell::new(SqliteStore::open(&path)?));
    let request = request()?;
    let state = {
        let mut coordinator = pos_core::ErasureCoordinatorStateMachineV1::new(
            AdapterHost {
                store: Rc::clone(&shared),
                targets: vec![target()],
                lineage_rule: reference(40),
                freeze_evidence: reference(41),
                retry_hook: ExactRetryHook,
            },
            reference(42),
        );
        coordinator.submit(request.clone(), request.provenance())?
    };
    let connection = rusqlite::Connection::open(&path)?;
    let foreign_request = reference(250).digest();
    let state_digest = state.state_digest().digest();
    connection.execute(
        "UPDATE erasure_states SET request_digest=?1 WHERE state_digest=?2",
        rusqlite::params![foreign_request.as_slice(), state_digest.as_slice()],
    )?;
    assert_eq!(
        shared.borrow().resolve_state(state.state_digest()),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_public_indexes_reject_unrepresentable_ordinals() -> Result<(), Box<dyn std::error::Error>>
{
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or(ErasureErrorV1::InvalidEncoding)?;
    let store = SqliteStore::open(path)?;
    for result in [
        store.attempt_page_ref(reference(1), u64::MAX),
        store.scope_node_ref(reference(1), u64::MAX),
        store.administrative_resolution_ref(reference(1), u64::MAX),
    ] {
        assert_eq!(result, Err(ErasureErrorV1::PolicyConflict));
    }
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_public_reads_reject_malformed_reference_columns() -> Result<(), Box<dyn std::error::Error>>
{
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or(ErasureErrorV1::InvalidEncoding)?;
    let store = SqliteStore::open(path)?;
    let connection = rusqlite::Connection::open(path)?;
    connection.execute_batch("PRAGMA ignore_check_constraints=ON")?;
    let request_digest = reference(1).digest();
    let malformed = vec![1_u8];

    connection.execute(
        "INSERT INTO erasure_records(request_digest,manifest_digest,manifest_cbor) VALUES(?1,?2,?3)",
        rusqlite::params![request_digest.as_slice(), &malformed, vec![0_u8]],
    )?;
    assert_eq!(
        store.read_manifest(reference(1)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    for (table, read) in [
        ("erasure_attempt_pages", SqliteReadOperation::AttemptRef),
        ("erasure_scope_nodes", SqliteReadOperation::ScopeRef),
        (
            "erasure_administrative_resolutions",
            SqliteReadOperation::ResolutionRef,
        ),
    ] {
        connection.execute(
            &format!(
                "INSERT INTO {table}(request_digest,ordinal,reference_digest) VALUES(?1,0,?2)"
            ),
            rusqlite::params![request_digest.as_slice(), &malformed],
        )?;
        assert_eq!(read.invoke(&store), Err(ErasureErrorV1::ProvenanceMissing));
    }

    let manifest = reference(2).digest();
    let subject = reference(3).digest();
    connection.execute(
        "INSERT INTO erasure_effects(manifest_digest,effect_digest,subject_digest,effect_cbor) VALUES(?1,?2,?3,?4)",
        rusqlite::params![
            manifest.as_slice(),
            &malformed,
            subject.as_slice(),
            pos_core::ErasureCasEffectV1::None.to_canonical_cbor()?
        ],
    )?;
    assert_eq!(
        store.read_effect(reference(2)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    connection.execute(
        "UPDATE erasure_effects SET manifest_digest=?1 WHERE subject_digest=?2",
        rusqlite::params![&malformed, subject.as_slice()],
    )?;
    assert_eq!(
        store.effect_manifest(reference(3)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let state_digest = reference(4).digest();
    connection.execute(
        "INSERT INTO erasure_states(state_digest,request_digest,state_cbor) VALUES(?1,?2,?3)",
        rusqlite::params![state_digest.as_slice(), &malformed, vec![0_u8]],
    )?;
    assert_eq!(
        store.resolve_state(reference(4)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}
