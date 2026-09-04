//! Backend parity for the raw ERCRP1 manifest/CAS persistence port.

use std::cell::RefCell;
use std::rc::Rc;

use pos_core::erasure::{target_closure_digest, ErasureAuthorizationDecisionV1};
use pos_core::{
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementProvenanceV1, ErasureAcknowledgementV1,
    ErasureArtifactTransitionV1, ErasureAtomicFreezeAdmissionInputV1,
    ErasureAtomicFreezeAdmissionV1, ErasureAtomicFreezeResultV1, ErasureAttemptQuotaReservationV1,
    ErasureCoordinatorPortV1, ErasureCoordinatorStateMachineV1, ErasureDestructionCommandV1,
    ErasureErrorV1, ErasureFreezeAdmissionEvidenceV1, ErasureFreezeAuthorizationEvidenceV1,
    ErasureFreezeAuthorizationVerifierV1, ErasureIndexInsertV1, ErasureInventoryCategoryV1,
    ErasureInventoryResultV1, ErasureLifecycleV1, ErasureObligationSetInputV1,
    ErasureObligationSetV1, ErasureObligationV1, ErasurePersistencePortV1, ErasureReceiptInputV1,
    ErasureReceiptInventoriesV1, ErasureRecoveryAuthorizationVerifierV1, ErasureRecoveryErrorV1,
    ErasureReferenceV1, ErasureReplayClaimV1, ErasureRequestV1, ErasureRequiredTargetV1,
    ErasureRetryAdmissionV1, ErasureScopeCommitmentInputV1, ErasureScopeCommitmentV1,
    ErasureScopeExtensionV1, ErasureScopeV1, ErasureStateResolverV1, ErasureStateTransitionV1,
    ErasureStateV1, ERASURE_MAX_RECOVERY_ERRORS,
};
use pos_store::memory::MemoryStore;

#[path = "support/erasure.rs"]
mod erasure_support;

use erasure_support::{
    freeze_evidence_fixture, obligation, reference, replay_target, request as fixture_request,
    retry_admission as fixture_retry_admission, FreezeEvidenceFixtureInput, RequestFixtureInput,
    RetryAdmissionFixture,
};

#[cfg(feature = "sqlite")]
use pos_store::sqlite::SqliteStore;

fn request() -> Result<ErasureRequestV1, ErasureErrorV1> {
    fixture_request(RequestFixtureInput {
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

const fn target() -> ErasureRequiredTargetV1 {
    replay_target(10)
}

fn admission(
    request: ErasureReferenceV1,
    target: ErasureRequiredTargetV1,
) -> Result<ErasureRetryAdmissionV1, ErasureErrorV1> {
    let obligation = obligation(request, target)?;
    fixture_retry_admission(RetryAdmissionFixture {
        request,
        attempt_ordinal: 0,
        source_receipt: None,
        obligations: std::slice::from_ref(&obligation),
        policy: reference(6),
        trust: reference(8),
        admitted_position: 11,
        deadline_position: 20,
        authorization_provenance: reference(12),
    })
}

const fn inventory(target: ErasureRequiredTargetV1) -> ErasureInventoryResultV1 {
    ErasureInventoryResultV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target,
        transition: ErasureArtifactTransitionV1 {
            from: ErasureReplayClaimV1::Exact,
            to: ErasureReplayClaimV1::StructuralOnly,
            reason: reference(20),
            owner: target.replica_id,
            acknowledgements: reference(21),
            provenance: reference(22),
        },
        retained_disclosure: reference(23),
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
        provenance: reference(11),
    }
}

struct Host<S> {
    store: Rc<RefCell<S>>,
    targets: Vec<ErasureRequiredTargetV1>,
    verify_exact_retry: bool,
    fail_read_object: bool,
}

type RetainedEffect = (ErasureReferenceV1, pos_core::ErasureCasEffectV1);
type CompletedErasure<S> = (Rc<RefCell<S>>, ErasureRequestV1, Vec<RetainedEffect>);

impl<S: ErasurePersistencePortV1> ErasureStateResolverV1 for Host<S> {
    fn resolve_state(
        &self,
        digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureStateV1>, ErasureErrorV1> {
        self.store.borrow().resolve_state(digest)
    }
}

impl<S: ErasurePersistencePortV1> ErasurePersistencePortV1 for Host<S> {
    fn read_manifest(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Option<pos_core::StoredErasureManifestV1>, ErasureErrorV1> {
        self.store.borrow().read_manifest(request)
    }

    fn read_object(&self, reference: ErasureReferenceV1) -> Result<Vec<u8>, ErasureErrorV1> {
        if self.fail_read_object {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
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
        mutation: pos_core::PreparedErasureCasV1,
    ) -> Result<pos_core::ErasureCasOutcomeV1, ErasureErrorV1> {
        let retry = self.verify_exact_retry.then_some(mutation.clone());
        let outcome = self.store.borrow_mut().compare_and_swap(mutation)?;
        if let Some(retry) = retry {
            let retry_outcome = self.store.borrow_mut().compare_and_swap(retry)?;
            if retry_outcome != pos_core::ErasureCasOutcomeV1::ExactRetry {
                return Err(ErasureErrorV1::PolicyConflict);
            }
        }
        Ok(outcome)
    }
}

impl<S: ErasurePersistencePortV1> ErasureFreezeAuthorizationVerifierV1 for Host<S> {
    fn validate_freeze_authorization(
        &self,
        admission: &ErasureFreezeAdmissionEvidenceV1,
        authorization: &ErasureFreezeAuthorizationEvidenceV1,
    ) -> Result<(), ErasureErrorV1> {
        authorization.verify_admission_body_binding(admission)
    }
}

impl<S: ErasurePersistencePortV1> ErasureRecoveryAuthorizationVerifierV1 for Host<S> {
    fn validate_scope_extension(
        &self,
        _extension: &ErasureScopeExtensionV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn validate_administrative_resolution(
        &self,
        _resolution: &pos_core::ErasureAdministrativeResolutionV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }
}

impl<S: ErasurePersistencePortV1> ErasureCoordinatorPortV1 for Host<S> {
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
        requested: &ErasureStateTransitionV1,
    ) -> Result<ErasureAtomicFreezeResultV1, ErasureErrorV1> {
        let mut targets = self.targets.clone();
        targets.sort_unstable();
        let mut obligations = targets
            .iter()
            .copied()
            .map(|target| obligation(request, target))
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
        let scope = ErasureScopeCommitmentInputV1 {
            request,
            scope_members: vec![reference(9)],
            target_closure: target_closure_digest(&targets),
            lineage_rule: None,
        };
        let scope_reference = ErasureScopeCommitmentV1::new(scope.clone())?.reference();
        let evidence = requested.provenance.digest();
        let freeze_position = requested.freeze_position.unwrap_or(10);
        let (freeze_admission_evidence, freeze_authorization_evidence) =
            freeze_evidence_fixture(FreezeEvidenceFixtureInput {
                request,
                scope_commitment: scope_reference,
                obligation_set: &obligation_set,
                targets: &targets,
                obligations: &obligations,
                freeze_position,
                evidence: &evidence,
            })?;
        ErasureAtomicFreezeAdmissionV1::new(ErasureAtomicFreezeAdmissionInputV1 {
            targets,
            scope,
            obligations,
            obligation_set,
            freeze_position,
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
        _resolution: &pos_core::ErasureAdministrativeResolutionV1,
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

    fn admit_receipt(&self, _input: &ErasureReceiptInputV1) -> Result<(), ErasureErrorV1> {
        Ok(())
    }
}

fn complete<S: ErasurePersistencePortV1>(store: S) -> Result<CompletedErasure<S>, ErasureErrorV1> {
    complete_with_retry_validation(store, false)
}

fn complete_with_retry_validation<S: ErasurePersistencePortV1>(
    store: S,
    verify_exact_retry: bool,
) -> Result<CompletedErasure<S>, ErasureErrorV1> {
    let shared = Rc::new(RefCell::new(store));
    let request = request()?;
    let target = target();
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(
        Host {
            store: Rc::clone(&shared),
            targets: vec![target],
            verify_exact_retry,
            fail_read_object: false,
        },
        reference(30),
    );
    coordinator.submit(request.clone(), request.provenance())?;
    coordinator.authorize(request.reference(), reference(31))?;
    coordinator.freeze_inventory(request.reference(), &transition())?;
    let admission = admission(request.reference(), target)?;
    coordinator.dispatch_attempt(request.reference(), &admission)?;
    let mut effects = vec![retained_effect(&shared, request.reference())?];
    assert_eq!(
        effects[0].1,
        pos_core::ErasureCasEffectV1::AttemptAdmission {
            reservation: ErasureAttemptQuotaReservationV1::new(
                admission.reference(),
                admission.reference(),
            ),
            commands: vec![ErasureDestructionCommandV1::from_obligation(
                &obligation(request.reference(), target)?,
                admission.reference(),
            )],
        }
    );
    let obligation = obligation(request.reference(), target)?;
    coordinator.acknowledge(
        request.reference(),
        ErasureAcknowledgementV1 {
            obligation: obligation.reference(),
            target,
            owner: target.replica_id,
            evidence: reference(32),
            outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
        },
    )?;
    effects.push(retained_effect(&shared, request.reference())?);
    assert!(matches!(
        &effects[1].1,
        pos_core::ErasureCasEffectV1::AcknowledgementAdmission { .. }
    ));
    let receipt = coordinator.finalize(
        request.reference(),
        ErasureReceiptInputV1 {
            request: reference(0),
            terminal_state: reference(0),
            coordinator: reference(0),
            lifecycle: ErasureLifecycleV1::Complete,
            freeze_position: 10,
            acknowledgements: Vec::new(),
            frozen_targets: vec![target],
            pending_owners: Vec::new(),
            failed_owners: Vec::new(),
            inventories: ErasureReceiptInventoriesV1 {
                artifacts: vec![inventory(target)],
                keys: Vec::new(),
                replicas: Vec::new(),
                backups: Vec::new(),
            },
            replay_claim: ErasureReplayClaimV1::StructuralOnly,
            policy: reference(0),
            trust: reference(0),
            provenance: reference(0),
            issue_position: 21,
            signature: reference(33),
            receipt_digest: reference(0),
        },
    )?;
    effects.push(retained_effect(&shared, request.reference())?);
    assert_eq!(
        effects[2].1,
        pos_core::ErasureCasEffectV1::ReceiptAdmission {
            receipt: receipt.receipt_digest(),
        }
    );
    Ok((shared, request, effects))
}

fn retained_effect<S: ErasurePersistencePortV1>(
    store: &Rc<RefCell<S>>,
    request: ErasureReferenceV1,
) -> Result<RetainedEffect, ErasureErrorV1> {
    let store = store.borrow();
    let manifest = store
        .read_manifest(request)?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .digest();
    let effect = store.read_effect(manifest)?;
    if let Some(subject) = effect.subject() {
        if store.effect_manifest(subject)? != Some(manifest) {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
    }
    Ok((manifest, effect))
}

fn assert_raw_backend<S: ErasurePersistencePortV1>(
    store: S,
) -> Result<(), Box<dyn std::error::Error>> {
    let (shared, request, _) = complete(store)?;
    let backend = shared.borrow();
    let manifest = backend
        .read_manifest(request.reference())?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    assert!(!manifest.canonical_cbor().is_empty());
    assert_eq!(backend.attempt_index_count(request.reference())?, 1);
    assert!(backend.attempt_page_ref(request.reference(), 0)?.is_some());
    assert!(backend.read_object(request.reference()).is_ok());
    drop(backend);

    let mut restarted = ErasureCoordinatorStateMachineV1::new(
        Host {
            store: shared,
            targets: vec![target()],
            verify_exact_retry: false,
            fail_read_object: false,
        },
        reference(30),
    );
    let provenance = request.provenance();
    let recovered = restarted.submit(request, provenance)?;
    assert_eq!(recovered.lifecycle(), ErasureLifecycleV1::Complete);
    Ok(())
}

fn assert_stale_head<S: ErasurePersistencePortV1>(
    store: S,
) -> Result<(), Box<dyn std::error::Error>> {
    let shared = Rc::new(RefCell::new(store));
    let request = request()?;
    let mut first = ErasureCoordinatorStateMachineV1::new(
        Host {
            store: Rc::clone(&shared),
            targets: Vec::new(),
            verify_exact_retry: false,
            fail_read_object: false,
        },
        reference(30),
    );
    let mut second = ErasureCoordinatorStateMachineV1::new(
        Host {
            store: shared,
            targets: Vec::new(),
            verify_exact_retry: false,
            fail_read_object: false,
        },
        reference(30),
    );
    first.submit(request.clone(), request.provenance())?;
    second.submit(request.clone(), request.provenance())?;
    first.authorize(request.reference(), reference(34))?;
    assert_eq!(
        second.authorize(request.reference(), reference(35)),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

fn assert_empty_backend<S: ErasurePersistencePortV1>(
    store: &S,
) -> Result<(), Box<dyn std::error::Error>> {
    let missing = reference(250);
    assert_eq!(store.read_manifest(missing)?, None);
    assert_eq!(
        store.read_object(missing),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        store.read_effect(missing),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(store.effect_manifest(missing)?, None);
    assert_eq!(store.attempt_page_ref(missing, 0)?, None);
    assert_eq!(store.attempt_index_count(missing)?, 0);
    assert_eq!(store.scope_node_ref(missing, 0)?, None);
    assert_eq!(store.scope_index_count(missing)?, 0);
    assert_eq!(store.administrative_resolution_ref(missing, 0)?, None);
    assert_eq!(store.administrative_resolution_index_count(missing)?, 0);
    assert!(store.recovery_error_refs(missing)?.is_empty());
    Ok(())
}

#[test]
fn memory_manifest_cas_survives_restart_and_retains_indexes(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_raw_backend(MemoryStore::new())
}

#[test]
fn memory_manifest_cas_rejects_a_stale_head() -> Result<(), Box<dyn std::error::Error>> {
    assert_stale_head(MemoryStore::new())
}

#[test]
fn memory_manifest_cas_reports_empty_indexes_and_objects() -> Result<(), Box<dyn std::error::Error>>
{
    assert_empty_backend(&MemoryStore::new())
}

#[test]
fn memory_manifest_cas_accepts_exact_retry_for_every_effect(
) -> Result<(), Box<dyn std::error::Error>> {
    complete_with_retry_validation(MemoryStore::new(), true)?;
    Ok(())
}

#[test]
fn memory_recovery_errors_are_idempotent_and_retrievable() -> Result<(), Box<dyn std::error::Error>>
{
    let (shared, request, _) = complete(MemoryStore::new())?;
    let manifest = shared
        .borrow()
        .read_manifest(request.reference())?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .digest();
    let mut failing = ErasureCoordinatorStateMachineV1::new(
        Host {
            store: Rc::clone(&shared),
            targets: vec![target()],
            verify_exact_retry: false,
            fail_read_object: true,
        },
        reference(30),
    );
    for _ in 0..2 {
        assert_eq!(
            failing.verified_state(request.reference()),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
    }
    drop(failing);

    let observer = ErasureCoordinatorStateMachineV1::new(
        Host {
            store: shared,
            targets: vec![target()],
            verify_exact_retry: false,
            fail_read_object: false,
        },
        reference(30),
    );
    let failures = observer.recovery_errors(request.reference())?;
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].manifest(), Some(manifest));
    assert_eq!(failures[0].error(), ErasureErrorV1::ProvenanceMissing);
    Ok(())
}

#[cfg(feature = "sqlite")]
fn retained_recovery_failure<S: ErasurePersistencePortV1>(
    store: S,
) -> Result<(ErasureRecoveryErrorV1, Vec<u8>), ErasureErrorV1> {
    let (shared, request, _) = complete(store)?;
    let mut failing = ErasureCoordinatorStateMachineV1::new(
        Host {
            store: Rc::clone(&shared),
            targets: vec![target()],
            verify_exact_retry: false,
            fail_read_object: true,
        },
        reference(30),
    );
    assert_eq!(
        failing.verified_state(request.reference()),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let observer = ErasureCoordinatorStateMachineV1::new(
        Host {
            store: shared,
            targets: vec![target()],
            verify_exact_retry: false,
            fail_read_object: false,
        },
        reference(30),
    );
    let failure = observer
        .recovery_errors(request.reference())?
        .into_iter()
        .next()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let bytes = failure.to_canonical_cbor()?;
    Ok((failure, bytes))
}

#[cfg(feature = "sqlite")]
#[test]
fn recovery_error_identity_and_canonical_bytes_match_across_backends(
) -> Result<(), Box<dyn std::error::Error>> {
    let memory = retained_recovery_failure(MemoryStore::new())?;
    let sqlite = retained_recovery_failure(SqliteStore::open_in_memory()?)?;
    assert_eq!(memory.0, sqlite.0);
    assert_eq!(memory.1, sqlite.1);
    assert_eq!(memory.0.reference(), sqlite.0.reference());
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_manifest_cas_survives_restart_and_retains_indexes(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_raw_backend(SqliteStore::open_in_memory()?)
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_manifest_cas_rejects_a_stale_head() -> Result<(), Box<dyn std::error::Error>> {
    assert_stale_head(SqliteStore::open_in_memory()?)
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_manifest_cas_reports_empty_indexes_and_objects() -> Result<(), Box<dyn std::error::Error>>
{
    assert_empty_backend(&SqliteStore::open_in_memory()?)
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_manifest_cas_accepts_exact_retry_for_every_effect(
) -> Result<(), Box<dyn std::error::Error>> {
    complete_with_retry_validation(SqliteStore::open_in_memory()?, true)?;
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_effect_payloads_survive_file_backed_reopen() -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or(ErasureErrorV1::InvalidEncoding)?;
    let (shared, request, effects) = complete(SqliteStore::open(path)?)?;
    drop(shared);

    let reopened = SqliteStore::open(path)?;
    for (manifest, expected) in effects {
        assert_eq!(reopened.read_effect(manifest)?, expected);
        if let Some(subject) = expected.subject() {
            assert_eq!(reopened.effect_manifest(subject)?, Some(manifest));
        }
    }
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(
        Host {
            store: Rc::new(RefCell::new(reopened)),
            targets: vec![target()],
            verify_exact_retry: false,
            fail_read_object: false,
        },
        reference(30),
    );
    let provenance = request.provenance();
    assert_eq!(
        coordinator.submit(request, provenance)?.lifecycle(),
        ErasureLifecycleV1::Complete
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_recovery_errors_survive_file_backed_reopen() -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or(ErasureErrorV1::InvalidEncoding)?;
    let (shared, request, _) = complete(SqliteStore::open(path)?)?;
    let manifest = shared
        .borrow()
        .read_manifest(request.reference())?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .digest();
    drop(shared);

    let raw = rusqlite::Connection::open(path)?;
    assert_eq!(
        raw.execute(
            "DELETE FROM erasure_evidence WHERE reference_digest=?1",
            rusqlite::params![request.reference().digest().as_slice()],
        )?,
        1
    );
    drop(raw);

    let mut failing = ErasureCoordinatorStateMachineV1::new(
        Host {
            store: Rc::new(RefCell::new(SqliteStore::open(path)?)),
            targets: vec![target()],
            verify_exact_retry: false,
            fail_read_object: false,
        },
        reference(30),
    );
    for _ in 0..2 {
        assert_eq!(
            failing.verified_state(request.reference()),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
    }
    drop(failing);

    let mut observer = ErasureCoordinatorStateMachineV1::new(
        Host {
            store: Rc::new(RefCell::new(SqliteStore::open(path)?)),
            targets: vec![target()],
            verify_exact_retry: false,
            fail_read_object: false,
        },
        reference(30),
    );
    let failures = observer.recovery_errors(request.reference())?;
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].manifest(), Some(manifest));
    assert_eq!(failures[0].error(), ErasureErrorV1::ProvenanceMissing);

    let failure_reference = failures[0].reference();
    let raw = rusqlite::Connection::open(path)?;
    raw.execute(
        "UPDATE erasure_evidence SET object_cbor=?1 WHERE reference_digest=?2",
        rusqlite::params![vec![0xff_u8], failure_reference.digest().as_slice()],
    )?;
    drop(raw);
    assert_eq!(
        observer.verified_state(request.reference()),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
fn assert_sqlite_recovery_error_retention_failure(
    open: impl FnOnce(&str) -> Result<SqliteStore, pos_core::CoreError>,
    corrupt: impl FnOnce(&rusqlite::Connection) -> rusqlite::Result<()>,
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or(ErasureErrorV1::InvalidEncoding)?;
    let (shared, request, _) = complete(SqliteStore::open(path)?)?;
    let store = open(path)?;
    drop(shared);
    let raw = rusqlite::Connection::open(path)?;
    corrupt(&raw)?;
    drop(raw);

    let mut coordinator = ErasureCoordinatorStateMachineV1::new(
        Host {
            store: Rc::new(RefCell::new(store)),
            targets: vec![target()],
            verify_exact_retry: false,
            fail_read_object: true,
        },
        reference(30),
    );
    assert_eq!(
        coordinator.verified_state(request.reference()),
        Err(ErasureErrorV1::ReceiptCommitFailed)
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_recovery_error_retention_fails_closed_at_backend_boundaries(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_sqlite_recovery_error_retention_failure(SqliteStore::open_read_only, |_connection| {
        Ok(())
    })?;
    assert_sqlite_recovery_error_retention_failure(SqliteStore::open, |connection| {
        connection.execute_batch(
            "DROP TABLE erasure_recovery_errors;
             CREATE TABLE erasure_recovery_errors (request_digest BLOB NOT NULL)",
        )
    })?;
    assert_sqlite_recovery_error_retention_failure(SqliteStore::open, |connection| {
        connection.execute_batch(
            "CREATE TRIGGER deny_recovery_error_index_insert
             BEFORE INSERT ON erasure_recovery_errors
             BEGIN SELECT RAISE(ABORT, 'recovery error index denied'); END;",
        )
    })?;
    assert_sqlite_recovery_error_retention_failure(SqliteStore::open, |connection| {
        connection.execute_batch(
            "CREATE TRIGGER deny_recovery_evidence_insert
             BEFORE INSERT ON erasure_evidence
             BEGIN SELECT RAISE(ABORT, 'recovery evidence denied'); END;",
        )
    })?;
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_recovery_error_reads_reject_an_over_bound_index() -> Result<(), Box<dyn std::error::Error>>
{
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or(ErasureErrorV1::InvalidEncoding)?;
    drop(SqliteStore::open(path)?);

    let request = reference(30);
    let reserved_reference =
        ErasureRecoveryErrorV1::new(request, None, request, ErasureErrorV1::ReceiptCommitFailed)?
            .reference();
    let raw = rusqlite::Connection::open(path)?;
    let mut inserted = 0_usize;
    let mut candidate_ordinal = 0_usize;
    while inserted <= ERASURE_MAX_RECOVERY_ERRORS {
        let ordinal = u64::try_from(candidate_ordinal)?;
        let mut digest = [0_u8; 32];
        digest[..8].copy_from_slice(&ordinal.to_be_bytes());
        if ErasureReferenceV1::from_digest(digest) != reserved_reference {
            raw.execute(
                "INSERT INTO erasure_recovery_errors(request_digest,error_digest)
                 VALUES(?1,?2)",
                rusqlite::params![request.digest().as_slice(), digest.as_slice()],
            )?;
            inserted = inserted.saturating_add(1);
        }
        candidate_ordinal = candidate_ordinal.saturating_add(1);
    }
    drop(raw);

    let store = SqliteStore::open(path)?;
    assert_eq!(
        store.recovery_error_refs(request),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let malformed_database = tempfile::NamedTempFile::new()?;
    let malformed_path = malformed_database
        .path()
        .to_str()
        .ok_or(ErasureErrorV1::InvalidEncoding)?;
    drop(SqliteStore::open(malformed_path)?);
    let malformed_connection = rusqlite::Connection::open(malformed_path)?;
    malformed_connection.execute_batch("PRAGMA ignore_check_constraints=ON")?;
    malformed_connection.execute(
        "INSERT INTO erasure_recovery_errors(request_digest,error_digest)
         VALUES(?1,?2)",
        rusqlite::params![request.digest().as_slice(), vec![1_u8]],
    )?;
    drop(malformed_connection);
    let malformed_store = SqliteStore::open(malformed_path)?;
    assert_eq!(
        malformed_store.recovery_error_refs(request),
        Err(ErasureErrorV1::ProvenanceMissing)
    );

    let schema_connection = rusqlite::Connection::open(path)?;
    schema_connection.execute_batch("DROP TABLE erasure_records")?;
    drop(schema_connection);
    let shared = Rc::new(RefCell::new(store));
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(
        Host {
            store: shared,
            targets: vec![target()],
            verify_exact_retry: false,
            fail_read_object: false,
        },
        reference(30),
    );
    assert_eq!(
        coordinator.verified_state(request),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_recovery_rejects_a_missing_durable_attempt_effect(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or(ErasureErrorV1::InvalidEncoding)?;
    let (shared, request, effects) = complete(SqliteStore::open(path)?)?;
    let attempt = effects
        .first()
        .and_then(|(_, effect)| effect.subject())
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    drop(shared);
    let raw = rusqlite::Connection::open(path)?;
    assert_eq!(
        raw.execute(
            "DELETE FROM erasure_effects WHERE subject_digest=?1",
            rusqlite::params![attempt.digest().as_slice()],
        )?,
        1
    );
    drop(raw);

    let mut coordinator = ErasureCoordinatorStateMachineV1::new(
        Host {
            store: Rc::new(RefCell::new(SqliteStore::open(path)?)),
            targets: vec![target()],
            verify_exact_retry: false,
            fail_read_object: false,
        },
        reference(30),
    );
    assert_eq!(
        coordinator.submit(request.clone(), request.provenance()),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_recovery_rejects_a_corrupted_durable_attempt_effect(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or(ErasureErrorV1::InvalidEncoding)?;
    let (shared, request, effects) = complete(SqliteStore::open(path)?)?;
    let manifest = effects
        .first()
        .map(|(manifest, _)| *manifest)
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    drop(shared);
    let raw = rusqlite::Connection::open(path)?;
    assert_eq!(
        raw.execute(
            "UPDATE erasure_effects SET effect_cbor=?1 WHERE manifest_digest=?2",
            rusqlite::params![&[0xff_u8], manifest.digest().as_slice()],
        )?,
        1
    );
    drop(raw);

    let mut coordinator = ErasureCoordinatorStateMachineV1::new(
        Host {
            store: Rc::new(RefCell::new(SqliteStore::open(path)?)),
            targets: vec![target()],
            verify_exact_retry: false,
            fail_read_object: false,
        },
        reference(30),
    );
    assert_eq!(
        coordinator.submit(request.clone(), request.provenance()),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn raw_index_variants_remain_explicitly_named() {
    assert!(matches!(
        ErasureIndexInsertV1::AttemptPage {
            ordinal: 0,
            reference: reference(1),
        },
        ErasureIndexInsertV1::AttemptPage { .. }
    ));
    assert!(matches!(
        ErasureIndexInsertV1::ScopeNode {
            ordinal: 0,
            reference: reference(2),
        },
        ErasureIndexInsertV1::ScopeNode { .. }
    ));
    assert!(matches!(
        ErasureIndexInsertV1::AdministrativeResolution {
            ordinal: 0,
            reference: reference(3),
        },
        ErasureIndexInsertV1::AdministrativeResolution { .. }
    ));
}
