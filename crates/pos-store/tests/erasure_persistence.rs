//! Black-box parity contracts for durable ERQ1/ERS1/ERC1 persistence.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use pos_core::erasure::target_closure_digest;
use pos_core::{
    CanonicalBytes, CoreError, EntityId, ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementV1,
    ErasureArtifactClassV1, ErasureArtifactTransitionV1, ErasureCoordinatorPortV1,
    ErasureCoordinatorRecordPartsV1, ErasureCoordinatorRecordV1, ErasureCoordinatorStateMachineV1,
    ErasureErrorV1, ErasureFreezeAdmissionV1, ErasureInventoryCategoryV1, ErasureInventoryResultV1,
    ErasureKeyRoleV1, ErasureLifecycleV1, ErasurePersistencePortV1, ErasureReceiptInputV1,
    ErasureReceiptInventoriesV1, ErasureReceiptV1, ErasureReferenceV1, ErasureReplayClaimV1,
    ErasureRequestInputV1, ErasureRequestV1, ErasureRequiredTargetV1, ErasureScopeV1,
    ErasureStateResolverV1, ErasureStateTransitionV1, ErasureStateV1, EventDraft, EventStore, Kind,
};
use pos_store::memory::MemoryStore;
use std::cell::RefCell;
use std::rc::Rc;

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
            reserved_targets: Vec::new(),
            targets: Vec::new(),
            acknowledgements: Vec::new(),
            receipt: None,
            receipt_input: None,
            authorize_provenance: None,
            freeze_provenance: None,
            freeze_admission: None,
            dispatch_provenance: None,
        },
        reference(8),
    )
}

fn record_parts(record: &ErasureCoordinatorRecordV1) -> ErasureCoordinatorRecordPartsV1 {
    ErasureCoordinatorRecordPartsV1 {
        request: record.request().clone(),
        state: record.state().clone(),
        reserved_targets: record.reserved_targets().to_vec(),
        targets: record.targets().to_vec(),
        acknowledgements: record.acknowledgements().to_vec(),
        receipt: record.receipt().cloned(),
        receipt_input: record.receipt_input().cloned(),
        authorize_provenance: record.authorize_provenance(),
        freeze_provenance: record.freeze_provenance(),
        freeze_admission: record.freeze_admission(),
        dispatch_provenance: record.dispatch_provenance(),
    }
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

const fn acknowledgement(
    target: ErasureRequiredTargetV1,
    evidence: u8,
) -> ErasureAcknowledgementV1 {
    ErasureAcknowledgementV1 {
        target,
        owner: target.replica_id,
        evidence: reference(evidence),
        outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
    }
}

const fn inventory(target: ErasureRequiredTargetV1) -> ErasureInventoryResultV1 {
    ErasureInventoryResultV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target,
        transition: ErasureArtifactTransitionV1 {
            from: ErasureReplayClaimV1::Exact,
            to: ErasureReplayClaimV1::StructuralOnly,
            reason: reference(50),
            owner: reference(51),
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

#[cfg(feature = "sqlite")]
struct DeletePredecessorBeforeCommit {
    store: SqliteStore,
    path: String,
    commit_calls: usize,
    delete_on_call: usize,
    replace_predecessor: bool,
    replace_request: bool,
}

#[cfg(feature = "sqlite")]
impl ErasureStateResolverV1 for DeletePredecessorBeforeCommit {
    fn resolve_state(
        &self,
        digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureStateV1>, ErasureErrorV1> {
        self.store.resolve_state(digest)
    }
}

#[cfg(feature = "sqlite")]
impl ErasurePersistencePortV1 for DeletePredecessorBeforeCommit {
    fn load_record(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Option<ErasureCoordinatorRecordV1>, ErasureErrorV1> {
        self.store.load_record(request)
    }

    fn commit_record(&mut self, record: ErasureCoordinatorRecordV1) -> Result<(), ErasureErrorV1> {
        self.commit_calls += 1;
        if self.commit_calls == self.delete_on_call {
            if let Some(previous) = record.state().previous_state() {
                let connection = rusqlite::Connection::open(&self.path)
                    .map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
                if self.replace_predecessor {
                    let replacement = ErasureStateV1::submitted(
                        record.request().reference(),
                        record.state().coordinator(),
                        reference(77),
                    )?
                    .to_canonical_cbor()?;
                    if self.replace_request {
                        connection
                            .execute(
                                "UPDATE erasure_states
                                 SET request_digest = ?1, state_cbor = ?2
                                 WHERE state_digest = ?3",
                                rusqlite::params![
                                    reference(99).digest().as_slice(),
                                    replacement,
                                    previous.digest().as_slice()
                                ],
                            )
                            .map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
                    } else {
                        connection
                            .execute(
                                "UPDATE erasure_states
                                 SET state_cbor = ?1
                                 WHERE state_digest = ?2",
                                rusqlite::params![replacement, previous.digest().as_slice(),],
                            )
                            .map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
                    }
                } else {
                    connection
                        .execute(
                            "DELETE FROM erasure_states WHERE state_digest = ?1",
                            rusqlite::params![previous.digest().as_slice()],
                        )
                        .map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
                }
            }
        }
        self.store.commit_record(record)
    }

    fn commit_records(
        &mut self,
        records: &[ErasureCoordinatorRecordV1],
    ) -> Result<(), ErasureErrorV1> {
        self.store.commit_records(records)
    }
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
    ) -> Result<Option<ErasureCoordinatorRecordV1>, ErasureErrorV1> {
        self.store.borrow().load_record(request)
    }

    fn commit_record(&mut self, record: ErasureCoordinatorRecordV1) -> Result<(), ErasureErrorV1> {
        self.store.borrow_mut().commit_record(record)
    }

    fn commit_records(
        &mut self,
        records: &[ErasureCoordinatorRecordV1],
    ) -> Result<(), ErasureErrorV1> {
        self.store.borrow_mut().commit_records(records)
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

    fn required_targets(
        &self,
        _request: ErasureReferenceV1,
    ) -> Result<Vec<ErasureRequiredTargetV1>, ErasureErrorV1> {
        Ok(self.targets.clone())
    }

    fn admit_freeze(
        &self,
        _request: ErasureReferenceV1,
        requested: &ErasureStateTransitionV1,
        targets: &[ErasureRequiredTargetV1],
    ) -> Result<ErasureFreezeAdmissionV1, ErasureErrorV1> {
        Ok(ErasureFreezeAdmissionV1 {
            freeze_position: requested.freeze_position.unwrap_or(10),
            provenance: requested.provenance,
            target_closure: target_closure_digest(targets),
        })
    }

    fn dispatch_destruction(
        &self,
        _request: ErasureReferenceV1,
        _commands: &[pos_core::ErasureDestructionCommandV1],
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_acknowledgement(
        &self,
        _request: ErasureReferenceV1,
        _acknowledgement: &ErasureAcknowledgementV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_receipt(&self, _input: &ErasureReceiptInputV1) -> Result<(), ErasureErrorV1> {
        Ok(())
    }
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
    let second_ack = acknowledgement(second, 61);
    let first_ack = acknowledgement(first, 60);
    coordinator.acknowledge(reference(1), second_ack)?;
    coordinator.acknowledge(reference(1), first_ack)?;
    let receipt = coordinator.finalize(reference(1), full_receipt_input(first, second))?;
    Ok((shared, receipt))
}

fn assert_generic_event_store_is_frozen<S>(store: S) -> Result<(), Box<dyn std::error::Error>>
where
    S: ErasurePersistencePortV1 + EventStore,
{
    let (shared, _) = run_full_lifecycle(store)?;
    let timeline = shared.borrow_mut().create_timeline("frozen")?;
    let timeline_id = timeline.id();
    let draft = EventDraft::new(
        EntityId::new(),
        Kind::new("test.event"),
        CanonicalBytes::from_static(b"payload"),
    );

    assert!(matches!(
        shared.borrow_mut().append(timeline_id, &[draft]),
        Err(CoreError::Storage(message)) if message.contains("frozen by ErasureCoordinator")
    ));
    assert!(matches!(
        shared
            .borrow()
            .read(timeline_id, pos_core::SeqRange::all()),
        Err(CoreError::Storage(message)) if message.contains("frozen by ErasureCoordinator")
    ));
    assert!(matches!(
        pos_store::export_timeline(&*shared.borrow(), timeline_id),
        Err(CoreError::Storage(message)) if message.contains("frozen by ErasureCoordinator")
    ));

    // Administrative rollback/deletion remains distinct from subject erasure.
    shared.borrow_mut().delete_timeline(timeline_id)?;
    Ok(())
}

fn full_receipt_input(
    first: ErasureRequiredTargetV1,
    second: ErasureRequiredTargetV1,
) -> ErasureReceiptInputV1 {
    ErasureReceiptInputV1 {
        request: reference(99),
        terminal_state: reference(98),
        coordinator: reference(97),
        lifecycle: ErasureLifecycleV1::Complete,
        freeze_position: 0,
        acknowledgements: vec![acknowledgement(first, 60), acknowledgement(second, 61)],
        required_targets: vec![second, first],
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
    }
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
            required_targets: vec![target],
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
            issue_position: 11,
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
    assert_eq!(store.load_record(request)?, None);
    assert_eq!(store.resolve_state(state_digest)?, None);

    store.commit_record(record.clone())?;
    assert_eq!(store.load_record(request)?, Some(record.clone()));
    assert_eq!(
        store.resolve_state(state_digest)?,
        Some(record.state().clone())
    );

    // Exact retries are idempotent and do not alter the loaded record.
    store.commit_record(record.clone())?;
    assert_eq!(store.load_record(request)?, Some(record));
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_erasure_persistence_rejects_a_missing_predecessor_during_commit(
) -> Result<(), ErasureErrorV1> {
    let database =
        tempfile::NamedTempFile::new().map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
    let path = database
        .path()
        .to_str()
        .ok_or(ErasureErrorV1::ReceiptCommitFailed)?
        .to_owned();
    let target = target(10);
    let shared = Rc::new(RefCell::new(DeletePredecessorBeforeCommit {
        store: SqliteStore::open(&path).map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?,
        path,
        commit_calls: 0,
        delete_on_call: 4,
        replace_predecessor: false,
        replace_request: false,
    }));
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(
        CoordinatorHost {
            store: Rc::clone(&shared),
            targets: vec![target],
        },
        reference(30),
    );
    coordinator.submit(request()?, reference(7))?;
    coordinator.authorize(reference(1), reference(8))?;
    assert_eq!(
        coordinator.freeze_inventory(reference(1), transition()),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_erasure_persistence_rejects_a_mismatched_predecessor_during_commit(
) -> Result<(), ErasureErrorV1> {
    let database =
        tempfile::NamedTempFile::new().map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
    let path = database
        .path()
        .to_str()
        .ok_or(ErasureErrorV1::ReceiptCommitFailed)?
        .to_owned();
    let target = target(10);
    let shared = Rc::new(RefCell::new(DeletePredecessorBeforeCommit {
        store: SqliteStore::open(&path).map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?,
        path,
        commit_calls: 0,
        delete_on_call: 4,
        replace_predecessor: true,
        replace_request: true,
    }));
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(
        CoordinatorHost {
            store: Rc::clone(&shared),
            targets: vec![target],
        },
        reference(30),
    );
    coordinator.submit(request()?, reference(7))?;
    coordinator.authorize(reference(1), reference(8))?;
    assert_eq!(
        coordinator.freeze_inventory(reference(1), transition()),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_erasure_persistence_rejects_a_predecessor_state_under_the_wrong_digest(
) -> Result<(), ErasureErrorV1> {
    let database =
        tempfile::NamedTempFile::new().map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
    let path = database
        .path()
        .to_str()
        .ok_or(ErasureErrorV1::ReceiptCommitFailed)?
        .to_owned();
    let target = target(10);
    let shared = Rc::new(RefCell::new(DeletePredecessorBeforeCommit {
        store: SqliteStore::open(&path).map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?,
        path,
        commit_calls: 0,
        delete_on_call: 4,
        replace_predecessor: true,
        replace_request: false,
    }));
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(
        CoordinatorHost {
            store: Rc::clone(&shared),
            targets: vec![target],
        },
        reference(30),
    );
    coordinator.submit(request()?, reference(7))?;
    coordinator.authorize(reference(1), reference(8))?;
    assert_eq!(
        coordinator.freeze_inventory(reference(1), transition()),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn memory_erasure_persistence_exposes_the_public_contract() -> Result<(), ErasureErrorV1> {
    assert_public_contract(&mut MemoryStore::new())
}

#[test]
fn memory_erasure_persistence_commits_canonical_acknowledgement_and_receipt_state(
) -> Result<(), ErasureErrorV1> {
    let (store, receipt) = run_full_lifecycle(MemoryStore::new())?;
    let record = store
        .borrow()
        .load_record(reference(1))?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    assert_eq!(record.state().lifecycle(), ErasureLifecycleV1::Complete);
    assert_eq!(record.receipt(), Some(&receipt));
    assert_eq!(record.acknowledgements().len(), 2);
    assert_eq!(receipt.acknowledgements().len(), 2);
    assert_eq!(receipt.acknowledgements()[0].target, target(10));
    Ok(())
}

#[test]
fn memory_generic_event_store_cannot_bypass_a_frozen_erasure(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_generic_event_store_is_frozen(MemoryStore::new())
}

#[test]
fn memory_erasure_persistence_commits_intermediate_and_partial_receipt_atomically(
) -> Result<(), ErasureErrorV1> {
    let (store, receipt) = run_partial_lifecycle(MemoryStore::new())?;
    let record = store
        .borrow()
        .load_record(reference(1))?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    assert_eq!(
        record.state().lifecycle(),
        ErasureLifecycleV1::PartialFailure
    );
    assert_eq!(record.receipt(), Some(&receipt));
    assert_eq!(record.state().pending_owners(), &[reference(12)]);
    Ok(())
}

#[test]
fn memory_erasure_persistence_rejects_orphans_and_keeps_batches_atomic(
) -> Result<(), ErasureErrorV1> {
    let (completed, receipt) = run_full_lifecycle(MemoryStore::new())?;
    let terminal = completed
        .borrow()
        .load_record(reference(1))?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    drop(completed);
    let mut store = MemoryStore::new();
    assert_eq!(
        store.commit_record(terminal.clone()),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(store.load_record(reference(1))?, None);

    let root = submitted_record()?;
    assert_eq!(
        store.commit_records(&[root, terminal]),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(store.load_record(reference(1))?, None);
    assert_eq!(receipt.lifecycle(), ErasureLifecycleV1::Complete);
    Ok(())
}

#[test]
fn memory_erasure_persistence_rejects_a_conflicting_terminal_retry() -> Result<(), ErasureErrorV1> {
    let (shared, _) = run_full_lifecycle(MemoryStore::new())?;
    let record = shared
        .borrow()
        .load_record(reference(1))?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let mut parts = record_parts(&record);
    let input = parts
        .receipt_input
        .as_mut()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    input.signature = reference(99);
    parts.receipt = Some(ErasureReceiptV1::new(input.clone())?);
    let conflicting = ErasureCoordinatorRecordV1::from_parts(parts, reference(30))?;
    assert_eq!(
        shared.borrow_mut().commit_record(conflicting),
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
        .load_record(reference(1))?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    let mut parts = record_parts(&record);
    let input = parts
        .receipt_input
        .as_mut()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    input.signature = reference(99);
    parts.receipt = Some(ErasureReceiptV1::new(input.clone())?);
    let conflicting = ErasureCoordinatorRecordV1::from_parts(parts, reference(30))?;
    assert_eq!(
        shared.borrow_mut().commit_record(conflicting),
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
        .load_record(reference(1))?
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
fn sqlite_erasure_persistence_commits_canonical_acknowledgement_and_receipt_state(
) -> Result<(), ErasureErrorV1> {
    let store = SqliteStore::open_in_memory().map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
    let (store, receipt) = run_full_lifecycle(store)?;
    let record = store
        .borrow()
        .load_record(reference(1))?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    assert_eq!(record.state().lifecycle(), ErasureLifecycleV1::Complete);
    assert_eq!(record.receipt(), Some(&receipt));
    assert_eq!(receipt.acknowledgements()[0].target, target(10));
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
        .load_record(reference(1))?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    assert_eq!(
        record.state().lifecycle(),
        ErasureLifecycleV1::PartialFailure
    );
    assert_eq!(record.receipt(), Some(&receipt));
    assert_eq!(record.state().pending_owners(), &[reference(12)]);
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
        .load_record(reference(1))?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    drop(completed);
    let mut store =
        SqliteStore::open_in_memory().map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
    assert_eq!(
        store.commit_record(terminal_record.clone()),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(store.load_record(reference(1))?, None);

    let root = submitted_record()?;
    assert_eq!(
        store.commit_records(&[root, terminal_record]),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(store.load_record(reference(1))?, None);
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
    store.commit_record(record.clone())?;
    drop(store);

    let reopened = SqliteStore::open(path)?;
    assert_eq!(reopened.load_record(request)?, Some(record));
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
        .load_record(reference(1))?
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
        coordinator.finalize(reference(1), full_receipt_input(target(10), target(20)))?,
        receipt
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_load_record_validates_the_complete_predecessor_chain(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or("temporary database path is not UTF-8")?;
    let (shared, _) = run_full_lifecycle(SqliteStore::open(path)?)?;
    let previous = shared
        .borrow()
        .load_record(reference(1))?
        .ok_or(ErasureErrorV1::ProvenanceMissing)?
        .state()
        .previous_state()
        .ok_or(ErasureErrorV1::ProvenanceMissing)?;
    drop(shared);

    let connection = rusqlite::Connection::open(path)?;
    connection.execute(
        "DELETE FROM erasure_states WHERE state_digest = ?1",
        rusqlite::params![previous.digest().as_slice()],
    )?;
    drop(connection);

    let reopened = SqliteStore::open(path)?;
    assert_eq!(
        reopened.load_record(reference(1)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_generic_event_store_cannot_bypass_a_frozen_erasure(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_generic_event_store_is_frozen(SqliteStore::open_in_memory()?)
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_erasure_persistence_rejects_a_record_under_the_wrong_request_key(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or("temporary database path is not UTF-8")?;
    let record = submitted_record()?;
    let request = record.request().reference();
    let alternate_request = ErasureRequestV1::new(ErasureRequestInputV1 {
        request: reference(99),
        subject: reference(2),
        scope: ErasureScopeV1::PrivateSubjectData,
        selectors: vec![reference(3)],
        requester: reference(4),
        authorization: reference(5),
        policy: reference(6),
        request_position: 10,
        horizon_position: 20,
        provenance: reference(7),
    })?;
    let alternate_state =
        ErasureStateV1::submitted(alternate_request.reference(), reference(8), reference(77))?;
    let alternate = ErasureCoordinatorRecordV1::from_parts(
        ErasureCoordinatorRecordPartsV1 {
            request: alternate_request,
            state: alternate_state,
            reserved_targets: Vec::new(),
            targets: Vec::new(),
            acknowledgements: Vec::new(),
            receipt: None,
            receipt_input: None,
            authorize_provenance: None,
            freeze_provenance: None,
            freeze_admission: None,
            dispatch_provenance: None,
        },
        reference(8),
    )?;

    let mut store = SqliteStore::open(path)?;
    store.commit_record(record)?;
    drop(store);
    let connection = rusqlite::Connection::open(path)?;
    connection.execute(
        "UPDATE erasure_records SET record_cbor = ?1 WHERE request_digest = ?2",
        rusqlite::params![alternate.to_canonical_cbor()?, request.digest().as_slice()],
    )?;
    drop(connection);

    let store = SqliteStore::open(path)?;
    assert_eq!(
        store.load_record(request),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_erasure_persistence_fails_closed_for_malformed_record_bytes(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or("temporary database path is not UTF-8")?;
    let record = submitted_record()?;
    let request = record.request().reference();
    let mut store = SqliteStore::open(path)?;
    store.commit_record(record)?;
    drop(store);

    let connection = rusqlite::Connection::open(path)?;
    connection.execute(
        "UPDATE erasure_records SET record_cbor = X'01' WHERE request_digest = ?1",
        rusqlite::params![request.digest().as_slice()],
    )?;
    drop(connection);

    let store = SqliteStore::open(path)?;
    assert_eq!(
        store.load_record(request),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_erasure_persistence_fails_closed_for_malformed_state_bytes(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or("temporary database path is not UTF-8")?;
    let record = submitted_record()?;
    let request = record.request().reference();
    let state_digest = record.state().state_digest();
    let mut store = SqliteStore::open(path)?;
    store.commit_record(record)?;
    drop(store);

    let connection = rusqlite::Connection::open(path)?;
    connection.execute(
        "UPDATE erasure_states SET state_cbor = X'01' WHERE state_digest = ?1",
        rusqlite::params![state_digest.digest().as_slice()],
    )?;
    drop(connection);

    let store = SqliteStore::open(path)?;
    assert_eq!(
        store.load_record(request),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        store.resolve_state(state_digest),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_erasure_persistence_rejects_state_bytes_under_the_wrong_digest(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or("temporary database path is not UTF-8")?;
    let record = submitted_record()?;
    let request = record.request().reference();
    let state_digest = record.state().state_digest();
    let replacement = ErasureStateV1::submitted(request, reference(8), reference(77))?;
    let mut store = SqliteStore::open(path)?;
    store.commit_record(record.clone())?;
    drop(store);

    let connection = rusqlite::Connection::open(path)?;
    connection.execute(
        "UPDATE erasure_states SET state_cbor = ?1 WHERE state_digest = ?2",
        rusqlite::params![
            replacement.to_canonical_cbor()?,
            state_digest.digest().as_slice()
        ],
    )?;
    drop(connection);

    let mut store = SqliteStore::open(path)?;
    assert_eq!(
        store.commit_record(record),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_erasure_persistence_fails_closed_for_mismatched_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or("temporary database path is not UTF-8")?;
    let record = submitted_record()?;
    let request = record.request().reference();
    let state_digest = record.state().state_digest();
    let mut store = SqliteStore::open(path)?;
    store.commit_record(record.clone())?;
    drop(store);

    let connection = rusqlite::Connection::open(path)?;
    connection.execute(
        "UPDATE erasure_records SET state_digest = ?1 WHERE request_digest = ?2",
        rusqlite::params![
            reference(99).digest().as_slice(),
            request.digest().as_slice()
        ],
    )?;
    connection.execute(
        "UPDATE erasure_states SET request_digest = ?1 WHERE state_digest = ?2",
        rusqlite::params![
            reference(98).digest().as_slice(),
            state_digest.digest().as_slice()
        ],
    )?;
    drop(connection);

    let mut store = SqliteStore::open(path)?;
    assert_eq!(
        store.load_record(request),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        store.commit_record(record),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        store.resolve_state(state_digest),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_erasure_persistence_rejects_recommit_after_state_row_deletion(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or("temporary database path is not UTF-8")?;
    let record = submitted_record()?;
    let request = record.request().reference();
    let state_digest = record.state().state_digest();
    let mut store = SqliteStore::open(path)?;
    store.commit_record(record.clone())?;
    drop(store);

    let connection = rusqlite::Connection::open(path)?;
    connection.execute(
        "DELETE FROM erasure_states WHERE state_digest = ?1",
        rusqlite::params![state_digest.digest().as_slice()],
    )?;
    drop(connection);

    let mut store = SqliteStore::open(path)?;
    assert_eq!(
        store.commit_record(record),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        store.load_record(request),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}
