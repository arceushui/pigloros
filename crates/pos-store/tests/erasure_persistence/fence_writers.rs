//! ADR-097 B6 fence-row writers, driven through the public erasure CAS port.
//!
//! Every test commits real coordinator mutations to a file-backed `SQLite`
//! store and reads the `erasure_fence_rows` table through a second connection,
//! so the rows are exactly what a separate owner process would see. Each
//! transition is asserted with exact-retry verification on, and each write
//! boundary is faulted with a trigger to prove a failed CAS changes no row.

use std::cell::RefCell;
use std::rc::Rc;

use pos_core::erasure::target_closure_digest;
use pos_core::{
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementV1, ErasureCasOutcomeV1,
    ErasureCoordinatorStateMachineV1, ErasureErrorV1, ErasureLifecycleV1, ErasureReceiptInputV1,
    ErasureReceiptInventoriesV1, ErasureReceiptV1, ErasureReferenceV1, ErasureReplayClaimV1,
    ErasureRequestV1, ErasureRetryAdmissionV1, ErasureScopeCommitmentInputV1,
    ErasureScopeCommitmentV1, ErasureScopeExtensionInputV1, ErasureScopeExtensionV1,
    ErasureStateV1, EventStore, TimelineId,
};
use pos_store::sqlite::SqliteStore;

use super::{
    bind_test_gate, commit_fork_admission, commit_fork_admission_direct, fixture_retry_admission,
    frozen_coordinator, inventory, obligation, overlapping_request, prepared_fork, reference,
    request as persistence_request, target as required_target, transition, Host,
    RetryAdmissionFixture,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Shared = Rc<RefCell<SqliteStore>>;
/// One stored row: `(timeline_id, erasure_request_id, lifecycle_code)`.
type FenceRow = (String, Vec<u8>, i64);

fn row(timeline: TimelineId, request: ErasureReferenceV1, code: i64) -> FenceRow {
    (timeline.to_string(), request.digest().to_vec(), code)
}

fn sorted(mut rows: Vec<FenceRow>) -> Vec<FenceRow> {
    rows.sort();
    rows
}

fn fence_rows(path: &str) -> rusqlite::Result<Vec<FenceRow>> {
    let connection = rusqlite::Connection::open(path)?;
    let mut statement = connection.prepare(
        "SELECT timeline_id, erasure_request_id, lifecycle_code
         FROM erasure_fence_rows ORDER BY timeline_id, erasure_request_id",
    )?;
    let rows = statement.query_map([], |stored| {
        Ok((stored.get(0)?, stored.get(1)?, stored.get(2)?))
    })?;
    rows.collect()
}

fn seed_row(path: &str, timeline: TimelineId, request: ErasureReferenceV1) -> rusqlite::Result<()> {
    rusqlite::Connection::open(path)?
        .execute(
            "INSERT INTO erasure_fence_rows (timeline_id, erasure_request_id, lifecycle_code)
             VALUES (?1, ?2, 2)",
            rusqlite::params![timeline.to_string(), request.digest().as_slice()],
        )
        .map(|_| ())
}

fn set_fault(path: &str, trigger: &str) -> rusqlite::Result<()> {
    rusqlite::Connection::open(path)?.execute_batch(&format!(
        "CREATE TRIGGER fence_fault BEFORE {trigger} BEGIN SELECT RAISE(ABORT, 'fault'); END;"
    ))
}

fn clear_fault(path: &str) -> rusqlite::Result<()> {
    rusqlite::Connection::open(path)?.execute_batch("DROP TRIGGER fence_fault;")
}

fn temp_database() -> Result<(tempfile::NamedTempFile, String), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or(ErasureErrorV1::InvalidEncoding)?
        .to_owned();
    Ok((database, path))
}

fn coordinator(shared: &Shared) -> ErasureCoordinatorStateMachineV1<Host<SqliteStore>> {
    ErasureCoordinatorStateMachineV1::new(
        Host {
            store: Rc::clone(shared),
            targets: vec![required_target()],
            topology_override: None,
            verify_exact_retry: true,
            fail_read_object: false,
            manifest_sequence: None,
        },
        reference(30),
    )
}

fn attempt(
    request: ErasureReferenceV1,
    ordinal: u64,
    source_receipt: Option<ErasureReferenceV1>,
) -> Result<ErasureRetryAdmissionV1, ErasureErrorV1> {
    let obligation = obligation(request, required_target())?;
    fixture_retry_admission(RetryAdmissionFixture {
        request,
        attempt_ordinal: ordinal,
        source_receipt,
        obligations: std::slice::from_ref(&obligation),
        policy: reference(6),
        trust: reference(8),
        admitted_position: 11 + ordinal,
        deadline_position: 20 + ordinal,
        authorization_provenance: reference(12),
    })
}

fn acknowledgement(
    request: ErasureReferenceV1,
    evidence: ErasureReferenceV1,
    outcome: ErasureAcknowledgementOutcomeV1,
) -> Result<ErasureAcknowledgementV1, ErasureErrorV1> {
    let target = required_target();
    Ok(ErasureAcknowledgementV1 {
        obligation: obligation(request, target)?.reference(),
        target,
        owner: target.replica_id,
        evidence,
        outcome,
    })
}

fn receipt_input(issue_position: u64) -> ErasureReceiptInputV1 {
    let target = required_target();
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
        issue_position,
        signature: reference(33),
        receipt_digest: reference(0),
    }
}

/// A file-backed store holding one Timeline and one not-yet-submitted request.
struct Fixture {
    _database: tempfile::NamedTempFile,
    path: String,
    shared: Shared,
    parent: TimelineId,
    request: ErasureRequestV1,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let (database, path) = temp_database()?;
        let mut store = SqliteStore::open(&path)?;
        bind_test_gate(&mut store)?;
        let parent = store.create_timeline("fence-parent")?.id();
        Ok(Self {
            _database: database,
            path,
            shared: Rc::new(RefCell::new(store)),
            parent,
            request: persistence_request()?,
        })
    }

    const fn id(&self) -> ErasureReferenceV1 {
        self.request.reference()
    }

    fn rows(&self) -> rusqlite::Result<Vec<FenceRow>> {
        fence_rows(&self.path)
    }

    fn assert_parent_row(&self, code: i64) -> TestResult {
        assert_eq!(self.rows()?, vec![row(self.parent, self.id(), code)]);
        Ok(())
    }

    fn submit(&self) -> Result<ErasureStateV1, ErasureErrorV1> {
        coordinator(&self.shared).submit(self.request.clone(), self.request.provenance())
    }

    fn authorize(&self) -> Result<ErasureStateV1, ErasureErrorV1> {
        coordinator(&self.shared).authorize(self.id(), reference(31))
    }

    fn reject(&self) -> Result<ErasureStateV1, ErasureErrorV1> {
        coordinator(&self.shared).reject(self.id(), reference(31))
    }

    fn freeze(&self) -> Result<ErasureStateV1, ErasureErrorV1> {
        coordinator(&self.shared).freeze_inventory(self.id(), &transition())
    }

    fn dispatch_first(&self) -> Result<ErasureStateV1, ErasureErrorV1> {
        attempt(self.id(), 0, None)
            .and_then(|first| coordinator(&self.shared).dispatch_attempt(self.id(), &first))
    }

    fn acknowledge(
        &self,
        evidence: ErasureReferenceV1,
        outcome: ErasureAcknowledgementOutcomeV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        acknowledgement(self.id(), evidence, outcome)
            .and_then(|ack| coordinator(&self.shared).acknowledge(self.id(), ack))
    }

    fn finalize(&self, issue_position: u64) -> Result<ErasureReceiptV1, ErasureErrorV1> {
        coordinator(&self.shared).finalize(self.id(), receipt_input(issue_position))
    }

    fn extend(
        &self,
        child: TimelineId,
        fork: ErasureReferenceV1,
        predecessor: Option<ErasureReferenceV1>,
    ) -> Result<ErasureScopeExtensionV1, ErasureErrorV1> {
        let scope = ErasureScopeCommitmentV1::new(ErasureScopeCommitmentInputV1 {
            request: self.id(),
            scope_members: vec![reference(9)],
            scope_timeline_ids: vec![self.parent],
            target_closure: target_closure_digest(&[required_target()]),
            lineage_rule: Some(reference(100)),
        })?;
        ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
            request: self.id(),
            scope_commitment: scope.reference(),
            fork,
            child_timeline: child,
            lineage_rule: reference(100),
            predecessor_extension: predecessor,
            admission_provenance: reference(102),
        })
    }

    fn append(&self, extension: ErasureScopeExtensionV1) -> Result<ErasureStateV1, ErasureErrorV1> {
        coordinator(&self.shared).append_scope_extension(self.id(), extension)
    }
}

/// Fault `trigger`, prove `step` fails closed with the rows untouched, then
/// heal the fault and prove the same step commits `after`.
fn assert_rolled_back(
    fixture: &Fixture,
    trigger: &str,
    step: impl Fn(&Fixture) -> Result<ErasureStateV1, ErasureErrorV1>,
    before: &[FenceRow],
    after: &[FenceRow],
) -> TestResult {
    set_fault(&fixture.path, trigger)?;
    assert_eq!(step(fixture), Err(ErasureErrorV1::ReceiptCommitFailed));
    assert_eq!(fixture.rows()?, before);
    clear_fault(&fixture.path)?;
    step(fixture)?;
    assert_eq!(fixture.rows()?, after);
    Ok(())
}

#[test]
fn rows_start_at_access_frozen_and_follow_the_lifecycle_to_complete() -> TestResult {
    let fixture = Fixture::new()?;
    assert_eq!(fixture.submit()?.lifecycle(), ErasureLifecycleV1::Submitted);
    assert!(fixture.rows()?.is_empty());
    assert_eq!(
        fixture.authorize()?.lifecycle(),
        ErasureLifecycleV1::Authorized
    );
    assert!(fixture.rows()?.is_empty());

    assert_eq!(
        fixture.freeze()?.lifecycle(),
        ErasureLifecycleV1::AccessFrozen
    );
    fixture.assert_parent_row(2)?;
    assert_eq!(
        fixture.dispatch_first()?.lifecycle(),
        ErasureLifecycleV1::AwaitingAcknowledgements
    );
    fixture.assert_parent_row(4)?;
    fixture.acknowledge(reference(32), ErasureAcknowledgementOutcomeV1::Acknowledged)?;
    fixture.assert_parent_row(4)?;
    assert_eq!(
        fixture.finalize(21)?.lifecycle(),
        ErasureLifecycleV1::Complete
    );
    fixture.assert_parent_row(5)
}

#[test]
fn a_partial_failure_retry_keeps_the_row_until_complete() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.submit()?;
    fixture.authorize()?;
    fixture.freeze()?;
    fixture.dispatch_first()?;
    fixture.acknowledge(reference(34), ErasureAcknowledgementOutcomeV1::Negative)?;
    let partial = fixture.finalize(20)?;
    assert_eq!(partial.lifecycle(), ErasureLifecycleV1::PartialFailure);
    fixture.assert_parent_row(6)?;

    let retry = attempt(fixture.id(), 1, Some(partial.receipt_digest()))?;
    assert_eq!(
        coordinator(&fixture.shared)
            .dispatch_attempt(fixture.id(), &retry)?
            .lifecycle(),
        ErasureLifecycleV1::PartialFailure
    );
    fixture.assert_parent_row(6)?;
    fixture.acknowledge(reference(35), ErasureAcknowledgementOutcomeV1::Acknowledged)?;
    assert_eq!(
        fixture.finalize(30)?.lifecycle(),
        ErasureLifecycleV1::Complete
    );
    fixture.assert_parent_row(5)
}

#[test]
fn rejection_before_freeze_writes_no_row() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.submit()?;
    assert_eq!(fixture.reject()?.lifecycle(), ErasureLifecycleV1::Rejected);
    assert!(fixture.rows()?.is_empty());
    Ok(())
}

#[test]
fn rejection_deletes_only_its_own_requests_rows() -> TestResult {
    let fixture = Fixture::new()?;
    let other = reference(77);
    fixture.submit()?;
    seed_row(&fixture.path, fixture.parent, fixture.id())?;
    seed_row(&fixture.path, fixture.parent, other)?;
    assert_eq!(fixture.reject()?.lifecycle(), ErasureLifecycleV1::Rejected);
    assert_eq!(fixture.rows()?, vec![row(fixture.parent, other, 2)]);
    Ok(())
}

#[test]
fn a_standalone_extension_adds_its_child_at_the_current_lifecycle() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.submit()?;
    fixture.authorize()?;
    fixture.freeze()?;
    let first = TimelineId::new();
    let first_extension = fixture.extend(first, reference(110), None)?;
    fixture.append(first_extension)?;
    let both = |code| {
        sorted(vec![
            row(fixture.parent, fixture.id(), code),
            row(first, fixture.id(), code),
        ])
    };
    assert_eq!(fixture.rows()?, both(2));

    fixture.dispatch_first()?;
    assert_eq!(fixture.rows()?, both(4));
    fixture.acknowledge(reference(32), ErasureAcknowledgementOutcomeV1::Acknowledged)?;
    fixture.finalize(21)?;
    assert_eq!(fixture.rows()?, both(5));

    let second = TimelineId::new();
    let second_extension =
        fixture.extend(second, reference(111), Some(first_extension.reference()))?;
    fixture.append(second_extension)?;
    assert_eq!(
        fixture.rows()?,
        sorted(vec![
            row(fixture.parent, fixture.id(), 5),
            row(first, fixture.id(), 5),
            row(second, fixture.id(), 5),
        ])
    );
    Ok(())
}

#[test]
fn a_request_never_changes_another_requests_rows() -> TestResult {
    let fixture = Fixture::new()?;
    let second = overlapping_request()?;
    let mut first_coordinator = frozen_coordinator(
        Rc::clone(&fixture.shared),
        &fixture.request,
        required_target(),
    )?;
    let _second_coordinator =
        frozen_coordinator(Rc::clone(&fixture.shared), &second, required_target())?;
    let rows = |first: i64, other: i64| {
        sorted(vec![
            row(fixture.parent, fixture.id(), first),
            row(fixture.parent, second.reference(), other),
        ])
    };
    assert_eq!(fixture.rows()?, rows(2, 2));
    first_coordinator.dispatch_attempt(fixture.id(), &attempt(fixture.id(), 0, None)?)?;
    assert_eq!(fixture.rows()?, rows(4, 2));
    Ok(())
}

#[test]
fn a_failed_freeze_commits_no_rows_whichever_write_fails() -> TestResult {
    for trigger in ["INSERT ON erasure_fence_rows", "INSERT ON erasure_effects"] {
        let fixture = Fixture::new()?;
        fixture.submit()?;
        fixture.authorize()?;
        let frozen = vec![row(fixture.parent, fixture.id(), 2)];
        assert_rolled_back(&fixture, trigger, Fixture::freeze, &[], &frozen)?;
    }
    Ok(())
}

#[test]
fn a_failed_transition_leaves_the_rows_at_their_previous_lifecycle() -> TestResult {
    for trigger in ["UPDATE ON erasure_fence_rows", "INSERT ON erasure_effects"] {
        let fixture = Fixture::new()?;
        fixture.submit()?;
        fixture.authorize()?;
        fixture.freeze()?;
        let (frozen, dispatched) = (
            vec![row(fixture.parent, fixture.id(), 2)],
            vec![row(fixture.parent, fixture.id(), 4)],
        );
        assert_rolled_back(
            &fixture,
            trigger,
            Fixture::dispatch_first,
            &frozen,
            &dispatched,
        )?;
    }
    Ok(())
}

#[test]
fn a_failed_extension_adds_no_child_row() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.submit()?;
    fixture.authorize()?;
    fixture.freeze()?;
    let child = TimelineId::new();
    let extension = fixture.extend(child, reference(110), None)?;
    let frozen = vec![row(fixture.parent, fixture.id(), 2)];
    let extended = sorted(vec![
        row(fixture.parent, fixture.id(), 2),
        row(child, fixture.id(), 2),
    ]);
    assert_rolled_back(
        &fixture,
        "INSERT ON erasure_fence_rows",
        |subject| subject.append(extension),
        &frozen,
        &extended,
    )
}

#[test]
fn a_failed_rejection_keeps_its_rows() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.submit()?;
    seed_row(&fixture.path, fixture.parent, fixture.id())?;
    let seeded = vec![row(fixture.parent, fixture.id(), 2)];
    assert_rolled_back(
        &fixture,
        "DELETE ON erasure_fence_rows",
        Fixture::reject,
        &seeded,
        &[],
    )
}

#[test]
fn a_fork_admission_inserts_its_child_row_and_an_exact_retry_changes_nothing() -> TestResult {
    let (_database, path) = temp_database()?;
    let (store, gate, request, child, prepared) = prepared_fork(SqliteStore::open(&path)?)?;
    let frozen = fence_rows(&path)?;
    assert_eq!(frozen.len(), 1);
    assert_eq!(
        (frozen[0].1.as_slice(), frozen[0].2),
        (&request.digest()[..], 2)
    );

    assert_eq!(
        commit_fork_admission(&store, &gate, &prepared)?,
        ErasureCasOutcomeV1::Applied
    );
    let extended = sorted(vec![frozen[0].clone(), row(child, request, 2)]);
    assert_eq!(fence_rows(&path)?, extended);
    assert_eq!(
        commit_fork_admission(&store, &gate, &prepared)?,
        ErasureCasOutcomeV1::ExactRetry
    );
    assert_eq!(fence_rows(&path)?, extended);
    Ok(())
}

#[test]
fn a_failed_fork_admission_leaves_no_child_row() -> TestResult {
    let (_database, path) = temp_database()?;
    let (store, _, _, child, prepared) = prepared_fork(SqliteStore::open(&path)?)?;
    let frozen = fence_rows(&path)?;
    drop(store);
    rusqlite::Connection::open(&path)?.execute_batch(&format!(
        "CREATE TRIGGER reject_fence_child BEFORE INSERT ON timelines
         WHEN NEW.id = '{child}' BEGIN SELECT RAISE(ABORT, 'fault'); END;"
    ))?;

    let mut reopened = SqliteStore::open(&path)?;
    let gate = bind_test_gate(&mut reopened)?;
    assert_eq!(
        commit_fork_admission_direct(&mut reopened, &gate, &prepared),
        Err(ErasureErrorV1::ReceiptCommitFailed)
    );
    assert_eq!(fence_rows(&path)?, frozen);
    Ok(())
}
