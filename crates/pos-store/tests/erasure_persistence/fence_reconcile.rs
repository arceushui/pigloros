//! ADR-097 B6 readiness reconciliation, driven through the public store seam.
//!
//! Every test commits real coordinator mutations to a file-backed `SQLite`
//! store, damages the `erasure_fence_rows` table through a second connection
//! the way a crash or an older store would, and reconciles against the
//! inventory that core verified from that same store. Refusals are asserted to
//! leave the table byte-for-byte unchanged.

use std::cell::RefCell;
use std::rc::Rc;

use pos_core::{
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementV1, ErasureCoordinatorStateMachineV1,
    ErasureErrorV1, ErasureLifecycleV1, ErasureReceiptInputV1, ErasureReceiptInventoriesV1,
    ErasureReceiptV1, ErasureReferenceV1, ErasureReplayClaimV1, ErasureRequestV1,
    ErasureRetryAdmissionV1, ErasureVerifiedInventoryQueryV1, EventStore, TimelineId,
    ERASURE_MAX_INVENTORY_REQUESTS,
};
use pos_store::sqlite::{erasure_fence_reconcile::ErasureFenceReconcileErrorV1, SqliteStore};

use super::{
    bind_test_gate, commit_fork_admission, fixture_retry_admission, frozen_coordinator, inventory,
    obligation, overlapping_request, prepared_fork, reference, request as persistence_request,
    target as required_target, Host, RetryAdmissionFixture,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Shared = Rc<RefCell<SqliteStore>>;
type Machine = ErasureCoordinatorStateMachineV1<Host<SqliteStore>>;
/// One stored row: `(timeline_id, erasure_request_id, lifecycle_code)`.
type FenceRow = (String, Vec<u8>, i64);

const CONTRADICTORY: Result<(), ErasureFenceReconcileErrorV1> =
    Err(ErasureFenceReconcileErrorV1::Contradictory);
const UNREADABLE: Result<(), ErasureFenceReconcileErrorV1> =
    Err(ErasureFenceReconcileErrorV1::Unreadable);

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

fn exec(path: &str, sql: &str) -> rusqlite::Result<()> {
    rusqlite::Connection::open(path)?.execute_batch(sql)
}

/// Run `sql` with the table's `CHECK` constraints off, as only damage can.
fn exec_unchecked(path: &str, sql: &str) -> rusqlite::Result<()> {
    exec(
        path,
        &format!("PRAGMA ignore_check_constraints = ON; {sql}"),
    )
}

fn seed_row(
    path: &str,
    timeline: TimelineId,
    request: ErasureReferenceV1,
    code: i64,
) -> rusqlite::Result<()> {
    rusqlite::Connection::open(path)?
        .execute(
            "INSERT INTO erasure_fence_rows (timeline_id, erasure_request_id, lifecycle_code)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![timeline.to_string(), request.digest().as_slice(), code],
        )
        .map(|_| ())
}

fn set_codes(path: &str, code: i64) -> rusqlite::Result<()> {
    exec(
        path,
        &format!("UPDATE erasure_fence_rows SET lifecycle_code = {code};"),
    )
}

fn delete_rows(path: &str) -> rusqlite::Result<()> {
    exec(path, "DELETE FROM erasure_fence_rows;")
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

fn machine(shared: &Shared) -> Machine {
    ErasureCoordinatorStateMachineV1::new(
        Host {
            store: Rc::clone(shared),
            targets: vec![required_target()],
            topology_override: None,
            verify_exact_retry: false,
            fail_read_object: false,
            manifest_sequence: None,
        },
        reference(30),
    )
}

/// Verify the store's inventory, then reconcile the fence rows against it.
fn reconcile(shared: &Shared) -> Result<Result<(), ErasureFenceReconcileErrorV1>, ErasureErrorV1> {
    machine(shared)
        .verified_inventory(ERASURE_MAX_INVENTORY_REQUESTS)
        .map(|verified| shared.borrow_mut().reconcile_erasure_fence_rows(&verified))
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

/// A file-backed store holding one Timeline and one request.
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
        let parent = store.create_timeline("fence-reconcile-parent")?.id();
        Ok(Self {
            _database: database,
            path,
            shared: Rc::new(RefCell::new(store)),
            parent,
            request: persistence_request()?,
        })
    }

    /// A fixture whose request is frozen at `AccessFrozen`.
    fn frozen() -> Result<Self, Box<dyn std::error::Error>> {
        let fixture = Self::new()?;
        frozen_coordinator(
            Rc::clone(&fixture.shared),
            &fixture.request,
            required_target(),
        )?;
        Ok(fixture)
    }

    const fn id(&self) -> ErasureReferenceV1 {
        self.request.reference()
    }

    fn rows(&self) -> rusqlite::Result<Vec<FenceRow>> {
        fence_rows(&self.path)
    }

    fn frozen_row(&self, code: i64) -> Vec<FenceRow> {
        vec![row(self.parent, self.id(), code)]
    }

    fn dispatch(&self, ordinal: u64, source: Option<ErasureReferenceV1>) -> TestResult {
        machine(&self.shared)
            .dispatch_attempt(self.id(), &attempt(self.id(), ordinal, source)?)
            .map(|_| ())
            .map_err(Into::into)
    }

    fn acknowledge(
        &self,
        evidence: ErasureReferenceV1,
        outcome: ErasureAcknowledgementOutcomeV1,
    ) -> TestResult {
        let ack = acknowledgement(self.id(), evidence, outcome)?;
        machine(&self.shared)
            .acknowledge(self.id(), ack)
            .map(|_| ())
            .map_err(Into::into)
    }

    fn finalize(&self, issue_position: u64) -> Result<ErasureReceiptV1, ErasureErrorV1> {
        machine(&self.shared).finalize(self.id(), receipt_input(issue_position))
    }

    /// Drive the request to `AwaitingAcknowledgements` (code 4).
    fn awaiting(self) -> Result<Self, Box<dyn std::error::Error>> {
        self.dispatch(0, None)?;
        assert_eq!(self.rows()?, self.frozen_row(4));
        Ok(self)
    }

    /// Drive the request to `Complete` (code 5).
    fn complete() -> Result<Self, Box<dyn std::error::Error>> {
        let fixture = Self::frozen()?.awaiting()?;
        fixture.acknowledge(reference(32), ErasureAcknowledgementOutcomeV1::Acknowledged)?;
        fixture.finalize(21)?;
        assert_eq!(fixture.rows()?, fixture.frozen_row(5));
        Ok(fixture)
    }

    /// Drive the request to `PartialFailure` (code 6) and return its receipt.
    fn partial() -> Result<(Self, ErasureReceiptV1), Box<dyn std::error::Error>> {
        let fixture = Self::frozen()?.awaiting()?;
        fixture.acknowledge(reference(34), ErasureAcknowledgementOutcomeV1::Negative)?;
        let receipt = fixture.finalize(20)?;
        assert_eq!(fixture.rows()?, fixture.frozen_row(6));
        Ok((fixture, receipt))
    }

    /// Damage the row to `stale`, reconcile, and expect the row at `want`.
    fn assert_repaired(&self, stale: i64, want: i64) -> TestResult {
        set_codes(&self.path, stale)?;
        assert_eq!(reconcile(&self.shared)?, Ok(()));
        assert_eq!(self.rows()?, self.frozen_row(want));
        Ok(())
    }

    /// Reconcile, expect `refusal`, and expect the rows exactly as they were.
    fn assert_refused(&self, refusal: Result<(), ErasureFenceReconcileErrorV1>) -> TestResult {
        let before = self.rows()?;
        assert_eq!(reconcile(&self.shared)?, refusal);
        assert_eq!(self.rows()?, before);
        Ok(())
    }
}

#[test]
fn missing_rows_of_a_frozen_request_are_derived_and_a_second_run_changes_nothing() -> TestResult {
    let fixture = Fixture::frozen()?;
    assert_eq!(fixture.rows()?, fixture.frozen_row(2));
    assert_eq!(reconcile(&fixture.shared)?, Ok(()));
    assert_eq!(fixture.rows()?, fixture.frozen_row(2));

    delete_rows(&fixture.path)?;
    assert_eq!(reconcile(&fixture.shared)?, Ok(()));
    assert_eq!(fixture.rows()?, fixture.frozen_row(2));
    assert_eq!(reconcile(&fixture.shared)?, Ok(()));
    assert_eq!(fixture.rows()?, fixture.frozen_row(2));
    Ok(())
}

#[test]
fn a_store_with_no_requests_reconciles_to_no_rows() -> TestResult {
    let fixture = Fixture::new()?;
    assert_eq!(reconcile(&fixture.shared)?, Ok(()));
    assert!(fixture.rows()?.is_empty());
    Ok(())
}

#[test]
fn a_stale_row_advances_to_an_awaiting_lifecycle() -> TestResult {
    Fixture::frozen()?.awaiting()?.assert_repaired(2, 4)
}

#[test]
fn a_stale_row_advances_to_complete_along_the_forward_edges() -> TestResult {
    let fixture = Fixture::complete()?;
    fixture.assert_repaired(2, 5)?;
    fixture.assert_repaired(4, 5)
}

#[test]
fn a_stale_row_advances_to_partial_failure_and_on_to_complete() -> TestResult {
    let (fixture, partial) = Fixture::partial()?;
    fixture.assert_repaired(2, 6)?;
    fixture.assert_repaired(4, 6)?;

    fixture.dispatch(1, Some(partial.receipt_digest()))?;
    fixture.acknowledge(reference(35), ErasureAcknowledgementOutcomeV1::Acknowledged)?;
    fixture.finalize(30)?;
    assert_eq!(fixture.rows()?, fixture.frozen_row(5));
    fixture.assert_repaired(6, 5)
}

#[test]
fn a_row_ahead_of_or_beside_its_verified_lifecycle_is_refused() -> TestResult {
    let awaiting = Fixture::frozen()?.awaiting()?;
    set_codes(&awaiting.path, 5)?;
    awaiting.assert_refused(CONTRADICTORY)?;
    set_codes(&awaiting.path, 6)?;
    awaiting.assert_refused(CONTRADICTORY)?;

    let (partial, _) = Fixture::partial()?;
    set_codes(&partial.path, 5)?;
    partial.assert_refused(CONTRADICTORY)?;

    let frozen = Fixture::frozen()?;
    set_codes(&frozen.path, 6)?;
    frozen.assert_refused(CONTRADICTORY)?;
    set_codes(&frozen.path, 3)?;
    frozen.assert_refused(CONTRADICTORY)
}

#[test]
fn a_row_the_chains_do_not_require_is_refused_and_never_deleted() -> TestResult {
    let extra_timeline = Fixture::frozen()?;
    seed_row(
        &extra_timeline.path,
        TimelineId::new(),
        extra_timeline.id(),
        2,
    )?;
    extra_timeline.assert_refused(CONTRADICTORY)?;

    let unknown_request = Fixture::frozen()?;
    seed_row(
        &unknown_request.path,
        unknown_request.parent,
        reference(77),
        2,
    )?;
    unknown_request.assert_refused(CONTRADICTORY)?;

    let pre_freeze = Fixture::new()?;
    machine(&pre_freeze.shared)
        .submit(pre_freeze.request.clone(), pre_freeze.request.provenance())?;
    assert!(pre_freeze.rows()?.is_empty());
    assert_eq!(reconcile(&pre_freeze.shared)?, Ok(()));
    seed_row(&pre_freeze.path, pre_freeze.parent, pre_freeze.id(), 2)?;
    pre_freeze.assert_refused(CONTRADICTORY)
}

#[test]
fn a_rejected_requests_rows_are_deleted_and_no_other_requests_rows_are() -> TestResult {
    let fixture = Fixture::new()?;
    let second = overlapping_request()?;
    machine(&fixture.shared).submit(fixture.request.clone(), fixture.request.provenance())?;
    machine(&fixture.shared).reject(fixture.id(), reference(31))?;
    frozen_coordinator(Rc::clone(&fixture.shared), &second, required_target())?;
    let kept = vec![row(fixture.parent, second.reference(), 2)];
    assert_eq!(fixture.rows()?, kept);

    seed_row(&fixture.path, fixture.parent, fixture.id(), 2)?;
    assert_eq!(fixture.rows()?.len(), 2);
    assert_eq!(reconcile(&fixture.shared)?, Ok(()));
    assert_eq!(fixture.rows()?, kept);

    delete_rows(&fixture.path)?;
    assert_eq!(reconcile(&fixture.shared)?, Ok(()));
    assert_eq!(fixture.rows()?, kept);
    Ok(())
}

#[test]
fn every_frozen_request_gets_its_own_rows() -> TestResult {
    let fixture = Fixture::frozen()?;
    let second = overlapping_request()?;
    frozen_coordinator(Rc::clone(&fixture.shared), &second, required_target())?;
    let both = sorted(vec![
        row(fixture.parent, fixture.id(), 2),
        row(fixture.parent, second.reference(), 2),
    ]);
    assert_eq!(fixture.rows()?, both);

    delete_rows(&fixture.path)?;
    assert_eq!(reconcile(&fixture.shared)?, Ok(()));
    assert_eq!(fixture.rows()?, both);
    Ok(())
}

#[test]
fn rows_that_do_not_parse_are_refused() -> TestResult {
    let lower_case = Fixture::frozen()?;
    exec_unchecked(
        &lower_case.path,
        "UPDATE erasure_fence_rows SET timeline_id = lower(timeline_id);",
    )?;
    lower_case.assert_refused(CONTRADICTORY)?;

    let short_request = Fixture::frozen()?;
    exec_unchecked(
        &short_request.path,
        "UPDATE erasure_fence_rows SET erasure_request_id = x'0102';",
    )?;
    short_request.assert_refused(CONTRADICTORY)?;

    let unknown_code = Fixture::frozen()?;
    exec_unchecked(
        &unknown_code.path,
        "UPDATE erasure_fence_rows SET lifecycle_code = 9;",
    )?;
    unknown_code.assert_refused(CONTRADICTORY)?;

    let text_code = Fixture::frozen()?;
    exec_unchecked(
        &text_code.path,
        "UPDATE erasure_fence_rows SET lifecycle_code = 'two';",
    )?;
    text_code.assert_refused(UNREADABLE)
}

#[test]
fn an_inventory_that_no_longer_describes_the_store_is_refused() -> TestResult {
    let fixture = Fixture::frozen()?;
    delete_rows(&fixture.path)?;
    let verified = machine(&fixture.shared).verified_inventory(ERASURE_MAX_INVENTORY_REQUESTS)?;
    fixture.dispatch(0, None)?;
    assert_eq!(
        fixture
            .shared
            .borrow_mut()
            .reconcile_erasure_fence_rows(&verified),
        Err(ErasureFenceReconcileErrorV1::StaleInventory)
    );
    assert!(fixture.rows()?.is_empty());

    assert_eq!(reconcile(&fixture.shared)?, Ok(()));
    assert_eq!(fixture.rows()?, fixture.frozen_row(4));
    Ok(())
}

#[test]
fn an_unreadable_table_fails_closed() -> TestResult {
    let fixture = Fixture::frozen()?;
    exec(&fixture.path, "DROP TABLE erasure_fence_rows;")?;
    assert_eq!(reconcile(&fixture.shared)?, UNREADABLE);
    Ok(())
}

#[test]
fn fork_children_get_their_rows_at_the_current_lifecycle() -> TestResult {
    let (_database, path) = temp_database()?;
    let (shared, gate, request, child, prepared) = prepared_fork(SqliteStore::open(&path)?)?;
    commit_fork_admission(&shared, &gate, &prepared)?;
    let full = fence_rows(&path)?;
    assert_eq!(full.len(), 2);
    assert!(full.contains(&row(child, request, 2)));

    delete_rows(&path)?;
    assert_eq!(reconcile(&shared)?, Ok(()));
    assert_eq!(fence_rows(&path)?, full);

    exec(
        &path,
        &format!("DELETE FROM erasure_fence_rows WHERE timeline_id = '{child}';"),
    )?;
    assert_eq!(reconcile(&shared)?, Ok(()));
    assert_eq!(fence_rows(&path)?, full);
    Ok(())
}

#[test]
fn a_failed_insert_commits_none_of_the_rows() -> TestResult {
    let (_database, path) = temp_database()?;
    let (shared, gate, _, _, prepared) = prepared_fork(SqliteStore::open(&path)?)?;
    commit_fork_admission(&shared, &gate, &prepared)?;
    let full = fence_rows(&path)?;
    delete_rows(&path)?;
    exec(
        &path,
        "CREATE TRIGGER fence_fault BEFORE INSERT ON erasure_fence_rows
         WHEN (SELECT count(*) FROM erasure_fence_rows) >= 1
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
    )?;
    assert_eq!(reconcile(&shared)?, UNREADABLE);
    assert!(fence_rows(&path)?.is_empty());

    exec(&path, "DROP TRIGGER fence_fault;")?;
    assert_eq!(reconcile(&shared)?, Ok(()));
    assert_eq!(fence_rows(&path)?, full);
    Ok(())
}

#[test]
fn a_failed_update_changes_none_of_the_rows() -> TestResult {
    let fixture = Fixture::frozen()?;
    let second = overlapping_request()?;
    let mut other = frozen_coordinator(Rc::clone(&fixture.shared), &second, required_target())?;
    fixture.dispatch(0, None)?;
    other.dispatch_attempt(second.reference(), &attempt(second.reference(), 0, None)?)?;
    let dispatched = fixture.rows()?;
    assert!(dispatched.iter().all(|stored| stored.2 == 4));
    set_codes(&fixture.path, 2)?;
    let stale = fixture.rows()?;
    exec(
        &fixture.path,
        "CREATE TRIGGER fence_fault BEFORE UPDATE ON erasure_fence_rows
         WHEN (SELECT count(*) FROM erasure_fence_rows WHERE lifecycle_code = 4) >= 1
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
    )?;
    assert_eq!(reconcile(&fixture.shared)?, UNREADABLE);
    assert_eq!(fixture.rows()?, stale);

    exec(&fixture.path, "DROP TRIGGER fence_fault;")?;
    assert_eq!(reconcile(&fixture.shared)?, Ok(()));
    assert_eq!(fixture.rows()?, dispatched);
    Ok(())
}

#[test]
fn a_failed_delete_keeps_the_rejected_requests_rows() -> TestResult {
    let fixture = Fixture::new()?;
    machine(&fixture.shared).submit(fixture.request.clone(), fixture.request.provenance())?;
    machine(&fixture.shared).reject(fixture.id(), reference(31))?;
    seed_row(&fixture.path, fixture.parent, fixture.id(), 2)?;
    let seeded = fixture.rows()?;
    exec(
        &fixture.path,
        "CREATE TRIGGER fence_fault BEFORE DELETE ON erasure_fence_rows
         BEGIN SELECT RAISE(ABORT, 'fault'); END;",
    )?;
    assert_eq!(reconcile(&fixture.shared)?, UNREADABLE);
    assert_eq!(fixture.rows()?, seeded);

    exec(&fixture.path, "DROP TRIGGER fence_fault;")?;
    assert_eq!(reconcile(&fixture.shared)?, Ok(()));
    assert!(fixture.rows()?.is_empty());
    Ok(())
}

/// `reaches` recurses along `permits` edges without a depth bound, which is
/// finite only while the edges, minus self edges, form a DAG. A future edge
/// that closes a cycle must fail here rather than overflow the stack.
#[test]
fn the_lifecycle_edges_without_self_edges_have_no_cycle() {
    const ALL: [ErasureLifecycleV1; 8] = [
        ErasureLifecycleV1::Submitted,
        ErasureLifecycleV1::Authorized,
        ErasureLifecycleV1::AccessFrozen,
        ErasureLifecycleV1::DestructionDispatched,
        ErasureLifecycleV1::AwaitingAcknowledgements,
        ErasureLifecycleV1::Complete,
        ErasureLifecycleV1::PartialFailure,
        ErasureLifecycleV1::Rejected,
    ];
    let successors = |from: ErasureLifecycleV1| {
        ALL.into_iter()
            .filter(move |next| *next != from && from.permits(*next))
    };
    // After n rounds each set holds every state reachable in 1..=n+1 steps;
    // a path longer than the state count must repeat a state.
    let closure = ALL.into_iter().fold(
        ALL.map(|from| successors(from).collect::<Vec<_>>()),
        |reached, _| {
            ALL.map(|from| {
                let index = from as usize;
                let mut next = reached[index].clone();
                next.extend(
                    reached[index]
                        .iter()
                        .flat_map(|step| reached[*step as usize].clone()),
                );
                next.sort_by_key(|state| *state as u8);
                next.dedup();
                next
            })
        },
    );
    assert!(ALL
        .into_iter()
        .all(|from| !closure[from as usize].contains(&from)));
}
