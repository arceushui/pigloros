//! Public-interface tests for the `SQLite` refusal to delete an admitted Fork
//! (ADR-099 revision 13, Redmine #657).
//!
//! An admitted Fork is a Timeline with a `fork_admissions` (`FAR1`) row of any
//! origin. `EventStore::delete_timeline` refuses it with
//! `AdmittedForkNotDeletable` before any mutation, so each refusal here is
//! checked against every row of every table. The open-transaction,
//! failed-lookup, and publication cases need private state and live in the
//! adapter's unit tests.
#![cfg(feature = "sqlite")]

#[path = "support/classified_fork_fixture.rs"]
pub mod classified;
#[path = "support/fae1_fixture.rs"]
pub mod fae1;

use std::mem::discriminant;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use classified::{
    batch, database_rows_at, draft, empty_record, hash, node_record, Authority, Fallible, Spec,
    FIRST_TICK, PARENT_CUT, TICK_KIND,
};
use pos_core::{
    CoreError, CounterfactualInvalidationOutcomeV1, CounterfactualStorePortV1,
    CounterfactualTickOutcomeV1, ErasureContainmentGateV1, EventId, EventStore,
    ForkAppendOperationV1, Hash, PipelineDraftBatchV1, RecordedNodeOriginV1, Seq,
    TickDependencyRecordV1, TimelineId,
};
use pos_store::sqlite::SqliteStore;
use pos_store::{
    ClassifiedCounterfactualErrorV1, ClassifiedCounterfactualStorePortV1,
    ClassifiedProvenanceErrorV1, ForkAppendSourcePermitV1, ForkAttributionAuthorityImportErrorV1,
    ForkAttributionAuthorityImportPortV1, ForkEventAuthorityErrorV1,
    ForkEventProvenanceAuthorityPortV1, ForkManifestPublicationPortV1,
};
use tempfile::{tempdir, TempDir};

type Classified = ClassifiedCounterfactualErrorV1;
type Outcome = CounterfactualInvalidationOutcomeV1;
type TickOutcome = CounterfactualTickOutcomeV1;
type TickRecord = TickDependencyRecordV1;
type AuthorityError = ForkEventAuthorityErrorV1;
type ImportError = ForkAttributionAuthorityImportErrorV1;

const CORRUPT_AUTHORITY: Classified =
    Classified::Provenance(ClassifiedProvenanceErrorV1::CorruptAuthority);
/// An undecodable `FAR1` row for the Timeline `?1`.
const FAR1_SQL: &str = "INSERT INTO fork_admissions (child_id, far1_cbor) VALUES (?1, X'00')";
/// Protected geographic evidence for the Timeline `?1`.
const PRESENCE_SQL: &str =
    "INSERT INTO geographic_presence (timeline_id, has_evidence) VALUES (?1, 1)";
/// The child-Fork refusal of the generic delete.
const HAS_FORKS: &str = "cannot delete timeline that still has forks";

fn open(path: &Path) -> Fallible<SqliteStore> {
    let mut store = SqliteStore::open(path.to_str().ok_or("utf-8 path")?)?;
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    Ok(store)
}

/// Run one raw statement that binds the Timeline `id` as `?1`.
fn execute(path: &Path, sql: &str, id: TimelineId) -> Fallible<()> {
    let connection = rusqlite::Connection::open(path)?;
    connection.execute(sql, [id.to_string()])?;
    Ok(())
}

/// Insert `operation` as a raw `FOP1` row at the child's local Seq `local_seq`.
fn insert_operation(
    path: &Path,
    operation: &ForkAppendOperationV1,
    local_seq: i64,
) -> Fallible<()> {
    let input = operation.input();
    let connection = rusqlite::Connection::open(path)?;
    connection.execute(
        "INSERT INTO fork_append_operations
         (operation_id, child_id, local_seq, event_id, fop1_cbor)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            input.operation_id.as_bytes().as_slice(),
            input.child_timeline_id.to_string(),
            local_seq,
            input.event_id.to_string(),
            operation.to_canonical_cbor(),
        ],
    )?;
    Ok(())
}

/// Delete `id`, which must fail with exactly `expected`, and change no row.
fn assert_delete_fails(
    store: &mut SqliteStore,
    path: &Path,
    id: TimelineId,
    expected: &CoreError,
) -> Fallible<()> {
    let before = database_rows_at(path)?;
    let deleted = store.delete_timeline(id);
    let error = deleted.err().ok_or("the delete must fail")?;
    assert_eq!(discriminant(&error), discriminant(expected));
    assert_eq!(error.to_string(), expected.to_string());
    assert_eq!(database_rows_at(path)?, before);
    Ok(())
}

/// Delete the admitted Fork `fork`, which must be refused with no row changed.
fn assert_refused(store: &mut SqliteStore, path: &Path, fork: TimelineId) -> Fallible<()> {
    let refused = CoreError::AdmittedForkNotDeletable(fork);
    assert_delete_fails(store, path, fork, &refused)
}

/// Re-creating `fork` from its own metadata fails as a duplicate id.
fn assert_not_recreatable(store: &mut SqliteStore, fork: TimelineId) -> Fallible<()> {
    let meta = store.get_timeline(fork)?.ok_or("the Fork exists")?.meta;
    let recreated = store.create_timeline_with_meta(meta).err();
    let error = recreated.ok_or("re-creating an admitted Fork must fail")?;
    let duplicate = format!("timeline already exists: {fork}");
    assert!(
        matches!(&error, CoreError::Storage(message) if *message == duplicate),
        "{error:?}"
    );
    Ok(())
}

/// The outcome of a later Tick that ends at logical head `head`.
const fn ticked_to(head: u64) -> TickOutcome {
    TickOutcome::Committed {
        head: Seq::from_u64(head),
    }
}

/// A file-backed store with a live authority and one registered admitted Fork.
struct World {
    _directory: TempDir,
    path: PathBuf,
    store: SqliteStore,
    authority: Authority,
    fork: TimelineId,
}

fn world() -> Fallible<World> {
    let directory = tempdir()?;
    let path = directory.path().join("admitted.db");
    let mut store = open(&path)?;
    let authority = Authority::open(&mut store)?;
    let fork = authority.admit(&mut store, 0xb1)?;
    Ok(World {
        _directory: directory,
        path,
        store,
        authority,
        fork,
    })
}

/// Issue a host-internal append permit for the world's Fork.
fn host_permit(world: &World) -> Fallible<ForkAppendSourcePermitV1> {
    world.authority.host_permit(&world.store, world.fork)
}

/// Append one classified Event under `operation` through the public append
/// and return its logical Seq.
fn append_classified(
    world: &mut World,
    permit: &ForkAppendSourcePermitV1,
    operation: Hash,
    value: u8,
) -> Result<Seq, AuthorityError> {
    let session = &world.authority.session;
    let appended =
        world
            .store
            .append_classified(session, permit, operation, draft(value, TICK_KIND));
    appended.map(|receipt| receipt.event.seq)
}

/// Commit one classified counterfactual invalidation under `base`.
fn commit(
    world: &mut World,
    permit: &ForkAppendSourcePermitV1,
    spec: &Spec,
    record: &TickRecord,
    base: Hash,
) -> Fallible<Result<Outcome, Classified>> {
    let command = spec.command()?;
    let lent = world.authority.lend(permit);
    let store = &mut world.store;
    Ok(store.commit_classified_counterfactual_invalidation(&command, record, &lent, base))
}

/// Append one later classified counterfactual Tick under `base`.
fn tick(
    world: &mut World,
    drafts: &PipelineDraftBatchV1,
    record: &TickRecord,
    base: Hash,
) -> Fallible<Result<TickOutcome, Classified>> {
    let fork = world.fork;
    let expected = world.store.current_counterfactual_basis(fork)?;
    let permit = host_permit(world)?;
    let lent = world.authority.lend(&permit);
    let store = &mut world.store;
    Ok(store.append_classified_counterfactual_tick(fork, &expected, drafts, record, &lent, base))
}

/// Tests 1 and 7: a locally admitted Fork with no classifier and no Event is
/// refused, and its id cannot be re-created.
#[test]
fn an_admitted_fork_without_a_classifier_is_not_deletable() -> Fallible<()> {
    let mut world = world()?;
    let store = &mut world.store;
    let bare = world.authority.admit_unregistered(store, 0xb2)?;
    assert_refused(&mut world.store, &world.path, bare)?;
    let before = database_rows_at(&world.path)?;
    assert_not_recreatable(&mut world.store, bare)?;
    assert_eq!(database_rows_at(&world.path)?, before);
    Ok(())
}

/// Tests 2 and 3: a registered Fork is refused before and after a public
/// classified append, and a fresh append still commits after each refusal.
#[test]
fn a_registered_fork_is_refused_around_public_appends_and_stays_usable() -> Fallible<()> {
    let mut world = world()?;
    let fork = world.fork;
    assert_refused(&mut world.store, &world.path, fork)?;
    assert_not_recreatable(&mut world.store, fork)?;
    let permit = host_permit(&world)?;
    let first = append_classified(&mut world, &permit, hash(0x71), 30);
    assert_eq!(first, Ok(Seq::from_u64(PARENT_CUT + 1)));
    assert_refused(&mut world.store, &world.path, fork)?;
    let second = append_classified(&mut world, &permit, hash(0x72), 31);
    assert_eq!(second, Ok(Seq::from_u64(PARENT_CUT + 2)));
    let from = PARENT_CUT + 1;
    let suffix = world.store.read_fork_event_suffix(fork, from)?;
    assert_eq!(suffix.len(), 2);
    Ok(())
}

/// Tests 2 and 3: a Fork with a classified counterfactual admission and one
/// later Tick is refused, and a further Tick still commits.
#[test]
fn a_fork_with_counterfactual_ticks_is_refused_and_keeps_ticking() -> Fallible<()> {
    let mut world = world()?;
    let fork = world.fork;
    let permit = host_permit(&world)?;
    let record = node_record(FIRST_TICK, "a", 1)?;
    let outcome = commit(&mut world, &permit, &Spec::new(fork), &record, hash(0x61))??;
    assert!(matches!(outcome, Outcome::Committed(_)), "{outcome:?}");
    let later = batch(vec![draft(20, TICK_KIND), draft(21, TICK_KIND)])?;
    let ticked = tick(&mut world, &later, &node_record(18, "b", 2)?, hash(0x62))?;
    assert_eq!(ticked, Ok(ticked_to(PARENT_CUT + 4)));
    assert_refused(&mut world.store, &world.path, fork)?;
    let further = batch(vec![draft(22, TICK_KIND), draft(23, TICK_KIND)])?;
    let ticked = tick(&mut world, &further, &node_record(19, "c", 3)?, hash(0x64))?;
    assert_eq!(ticked, Ok(ticked_to(PARENT_CUT + 6)));
    let from = PARENT_CUT + 1;
    let suffix = world.store.read_fork_event_suffix(fork, from)?;
    assert_eq!(suffix.len(), 6);
    Ok(())
}

/// Tests 4 and 7: a code-2 imported Fork is refused and stays readable; an
/// identical import retry still returns its receipt, while another import
/// naming the same child and a re-creation of the child both fail.
#[test]
fn an_imported_fork_is_refused_and_keeps_its_child_id() -> Fallible<()> {
    let directory = tempdir()?;
    let path = directory.path().join("imported.db");
    let mut store = SqliteStore::open(path.to_str().ok_or("utf-8 path")?)?;
    let source = fae1::World::new(fae1::Shape::Mixed, false)?;
    let built = source.build(&fae1::Spec::default())?;
    // Seeding the destination binds the open erasure gate.
    source.seed_destination(&mut store)?;
    fae1::pin_policy(&mut store, &built.policy)?;
    let receipt = store.import_verified(&fae1::request_for(&source, &built))?;
    let child = source.child_at(0)?.id;
    assert_refused(&mut store, &path, child)?;
    let suffix = store.read_fork_event_suffix(child, fae1::PARENT_CUT + 1)?;
    assert_eq!(suffix.len(), 4);
    let head = fae1::PARENT_CUT + fae1::Shape::Mixed.events();
    let committed = store.read_committed(child, head)?;
    assert_eq!(committed.receipt.final_logical_head, head);
    let retried = store.import_verified(&fae1::request_for(&source, &built));
    assert_eq!(retried, Ok(receipt));
    let other = source.build(&fae1::Spec::distinct(0))?;
    let conflicting = store.import_verified(&fae1::request_for(&source, &other));
    assert_eq!(conflicting, Err(ImportError::Conflict));
    assert_not_recreatable(&mut store, child)
}

/// Test 5: on a gated store the direct-topology guard refuses first.
#[test]
fn a_gated_store_refuses_before_the_admission_check() -> Fallible<()> {
    let World {
        _directory,
        path,
        store,
        fork,
        ..
    } = world()?;
    drop(store);
    let mut gated = SqliteStore::open(path.to_str().ok_or("utf-8 path")?)?;
    gated.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_fail_closed()))?;
    let unavailable = CoreError::ErasureContainmentUnavailable;
    assert_delete_fails(&mut gated, &path, fork, &unavailable)
}

/// Tests 5 and 6: the child-Fork check precedes the admission check, and the
/// generic child itself is still deleted.
#[test]
fn a_child_fork_is_checked_before_the_admission() -> Fallible<()> {
    let mut world = world()?;
    let fork = world.fork;
    let head = Seq::from_u64(PARENT_CUT);
    let child = world.store.fork(fork, head, "generic-child")?.id();
    let has_forks = CoreError::Storage(HAS_FORKS.to_owned());
    assert_delete_fails(&mut world.store, &world.path, fork, &has_forks)?;
    world.store.delete_timeline(child)?;
    assert!(world.store.get_timeline(child)?.is_none());
    assert_refused(&mut world.store, &world.path, fork)
}

/// Test 5: geographic concealment still precedes the admission check.
#[test]
fn a_geographic_admitted_fork_stays_concealed() -> Fallible<()> {
    let mut world = world()?;
    let fork = world.fork;
    execute(&world.path, PRESENCE_SQL, fork)?;
    let concealed = CoreError::TimelineNotFound(fork);
    assert_delete_fails(&mut world.store, &world.path, fork, &concealed)
}

/// Test 5: the admission check tests row existence on an existing Timeline,
/// so a malformed `FAR1` row refuses, while a missing Timeline is not found
/// even when an orphan `FAR1` row names it.
#[test]
fn raw_admission_rows_refuse_only_existing_timelines() -> Fallible<()> {
    let directory = tempdir()?;
    let path = directory.path().join("raw-admission.db");
    let mut store = open(&path)?;
    let malformed = store.create_timeline("malformed-admission")?.id();
    let orphan = TimelineId::new();
    execute(&path, FAR1_SQL, malformed)?;
    execute(&path, FAR1_SQL, orphan)?;
    assert_refused(&mut store, &path, malformed)?;
    let missing = CoreError::TimelineNotFound(orphan);
    assert_delete_fails(&mut store, &path, orphan, &missing)?;
    let unknown = TimelineId::new();
    let not_found = CoreError::TimelineNotFound(unknown);
    assert_delete_fails(&mut store, &path, unknown, &not_found)
}

/// Test 9: a decodable `FOP1` row pre-inserted at the Fork's next local Seq
/// makes the counterfactual commit corrupt authority and the public append a
/// conflict, and neither changes a row.
#[test]
fn a_tampered_next_operation_is_refused_on_both_classified_paths() -> Fallible<()> {
    let mut world = world()?;
    let fork = world.fork;
    let permit = host_permit(&world)?;
    let session = &world.authority.session;
    let first =
        world
            .store
            .append_classified(session, &permit, hash(0x71), draft(30, TICK_KIND))?;
    // A fresh operation and Event ID re-encode new FOP1 bytes that agree
    // with their columns, so only `UNIQUE (child_id, local_seq)` can refuse.
    let mut input = first.operation.input().clone();
    input.operation_id = hash(0x7a);
    input.event_id = EventId::new();
    input.logical_seq = PARENT_CUT + 2;
    // A second connection's commit changes `PRAGMA data_version`, which the
    // open store's erasure gate check would refuse, so write while it is closed.
    let World {
        _directory: directory,
        path,
        store,
        ..
    } = world;
    drop(store);
    insert_operation(&path, &ForkAppendOperationV1::new(input)?, 2)?;
    let mut store = open(&path)?;
    let authority = Authority::reopen(&mut store)?;
    let mut world = World {
        _directory: directory,
        path,
        store,
        authority,
        fork,
    };
    let permit = host_permit(&world)?;
    let before = database_rows_at(&world.path)?;
    let spec = Spec {
        head: PARENT_CUT + 1,
        ..Spec::new(fork)
    };
    let record = empty_record(FIRST_TICK, RecordedNodeOriginV1::Provisional)?;
    let committed = commit(&mut world, &permit, &spec, &record, hash(0x63))?;
    assert_eq!(committed, Err(CORRUPT_AUTHORITY));
    let appended = append_classified(&mut world, &permit, hash(0x72), 31);
    assert_eq!(appended, Err(AuthorityError::Conflict));
    assert_eq!(database_rows_at(&world.path)?, before);
    Ok(())
}
