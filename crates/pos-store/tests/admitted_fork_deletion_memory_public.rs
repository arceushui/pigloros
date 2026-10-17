//! Public-interface tests for the `MemoryStore` refusal to delete an admitted
//! Fork (ADR-099 revision 13, Redmine #658).
//!
//! They mirror the `SQLite` suite case for case, with equal outcomes. An
//! admitted Fork is a Timeline with a local or an imported `FAR1`.
//! `EventStore::delete_timeline` refuses it with `AdmittedForkNotDeletable`
//! before any mutation, so each refusal here is checked against what the
//! public ports read of every Timeline. The orphan-`FAR1`, geographic,
//! occupied-`Seq`, and publication cases need private state and live in the
//! adapter's unit tests.

#[path = "support/classified_fork_fixture.rs"]
pub mod classified;
#[path = "support/fae1_fixture.rs"]
pub mod fae1;

use std::mem::discriminant;
use std::sync::Arc;

use classified::{
    batch, draft, hash, node_record, Authority, Fallible, Spec, FIRST_TICK, PARENT_CUT, TICK_KIND,
};
use pos_core::{
    CoreError, CounterfactualInvalidationOutcomeV1, CounterfactualStorePortV1,
    CounterfactualTickOutcomeV1, ErasureContainmentGateV1, EventStore, Hash, PipelineDraftBatchV1,
    Seq, SeqRange, TickDependencyRecordV1, TimelineId,
};
use pos_store::memory::MemoryStore;
use pos_store::{
    ClassifiedCounterfactualErrorV1, ClassifiedCounterfactualStorePortV1, ForkAppendSourcePermitV1,
    ForkAttributionAuthorityImportErrorV1, ForkAttributionAuthorityImportPortV1,
    ForkEventAuthorityErrorV1, ForkEventProvenanceAuthorityPortV1, ForkManifestPublicationPortV1,
};

type Classified = ClassifiedCounterfactualErrorV1;
type Outcome = CounterfactualInvalidationOutcomeV1;
type TickOutcome = CounterfactualTickOutcomeV1;
type TickRecord = TickDependencyRecordV1;
type AuthorityError = ForkEventAuthorityErrorV1;
type ImportError = ForkAttributionAuthorityImportErrorV1;

/// The child-Fork refusal of the generic delete.
const HAS_FORKS: &str = "cannot delete timeline that still has forks";

/// A Memory store with an open erasure gate.
fn open() -> Fallible<MemoryStore> {
    let mut store = MemoryStore::new();
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    Ok(store)
}

/// What the public ports read of every Timeline, in a stable order: the
/// Timeline, its own Events, its validated provenance suffix, and its
/// counterfactual basis and generation, each as its result.
fn observed(store: &MemoryStore) -> Fallible<Vec<String>> {
    let mut lines = Vec::new();
    for timeline in store.list_timelines()? {
        let id = timeline.id();
        lines.push(format!(
            "{timeline:?} {:?} {:?} {:?} {:?}",
            store.read_own(id, SeqRange::all()),
            store.read_fork_event_suffix(id, 0),
            store.current_counterfactual_basis(id),
            store.current_fork_generation(id),
        ));
    }
    lines.sort();
    Ok(lines)
}

/// Delete `id`, which must fail with exactly `expected`, and change nothing.
fn assert_delete_fails(
    store: &mut MemoryStore,
    id: TimelineId,
    expected: &CoreError,
) -> Fallible<()> {
    let before = observed(store)?;
    let deleted = store.delete_timeline(id);
    let error = deleted.err().ok_or("the delete must fail")?;
    assert_eq!(discriminant(&error), discriminant(expected));
    assert_eq!(error.to_string(), expected.to_string());
    assert_eq!(observed(store)?, before);
    Ok(())
}

/// Delete the admitted Fork `fork`, which must be refused with nothing changed.
fn assert_refused(store: &mut MemoryStore, fork: TimelineId) -> Fallible<()> {
    let refused = CoreError::AdmittedForkNotDeletable(fork);
    assert_delete_fails(store, fork, &refused)
}

/// Re-creating `fork` from its own metadata fails as a duplicate id and
/// changes nothing.
fn assert_not_recreatable(store: &mut MemoryStore, fork: TimelineId) -> Fallible<()> {
    let before = observed(store)?;
    let meta = store.get_timeline(fork)?.ok_or("the Fork exists")?.meta;
    let recreated = store.create_timeline_with_meta(meta).err();
    let error = recreated.ok_or("re-creating an admitted Fork must fail")?;
    let duplicate = format!("timeline already exists: {fork}");
    assert!(
        matches!(&error, CoreError::Storage(message) if *message == duplicate),
        "{error:?}"
    );
    assert_eq!(observed(store)?, before);
    Ok(())
}

/// The outcome of a later Tick that ends at logical head `head`.
const fn ticked_to(head: u64) -> TickOutcome {
    TickOutcome::Committed {
        head: Seq::from_u64(head),
    }
}

/// A store with a live authority and one registered admitted Fork.
struct World {
    store: MemoryStore,
    authority: Authority,
    fork: TimelineId,
}

fn world() -> Fallible<World> {
    let mut store = open()?;
    let authority = Authority::open(&mut store)?;
    let fork = authority.admit(&mut store, 0xb1)?;
    Ok(World {
        store,
        authority,
        fork,
    })
}

/// Issue a host-internal append permit for the world's Fork.
fn permit(world: &World) -> Fallible<ForkAppendSourcePermitV1> {
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
    let appended = world
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
    let permit = permit(world)?;
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
    assert_refused(&mut world.store, bare)?;
    assert_not_recreatable(&mut world.store, bare)
}

/// Tests 2 and 3: a registered Fork is refused before and after a public
/// classified append, and a fresh append still commits after each refusal.
#[test]
fn a_registered_fork_is_refused_around_public_appends_and_stays_usable() -> Fallible<()> {
    let mut world = world()?;
    let fork = world.fork;
    assert_refused(&mut world.store, fork)?;
    assert_not_recreatable(&mut world.store, fork)?;
    let permit = permit(&world)?;
    let first = append_classified(&mut world, &permit, hash(0x71), 30);
    assert_eq!(first, Ok(Seq::from_u64(PARENT_CUT + 1)));
    assert_refused(&mut world.store, fork)?;
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
    let permit = permit(&world)?;
    let record = node_record(FIRST_TICK, "a", 1)?;
    let outcome = commit(&mut world, &permit, &Spec::new(fork), &record, hash(0x61))??;
    assert!(matches!(outcome, Outcome::Committed(_)), "{outcome:?}");
    let later = batch(vec![draft(20, TICK_KIND), draft(21, TICK_KIND)])?;
    let ticked = tick(&mut world, &later, &node_record(18, "b", 2)?, hash(0x62))?;
    assert_eq!(ticked, Ok(ticked_to(PARENT_CUT + 4)));
    assert_refused(&mut world.store, fork)?;
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
    let mut store = MemoryStore::new();
    let source = fae1::World::new(fae1::Shape::Mixed, false)?;
    let built = source.build(&fae1::Spec::default())?;
    // Seeding the destination binds the open erasure gate.
    source.seed_destination(&mut store)?;
    fae1::pin_policy(&mut store, &built.policy)?;
    let receipt = store.import_verified(&fae1::request_for(&source, &built))?;
    let child = source.child_at(0)?.id;
    assert_refused(&mut store, child)?;
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
    let mut store = MemoryStore::new();
    let authority = Authority::open(&mut store)?;
    let fork = authority.admit_unregistered(&mut store, 0xb1)?;
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_fail_closed()))?;
    let unavailable = CoreError::ErasureContainmentUnavailable;
    let deleted = store.delete_timeline(fork).err();
    let error = deleted.ok_or("the gated delete must fail")?;
    assert_eq!(discriminant(&error), discriminant(&unavailable));
    assert_eq!(error.to_string(), unavailable.to_string());
    Ok(())
}

/// Tests 5 and 6: the child-Fork check precedes the admission check, and the
/// generic child itself is still deleted.
#[test]
fn a_child_fork_is_checked_before_the_admission() -> Fallible<()> {
    let mut world = world()?;
    let fork = world.fork;
    let cut = Seq::from_u64(PARENT_CUT);
    let child = world.store.fork(fork, cut, "generic-child")?.id();
    let has_forks = CoreError::Storage(HAS_FORKS.to_owned());
    assert_delete_fails(&mut world.store, fork, &has_forks)?;
    world.store.delete_timeline(child)?;
    assert!(world.store.get_timeline(child)?.is_none());
    assert_refused(&mut world.store, fork)
}

/// Test 5: an unknown id is not found.
#[test]
fn an_unknown_timeline_is_not_found() -> Fallible<()> {
    let mut world = world()?;
    let unknown = TimelineId::new();
    let not_found = CoreError::TimelineNotFound(unknown);
    assert_delete_fails(&mut world.store, unknown, &not_found)
}
