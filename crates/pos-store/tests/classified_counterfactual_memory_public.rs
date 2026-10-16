//! Public-interface tests for the `MemoryStore` classified counterfactual
//! commit and append (ADR-099 revision 12, Redmine #642).
//!
//! They mirror the `SQLite` suite case for case, except the `SQLite`-only
//! out-of-range record Tick. Each rejection is checked to leave no own Event,
//! validated `EOR1`/`FOP1` pair, generation, or dependency node, read back
//! through the public ports; the receipt, quarantine, and artifacts of a
//! generation install with it. The set-capacity case and the cases that need
//! private state (an injected staging failure, a forged permit, a corrupt
//! authority graph) live in the adapter's unit tests.

#[path = "support/classified_fork_fixture.rs"]
pub mod classified;
#[path = "support/fae1_fixture.rs"]
pub mod fae1;

use std::sync::Arc;

use classified::{
    batch, draft, empty_record, facts, hash, node_record, Authority, Fallible, Spec, FIRST_TICK,
    PARENT_CUT, TICK_KIND,
};
use pos_core::{
    CanonicalBytes, CounterfactualAdapterSealV1, CounterfactualBasisV1,
    CounterfactualDependencyReadPortV1, CounterfactualInvalidationOutcomeV1,
    CounterfactualStoreErrorV1, CounterfactualStorePortV1, CounterfactualTickOutcomeV1,
    DependencyPageRequestV1, DependencyReadScopeV1, EntityId, ErasureContainmentGateV1, EventDraft,
    EventStore, Hash, InvalidationConflictV1, Kind, PipelineDraftBatchV1, RecordedNodeOriginV1, Seq,
    SeqRange, TickDependencyRecordV1, TimelineId, WallTime, MAX_DEPENDENCY_PAGE_ROWS_V1,
    MAX_PIPELINE_DRAFT_BATCH_BYTES,
};
use pos_store::memory::MemoryStore;
use pos_store::{
    ClassifiedCounterfactualErrorV1, ClassifiedCounterfactualStorePortV1,
    ClassifiedProvenanceErrorV1, ClassifiedTickAuthorityV1, ForkAppendSourcePermitV1,
    ForkAttributionAuthorityImportPortV1, ForkEventProvenanceAuthorityPortV1,
};
use ulid::Ulid;

type Classified = ClassifiedCounterfactualErrorV1;
type Provenance = ClassifiedProvenanceErrorV1;
type Outcome = CounterfactualInvalidationOutcomeV1;
type TickOutcome = CounterfactualTickOutcomeV1;
type StoreError = CounterfactualStoreErrorV1;
type Conflict = InvalidationConflictV1;
type TickRecord = TickDependencyRecordV1;

/// The adapter seal, minted here only to build expected receipts.
const SEAL: CounterfactualAdapterSealV1 = CounterfactualAdapterSealV1::for_adapter();
const PROVISIONAL: RecordedNodeOriginV1 = RecordedNodeOriginV1::Provisional;
const COMMITTED: RecordedNodeOriginV1 = RecordedNodeOriginV1::Committed;
/// The operation base of every invalidation, and of every later Tick.
const BASE: Hash = hash(0x61);
const LATER_BASE: Hash = hash(0x62);
/// The documented domain of one counterfactual operation ID.
const OPERATION_DOMAIN: &[u8] = b"pigloros/counterfactual-tick-operation-index/v1";
const INVALID_REQUEST: Classified = Classified::Provenance(Provenance::InvalidRequest);
const UNAUTHENTICATED: Classified = Classified::Provenance(Provenance::Unauthenticated);
const CORRUPT_AUTHORITY: Classified = Classified::Provenance(Provenance::CorruptAuthority);
const BINDING_MISMATCH: Classified = Classified::Store(StoreError::BindingMismatch);
const NOT_FOUND: Classified = Classified::Store(StoreError::ForkNotFound);
/// Event types the draft guard conceals as an absent Fork.
const GUARDED_KINDS: [&str; 3] = ["geo.location", "geo.cell", "consent.granted.v1"];

/// The snapshot of a Fork no classified write touched.
const NOTHING: [usize; 4] = [0; 4];
/// The snapshot after the default invalidation: two Events with their
/// provenance, one generation, and one record of one node.
const COMMITTED_ROWS: [usize; 4] = [2, 2, 1, 1];

/// The rows a classified write on `fork` adds, read through the public ports:
/// own Events, validated `EOR1`/`FOP1` pairs, the generation, and the
/// current generation's dependency nodes.
fn snapshot(store: &MemoryStore, fork: TimelineId) -> Fallible<[usize; 4]> {
    let events = store.read_own(fork, SeqRange::all())?.len();
    let provenance = store.read_fork_event_suffix(fork, 0)?.len();
    let at = store.current_fork_generation(fork)?;
    let scope = DependencyReadScopeV1::ForkGeneration(at);
    let request = DependencyPageRequestV1::try_new(scope, None, MAX_DEPENDENCY_PAGE_ROWS_V1)?;
    let nodes = store.read_dependency_nodes(&request)?.items().len();
    Ok([events, provenance, usize::try_from(at.generation)?, nodes])
}

/// A Memory store with an open erasure gate.
fn open() -> Fallible<MemoryStore> {
    let mut store = MemoryStore::new();
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    Ok(store)
}

/// The documented operation IDs of the first `count` drafts under `base`.
fn operation_ids(base: Hash, count: u32) -> Vec<Hash> {
    (0..count)
        .map(|index| {
            let input = [OPERATION_DOMAIN, base.as_bytes(), &index.to_be_bytes()].concat();
            Hash::from_bytes(*blake3::hash(&input).as_bytes())
        })
        .collect()
}

/// The ordinary batch of one later Tick.
fn later_drafts() -> Fallible<PipelineDraftBatchV1> {
    batch(vec![draft(20, TICK_KIND), draft(21, TICK_KIND)])
}

/// A store with a live authority and one classified Fork.
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

fn commit_at(
    store: &mut MemoryStore,
    authority: &ClassifiedTickAuthorityV1<'_>,
    spec: &Spec,
    record: &TickRecord,
    base: Hash,
) -> Fallible<Result<Outcome, Classified>> {
    let command = spec.command()?;
    Ok(store.commit_classified_counterfactual_invalidation(&command, record, authority, base))
}

fn commit_as(
    store: &mut MemoryStore,
    authority: &ClassifiedTickAuthorityV1<'_>,
    spec: &Spec,
    record: &TickRecord,
) -> Fallible<Result<Outcome, Classified>> {
    commit_at(store, authority, spec, record, BASE)
}

fn append_as(
    store: &mut MemoryStore,
    lent: &ClassifiedTickAuthorityV1<'_>,
    fork: TimelineId,
    expected: &CounterfactualBasisV1,
    drafts: &PipelineDraftBatchV1,
    record: &TickRecord,
) -> Result<TickOutcome, Classified> {
    store.append_classified_counterfactual_tick(fork, expected, drafts, record, lent, LATER_BASE)
}

impl World {
    fn snapshot(&self) -> Fallible<[usize; 4]> {
        snapshot(&self.store, self.fork)
    }

    fn host_permit(&self) -> Fallible<ForkAppendSourcePermitV1> {
        self.authority.host_permit(&self.store, self.fork)
    }

    fn commit_under(
        &mut self,
        permit: &ForkAppendSourcePermitV1,
        spec: &Spec,
        record: &TickRecord,
    ) -> Fallible<Result<Outcome, Classified>> {
        let lent = self.authority.lend(permit);
        commit_as(&mut self.store, &lent, spec, record)
    }

    fn commit(
        &mut self,
        spec: &Spec,
        record: &TickRecord,
    ) -> Fallible<Result<Outcome, Classified>> {
        let permit = self.host_permit()?;
        self.commit_under(&permit, spec, record)
    }

    /// Commit the default invalidation with a one-node record.
    fn committed(&mut self) -> Fallible<()> {
        let outcome = self.commit(&Spec::new(self.fork), &node_record(FIRST_TICK, "a", 1)?)??;
        assert!(
            matches!(outcome, Outcome::Committed(_)),
            "the default invalidation commits: {outcome:?}"
        );
        Ok(())
    }

    fn append_under(
        &mut self,
        permit: &ForkAppendSourcePermitV1,
        drafts: &PipelineDraftBatchV1,
        record: &TickRecord,
    ) -> Fallible<Result<TickOutcome, Classified>> {
        let fork = self.fork;
        let expected = self.store.current_counterfactual_basis(fork)?;
        let lent = self.authority.lend(permit);
        Ok(append_as(
            &mut self.store,
            &lent,
            fork,
            &expected,
            drafts,
            record,
        ))
    }

    fn append(
        &mut self,
        drafts: &PipelineDraftBatchV1,
        record: &TickRecord,
    ) -> Fallible<Result<TickOutcome, Classified>> {
        let permit = self.host_permit()?;
        self.append_under(&permit, drafts, record)
    }

    /// The `FOP1` operation IDs of the Fork's classified Events from logical
    /// Seq `from`, read back through the validating suffix read; none of them
    /// carries an `FIA1`.
    fn operations(&self, from: u64) -> Fallible<Vec<Hash>> {
        let suffix = self.store.read_fork_event_suffix(self.fork, from)?;
        for (_, intervention, _) in &suffix {
            assert!(intervention.is_none(), "a host-internal Event has no FIA1");
        }
        Ok(suffix
            .iter()
            .map(|(_, _, operation)| operation.input().operation_id)
            .collect())
    }
}

#[test]
fn a_classified_commit_and_tick_write_events_provenance_and_records_together() -> Fallible<()> {
    let mut world = world()?;
    let fork = world.fork;
    assert_eq!(world.snapshot()?, NOTHING, "a fresh Fork");
    let command = Spec::new(fork).command()?;
    let record = node_record(FIRST_TICK, "a", 1)?;
    let permit = world.host_permit()?;
    let lent = world.authority.lend(&permit);
    let outcome = commit_as(&mut world.store, &lent, &Spec::new(fork), &record)??;
    // The Fork's origin prefix holds its parent's two Events, so the two
    // drafts end at logical Seq 4: the prior head plus the batch length.
    let first_head = Seq::from_u64(PARENT_CUT + 2);
    let receipt = command.committed_receipt(&SEAL, first_head)?;
    assert_eq!(outcome, Outcome::Committed(Box::new(receipt)), "receipt");
    assert_eq!(world.snapshot()?, COMMITTED_ROWS, "the committed rows");
    assert_eq!(world.store.logical_head(fork)?, first_head, "the head");
    // Each Event is host-internal, and its FOP1 carries the operation ID
    // derived from the base and its index in the batch.
    let first = world.operations(PARENT_CUT + 1)?;
    assert_eq!(first, operation_ids(BASE, 2), "the first operation IDs");

    // A later Tick adds its Events, provenance, and record, and no generation.
    assert_eq!(
        world.append(&later_drafts()?, &node_record(18, "b", 2)?)?,
        Ok(TickOutcome::Committed {
            head: Seq::from_u64(PARENT_CUT + 4)
        }),
        "the later Tick commits"
    );
    assert_eq!(world.snapshot()?, [4, 4, 1, 2], "the later rows");
    let later = world.operations(PARENT_CUT + 3)?;
    assert_eq!(later, operation_ids(LATER_BASE, 2), "later IDs");
    Ok(())
}

#[test]
fn a_replayed_commit_or_tick_fails_the_basis_recheck() -> Fallible<()> {
    let mut world = world()?;
    world.committed()?;
    let fork = world.fork;
    let expected = world.store.current_counterfactual_basis(fork)?;
    let record = node_record(FIRST_TICK, "a", 1)?;
    // The exact replay names the head before its own Events; at the current
    // head it still names the generation it replaced.
    let at_head = Spec {
        head: PARENT_CUT + 2,
        ..Spec::new(fork)
    };
    for (spec, conflict) in [
        (Spec::new(fork), Conflict::LogicalHead),
        (at_head, Conflict::PriorGeneration),
    ] {
        let replayed = world.commit(&spec, &record)?;
        let expected_conflict = Ok(Outcome::InvalidationConflict(conflict));
        assert_eq!(replayed, expected_conflict, "{conflict:?}");
    }
    let appended = world.append(&later_drafts()?, &node_record(18, "b", 2)?)?;
    assert!(appended.is_ok(), "the later Tick commits: {appended:?}");
    let written = world.snapshot()?;
    let permit = world.host_permit()?;
    let lent = world.authority.lend(&permit);
    let drafts = later_drafts()?;
    let record = node_record(19, "c", 3)?;
    let replay = append_as(&mut world.store, &lent, fork, &expected, &drafts, &record);
    let stale = Ok(TickOutcome::Stale(Conflict::LogicalHead));
    assert_eq!(replay, stale, "the replayed Tick is stale");
    assert_eq!(world.snapshot()?, written, "the replay wrote nothing");
    Ok(())
}

#[test]
fn a_session_that_is_not_live_is_unauthenticated_even_for_a_missing_fork() -> Fallible<()> {
    let mut world = world()?;
    let permit = world.host_permit()?;
    let expected = world.store.current_counterfactual_basis(world.fork)?;
    // A new session ends the one that issued the permit.
    let ended = std::mem::replace(&mut world.authority, Authority::reopen(&mut world.store)?);
    let lent = ended.lend(&permit);
    let missing = TimelineId::from_ulid(Ulid::from(0x0123_4567_89ab_cdef_u128));
    let record = empty_record(FIRST_TICK, PROVISIONAL)?;
    let later = empty_record(18, PROVISIONAL)?;
    let drafts = later_drafts()?;
    for fork in [world.fork, missing] {
        // The session is checked before the Fork is resolved, and the open
        // test gate admits an unknown Timeline, so neither is `ForkNotFound`.
        let committed = commit_as(&mut world.store, &lent, &Spec::new(fork), &record)?;
        assert_eq!(committed, Err(UNAUTHENTICATED), "{fork}");
        let appended = append_as(&mut world.store, &lent, fork, &expected, &drafts, &later);
        assert_eq!(appended, Err(UNAUTHENTICATED), "{fork}");
    }
    assert_eq!(world.snapshot()?, NOTHING, "nothing was written");
    Ok(())
}

#[test]
fn an_imported_fork_is_an_invalid_request() -> Fallible<()> {
    let mut store = MemoryStore::new();
    let source = fae1::World::new(fae1::Shape::EmptyClassified, false)?;
    let built = source.build(&fae1::Spec::default())?;
    // Seeding the destination binds the open erasure gate.
    source.seed_destination(&mut store)?;
    fae1::pin_policy(&mut store, &built.policy)?;
    store.import_verified(&fae1::request_for(&source, &built))?;
    let imported = source.child_at(0)?.id;
    store.publish_counterfactual_facts(imported, facts())?;
    // A live session and a valid permit, both for a local classified Fork.
    let authority = Authority::open(&mut store)?;
    let local = authority.admit(&mut store, 0xb1)?;
    let permit = authority.host_permit(&store, local)?;
    let lent = authority.lend(&permit);
    let spec = Spec {
        head: fae1::PARENT_CUT,
        ..Spec::new(imported)
    };
    let record = empty_record(FIRST_TICK, PROVISIONAL)?;
    let committed = commit_as(&mut store, &lent, &spec, &record)?;
    assert_eq!(committed, Err(INVALID_REQUEST), "the imported commit");
    let expected = store.current_counterfactual_basis(imported)?;
    let later = empty_record(18, PROVISIONAL)?;
    let drafts = later_drafts()?;
    let appended = append_as(&mut store, &lent, imported, &expected, &drafts, &later);
    assert_eq!(appended, Err(INVALID_REQUEST), "the imported Tick");
    assert_eq!(snapshot(&store, imported)?, NOTHING, "nothing was written");
    Ok(())
}

#[test]
fn an_unclassified_fork_is_an_invalid_request() -> Fallible<()> {
    let mut world = world()?;
    let parent = world.store.create_timeline("generic-parent")?.id();
    world
        .store
        .append(parent, &[draft(1, "factual"), draft(2, "factual")])?;
    let generic = world
        .store
        .fork(parent, Seq::from_u64(PARENT_CUT), "generic")?
        .id();
    world.store.publish_counterfactual_facts(generic, facts())?;
    let permit = world.host_permit()?;
    let lent = world.authority.lend(&permit);
    let record = empty_record(FIRST_TICK, PROVISIONAL)?;
    let committed = commit_as(&mut world.store, &lent, &Spec::new(generic), &record)?;
    assert_eq!(committed, Err(INVALID_REQUEST), "the generic commit");
    let expected = world.store.current_counterfactual_basis(generic)?;
    let later = empty_record(18, PROVISIONAL)?;
    let drafts = later_drafts()?;
    let store = &mut world.store;
    let appended = append_as(store, &lent, generic, &expected, &drafts, &later);
    assert_eq!(appended, Err(INVALID_REQUEST), "the generic Tick");
    assert_eq!(snapshot(&world.store, generic)?, NOTHING, "no write");
    Ok(())
}

#[test]
fn the_record_is_checked_before_the_basis_and_a_conflict_writes_nothing() -> Fallible<()> {
    let mut world = world()?;
    let fork = world.fork;
    let stale = || Spec {
        head: PARENT_CUT + 1,
        ..Spec::new(fork)
    };
    // A misplaced record wins over a stale basis.
    for spec in [Spec::new(fork), stale()] {
        for record in [
            empty_record(FIRST_TICK, COMMITTED)?,
            empty_record(FIRST_TICK + 1, PROVISIONAL)?,
        ] {
            let committed = world.commit(&spec, &record)?;
            assert_eq!(committed, Err(BINDING_MISMATCH), "head {}", spec.head);
        }
    }
    assert_eq!(
        world.commit(&stale(), &empty_record(FIRST_TICK, PROVISIONAL)?)?,
        Ok(Outcome::InvalidationConflict(Conflict::LogicalHead)),
        "the stale basis conflicts"
    );
    assert_eq!(world.snapshot()?, NOTHING, "nothing was written");
    Ok(())
}

#[test]
fn a_geographic_draft_is_concealed_as_an_absent_fork() -> Fallible<()> {
    let mut world = world()?;
    let fork = world.fork;
    let record = empty_record(FIRST_TICK, PROVISIONAL)?;
    for kind in GUARDED_KINDS {
        let spec = Spec {
            drafts: vec![draft(7, TICK_KIND), draft(0, kind)],
            ..Spec::new(fork)
        };
        assert_eq!(world.commit(&spec, &record)?, Err(NOT_FOUND), "{kind}");
    }
    assert_eq!(world.snapshot()?, NOTHING, "nothing was written");
    world.committed()?;
    for kind in GUARDED_KINDS {
        let drafts = batch(vec![draft(20, TICK_KIND), draft(0, kind)])?;
        let appended = world.append(&drafts, &empty_record(18, PROVISIONAL)?)?;
        assert_eq!(appended, Err(NOT_FOUND), "{kind}");
    }
    assert_eq!(world.snapshot()?, COMMITTED_ROWS, "no later Tick");
    Ok(())
}

#[test]
fn a_wall_time_override_is_an_invalid_request() -> Fallible<()> {
    let mut world = world()?;
    let stamped = draft(8, TICK_KIND).with_wall_time(WallTime::from_micros(10));
    let spec = Spec {
        drafts: vec![draft(7, TICK_KIND), stamped.clone()],
        ..Spec::new(world.fork)
    };
    let record = empty_record(FIRST_TICK, PROVISIONAL)?;
    let committed = world.commit(&spec, &record)?;
    assert_eq!(committed, Err(INVALID_REQUEST), "the stamped commit");
    assert_eq!(world.snapshot()?, NOTHING, "nothing was written");
    world.committed()?;
    let drafts = batch(vec![stamped])?;
    let appended = world.append(&drafts, &empty_record(18, PROVISIONAL)?)?;
    assert_eq!(appended, Err(INVALID_REQUEST), "the stamped Tick");
    assert_eq!(world.snapshot()?, COMMITTED_ROWS, "no later Tick");
    Ok(())
}

#[test]
fn a_permit_for_a_source_that_is_not_host_internal_is_an_invalid_request() -> Fallible<()> {
    let mut world = world()?;
    let fork = world.fork;
    let external = world.authority.external_permit(&world.store, fork)?;
    let record = empty_record(FIRST_TICK, PROVISIONAL)?;
    let committed = world.commit_under(&external, &Spec::new(fork), &record)?;
    assert_eq!(committed, Err(INVALID_REQUEST), "the external commit");
    assert_eq!(world.snapshot()?, NOTHING, "nothing was written");
    world.committed()?;
    let later = empty_record(18, PROVISIONAL)?;
    let appended = world.append_under(&external, &later_drafts()?, &later)?;
    assert_eq!(appended, Err(INVALID_REQUEST), "the external Tick");
    assert_eq!(world.snapshot()?, COMMITTED_ROWS, "no later Tick");
    Ok(())
}

#[test]
fn a_permit_for_another_fork_or_an_ended_session_is_unauthenticated() -> Fallible<()> {
    let mut world = world()?;
    let fork = world.fork;
    let record = empty_record(FIRST_TICK, PROVISIONAL)?;
    // A live permit of another classified Fork of the same session.
    let other = world.authority.admit(&mut world.store, 0xb2)?;
    let foreign = world.authority.host_permit(&world.store, other)?;
    let committed = world.commit_under(&foreign, &Spec::new(fork), &record)?;
    assert_eq!(committed, Err(UNAUTHENTICATED), "the foreign permit");
    // A permit of a session that a new one ended, lent with the live session.
    let earlier = world.host_permit()?;
    world.authority = Authority::reopen(&mut world.store)?;
    let committed = world.commit_under(&earlier, &Spec::new(fork), &record)?;
    assert_eq!(committed, Err(UNAUTHENTICATED), "the ended permit");
    assert_eq!(world.snapshot()?, NOTHING, "nothing was written");
    world.committed()?;
    let later = empty_record(18, PROVISIONAL)?;
    for permit in [&foreign, &earlier] {
        let appended = world.append_under(permit, &later_drafts()?, &later)?;
        assert_eq!(appended, Err(UNAUTHENTICATED), "the refused Tick");
    }
    assert_eq!(world.snapshot()?, COMMITTED_ROWS, "no later Tick");
    Ok(())
}

#[test]
fn an_existing_operation_under_a_derived_id_is_corrupt_authority() -> Fallible<()> {
    let mut world = world()?;
    let fork = world.fork;
    let permit = world.host_permit()?;
    // The host misuses the public append with the ID of draft 1 under `BASE`.
    let derived = operation_ids(BASE, 2);
    let orphan = *derived.get(1).ok_or("two operation IDs")?;
    let session = &world.authority.session;
    let appended = world
        .store
        .append_classified(session, &permit, orphan, draft(5, TICK_KIND))?;
    assert_eq!(appended.operation.input().operation_id, orphan, "orphan");
    let before = world.snapshot()?;
    assert_eq!(before, [1, 1, 0, 0], "one public classified append");
    // The append advanced the head, so the commit names the new basis, which
    // matches; the derived ID is then refused before anything is staged.
    let spec = Spec {
        head: PARENT_CUT + 1,
        ..Spec::new(fork)
    };
    let record = empty_record(FIRST_TICK, PROVISIONAL)?;
    let committed = world.commit_under(&permit, &spec, &record)?;
    assert_eq!(committed, Err(CORRUPT_AUTHORITY), "the derived ID is taken");
    assert_eq!(world.snapshot()?, before, "nothing was written");
    Ok(())
}

#[test]
fn a_failing_later_draft_rolls_every_row_back() -> Fallible<()> {
    let mut world = world()?;
    // `PipelineDraftBatchV1` takes a 257-byte Event type, which no FEQ1 can
    // hold, so draft 1 fails after draft 0 was staged.
    let long = "t".repeat(257);
    let spec = Spec {
        drafts: vec![draft(7, TICK_KIND), draft(8, &long)],
        ..Spec::new(world.fork)
    };
    let record = node_record(FIRST_TICK, "a", 1)?;
    let committed = world.commit(&spec, &record)?;
    assert_eq!(committed, Err(INVALID_REQUEST), "the long commit");
    assert_eq!(world.snapshot()?, NOTHING, "nothing was written");
    world.committed()?;
    let drafts = batch(vec![draft(20, TICK_KIND), draft(21, &long)])?;
    let appended = world.append(&drafts, &node_record(18, "b", 2)?)?;
    assert_eq!(appended, Err(INVALID_REQUEST), "the long Tick");
    assert_eq!(world.snapshot()?, COMMITTED_ROWS, "no later Tick");
    Ok(())
}

#[test]
fn a_later_tick_checks_the_basis_before_the_record_rules() -> Fallible<()> {
    let mut world = world()?;
    world.committed()?;
    let fork = world.fork;
    let mut stale = world.store.current_counterfactual_basis(fork)?;
    stale.fork_logical_head = Seq::from_u64(PARENT_CUT);
    let permit = world.host_permit()?;
    let lent = world.authority.lend(&permit);
    let drafts = later_drafts()?;
    let early = empty_record(FIRST_TICK, PROVISIONAL)?;
    let appended = append_as(&mut world.store, &lent, fork, &stale, &drafts, &early);
    let conflict = Ok(TickOutcome::Stale(Conflict::LogicalHead));
    assert_eq!(appended, conflict, "the stale basis wins");
    // On the current basis: the Tick rule, the provisional rule, and a node
    // repeating the artifact digest of the first record's node.
    for (record, error) in [
        (early, StoreError::BindingMismatch),
        (empty_record(18, COMMITTED)?, StoreError::BindingMismatch),
        (node_record(18, "z", 1)?, StoreError::DuplicateIdentity),
    ] {
        let appended = world.append(&drafts, &record)?;
        assert_eq!(appended, Err(Classified::Store(error)), "{error:?}");
    }
    assert_eq!(world.snapshot()?, COMMITTED_ROWS, "no later Tick");
    Ok(())
}

/// Pins existing ADR-099 behaviour, not a counterfactual-path rule:
/// `delete_timeline` keeps a classified Fork's FAR1, classifier, EOR1, and
/// FOP1 rows, so a re-created Fork ID resumes at its generation floor and a
/// base that re-derives its old operation IDs is refused.
#[test]
fn a_recreated_fork_resumes_at_its_floor_and_refuses_its_old_operations() -> Fallible<()> {
    let mut world = world()?;
    world.committed()?;
    let fork = world.fork;
    let meta = world
        .store
        .get_timeline(fork)?
        .ok_or("the Fork exists")?
        .meta;
    world.store.delete_timeline(fork)?;
    world.store.create_timeline_with_meta(meta)?;
    let published = world.store.publish_counterfactual_facts(fork, facts())?;
    assert_eq!(published.generation, 1, "the floor seeds the generation");
    let before = world.store.current_counterfactual_basis(fork)?;
    let next = Spec {
        prior: 1,
        ..Spec::new(fork)
    };
    let record = node_record(FIRST_TICK, "a", 1)?;
    // The orphan-operation guard: a base that re-derives the first
    // generation's operation IDs finds their retained FOP1 rows.
    let committed = world.commit(&next, &record)?;
    assert_eq!(committed, Err(CORRUPT_AUTHORITY), "old IDs retained");
    let after = world.store.current_counterfactual_basis(fork)?;
    assert_eq!(after, before, "nothing was written");
    let own = world.store.read_own(fork, SeqRange::all())?;
    assert!(own.is_empty(), "the re-created Fork has no Event: {own:?}");
    Ok(())
}

#[test]
fn a_maximal_single_draft_batch_commits() -> Fallible<()> {
    let mut world = world()?;
    // The draft's fixed fields take 52 bytes beside its 256-byte Event type
    // and its payload, so this one draft fills the 16 MiB batch bound.
    let kind = "m".repeat(256);
    let payload = vec![0x5a; MAX_PIPELINE_DRAFT_BATCH_BYTES - 308];
    let maximal = EventDraft::new(
        EntityId::from_ulid(Ulid::from(9_u128)),
        Kind::new(&kind),
        CanonicalBytes::from_vec(payload),
    );
    let drafts = batch(vec![maximal.clone()])?;
    let bytes = drafts.content_bytes();
    assert_eq!(bytes, MAX_PIPELINE_DRAFT_BATCH_BYTES, "maximal");
    let spec = Spec {
        drafts: vec![maximal],
        ..Spec::new(world.fork)
    };
    let outcome = world.commit(&spec, &empty_record(FIRST_TICK, PROVISIONAL)?)??;
    assert!(
        matches!(outcome, Outcome::Committed(_)),
        "the maximal batch commits: {outcome:?}"
    );
    assert_eq!(world.snapshot()?, [1, 1, 1, 0], "one Event with provenance");
    let operations = world.operations(PARENT_CUT + 1)?;
    assert_eq!(operations, operation_ids(BASE, 1), "its FOP1 operation ID");
    Ok(())
}
