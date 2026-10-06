//! Public-interface tests for the `MemoryStore` ADR-064 counterfactual
//! transaction adapter.

use std::sync::Arc;

use pos_core::counterfactual_store::test_fixtures::{
    frontier_frame, hash_field, id_field, invalidation_frame, invalidation_middle, uint,
};
use pos_core::{
    CanonicalBytes, CounterfactualAdapterSealV1, CounterfactualBasisV1, CounterfactualFactsV1,
    CounterfactualGenerationReceiptV1, CounterfactualInvalidationCommandV1,
    CounterfactualInvalidationInputV1, CounterfactualInvalidationOutcomeV1,
    CounterfactualStoreErrorV1, CounterfactualStorePortV1, CounterfactualTickOutcomeV1, EntityId,
    ErasureContainmentGateV1, EventDraft, ForkGenerationV1, Hash, InvalidationConflictV1, Kind,
    PipelineDraftBatchV1, RecomputationFrontierBytesV1, Seq, SeqRange, SuffixInvalidationBytesV1,
    TimelineId, TimelineMeta,
};
use pos_store::{memory::MemoryStore, EventStore};

type StoreError = CounterfactualStoreErrorV1;

/// The adapter seal, minted here only to build expected receipts.
const SEAL: CounterfactualAdapterSealV1 = CounterfactualAdapterSealV1::for_adapter();

/// One stale-basis case: how the expectation is altered and the conflict.
type StaleCase<T> = (fn(&mut T), InvalidationConflictV1);

/// Event types the generic append guard conceals as an absent Fork.
const GUARDED_KINDS: [&str; 3] = ["geo.location", "geo.cell", "consent.granted.v1"];

/// Tick number of every test command's first recomputation Tick.
const FIRST_TICK: u64 = 17;

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
    })
}

const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

fn draft(value: u8) -> EventDraft {
    typed_draft("counterfactual.tick", value)
}

fn typed_draft(kind: &str, value: u8) -> EventDraft {
    EventDraft::new(
        EntityId::new(),
        Kind::new(kind),
        CanonicalBytes::from_vec(vec![value]),
    )
}

/// One later Tick of ordinary drafts, optionally ending with a `guarded` one.
fn tick_drafts(count: u8, guarded: Option<&str>) -> PipelineDraftBatchV1 {
    ok(PipelineDraftBatchV1::try_new(
        (0..count)
            .map(draft)
            .chain(guarded.map(|kind| typed_draft(kind, 0)))
            .collect(),
    ))
}

const fn facts() -> CounterfactualFactsV1 {
    CounterfactualFactsV1 {
        plan_digest: hash(5),
        dependency_graph_digest: hash(3),
        trust_epoch: 6,
        revocation_epoch: 7,
        erasure_epoch: 8,
    }
}

/// One invalidation command, defaulting to the published facts at generation 0.
struct Spec {
    fork: TimelineId,
    record_id: u8,
    head: u64,
    prior: u64,
    plan: Hash,
    graph: Hash,
    trust_epoch: u64,
    revocation_epoch: u64,
    erasure_epoch: u64,
    invalid_artifacts: Vec<Hash>,
    evictions: Vec<Hash>,
    drafts: u8,
    guarded: Option<&'static str>,
}

impl Spec {
    fn new(fork: TimelineId) -> Self {
        Self {
            fork,
            record_id: 1,
            head: 1,
            prior: 0,
            plan: hash(5),
            graph: hash(3),
            trust_epoch: 6,
            revocation_epoch: 7,
            erasure_epoch: 8,
            invalid_artifacts: vec![hash(10), hash(11)],
            evictions: vec![hash(12)],
            drafts: 2,
            guarded: None,
        }
    }

    fn command(&self) -> CounterfactualInvalidationCommandV1 {
        let frontier = ok(RecomputationFrontierBytesV1::try_from_canonical(
            frontier_frame(
                &[
                    id_field([self.record_id; 16]),
                    hash_field(self.plan),
                    hash_field(hash(2)),
                    hash_field(self.graph),
                    vec![0x01],
                ]
                .concat(),
                0,
            ),
        ));
        let invalidation = ok(SuffixInvalidationBytesV1::try_from_canonical(
            invalidation_frame(
                &[
                    id_field([self.record_id; 16]),
                    hash_field(self.plan),
                    id_field(self.fork.inner().to_bytes()),
                    uint(self.prior),
                    uint(self.prior + 1),
                    hash_field(frontier.digest()),
                    invalidation_middle(),
                    // Commit coordinate: the Fork, its expected head, the first Tick.
                    vec![0x83],
                    id_field(self.fork.inner().to_bytes()),
                    uint(self.head),
                    uint(FIRST_TICK),
                ]
                .concat(),
                0,
            ),
        ));
        ok(CounterfactualInvalidationCommandV1::try_new(
            CounterfactualInvalidationInputV1 {
                fork: self.fork,
                fork_logical_head: Seq::from_u64(self.head),
                trust_epoch: self.trust_epoch,
                revocation_epoch: self.revocation_epoch,
                erasure_epoch: self.erasure_epoch,
                frontier,
                invalidation,
                invalid_artifacts: self.invalid_artifacts.clone(),
                evictions: self.evictions.clone(),
                first_tick: FIRST_TICK,
                first_tick_drafts: tick_drafts(self.drafts, self.guarded),
            },
        ))
    }
}

struct Fixture {
    store: MemoryStore,
    gate: Arc<ErasureContainmentGateV1>,
    root: TimelineId,
    fork: TimelineId,
}

/// A root Timeline with two Events and a Fork of it at logical Seq 1.
fn fixture() -> Fixture {
    let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    let mut store = MemoryStore::new();
    ok(store.bind_erasure_gate(Arc::clone(&gate)));
    let root = ok(store.create_timeline("counterfactual-root")).id();
    ok(store.append(root, &[draft(100), draft(101)]));
    let fork = ok(store.fork(root, Seq::from_u64(1), "counterfactual-fork")).id();
    Fixture {
        store,
        gate,
        root,
        fork,
    }
}

/// A fixture whose Fork has the default facts published.
fn published() -> Fixture {
    let mut fixture = fixture();
    ok(fixture
        .store
        .publish_counterfactual_facts(fixture.fork, facts()));
    fixture
}

const fn at(fork: TimelineId, generation: u64) -> ForkGenerationV1 {
    ForkGenerationV1 { fork, generation }
}

/// Logical sequence numbers visible on one Timeline.
fn seqs(store: &MemoryStore, timeline: TimelineId) -> Vec<u64> {
    ok(store.read(timeline, SeqRange::all()))
        .iter()
        .map(|event| event.seq.as_u64())
        .collect()
}

fn committed(
    store: &mut MemoryStore,
    command: &CounterfactualInvalidationCommandV1,
) -> CounterfactualGenerationReceiptV1 {
    match ok(store.commit_counterfactual_invalidation(command)) {
        CounterfactualInvalidationOutcomeV1::Committed(receipt) => *receipt,
        other @ CounterfactualInvalidationOutcomeV1::InvalidationConflict(_) => {
            std::panic::resume_unwind(Box::new(format!("expected a commit, got {other:?}")))
        }
    }
}

#[test]
fn facts_require_a_visible_fork() {
    let mut fixture = fixture();
    let fork = fixture.fork;
    let store = &mut fixture.store;

    assert_eq!(
        store.publish_counterfactual_facts(TimelineId::new(), facts()),
        Err(StoreError::ForkNotFound)
    );
    assert_eq!(
        store.publish_counterfactual_facts(fixture.root, facts()),
        Err(StoreError::ForkNotFound)
    );
    assert_eq!(
        store.current_fork_generation(fork),
        Err(StoreError::ForkNotFound)
    );
    assert_eq!(
        store.read_generation_artifact(at(fork, 0), hash(1)),
        Err(StoreError::ForkNotFound)
    );

    assert_eq!(
        store.publish_counterfactual_facts(fork, facts()),
        Ok(at(fork, 0))
    );
    assert_eq!(store.current_fork_generation(fork), Ok(at(fork, 0)));
    assert_eq!(
        store.read_generation_artifact(at(fork, 0), hash(1)),
        Ok(None)
    );
}

#[test]
fn commit_installs_the_whole_generation() {
    let mut fixture = published();
    let fork = fixture.fork;
    let store = &mut fixture.store;
    let command = Spec::new(fork).command();

    let receipt = committed(store, &command);

    assert_eq!(
        receipt,
        ok(command.committed_receipt(&SEAL, Seq::from_u64(3)))
    );
    assert_eq!(receipt.generation(), at(fork, 1));
    assert_eq!(receipt.first_tick_head(), Seq::from_u64(3));
    assert_eq!(store.current_fork_generation(fork), Ok(at(fork, 1)));
    assert_eq!(seqs(store, fork), vec![1, 2, 3]);
    assert_eq!(seqs(store, fixture.root), vec![1, 2]);
    assert_eq!(
        store.read_generation_artifact(at(fork, 1), command.frontier().digest()),
        Ok(Some(command.frontier().as_bytes().to_vec()))
    );
    assert_eq!(
        store.read_generation_artifact(at(fork, 1), command.invalidation().digest()),
        Ok(Some(command.invalidation().as_bytes().to_vec()))
    );
    assert_eq!(
        store.read_generation_artifact(at(fork, 1), hash(99)),
        Ok(None)
    );
    // A quarantined digest this store holds no bytes for reads as absent.
    for quarantined in [hash(10), hash(11), hash(12)] {
        assert_eq!(
            store.read_generation_artifact(at(fork, 1), quarantined),
            Ok(None)
        );
    }
    for stale in [0, 2] {
        assert_eq!(
            store.read_generation_artifact(at(fork, stale), command.frontier().digest()),
            Err(StoreError::MixedForkGeneration)
        );
    }
    assert_eq!(
        store.read_generation_artifact(at(fixture.root, 1), hash(99)),
        Err(StoreError::ForkNotFound)
    );
}

#[test]
fn later_generation_quarantines_prior_artifacts_and_keeps_its_generation() {
    let mut fixture = published();
    let fork = fixture.fork;
    let store = &mut fixture.store;
    let first = Spec::new(fork).command();
    committed(store, &first);
    let second = Spec {
        record_id: 2,
        head: 3,
        prior: 1,
        invalid_artifacts: vec![first.frontier().digest()],
        evictions: Vec::new(),
        drafts: 1,
        ..Spec::new(fork)
    }
    .command();

    let receipt = committed(store, &second);

    assert_eq!(receipt.generation(), at(fork, 2));
    assert_eq!(receipt.first_tick_head(), Seq::from_u64(4));
    assert_eq!(seqs(store, fork), vec![1, 2, 3, 4]);
    assert_eq!(
        store.read_generation_artifact(at(fork, 2), first.frontier().digest()),
        Err(StoreError::InvalidArtifactReuse)
    );
    assert_eq!(
        store.read_generation_artifact(at(fork, 2), first.invalidation().digest()),
        Ok(Some(first.invalidation().as_bytes().to_vec()))
    );
    assert_eq!(
        store.read_generation_artifact(at(fork, 2), second.frontier().digest()),
        Ok(Some(second.frontier().as_bytes().to_vec()))
    );
    assert_eq!(
        store.read_generation_artifact(at(fork, 2), hash(10)),
        Ok(None)
    );
    assert_eq!(
        store.publish_counterfactual_facts(fork, facts()),
        Ok(at(fork, 2))
    );
    assert_eq!(store.current_fork_generation(fork), Ok(at(fork, 2)));
}

#[test]
fn bytes_rewritten_by_a_later_generation_are_readable_there() {
    let mut fixture = published();
    let fork = fixture.fork;
    let store = &mut fixture.store;
    let first = Spec::new(fork).command();
    committed(store, &first);
    let second = Spec {
        record_id: 2,
        head: 3,
        prior: 1,
        invalid_artifacts: vec![first.frontier().digest()],
        evictions: Vec::new(),
        drafts: 1,
        ..Spec::new(fork)
    }
    .command();
    committed(store, &second);
    // The third generation recomputes the first generation's exact frontier.
    let third = Spec {
        head: 4,
        prior: 2,
        invalid_artifacts: Vec::new(),
        evictions: Vec::new(),
        drafts: 1,
        ..Spec::new(fork)
    }
    .command();
    assert_eq!(third.frontier(), first.frontier());
    assert_eq!(
        store.read_generation_artifact(at(fork, 2), first.frontier().digest()),
        Err(StoreError::InvalidArtifactReuse)
    );

    assert_eq!(committed(store, &third).generation(), at(fork, 3));

    assert_eq!(
        store.read_generation_artifact(at(fork, 3), first.frontier().digest()),
        Ok(Some(first.frontier().as_bytes().to_vec()))
    );
    assert_eq!(
        store.read_generation_artifact(at(fork, 3), third.invalidation().digest()),
        Ok(Some(third.invalidation().as_bytes().to_vec()))
    );
}

#[test]
fn committed_generation_receipts_are_recoverable() {
    let mut fixture = fixture();
    let fork = fixture.fork;
    let store = &mut fixture.store;
    assert_eq!(
        store.committed_generation_receipt(at(fork, 1)),
        Err(StoreError::ForkNotFound)
    );
    ok(store.publish_counterfactual_facts(fork, facts()));
    assert_eq!(store.committed_generation_receipt(at(fork, 0)), Ok(None));
    let first = committed(store, &Spec::new(fork).command());
    let second = committed(
        store,
        &Spec {
            record_id: 2,
            head: 3,
            prior: 1,
            drafts: 1,
            ..Spec::new(fork)
        }
        .command(),
    );

    // Earlier generations stay recoverable; nothing committed generation 0
    // or any generation after the committed one.
    assert_eq!(
        store.committed_generation_receipt(at(fork, 1)),
        Ok(Some(first))
    );
    assert_eq!(
        store.committed_generation_receipt(at(fork, 2)),
        Ok(Some(second))
    );
    for absent in [0, 3, u64::MAX] {
        assert_eq!(
            store.committed_generation_receipt(at(fork, absent)),
            Ok(None)
        );
    }
    assert_eq!(
        store.committed_generation_receipt(at(fixture.root, 1)),
        Err(StoreError::ForkNotFound)
    );

    fixture.gate.block_timeline(fork);
    assert_eq!(
        fixture.store.committed_generation_receipt(at(fork, 1)),
        Err(StoreError::StorageFailure)
    );
    let ungated = fixture.store.without_erasure_gate();
    assert_eq!(
        ungated.committed_generation_receipt(at(fork, 1)),
        Err(StoreError::StorageFailure)
    );
}

#[test]
fn every_stale_basis_fact_conflicts_and_commits_nothing() {
    let cases: [StaleCase<Spec>; 7] = [
        (|spec| spec.head = 2, InvalidationConflictV1::LogicalHead),
        (
            |spec| spec.plan = hash(50),
            InvalidationConflictV1::PlanDigest,
        ),
        (
            |spec| spec.graph = hash(30),
            InvalidationConflictV1::DependencyGraphDigest,
        ),
        (
            |spec| spec.prior = 1,
            InvalidationConflictV1::PriorGeneration,
        ),
        (
            |spec| spec.trust_epoch = 60,
            InvalidationConflictV1::TrustEpoch,
        ),
        (
            |spec| spec.revocation_epoch = 70,
            InvalidationConflictV1::RevocationEpoch,
        ),
        (
            |spec| spec.erasure_epoch = 80,
            InvalidationConflictV1::ErasureEpoch,
        ),
    ];
    for (mutate, conflict) in cases {
        let mut fixture = published();
        let fork = fixture.fork;
        let mut spec = Spec::new(fork);
        mutate(&mut spec);
        let command = spec.command();

        assert_eq!(
            fixture.store.commit_counterfactual_invalidation(&command),
            Ok(CounterfactualInvalidationOutcomeV1::InvalidationConflict(
                conflict
            ))
        );
        assert_eq!(fixture.store.current_fork_generation(fork), Ok(at(fork, 0)));
        assert_eq!(seqs(&fixture.store, fork), vec![1]);
        assert_eq!(
            fixture
                .store
                .read_generation_artifact(at(fork, 0), command.frontier().digest()),
            Ok(None)
        );
        assert_eq!(
            fixture
                .store
                .read_generation_artifact(at(fork, 0), hash(10)),
            Ok(None)
        );
    }
}

#[test]
fn republished_facts_are_the_recheck_basis() {
    let mut fixture = published();
    let fork = fixture.fork;
    let republished = CounterfactualFactsV1 {
        revocation_epoch: 9,
        ..facts()
    };
    assert_eq!(
        fixture
            .store
            .publish_counterfactual_facts(fork, republished),
        Ok(at(fork, 0))
    );

    assert_eq!(
        fixture
            .store
            .commit_counterfactual_invalidation(&Spec::new(fork).command()),
        Ok(CounterfactualInvalidationOutcomeV1::InvalidationConflict(
            InvalidationConflictV1::RevocationEpoch
        ))
    );
    let accepted = Spec {
        revocation_epoch: 9,
        ..Spec::new(fork)
    }
    .command();
    assert_eq!(
        committed(&mut fixture.store, &accepted).generation(),
        at(fork, 1)
    );
}

#[test]
fn replaying_a_committed_command_is_stale() {
    let mut fixture = published();
    let fork = fixture.fork;
    let command = Spec::new(fork).command();
    committed(&mut fixture.store, &command);

    assert_eq!(
        fixture.store.commit_counterfactual_invalidation(&command),
        Ok(CounterfactualInvalidationOutcomeV1::InvalidationConflict(
            InvalidationConflictV1::LogicalHead
        ))
    );
    assert_eq!(fixture.store.current_fork_generation(fork), Ok(at(fork, 1)));
    assert_eq!(seqs(&fixture.store, fork), vec![1, 2, 3]);
}

#[test]
fn unpublished_root_and_deleted_forks_are_not_found() {
    let mut fixture = fixture();
    let fork = fixture.fork;
    let store = &mut fixture.store;

    assert_eq!(
        store.commit_counterfactual_invalidation(&Spec::new(fork).command()),
        Err(StoreError::ForkNotFound)
    );
    assert_eq!(
        store.commit_counterfactual_invalidation(&Spec::new(fixture.root).command()),
        Err(StoreError::ForkNotFound)
    );
    assert_eq!(seqs(store, fork), vec![1]);

    ok(store.publish_counterfactual_facts(fork, facts()));
    let command = Spec::new(fork).command();
    committed(store, &command);
    ok(store.delete_timeline(fork));

    // Deletion purges the counterfactual state, and the deleted Fork is no
    // longer visible to any port operation.
    assert_eq!(
        store.commit_counterfactual_invalidation(&command),
        Err(StoreError::ForkNotFound)
    );
    assert_eq!(
        store.current_fork_generation(fork),
        Err(StoreError::ForkNotFound)
    );
    assert_eq!(
        store.read_generation_artifact(at(fork, 1), command.frontier().digest()),
        Err(StoreError::ForkNotFound)
    );
    assert_eq!(
        store.publish_counterfactual_facts(fork, facts()),
        Err(StoreError::ForkNotFound)
    );
    assert_eq!(
        store.current_counterfactual_basis(fork),
        Err(StoreError::ForkNotFound)
    );
    assert_eq!(
        store.append_counterfactual_tick(fork, &basis(3, 1, facts()), &tick_drafts(1, None)),
        Err(StoreError::ForkNotFound)
    );
}

#[test]
fn deleting_a_fork_purges_its_state_and_keeps_only_a_generation_floor() {
    let mut fixture = published();
    let (fork, root) = (fixture.fork, fixture.root);
    let store = &mut fixture.store;
    let command = Spec::new(fork).command();
    committed(store, &command);

    // A failed delete (the root still has a Fork) leaves the rows intact.
    assert!(store.delete_timeline(root).is_err());
    assert_eq!(store.current_fork_generation(fork), Ok(at(fork, 1)));
    assert_eq!(
        store.read_generation_artifact(at(fork, 1), command.frontier().digest()),
        Ok(Some(command.frontier().as_bytes().to_vec()))
    );

    ok(store.delete_timeline(fork));
    assert_eq!(
        store.committed_generation_receipt(at(fork, 1)),
        Err(StoreError::ForkNotFound)
    );

    // A Fork re-created under the same id resumes at the floor and holds
    // none of the purged state.
    let mut meta = TimelineMeta::forked_from(root, Seq::from_u64(1), "recreated");
    meta.id = fork;
    ok(store.create_timeline_with_meta(meta.clone()));
    assert_eq!(
        store.current_fork_generation(fork),
        Err(StoreError::ForkNotFound)
    );
    assert_eq!(
        store.publish_counterfactual_facts(fork, facts()),
        Ok(at(fork, 1))
    );
    assert_eq!(
        store.read_generation_artifact(at(fork, 1), command.frontier().digest()),
        Ok(None)
    );
    assert_eq!(store.committed_generation_receipt(at(fork, 1)), Ok(None));
    let second = Spec {
        prior: 1,
        ..Spec::new(fork)
    }
    .command();
    assert_eq!(committed(store, &second).generation(), at(fork, 2));

    // The floor follows the last generation, so a second delete raises it.
    ok(store.delete_timeline(fork));
    ok(store.create_timeline_with_meta(meta));
    assert_eq!(
        store.publish_counterfactual_facts(fork, facts()),
        Ok(at(fork, 2))
    );
}

#[test]
fn contained_fork_fails_closed_without_committing() {
    let mut fixture = published();
    let fork = fixture.fork;
    let command = Spec::new(fork).command();
    fixture.gate.block_timeline(fork);

    assert_eq!(
        fixture.store.commit_counterfactual_invalidation(&command),
        Err(StoreError::StorageFailure)
    );
    assert_eq!(
        fixture.store.append_counterfactual_tick(
            fork,
            &command.expected_basis(),
            &tick_drafts(1, None)
        ),
        Err(StoreError::StorageFailure)
    );
    // The generation, basis, and artifact reads are fenced like every
    // Timeline read.
    assert_eq!(
        fixture.store.current_fork_generation(fork),
        Err(StoreError::StorageFailure)
    );
    assert_eq!(
        fixture.store.current_counterfactual_basis(fork),
        Err(StoreError::StorageFailure)
    );
    assert_eq!(
        fixture
            .store
            .read_generation_artifact(at(fork, 0), command.frontier().digest()),
        Err(StoreError::StorageFailure)
    );
    // Unfenced publication still reports the uncommitted generation 0.
    assert_eq!(
        fixture.store.publish_counterfactual_facts(fork, facts()),
        Ok(at(fork, 0))
    );
}

#[test]
fn ungated_store_fails_closed_except_publication() {
    let fixture = published();
    let fork = fixture.fork;
    let command = Spec::new(fork).command();

    // Without the host erasure gate the appending commit and the
    // Timeline-derived reads are refused, while publication touches only
    // host-owned facts.
    let mut ungated = fixture.store.without_erasure_gate();
    assert_eq!(
        ungated.commit_counterfactual_invalidation(&command),
        Err(StoreError::StorageFailure)
    );
    assert_eq!(
        ungated.append_counterfactual_tick(fork, &command.expected_basis(), &tick_drafts(1, None)),
        Err(StoreError::StorageFailure)
    );
    assert_eq!(
        ungated.publish_counterfactual_facts(fork, facts()),
        Ok(at(fork, 0))
    );
    assert_eq!(
        ungated.current_fork_generation(fork),
        Err(StoreError::StorageFailure)
    );
    assert_eq!(
        ungated.current_counterfactual_basis(fork),
        Err(StoreError::StorageFailure)
    );
    assert_eq!(
        ungated.read_generation_artifact(at(fork, 0), hash(1)),
        Err(StoreError::StorageFailure)
    );
}

const fn basis(head: u64, generation: u64, facts: CounterfactualFactsV1) -> CounterfactualBasisV1 {
    CounterfactualBasisV1 {
        fork_logical_head: Seq::from_u64(head),
        generation,
        facts,
    }
}

/// A published fixture with the default command committed at generation 1.
fn generation_one() -> (Fixture, CounterfactualGenerationReceiptV1) {
    let mut fixture = published();
    let receipt = committed(&mut fixture.store, &Spec::new(fixture.fork).command());
    (fixture, receipt)
}

#[test]
fn basis_reads_the_persisted_head_generation_and_facts() {
    let mut fixture = fixture();
    let fork = fixture.fork;
    let store = &mut fixture.store;

    assert_eq!(
        store.current_counterfactual_basis(fork),
        Err(StoreError::ForkNotFound)
    );
    assert_eq!(
        store.current_counterfactual_basis(fixture.root),
        Err(StoreError::ForkNotFound)
    );
    ok(store.publish_counterfactual_facts(fork, facts()));
    assert_eq!(
        store.current_counterfactual_basis(fork),
        Ok(basis(1, 0, facts()))
    );

    let receipt = committed(store, &Spec::new(fork).command());
    assert_eq!(receipt.facts(), facts());
    assert_eq!(
        store.current_counterfactual_basis(fork),
        Ok(receipt.tick_basis(Seq::from_u64(3)))
    );

    let republished = CounterfactualFactsV1 {
        erasure_epoch: 81,
        ..facts()
    };
    ok(store.publish_counterfactual_facts(fork, republished));
    assert_eq!(
        store.current_counterfactual_basis(fork),
        Ok(basis(3, 1, republished))
    );
}

#[test]
fn later_ticks_commit_on_the_receipt_basis() {
    let (mut fixture, receipt) = generation_one();
    let fork = fixture.fork;
    let store = &mut fixture.store;
    let first = receipt.tick_basis(receipt.first_tick_head());

    assert_eq!(
        store.append_counterfactual_tick(fork, &first, &tick_drafts(2, None)),
        Ok(CounterfactualTickOutcomeV1::Committed {
            head: Seq::from_u64(5)
        })
    );
    assert_eq!(seqs(store, fork), vec![1, 2, 3, 4, 5]);
    assert_eq!(
        store.append_counterfactual_tick(
            fork,
            &receipt.tick_basis(Seq::from_u64(5)),
            &tick_drafts(1, None)
        ),
        Ok(CounterfactualTickOutcomeV1::Committed {
            head: Seq::from_u64(6)
        })
    );
    // Replaying the first Tick on its old basis is stale and commits nothing.
    assert_eq!(
        store.append_counterfactual_tick(fork, &first, &tick_drafts(2, None)),
        Ok(CounterfactualTickOutcomeV1::Stale(
            InvalidationConflictV1::LogicalHead
        ))
    );
    assert_eq!(seqs(store, fork), vec![1, 2, 3, 4, 5, 6]);
    assert_eq!(seqs(store, fixture.root), vec![1, 2]);
    assert_eq!(store.current_fork_generation(fork), Ok(at(fork, 1)));
    assert_eq!(
        store.current_counterfactual_basis(fork),
        Ok(receipt.tick_basis(Seq::from_u64(6)))
    );
}

#[test]
fn every_stale_tick_basis_fact_is_stale_and_commits_nothing() {
    let cases: [StaleCase<CounterfactualBasisV1>; 7] = [
        (
            |basis| basis.fork_logical_head = Seq::from_u64(2),
            InvalidationConflictV1::LogicalHead,
        ),
        (
            |basis| basis.facts.plan_digest = hash(50),
            InvalidationConflictV1::PlanDigest,
        ),
        (
            |basis| basis.facts.dependency_graph_digest = hash(30),
            InvalidationConflictV1::DependencyGraphDigest,
        ),
        (
            |basis| basis.generation = 0,
            InvalidationConflictV1::PriorGeneration,
        ),
        (
            |basis| basis.facts.trust_epoch = 60,
            InvalidationConflictV1::TrustEpoch,
        ),
        (
            |basis| basis.facts.revocation_epoch = 70,
            InvalidationConflictV1::RevocationEpoch,
        ),
        (
            |basis| basis.facts.erasure_epoch = 80,
            InvalidationConflictV1::ErasureEpoch,
        ),
    ];
    for (mutate, conflict) in cases {
        let (mut fixture, receipt) = generation_one();
        let fork = fixture.fork;
        let mut expected = receipt.tick_basis(receipt.first_tick_head());
        mutate(&mut expected);

        assert_eq!(
            fixture
                .store
                .append_counterfactual_tick(fork, &expected, &tick_drafts(1, None)),
            Ok(CounterfactualTickOutcomeV1::Stale(conflict))
        );
        assert_eq!(seqs(&fixture.store, fork), vec![1, 2, 3]);
        assert_eq!(
            fixture.store.current_counterfactual_basis(fork),
            Ok(receipt.tick_basis(Seq::from_u64(3)))
        );
    }
}

#[test]
fn guarded_first_tick_drafts_are_not_found_and_commit_nothing() {
    for kind in GUARDED_KINDS {
        let mut fixture = published();
        let fork = fixture.fork;
        let command = Spec {
            guarded: Some(kind),
            ..Spec::new(fork)
        }
        .command();

        assert_eq!(
            fixture.store.commit_counterfactual_invalidation(&command),
            Err(StoreError::ForkNotFound)
        );
        assert_eq!(
            fixture.store.current_counterfactual_basis(fork),
            Ok(basis(1, 0, facts()))
        );
        assert_eq!(seqs(&fixture.store, fork), vec![1]);
        assert_eq!(
            fixture
                .store
                .read_generation_artifact(at(fork, 0), command.frontier().digest()),
            Ok(None)
        );
        // The basis is rechecked first, so a stale command still conflicts.
        let stale = Spec {
            guarded: Some(kind),
            trust_epoch: 60,
            ..Spec::new(fork)
        }
        .command();
        assert_eq!(
            fixture.store.commit_counterfactual_invalidation(&stale),
            Ok(CounterfactualInvalidationOutcomeV1::InvalidationConflict(
                InvalidationConflictV1::TrustEpoch
            ))
        );
    }
}

#[test]
fn guarded_later_tick_drafts_are_not_found_and_commit_nothing() {
    for kind in GUARDED_KINDS {
        let (mut fixture, receipt) = generation_one();
        let fork = fixture.fork;
        let expected = receipt.tick_basis(receipt.first_tick_head());

        assert_eq!(
            fixture
                .store
                .append_counterfactual_tick(fork, &expected, &tick_drafts(2, Some(kind))),
            Err(StoreError::ForkNotFound)
        );
        assert_eq!(seqs(&fixture.store, fork), vec![1, 2, 3]);
        assert_eq!(
            fixture.store.current_counterfactual_basis(fork),
            Ok(expected)
        );
    }
}

#[test]
fn ticks_require_a_visible_published_fork() {
    let mut fixture = fixture();
    let fork = fixture.fork;
    let expected = basis(1, 0, facts());

    assert_eq!(
        fixture
            .store
            .append_counterfactual_tick(fork, &expected, &tick_drafts(1, None)),
        Err(StoreError::ForkNotFound)
    );
    assert_eq!(
        fixture
            .store
            .append_counterfactual_tick(fixture.root, &expected, &tick_drafts(1, None)),
        Err(StoreError::ForkNotFound)
    );
    assert_eq!(seqs(&fixture.store, fork), vec![1]);
    assert_eq!(seqs(&fixture.store, fixture.root), vec![1, 2]);
}
