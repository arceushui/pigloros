//! Public-interface tests for the ADR-064 `SQLite` counterfactual adapter.
#![cfg(feature = "sqlite")]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use pos_core::counterfactual_store::test_fixtures::{
    frontier_frame, hash_field, id_field, invalidation_frame, invalidation_middle, uint,
};
use pos_core::{
    CanonicalBytes, CounterfactualAdapterSealV1, CounterfactualBasisV1, CounterfactualFactsV1,
    CounterfactualGenerationReceiptV1, CounterfactualInvalidationCommandV1,
    CounterfactualInvalidationInputV1, CounterfactualInvalidationOutcomeV1,
    CounterfactualStoreErrorV1, CounterfactualStorePortV1, CounterfactualTickOutcomeV1, EntityId,
    ErasureContainmentGateV1, EventDraft, EventStore, ForkGenerationV1, Hash,
    InvalidationConflictV1, Kind, PipelineDraftBatchV1, RecomputationFrontierBytesV1, Seq,
    SuffixInvalidationBytesV1, TimelineId, TimelineMeta,
};
use pos_store::sqlite::SqliteStore;
use tempfile::{tempdir, TempDir};
use ulid::Ulid;

type StoreError = CounterfactualStoreErrorV1;
type Outcome = CounterfactualInvalidationOutcomeV1;
type TickOutcome = CounterfactualTickOutcomeV1;

/// Every column of one `counterfactual_generations` row after its key.
type StoredGenerationRow = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    i64,
);

/// One stale-basis case: how the expectation is altered and the conflict.
type StaleCase<T> = (fn(&mut T), InvalidationConflictV1);

/// One epoch setter and the conflict a different stored epoch reports.
type EpochSetter = (fn(&mut CounterfactualFactsV1, u64), InvalidationConflictV1);

/// Event types the generic append guard conceals as an absent Fork.
const GUARDED_KINDS: [&str; 3] = ["geo.location", "geo.cell", "consent.granted.v1"];

/// The adapter seal, minted here only to build expected receipts.
const SEAL: CounterfactualAdapterSealV1 = CounterfactualAdapterSealV1::for_adapter();
/// The largest integer `SQLite` stores.
const SQL_MAX: u64 = 9_223_372_036_854_775_807;

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
    })
}

const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
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

fn draft(value: u8) -> EventDraft {
    typed_draft("counterfactual.tick", value)
}

fn typed_draft(kind: &str, value: u8) -> EventDraft {
    EventDraft::new(
        EntityId::from_ulid(Ulid::from(9_u128)),
        Kind::new(kind),
        CanonicalBytes::from_vec(vec![value]),
    )
}

/// Ordinary drafts `values`, optionally ending with a `guarded` one.
fn tick_drafts(values: &[u8], guarded: Option<&str>) -> PipelineDraftBatchV1 {
    ok(PipelineDraftBatchV1::try_new(
        values
            .iter()
            .copied()
            .map(draft)
            .chain(guarded.map(|kind| typed_draft(kind, 0)))
            .collect(),
    ))
}

/// One invalidation request; every field defaults to the fixture's basis.
struct Spec {
    fork: TimelineId,
    facts: CounterfactualFactsV1,
    head: u64,
    prior: u64,
    frontier_id: u8,
    invalid_artifacts: Vec<Hash>,
    evictions: Vec<Hash>,
    first_tick: u64,
    guarded: Option<&'static str>,
}

impl Spec {
    fn new(fork: TimelineId) -> Self {
        Self {
            fork,
            facts: facts(),
            head: 2,
            prior: 0,
            frontier_id: 1,
            invalid_artifacts: vec![hash(10), hash(11)],
            evictions: vec![hash(12)],
            first_tick: 17,
            guarded: None,
        }
    }

    fn frontier(&self) -> RecomputationFrontierBytesV1 {
        let fields = [
            id_field([self.frontier_id; 16]),
            hash_field(self.facts.plan_digest),
            hash_field(hash(2)),
            hash_field(self.facts.dependency_graph_digest),
            vec![0x01],
        ]
        .concat();
        ok(RecomputationFrontierBytesV1::try_from_canonical(
            frontier_frame(&fields, 0),
        ))
    }

    fn invalidation(&self, frontier: &RecomputationFrontierBytesV1) -> SuffixInvalidationBytesV1 {
        let fields = [
            id_field([self.frontier_id; 16]),
            hash_field(frontier.plan_digest()),
            id_field(self.fork.inner().to_bytes()),
            uint(self.prior),
            uint(self.prior + 1),
            hash_field(frontier.digest()),
            invalidation_middle(),
            // Commit coordinate: the Fork, its expected head, the first Tick.
            vec![0x83],
            id_field(self.fork.inner().to_bytes()),
            uint(self.head),
            uint(self.first_tick),
        ]
        .concat();
        ok(SuffixInvalidationBytesV1::try_from_canonical(
            invalidation_frame(&fields, 0),
        ))
    }

    fn command(&self) -> CounterfactualInvalidationCommandV1 {
        let frontier = self.frontier();
        let invalidation = self.invalidation(&frontier);
        let mut invalid_artifacts = self.invalid_artifacts.clone();
        invalid_artifacts.sort();
        let mut evictions = self.evictions.clone();
        evictions.sort();
        ok(CounterfactualInvalidationCommandV1::try_new(
            CounterfactualInvalidationInputV1 {
                fork: self.fork,
                fork_logical_head: Seq::from_u64(self.head),
                trust_epoch: self.facts.trust_epoch,
                revocation_epoch: self.facts.revocation_epoch,
                erasure_epoch: self.facts.erasure_epoch,
                frontier,
                invalidation,
                invalid_artifacts,
                evictions,
                first_tick: self.first_tick,
                first_tick_drafts: tick_drafts(&[7, 8], self.guarded),
            },
        ))
    }
}

/// A file-backed store with a factual root (two Events) and a Fork at Seq 2
/// whose counterfactual facts are published.
struct Fixture {
    _directory: TempDir,
    path: PathBuf,
    root: TimelineId,
    fork: TimelineId,
}

fn fixture_path_str(fixture: &Fixture) -> &str {
    fixture.path.to_str().unwrap_or_default()
}

fn open(path: &Path) -> SqliteStore {
    let mut store = ok(SqliteStore::open(path.to_str().unwrap_or_default()));
    ok(store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open())));
    store
}

fn fixture() -> Fixture {
    let directory = ok(tempdir());
    let path = directory.path().join("counterfactual.db");
    let mut store = open(&path);
    let root = ok(store.create_timeline("factual")).id();
    ok(store.append(root, &[draft(1), draft(2)]));
    let fork = ok(store.fork(root, Seq::from_u64(2), "counterfactual")).id();
    assert_eq!(
        store.publish_counterfactual_facts(fork, facts()),
        Ok(ForkGenerationV1 {
            fork,
            generation: 0
        })
    );
    Fixture {
        _directory: directory,
        path,
        root,
        fork,
    }
}

fn execute(path: &Path, sql: &str) -> rusqlite::Result<()> {
    rusqlite::Connection::open(path).and_then(|connection| connection.execute_batch(sql))
}

fn scalar(path: &Path, sql: &str, fork: TimelineId) -> i64 {
    ok(rusqlite::Connection::open(path).and_then(|connection| {
        connection.query_row(sql, rusqlite::params![fork.to_string()], |row| row.get(0))
    }))
}

/// Rows written by commits on `fork`: own Events, generations, quarantine,
/// and readable artifacts.
fn written_rows(path: &Path, fork: TimelineId) -> [i64; 4] {
    [
        "SELECT count(*) FROM events WHERE timeline_id = ?1",
        "SELECT count(*) FROM counterfactual_generations WHERE fork_id = ?1",
        "SELECT count(*) FROM counterfactual_quarantine WHERE fork_id = ?1",
        "SELECT count(*) FROM counterfactual_artifacts WHERE fork_id = ?1",
    ]
    .map(|sql| scalar(path, sql, fork))
}

/// Count one exact quarantine row of generation 1.
fn quarantined_at_generation_one(path: &Path, fork: TimelineId, kind: i64, digest: Hash) -> i64 {
    ok(rusqlite::Connection::open(path).and_then(|connection| {
        connection.query_row(
            "SELECT count(*) FROM counterfactual_quarantine
             WHERE fork_id = ?1 AND generation = 1 AND kind = ?2 AND artifact_digest = ?3",
            rusqlite::params![fork.to_string(), kind, digest.as_bytes().as_slice()],
            |row| row.get(0),
        )
    }))
}

fn generation(store: &SqliteStore, fork: TimelineId) -> u64 {
    ok(store.current_fork_generation(fork)).generation
}

const fn at(fork: TimelineId, generation: u64) -> ForkGenerationV1 {
    ForkGenerationV1 { fork, generation }
}

fn open_error(result: Result<SqliteStore, pos_core::CoreError>) -> String {
    result
        .err()
        .map_or_else(String::new, |error| format!("{error}"))
}

#[test]
fn commit_persists_the_whole_generation_atomically() {
    let fixture = fixture();
    let fork = fixture.fork;
    let command = Spec::new(fork).command();
    let mut store = open(&fixture.path);
    assert_eq!(
        store.commit_counterfactual_invalidation(&command),
        Ok(Outcome::Committed(Box::new(ok(
            command.committed_receipt(&SEAL, Seq::from_u64(4))
        ))))
    );
    assert_eq!(store.current_fork_generation(fork), Ok(at(fork, 1)));
    assert_eq!(ok(store.logical_head(fork)), Seq::from_u64(4));
    assert_eq!(ok(store.logical_head(fixture.root)), Seq::from_u64(2));
    assert_eq!(written_rows(&fixture.path, fork), [2, 1, 3, 2]);

    let stored = ok(
        rusqlite::Connection::open(&fixture.path).and_then(|connection| {
            connection.query_row(
                "SELECT frontier_digest, frontier_bytes, invalidation_digest, invalidation_bytes,
                    first_tick, first_tick_head, plan_digest, dependency_graph_digest,
                    trust_epoch, revocation_epoch, erasure_epoch
             FROM counterfactual_generations WHERE fork_id = ?1 AND generation = 1",
                rusqlite::params![fork.to_string()],
                |row| <StoredGenerationRow>::try_from(row),
            )
        }),
    );
    assert_eq!(
        stored,
        (
            command.frontier().digest().as_bytes().to_vec(),
            command.frontier().as_bytes().to_vec(),
            command.invalidation().digest().as_bytes().to_vec(),
            command.invalidation().as_bytes().to_vec(),
            17,
            4,
            hash(5).as_bytes().to_vec(),
            hash(3).as_bytes().to_vec(),
            6,
            7,
            8,
        )
    );
    for (kind, digest) in [(0, hash(10)), (0, hash(11)), (1, hash(12))] {
        assert_eq!(
            quarantined_at_generation_one(&fixture.path, fork, kind, digest),
            1
        );
    }
    drop(store);

    // The committed generation is durable and generation-qualified.
    let reopened = open(&fixture.path);
    let current = at(fork, 1);
    assert_eq!(
        reopened.read_generation_artifact(current, command.frontier().digest()),
        Ok(Some(command.frontier().as_bytes().to_vec()))
    );
    assert_eq!(
        reopened.read_generation_artifact(current, command.invalidation().digest()),
        Ok(Some(command.invalidation().as_bytes().to_vec()))
    );
    // A quarantined digest this store holds no bytes for reads as absent.
    for quarantined in [hash(10), hash(11), hash(12)] {
        assert_eq!(
            reopened.read_generation_artifact(current, quarantined),
            Ok(None)
        );
    }
    assert_eq!(
        reopened.read_generation_artifact(current, hash(30)),
        Ok(None)
    );
    assert_eq!(
        reopened.read_generation_artifact(at(fork, 0), command.frontier().digest()),
        Err(StoreError::MixedForkGeneration)
    );
    assert_eq!(
        reopened.read_generation_artifact(at(fork, 2), hash(30)),
        Err(StoreError::MixedForkGeneration)
    );
}

#[test]
fn a_later_generation_quarantines_stored_bytes_permanently() {
    let fixture = fixture();
    let fork = fixture.fork;
    let first = Spec::new(fork).command();
    let mut store = open(&fixture.path);
    assert!(matches!(
        store.commit_counterfactual_invalidation(&first),
        Ok(Outcome::Committed(_))
    ));

    let mut spec = Spec::new(fork);
    spec.prior = 1;
    spec.head = 4;
    spec.frontier_id = 2;
    spec.invalid_artifacts = vec![hash(20), first.frontier().digest()];
    spec.evictions = Vec::new();
    let second = spec.command();
    assert_eq!(
        store.commit_counterfactual_invalidation(&second),
        Ok(Outcome::Committed(Box::new(ok(
            second.committed_receipt(&SEAL, Seq::from_u64(6))
        ))))
    );
    assert_eq!(generation(&store, fork), 2);
    let current = at(fork, 2);
    // Bytes written at or before the quarantined generation stay for audit
    // only.
    assert_eq!(
        store.read_generation_artifact(current, first.frontier().digest()),
        Err(StoreError::InvalidArtifactReuse)
    );
    assert_eq!(
        scalar(
            &fixture.path,
            "SELECT count(*) FROM counterfactual_artifacts WHERE fork_id = ?1",
            fork
        ),
        4
    );
    assert_eq!(
        store.read_generation_artifact(current, first.invalidation().digest()),
        Ok(Some(first.invalidation().as_bytes().to_vec()))
    );
    assert_eq!(store.read_generation_artifact(current, hash(10)), Ok(None));

    // Republishing facts replaces them without resetting the generation.
    let mut republished = facts();
    republished.trust_epoch = 9;
    assert_eq!(
        store.publish_counterfactual_facts(fork, republished),
        Ok(current)
    );
    assert_eq!(generation(&store, fork), 2);
    spec.prior = 2;
    spec.head = 6;
    spec.frontier_id = 3;
    spec.invalid_artifacts = Vec::new();
    assert_eq!(
        store.commit_counterfactual_invalidation(&spec.command()),
        Ok(Outcome::InvalidationConflict(
            InvalidationConflictV1::TrustEpoch
        ))
    );
    spec.facts = republished;
    assert!(matches!(
        store.commit_counterfactual_invalidation(&spec.command()),
        Ok(Outcome::Committed(_))
    ));
    assert_eq!(generation(&store, fork), 3);
}

#[test]
fn every_stale_basis_fact_conflicts_and_commits_nothing() {
    let fixture = fixture();
    let fork = fixture.fork;
    let cases: [StaleCase<Spec>; 7] = [
        (|spec| spec.head = 3, InvalidationConflictV1::LogicalHead),
        (
            |spec| spec.facts.plan_digest = hash(50),
            InvalidationConflictV1::PlanDigest,
        ),
        (
            |spec| spec.facts.dependency_graph_digest = hash(51),
            InvalidationConflictV1::DependencyGraphDigest,
        ),
        (
            |spec| spec.prior = 1,
            InvalidationConflictV1::PriorGeneration,
        ),
        (
            |spec| spec.facts.trust_epoch = 16,
            InvalidationConflictV1::TrustEpoch,
        ),
        (
            |spec| spec.facts.revocation_epoch = 17,
            InvalidationConflictV1::RevocationEpoch,
        ),
        (
            |spec| spec.facts.erasure_epoch = 18,
            InvalidationConflictV1::ErasureEpoch,
        ),
    ];
    let mut store = open(&fixture.path);
    for (stale, conflict) in cases {
        let mut spec = Spec::new(fork);
        stale(&mut spec);
        assert_eq!(
            store.commit_counterfactual_invalidation(&spec.command()),
            Ok(Outcome::InvalidationConflict(conflict))
        );
        assert_eq!(generation(&store, fork), 0);
        assert_eq!(ok(store.logical_head(fork)), Seq::from_u64(2));
        assert_eq!(written_rows(&fixture.path, fork), [0; 4]);
    }

    // A persisted fact moved by the host conflicts the same way.
    let mut moved = facts();
    moved.erasure_epoch = 99;
    assert_eq!(
        store.publish_counterfactual_facts(fork, moved),
        Ok(at(fork, 0))
    );
    assert_eq!(
        store.commit_counterfactual_invalidation(&Spec::new(fork).command()),
        Ok(Outcome::InvalidationConflict(
            InvalidationConflictV1::ErasureEpoch
        ))
    );
    assert_eq!(written_rows(&fixture.path, fork), [0; 4]);
    assert_eq!(
        store.publish_counterfactual_facts(fork, facts()),
        Ok(at(fork, 0))
    );
    assert!(matches!(
        store.commit_counterfactual_invalidation(&Spec::new(fork).command()),
        Ok(Outcome::Committed(_))
    ));
}

#[test]
fn injected_faults_roll_back_everything_and_recover_after_reopen() {
    let fixture = fixture();
    let fork = fixture.fork;
    let command = Spec::new(fork).command();
    for fault in [
        "BEFORE INSERT ON events WHEN (SELECT count(*) FROM events) = 3",
        "BEFORE INSERT ON counterfactual_generations",
        "BEFORE INSERT ON counterfactual_artifacts
         WHEN (SELECT count(*) FROM counterfactual_artifacts) = 1",
        "BEFORE INSERT ON counterfactual_quarantine WHEN NEW.kind = 1",
        "BEFORE UPDATE ON counterfactual_forks",
    ] {
        ok(execute(
            &fixture.path,
            &format!(
                "CREATE TRIGGER injected_fault {fault}
                 BEGIN SELECT RAISE(ABORT, 'injected counterfactual fault'); END;"
            ),
        ));
        let mut faulted = open(&fixture.path);
        assert_eq!(
            faulted.commit_counterfactual_invalidation(&command),
            Err(StoreError::StorageFailure),
            "{fault}"
        );
        assert_eq!(generation(&faulted, fork), 0, "{fault}");
        assert_eq!(ok(faulted.logical_head(fork)), Seq::from_u64(2), "{fault}");
        assert_eq!(written_rows(&fixture.path, fork), [0; 4], "{fault}");
        drop(faulted);
        ok(execute(&fixture.path, "DROP TRIGGER injected_fault;"));
    }

    let mut recovered = open(&fixture.path);
    assert_eq!(
        recovered.commit_counterfactual_invalidation(&command),
        Ok(Outcome::Committed(Box::new(ok(
            command.committed_receipt(&SEAL, Seq::from_u64(4))
        ))))
    );
    drop(recovered);
    let reopened = open(&fixture.path);
    assert_eq!(generation(&reopened, fork), 1);
    assert_eq!(
        reopened.committed_generation_receipt(at(fork, 1)),
        Ok(Some(ok(command.committed_receipt(&SEAL, Seq::from_u64(4)))))
    );
    assert_eq!(written_rows(&fixture.path, fork), [2, 1, 3, 2]);
}

#[test]
fn the_database_never_decreases_a_generation_or_rewrites_recorded_state() {
    let fixture = fixture();
    let fork = fixture.fork;
    let mut store = open(&fixture.path);
    assert!(matches!(
        store.commit_counterfactual_invalidation(&Spec::new(fork).command()),
        Ok(Outcome::Committed(_))
    ));
    drop(store);
    for rollback in [
        "UPDATE counterfactual_forks SET generation = 0",
        "UPDATE counterfactual_forks SET fork_id = 'reassigned'",
        "DELETE FROM counterfactual_forks",
        "DELETE FROM counterfactual_quarantine",
        "UPDATE counterfactual_quarantine SET artifact_digest = zeroblob(32)",
        "DELETE FROM counterfactual_generations",
        "UPDATE counterfactual_generations SET frontier_bytes = X'00'",
        "DELETE FROM counterfactual_artifacts",
        "UPDATE counterfactual_artifacts SET artifact_bytes = X'00'",
    ] {
        assert!(execute(&fixture.path, rollback).is_err(), "{rollback}");
    }
    ok(execute(
        &fixture.path,
        "UPDATE counterfactual_forks SET trust_epoch = trust_epoch",
    ));

    let mut reopened = open(&fixture.path);
    assert_eq!(generation(&reopened, fork), 1);
    // The recorded bytes are unchanged by the refused rewrites.
    let command = Spec::new(fork).command();
    assert_eq!(
        reopened.read_generation_artifact(at(fork, 1), command.frontier().digest()),
        Ok(Some(command.frontier().as_bytes().to_vec()))
    );
    assert_eq!(
        reopened.publish_counterfactual_facts(fork, facts()),
        Ok(at(fork, 1))
    );
    assert_eq!(written_rows(&fixture.path, fork), [2, 1, 3, 2]);
}

#[test]
fn missing_root_and_unpublished_timelines_are_not_forks() {
    let fixture = fixture();
    let mut store = open(&fixture.path);
    let unpublished = ok(store.fork(fixture.root, Seq::from_u64(1), "unpublished")).id();
    let missing = TimelineId::from_ulid(Ulid::from(0x0123_4567_89ab_cdef_u128));
    for timeline in [missing, fixture.root] {
        assert_eq!(
            store.publish_counterfactual_facts(timeline, facts()),
            Err(StoreError::ForkNotFound)
        );
    }
    for timeline in [missing, fixture.root, unpublished] {
        assert_eq!(
            store.current_fork_generation(timeline),
            Err(StoreError::ForkNotFound)
        );
        assert_eq!(
            store.read_generation_artifact(at(timeline, 0), hash(10)),
            Err(StoreError::ForkNotFound)
        );
        assert_eq!(
            store.commit_counterfactual_invalidation(&Spec::new(timeline).command()),
            Err(StoreError::ForkNotFound)
        );
        assert_eq!(
            store.append_counterfactual_tick(
                timeline,
                &basis(1, 0, facts()),
                &tick_drafts(&[1], None)
            ),
            Err(StoreError::ForkNotFound)
        );
        assert_eq!(
            store.current_counterfactual_basis(timeline),
            Err(StoreError::ForkNotFound)
        );
        assert_eq!(
            store.committed_generation_receipt(at(timeline, 1)),
            Err(StoreError::ForkNotFound)
        );
    }
    assert_eq!(written_rows(&fixture.path, unpublished), [0; 4]);
    assert_eq!(
        store.publish_counterfactual_facts(unpublished, facts()),
        Ok(at(unpublished, 0))
    );
    let mut spec = Spec::new(unpublished);
    spec.head = 1;
    assert!(matches!(
        store.commit_counterfactual_invalidation(&spec.command()),
        Ok(Outcome::Committed(_))
    ));
}

#[test]
fn integers_beyond_sqlite_storage_are_out_of_bounds() {
    let fixture = fixture();
    let fork = fixture.fork;
    let mut store = open(&fixture.path);
    let setters: [EpochSetter; 3] = [
        (
            |facts, value| facts.trust_epoch = value,
            InvalidationConflictV1::TrustEpoch,
        ),
        (
            |facts, value| facts.revocation_epoch = value,
            InvalidationConflictV1::RevocationEpoch,
        ),
        (
            |facts, value| facts.erasure_epoch = value,
            InvalidationConflictV1::ErasureEpoch,
        ),
    ];
    for (set, conflict) in setters {
        let mut limit = facts();
        set(&mut limit, SQL_MAX);
        assert_eq!(
            store.publish_counterfactual_facts(fork, limit),
            Ok(at(fork, 0))
        );
        let mut beyond = facts();
        set(&mut beyond, SQL_MAX + 1);
        assert_eq!(
            store.publish_counterfactual_facts(fork, beyond),
            Err(StoreError::FieldOutOfBounds)
        );
        // The rejected publication left the stored limit in place.
        assert_eq!(
            store.commit_counterfactual_invalidation(&Spec::new(fork).command()),
            Ok(Outcome::InvalidationConflict(conflict))
        );
        assert_eq!(
            store.publish_counterfactual_facts(fork, facts()),
            Ok(at(fork, 0))
        );
    }

    let mut spec = Spec::new(fork);
    spec.prior = SQL_MAX;
    assert_eq!(
        store.commit_counterfactual_invalidation(&spec.command()),
        Err(StoreError::FieldOutOfBounds)
    );
    spec.prior = SQL_MAX - 1;
    assert_eq!(
        store.commit_counterfactual_invalidation(&spec.command()),
        Ok(Outcome::InvalidationConflict(
            InvalidationConflictV1::PriorGeneration
        ))
    );

    let mut spec = Spec::new(fork);
    spec.first_tick = SQL_MAX + 1;
    assert_eq!(
        store.commit_counterfactual_invalidation(&spec.command()),
        Err(StoreError::FieldOutOfBounds)
    );
    assert_eq!(written_rows(&fixture.path, fork), [0; 4]);
    spec.first_tick = SQL_MAX;
    assert!(matches!(
        store.commit_counterfactual_invalidation(&spec.command()),
        Ok(Outcome::Committed(_))
    ));
    assert_eq!(
        scalar(
            &fixture.path,
            "SELECT first_tick FROM counterfactual_generations WHERE fork_id = ?1",
            fork
        ),
        i64::MAX
    );
}

#[test]
fn containment_and_admitted_forks_fail_closed() {
    let fixture = fixture();
    let fork = fixture.fork;
    let command = Spec::new(fork).command();

    // Without the host erasure gate the appending commit and the
    // Timeline-derived reads are refused, while publication touches only
    // host-owned facts.
    let mut ungated = ok(SqliteStore::open(fixture.path.to_str().unwrap_or_default()));
    assert_eq!(
        ungated.commit_counterfactual_invalidation(&command),
        Err(StoreError::StorageFailure)
    );
    assert_eq!(
        ungated.append_counterfactual_tick(
            fork,
            &command.expected_basis(),
            &tick_drafts(&[1], None)
        ),
        Err(StoreError::StorageFailure)
    );
    assert_eq!(
        ungated.current_counterfactual_basis(fork),
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
        ungated.read_generation_artifact(at(fork, 0), hash(1)),
        Err(StoreError::StorageFailure)
    );
    assert_eq!(
        ungated.committed_generation_receipt(at(fork, 1)),
        Err(StoreError::StorageFailure)
    );
    drop(ungated);
    assert_eq!(written_rows(&fixture.path, fork), [0; 4]);

    // An ADR-099 admitted Fork reserves its appends for classified authority.
    ok(execute(
        &fixture.path,
        &format!("INSERT INTO fork_admissions (child_id, far1_cbor) VALUES ('{fork}', X'00');"),
    ));
    let mut admitted = open(&fixture.path);
    assert_eq!(
        admitted.commit_counterfactual_invalidation(&command),
        Err(StoreError::StorageFailure)
    );
    assert_eq!(
        admitted.append_counterfactual_tick(
            fork,
            &command.expected_basis(),
            &tick_drafts(&[1], None)
        ),
        Err(StoreError::StorageFailure)
    );
    // Reading the basis is not an append and stays available.
    assert_eq!(
        admitted.current_counterfactual_basis(fork),
        Ok(command.expected_basis())
    );
    assert_eq!(generation(&admitted, fork), 0);
    assert_eq!(written_rows(&fixture.path, fork), [0; 4]);
}

#[test]
fn a_geographic_evidence_protected_fork_is_not_found() {
    let fixture = fixture();
    let fork = fixture.fork;
    ok(execute(
        &fixture.path,
        &format!(
            "INSERT INTO geographic_presence (timeline_id, has_evidence) VALUES ('{root}', 1);",
            root = fixture.root
        ),
    ));
    let mut store = open(&fixture.path);
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
        Err(StoreError::ForkNotFound)
    );
    assert_eq!(
        store.commit_counterfactual_invalidation(&Spec::new(fork).command()),
        Err(StoreError::ForkNotFound)
    );
    assert_eq!(
        store.append_counterfactual_tick(fork, &basis(2, 0, facts()), &tick_drafts(&[1], None)),
        Err(StoreError::ForkNotFound)
    );
    assert_eq!(
        store.current_counterfactual_basis(fork),
        Err(StoreError::ForkNotFound)
    );
    assert_eq!(
        store.committed_generation_receipt(at(fork, 1)),
        Err(StoreError::ForkNotFound)
    );
    assert_eq!(written_rows(&fixture.path, fork), [0; 4]);
}

#[test]
fn corrupt_persisted_state_is_rejected_closed() {
    for (column, value) in [
        ("generation", "-1"),
        ("plan_digest", "X'00'"),
        ("dependency_graph_digest", "X'00'"),
        ("trust_epoch", "-1"),
        ("revocation_epoch", "-1"),
        ("erasure_epoch", "-1"),
    ] {
        let fixture = fixture();
        let fork = fixture.fork;
        ok(execute(
            &fixture.path,
            &format!(
                "PRAGMA ignore_check_constraints = ON;
                 DROP TRIGGER counterfactual_forks_generation_monotonic;
                 UPDATE counterfactual_forks SET {column} = {value};"
            ),
        ));
        // A writable open restores the dropped guard and accepts the shape.
        let mut store = open(&fixture.path);
        assert_eq!(
            store.current_fork_generation(fork),
            Err(StoreError::CorruptState),
            "{column}"
        );
        assert_eq!(
            store.current_counterfactual_basis(fork),
            Err(StoreError::CorruptState),
            "{column}"
        );
        assert_eq!(
            store.commit_counterfactual_invalidation(&Spec::new(fork).command()),
            Err(StoreError::CorruptState),
            "{column}"
        );
        assert_eq!(written_rows(&fixture.path, fork), [0; 4], "{column}");
        if column == "generation" {
            assert_eq!(
                store.read_generation_artifact(at(fork, 0), hash(1)),
                Err(StoreError::CorruptState)
            );
            assert_eq!(
                store.publish_counterfactual_facts(fork, facts()),
                Err(StoreError::CorruptState)
            );
        } else {
            // Republishing the facts repairs every host-owned column.
            assert_eq!(
                store.read_generation_artifact(at(fork, 0), hash(1)),
                Ok(None)
            );
            assert_eq!(
                store.publish_counterfactual_facts(fork, facts()),
                Ok(at(fork, 0))
            );
            assert_eq!(store.current_fork_generation(fork), Ok(at(fork, 0)));
        }
    }
}

/// Every counterfactual index and guard trigger, with a weakened body.
const SCHEMA_OBJECTS: [(&str, &str, &str); 16] = [
    (
        "INDEX",
        "idx_counterfactual_quarantine_artifact",
        "ON counterfactual_quarantine(fork_id)",
    ),
    (
        "TRIGGER",
        "counterfactual_forks_generation_monotonic",
        "BEFORE UPDATE ON counterfactual_forks BEGIN SELECT 1; END",
    ),
    (
        "TRIGGER",
        "counterfactual_forks_retained",
        "BEFORE DELETE ON counterfactual_forks BEGIN SELECT 1; END",
    ),
    (
        "TRIGGER",
        "counterfactual_quarantine_retained",
        "BEFORE DELETE ON counterfactual_quarantine BEGIN SELECT 1; END",
    ),
    (
        "TRIGGER",
        "counterfactual_quarantine_immutable",
        "BEFORE UPDATE ON counterfactual_quarantine BEGIN SELECT 1; END",
    ),
    (
        "TRIGGER",
        "counterfactual_generations_retained",
        "BEFORE DELETE ON counterfactual_generations BEGIN SELECT 1; END",
    ),
    (
        "TRIGGER",
        "counterfactual_generations_immutable",
        "BEFORE UPDATE ON counterfactual_generations BEGIN SELECT 1; END",
    ),
    (
        "TRIGGER",
        "counterfactual_artifacts_retained",
        "BEFORE DELETE ON counterfactual_artifacts BEGIN SELECT 1; END",
    ),
    (
        "TRIGGER",
        "counterfactual_artifacts_immutable",
        "BEFORE UPDATE ON counterfactual_artifacts BEGIN SELECT 1; END",
    ),
    (
        "TRIGGER",
        "counterfactual_forks_not_replaced",
        "BEFORE INSERT ON counterfactual_forks BEGIN SELECT 1; END",
    ),
    (
        "TRIGGER",
        "counterfactual_quarantine_not_replaced",
        "BEFORE INSERT ON counterfactual_quarantine BEGIN SELECT 1; END",
    ),
    (
        "TRIGGER",
        "counterfactual_generations_not_replaced",
        "BEFORE INSERT ON counterfactual_generations BEGIN SELECT 1; END",
    ),
    (
        "TRIGGER",
        "counterfactual_artifacts_not_replaced",
        "BEFORE INSERT ON counterfactual_artifacts BEGIN SELECT 1; END",
    ),
    (
        "TRIGGER",
        "counterfactual_fork_tombstones_retained",
        "BEFORE DELETE ON counterfactual_fork_tombstones BEGIN SELECT 1; END",
    ),
    (
        "TRIGGER",
        "counterfactual_fork_tombstones_floor_monotonic",
        "BEFORE UPDATE ON counterfactual_fork_tombstones BEGIN SELECT 1; END",
    ),
    (
        "TRIGGER",
        "counterfactual_fork_tombstones_floor_kept",
        "BEFORE INSERT ON counterfactual_fork_tombstones BEGIN SELECT 1; END",
    ),
];

#[test]
fn the_schema_is_additive_idempotent_and_validated_on_every_open() {
    let fixture = fixture();
    let fork = fixture.fork;
    let path_text = fixture.path.to_str().unwrap_or_default();
    let open_read_only = || open_error(SqliteStore::open_read_only(path_text));
    let open_writable = || open_error(SqliteStore::open(path_text));
    assert_eq!(open_writable(), "");
    assert_eq!(open_writable(), "");
    assert_eq!(open_read_only(), "");
    let mut read_only = ok(SqliteStore::open_read_only(path_text));
    ok(read_only.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open())));
    assert_eq!(read_only.current_fork_generation(fork), Ok(at(fork, 0)));
    drop(read_only);

    // A file from before this schema gains the tables on a writable open.
    ok(execute(
        &fixture.path,
        "DROP TABLE counterfactual_forks;
         DROP TABLE counterfactual_generations;
         DROP TABLE counterfactual_quarantine;
         DROP TABLE counterfactual_artifacts;
         DROP TABLE counterfactual_fork_tombstones;
         DROP TABLE counterfactual_purge_fence;",
    ));
    assert_eq!(open_read_only(), "");
    assert_eq!(open_writable(), "");
    assert_eq!(open_read_only(), "");
    let mut reopened = open(&fixture.path);
    assert_eq!(ok(reopened.logical_head(fork)), Seq::from_u64(2));
    assert_eq!(
        reopened.current_fork_generation(fork),
        Err(StoreError::ForkNotFound)
    );
    assert_eq!(
        reopened.publish_counterfactual_facts(fork, facts()),
        Ok(at(fork, 0))
    );
    drop(reopened);

    for (kind, name, weakened) in SCHEMA_OBJECTS {
        ok(execute(&fixture.path, &format!("DROP {kind} {name};")));
        assert!(open_read_only().contains(name), "{name}");
        // A writable open recreates a missing object.
        assert_eq!(open_writable(), "", "{name}");
        assert_eq!(open_read_only(), "", "{name}");
        ok(execute(
            &fixture.path,
            &format!("DROP {kind} {name}; CREATE {kind} {name} {weakened};"),
        ));
        assert!(open_writable().contains(name), "{name}");
        ok(execute(&fixture.path, &format!("DROP {kind} {name};")));
        assert_eq!(open_writable(), "", "{name}");
    }

    ok(execute(
        &fixture.path,
        "DROP TABLE counterfactual_artifacts;
         CREATE TABLE counterfactual_artifacts (
             fork_id TEXT NOT NULL,
             artifact_digest BLOB NOT NULL,
             PRIMARY KEY (fork_id, artifact_digest)
         );",
    ));
    assert!(open_writable().contains("counterfactual_artifacts table"));
    assert!(open_read_only().contains("counterfactual_artifacts table"));
}

const fn basis(head: u64, generation: u64, facts: CounterfactualFactsV1) -> CounterfactualBasisV1 {
    CounterfactualBasisV1 {
        fork_logical_head: Seq::from_u64(head),
        generation,
        facts,
    }
}

/// Commit the default command and return its receipt.
fn commit_default(store: &mut SqliteStore, fork: TimelineId) -> CounterfactualGenerationReceiptV1 {
    match ok(store.commit_counterfactual_invalidation(&Spec::new(fork).command())) {
        Outcome::Committed(receipt) => *receipt,
        other @ Outcome::InvalidationConflict(_) => {
            std::panic::resume_unwind(Box::new(format!("expected a commit, got {other:?}")))
        }
    }
}

/// Make the Fork's own head fall back to `reset` once it reaches `reached`,
/// so the staged Logical Head does not advance.
fn stall_head(path: &Path, fork: TimelineId, reached: u64, reset: u64) {
    ok(execute(
        path,
        &format!(
            "CREATE TRIGGER stalled_head AFTER UPDATE OF head_seq ON timelines
             WHEN NEW.id = '{fork}' AND NEW.head_seq = {reached}
             BEGIN UPDATE timelines SET head_seq = {reset} WHERE id = NEW.id; END;"
        ),
    ));
}

#[test]
fn the_basis_reads_the_persisted_head_generation_and_facts() {
    let fixture = fixture();
    let fork = fixture.fork;
    let mut store = open(&fixture.path);
    assert_eq!(
        store.current_counterfactual_basis(fork),
        Ok(basis(2, 0, facts()))
    );

    let receipt = commit_default(&mut store, fork);
    assert_eq!(receipt.facts(), facts());
    assert_eq!(
        store.current_counterfactual_basis(fork),
        Ok(receipt.tick_basis(Seq::from_u64(4)))
    );

    let mut republished = facts();
    republished.erasure_epoch = 81;
    ok(store.publish_counterfactual_facts(fork, republished));
    drop(store);
    let reopened = open(&fixture.path);
    assert_eq!(
        reopened.current_counterfactual_basis(fork),
        Ok(basis(4, 1, republished))
    );
}

#[test]
fn later_ticks_commit_on_the_receipt_basis() {
    let fixture = fixture();
    let fork = fixture.fork;
    let mut store = open(&fixture.path);
    let receipt = commit_default(&mut store, fork);
    let first = receipt.tick_basis(receipt.first_tick_head());

    assert_eq!(
        store.append_counterfactual_tick(fork, &first, &tick_drafts(&[20, 21], None)),
        Ok(TickOutcome::Committed {
            head: Seq::from_u64(6)
        })
    );
    assert_eq!(
        store.append_counterfactual_tick(
            fork,
            &receipt.tick_basis(Seq::from_u64(6)),
            &tick_drafts(&[22], None)
        ),
        Ok(TickOutcome::Committed {
            head: Seq::from_u64(7)
        })
    );
    // Replaying the first Tick on its old basis is stale and commits nothing.
    assert_eq!(
        store.append_counterfactual_tick(fork, &first, &tick_drafts(&[20, 21], None)),
        Ok(TickOutcome::Stale(InvalidationConflictV1::LogicalHead))
    );
    assert_eq!(written_rows(&fixture.path, fork), [5, 1, 3, 2]);
    assert_eq!(ok(store.logical_head(fixture.root)), Seq::from_u64(2));
    drop(store);
    let reopened = open(&fixture.path);
    assert_eq!(generation(&reopened, fork), 1);
    assert_eq!(
        reopened.current_counterfactual_basis(fork),
        Ok(receipt.tick_basis(Seq::from_u64(7)))
    );
}

#[test]
fn every_stale_tick_basis_fact_is_stale_and_commits_nothing() {
    let cases: [StaleCase<CounterfactualBasisV1>; 7] = [
        (
            |basis| basis.fork_logical_head = Seq::from_u64(3),
            InvalidationConflictV1::LogicalHead,
        ),
        (
            |basis| basis.facts.plan_digest = hash(50),
            InvalidationConflictV1::PlanDigest,
        ),
        (
            |basis| basis.facts.dependency_graph_digest = hash(51),
            InvalidationConflictV1::DependencyGraphDigest,
        ),
        (
            |basis| basis.generation = 0,
            InvalidationConflictV1::PriorGeneration,
        ),
        (
            |basis| basis.facts.trust_epoch = 16,
            InvalidationConflictV1::TrustEpoch,
        ),
        (
            |basis| basis.facts.revocation_epoch = 17,
            InvalidationConflictV1::RevocationEpoch,
        ),
        (
            |basis| basis.facts.erasure_epoch = 18,
            InvalidationConflictV1::ErasureEpoch,
        ),
    ];
    let fixture = fixture();
    let fork = fixture.fork;
    let mut store = open(&fixture.path);
    let receipt = commit_default(&mut store, fork);
    for (stale, conflict) in cases {
        let mut expected = receipt.tick_basis(receipt.first_tick_head());
        stale(&mut expected);
        assert_eq!(
            store.append_counterfactual_tick(fork, &expected, &tick_drafts(&[20], None)),
            Ok(TickOutcome::Stale(conflict))
        );
        assert_eq!(written_rows(&fixture.path, fork), [2, 1, 3, 2]);
        assert_eq!(
            store.current_counterfactual_basis(fork),
            Ok(receipt.tick_basis(Seq::from_u64(4)))
        );
    }
}

#[test]
fn guarded_tick_drafts_are_not_found_and_commit_nothing() {
    let fixture = fixture();
    let fork = fixture.fork;
    let mut store = open(&fixture.path);
    for kind in GUARDED_KINDS {
        let mut spec = Spec::new(fork);
        spec.guarded = Some(kind);
        assert_eq!(
            store.commit_counterfactual_invalidation(&spec.command()),
            Err(StoreError::ForkNotFound),
            "{kind}"
        );
        assert_eq!(written_rows(&fixture.path, fork), [0; 4], "{kind}");
        // The basis is rechecked first, so a stale command still conflicts.
        spec.facts.trust_epoch = 16;
        assert_eq!(
            store.commit_counterfactual_invalidation(&spec.command()),
            Ok(Outcome::InvalidationConflict(
                InvalidationConflictV1::TrustEpoch
            )),
            "{kind}"
        );
    }
    let receipt = commit_default(&mut store, fork);
    let expected = receipt.tick_basis(receipt.first_tick_head());
    for kind in GUARDED_KINDS {
        assert_eq!(
            store.append_counterfactual_tick(fork, &expected, &tick_drafts(&[20], Some(kind))),
            Err(StoreError::ForkNotFound),
            "{kind}"
        );
        assert_eq!(written_rows(&fixture.path, fork), [2, 1, 3, 2], "{kind}");
    }
    assert_eq!(store.current_counterfactual_basis(fork), Ok(expected));
}

#[test]
fn a_head_that_does_not_advance_is_corrupt_and_rolls_back() {
    let fixture = fixture();
    let fork = fixture.fork;
    let command = Spec::new(fork).command();
    // The first Tick's two Events reach own head 2; it falls back to 0.
    stall_head(&fixture.path, fork, 2, 0);
    let mut store = open(&fixture.path);
    assert_eq!(
        store.commit_counterfactual_invalidation(&command),
        Err(StoreError::CorruptState)
    );
    assert_eq!(written_rows(&fixture.path, fork), [0; 4]);
    assert_eq!(
        store.current_counterfactual_basis(fork),
        Ok(command.expected_basis())
    );
    drop(store);
    ok(execute(&fixture.path, "DROP TRIGGER stalled_head;"));

    let mut store = open(&fixture.path);
    let receipt = commit_default(&mut store, fork);
    drop(store);
    // A later Tick's Event reaches own head 3; it falls back to 2.
    stall_head(&fixture.path, fork, 3, 2);
    let mut store = open(&fixture.path);
    let expected = receipt.tick_basis(receipt.first_tick_head());
    assert_eq!(
        store.append_counterfactual_tick(fork, &expected, &tick_drafts(&[20], None)),
        Err(StoreError::CorruptState)
    );
    assert_eq!(written_rows(&fixture.path, fork), [2, 1, 3, 2]);
    assert_eq!(store.current_counterfactual_basis(fork), Ok(expected));
}

#[test]
fn a_repeated_frontier_is_recorded_at_each_generation() {
    let fixture = fixture();
    let fork = fixture.fork;
    let mut store = open(&fixture.path);
    let first = commit_default(&mut store, fork);
    let mut spec = Spec::new(fork);
    spec.prior = 1;
    spec.head = 4;
    spec.invalid_artifacts = Vec::new();
    spec.evictions = Vec::new();
    let repeated = spec.command();
    assert_eq!(repeated.frontier().digest(), first.frontier_digest());

    assert!(matches!(
        store.commit_counterfactual_invalidation(&repeated),
        Ok(Outcome::Committed(_))
    ));
    assert_eq!(written_rows(&fixture.path, fork), [4, 2, 3, 4]);
    assert_eq!(
        scalar(
            &fixture.path,
            "SELECT group_concat(generation) = '1,2' FROM (
                 SELECT generation FROM counterfactual_artifacts
                 WHERE fork_id = ?1 AND artifact_digest = (
                     SELECT frontier_digest FROM counterfactual_generations
                     WHERE fork_id = ?1 AND generation = 2
                 )
                 ORDER BY generation
             )",
            fork
        ),
        1
    );
    assert_eq!(
        store.read_generation_artifact(at(fork, 2), first.frontier_digest()),
        Ok(Some(repeated.frontier().as_bytes().to_vec()))
    );
}

#[test]
fn replacing_inserts_cannot_rewrite_recorded_state() {
    let fixture = fixture();
    let fork = fixture.fork;
    let mut store = open(&fixture.path);
    let receipt = commit_default(&mut store, fork);
    drop(store);
    for replace in [
        "INSERT OR REPLACE INTO counterfactual_forks
         SELECT fork_id, 0, plan_digest, dependency_graph_digest,
                trust_epoch, revocation_epoch, erasure_epoch
         FROM counterfactual_forks",
        "REPLACE INTO counterfactual_generations
         SELECT fork_id, generation, frontier_digest, X'00', invalidation_digest,
                invalidation_bytes, first_tick, first_tick_head, plan_digest,
                dependency_graph_digest, trust_epoch, revocation_epoch, erasure_epoch
         FROM counterfactual_generations",
        "INSERT OR REPLACE INTO counterfactual_artifacts
         SELECT fork_id, artifact_digest, generation, X'00' FROM counterfactual_artifacts",
        "REPLACE INTO counterfactual_quarantine SELECT * FROM counterfactual_quarantine",
    ] {
        assert!(execute(&fixture.path, replace).is_err(), "{replace}");
    }

    let reopened = open(&fixture.path);
    assert_eq!(generation(&reopened, fork), 1);
    assert_eq!(written_rows(&fixture.path, fork), [2, 1, 3, 2]);
    let command = Spec::new(fork).command();
    assert_eq!(
        reopened.read_generation_artifact(at(fork, 1), receipt.frontier_digest()),
        Ok(Some(command.frontier().as_bytes().to_vec()))
    );
    assert_eq!(
        reopened.committed_generation_receipt(at(fork, 1)),
        Ok(Some(receipt))
    );
    let stored = ok(
        rusqlite::Connection::open(&fixture.path).and_then(|connection| {
            connection.query_row(
                "SELECT frontier_bytes FROM counterfactual_generations WHERE fork_id = ?1",
                rusqlite::params![fork.to_string()],
                |row| row.get::<_, Vec<u8>>(0),
            )
        }),
    );
    assert_eq!(stored, command.frontier().as_bytes().to_vec());
}

#[test]
fn a_pre_schema_file_opens_read_only_without_counterfactual_state() {
    let fixture = fixture();
    let fork = fixture.fork;
    let path_text = fixture.path.to_str().unwrap_or_default();
    // Dropping the tables also drops their index and triggers.
    ok(execute(
        &fixture.path,
        "DROP TABLE counterfactual_forks;
         DROP TABLE counterfactual_generations;
         DROP TABLE counterfactual_quarantine;
         DROP TABLE counterfactual_artifacts;
         DROP TABLE counterfactual_fork_tombstones;
         DROP TABLE counterfactual_purge_fence;",
    ));
    let mut read_only = ok(SqliteStore::open_read_only(path_text));
    ok(read_only.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open())));
    assert_eq!(ok(read_only.logical_head(fork)), Seq::from_u64(2));
    assert_eq!(
        read_only.current_fork_generation(fork),
        Err(StoreError::ForkNotFound)
    );
    assert_eq!(
        read_only.current_counterfactual_basis(fork),
        Err(StoreError::ForkNotFound)
    );
    assert_eq!(
        read_only.read_generation_artifact(at(fork, 0), hash(1)),
        Err(StoreError::ForkNotFound)
    );
    drop(read_only);

    // A present but incomplete counterfactual schema is still refused.
    ok(execute(
        &fixture.path,
        "CREATE TABLE counterfactual_forks (fork_id TEXT NOT NULL PRIMARY KEY);",
    ));
    assert!(open_error(SqliteStore::open_read_only(path_text)).contains("counterfactual_forks"));
    ok(execute(&fixture.path, "DROP TABLE counterfactual_forks;"));
    ok(execute(
        &fixture.path,
        "CREATE TABLE unrelated (id INTEGER);
         CREATE TRIGGER counterfactual_shadow BEFORE INSERT ON unrelated BEGIN SELECT 1; END;",
    ));
    // An object on another table is not counterfactual state.
    assert_eq!(open_error(SqliteStore::open_read_only(path_text)), "");
    // `_` in the prefix is literal, so a lookalike table is not counterfactual
    // state either.
    ok(execute(
        &fixture.path,
        "CREATE TABLE counterfactualXother (id INTEGER);",
    ));
    let mut read_only = ok(SqliteStore::open_read_only(path_text));
    ok(read_only.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open())));
    assert_eq!(
        read_only.current_fork_generation(fork),
        Err(StoreError::ForkNotFound)
    );
}

#[test]
fn bytes_rewritten_by_a_later_generation_are_readable_there() {
    let fixture = fixture();
    let fork = fixture.fork;
    let mut store = open(&fixture.path);
    let first = Spec::new(fork).command();
    assert!(matches!(
        store.commit_counterfactual_invalidation(&first),
        Ok(Outcome::Committed(_))
    ));
    let mut spec = Spec::new(fork);
    spec.prior = 1;
    spec.head = 4;
    spec.frontier_id = 2;
    spec.invalid_artifacts = vec![first.frontier().digest()];
    spec.evictions = Vec::new();
    assert!(matches!(
        store.commit_counterfactual_invalidation(&spec.command()),
        Ok(Outcome::Committed(_))
    ));
    assert_eq!(
        store.read_generation_artifact(at(fork, 2), first.frontier().digest()),
        Err(StoreError::InvalidArtifactReuse)
    );

    // The third generation recomputes the first generation's exact frontier.
    spec.prior = 2;
    spec.head = 6;
    spec.frontier_id = 1;
    spec.invalid_artifacts = Vec::new();
    let third = spec.command();
    assert_eq!(third.frontier(), first.frontier());
    assert!(matches!(
        store.commit_counterfactual_invalidation(&third),
        Ok(Outcome::Committed(_))
    ));
    drop(store);

    let reopened = open(&fixture.path);
    assert_eq!(
        reopened.read_generation_artifact(at(fork, 3), first.frontier().digest()),
        Ok(Some(first.frontier().as_bytes().to_vec()))
    );
    assert_eq!(
        reopened.read_generation_artifact(at(fork, 3), first.invalidation().digest()),
        Ok(Some(first.invalidation().as_bytes().to_vec()))
    );
}

#[test]
fn committed_generation_receipts_are_recoverable_after_reopen() {
    let fixture = fixture();
    let fork = fixture.fork;
    let mut store = open(&fixture.path);
    assert_eq!(store.committed_generation_receipt(at(fork, 0)), Ok(None));
    assert_eq!(store.committed_generation_receipt(at(fork, 1)), Ok(None));
    let first = commit_default(&mut store, fork);
    let mut spec = Spec::new(fork);
    spec.prior = 1;
    spec.head = 4;
    spec.frontier_id = 2;
    let second = spec.command();
    assert!(matches!(
        store.commit_counterfactual_invalidation(&second),
        Ok(Outcome::Committed(_))
    ));
    drop(store);

    let reopened = open(&fixture.path);
    assert_eq!(
        reopened.committed_generation_receipt(at(fork, 1)),
        Ok(Some(first))
    );
    let recovered = ok(reopened.committed_generation_receipt(at(fork, 2)));
    assert_eq!(
        recovered,
        Some(ok(second.committed_receipt(&SEAL, Seq::from_u64(6))))
    );
    assert!(recovered.is_some_and(|receipt| receipt.matches_invalidation(second.invalidation())));
    // Nothing committed generation 0 or any generation after the committed
    // one, including generations SQLite cannot store.
    for absent in [0, 3, SQL_MAX, SQL_MAX + 1, u64::MAX] {
        assert_eq!(
            reopened.committed_generation_receipt(at(fork, absent)),
            Ok(None),
            "{absent}"
        );
    }
}

#[test]
fn corrupt_receipts_and_artifact_rows_are_rejected_closed() {
    for (table, trigger, assignment) in [
        (
            "counterfactual_generations",
            "counterfactual_generations_immutable",
            "first_tick_head = -1",
        ),
        (
            "counterfactual_generations",
            "counterfactual_generations_immutable",
            "plan_digest = X'00'",
        ),
        (
            "counterfactual_artifacts",
            "counterfactual_artifacts_immutable",
            "generation = -1",
        ),
    ] {
        let fixture = fixture();
        let fork = fixture.fork;
        let mut store = open(&fixture.path);
        let receipt = commit_default(&mut store, fork);
        drop(store);
        ok(execute(
            &fixture.path,
            &format!(
                "PRAGMA ignore_check_constraints = ON;
                 DROP TRIGGER {trigger};
                 UPDATE {table} SET {assignment};"
            ),
        ));
        let reopened = open(&fixture.path);
        let frontier = Spec::new(fork).command().frontier().as_bytes().to_vec();
        let (receipt_read, artifact_read) = if table == "counterfactual_artifacts" {
            (Ok(Some(receipt)), Err(StoreError::CorruptState))
        } else {
            (Err(StoreError::CorruptState), Ok(Some(frontier)))
        };
        assert_eq!(
            reopened.committed_generation_receipt(at(fork, 1)),
            receipt_read,
            "{assignment}"
        );
        assert_eq!(
            reopened.read_generation_artifact(at(fork, 1), receipt.frontier_digest()),
            artifact_read,
            "{assignment}"
        );
    }
}

#[test]
fn a_drifted_index_definition_is_rejected_on_open() {
    let fixture = fixture();
    let path_text = fixture.path.to_str().unwrap_or_default();
    for drifted in [
        "CREATE UNIQUE INDEX idx_counterfactual_quarantine_artifact
         ON counterfactual_quarantine(fork_id, artifact_digest)",
        "CREATE INDEX idx_counterfactual_quarantine_artifact
         ON counterfactual_quarantine(fork_id, artifact_digest) WHERE kind = 0",
    ] {
        ok(execute(
            &fixture.path,
            &format!("DROP INDEX idx_counterfactual_quarantine_artifact; {drifted};"),
        ));
        assert!(
            open_error(SqliteStore::open(path_text)).contains("idx_counterfactual_quarantine"),
            "{drifted}"
        );
        assert!(
            open_error(SqliteStore::open_read_only(path_text))
                .contains("idx_counterfactual_quarantine"),
            "{drifted}"
        );
    }
    ok(execute(
        &fixture.path,
        "DROP INDEX idx_counterfactual_quarantine_artifact;",
    ));
    assert_eq!(open_error(SqliteStore::open(path_text)), "");
}

/// Row counts of one Fork in the Fork, generation, quarantine, and artifact
/// tables, then the tombstone and purge-marker tables.
fn counterfactual_rows(path: &Path, fork: TimelineId) -> [i64; 6] {
    [
        "SELECT count(*) FROM counterfactual_forks WHERE fork_id = ?1",
        "SELECT count(*) FROM counterfactual_generations WHERE fork_id = ?1",
        "SELECT count(*) FROM counterfactual_quarantine WHERE fork_id = ?1",
        "SELECT count(*) FROM counterfactual_artifacts WHERE fork_id = ?1",
        "SELECT count(*) FROM counterfactual_fork_tombstones WHERE fork_id = ?1",
        "SELECT count(*) FROM counterfactual_purge_fence WHERE fork_id = ?1",
    ]
    .map(|sql| scalar(path, sql, fork))
}

/// A Fork holding one committed generation.
const LIVE_ROWS: [i64; 6] = [1, 1, 3, 2, 0, 0];
/// A purged Fork: only its tombstone remains.
const PURGED_ROWS: [i64; 6] = [0, 0, 0, 0, 1, 0];

fn tombstone_floor(path: &Path, fork: TimelineId) -> i64 {
    scalar(
        path,
        "SELECT generation_floor FROM counterfactual_fork_tombstones WHERE fork_id = ?1",
        fork,
    )
}

/// Commit the default command on a fresh Fork of the root at Seq 1.
fn published_other_fork(store: &mut SqliteStore, root: TimelineId) -> TimelineId {
    let other = ok(store.fork(root, Seq::from_u64(1), "other")).id();
    ok(store.publish_counterfactual_facts(other, facts()));
    let spec = Spec {
        head: 1,
        ..Spec::new(other)
    };
    assert!(matches!(
        ok(store.commit_counterfactual_invalidation(&spec.command())),
        Outcome::Committed(_)
    ));
    other
}

#[test]
fn deleting_a_fork_purges_its_rows_and_keeps_only_a_generation_floor() {
    let fixture = fixture();
    let (fork, root) = (fixture.fork, fixture.root);
    let mut store = open(&fixture.path);
    commit_default(&mut store, fork);
    let other = published_other_fork(&mut store, root);
    assert_eq!(counterfactual_rows(&fixture.path, fork), LIVE_ROWS);

    ok(store.delete_timeline(fork));
    assert_eq!(counterfactual_rows(&fixture.path, fork), PURGED_ROWS);
    assert_eq!(tombstone_floor(&fixture.path, fork), 1);
    assert_eq!(counterfactual_rows(&fixture.path, other), LIVE_ROWS);
    assert_eq!(store.current_fork_generation(other), Ok(at(other, 1)));
    // Nothing reads the deleted Fork or its tombstone.
    assert_eq!(
        store.current_fork_generation(fork),
        Err(StoreError::ForkNotFound)
    );
    assert_eq!(
        store.current_counterfactual_basis(fork),
        Err(StoreError::ForkNotFound)
    );
    assert_eq!(
        store.read_generation_artifact(at(fork, 1), hash(10)),
        Err(StoreError::ForkNotFound)
    );
    assert_eq!(
        store.committed_generation_receipt(at(fork, 1)),
        Err(StoreError::ForkNotFound)
    );
    assert_eq!(
        store.publish_counterfactual_facts(fork, facts()),
        Err(StoreError::ForkNotFound)
    );
}

#[test]
fn a_recreated_fork_id_resumes_at_the_floor_and_never_decreases() {
    let fixture = fixture();
    let (fork, root) = (fixture.fork, fixture.root);
    let mut store = open(&fixture.path);
    commit_default(&mut store, fork);
    ok(store.delete_timeline(fork));
    drop(store);

    let mut store = open(&fixture.path);
    let mut meta = TimelineMeta::forked_from(root, Seq::from_u64(2), "recreated");
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
    assert_eq!(generation(&store, fork), 1);
    assert_eq!(store.committed_generation_receipt(at(fork, 1)), Ok(None));
    assert_eq!(counterfactual_rows(&fixture.path, fork), [1, 0, 0, 0, 1, 0]);
    let second = Spec {
        prior: 1,
        ..Spec::new(fork)
    };
    assert!(matches!(
        ok(store.commit_counterfactual_invalidation(&second.command())),
        Outcome::Committed(_)
    ));
    assert_eq!(generation(&store, fork), 2);

    // The floor follows the last generation, so a second purge raises it.
    ok(store.delete_timeline(fork));
    assert_eq!(counterfactual_rows(&fixture.path, fork), PURGED_ROWS);
    assert_eq!(tombstone_floor(&fixture.path, fork), 2);
    ok(store.create_timeline_with_meta(meta));
    assert_eq!(
        store.publish_counterfactual_facts(fork, facts()),
        Ok(at(fork, 2))
    );
}

/// Direct deletes that no purge marker authorizes.
const UNMARKED_DELETES: [&str; 5] = [
    "DELETE FROM counterfactual_forks",
    "DELETE FROM counterfactual_quarantine",
    "DELETE FROM counterfactual_generations",
    "DELETE FROM counterfactual_artifacts",
    "DELETE FROM counterfactual_fork_tombstones",
];

#[test]
fn only_a_marked_purge_passes_the_delete_guards_and_the_floor_cannot_drop() {
    let fixture = fixture();
    let (fork, root) = (fixture.fork, fixture.root);
    let mut store = open(&fixture.path);
    let other = published_other_fork(&mut store, root);
    ok(store.delete_timeline(other));
    commit_default(&mut store, fork);
    drop(store);

    for delete in UNMARKED_DELETES {
        assert!(execute(&fixture.path, delete).is_err(), "{delete}");
        // A marker for another Fork authorizes nothing here.
        let marked = format!(
            "BEGIN;
             INSERT INTO counterfactual_purge_fence (fork_id) VALUES ('another');
             {delete};
             COMMIT;"
        );
        assert!(execute(&fixture.path, &marked).is_err(), "{marked}");
    }
    for lowering in [
        "UPDATE counterfactual_fork_tombstones SET generation_floor = 0",
        "UPDATE counterfactual_fork_tombstones SET fork_id = 'reassigned'",
        "INSERT OR REPLACE INTO counterfactual_fork_tombstones
         SELECT fork_id, 0 FROM counterfactual_fork_tombstones",
    ] {
        assert!(execute(&fixture.path, lowering).is_err(), "{lowering}");
    }
    assert_eq!(counterfactual_rows(&fixture.path, fork), LIVE_ROWS);
    assert_eq!(counterfactual_rows(&fixture.path, other), PURGED_ROWS);
    assert_eq!(tombstone_floor(&fixture.path, other), 1);
    ok(execute(
        &fixture.path,
        "UPDATE counterfactual_fork_tombstones SET generation_floor = generation_floor",
    ));
    // Raising the floor through `INSERT OR REPLACE` passes only because
    // `recursive_triggers` is off, so the replaced row fires no delete guard.
    ok(execute(
        &fixture.path,
        "INSERT OR REPLACE INTO counterfactual_fork_tombstones
         SELECT fork_id, 9 FROM counterfactual_fork_tombstones",
    ));
    assert_eq!(tombstone_floor(&fixture.path, other), 9);
    assert_eq!(
        open_error(SqliteStore::open(fixture_path_str(&fixture))),
        ""
    );
}

/// A purge marker authorizes deletes of its own Fork's rows only.
#[test]
fn a_purge_marker_authorizes_only_its_own_forks_rows() {
    let fixture = fixture();
    let (fork, root) = (fixture.fork, fixture.root);
    let mut store = open(&fixture.path);
    commit_default(&mut store, fork);
    let other = published_other_fork(&mut store, root);
    drop(store);
    let mark = format!("INSERT INTO counterfactual_purge_fence (fork_id) VALUES ('{fork}');");

    // The other Fork's quarantine rows are not authorized, so the whole
    // unqualified delete aborts and removes nothing.
    let unqualified = format!("BEGIN; {mark} DELETE FROM counterfactual_quarantine; COMMIT;");
    assert!(execute(&fixture.path, &unqualified).is_err());
    assert_eq!(counterfactual_rows(&fixture.path, fork), LIVE_ROWS);
    assert_eq!(counterfactual_rows(&fixture.path, other), LIVE_ROWS);

    let scoped = format!(
        "BEGIN; {mark}
         DELETE FROM counterfactual_quarantine WHERE fork_id = '{fork}';
         DELETE FROM counterfactual_purge_fence;
         COMMIT;"
    );
    ok(execute(&fixture.path, &scoped));
    assert_eq!(counterfactual_rows(&fixture.path, fork), [1, 1, 0, 2, 0, 0]);
    assert_eq!(counterfactual_rows(&fixture.path, other), LIVE_ROWS);
}

/// Faults that fail one statement of the delete transaction.
const DELETE_FAULTS: [&str; 8] = [
    "BEFORE INSERT ON counterfactual_purge_fence",
    "BEFORE DELETE ON counterfactual_artifacts",
    "BEFORE DELETE ON counterfactual_quarantine",
    "BEFORE DELETE ON counterfactual_generations",
    "BEFORE INSERT ON counterfactual_fork_tombstones",
    "BEFORE DELETE ON counterfactual_forks",
    "BEFORE DELETE ON counterfactual_purge_fence",
    "BEFORE DELETE ON timelines",
];

#[test]
fn a_failed_delete_leaves_every_row_and_no_purge_marker() {
    let fixture = fixture();
    let fork = fixture.fork;
    let mut store = open(&fixture.path);
    commit_default(&mut store, fork);
    drop(store);
    for fault in DELETE_FAULTS {
        ok(execute(
            &fixture.path,
            &format!(
                "CREATE TRIGGER injected_fault {fault}
                 BEGIN SELECT RAISE(ABORT, 'injected delete fault'); END;"
            ),
        ));
        let mut faulted = open(&fixture.path);
        assert!(faulted.delete_timeline(fork).is_err(), "{fault}");
        assert_eq!(faulted.current_fork_generation(fork), Ok(at(fork, 1)));
        assert_eq!(
            counterfactual_rows(&fixture.path, fork),
            LIVE_ROWS,
            "{fault}"
        );
        drop(faulted);
        ok(execute(&fixture.path, "DROP TRIGGER injected_fault;"));
        assert_eq!(
            open_error(SqliteStore::open(fixture_path_str(&fixture))),
            ""
        );
    }

    let mut recovered = open(&fixture.path);
    ok(recovered.delete_timeline(fork));
    assert_eq!(counterfactual_rows(&fixture.path, fork), PURGED_ROWS);
}

#[test]
fn a_surviving_purge_marker_fails_every_open_closed() {
    let fixture = fixture();
    ok(execute(
        &fixture.path,
        "INSERT INTO counterfactual_purge_fence (fork_id) VALUES ('stranded')",
    ));
    let text = fixture_path_str(&fixture);
    let writable = open_error(SqliteStore::open(text));
    let read_only = open_error(SqliteStore::open_read_only(text));
    assert!(writable.contains("purge marker"), "{writable}");
    assert!(read_only.contains("purge marker"), "{read_only}");
    ok(execute(
        &fixture.path,
        "DELETE FROM counterfactual_purge_fence",
    ));
    assert_eq!(open_error(SqliteStore::open(text)), "");
}

/// The delete guards as the previous build created them, without the
/// purge-marker condition: name, table, message.
const OLD_DELETE_GUARDS: [(&str, &str, &str); 4] = [
    (
        "counterfactual_forks_retained",
        "counterfactual_forks",
        "counterfactual generation is retained",
    ),
    (
        "counterfactual_quarantine_retained",
        "counterfactual_quarantine",
        "quarantined artifact cannot be reactivated",
    ),
    (
        "counterfactual_generations_retained",
        "counterfactual_generations",
        "counterfactual generation record is retained",
    ),
    (
        "counterfactual_artifacts_retained",
        "counterfactual_artifacts",
        "counterfactual artifact is retained",
    ),
];

#[test]
fn an_old_bodied_delete_guard_is_rejected_on_every_open() {
    for (name, table, message) in OLD_DELETE_GUARDS {
        let fixture = fixture();
        ok(execute(
            &fixture.path,
            &format!(
                "DROP TRIGGER {name};
                 CREATE TRIGGER {name} BEFORE DELETE ON {table}
                 BEGIN SELECT RAISE(ABORT, '{message}'); END;"
            ),
        ));
        let text = fixture_path_str(&fixture);
        assert!(open_error(SqliteStore::open(text)).contains(name), "{name}");
        assert!(
            open_error(SqliteStore::open_read_only(text)).contains(name),
            "{name}"
        );
    }
}

#[test]
fn a_drifted_purge_table_is_rejected_on_open() {
    for (table, drifted) in [
        (
            "counterfactual_fork_tombstones",
            "fork_id TEXT NOT NULL PRIMARY KEY, generation_floor TEXT NOT NULL",
        ),
        ("counterfactual_purge_fence", "fork_id TEXT NOT NULL"),
    ] {
        let fixture = fixture();
        ok(execute(
            &fixture.path,
            &format!("DROP TABLE {table}; CREATE TABLE {table} ({drifted});"),
        ));
        assert!(
            open_error(SqliteStore::open_read_only(fixture_path_str(&fixture))).contains(table),
            "{table}"
        );
    }
}
