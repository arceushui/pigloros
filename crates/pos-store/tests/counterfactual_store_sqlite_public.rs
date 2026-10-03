//! Public-interface tests for the ADR-064 `SQLite` counterfactual adapter.
#![cfg(feature = "sqlite")]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use pos_core::{
    CanonicalBytes, CounterfactualInvalidationCommandV1, CounterfactualInvalidationInputV1,
    CounterfactualInvalidationOutcomeV1, CounterfactualStoreErrorV1, CounterfactualStorePortV1,
    EntityId, ErasureContainmentGateV1, EventDraft, EventStore, ForkGenerationV1, Hash,
    InvalidationConflictV1, Kind, PipelineDraftBatchV1, RecomputationFrontierBytesV1, Seq,
    SuffixInvalidationBytesV1, TimelineId,
};
use pos_store::sqlite::{SqliteCounterfactualFactsV1, SqliteStore};
use tempfile::{tempdir, TempDir};
use ulid::Ulid;

type StoreError = CounterfactualStoreErrorV1;
type Outcome = CounterfactualInvalidationOutcomeV1;

const FRONTIER_DOMAIN: &[u8] = b"PiglorOS.RecomputationFrontier.v1";
const INVALIDATION_DOMAIN: &[u8] = b"PiglorOS.SuffixInvalidation.v1";
const FRONTIER_PREFIX: [u8; 6] = [0x64, b'R', b'C', b'F', b'1', 0x01];
const INVALIDATION_PREFIX: [u8; 6] = [0x64, b'S', b'I', b'V', b'1', 0x01];
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

const fn facts() -> SqliteCounterfactualFactsV1 {
    SqliteCounterfactualFactsV1 {
        plan_digest: hash(5),
        dependency_graph_digest: hash(3),
        trust_epoch: 6,
        revocation_epoch: 7,
        erasure_epoch: 8,
    }
}

fn draft(value: u8) -> EventDraft {
    EventDraft::new(
        EntityId::from_ulid(Ulid::from(9_u128)),
        Kind::new("counterfactual.tick"),
        CanonicalBytes::from_vec(vec![value]),
    )
}

/// Encode one shortest-form CBOR unsigned integer.
fn uint(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    match value {
        0..=23 => vec![bytes[7]],
        24..=0xff => vec![0x18, bytes[7]],
        0x100..=0xffff => [&[0x19][..], &bytes[6..]].concat(),
        0x1_0000..=0xffff_ffff => [&[0x1a][..], &bytes[4..]].concat(),
        _ => [&[0x1b][..], &bytes[..]].concat(),
    }
}

/// Encode one shortest-form CBOR head of `major` with `argument`.
fn head(major: u8, argument: u64) -> Vec<u8> {
    let mut encoded = uint(argument);
    encoded[0] |= major << 5;
    encoded
}

fn text_field(value: &str) -> Vec<u8> {
    [
        head(3, ok(u64::try_from(value.len()))),
        value.as_bytes().to_vec(),
    ]
    .concat()
}

/// Encode one six-field dependency-node coordinate.
fn node_field(tick: u64, owner: &str) -> Vec<u8> {
    [
        vec![0x86],
        uint(tick),
        uint(0),
        text_field(owner),
        uint(0),
        uint(7),
        hash_field(hash(21)),
    ]
    .concat()
}

/// Encode `SIV1` fields 8 through 14, as the `pos-core` port tests do.
fn invalidation_middle() -> Vec<u8> {
    [
        node_field(5, "agent-a"),
        node_field(4_294_967_296, "an-owner-identifier-of-thirty-"),
        vec![0x81, 0x86],
        text_field("event"),
        uint(70_000),
        hash_field(hash(22)),
        node_field(5, "agent-a"),
        uint(300),
        uint(0),
        vec![0x81],
        hash_field(hash(23)),
        vec![0x80, 0x80],
        uint(0),
    ]
    .concat()
}

fn id_field(value: [u8; 16]) -> Vec<u8> {
    [&[0x50][..], &value[..]].concat()
}

fn hash_field(value: Hash) -> Vec<u8> {
    [&[0x58, 0x20][..], &value.as_bytes()[..]].concat()
}

/// Frame fields after the version as one self-digested record.
fn frame(heads: (u8, u8), prefix: [u8; 6], domain: &[u8], fields: &[u8]) -> Vec<u8> {
    let mut bytes = vec![heads.0];
    bytes.extend_from_slice(&prefix);
    bytes.extend_from_slice(fields);
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0, heads.1]);
    hasher.update(&bytes[1..]);
    bytes.extend_from_slice(&[0x58, 0x20]);
    bytes.extend_from_slice(hasher.finalize().as_bytes());
    bytes
}

/// One invalidation request; every field defaults to the fixture's basis.
struct Spec {
    fork: TimelineId,
    facts: SqliteCounterfactualFactsV1,
    head: u64,
    prior: u64,
    frontier_id: u8,
    invalid_artifacts: Vec<Hash>,
    evictions: Vec<Hash>,
    first_tick: u64,
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
        ok(RecomputationFrontierBytesV1::try_from_canonical(frame(
            (0x91, 0x90),
            FRONTIER_PREFIX,
            FRONTIER_DOMAIN,
            &fields,
        )))
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
        ok(SuffixInvalidationBytesV1::try_from_canonical(frame(
            (0x92, 0x91),
            INVALIDATION_PREFIX,
            INVALIDATION_DOMAIN,
            &fields,
        )))
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
                first_tick_drafts: ok(PipelineDraftBatchV1::try_new(vec![draft(7), draft(8)])),
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

fn count(path: &Path, sql: &str, fork: TimelineId) -> i64 {
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
    .map(|sql| count(path, sql, fork))
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
        Ok(Outcome::Committed(ok(
            command.committed_receipt(Seq::from_u64(4))
        )))
    );
    assert_eq!(store.current_fork_generation(fork), Ok(at(fork, 1)));
    assert_eq!(ok(store.logical_head(fork)), Seq::from_u64(4));
    assert_eq!(ok(store.logical_head(fixture.root)), Seq::from_u64(2));
    assert_eq!(written_rows(&fixture.path, fork), [2, 1, 3, 2]);

    let stored = ok(
        rusqlite::Connection::open(&fixture.path).and_then(|connection| {
            connection.query_row(
                "SELECT frontier_digest, frontier_bytes, invalidation_digest, invalidation_bytes,
                    first_tick
             FROM counterfactual_generations WHERE fork_id = ?1 AND generation = 1",
                rusqlite::params![fork.to_string()],
                |row| <(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64)>::try_from(row),
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
    for quarantined in [hash(10), hash(11), hash(12)] {
        assert_eq!(
            reopened.read_generation_artifact(current, quarantined),
            Err(StoreError::InvalidArtifactReuse)
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
        Ok(Outcome::Committed(ok(
            second.committed_receipt(Seq::from_u64(6))
        )))
    );
    assert_eq!(generation(&store, fork), 2);
    let current = at(fork, 2);
    // Quarantine wins over stored bytes; the bytes stay for audit only.
    assert_eq!(
        store.read_generation_artifact(current, first.frontier().digest()),
        Err(StoreError::InvalidArtifactReuse)
    );
    assert_eq!(
        count(
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
    assert_eq!(
        store.read_generation_artifact(current, hash(10)),
        Err(StoreError::InvalidArtifactReuse)
    );

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
    let cases: [(fn(&mut Spec), InvalidationConflictV1); 7] = [
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
        Ok(Outcome::Committed(ok(
            command.committed_receipt(Seq::from_u64(4))
        )))
    );
    drop(recovered);
    let reopened = open(&fixture.path);
    assert_eq!(generation(&reopened, fork), 1);
    assert_eq!(
        reopened.read_generation_artifact(at(fork, 1), hash(11)),
        Err(StoreError::InvalidArtifactReuse)
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
    assert_eq!(
        reopened.read_generation_artifact(at(fork, 1), hash(10)),
        Err(StoreError::InvalidArtifactReuse)
    );
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
    let setters: [(
        fn(&mut SqliteCounterfactualFactsV1, u64),
        InvalidationConflictV1,
    ); 3] = [
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
        count(
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
         DROP TABLE counterfactual_artifacts;",
    ));
    assert!(open_read_only().contains("counterfactual_forks table"));
    assert_eq!(open_writable(), "");
    assert_eq!(open_read_only(), "");
    let mut migrated = open(&fixture.path);
    assert_eq!(ok(migrated.logical_head(fork)), Seq::from_u64(2));
    assert_eq!(
        migrated.current_fork_generation(fork),
        Err(StoreError::ForkNotFound)
    );
    assert_eq!(
        migrated.publish_counterfactual_facts(fork, facts()),
        Ok(at(fork, 0))
    );
    drop(migrated);

    for (kind, name, weakened) in [
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
    ] {
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
