//! `SQLite` adapter and additive schema for the ADR-064 counterfactual
//! storage port.
//!
//! [`CounterfactualStorePortV1::commit_counterfactual_invalidation`] runs in
//! one `BEGIN IMMEDIATE` transaction: it reads the persisted
//! [`CounterfactualBasisV1`], and either reports the first conflict or appends
//! the first recomputation Tick's Events to the Fork Timeline, builds the
//! receipt from the staged head, records the receipt and the exact
//! `RCF1`/`SIV1` bytes under the new generation, quarantines the
//! invalid-artifact index and the eviction set, and advances the Fork
//! generation.
//! [`CounterfactualStorePortV1::append_counterfactual_tick`] runs the same
//! recheck and appends one later Tick in its own `BEGIN IMMEDIATE`
//! transaction. Any failure or rejection rolls the whole transaction back.
//!
//! # Schema
//!
//! Four additive tables (`counterfactual_forks`, `counterfactual_generations`,
//! `counterfactual_quarantine`, `counterfactual_artifacts`), three dependency
//! record tables (`counterfactual_dependency_records`,
//! `counterfactual_dependency_nodes`, `counterfactual_dependency_edges`, see
//! the `dependency` module), two purge tables
//! (`counterfactual_fork_tombstones`, `counterfactual_purge_fence`), one
//! lookup index, and twenty-four guard triggers (fifteen on the storage and
//! purge tables, nine on the dependency tables) are created with
//! `IF NOT EXISTS` by every writable open, so creation is additive and
//! idempotent. This is the one normative first version of the schema: a file
//! written by an earlier build, whose delete guards lack the purge-marker
//! condition, fails the exact validation below with a storage error and must
//! be recreated. A writable open of such a file still creates the tables,
//! index, and triggers it lacks before validation fails, so a rejected file
//! may gain those additive objects; its old delete guards stay and every later
//! open still fails. A file with the exact storage schema that only lacks the
//! dependency tables gains them empty on a writable open (there is nothing to
//! migrate, and no migration exists), and a read-only open of it fails the
//! validation with a missing-table error.
//! Every open validates the exact table shapes, the index, and the trigger
//! bodies, and fails closed with a storage error on any drift. A read-only
//! open of a file written before this schema, which has no counterfactual
//! table, index, or trigger at all, accepts the file as holding no
//! counterfactual state: every port read reports `ForkNotFound`. Any
//! counterfactual object that is present must still be complete and exact.
//! The triggers make the database itself refuse to decrease a Fork
//! generation, and, outside a purge, to delete a Fork row, a quarantine row,
//! a recorded generation, an artifact, or a dependency record, node, or edge
//! (see the Timeline deletion decision below). They also refuse to rewrite a
//! quarantine row, a recorded generation, an artifact, or a dependency row.
//! The four tables with a stored history (Forks, quarantine, generations,
//! artifacts) and the three dependency tables each refuse an insert whose
//! primary key already exists, before conflict resolution, so
//! `INSERT OR REPLACE`, `REPLACE INTO`, and an upsert cannot delete and
//! rewrite a row past the delete and update guards. The tombstone table
//! instead refuses an insert that would lower an existing floor, and the
//! purge-fence table has no guard. A rolled-back coordinator version
//! therefore cannot reactivate an invalidated artifact, and the prior `RCF1`,
//! `SIV1`, and artifact bytes stay immutable for audit.
//!
//! # ADR gap decisions
//!
//! These mirror the `MemoryStore` adapter so the coordinator treats both
//! backends identically.
//!
//! - **Host-published facts.** ADR-064 names the facts rechecked at commit
//!   but no store for them. The Fork Logical Head is read live from the Event
//!   Store (inherited prefix plus the Fork's own Events). The admitted plan
//!   digest, the dependency-graph digest, and the trust, revocation, and
//!   erasure epochs are published per Fork by the host with
//!   [`CounterfactualStorePortV1::publish_counterfactual_facts`]; the first
//!   publication inserts the Fork's row at generation `0`, and a
//!   republication updates only the facts, never the generation or the stored
//!   artifacts.
//! - **Readable artifacts.** The committed `RCF1` and `SIV1` bytes become
//!   readable by their self-digests at the new generation. Every writing
//!   generation records its own `counterfactual_artifacts` row, so the
//!   latest generation that wrote a digest is its highest row. Staging later
//!   recomputed outputs is owned by the coordinator slices, not this adapter.
//! - **Quarantine by generation.** The invalid-artifact index (kind `0`) and
//!   the cache/checkpoint eviction set (kind `1`) are both stored exactly,
//!   keyed by the generation that committed them. A digest is quarantined
//!   through its highest such generation minus one, the
//!   [`CounterfactualInvalidationCommandV1::quarantines_through`] of that
//!   invalidation, and every read resolves the stored state with
//!   [`ForkGenerationV1::resolve_read`]: quarantined bytes written at or
//!   before that generation stay retained for audit only, while the same
//!   bytes written again by a later generation are readable there. A
//!   quarantined digest this store holds no bytes for reads as absent.
//! - **Recovery read.** The invalidation records its receipt's
//!   [`CounterfactualGenerationRecordV1`] in the same transaction, in its
//!   `counterfactual_generations` row: the first Tick's head and the facts
//!   are copied from the persisted Fork row the basis was rechecked against,
//!   which equal the receipt's. The
//!   [`CounterfactualStorePortV1::committed_generation_receipt`] read
//!   rebuilds the receipt from that row; a generation above `i64::MAX`
//!   cannot have committed and reads as `None`. On a deleted or unpublished
//!   Fork it returns `ForkNotFound`, never `Ok(None)`, even when the deleted
//!   Fork committed that generation, so a recovering caller cannot mistake a
//!   deleted Fork for "nothing committed", matching the `MemoryStore` adapter.
//! - **Outcome unknown.** A write whose commit or rollback failed is
//!   `CoreError::StorageOutcomeUnknown`, reported through the crate's shared
//!   `counterfactual_port_error` as `OutcomeUnknown`; a rejection never hides
//!   it. When that write leaves the connection still inside a transaction
//!   (one the failed write may have left open, or the host's outer
//!   transaction holding the write's unreleased savepoint), it marks the
//!   store's connection in doubt, and while the mark is set and the
//!   connection is still inside a transaction every port read is refused
//!   with `StorageFailure`, so a recovery read never answers from unsettled
//!   state. The mark is cleared once the connection is seen in autocommit
//!   again, by the next port read or by the host beginning a new
//!   protected-effect interval; the recovery read then answers from settled
//!   state. An unknown outcome reported with the connection already back in
//!   autocommit left nothing open and never sets the mark, so a host that
//!   later opens a transaction by any means is answered normally.
//! - **Reads inside a host transaction.** Outside that in-doubt state, a
//!   port read on a connection already inside a transaction (the host's
//!   protected-effect interval runs `BEGIN IMMEDIATE` on this connection)
//!   runs inside a savepoint of that transaction, exactly as the writes do,
//!   so it sees the interval's own earlier, not yet committed writes at one
//!   read point.
//! - **Epoch monotonicity.** The store does not require a republished trust,
//!   revocation, or erasure epoch to be at least the previously published
//!   one; keeping the published epochs monotonic is a host obligation.
//! - **Recheck order.** The basis is rechecked before any Tick is appended,
//!   so a stale invalidation or later Tick reports its conflict even when its
//!   drafts could not be appended, matching the `MemoryStore` adapter.
//! - **Tick admission.** The first and every later recomputation Tick apply
//!   the generic append guard `ensure_non_geographic_drafts` before any
//!   write; a rejected draft is concealed as `ForkNotFound` and commits
//!   nothing.
//! - **Containment.** The invalidation commit and later Tick appends add
//!   Events, so they run under the ADR-060 erasure write fence and, like every
//!   generic Fork append, are rejected on an ADR-099 admitted Fork whose
//!   appends are reserved for the classified append authority. The
//!   generation, basis, and artifact reads are derived from the Fork
//!   Timeline, so they run under the ADR-060 erasure read fence like every
//!   other `SQLite` Timeline read, and fail closed without a bound erasure
//!   gate. Publishing facts writes host-owned facts only, touches no Timeline
//!   Event or derived artifact, and is not fenced.
//! - **Concurrency.** Every port read runs its statements (Fork visibility,
//!   the counterfactual rows, and the live Fork head) inside one deferred
//!   read transaction, or one savepoint of an enclosing transaction, so they
//!   observe one consistent read point even when another connection commits
//!   to the same file. A read transaction whose `COMMIT` fails is rolled back
//!   so the connection is never left inside it. Every write runs in its
//!   `BEGIN IMMEDIATE` transaction and first compares `PRAGMA data_version`
//!   with the bound erasure inventory, because another connection may have
//!   changed the file; the single-handle `MemoryStore` has no equivalent
//!   check.
//! - **Timeline deletion.** The generic `delete_timeline` purges the deleted
//!   Fork's counterfactual rows in its own transaction, after its other
//!   per-Timeline cleanup and before the Timeline row goes. The purge first
//!   inserts a marker row for that Fork into `counterfactual_purge_fence`,
//!   deletes the Timeline's dependency edge, node, and record rows (a Fork's
//!   generations' and a parent Timeline's committed prefix), the Fork's
//!   artifact, quarantine, generation, and Fork rows,
//!   upserts one `counterfactual_fork_tombstones` row holding only the
//!   Fork's last generation, and deletes the marker. Only the seven delete
//!   guards honor a marker, and only for the marked Timeline, so any other
//!   delete still aborts. The marker is an accident guard for the generic delete
//!   path, not an authorization boundary: a client with write access to the
//!   database file can already drop the triggers, and the marker table has no
//!   guard of its own. The tombstone is a generation floor: its own guards
//!   refuse a delete and any change that lowers it, while raising it (an
//!   update or a replacing insert) is allowed; the replacing insert passes
//!   only because `recursive_triggers` is off, so the replaced row fires no
//!   delete guard. No port read touches the tombstone, so every read of a
//!   deleted Fork stays `ForkNotFound`, matching the `MemoryStore` adapter.
//!   A Timeline later created with the same ID (an identity-preserving
//!   import) is seeded at the floor when its facts are published, so its
//!   generation never decreases. A marker only exists inside the purge
//!   transaction, so a rollback or crash leaves none, and an open that finds
//!   one fails closed. Files created by an earlier build
//!   before this schema version must be recreated: their old delete guards
//!   fail the exact validation. **ADR-060 clarification:** the
//!   counterfactual rows are derived state of the Fork Timeline, not erasure
//!   evidence, so purging them in the generic `delete_timeline` is
//!   derived-state cleanup. It clears no erasure evidence, fence, or
//!   inventory, and the purge touches none of them. The tombstone stores
//!   only the Fork id and a generation number; if ADR-060 or ADR-064 ever
//!   treat Fork ids as erasable, the tombstone table needs its own erasure
//!   path.
//! - **Errors.** A missing, deleted, non-Fork, unpublished, or protected
//!   Timeline, and a Tick draft the generic append guard rejects, is
//!   `ForkNotFound`; a staged head that did not advance is `CorruptState`;
//!   every other backend failure, including a containment denial, is
//!   `StorageFailure`. Every rejection, including one decided after a write,
//!   rolls the transaction back, so it commits nothing.
//! - **Dependency record.** The `_with_dependencies` write methods and the
//!   dependency read methods of the ADR-064 record contract run through the
//!   same transaction, in-doubt, fence, and read-scope helpers; the `dependency`
//!   module documents their tables and decisions.
//! - **`SQLite`-only differences.** `SQLite` stores signed 64-bit integers:
//!   a generation, epoch, or Tick above `i64::MAX` is `FieldOutOfBounds`
//!   before any transaction, and a persisted value outside its range is
//!   `CorruptState`. The read-only handling of a pre-schema file above has
//!   no in-memory counterpart.

use pos_core::{
    CoreError, CounterfactualBasisV1, CounterfactualFactsV1, CounterfactualGenerationReceiptV1,
    CounterfactualGenerationRecordV1, CounterfactualInvalidationCommandV1,
    CounterfactualInvalidationOutcomeV1, CounterfactualStoreErrorV1, CounterfactualStorePortV1,
    CounterfactualTickOutcomeV1, ErasureProtectedOperationV1, ForkGenerationV1, Hash,
    PipelineDraftBatchV1, Seq, StoredCounterfactualArtifactV1, TimelineId,
};
use rusqlite::{params, Connection, OptionalExtension};

use super::{
    begin_immediate_scope, finish_immediate_scope, normalize_schema_sql, seq_as_i64,
    sqlite_schema_ddl, SqliteSchemaColumn, SqliteSchemaTable, SqliteStore,
};
use crate::{counterfactual_port_error, COUNTERFACTUAL_SEAL};

mod dependency;

type StoreError = CounterfactualStoreErrorV1;

/// A storage step whose inner result carries a closed port rejection.
type Staged<T> = Result<Result<T, StoreError>, CoreError>;

/// Quarantine kind of an invalid-artifact index member.
const INVALID_ARTIFACT_KIND: i64 = 0;
/// Quarantine kind of a cache/checkpoint eviction set member.
const EVICTION_KIND: i64 = 1;

/// Additive tables owned by the counterfactual adapter.
const COUNTERFACTUAL_SCHEMA_TABLES: &[SqliteSchemaTable] = &[
    SqliteSchemaTable {
        name: "counterfactual_forks",
        columns_query: "PRAGMA table_info(counterfactual_forks)",
        columns: &[
            SqliteSchemaColumn {
                name: "fork_id",
                kind: "TEXT",
                not_null: true,
                primary_key: true,
            },
            SqliteSchemaColumn {
                name: "generation",
                kind: "INTEGER",
                not_null: true,
                primary_key: false,
            },
            SqliteSchemaColumn {
                name: "plan_digest",
                kind: "BLOB",
                not_null: true,
                primary_key: false,
            },
            SqliteSchemaColumn {
                name: "dependency_graph_digest",
                kind: "BLOB",
                not_null: true,
                primary_key: false,
            },
            SqliteSchemaColumn {
                name: "trust_epoch",
                kind: "INTEGER",
                not_null: true,
                primary_key: false,
            },
            SqliteSchemaColumn {
                name: "revocation_epoch",
                kind: "INTEGER",
                not_null: true,
                primary_key: false,
            },
            SqliteSchemaColumn {
                name: "erasure_epoch",
                kind: "INTEGER",
                not_null: true,
                primary_key: false,
            },
        ],
        constraints: &[
            "CHECK (generation >= 0)",
            "CHECK (length(plan_digest) = 32)",
            "CHECK (length(dependency_graph_digest) = 32)",
            "CHECK (trust_epoch >= 0)",
            "CHECK (revocation_epoch >= 0)",
            "CHECK (erasure_epoch >= 0)",
        ],
    },
    SqliteSchemaTable {
        name: "counterfactual_generations",
        columns_query: "PRAGMA table_info(counterfactual_generations)",
        columns: &[
            SqliteSchemaColumn {
                name: "fork_id",
                kind: "TEXT",
                not_null: true,
                primary_key: true,
            },
            SqliteSchemaColumn {
                name: "generation",
                kind: "INTEGER",
                not_null: true,
                primary_key: true,
            },
            SqliteSchemaColumn {
                name: "frontier_digest",
                kind: "BLOB",
                not_null: true,
                primary_key: false,
            },
            SqliteSchemaColumn {
                name: "frontier_bytes",
                kind: "BLOB",
                not_null: true,
                primary_key: false,
            },
            SqliteSchemaColumn {
                name: "invalidation_digest",
                kind: "BLOB",
                not_null: true,
                primary_key: false,
            },
            SqliteSchemaColumn {
                name: "invalidation_bytes",
                kind: "BLOB",
                not_null: true,
                primary_key: false,
            },
            SqliteSchemaColumn {
                name: "first_tick",
                kind: "INTEGER",
                not_null: true,
                primary_key: false,
            },
            SqliteSchemaColumn {
                name: "first_tick_head",
                kind: "INTEGER",
                not_null: true,
                primary_key: false,
            },
            SqliteSchemaColumn {
                name: "plan_digest",
                kind: "BLOB",
                not_null: true,
                primary_key: false,
            },
            SqliteSchemaColumn {
                name: "dependency_graph_digest",
                kind: "BLOB",
                not_null: true,
                primary_key: false,
            },
            SqliteSchemaColumn {
                name: "trust_epoch",
                kind: "INTEGER",
                not_null: true,
                primary_key: false,
            },
            SqliteSchemaColumn {
                name: "revocation_epoch",
                kind: "INTEGER",
                not_null: true,
                primary_key: false,
            },
            SqliteSchemaColumn {
                name: "erasure_epoch",
                kind: "INTEGER",
                not_null: true,
                primary_key: false,
            },
        ],
        constraints: &[
            "CHECK (generation >= 1)",
            "CHECK (length(frontier_digest) = 32)",
            "CHECK (length(invalidation_digest) = 32)",
            "CHECK (first_tick >= 0)",
            "CHECK (first_tick_head >= 1)",
            "CHECK (length(plan_digest) = 32)",
            "CHECK (length(dependency_graph_digest) = 32)",
            "CHECK (trust_epoch >= 0)",
            "CHECK (revocation_epoch >= 0)",
            "CHECK (erasure_epoch >= 0)",
        ],
    },
    SqliteSchemaTable {
        name: "counterfactual_quarantine",
        columns_query: "PRAGMA table_info(counterfactual_quarantine)",
        columns: &[
            SqliteSchemaColumn {
                name: "fork_id",
                kind: "TEXT",
                not_null: true,
                primary_key: true,
            },
            SqliteSchemaColumn {
                name: "generation",
                kind: "INTEGER",
                not_null: true,
                primary_key: true,
            },
            SqliteSchemaColumn {
                name: "kind",
                kind: "INTEGER",
                not_null: true,
                primary_key: true,
            },
            SqliteSchemaColumn {
                name: "artifact_digest",
                kind: "BLOB",
                not_null: true,
                primary_key: true,
            },
        ],
        constraints: &[
            "CHECK (generation >= 1)",
            "CHECK (kind IN (0, 1))",
            "CHECK (length(artifact_digest) = 32)",
        ],
    },
    SqliteSchemaTable {
        name: "counterfactual_artifacts",
        columns_query: "PRAGMA table_info(counterfactual_artifacts)",
        columns: &[
            SqliteSchemaColumn {
                name: "fork_id",
                kind: "TEXT",
                not_null: true,
                primary_key: true,
            },
            SqliteSchemaColumn {
                name: "artifact_digest",
                kind: "BLOB",
                not_null: true,
                primary_key: true,
            },
            SqliteSchemaColumn {
                name: "generation",
                kind: "INTEGER",
                not_null: true,
                primary_key: true,
            },
            SqliteSchemaColumn {
                name: "artifact_bytes",
                kind: "BLOB",
                not_null: true,
                primary_key: false,
            },
        ],
        constraints: &[
            "CHECK (length(artifact_digest) = 32)",
            "CHECK (generation >= 1)",
        ],
    },
    SqliteSchemaTable {
        name: "counterfactual_fork_tombstones",
        columns_query: "PRAGMA table_info(counterfactual_fork_tombstones)",
        columns: &[
            SqliteSchemaColumn {
                name: "fork_id",
                kind: "TEXT",
                not_null: true,
                primary_key: true,
            },
            SqliteSchemaColumn {
                name: "generation_floor",
                kind: "INTEGER",
                not_null: true,
                primary_key: false,
            },
        ],
        constraints: &["CHECK (generation_floor >= 0)"],
    },
    SqliteSchemaTable {
        name: "counterfactual_purge_fence",
        columns_query: "PRAGMA table_info(counterfactual_purge_fence)",
        columns: &[SqliteSchemaColumn {
            name: "fork_id",
            kind: "TEXT",
            not_null: true,
            primary_key: true,
        }],
        constraints: &[],
    },
    dependency::RECORDS_TABLE,
    dependency::NODES_TABLE,
    dependency::EDGES_TABLE,
];

/// One named index or trigger and the exact body every open requires after
/// `CREATE <kind> <name>`.
struct CounterfactualSchemaObjectV1 {
    kind: &'static str,
    name: &'static str,
    body: &'static str,
}

// The `WHEN NOT EXISTS (... counterfactual_purge_fence ...)` clause is
// repeated in four trigger bodies on purpose: the exact-body validation
// compares literal text, so the four copies must stay identical.
/// The quarantine lookup index and the guards that keep generations
/// monotonic, quarantine permanent, and recorded bytes immutable.
const COUNTERFACTUAL_SCHEMA_OBJECTS: &[CounterfactualSchemaObjectV1] = &[
    CounterfactualSchemaObjectV1 {
        kind: "index",
        name: "idx_counterfactual_quarantine_artifact",
        body: "ON counterfactual_quarantine(fork_id, artifact_digest)",
    },
    CounterfactualSchemaObjectV1 {
        kind: "trigger",
        name: "counterfactual_forks_generation_monotonic",
        body: "BEFORE UPDATE ON counterfactual_forks
               WHEN NEW.generation < OLD.generation OR NEW.fork_id IS NOT OLD.fork_id
               BEGIN SELECT RAISE(ABORT, 'counterfactual generation cannot decrease'); END",
    },
    CounterfactualSchemaObjectV1 {
        kind: "trigger",
        name: "counterfactual_forks_retained",
        body: "BEFORE DELETE ON counterfactual_forks
               WHEN NOT EXISTS (
                   SELECT 1 FROM counterfactual_purge_fence WHERE fork_id = OLD.fork_id
               )
               BEGIN SELECT RAISE(ABORT, 'counterfactual generation is retained'); END",
    },
    CounterfactualSchemaObjectV1 {
        kind: "trigger",
        name: "counterfactual_quarantine_retained",
        body: "BEFORE DELETE ON counterfactual_quarantine
               WHEN NOT EXISTS (
                   SELECT 1 FROM counterfactual_purge_fence WHERE fork_id = OLD.fork_id
               )
               BEGIN SELECT RAISE(ABORT, 'quarantined artifact cannot be reactivated'); END",
    },
    CounterfactualSchemaObjectV1 {
        kind: "trigger",
        name: "counterfactual_quarantine_immutable",
        body: "BEFORE UPDATE ON counterfactual_quarantine
               BEGIN SELECT RAISE(ABORT, 'quarantined artifact cannot be reactivated'); END",
    },
    CounterfactualSchemaObjectV1 {
        kind: "trigger",
        name: "counterfactual_generations_retained",
        body: "BEFORE DELETE ON counterfactual_generations
               WHEN NOT EXISTS (
                   SELECT 1 FROM counterfactual_purge_fence WHERE fork_id = OLD.fork_id
               )
               BEGIN SELECT RAISE(ABORT, 'counterfactual generation record is retained'); END",
    },
    CounterfactualSchemaObjectV1 {
        kind: "trigger",
        name: "counterfactual_generations_immutable",
        body: "BEFORE UPDATE ON counterfactual_generations
               BEGIN SELECT RAISE(ABORT, 'counterfactual generation record is immutable'); END",
    },
    CounterfactualSchemaObjectV1 {
        kind: "trigger",
        name: "counterfactual_artifacts_retained",
        body: "BEFORE DELETE ON counterfactual_artifacts
               WHEN NOT EXISTS (
                   SELECT 1 FROM counterfactual_purge_fence WHERE fork_id = OLD.fork_id
               )
               BEGIN SELECT RAISE(ABORT, 'counterfactual artifact is retained'); END",
    },
    CounterfactualSchemaObjectV1 {
        kind: "trigger",
        name: "counterfactual_artifacts_immutable",
        body: "BEFORE UPDATE ON counterfactual_artifacts
               BEGIN SELECT RAISE(ABORT, 'counterfactual artifact is immutable'); END",
    },
    CounterfactualSchemaObjectV1 {
        kind: "trigger",
        name: "counterfactual_forks_not_replaced",
        body: "BEFORE INSERT ON counterfactual_forks
               WHEN EXISTS (SELECT 1 FROM counterfactual_forks WHERE fork_id = NEW.fork_id)
               BEGIN SELECT RAISE(ABORT, 'counterfactual generation is retained'); END",
    },
    CounterfactualSchemaObjectV1 {
        kind: "trigger",
        name: "counterfactual_quarantine_not_replaced",
        body: "BEFORE INSERT ON counterfactual_quarantine
               WHEN EXISTS (
                   SELECT 1 FROM counterfactual_quarantine
                   WHERE fork_id = NEW.fork_id AND generation = NEW.generation
                     AND kind = NEW.kind AND artifact_digest = NEW.artifact_digest
               )
               BEGIN SELECT RAISE(ABORT, 'quarantined artifact cannot be reactivated'); END",
    },
    CounterfactualSchemaObjectV1 {
        kind: "trigger",
        name: "counterfactual_generations_not_replaced",
        body: "BEFORE INSERT ON counterfactual_generations
               WHEN EXISTS (
                   SELECT 1 FROM counterfactual_generations
                   WHERE fork_id = NEW.fork_id AND generation = NEW.generation
               )
               BEGIN SELECT RAISE(ABORT, 'counterfactual generation record is immutable'); END",
    },
    CounterfactualSchemaObjectV1 {
        kind: "trigger",
        name: "counterfactual_artifacts_not_replaced",
        body: "BEFORE INSERT ON counterfactual_artifacts
               WHEN EXISTS (
                   SELECT 1 FROM counterfactual_artifacts
                   WHERE fork_id = NEW.fork_id AND artifact_digest = NEW.artifact_digest
                     AND generation = NEW.generation
               )
               BEGIN SELECT RAISE(ABORT, 'counterfactual artifact is immutable'); END",
    },
    CounterfactualSchemaObjectV1 {
        kind: "trigger",
        name: "counterfactual_fork_tombstones_retained",
        body: "BEFORE DELETE ON counterfactual_fork_tombstones
               BEGIN SELECT RAISE(ABORT, 'counterfactual generation floor is retained'); END",
    },
    CounterfactualSchemaObjectV1 {
        kind: "trigger",
        name: "counterfactual_fork_tombstones_floor_monotonic",
        body: "BEFORE UPDATE ON counterfactual_fork_tombstones
               WHEN NEW.generation_floor < OLD.generation_floor
                 OR NEW.fork_id IS NOT OLD.fork_id
               BEGIN SELECT RAISE(ABORT, 'counterfactual generation floor cannot decrease'); END",
    },
    CounterfactualSchemaObjectV1 {
        kind: "trigger",
        name: "counterfactual_fork_tombstones_floor_kept",
        body: "BEFORE INSERT ON counterfactual_fork_tombstones
               WHEN EXISTS (
                   SELECT 1 FROM counterfactual_fork_tombstones
                   WHERE fork_id = NEW.fork_id AND generation_floor > NEW.generation_floor
               )
               BEGIN SELECT RAISE(ABORT, 'counterfactual generation floor cannot decrease'); END",
    },
    dependency::RECORDS_RETAINED,
    dependency::RECORDS_IMMUTABLE,
    dependency::RECORDS_MONOTONIC,
    dependency::NODES_RETAINED,
    dependency::NODES_IMMUTABLE,
    dependency::NODES_NOT_REPLACED,
    dependency::EDGES_RETAINED,
    dependency::EDGES_IMMUTABLE,
    dependency::EDGES_NOT_REPLACED,
];

/// Statements that purge one Fork's counterfactual state, each bound to the
/// Fork id as `?1`. The marker row relaxes the delete guards for that Fork
/// only; the tombstone keeps the Fork's last generation as a floor; the marker
/// is removed before the enclosing transaction commits. The dependency
/// tables are keyed by the Timeline ID, which is the Fork's own for its
/// generations' rows and a parent Timeline's for its committed prefix.
const PURGE_COUNTERFACTUAL_STATEMENTS: [&str; 10] = [
    "INSERT INTO counterfactual_purge_fence (fork_id) VALUES (?1)",
    "DELETE FROM counterfactual_dependency_edges WHERE timeline_id = ?1",
    "DELETE FROM counterfactual_dependency_nodes WHERE timeline_id = ?1",
    "DELETE FROM counterfactual_dependency_records WHERE timeline_id = ?1",
    "DELETE FROM counterfactual_artifacts WHERE fork_id = ?1",
    "DELETE FROM counterfactual_quarantine WHERE fork_id = ?1",
    "DELETE FROM counterfactual_generations WHERE fork_id = ?1",
    "INSERT INTO counterfactual_fork_tombstones (fork_id, generation_floor)
     SELECT fork_id, generation FROM counterfactual_forks WHERE fork_id = ?1
     ON CONFLICT (fork_id) DO UPDATE SET generation_floor = excluded.generation_floor",
    "DELETE FROM counterfactual_forks WHERE fork_id = ?1",
    "DELETE FROM counterfactual_purge_fence WHERE fork_id = ?1",
];

/// The normalized statement `sqlite_master` keeps for `object`: without
/// `IF NOT EXISTS`.
fn expected_schema_sql(object: &CounterfactualSchemaObjectV1) -> String {
    normalize_schema_sql(&format!(
        "CREATE {} {} {}",
        object.kind, object.name, object.body
    ))
}

/// Whether the stored statement of an object equals the one `object` expects.
fn stored_matches(sql: Option<String>, object: &CounterfactualSchemaObjectV1) -> bool {
    sql.is_some_and(|sql| normalize_schema_sql(&sql) == expected_schema_sql(object))
}

/// Whether any counterfactual table, or any index or trigger on one, exists.
const COUNTERFACTUAL_SCHEMA_PRESENT_SQL: &str = "SELECT EXISTS (
     SELECT 1 FROM sqlite_master WHERE tbl_name LIKE 'counterfactual!_%' ESCAPE '!'
 )";

/// Decoded `counterfactual_forks` row.
#[derive(Clone, Copy)]
struct ForkStateV1 {
    generation: u64,
    facts: CounterfactualFactsV1,
}

impl ForkStateV1 {
    /// The persisted basis at the Fork's live Logical Head.
    const fn basis(self, fork_logical_head: Seq) -> CounterfactualBasisV1 {
        CounterfactualBasisV1 {
            fork_logical_head,
            generation: self.generation,
            facts: self.facts,
        }
    }
}

/// Raw `counterfactual_forks` columns before range validation.
type ForkStateRowV1 = (i64, Vec<u8>, Vec<u8>, i64, i64, i64);

/// Raw current generation, quarantined-through generation, and the latest
/// writing generation and bytes of one artifact lookup.
type StoredArtifactRowV1 = (i64, Option<i64>, Option<i64>, Option<Vec<u8>>);

/// Raw receipt columns of one `counterfactual_generations` row: frontier
/// digest, invalidation digest, first Tick, first Tick head, plan digest,
/// dependency-graph digest, and the trust, revocation, and erasure epochs.
type GenerationRecordRowV1 = (Vec<u8>, Vec<u8>, i64, i64, Vec<u8>, Vec<u8>, i64, i64, i64);

fn decode_fork_state(row: ForkStateRowV1) -> Result<ForkStateV1, StoreError> {
    let (generation, plan_digest, dependency_graph_digest, trust, revocation, erasure) = row;
    Ok(ForkStateV1 {
        generation: stored_u64(generation)?,
        facts: CounterfactualFactsV1 {
            plan_digest: stored_hash(plan_digest)?,
            dependency_graph_digest: stored_hash(dependency_graph_digest)?,
            trust_epoch: stored_u64(trust)?,
            revocation_epoch: stored_u64(revocation)?,
            erasure_epoch: stored_u64(erasure)?,
        },
    })
}

/// A persisted integer outside `u64` is corrupt state, never a clamp.
fn stored_u64(value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).or(Err(StoreError::CorruptState))
}

fn stored_hash(bytes: Vec<u8>) -> Result<Hash, StoreError> {
    <[u8; 32]>::try_from(bytes)
        .map(Hash::from_bytes)
        .or(Err(StoreError::CorruptState))
}

/// `SQLite` stores signed 64-bit integers; a larger value cannot be stored.
fn sql_integer(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).or(Err(StoreError::FieldOutOfBounds))
}

/// Decode one artifact lookup into the current generation and the stored
/// state [`ForkGenerationV1::resolve_read`] resolves.
fn decode_artifact_state(
    row: StoredArtifactRowV1,
) -> Result<(u64, StoredCounterfactualArtifactV1), StoreError> {
    let (generation, quarantined_through, written_generation, bytes) = row;
    let stored = match (
        written_generation.map(stored_u64),
        quarantined_through.map(stored_u64).transpose(),
        bytes,
    ) {
        (Some(Ok(written_generation)), Ok(quarantined_through), Some(bytes)) => {
            Ok(StoredCounterfactualArtifactV1::Stored {
                bytes,
                written_generation,
                quarantined_through,
            })
        }
        (None, Ok(_), None) => Ok(StoredCounterfactualArtifactV1::Absent),
        _ => Err(StoreError::CorruptState),
    };
    stored_u64(generation).and_then(|generation| stored.map(|stored| (generation, stored)))
}

/// Decode one persisted receipt record of generation `at`.
fn decode_generation_record(
    at: ForkGenerationV1,
    row: GenerationRecordRowV1,
) -> Result<CounterfactualGenerationRecordV1, StoreError> {
    match (
        [row.0, row.1, row.4, row.5].map(stored_hash),
        [row.2, row.3, row.6, row.7, row.8].map(stored_u64),
    ) {
        (
            [Ok(frontier), Ok(invalidation), Ok(plan), Ok(graph)],
            [Ok(tick), Ok(head), Ok(trust), Ok(revocation), Ok(erasure)],
        ) => Ok(CounterfactualGenerationRecordV1 {
            generation: at,
            frontier_digest: frontier,
            invalidation_digest: invalidation,
            first_tick: tick,
            first_tick_head: Seq::from_u64(head),
            facts: CounterfactualFactsV1 {
                plan_digest: plan,
                dependency_graph_digest: graph,
                trust_epoch: trust,
                revocation_epoch: revocation,
                erasure_epoch: erasure,
            },
        }),
        _ => Err(StoreError::CorruptState),
    }
}

fn settle<T>(staged: Staged<T>) -> Result<T, StoreError> {
    staged.unwrap_or_else(|error| Err(counterfactual_port_error(&error)))
}

/// Statements that open, release, and abandon one port read: a deferred read
/// transaction, or a savepoint of an enclosing transaction.
struct ReadScopeSqlV1 {
    begin: &'static str,
    release: &'static str,
    abandon: &'static str,
}

const READ_TRANSACTION: ReadScopeSqlV1 = ReadScopeSqlV1 {
    begin: "BEGIN DEFERRED",
    release: "COMMIT",
    abandon: "ROLLBACK",
};

const READ_SAVEPOINT: ReadScopeSqlV1 = ReadScopeSqlV1 {
    begin: "SAVEPOINT pigloros_counterfactual_read",
    release: "RELEASE SAVEPOINT pigloros_counterfactual_read",
    abandon: concat!(
        "ROLLBACK TO SAVEPOINT pigloros_counterfactual_read;",
        "RELEASE SAVEPOINT pigloros_counterfactual_read",
    ),
};

/// Run `next` only when the previous staged step accepted.
fn then_staged<T, U>(staged: Staged<T>, next: impl FnOnce(T) -> Staged<U>) -> Staged<U> {
    staged.and_then(|accepted| accepted.map_or_else(|rejected| Ok(Err(rejected)), next))
}

fn read_fork_state(conn: &Connection, fork: TimelineId) -> Staged<ForkStateV1> {
    conn.query_row(
        "SELECT generation, plan_digest, dependency_graph_digest,
                trust_epoch, revocation_epoch, erasure_epoch
         FROM counterfactual_forks WHERE fork_id = ?1",
        params![fork.to_string()],
        |row| <ForkStateRowV1>::try_from(row),
    )
    .optional()
    .map_err(SqliteStore::into_storage_error)
    .map(|row| {
        row.ok_or(StoreError::ForkNotFound)
            .and_then(decode_fork_state)
    })
}

/// Read the generation and one artifact's state in a single statement: the
/// current generation, the generation the digest is quarantined through (the
/// highest quarantining generation minus one), and the latest writing
/// generation with its bytes.
fn read_artifact_state(
    conn: &Connection,
    fork: TimelineId,
    artifact_digest: Hash,
) -> Staged<(u64, StoredCounterfactualArtifactV1)> {
    conn.query_row(
        "SELECT forks.generation,
                (
                    SELECT MAX(quarantine.generation) - 1
                    FROM counterfactual_quarantine AS quarantine
                    WHERE quarantine.fork_id = forks.fork_id
                      AND quarantine.artifact_digest = ?2
                ),
                latest.generation,
                latest.artifact_bytes
         FROM counterfactual_forks AS forks
         LEFT JOIN (
             SELECT generation, artifact_bytes FROM counterfactual_artifacts
             WHERE fork_id = ?1 AND artifact_digest = ?2
             ORDER BY generation DESC LIMIT 1
         ) AS latest ON 1
         WHERE forks.fork_id = ?1",
        params![fork.to_string(), artifact_digest.as_bytes().as_slice()],
        |row| <StoredArtifactRowV1>::try_from(row),
    )
    .optional()
    .map_err(SqliteStore::into_storage_error)
    .map(|row| {
        row.ok_or(StoreError::ForkNotFound)
            .and_then(decode_artifact_state)
    })
}

/// Read the persisted receipt record of generation `at`; `None` when no
/// invalidation committed it. A generation above `i64::MAX` cannot be stored,
/// so it cannot have committed.
fn read_generation_record(
    conn: &Connection,
    at: ForkGenerationV1,
) -> Staged<Option<CounterfactualGenerationRecordV1>> {
    let Ok(generation) = i64::try_from(at.generation) else {
        return Ok(Ok(None));
    };
    conn.query_row(
        "SELECT frontier_digest, invalidation_digest, first_tick, first_tick_head,
                plan_digest, dependency_graph_digest,
                trust_epoch, revocation_epoch, erasure_epoch
         FROM counterfactual_generations WHERE fork_id = ?1 AND generation = ?2",
        params![at.fork.to_string(), generation],
        |row| <GenerationRecordRowV1>::try_from(row),
    )
    .optional()
    .map_err(SqliteStore::into_storage_error)
    .map(|row| row.map(|row| decode_generation_record(at, row)).transpose())
}

/// Read whether the Fork is published and the generation a publication
/// continues at: its committed generation, else the floor a purge of an
/// earlier Fork with this id left, else `0`.
fn publication_state(conn: &Connection, fork: TimelineId) -> Staged<(bool, u64)> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM counterfactual_forks WHERE fork_id = ?1),
                COALESCE(
                    (SELECT generation FROM counterfactual_forks WHERE fork_id = ?1),
                    (SELECT generation_floor FROM counterfactual_fork_tombstones
                     WHERE fork_id = ?1),
                    0
                )",
        params![fork.to_string()],
        |row| <(bool, i64)>::try_from(row),
    )
    .map_err(SqliteStore::into_storage_error)
    .map(|(published, stored)| stored_u64(stored).map(|generation| (published, generation)))
}

/// Purge every counterfactual row of one deleted Fork inside the caller's
/// delete transaction, keeping only its last generation as a tombstone floor.
pub(super) fn purge_counterfactual_state(conn: &Connection, fork: &str) -> Result<(), CoreError> {
    PURGE_COUNTERFACTUAL_STATEMENTS
        .iter()
        .try_for_each(|sql| conn.execute(sql, params![fork]).map(|_| ()))
        .map_err(SqliteStore::into_storage_error)
}

/// Insert the first publication at the generation its Fork id resumes at
/// (`0`, or the tombstone floor), or update only the facts of a published
/// Fork. Publication never inserts over an existing row, so the insert guard
/// can refuse every conflicting insert.
fn write_fork_facts(
    conn: &Connection,
    fork: TimelineId,
    facts: &CounterfactualFactsV1,
    epochs: [i64; 3],
    published: bool,
) -> Result<(), CoreError> {
    let sql = if published {
        "UPDATE counterfactual_forks SET
             plan_digest = ?2, dependency_graph_digest = ?3,
             trust_epoch = ?4, revocation_epoch = ?5, erasure_epoch = ?6
         WHERE fork_id = ?1"
    } else {
        "INSERT INTO counterfactual_forks
         (fork_id, generation, plan_digest, dependency_graph_digest,
          trust_epoch, revocation_epoch, erasure_epoch)
         SELECT ?1, COALESCE(
                    (SELECT generation_floor FROM counterfactual_fork_tombstones
                     WHERE fork_id = ?1),
                    0
                ), ?2, ?3, ?4, ?5, ?6"
    };
    conn.execute(
        sql,
        params![
            fork.to_string(),
            facts.plan_digest.as_bytes().as_slice(),
            facts.dependency_graph_digest.as_bytes().as_slice(),
            epochs[0],
            epochs[1],
            epochs[2],
        ],
    )
    .map(|_| ())
    .map_err(SqliteStore::into_storage_error)
}

/// Record the receipt and the exact `RCF1`/`SIV1` bytes, make the bytes
/// readable by their digests at this generation, and advance the Fork
/// generation.
///
/// The receipt's facts are the command's expected facts, which the recheck
/// found equal to the persisted Fork row, so the row's facts are copied.
fn insert_generation(
    conn: &Connection,
    command: &CounterfactualInvalidationCommandV1,
    generation: i64,
    first_tick: i64,
    first_tick_head: Seq,
) -> Result<(), CoreError> {
    let fork = command.fork().to_string();
    conn.execute(
        "INSERT INTO counterfactual_generations
         (fork_id, generation, frontier_digest, frontier_bytes,
          invalidation_digest, invalidation_bytes, first_tick, first_tick_head,
          plan_digest, dependency_graph_digest,
          trust_epoch, revocation_epoch, erasure_epoch)
         SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8,
                plan_digest, dependency_graph_digest,
                trust_epoch, revocation_epoch, erasure_epoch
         FROM counterfactual_forks WHERE fork_id = ?1",
        params![
            fork,
            generation,
            command.frontier().digest().as_bytes().as_slice(),
            command.frontier().as_bytes(),
            command.invalidation().digest().as_bytes().as_slice(),
            command.invalidation().as_bytes(),
            first_tick,
            seq_as_i64(first_tick_head),
        ],
    )
    .and_then(|_| {
        conn.prepare_cached(
            "INSERT INTO counterfactual_artifacts
             (fork_id, artifact_digest, generation, artifact_bytes)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .and_then(|mut statement| {
            statement
                .execute(params![
                    fork,
                    command.frontier().digest().as_bytes().as_slice(),
                    generation,
                    command.frontier().as_bytes(),
                ])
                .and_then(|_| {
                    statement.execute(params![
                        fork,
                        command.invalidation().digest().as_bytes().as_slice(),
                        generation,
                        command.invalidation().as_bytes(),
                    ])
                })
        })
    })
    .and_then(|_| {
        conn.execute(
            "UPDATE counterfactual_forks SET generation = ?2 WHERE fork_id = ?1",
            params![fork, generation],
        )
    })
    .map(|_| ())
    .map_err(SqliteStore::into_storage_error)
}

fn insert_quarantine(
    conn: &Connection,
    fork: TimelineId,
    generation: i64,
    kind: i64,
    digests: &[Hash],
) -> Result<(), CoreError> {
    let fork = fork.to_string();
    conn.prepare_cached(
        "INSERT INTO counterfactual_quarantine (fork_id, generation, kind, artifact_digest)
         VALUES (?1, ?2, ?3, ?4)",
    )
    .and_then(|mut statement| {
        digests.iter().try_for_each(|digest| {
            statement
                .execute(params![
                    fork,
                    generation,
                    kind,
                    digest.as_bytes().as_slice()
                ])
                .map(|_| ())
        })
    })
    .map_err(SqliteStore::into_storage_error)
}

impl SqliteStore {
    /// Create the additive counterfactual tables, index, and guard
    /// triggers, then validate their exact shape.
    pub(super) fn prepare_counterfactual_schema(&self) -> Result<(), CoreError> {
        let objects = COUNTERFACTUAL_SCHEMA_OBJECTS
            .iter()
            .map(|object| {
                format!(
                    "CREATE {} IF NOT EXISTS {} {};",
                    object.kind, object.name, object.body
                )
            })
            .collect::<Vec<_>>()
            .concat();
        self.conn
            .execute_batch(&format!(
                "BEGIN IMMEDIATE;
                 {}
                 {objects}
                 COMMIT;",
                sqlite_schema_ddl(COUNTERFACTUAL_SCHEMA_TABLES)
            ))
            .map_err(Self::into_storage_error)
            .and_then(|()| self.validate_counterfactual_schema())
    }

    /// Validate the counterfactual tables, index, and triggers without
    /// creating them, and refuse a file holding a purge marker: a marker only
    /// exists inside the purge transaction, so a surviving one is corruption.
    fn validate_counterfactual_schema(&self) -> Result<(), CoreError> {
        COUNTERFACTUAL_SCHEMA_TABLES
            .iter()
            .try_for_each(|table| self.validate_sqlite_schema_table(table))
            .and_then(|()| {
                COUNTERFACTUAL_SCHEMA_OBJECTS
                    .iter()
                    .try_for_each(|object| self.validate_counterfactual_schema_object(object))
            })
            .and_then(|()| {
                self.conn
                    .query_row(
                        "SELECT EXISTS (SELECT 1 FROM counterfactual_purge_fence)",
                        [],
                        |row| row.get::<_, bool>(0),
                    )
                    .map_err(Self::into_storage_error)
            })
            .and_then(|pending| {
                if pending {
                    Err(CoreError::Storage(
                        "SQLite counterfactual purge marker survived a transaction".to_owned(),
                    ))
                } else {
                    Ok(())
                }
            })
    }

    /// Read-only validation: a file without any counterfactual object holds
    /// no counterfactual state; any present object must be complete and exact.
    pub(super) fn validate_present_counterfactual_schema(&self) -> Result<(), CoreError> {
        counterfactual_schema_present(&self.conn).and_then(|present| {
            if present {
                self.validate_counterfactual_schema()
            } else {
                Ok(())
            }
        })
    }

    /// The stored statement of one index or trigger, if it exists.
    fn stored_schema_sql(
        &self,
        object: &CounterfactualSchemaObjectV1,
    ) -> Result<Option<String>, CoreError> {
        self.conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = ?1 AND name = ?2",
                params![object.kind, object.name],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(Self::into_storage_error)
    }

    /// Require one index or trigger with its exact body.
    fn validate_counterfactual_schema_object(
        &self,
        object: &CounterfactualSchemaObjectV1,
    ) -> Result<(), CoreError> {
        self.stored_schema_sql(object).and_then(|sql| {
            if stored_matches(sql, object) {
                Ok(())
            } else {
                Err(CoreError::Storage(format!(
                    "SQLite {} {} has an incompatible schema",
                    object.name, object.kind
                )))
            }
        })
    }

    /// Run `work` in one immediate transaction under the bound erasure
    /// inventory. A closed rejection rolls the transaction back exactly like
    /// a storage error, so a rejection decided after a write (a staged head
    /// that did not advance) commits nothing either. If the rollback itself
    /// fails, the unknown outcome wins over the rejection.
    fn in_counterfactual_scope<T>(&self, work: impl FnOnce(&Self) -> Staged<T>) -> Staged<T> {
        let mut rejection = None;
        begin_immediate_scope(&self.conn)
            .and_then(|scope| {
                let result = self
                    .validate_erasure_inventory_data_version()
                    .and_then(|()| work(self))
                    .and_then(|staged| {
                        staged.map_err(|rejected| {
                            rejection = Some(rejected);
                            CoreError::Storage("counterfactual rejection rolled back".to_owned())
                        })
                    });
                finish_immediate_scope(&self.conn, scope, result)
            })
            .map(Ok)
            .or_else(|error| {
                // Only a failed rollback leaves the outcome unknown, and it
                // then wins over the rejection.
                let outcome_known = !matches!(error, CoreError::StorageOutcomeUnknown(_));
                rejection
                    .filter(|_| outcome_known)
                    .map_or(Err(error), |rejected| Ok(Err(rejected)))
            })
    }

    /// Clear the in-doubt mark once the connection is back in autocommit:
    /// the transaction an in-doubt write could have left open has settled.
    pub(super) fn settle_counterfactual_doubt(&self) {
        self.counterfactual_write_in_doubt
            .set(self.counterfactual_write_in_doubt.get() && !self.conn.is_autocommit());
    }

    /// Settle a write's result; an unknown outcome reported while the
    /// connection is still inside a transaction marks it in doubt until it is
    /// next seen in autocommit. One reported back in autocommit has nothing
    /// left open, so it is settled at once.
    fn settle_write<T>(&self, staged: Staged<T>) -> Result<T, StoreError> {
        let settled = settle(staged);
        let unknown = matches!(settled, Err(StoreError::OutcomeUnknown));
        self.counterfactual_write_in_doubt.set(
            (self.counterfactual_write_in_doubt.get() || unknown) && !self.conn.is_autocommit(),
        );
        settled
    }

    /// Run a multi-statement port read at one consistent read point: one
    /// deferred read transaction, or, inside an enclosing transaction such as
    /// the host's protected-effect interval, one savepoint of it. While an
    /// in-doubt write may have left that enclosing transaction holding
    /// unsettled state, the read is refused rather than answered from it. A
    /// scope that cannot be released is abandoned, so a failed read never
    /// leaves the connection inside its transaction.
    fn in_counterfactual_read<T>(&self, work: impl FnOnce(&Self) -> Staged<T>) -> Staged<T> {
        self.settle_counterfactual_doubt();
        if self.counterfactual_write_in_doubt.get() {
            return Err(CoreError::Storage(
                "counterfactual read refused while an in-doubt write is unsettled".to_owned(),
            ));
        }
        let scope = if self.conn.is_autocommit() {
            &READ_TRANSACTION
        } else {
            &READ_SAVEPOINT
        };
        self.conn
            .execute_batch(scope.begin)
            .map_err(Self::into_storage_error)
            .and_then(|()| {
                let result = work(self);
                self.conn
                    .execute_batch(scope.release)
                    .map_err(|error| {
                        drop(self.conn.execute_batch(scope.abandon));
                        Self::into_storage_error(error)
                    })
                    .and(result)
            })
    }

    /// Require a visible Fork with counterfactual tables; a root Timeline is
    /// not a Fork, and a pre-schema read-only file holds no counterfactual
    /// state.
    fn visible_counterfactual_fork(&self, fork: TimelineId) -> Staged<()> {
        self.ensure_generic_timeline_visibility(fork)
            .and_then(|()| Self::fork_chain_on(&self.conn, fork))
            .and_then(|chain| {
                counterfactual_schema_present(&self.conn).map(|present| {
                    if present && chain.len() > 1 {
                        Ok(())
                    } else {
                        Err(StoreError::ForkNotFound)
                    }
                })
            })
    }

    /// Read the persisted basis: the Fork's live Logical Head, committed
    /// generation, and published facts.
    fn persisted_counterfactual_basis(&self, fork: TimelineId) -> Staged<CounterfactualBasisV1> {
        then_staged(self.visible_counterfactual_fork(fork), |()| {
            then_staged(read_fork_state(&self.conn, fork), |state| {
                Self::logical_head_unchecked_on(&self.conn, fork).map(|head| Ok(state.basis(head)))
            })
        })
    }

    /// Read the persisted basis a write is rechecked against; an admitted
    /// Fork's appends are reserved for its classified append authority.
    fn writable_counterfactual_basis(&self, fork: TimelineId) -> Staged<CounterfactualBasisV1> {
        self.ensure_generic_fork_append_is_rejected(fork)
            .and_then(|()| self.persisted_counterfactual_basis(fork))
    }

    /// Append one recomputation Tick under the generic append guard and
    /// return the Fork Logical Head after it.
    fn append_tick_in_transaction(
        &self,
        fork: TimelineId,
        drafts: &PipelineDraftBatchV1,
    ) -> Result<Seq, CoreError> {
        crate::ensure_non_geographic_drafts(drafts.drafts(), fork)
            .and_then(|()| {
                drafts.drafts().iter().try_for_each(|draft| {
                    Self::append_one_in_transaction(
                        &self.conn,
                        self.hasher.as_ref(),
                        fork,
                        draft.clone(),
                    )
                    .map(drop)
                })
            })
            .and_then(|()| Self::logical_head_unchecked_on(&self.conn, fork))
    }

    /// Append the first Tick and build the receipt from its head, then record
    /// the generation and quarantine.
    fn write_counterfactual_generation(
        &self,
        command: &CounterfactualInvalidationCommandV1,
        generation: i64,
        first_tick: i64,
    ) -> Staged<CounterfactualInvalidationOutcomeV1> {
        let fork = command.fork();
        let staged = self
            .append_tick_in_transaction(fork, command.first_tick_drafts())
            .map(|head| command.committed_receipt(&COUNTERFACTUAL_SEAL, head));
        then_staged(staged, |receipt| {
            insert_generation(
                &self.conn,
                command,
                generation,
                first_tick,
                receipt.first_tick_head(),
            )
            .and_then(|()| {
                insert_quarantine(
                    &self.conn,
                    fork,
                    generation,
                    INVALID_ARTIFACT_KIND,
                    command.invalid_artifacts(),
                )
            })
            .and_then(|()| {
                insert_quarantine(
                    &self.conn,
                    fork,
                    generation,
                    EVICTION_KIND,
                    command.evictions(),
                )
            })
            .map(|()| {
                Ok(CounterfactualInvalidationOutcomeV1::Committed(Box::new(
                    receipt,
                )))
            })
        })
    }
}

/// Whether this database holds any counterfactual table, index, or trigger.
fn counterfactual_schema_present(conn: &Connection) -> Result<bool, CoreError> {
    conn.query_row(COUNTERFACTUAL_SCHEMA_PRESENT_SQL, [], |row| {
        row.get::<_, bool>(0)
    })
    .map_err(SqliteStore::into_storage_error)
}

impl CounterfactualStorePortV1 for SqliteStore {
    fn publish_counterfactual_facts(
        &mut self,
        fork: TimelineId,
        facts: CounterfactualFactsV1,
    ) -> Result<ForkGenerationV1, StoreError> {
        let epochs = sql_integer(facts.trust_epoch).and_then(|trust| {
            sql_integer(facts.revocation_epoch).and_then(|revocation| {
                sql_integer(facts.erasure_epoch).map(|erasure| [trust, revocation, erasure])
            })
        })?;
        self.settle_write(self.in_counterfactual_scope(|store| {
            then_staged(store.visible_counterfactual_fork(fork), |()| {
                then_staged(
                    publication_state(&store.conn, fork),
                    |(published, generation)| {
                        write_fork_facts(&store.conn, fork, &facts, epochs, published)
                            .map(|()| Ok(ForkGenerationV1 { fork, generation }))
                    },
                )
            })
        }))
    }

    fn commit_counterfactual_invalidation(
        &mut self,
        command: &CounterfactualInvalidationCommandV1,
    ) -> Result<CounterfactualInvalidationOutcomeV1, StoreError> {
        let fork = command.fork();
        let generation = sql_integer(command.new_generation().generation)?;
        let first_tick = sql_integer(command.first_tick())?;
        let staged = self.with_erasure_fence(fork, ErasureProtectedOperationV1::Append, |store| {
            store.in_counterfactual_scope(|store| {
                then_staged(store.writable_counterfactual_basis(fork), |persisted| {
                    command
                        .expected_basis()
                        .first_conflict(&persisted)
                        .map_or_else(
                            || {
                                store.write_counterfactual_generation(
                                    command, generation, first_tick,
                                )
                            },
                            |conflict| {
                                Ok(Ok(
                                    CounterfactualInvalidationOutcomeV1::InvalidationConflict(
                                        conflict,
                                    ),
                                ))
                            },
                        )
                })
            })
        });
        self.settle_write(staged)
    }

    fn append_counterfactual_tick(
        &mut self,
        fork: TimelineId,
        expected: &CounterfactualBasisV1,
        drafts: &PipelineDraftBatchV1,
    ) -> Result<CounterfactualTickOutcomeV1, StoreError> {
        let staged = self.with_erasure_fence(fork, ErasureProtectedOperationV1::Append, |store| {
            store.in_counterfactual_scope(|store| {
                then_staged(store.writable_counterfactual_basis(fork), |persisted| {
                    expected.first_conflict(&persisted).map_or_else(
                        || {
                            // The outcome is built from the staged head; a
                            // head that did not advance rolls back.
                            store
                                .append_tick_in_transaction(fork, drafts)
                                .map(|head| persisted.committed_tick(&COUNTERFACTUAL_SEAL, head))
                        },
                        |conflict| Ok(Ok(CounterfactualTickOutcomeV1::Stale(conflict))),
                    )
                })
            })
        });
        self.settle_write(staged)
    }

    fn current_fork_generation(&self, fork: TimelineId) -> Result<ForkGenerationV1, StoreError> {
        settle(
            self.with_erasure_read_fence(fork, ErasureProtectedOperationV1::Read, |store| {
                store.in_counterfactual_read(|store| {
                    then_staged(store.visible_counterfactual_fork(fork), |()| {
                        read_fork_state(&store.conn, fork)
                    })
                })
            }),
        )
        .map(|state| ForkGenerationV1 {
            fork,
            generation: state.generation,
        })
    }

    fn current_counterfactual_basis(
        &self,
        fork: TimelineId,
    ) -> Result<CounterfactualBasisV1, StoreError> {
        settle(
            self.with_erasure_read_fence(fork, ErasureProtectedOperationV1::Read, |store| {
                store.in_counterfactual_read(|store| store.persisted_counterfactual_basis(fork))
            }),
        )
    }

    fn committed_generation_receipt(
        &self,
        at: ForkGenerationV1,
    ) -> Result<Option<CounterfactualGenerationReceiptV1>, StoreError> {
        let fork = at.fork;
        settle(
            self.with_erasure_read_fence(fork, ErasureProtectedOperationV1::Read, |store| {
                store.in_counterfactual_read(|store| {
                    then_staged(store.visible_counterfactual_fork(fork), |()| {
                        then_staged(read_fork_state(&store.conn, fork), |_| {
                            read_generation_record(&store.conn, at)
                        })
                    })
                })
            }),
        )
        .and_then(|record| {
            record
                .map(|record| {
                    CounterfactualGenerationReceiptV1::from_record(&COUNTERFACTUAL_SEAL, record)
                })
                .transpose()
        })
    }

    fn read_generation_artifact(
        &self,
        at: ForkGenerationV1,
        artifact_digest: Hash,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let fork = at.fork;
        settle(
            self.with_erasure_read_fence(fork, ErasureProtectedOperationV1::Read, |store| {
                store.in_counterfactual_read(|store| {
                    then_staged(store.visible_counterfactual_fork(fork), |()| {
                        read_artifact_state(&store.conn, fork, artifact_digest)
                    })
                })
            }),
        )
        .and_then(|(current, stored)| at.resolve_read(current, stored))
    }
}

#[cfg(test)]
mod tests {
    use pos_core::counterfactual_store::test_fixtures::{
        frontier_frame, hash_field, id_field, invalidation_frame, invalidation_middle, uint,
    };
    use pos_core::{
        CanonicalBytes, CounterfactualInvalidationInputV1, EntityId,
        ErasureInventoryPersistencePortV1, ErasureProtectedEffectDispositionV1, EventDraft,
        EventStore, Kind, RecomputationFrontierBytesV1, SuffixInvalidationBytesV1,
    };

    use super::*;

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
        })
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn drafts() -> PipelineDraftBatchV1 {
        ok(PipelineDraftBatchV1::try_new(vec![EventDraft::new(
            EntityId::new(),
            Kind::new("counterfactual.tick"),
            CanonicalBytes::from_vec(vec![1]),
        )]))
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    const fn facts() -> CounterfactualFactsV1 {
        CounterfactualFactsV1 {
            plan_digest: Hash::from_bytes([5; 32]),
            dependency_graph_digest: Hash::from_bytes([3; 32]),
            trust_epoch: 0,
            revocation_epoch: 0,
            erasure_epoch: 0,
        }
    }

    /// The invalidation of generation 0 of `fork`, whose head is Seq 1.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn command(fork: TimelineId) -> CounterfactualInvalidationCommandV1 {
        let frontier = ok(RecomputationFrontierBytesV1::try_from_canonical(
            frontier_frame(
                &[
                    id_field([1; 16]),
                    hash_field(facts().plan_digest),
                    hash_field(Hash::from_bytes([2; 32])),
                    hash_field(facts().dependency_graph_digest),
                    vec![0x01],
                ]
                .concat(),
                0,
            ),
        ));
        let invalidation = ok(SuffixInvalidationBytesV1::try_from_canonical(
            invalidation_frame(
                &[
                    id_field([4; 16]),
                    hash_field(facts().plan_digest),
                    id_field(fork.inner().to_bytes()),
                    uint(0),
                    uint(1),
                    hash_field(frontier.digest()),
                    invalidation_middle(),
                    vec![0x83],
                    id_field(fork.inner().to_bytes()),
                    uint(1),
                    uint(1),
                ]
                .concat(),
                0,
            ),
        ));
        ok(CounterfactualInvalidationCommandV1::try_new(
            CounterfactualInvalidationInputV1 {
                fork,
                fork_logical_head: Seq::from_u64(1),
                trust_epoch: 0,
                revocation_epoch: 0,
                erasure_epoch: 0,
                frontier,
                invalidation,
                invalid_artifacts: vec![Hash::from_bytes([9; 32])],
                evictions: Vec::new(),
                first_tick: 1,
                first_tick_drafts: drafts(),
            },
        ))
    }

    /// An in-memory store with a published Fork at logical Seq 1.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn published_store() -> (SqliteStore, TimelineId) {
        let mut store = super::super::tests::new_store();
        let root = ok(store.create_timeline("counterfactual-root")).id();
        ok(store.append(root, drafts().drafts()));
        let fork = ok(store.fork(root, Seq::from_u64(1), "counterfactual-fork")).id();
        ok(store.publish_counterfactual_facts(fork, facts()));
        (store, fork)
    }

    /// Make the next commit fail and its rollback fail too, so every write
    /// reports an unknown outcome although nothing committed.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fail_commits(store: &SqliteStore, fail: bool) {
        if fail {
            ok(store.conn.commit_hook(Some(|| true)));
        } else {
            ok(store.conn.commit_hook::<fn() -> bool>(None));
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn an_in_doubt_invalidation_is_outcome_unknown_and_recoverable() {
        let (mut store, fork) = published_store();
        let command = command(fork);
        let next = command.new_generation();

        fail_commits(&store, true);
        let in_doubt = store.commit_counterfactual_invalidation(&command);
        fail_commits(&store, false);

        assert_eq!(in_doubt, Err(StoreError::OutcomeUnknown));
        // The recovery read finds nothing committed at the new generation, so
        // the same command is retried.
        assert_eq!(store.committed_generation_receipt(next), Ok(None));
        assert_eq!(
            store.current_counterfactual_basis(fork),
            Ok(command.expected_basis())
        );
        let receipt = ok(command.committed_receipt(&COUNTERFACTUAL_SEAL, Seq::from_u64(2)));
        assert_eq!(
            store.commit_counterfactual_invalidation(&command),
            Ok(CounterfactualInvalidationOutcomeV1::Committed(Box::new(
                receipt
            )))
        );
        assert_eq!(store.committed_generation_receipt(next), Ok(Some(receipt)));
        assert!(receipt.matches_invalidation(command.invalidation()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn in_doubt_ticks_and_publications_are_outcome_unknown() {
        let (mut store, fork) = published_store();
        let receipt = match ok(store.commit_counterfactual_invalidation(&command(fork))) {
            CounterfactualInvalidationOutcomeV1::Committed(receipt) => receipt,
            other @ CounterfactualInvalidationOutcomeV1::InvalidationConflict(_) => {
                std::panic::resume_unwind(Box::new(format!("expected a commit, got {other:?}")))
            }
        };
        let expected = receipt.tick_basis(receipt.first_tick_head());

        fail_commits(&store, true);
        let tick = store.append_counterfactual_tick(fork, &expected, &drafts());
        let publication = store.publish_counterfactual_facts(fork, facts());
        fail_commits(&store, false);

        assert_eq!(tick, Err(StoreError::OutcomeUnknown));
        assert_eq!(publication, Err(StoreError::OutcomeUnknown));
        // An unmoved basis proves the in-doubt Tick did not commit.
        let persisted = ok(store.current_counterfactual_basis(fork));
        assert_eq!(expected.first_conflict(&persisted), None);
        assert_eq!(
            store.append_counterfactual_tick(fork, &expected, &drafts()),
            Ok(CounterfactualTickOutcomeV1::Committed {
                head: Seq::from_u64(3)
            })
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reads_run_in_one_transaction_or_one_savepoint() {
        let (store, fork) = published_store();
        let observed = store.in_counterfactual_read(|store| Ok(Ok(store.conn.is_autocommit())));
        assert!(matches!(observed, Ok(Ok(false))));
        assert!(store.conn.is_autocommit());

        // Inside an enclosing transaction the read is one savepoint of it.
        assert!(store.conn.execute_batch("BEGIN").is_ok());
        let nested = store.in_counterfactual_read(|store| {
            Ok(Ok(store
                .conn
                .execute_batch("ROLLBACK TO SAVEPOINT pigloros_counterfactual_read")
                .is_ok()))
        });
        assert!(matches!(nested, Ok(Ok(true))));
        assert!(!store.conn.is_autocommit());
        assert_eq!(
            store.current_fork_generation(fork),
            Ok(ForkGenerationV1 {
                fork,
                generation: 0
            })
        );
        assert!(store.conn.execute_batch("ROLLBACK").is_ok());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reads_inside_a_protected_effect_interval_see_its_writes() {
        let (mut store, fork) = published_store();
        let command = command(fork);
        let next = command.new_generation();
        let before = ok(store.current_counterfactual_basis(fork));
        let interval = ok(store.begin_protected_effect_interval());
        assert!(!store.conn.is_autocommit());
        assert_eq!(store.current_counterfactual_basis(fork), Ok(before));

        let receipt = ok(command.committed_receipt(&COUNTERFACTUAL_SEAL, Seq::from_u64(2)));
        assert_eq!(
            store.commit_counterfactual_invalidation(&command),
            Ok(CounterfactualInvalidationOutcomeV1::Committed(Box::new(
                receipt
            )))
        );
        assert_eq!(store.current_fork_generation(fork), Ok(next));
        assert_eq!(
            store.current_counterfactual_basis(fork),
            Ok(receipt.tick_basis(receipt.first_tick_head()))
        );
        assert_eq!(store.committed_generation_receipt(next), Ok(Some(receipt)));
        assert_eq!(
            store.read_generation_artifact(next, command.invalidation().digest()),
            Ok(Some(command.invalidation().as_bytes().to_vec()))
        );
        assert!(!store.conn.is_autocommit());

        ok(store.finish_protected_effect_interval(
            interval,
            ErasureProtectedEffectDispositionV1::Rollback,
        ));
        assert_eq!(store.current_counterfactual_basis(fork), Ok(before));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reads_after_an_in_doubt_write_wait_until_it_settles() {
        let (store, fork) = published_store();
        let settled = ForkGenerationV1 {
            fork,
            generation: 0,
        };
        let unknown = || CoreError::StorageOutcomeUnknown("in doubt".to_owned());

        // A known failure leaves reads inside the transaction available.
        assert!(store.conn.execute_batch("BEGIN").is_ok());
        assert_eq!(
            store.settle_write::<()>(Err(CoreError::Storage("known".to_owned()))),
            Err(StoreError::StorageFailure)
        );
        assert_eq!(store.current_fork_generation(fork), Ok(settled));

        // An unknown outcome refuses every read until the transaction settles.
        assert_eq!(
            store.settle_write::<()>(Err(unknown())),
            Err(StoreError::OutcomeUnknown)
        );
        assert_eq!(
            store.current_fork_generation(fork),
            Err(StoreError::StorageFailure)
        );
        assert!(matches!(
            store.in_counterfactual_read(|_| Ok(Ok(()))),
            Err(CoreError::Storage(_))
        ));
        assert!(store.conn.execute_batch("ROLLBACK").is_ok());

        // Beginning a new protected-effect interval observes the settled
        // connection, so reads inside it are answered again.
        let interval = ok(store.begin_protected_effect_interval());
        assert_eq!(store.current_fork_generation(fork), Ok(settled));
        ok(store.finish_protected_effect_interval(
            interval,
            ErasureProtectedEffectDispositionV1::Rollback,
        ));

        // An unknown outcome that left the connection in autocommit never
        // marks it in doubt, so reads in a transaction the host opens by
        // other means than a protected-effect interval are answered.
        assert_eq!(
            store.settle_write::<()>(Err(unknown())),
            Err(StoreError::OutcomeUnknown)
        );
        assert!(!store.counterfactual_write_in_doubt.get());
        assert!(store.conn.execute_batch("BEGIN").is_ok());
        assert_eq!(store.current_fork_generation(fork), Ok(settled));
        assert!(store.conn.execute_batch("ROLLBACK").is_ok());
        assert_eq!(store.current_fork_generation(fork), Ok(settled));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn a_failed_read_commit_leaves_the_connection_in_autocommit() {
        let store = super::super::tests::new_store();
        assert!(store
            .conn
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 CREATE TEMP TABLE read_parent (id INTEGER PRIMARY KEY);
                 CREATE TEMP TABLE read_child (
                     parent INTEGER REFERENCES read_parent (id) DEFERRABLE INITIALLY DEFERRED
                 );"
            )
            .is_ok());
        // A deferred foreign-key violation fails the read's COMMIT and keeps
        // its transaction open until the read abandons it.
        let failed = store.in_counterfactual_read(|store| {
            Ok(Ok(store
                .conn
                .execute_batch("INSERT INTO read_child VALUES (1)")
                .is_ok()))
        });
        assert!(matches!(failed, Err(CoreError::Storage(_))));
        assert!(store.conn.is_autocommit());
        let children = store
            .conn
            .query_row("SELECT count(*) FROM read_child", [], |row| {
                row.get::<_, i64>(0)
            });
        assert!(matches!(children, Ok(0)));
    }

    /// A rejection is reported only while its rollback is guaranteed: once
    /// the rollback itself fails, the unknown outcome wins.
    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn a_failed_rollback_wins_over_a_rejection() {
        let store = super::super::tests::new_store();
        // An open transaction makes the counterfactual scope a savepoint.
        assert!(store.conn.execute_batch("BEGIN").is_ok());
        let rejected =
            store.in_counterfactual_scope(|_| Ok(Err::<(), _>(StoreError::CorruptState)));
        assert!(matches!(rejected, Ok(Err(StoreError::CorruptState))));
        // Releasing the savepoint inside the scope makes its rollback fail.
        let unknown = store.in_counterfactual_scope(|store| {
            assert!(store
                .conn
                .execute_batch("RELEASE SAVEPOINT pigloros_protected_effect")
                .is_ok());
            Ok(Err::<(), _>(StoreError::CorruptState))
        });
        assert!(matches!(unknown, Err(CoreError::StorageOutcomeUnknown(_))));
        assert!(store.conn.execute_batch("ROLLBACK").is_ok());
    }
}
