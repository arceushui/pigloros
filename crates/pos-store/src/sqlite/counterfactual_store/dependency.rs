//! `SQLite` rows and ports of the ADR-064 dependency record.
//!
//! The recording methods of [`CounterfactualDependencyRecordingPortV1`] run
//! the storage port's own write path and insert the record's rows inside the
//! same `BEGIN IMMEDIATE` transaction, so a stale, conflicting, rejected, or
//! failed commit records nothing. The read methods of
//! [`CounterfactualDependencyReadPortV1`] page the rows with keyset queries.
//!
//! # Schema
//!
//! Five additive tables, two indexes, and seventeen guard triggers, created and
//! validated like the rest of the counterfactual schema:
//!
//! - `counterfactual_dependency_records` holds one row per recorded Tick
//!   record: its set, its Tick (persisted apart from the node Ticks), and the
//!   node, edge, and declared-input counts of the record. Summing these rows
//!   gives the stored counts of a set, so the capacity check sums one summary
//!   row per recorded Tick of the set instead of counting every node and edge.
//! - `counterfactual_dependency_nodes` holds the nodes, keyed by their set and
//!   position key `(tick, scheduler_position, owner_id, output_ordinal)`, with
//!   a second unique key on the set and artifact digest. The primary key
//!   index is the canonical read order, so rows are served ordered by
//!   position key across records, never by insertion order. A node stores its
//!   class code, origin code, schema ID, artifact digest, the declared input
//!   digests as one blob of concatenated 32-byte digests, and its provenance
//!   digest.
//! - `counterfactual_dependency_edges` holds the edges keyed by their set,
//!   consumer position key, and source digest (the `IDP1` edge-list order). An
//!   edge stores the exact `IDP1` bytes and the consumer's schema ID and
//!   artifact digest, which are not part of the key; a read re-validates the
//!   bytes against them with `DependencyEdgeRecordV1::try_from_canonical`.
//! - `counterfactual_dependency_commit_ranges` holds, per Timeline, one row per
//!   committed factual Tick of the Timeline's own set: the Tick and the
//!   first and last `seq` it owns. Its primary key is `(timeline_id, tick)`,
//!   and the index `counterfactual_dependency_commit_ranges_by_last_seq` on
//!   `(timeline_id, last_seq)` serves the head and cut reads.
//! - `counterfactual_dependency_event_nodes` holds, per Timeline, the node
//!   each committed `seq` is bound to: the Tick that recorded it and the node's
//!   artifact digest. Its primary key is `(timeline_id, seq)`, and a second
//!   unique key on the Timeline and artifact digest serves the bound `seq` of
//!   a digest lookup.
//! - The index `counterfactual_dependency_nodes_by_owner` on the nodes table,
//!   over `(timeline_id, generation, owner_id, tick)`, serves the latest step
//!   node of an owner.
//!
//! A set is addressed by a Timeline ID and a generation key. A Fork
//! generation's provisional rows use the generation itself (at least `1`); the
//! committed prefix of a Timeline uses the reserved key `-1`. No write path
//! records a prefix yet (#554), so those rows exist only when the
//! `test-support` seeding function installs them, and the tables keep and
//! serve them. The keys can never meet: a check ties the origin code to the
//! key, and generation `0` holds no rows.
//!
//! The five tables refuse an update, refuse a delete outside the marked #530
//! purge (the same `counterfactual_purge_fence` condition as the four delete
//! guards of the storage tables), and refuse an insert that repeats a key.
//! The record Tick guard also refuses an insert that is not above every Tick
//! already recorded in its set, so the database enforces what the adapter
//! checks. A node has two unique keys and one insert guard for each, a single
//! condition per guard so each lookup is one index probe; together they stop
//! `INSERT OR REPLACE` from deleting and rewriting a node past the other
//! guards.
//!
//! # Decisions
//!
//! - **Order of checks.** Both writes take the erasure fence, then refuse an
//!   admitted Fork and look the Fork up, like the in-memory adapter: a record
//!   on an unknown, protected, or admitted Fork gets the Fork's error, never
//!   `BindingMismatch`. An invalidation then checks its record before the
//!   basis, like the contract's reference model: a record that is not
//!   provisional or not at the command's first Tick is `BindingMismatch` even
//!   when the basis is stale. A later Tick rechecks the basis first and
//!   reports `Stale` before it checks the record; then it checks, in order,
//!   provisional, record Tick, node collisions, and set capacity, all before
//!   the Tick's drafts are appended.
//! - **One write path.** The plain and the recording write of each operation
//!   run the same helper, which takes the record as an `Option`, so a plain
//!   write records nothing and cannot drift from the recording one.
//! - **First record of a generation.** The record of an invalidation opens an
//!   empty set at the command's first Tick, so it needs no Tick, collision, or
//!   capacity check: a record is bounded far below the set bounds.
//! - **Record Tick.** It must be above the highest Tick recorded in the set,
//!   or, while the set has no record, not below the first Tick persisted in
//!   the generation's receipt row. A generation with no receipt row (a Fork id
//!   re-created after a purge resumes at its floor without an invalidation)
//!   has no first Tick, so a later Tick with a record is `BindingMismatch`.
//! - **Capacity.** The check sums the stored counts of the set's record rows
//!   and trusts them; it does not recount the node and edge rows. That is the
//!   accepted trust boundary: this adapter alone writes the counts, in the
//!   same transaction as the rows they describe, and the immutability guard
//!   keeps them from changing. A count that drifted low (only possible by
//!   editing the file with the guards dropped) lets a record in that the real
//!   rows would exceed; a negative or invalid count is `CorruptState`.
//! - **Collisions.** One indexed lookup per node finds a position key or an
//!   artifact digest the set already holds, `DuplicateIdentity`; the unique
//!   keys and the insert guard are the backstop.
//! - **Reads.** A parent-prefix read needs a visible parent Timeline and runs
//!   under the parent's own erasure read fence and its inherited scopes. A
//!   Fork read needs a published Fork and runs under the Fork's fence. Both
//!   resolve through the read scope the storage reads use, so they see the
//!   host's savepoint and refuse an unsettled in-doubt write. A stored row
//!   that fails re-validation, or lies outside the requested scope, is
//!   `CorruptState`.
//! - **Factual prefix reads.** [`FactualPrefixReadPortV1`] runs under the
//!   Timeline's own erasure read fence and its inherited scopes, at one read
//!   point. It stitches the Timeline's own committed prefix set with every
//!   ancestor's set through that ancestor's cut, as the Memory adapter does:
//!   an ancestor's Ticks are visible when they end at or before the fork
//!   point `seq`, a lookup that finds nothing continues in the next older set,
//!   and a `seq` inside a Tick is a mid-Tick cut. A parent-prefix page read
//!   stitches the same way, each ancestor serving only its visible Ticks. An
//!   unknown or concealed
//!   Timeline, or one whose ancestor was deleted, is `TimelineNotFound`. A
//!   stored row that fails re-validation is a storage fault, and so is any
//!   read of a pre-schema read-only file, which holds none of the tables. The
//!   set counts are the sums of the Timeline's own record rows.
//! - **Seeding.** The insert function behind `seed_factual_prefix` records one
//!   committed Tick: its record, nodes, and edges under the prefix key, its
//!   commit range, and its Event bindings, in one transaction. It exists only
//!   with `test-support` until the pipeline commit calls it.
//! - **`SQLite`-only differences.** `SQLite` stores signed 64-bit integers, so:
//!   a record Tick above `i64::MAX` is `FieldOutOfBounds` before any fence,
//!   Fork lookup, or transaction, and a first Tick above it is rejected the
//!   same way; a cursor Tick above it is `BindingMismatch` before any fence
//!   or Fork lookup; a parent-prefix `through_tick` above it selects every
//!   row; and the rows of an older generation are retained but unreachable
//!   (a read names the current generation only), where the in-memory adapter
//!   keeps only the current generation's set. One more difference is not
//!   about integers: a parent-prefix read of an existing Timeline on a
//!   pre-schema read-only file is `ForkNotFound`, not an empty page, because
//!   the tables do not exist there and cannot be created, so the read fails
//!   closed as not found.
//! - **Deletion.** The marked purge of a deleted Timeline also deletes its
//!   edges, nodes, records, commit ranges, and Event bindings, whether they
//!   are its Fork generations' or its own committed prefix. A re-created
//!   Timeline ID starts with empty sets.
//! - **Existing files.** The tables are additive and created with
//!   `IF NOT EXISTS`; a writable open of a file with the storage tables but
//!   without these creates them empty, and a read-only open of such a file
//!   fails the exact validation. There is no migration. Operationally, a file
//!   written by the #337 storage schema and never opened writably since
//!   refuses a read-only open until one writable open adds the new tables;
//!   that is acceptable under the no-migration, replacement-first rule.

#[cfg(any(test, feature = "test-support"))]
use pos_core::counterfactual_store::test_fixtures::SeededFactualTickV1;
use pos_core::factual_dependency::BoundFactualNodeV1;
use pos_core::{
    CoreError, CounterfactualBasisV1, CounterfactualDependencyErrorV1 as DepError,
    CounterfactualDependencyReadPortV1, CounterfactualDependencyRecordingPortV1,
    CounterfactualInvalidationCommandV1, CounterfactualInvalidationOutcomeV1,
    CounterfactualTickOutcomeV1, DependencyEdgeRecordV1, DependencyNodeCoordinateV1,
    DependencyNodeRecordV1, DependencyPageCursorV1, DependencyPageRequestV1, DependencyPageV1,
    DependencyPagedRowV1, DependencyReadScopeV1, ErasureProtectedOperationV1, FactualCutV1,
    FactualHeadV1, FactualOwnerIdV1, FactualPrefixReadPortV1, Hash, PipelineDraftBatchV1,
    RecordedDependencyClassV1, RecordedNodeOriginV1, RecordedSetCountsV1, Seq,
    TickDependencyRecordV1, TimelineId,
};
use rusqlite::{params, Connection, OptionalExtension, Params, Row};

use super::{
    counterfactual_schema_present, read_fork_state, settle, sql_integer, stored_hash, stored_u64,
    then_staged, CounterfactualSchemaObjectV1, Staged, StoreError,
};
use crate::sqlite::{seq_as_i64, SqliteSchemaColumn, SqliteSchemaTable, SqliteStore};
use crate::COUNTERFACTUAL_SEAL;

/// The generation key of a parent Timeline's committed prefix.
const PREFIX_GENERATION: i64 = -1;

/// Bytes of one stored digest.
const HASH_BYTES: usize = 32;

/// The generation key rule every table shares.
const GENERATION_CHECK: &str = "CHECK (generation = -1 OR generation >= 1)";

/// A primary-key column of a schema constant. A macro, not a function: the
/// schema constants are built at compile time, so a function body would never
/// run and would show as uncovered code.
macro_rules! key_column {
    ($name:literal, $kind:literal) => {
        SqliteSchemaColumn {
            name: $name,
            kind: $kind,
            not_null: true,
            primary_key: true,
        }
    };
}

/// A non-key column of a schema constant (see `key_column`).
macro_rules! data_column {
    ($name:literal, $kind:literal) => {
        SqliteSchemaColumn {
            name: $name,
            kind: $kind,
            not_null: true,
            primary_key: false,
        }
    };
}

/// Tick records: the Tick persisted apart from the node Ticks, and the counts
/// the capacity check sums.
pub(super) const RECORDS_TABLE: SqliteSchemaTable = SqliteSchemaTable {
    name: "counterfactual_dependency_records",
    columns_query: "PRAGMA table_info(counterfactual_dependency_records)",
    columns: &[
        key_column!("timeline_id", "TEXT"),
        key_column!("generation", "INTEGER"),
        key_column!("record_tick", "INTEGER"),
        data_column!("node_count", "INTEGER"),
        data_column!("edge_count", "INTEGER"),
        data_column!("input_count", "INTEGER"),
    ],
    constraints: &[
        GENERATION_CHECK,
        "CHECK (record_tick >= 0)",
        "CHECK (node_count >= 0)",
        "CHECK (edge_count >= 0)",
        "CHECK (input_count >= 0)",
    ],
};

/// Nodes keyed by their set and position key, unique by artifact digest.
pub(super) const NODES_TABLE: SqliteSchemaTable = SqliteSchemaTable {
    name: "counterfactual_dependency_nodes",
    columns_query: "PRAGMA table_info(counterfactual_dependency_nodes)",
    columns: &[
        key_column!("timeline_id", "TEXT"),
        key_column!("generation", "INTEGER"),
        key_column!("tick", "INTEGER"),
        key_column!("scheduler_position", "INTEGER"),
        key_column!("owner_id", "TEXT"),
        key_column!("output_ordinal", "INTEGER"),
        data_column!("schema_id", "INTEGER"),
        data_column!("artifact_digest", "BLOB"),
        data_column!("class", "INTEGER"),
        data_column!("origin", "INTEGER"),
        data_column!("input_digests", "BLOB"),
        data_column!("provenance_digest", "BLOB"),
    ],
    constraints: &[
        GENERATION_CHECK,
        "CHECK ((generation = -1) = (origin = 0))",
        "CHECK (tick >= 0)",
        "CHECK (scheduler_position BETWEEN 0 AND 4294967295)",
        "CHECK (length(CAST(owner_id AS BLOB)) BETWEEN 1 AND 128)",
        "CHECK (output_ordinal BETWEEN 0 AND 4294967295)",
        "CHECK (schema_id BETWEEN 1 AND 4294967295)",
        "CHECK (length(artifact_digest) = 32)",
        "CHECK (class BETWEEN 0 AND 4)",
        "CHECK (origin IN (0, 1))",
        "CHECK (length(input_digests) % 32 = 0 AND length(input_digests) <= 131072)",
        "CHECK (length(provenance_digest) = 32)",
        "UNIQUE (timeline_id, generation, artifact_digest)",
    ],
};

/// Edges keyed by their set, consumer position key, and source digest.
pub(super) const EDGES_TABLE: SqliteSchemaTable = SqliteSchemaTable {
    name: "counterfactual_dependency_edges",
    columns_query: "PRAGMA table_info(counterfactual_dependency_edges)",
    columns: &[
        key_column!("timeline_id", "TEXT"),
        key_column!("generation", "INTEGER"),
        key_column!("tick", "INTEGER"),
        key_column!("scheduler_position", "INTEGER"),
        key_column!("owner_id", "TEXT"),
        key_column!("output_ordinal", "INTEGER"),
        key_column!("source_digest", "BLOB"),
        data_column!("consumer_schema_id", "INTEGER"),
        data_column!("consumer_digest", "BLOB"),
        data_column!("edge_bytes", "BLOB"),
    ],
    constraints: &[
        GENERATION_CHECK,
        "CHECK (tick >= 0)",
        "CHECK (scheduler_position BETWEEN 0 AND 4294967295)",
        "CHECK (length(CAST(owner_id AS BLOB)) BETWEEN 1 AND 128)",
        "CHECK (output_ordinal BETWEEN 0 AND 4294967295)",
        "CHECK (length(source_digest) = 32)",
        "CHECK (consumer_schema_id BETWEEN 1 AND 4294967295)",
        "CHECK (length(consumer_digest) = 32)",
        "CHECK (length(edge_bytes) <= 16384)",
    ],
};

/// Commit ranges: the Tick and the `seq` range of each committed factual Tick
/// of a Timeline's own set.
pub(super) const COMMIT_RANGES_TABLE: SqliteSchemaTable = SqliteSchemaTable {
    name: "counterfactual_dependency_commit_ranges",
    columns_query: "PRAGMA table_info(counterfactual_dependency_commit_ranges)",
    columns: &[
        key_column!("timeline_id", "TEXT"),
        key_column!("tick", "INTEGER"),
        data_column!("first_seq", "INTEGER"),
        data_column!("last_seq", "INTEGER"),
    ],
    constraints: &[
        "CHECK (tick >= 1)",
        "CHECK (first_seq >= 1)",
        "CHECK (last_seq >= first_seq)",
    ],
};

/// Event bindings: the Tick that recorded the node of a committed `seq` and
/// the node's artifact digest, unique per Timeline.
pub(super) const EVENT_NODES_TABLE: SqliteSchemaTable = SqliteSchemaTable {
    name: "counterfactual_dependency_event_nodes",
    columns_query: "PRAGMA table_info(counterfactual_dependency_event_nodes)",
    columns: &[
        key_column!("timeline_id", "TEXT"),
        key_column!("seq", "INTEGER"),
        data_column!("tick", "INTEGER"),
        data_column!("artifact_digest", "BLOB"),
    ],
    constraints: &[
        "CHECK (seq >= 1)",
        "CHECK (tick >= 1)",
        "CHECK (length(artifact_digest) = 32)",
        "UNIQUE (timeline_id, artifact_digest)",
    ],
};

// The `WHEN NOT EXISTS (... counterfactual_purge_fence ...)` clause is
// repeated in five trigger bodies here and in four in the parent module, nine
// copies in all, on purpose: the exact-body validation compares literal text,
// so the nine copies must stay identical.
pub(super) const RECORDS_RETAINED: CounterfactualSchemaObjectV1 = CounterfactualSchemaObjectV1 {
    kind: "trigger",
    name: "counterfactual_dependency_records_retained",
    body: "BEFORE DELETE ON counterfactual_dependency_records
           WHEN NOT EXISTS (
               SELECT 1 FROM counterfactual_purge_fence WHERE fork_id = OLD.timeline_id
           )
           BEGIN SELECT RAISE(ABORT, 'dependency record is retained'); END",
};

pub(super) const RECORDS_IMMUTABLE: CounterfactualSchemaObjectV1 = CounterfactualSchemaObjectV1 {
    kind: "trigger",
    name: "counterfactual_dependency_records_immutable",
    body: "BEFORE UPDATE ON counterfactual_dependency_records
           BEGIN SELECT RAISE(ABORT, 'dependency record is immutable'); END",
};

/// A record Tick must be above every Tick of its set; an equal Tick is the
/// replaced row of an upsert and is refused too.
pub(super) const RECORDS_MONOTONIC: CounterfactualSchemaObjectV1 = CounterfactualSchemaObjectV1 {
    kind: "trigger",
    name: "counterfactual_dependency_records_monotonic",
    body: "BEFORE INSERT ON counterfactual_dependency_records
           WHEN EXISTS (
               SELECT 1 FROM counterfactual_dependency_records
               WHERE timeline_id = NEW.timeline_id AND generation = NEW.generation
                 AND record_tick >= NEW.record_tick
           )
           BEGIN SELECT RAISE(ABORT, 'dependency record Tick must increase'); END",
};

pub(super) const NODES_RETAINED: CounterfactualSchemaObjectV1 = CounterfactualSchemaObjectV1 {
    kind: "trigger",
    name: "counterfactual_dependency_nodes_retained",
    body: "BEFORE DELETE ON counterfactual_dependency_nodes
           WHEN NOT EXISTS (
               SELECT 1 FROM counterfactual_purge_fence WHERE fork_id = OLD.timeline_id
           )
           BEGIN SELECT RAISE(ABORT, 'dependency node is retained'); END",
};

pub(super) const NODES_IMMUTABLE: CounterfactualSchemaObjectV1 = CounterfactualSchemaObjectV1 {
    kind: "trigger",
    name: "counterfactual_dependency_nodes_immutable",
    body: "BEFORE UPDATE ON counterfactual_dependency_nodes
           BEGIN SELECT RAISE(ABORT, 'dependency node is immutable'); END",
};

/// Guards the artifact digest key of a node, so a replacing insert deletes no
/// node that holds the digest.
pub(super) const NODES_DIGEST_NOT_REPLACED: CounterfactualSchemaObjectV1 =
    CounterfactualSchemaObjectV1 {
        kind: "trigger",
        name: "counterfactual_dependency_nodes_digest_not_replaced",
        body: "BEFORE INSERT ON counterfactual_dependency_nodes
           WHEN EXISTS (
               SELECT 1 FROM counterfactual_dependency_nodes
               WHERE timeline_id = NEW.timeline_id AND generation = NEW.generation
                 AND artifact_digest = NEW.artifact_digest
           )
           BEGIN SELECT RAISE(ABORT, 'dependency node digest is already recorded'); END",
    };

/// Guards the position key of a node, so a replacing insert deletes no node
/// that holds the key. One condition per trigger keeps each lookup on one
/// index.
pub(super) const NODES_KEY_NOT_REPLACED: CounterfactualSchemaObjectV1 =
    CounterfactualSchemaObjectV1 {
        kind: "trigger",
        name: "counterfactual_dependency_nodes_key_not_replaced",
        body: "BEFORE INSERT ON counterfactual_dependency_nodes
           WHEN EXISTS (
               SELECT 1 FROM counterfactual_dependency_nodes
               WHERE timeline_id = NEW.timeline_id AND generation = NEW.generation
                 AND tick = NEW.tick AND scheduler_position = NEW.scheduler_position
                 AND owner_id = NEW.owner_id AND output_ordinal = NEW.output_ordinal
           )
           BEGIN SELECT RAISE(ABORT, 'dependency node key is already recorded'); END",
    };

pub(super) const EDGES_RETAINED: CounterfactualSchemaObjectV1 = CounterfactualSchemaObjectV1 {
    kind: "trigger",
    name: "counterfactual_dependency_edges_retained",
    body: "BEFORE DELETE ON counterfactual_dependency_edges
           WHEN NOT EXISTS (
               SELECT 1 FROM counterfactual_purge_fence WHERE fork_id = OLD.timeline_id
           )
           BEGIN SELECT RAISE(ABORT, 'dependency edge is retained'); END",
};

pub(super) const EDGES_IMMUTABLE: CounterfactualSchemaObjectV1 = CounterfactualSchemaObjectV1 {
    kind: "trigger",
    name: "counterfactual_dependency_edges_immutable",
    body: "BEFORE UPDATE ON counterfactual_dependency_edges
           BEGIN SELECT RAISE(ABORT, 'dependency edge is immutable'); END",
};

pub(super) const EDGES_NOT_REPLACED: CounterfactualSchemaObjectV1 = CounterfactualSchemaObjectV1 {
    kind: "trigger",
    name: "counterfactual_dependency_edges_not_replaced",
    body: "BEFORE INSERT ON counterfactual_dependency_edges
           WHEN EXISTS (
               SELECT 1 FROM counterfactual_dependency_edges
               WHERE timeline_id = NEW.timeline_id AND generation = NEW.generation
                 AND tick = NEW.tick AND scheduler_position = NEW.scheduler_position
                 AND owner_id = NEW.owner_id AND output_ordinal = NEW.output_ordinal
                 AND source_digest = NEW.source_digest
           )
           BEGIN SELECT RAISE(ABORT, 'dependency edge is already recorded'); END",
};

pub(super) const RANGES_RETAINED: CounterfactualSchemaObjectV1 = CounterfactualSchemaObjectV1 {
    kind: "trigger",
    name: "counterfactual_dependency_commit_ranges_retained",
    body: "BEFORE DELETE ON counterfactual_dependency_commit_ranges
           WHEN NOT EXISTS (
               SELECT 1 FROM counterfactual_purge_fence WHERE fork_id = OLD.timeline_id
           )
           BEGIN SELECT RAISE(ABORT, 'dependency commit range is retained'); END",
};

pub(super) const RANGES_IMMUTABLE: CounterfactualSchemaObjectV1 = CounterfactualSchemaObjectV1 {
    kind: "trigger",
    name: "counterfactual_dependency_commit_ranges_immutable",
    body: "BEFORE UPDATE ON counterfactual_dependency_commit_ranges
           BEGIN SELECT RAISE(ABORT, 'dependency commit range is immutable'); END",
};

pub(super) const RANGES_NOT_REPLACED: CounterfactualSchemaObjectV1 = CounterfactualSchemaObjectV1 {
    kind: "trigger",
    name: "counterfactual_dependency_commit_ranges_not_replaced",
    body: "BEFORE INSERT ON counterfactual_dependency_commit_ranges
           WHEN EXISTS (
               SELECT 1 FROM counterfactual_dependency_commit_ranges
               WHERE timeline_id = NEW.timeline_id AND tick = NEW.tick
           )
           BEGIN SELECT RAISE(ABORT, 'dependency commit range is already recorded'); END",
};

pub(super) const BINDINGS_RETAINED: CounterfactualSchemaObjectV1 = CounterfactualSchemaObjectV1 {
    kind: "trigger",
    name: "counterfactual_dependency_event_nodes_retained",
    body: "BEFORE DELETE ON counterfactual_dependency_event_nodes
           WHEN NOT EXISTS (
               SELECT 1 FROM counterfactual_purge_fence WHERE fork_id = OLD.timeline_id
           )
           BEGIN SELECT RAISE(ABORT, 'dependency event node is retained'); END",
};

pub(super) const BINDINGS_IMMUTABLE: CounterfactualSchemaObjectV1 = CounterfactualSchemaObjectV1 {
    kind: "trigger",
    name: "counterfactual_dependency_event_nodes_immutable",
    body: "BEFORE UPDATE ON counterfactual_dependency_event_nodes
           BEGIN SELECT RAISE(ABORT, 'dependency event node is immutable'); END",
};

/// Guards the `seq` key of a binding, so a replacing insert deletes no binding
/// that holds the `seq`.
pub(super) const BINDINGS_SEQ_NOT_REPLACED: CounterfactualSchemaObjectV1 =
    CounterfactualSchemaObjectV1 {
        kind: "trigger",
        name: "counterfactual_dependency_event_nodes_seq_not_replaced",
        body: "BEFORE INSERT ON counterfactual_dependency_event_nodes
           WHEN EXISTS (
               SELECT 1 FROM counterfactual_dependency_event_nodes
               WHERE timeline_id = NEW.timeline_id AND seq = NEW.seq
           )
           BEGIN SELECT RAISE(ABORT, 'dependency event node is already recorded'); END",
    };

/// Guards the artifact digest key of a binding, so a replacing insert deletes
/// no binding that holds the digest.
pub(super) const BINDINGS_DIGEST_NOT_REPLACED: CounterfactualSchemaObjectV1 =
    CounterfactualSchemaObjectV1 {
        kind: "trigger",
        name: "counterfactual_dependency_event_nodes_digest_not_replaced",
        body: "BEFORE INSERT ON counterfactual_dependency_event_nodes
           WHEN EXISTS (
               SELECT 1 FROM counterfactual_dependency_event_nodes
               WHERE timeline_id = NEW.timeline_id AND artifact_digest = NEW.artifact_digest
           )
           BEGIN SELECT RAISE(ABORT, 'dependency event node digest is already recorded'); END",
    };

/// Serves the head and cut reads: the commit ranges of a Timeline by last `seq`.
pub(super) const RANGES_BY_LAST_SEQ: CounterfactualSchemaObjectV1 = CounterfactualSchemaObjectV1 {
    kind: "index",
    name: "counterfactual_dependency_commit_ranges_by_last_seq",
    body: "ON counterfactual_dependency_commit_ranges(timeline_id, last_seq)",
};

/// Serves the latest step node of an owner.
pub(super) const NODES_BY_OWNER: CounterfactualSchemaObjectV1 = CounterfactualSchemaObjectV1 {
    kind: "index",
    name: "counterfactual_dependency_nodes_by_owner",
    body: "ON counterfactual_dependency_nodes(timeline_id, generation, owner_id, tick)",
};

/// One recorded set: the Timeline that owns it and its generation key.
struct DependencySetV1 {
    timeline: String,
    generation: i64,
}

/// The key a page resumes after: Tick, scheduler position, owner, output
/// ordinal, and the edge source digest (empty for a node cursor).
type CursorKeyV1 = (i64, i64, String, i64, Vec<u8>);

impl DependencySetV1 {
    fn new(timeline: TimelineId, generation: i64) -> Self {
        Self {
            timeline: timeline.to_string(),
            generation,
        }
    }
}

/// One page read: its set, the last Tick it may return, the key it resumes
/// after, and one more than the page limit.
struct PageQueryV1<'a> {
    set: &'a DependencySetV1,
    through: i64,
    after: &'a CursorKeyV1,
    limit: i64,
}

/// Raw node columns after the set, in the node SELECT column order: position
/// key, schema ID, artifact digest, class code, origin code, input digests,
/// and provenance digest.
type NodeRowV1 = (
    i64,
    i64,
    String,
    i64,
    i64,
    Vec<u8>,
    i64,
    i64,
    Vec<u8>,
    Vec<u8>,
);

/// Raw edge columns after the set, in the edge SELECT column order: position
/// key, source digest, the consumer's schema ID and artifact digest, and the
/// `IDP1` bytes.
type EdgeRowV1 = (i64, i64, String, i64, Vec<u8>, i64, Vec<u8>, Vec<u8>);

/// Raw set aggregates, in the `SET_STATE_SQL` column order: recorded node,
/// edge, and declared-input totals, the highest record Tick, and the
/// generation's first Tick.
type SetStateRowV1 = (i64, i64, i64, Option<i64>, Option<i64>);

/// One page window: the last Tick it may return, the key it resumes after,
/// and one more than the page limit.
struct PageWindowV1<'a> {
    through: i64,
    after: &'a CursorKeyV1,
    limit: i64,
}

/// Reads one kind of row for a page query.
type PageRowsFnV1<T> = fn(&Connection, &PageQueryV1<'_>) -> Staged<Vec<T>>;

/// The set aggregates a record is admitted against.
struct SetStateV1 {
    counts: RecordedSetCountsV1,
    last_tick: Option<u64>,
    first_tick: Option<u64>,
}

impl SetStateV1 {
    /// A record Tick must be above the highest recorded Tick, or, while the
    /// set has no record, not below the generation's first Tick.
    fn admit_tick(&self, tick: u64) -> Result<(), StoreError> {
        let admitted = self.last_tick.map_or_else(
            || self.first_tick.is_some_and(|first| tick >= first),
            |last| tick > last,
        );
        admitted.then_some(()).ok_or(StoreError::BindingMismatch)
    }
}

/// A Tick bound that fits `SQLite` or selects every row: a record Tick is
/// checked to fit before it is written, and the other callers only compare.
// The saturation is never reached when writing: node Ticks never exceed the
// record Tick, and the record Tick passed `sql_integer` up front.
fn sql_tick(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// A row count of one record, which is bounded far below `i64::MAX`.
// The saturation is never reached: counts are bounded by the per-record caps
// and the page limit.
fn sql_count(count: usize) -> i64 {
    i64::try_from(count).unwrap_or(i64::MAX)
}

/// Narrow a stored integer to `u32`; out of range is corrupt.
fn stored_u32(value: i64) -> Result<u32, StoreError> {
    u32::try_from(value).or(Err(StoreError::CorruptState))
}

/// Widen a stored non-negative integer to `usize`; a negative is corrupt.
fn stored_count(value: i64) -> Result<usize, StoreError> {
    usize::try_from(value).or(Err(StoreError::CorruptState))
}

/// Split a blob of concatenated digests; a trailing partial digest is corrupt.
fn stored_hashes(bytes: &[u8]) -> Result<Vec<Hash>, StoreError> {
    bytes
        .chunks(HASH_BYTES)
        .map(|chunk| stored_hash(chunk.to_vec()))
        .collect()
}

/// Decode a stored class code, or fail as a corrupt read-back.
fn stored_class(code: i64) -> Result<RecordedDependencyClassV1, StoreError> {
    stored_u64(code).and_then(|code| {
        RecordedDependencyClassV1::from_code(code).or(Err(DepError::READ_BACK_FAULT))
    })
}

/// Decode a stored origin code, or fail as a corrupt read-back.
fn stored_origin(code: i64) -> Result<RecordedNodeOriginV1, StoreError> {
    stored_u64(code)
        .and_then(|code| RecordedNodeOriginV1::from_code(code).or(Err(DepError::READ_BACK_FAULT)))
}

/// Decode one stored node; a row that fails the contract's checks is corrupt.
fn decode_node(row: NodeRowV1) -> Result<DependencyNodeRecordV1, StoreError> {
    // Destructure in the `NodeRowV1` column order.
    let (tick, position, owner, ordinal, schema, digest, class, origin, inputs, provenance) = row;
    match (
        stored_u64(tick),
        [position, ordinal, schema].map(stored_u32),
        [digest, provenance].map(stored_hash),
        stored_hashes(&inputs),
        stored_class(class),
        stored_origin(origin),
    ) {
        (
            Ok(tick),
            [Ok(position), Ok(ordinal), Ok(schema)],
            [Ok(digest), Ok(provenance)],
            Ok(inputs),
            Ok(class),
            Ok(origin),
        ) => DependencyNodeCoordinateV1::try_new(tick, position, owner, ordinal, schema, digest)
            .and_then(|coordinate| {
                DependencyNodeRecordV1::try_new(coordinate, class, origin, inputs, provenance)
            })
            .or(Err(DepError::READ_BACK_FAULT)),
        _ => Err(DepError::READ_BACK_FAULT),
    }
}

/// Decode one stored edge, re-validating its `IDP1` bytes against its key.
fn decode_edge(row: EdgeRowV1) -> Result<DependencyEdgeRecordV1, StoreError> {
    // Destructure in the `EdgeRowV1` column order.
    let (tick, position, owner, ordinal, source, schema, consumer, bytes) = row;
    match (
        stored_u64(tick),
        [position, ordinal, schema].map(stored_u32),
        [source, consumer].map(stored_hash),
    ) {
        (Ok(tick), [Ok(position), Ok(ordinal), Ok(schema)], [Ok(source), Ok(consumer)]) => {
            DependencyNodeCoordinateV1::try_new(tick, position, owner, ordinal, schema, consumer)
                .and_then(|coordinate| {
                    DependencyEdgeRecordV1::try_from_canonical(bytes, coordinate, source)
                })
                .or(Err(DepError::READ_BACK_FAULT))
        }
        _ => Err(DepError::READ_BACK_FAULT),
    }
}

/// Decode the stored set aggregates; a negative or out-of-range value is corrupt.
fn decode_set_state(row: SetStateRowV1) -> Result<SetStateV1, StoreError> {
    // Destructure in the `SetStateRowV1` column order.
    let (nodes, edges, inputs, last, first) = row;
    match (
        [nodes, edges, inputs].map(stored_count),
        last.map(stored_u64).transpose(),
        first.map(stored_u64).transpose(),
    ) {
        ([Ok(nodes), Ok(edges), Ok(inputs)], Ok(last_tick), Ok(first_tick)) => Ok(SetStateV1 {
            counts: RecordedSetCountsV1 {
                nodes,
                edges,
                inputs,
            },
            last_tick,
            first_tick,
        }),
        _ => Err(StoreError::CorruptState),
    }
}

/// The key a page resumes after; every stored key is above the start key.
fn cursor_key(after: Option<&DependencyPageCursorV1>) -> Result<CursorKeyV1, StoreError> {
    after.map_or_else(
        || Ok((-1, -1, String::new(), -1, Vec::new())),
        |cursor| {
            sql_integer(cursor.tick())
                .or(Err(StoreError::BindingMismatch))
                .map(|tick| {
                    (
                        tick,
                        i64::from(cursor.scheduler_position()),
                        cursor.owner_id().to_owned(),
                        i64::from(cursor.output_ordinal()),
                        cursor
                            .source_digest()
                            .map_or_else(Vec::new, |digest| digest.as_bytes().to_vec()),
                    )
                })
        },
    )
}

/// Keyset page of a set's nodes in canonical position-key order.
const NODE_PAGE_SQL: &str = "SELECT tick, scheduler_position, owner_id, output_ordinal,
            schema_id, artifact_digest, class, origin, input_digests, provenance_digest
     FROM counterfactual_dependency_nodes
     WHERE timeline_id = ?1 AND generation = ?2 AND tick <= ?3
       AND (tick, scheduler_position, owner_id, output_ordinal) > (?4, ?5, ?6, ?7)
     ORDER BY tick, scheduler_position, owner_id, output_ordinal
     LIMIT ?8";

/// Keyset page of a set's edges in `IDP1` edge-list order.
const EDGE_PAGE_SQL: &str = "SELECT tick, scheduler_position, owner_id, output_ordinal,
            source_digest, consumer_schema_id, consumer_digest, edge_bytes
     FROM counterfactual_dependency_edges
     WHERE timeline_id = ?1 AND generation = ?2 AND tick <= ?3
       AND (tick, scheduler_position, owner_id, output_ordinal, source_digest)
           > (?4, ?5, ?6, ?7, ?8)
     ORDER BY tick, scheduler_position, owner_id, output_ordinal, source_digest
     LIMIT ?9";

/// Read and decode one page of node rows after the cursor.
fn node_rows(conn: &Connection, query: &PageQueryV1<'_>) -> Staged<Vec<DependencyNodeRecordV1>> {
    let (tick, position, owner, ordinal, _) = query.after;
    conn.prepare_cached(NODE_PAGE_SQL)
        .and_then(|mut statement| {
            statement
                .query_map(
                    params![
                        query.set.timeline,
                        query.set.generation,
                        query.through,
                        tick,
                        position,
                        owner,
                        ordinal,
                        query.limit
                    ],
                    |row| <NodeRowV1>::try_from(row),
                )
                .and_then(|mapped| mapped.collect::<rusqlite::Result<Vec<_>>>())
        })
        .map_err(SqliteStore::into_storage_error)
        .map(|raw| raw.into_iter().map(decode_node).collect())
}

/// Read and decode one page of edge rows after the cursor.
fn edge_rows(conn: &Connection, query: &PageQueryV1<'_>) -> Staged<Vec<DependencyEdgeRecordV1>> {
    let (tick, position, owner, ordinal, source) = query.after;
    conn.prepare_cached(EDGE_PAGE_SQL)
        .and_then(|mut statement| {
            statement
                .query_map(
                    params![
                        query.set.timeline,
                        query.set.generation,
                        query.through,
                        tick,
                        position,
                        owner,
                        ordinal,
                        source,
                        query.limit
                    ],
                    |row| <EdgeRowV1>::try_from(row),
                )
                .and_then(|mapped| mapped.collect::<rusqlite::Result<Vec<_>>>())
        })
        .map_err(SqliteStore::into_storage_error)
        .map(|raw| raw.into_iter().map(decode_edge).collect())
}

/// Read the rows of every segment, in ancestry order, up to the window limit
/// in all; each segment serves only the Ticks it may show.
fn window_rows<T>(
    conn: &Connection,
    rows: PageRowsFnV1<T>,
    segments: &[SegmentV1],
    window: &PageWindowV1<'_>,
) -> Staged<Vec<T>> {
    let start: Staged<Vec<T>> = Ok(Ok(Vec::new()));
    segments.iter().fold(start, |held, segment| {
        then_staged(held, |mut found| {
            let query = PageQueryV1 {
                set: &segment.set,
                through: window.through.min(segment.bound),
                after: window.after,
                limit: window.limit - sql_count(found.len()),
            };
            then_staged(rows(conn, &query), |more| {
                found.extend(more);
                Ok(Ok(found))
            })
        })
    })
}

/// Build the page of the fetched rows, which are after the request cursor and
/// one more than the limit at most. A cursor of the other row kind is the
/// caller's fault; a stored row that fails the page checks is corrupt state.
fn build_page<T: DependencyPagedRowV1 + Clone>(
    request: &DependencyPageRequestV1,
    rows: &[T],
) -> Result<DependencyPageV1<T>, StoreError> {
    // The rebuild clones the page, at most `MAX_DEPENDENCY_PAGE_ROWS_V1` rows:
    // that bound is the accepted price of telling a caller's fault from a
    // stored-row fault, since `try_new` is the only constructor that re-checks
    // the rows.
    DependencyPageV1::from_ordered(request, rows)
        .map_err(StoreError::from)
        .and_then(|page| {
            DependencyPageV1::try_new(request, page.items().to_vec(), page.next().cloned())
                .or(Err(DepError::READ_BACK_FAULT))
        })
}

/// The Timeline whose erasure read fence serves a scope.
const fn fence_timeline(scope: DependencyReadScopeV1) -> TimelineId {
    match scope {
        DependencyReadScopeV1::ParentPrefix { timeline, .. } => timeline,
        DependencyReadScopeV1::ForkGeneration(at) => at.fork,
    }
}

/// Aggregate the record rows of a set and read the generation's first Tick.
const SET_STATE_SQL: &str = "SELECT COALESCE(SUM(node_count), 0), COALESCE(SUM(edge_count), 0),
            COALESCE(SUM(input_count), 0), MAX(record_tick),
            (SELECT first_tick FROM counterfactual_generations
             WHERE fork_id = ?1 AND generation = ?2)
     FROM counterfactual_dependency_records WHERE timeline_id = ?1 AND generation = ?2";

/// Read the stored counts, highest record Tick, and first Tick of a set.
fn read_set_state(conn: &Connection, set: &DependencySetV1) -> Staged<SetStateV1> {
    conn.query_row(
        SET_STATE_SQL,
        params![set.timeline, set.generation],
        |row| <SetStateRowV1>::try_from(row),
    )
    .map_err(SqliteStore::into_storage_error)
    .map(decode_set_state)
}

/// Whether a node's artifact digest or position key is already in the set.
const COLLISION_SQL: &str = "SELECT EXISTS (
         SELECT 1 FROM counterfactual_dependency_nodes
         WHERE timeline_id = ?1 AND generation = ?2 AND artifact_digest = ?3
     ) OR EXISTS (
         SELECT 1 FROM counterfactual_dependency_nodes
         WHERE timeline_id = ?1 AND generation = ?2 AND tick = ?4
           AND scheduler_position = ?5 AND owner_id = ?6 AND output_ordinal = ?7
     )";

/// Whether any node of the record repeats a position key or an artifact
/// digest the set already holds.
fn nodes_collide(
    conn: &Connection,
    set: &DependencySetV1,
    record: &TickDependencyRecordV1,
) -> Staged<bool> {
    conn.prepare_cached(COLLISION_SQL)
        .and_then(|mut statement| {
            record.nodes().iter().try_fold(false, |found, node| {
                if found {
                    return Ok(true);
                }
                let coordinate = node.coordinate();
                statement.query_row(
                    params![
                        set.timeline,
                        set.generation,
                        coordinate.artifact_digest().as_bytes().as_slice(),
                        sql_tick(coordinate.tick()),
                        i64::from(coordinate.scheduler_position()),
                        coordinate.owner_id(),
                        i64::from(coordinate.output_ordinal())
                    ],
                    |row| row.get::<_, bool>(0),
                )
            })
        })
        .map_err(SqliteStore::into_storage_error)
        .map(Ok)
}

/// Admit the record of a later Tick, if any: a plain Tick has none.
fn admit_later_record(
    conn: &Connection,
    set: &DependencySetV1,
    record: Option<&TickDependencyRecordV1>,
) -> Staged<()> {
    record.map_or(Ok(Ok(())), |record| admit_recorded_tick(conn, set, record))
}

/// Admit a record of a later Tick against the stored set: provisional, its
/// Tick, no repeated position key or digest, and the set bounds.
fn admit_recorded_tick(
    conn: &Connection,
    set: &DependencySetV1,
    record: &TickDependencyRecordV1,
) -> Staged<()> {
    then_staged(Ok(record.ensure_provisional()), |()| {
        then_staged(read_set_state(conn, set), |state| {
            then_staged(Ok(state.admit_tick(record.tick())), |()| {
                then_staged(nodes_collide(conn, set, record), |collides| {
                    Ok(if collides {
                        Err(StoreError::DuplicateIdentity)
                    } else {
                        record
                            .ensure_set_capacity(state.counts)
                            .map_err(StoreError::from)
                    })
                })
            })
        })
    })
}

/// Admit the record of an invalidation, if any: provisional and at the first
/// Tick. It opens an empty set and is bounded far below the set bounds.
fn admit_first_record(
    record: Option<&TickDependencyRecordV1>,
    first_tick: u64,
) -> Result<(), StoreError> {
    record.map_or(Ok(()), |record| {
        record.ensure_provisional().and_then(|()| {
            (record.tick() == first_tick)
                .then_some(())
                .ok_or(StoreError::BindingMismatch)
        })
    })
}

/// Insert the record's summary row for the set and Tick.
fn insert_record_row(
    conn: &Connection,
    set: &DependencySetV1,
    tick: i64,
    record: &TickDependencyRecordV1,
) -> Result<(), CoreError> {
    conn.execute(
        "INSERT INTO counterfactual_dependency_records
         (timeline_id, generation, record_tick, node_count, edge_count, input_count)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            set.timeline,
            set.generation,
            tick,
            sql_count(record.nodes().len()),
            sql_count(record.edges().len()),
            sql_count(record.declared_input_count())
        ],
    )
    .map(|_| ())
    .map_err(SqliteStore::into_storage_error)
}

/// The declared input digests of a node as one blob of 32-byte digests.
fn input_blob(node: &DependencyNodeRecordV1) -> Vec<u8> {
    node.input_digests()
        .iter()
        .flat_map(|digest| *digest.as_bytes())
        .collect()
}

/// Insert every node of the record under the set.
fn insert_nodes(
    conn: &Connection,
    set: &DependencySetV1,
    record: &TickDependencyRecordV1,
) -> Result<(), CoreError> {
    conn.prepare_cached(
        "INSERT INTO counterfactual_dependency_nodes
         (timeline_id, generation, tick, scheduler_position, owner_id, output_ordinal,
          schema_id, artifact_digest, class, origin, input_digests, provenance_digest)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
    )
    .and_then(|mut statement| {
        record.nodes().iter().try_for_each(|node| {
            let coordinate = node.coordinate();
            let inputs = input_blob(node);
            statement
                .execute(params![
                    set.timeline,
                    set.generation,
                    sql_tick(coordinate.tick()),
                    i64::from(coordinate.scheduler_position()),
                    coordinate.owner_id(),
                    i64::from(coordinate.output_ordinal()),
                    i64::from(coordinate.schema_id()),
                    coordinate.artifact_digest().as_bytes().as_slice(),
                    i64::from(node.class().code()),
                    i64::from(node.origin().code()),
                    inputs,
                    node.provenance_digest().as_bytes().as_slice()
                ])
                .map(|_| ())
        })
    })
    .map_err(SqliteStore::into_storage_error)
}

/// Insert every edge of the record under the set.
fn insert_edges(
    conn: &Connection,
    set: &DependencySetV1,
    record: &TickDependencyRecordV1,
) -> Result<(), CoreError> {
    conn.prepare_cached(
        "INSERT INTO counterfactual_dependency_edges
         (timeline_id, generation, tick, scheduler_position, owner_id, output_ordinal,
          source_digest, consumer_schema_id, consumer_digest, edge_bytes)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
    )
    .and_then(|mut statement| {
        record.edges().iter().try_for_each(|edge| {
            let consumer = edge.consumer();
            statement
                .execute(params![
                    set.timeline,
                    set.generation,
                    sql_tick(consumer.tick()),
                    i64::from(consumer.scheduler_position()),
                    consumer.owner_id(),
                    i64::from(consumer.output_ordinal()),
                    edge.source_digest().as_bytes().as_slice(),
                    i64::from(consumer.schema_id()),
                    consumer.artifact_digest().as_bytes().as_slice(),
                    edge.as_bytes()
                ])
                .map(|_| ())
        })
    })
    .map_err(SqliteStore::into_storage_error)
}

/// Insert the record, its nodes, and its edges into the open transaction.
fn insert_dependency_record(
    conn: &Connection,
    set: &DependencySetV1,
    tick: i64,
    record: &TickDependencyRecordV1,
) -> Result<(), CoreError> {
    insert_record_row(conn, set, tick, record)
        .and_then(|()| insert_nodes(conn, set, record))
        .and_then(|()| insert_edges(conn, set, record))
}

impl SqliteStore {
    /// Require a visible parent Timeline, under its own erasure scopes and
    /// the schema. A pre-schema read-only file holds no counterfactual state.
    fn visible_dependency_parent(&self, timeline: TimelineId) -> Staged<()> {
        self.ensure_generic_timeline_visibility(timeline)
            .and_then(|()| {
                self.authorize_inherited_scopes(timeline, ErasureProtectedOperationV1::Read)
            })
            .and_then(|()| {
                counterfactual_schema_present(&self.conn).map(|present| {
                    if present {
                        Ok(())
                    } else {
                        Err(StoreError::ForkNotFound)
                    }
                })
            })
    }

    /// Resolve a read scope to its segments, oldest first: a visible
    /// Timeline's committed prefix stitched with every ancestor's through its
    /// cut, or a published Fork's committed generation.
    fn dependency_segments(&self, scope: DependencyReadScopeV1) -> Staged<Vec<SegmentV1>> {
        match scope {
            DependencyReadScopeV1::ParentPrefix { timeline, .. } => {
                then_staged(self.visible_dependency_parent(timeline), |()| {
                    self.factual_path(timeline).map(Ok)
                })
            }
            DependencyReadScopeV1::ForkGeneration(at) => {
                then_staged(self.visible_counterfactual_fork(at.fork), |()| {
                    then_staged(read_fork_state(&self.conn, at.fork), |state| {
                        let set = DependencySetV1::new(at.fork, sql_tick(at.generation));
                        let current = scope.ensure_current(state.generation);
                        Ok(current.map(|()| vec![whole(set)]))
                    })
                })
            }
        }
    }

    /// Serve one page of one row kind under the scope's erasure read fence,
    /// at one read point.
    fn read_dependency_page<T: DependencyPagedRowV1 + Clone>(
        &self,
        request: &DependencyPageRequestV1,
        rows: PageRowsFnV1<T>,
    ) -> Result<DependencyPageV1<T>, StoreError> {
        cursor_key(request.after())
            .and_then(|after| {
                let scope = request.scope();
                let limit = sql_count(request.limit().saturating_add(1));
                let through = scope.through_tick().map_or(i64::MAX, sql_tick);
                let fenced = self.with_erasure_read_fence(
                    fence_timeline(scope),
                    ErasureProtectedOperationV1::Read,
                    |store| {
                        store.in_counterfactual_read(|store| {
                            then_staged(store.dependency_segments(scope), |segments| {
                                let window = PageWindowV1 {
                                    through,
                                    after: &after,
                                    limit,
                                };
                                window_rows(&store.conn, rows, &segments, &window)
                            })
                        })
                    },
                );
                settle(fenced)
            })
            .and_then(|fetched| build_page(request, &fetched))
    }

    /// Write the invalidation's generation and insert its first record, if
    /// any, in the open transaction.
    ///
    /// The first record skips the collision and capacity checks. That is safe
    /// because `TickDependencyRecordV1::try_new` already enforces the
    /// per-record node, edge, input, and byte caps, which are far below the
    /// set bounds, and the generation's set starts empty.
    fn write_recorded_generation(
        &self,
        command: &CounterfactualInvalidationCommandV1,
        set: &DependencySetV1,
        first_tick: i64,
        record: Option<&TickDependencyRecordV1>,
    ) -> Staged<CounterfactualInvalidationOutcomeV1> {
        let written = self.write_counterfactual_generation(command, set.generation, first_tick);
        then_staged(written, |outcome| {
            record
                .map_or(Ok(()), |record| {
                    insert_dependency_record(&self.conn, set, first_tick, record)
                })
                .map(|()| Ok(outcome))
        })
    }

    /// Append one later Tick and insert its record, if any, in the open
    /// transaction. The outcome is built from the staged head; a head that did
    /// not advance rolls back.
    fn append_recorded_tick(
        &self,
        fork: TimelineId,
        persisted: &CounterfactualBasisV1,
        drafts: &PipelineDraftBatchV1,
        record: Option<&TickDependencyRecordV1>,
    ) -> Staged<CounterfactualTickOutcomeV1> {
        let set = DependencySetV1::new(fork, sql_tick(persisted.generation));
        then_staged(admit_later_record(&self.conn, &set, record), |()| {
            let appended = self
                .append_tick_in_transaction(fork, drafts)
                .map(|head| persisted.committed_tick(&COUNTERFACTUAL_SEAL, head));
            then_staged(appended, |outcome| {
                record
                    .map_or(Ok(()), |record| {
                        insert_dependency_record(&self.conn, &set, sql_tick(record.tick()), record)
                    })
                    .map(|()| Ok(outcome))
            })
        })
    }

    /// The one write path of an invalidation, plain (`record` is `None`) or
    /// recording. After the fence, the admitted-Fork guard, and the Fork
    /// lookup, a record is checked before the basis, so a misplaced record
    /// wins over a stale basis.
    pub(super) fn commit_invalidation_recording(
        &mut self,
        command: &CounterfactualInvalidationCommandV1,
        record: Option<&TickDependencyRecordV1>,
    ) -> Result<CounterfactualInvalidationOutcomeV1, StoreError> {
        let fork = command.fork();
        let generation = sql_integer(command.new_generation().generation)?;
        let first_tick = sql_integer(command.first_tick())?;
        let set = DependencySetV1::new(fork, generation);
        let staged = self.with_erasure_fence(fork, ErasureProtectedOperationV1::Append, |store| {
            store.in_counterfactual_scope(|store| {
                then_staged(store.writable_counterfactual_basis(fork), |persisted| {
                    let admitted = admit_first_record(record, command.first_tick());
                    then_staged(Ok(admitted), |()| {
                        command
                            .expected_basis()
                            .first_conflict(&persisted)
                            .map_or_else(
                                || {
                                    store.write_recorded_generation(
                                        command, &set, first_tick, record,
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
            })
        });
        self.settle_write(staged)
    }

    /// The one write path of a later Tick, plain (`record` is `None`) or
    /// recording. A record's Tick must fit `SQLite` before any fence.
    pub(super) fn append_tick_recording(
        &mut self,
        fork: TimelineId,
        expected: &CounterfactualBasisV1,
        drafts: &PipelineDraftBatchV1,
        record: Option<&TickDependencyRecordV1>,
    ) -> Result<CounterfactualTickOutcomeV1, StoreError> {
        record
            .map_or(Ok(()), |record| sql_integer(record.tick()).map(|_| ()))
            .and_then(|()| {
                let staged =
                    self.with_erasure_fence(fork, ErasureProtectedOperationV1::Append, |store| {
                        store.in_counterfactual_scope(|store| {
                            then_staged(store.writable_counterfactual_basis(fork), |persisted| {
                                expected.first_conflict(&persisted).map_or_else(
                                    || store.append_recorded_tick(fork, &persisted, drafts, record),
                                    |conflict| Ok(Ok(CounterfactualTickOutcomeV1::Stale(conflict))),
                                )
                            })
                        })
                    });
                self.settle_write(staged)
            })
    }
}

impl CounterfactualDependencyReadPortV1 for SqliteStore {
    fn read_dependency_nodes(
        &self,
        request: &DependencyPageRequestV1,
    ) -> Result<DependencyPageV1<DependencyNodeRecordV1>, StoreError> {
        self.read_dependency_page(request, node_rows)
    }

    fn read_dependency_edges(
        &self,
        request: &DependencyPageRequestV1,
    ) -> Result<DependencyPageV1<DependencyEdgeRecordV1>, StoreError> {
        self.read_dependency_page(request, edge_rows)
    }
}

impl CounterfactualDependencyRecordingPortV1 for SqliteStore {
    fn commit_counterfactual_invalidation_with_dependencies(
        &mut self,
        command: &CounterfactualInvalidationCommandV1,
        record: &TickDependencyRecordV1,
    ) -> Result<CounterfactualInvalidationOutcomeV1, StoreError> {
        self.commit_invalidation_recording(command, Some(record))
    }

    fn append_counterfactual_tick_with_dependencies(
        &mut self,
        fork: TimelineId,
        expected: &CounterfactualBasisV1,
        drafts: &PipelineDraftBatchV1,
        record: &TickDependencyRecordV1,
    ) -> Result<CounterfactualTickOutcomeV1, StoreError> {
        self.append_tick_recording(fork, expected, drafts, Some(record))
    }
}

/// The erasure operation of every factual prefix read.
const READ: ErasureProtectedOperationV1 = ErasureProtectedOperationV1::Read;

/// The head of a Timeline without a recorded Tick.
const NO_HEAD: FactualHeadV1 = FactualHeadV1 {
    tick: 0,
    last_seq: Seq::ZERO,
};

/// One segment of a Timeline's fork ancestry, as far as it is visible.
struct SegmentV1 {
    /// The segment's recorded set.
    set: DependencySetV1,
    /// Last `seq` a Tick of the segment may end on to be visible.
    limit: i64,
    /// Highest Tick of the segment that is visible.
    bound: i64,
}

/// At most one node, or the store's fault.
type NodeLookupV1 = Result<Option<DependencyNodeRecordV1>, CoreError>;

/// At most one node with its bound `seq`, or the store's fault.
type BoundLookupV1 = Result<Option<BoundFactualNodeV1>, CoreError>;

/// One entry per requested `seq`, or the store's fault.
type NodeListV1 = Result<Vec<Option<DependencyNodeRecordV1>>, CoreError>;

/// One entry per requested digest, or the store's fault.
type BoundListV1 = Result<Vec<Option<BoundFactualNodeV1>>, CoreError>;

/// Reads one row of a statement.
type RowReaderV1<T> = fn(&Row<'_>) -> rusqlite::Result<T>;

/// The Tick and last `seq` of the highest commit range that ends at or before
/// a limit.
const HEAD_SQL: &str = "SELECT tick, last_seq FROM counterfactual_dependency_commit_ranges
     WHERE timeline_id = ?1 AND last_seq <= ?2
     ORDER BY last_seq DESC LIMIT 1";

/// The Tick that a `seq` splits: the first commit range that ends after the
/// `seq` (`?2`), if it starts at or before it and ends within the limit (`?3`).
const SPLIT_SQL: &str = "SELECT tick FROM (
         SELECT tick, first_seq, last_seq FROM counterfactual_dependency_commit_ranges
         WHERE timeline_id = ?1 AND last_seq > ?2
         ORDER BY last_seq LIMIT 1
     ) WHERE first_seq <= ?2 AND last_seq <= ?3";

/// The node bound to a committed `seq` (`?2`), if its Tick is at or below the
/// bound (`?3`) in the prefix set (`?4`).
const EVENT_NODE_SQL: &str = "SELECT n.tick, n.scheduler_position, n.owner_id, n.output_ordinal,
            n.schema_id, n.artifact_digest, n.class, n.origin, n.input_digests,
            n.provenance_digest
     FROM counterfactual_dependency_event_nodes AS e
     JOIN counterfactual_dependency_nodes AS n
       ON n.timeline_id = e.timeline_id AND n.generation = ?4
      AND n.artifact_digest = e.artifact_digest
     WHERE e.timeline_id = ?1 AND e.seq = ?2 AND e.tick <= ?3";

/// The node with an artifact digest (`?3`) in the prefix set (`?2`), if its
/// Tick is at or below the bound (`?4`).
const DIGEST_NODE_SQL: &str = "SELECT tick, scheduler_position, owner_id, output_ordinal,
            schema_id, artifact_digest, class, origin, input_digests, provenance_digest
     FROM counterfactual_dependency_nodes
     WHERE timeline_id = ?1 AND generation = ?2 AND artifact_digest = ?3 AND tick <= ?4";

/// The latest step node (output ordinal zero) of an owner (`?3`) in the prefix
/// set (`?2`) at or below the bound (`?4`).
const STEP_NODE_SQL: &str = "SELECT tick, scheduler_position, owner_id, output_ordinal,
            schema_id, artifact_digest, class, origin, input_digests, provenance_digest
     FROM counterfactual_dependency_nodes
     WHERE timeline_id = ?1 AND generation = ?2 AND owner_id = ?3
       AND output_ordinal = 0 AND tick <= ?4
     ORDER BY tick DESC, scheduler_position DESC LIMIT 1";

/// The `seq` an artifact digest (`?2`) is bound to.
const BOUND_SEQ_SQL: &str = "SELECT seq FROM counterfactual_dependency_event_nodes
     WHERE timeline_id = ?1 AND artifact_digest = ?2";

/// The error of a stored row that fails the contract's checks.
fn factual_fault(error: StoreError) -> CoreError {
    CoreError::Storage(format!("factual prefix row is corrupt: {error:?}"))
}

/// Settle a staged read: a closed rejection is a corrupt row here.
fn unstaged<T>(staged: Staged<T>) -> Result<T, CoreError> {
    staged.and_then(|inner| inner.map_err(factual_fault))
}

/// Narrow a stored integer to `u64`; a negative is a corrupt row.
fn stored_unsigned(value: i64) -> Result<u64, CoreError> {
    stored_u64(value).map_err(factual_fault)
}

/// The first column of a row.
fn first_column(row: &Row<'_>) -> rusqlite::Result<i64> {
    row.get(0)
}

/// The Tick and last `seq` columns of a commit range row.
fn head_row(row: &Row<'_>) -> rusqlite::Result<(i64, i64)> {
    <(i64, i64)>::try_from(row)
}

/// The columns of a node row.
fn node_row(row: &Row<'_>) -> rusqlite::Result<NodeRowV1> {
    <NodeRowV1>::try_from(row)
}

/// Decode a stored node; a row that fails the contract's checks is corrupt.
fn decode_factual_node(row: NodeRowV1) -> Result<DependencyNodeRecordV1, CoreError> {
    decode_node(row).map_err(factual_fault)
}

/// Read at most one row of a statement.
fn optional_row<T>(
    conn: &Connection,
    sql: &str,
    query: impl Params,
    read: RowReaderV1<T>,
) -> Result<Option<T>, CoreError> {
    let mut statement = conn
        .prepare_cached(sql)
        .map_err(SqliteStore::into_storage_error)?;
    statement
        .query_row(query, read)
        .optional()
        .map_err(SqliteStore::into_storage_error)
}

/// Read and decode at most one node.
fn node_lookup(conn: &Connection, sql: &str, query: impl Params) -> NodeLookupV1 {
    optional_row(conn, sql, query, node_row)
        .and_then(|row| row.map(decode_factual_node).transpose())
}

/// The first result `find` yields over the segments, in the order given.
fn first_found<'a, T>(
    mut path: impl Iterator<Item = &'a SegmentV1>,
    find: impl Fn(&SegmentV1) -> Result<Option<T>, CoreError>,
) -> Result<Option<T>, CoreError> {
    path.try_fold(None, |found, segment| {
        found.map_or_else(|| find(segment), |done| Ok(Some(done)))
    })
}

/// One result of `find` per item, or the first fault.
fn each_of<T, R>(
    items: &[T],
    find: impl Fn(&T) -> Result<R, CoreError>,
) -> Result<Vec<R>, CoreError> {
    items.iter().map(find).collect()
}

/// The highest commit range of the Timeline's own set that ends at or before
/// `limit`, as its Tick and last `seq`.
fn head_through(
    conn: &Connection,
    timeline: &str,
    limit: i64,
) -> Result<Option<(i64, i64)>, CoreError> {
    optional_row(conn, HEAD_SQL, params![timeline, limit], head_row)
}

/// The visible head of a segment at or before `at`.
fn segment_head(
    conn: &Connection,
    segment: &SegmentV1,
    at: i64,
) -> Result<Option<FactualHeadV1>, CoreError> {
    let found = head_through(conn, &segment.set.timeline, at.min(segment.limit));
    found.and_then(|row| row.map(head_of).transpose())
}

/// The Tick the point `at` splits in a segment, if the Tick is visible.
fn segment_split(
    conn: &Connection,
    segment: &SegmentV1,
    at: i64,
) -> Result<Option<u64>, CoreError> {
    let found = optional_row(
        conn,
        SPLIT_SQL,
        params![segment.set.timeline, at, segment.limit],
        first_column,
    );
    found.and_then(|row| row.map(stored_unsigned).transpose())
}

/// Decode the Tick and last `seq` of a commit range.
fn head_of(row: (i64, i64)) -> Result<FactualHeadV1, CoreError> {
    let (tick, last) = row;
    let last_seq = stored_seq(last);
    stored_unsigned(tick).and_then(|found| {
        last_seq.map(|seq| FactualHeadV1 {
            tick: found,
            last_seq: seq,
        })
    })
}

/// A segment of an ancestor, visible through its cut.
fn ancestor_segment(
    conn: &Connection,
    ancestor: TimelineId,
    cut: Seq,
) -> Result<SegmentV1, CoreError> {
    let set = DependencySetV1::new(ancestor, PREFIX_GENERATION);
    let limit = seq_as_i64(cut);
    let head = head_through(conn, &set.timeline, limit);
    head.map(|found| SegmentV1 {
        bound: found.map_or(0, |(tick, _)| tick),
        set,
        limit,
    })
}

/// A set that is fully visible.
const fn whole(set: DependencySetV1) -> SegmentV1 {
    SegmentV1 {
        set,
        limit: i64::MAX,
        bound: i64::MAX,
    }
}

/// The ancestors' segments, then the Timeline's own, which is fully visible.
fn with_leaf(mut path: Vec<SegmentV1>, timeline: TimelineId) -> Vec<SegmentV1> {
    path.push(whole(DependencySetV1::new(timeline, PREFIX_GENERATION)));
    path
}

/// The segments of a Timeline's ancestry, oldest first, from its fork chain.
fn path_of(
    conn: &Connection,
    timeline: TimelineId,
    chain: &[(TimelineId, Seq)],
) -> Result<Vec<SegmentV1>, CoreError> {
    chain
        .iter()
        .zip(chain.iter().skip(1))
        .map(|(up, down)| ancestor_segment(conn, up.0, down.1))
        .collect::<Result<Vec<_>, CoreError>>()
        .map(|ancestors| with_leaf(ancestors, timeline))
}

/// The head of the Timeline's factual history.
fn last_head(conn: &Connection, path: &[SegmentV1]) -> Result<FactualHeadV1, CoreError> {
    let head = |segment: &SegmentV1| segment_head(conn, segment, i64::MAX);
    first_found(path.iter().rev(), head)
        .map(|found| found.unwrap_or(NO_HEAD))
}

/// Where a cut at `seq` falls in the visible Ticks.
fn cut_at(conn: &Connection, path: &[SegmentV1], seq: Seq) -> Result<FactualCutV1, CoreError> {
    let point = seq_as_i64(seq);
    let head = |segment: &SegmentV1| segment_head(conn, segment, point);
    let split = |segment: &SegmentV1| segment_split(conn, segment, point);
    let ended = first_found(path.iter().rev(), head);
    let inside = first_found(path.iter(), split);
    ended.and_then(|top| inside.map(|mid| cut_of(top, mid)))
}

/// The cut after the highest Tick that ends before it and the Tick it splits.
fn cut_of(ended: Option<FactualHeadV1>, split: Option<u64>) -> FactualCutV1 {
    let cut_tick = ended.map_or(0, |found| found.tick);
    let mid = |split_tick| FactualCutV1::MidTick {
        cut_tick,
        split_tick,
    };
    split.map_or(FactualCutV1::Boundary { cut_tick }, mid)
}

/// The node bound to a committed `seq` in a segment.
fn event_node(conn: &Connection, segment: &SegmentV1, seq: i64) -> NodeLookupV1 {
    node_lookup(
        conn,
        EVENT_NODE_SQL,
        params![segment.set.timeline, seq, segment.bound, PREFIX_GENERATION],
    )
}

/// The node with an artifact digest in a segment.
fn node_by_digest(conn: &Connection, segment: &SegmentV1, digest: &Hash) -> NodeLookupV1 {
    let bytes = digest.as_bytes().as_slice();
    node_lookup(
        conn,
        DIGEST_NODE_SQL,
        params![segment.set.timeline, PREFIX_GENERATION, bytes, segment.bound],
    )
}

/// The latest step node of an owner in a segment.
fn step_node(conn: &Connection, segment: &SegmentV1, owner: &str) -> NodeLookupV1 {
    node_lookup(
        conn,
        STEP_NODE_SQL,
        params![segment.set.timeline, PREFIX_GENERATION, owner, segment.bound],
    )
}

/// The `seq` an artifact digest is bound to in a segment.
fn bound_seq(
    conn: &Connection,
    segment: &SegmentV1,
    digest: &Hash,
) -> Result<Option<Seq>, CoreError> {
    let bytes = digest.as_bytes().as_slice();
    let found = optional_row(
        conn,
        BOUND_SEQ_SQL,
        params![segment.set.timeline, bytes],
        first_column,
    );
    found.and_then(|seq| seq.map(stored_seq).transpose())
}

/// Decode a stored `seq`.
fn stored_seq(value: i64) -> Result<Seq, CoreError> {
    stored_unsigned(value).map(Seq::from_u64)
}

/// The node with an artifact digest in a segment and the `seq` it is bound to.
fn digest_node(conn: &Connection, segment: &SegmentV1, digest: &Hash) -> BoundLookupV1 {
    let found = node_by_digest(conn, segment, digest);
    let bind = |node| bound_seq(conn, segment, digest).map(|seq| (node, seq));
    found.and_then(|held| held.map(bind).transpose())
}

/// The node bound to a committed `seq`, searching from the newest segment.
fn node_of_seq(conn: &Connection, path: &[SegmentV1], seq: Seq) -> NodeLookupV1 {
    let find = |segment: &SegmentV1| event_node(conn, segment, seq_as_i64(seq));
    first_found(path.iter().rev(), find)
}

/// The node of each committed `seq`.
fn event_nodes(conn: &Connection, path: &[SegmentV1], seqs: &[Seq]) -> NodeListV1 {
    each_of(seqs, |seq| node_of_seq(conn, path, *seq))
}

/// The node with an artifact digest, searching from the newest segment.
fn node_of_digest(conn: &Connection, path: &[SegmentV1], digest: &Hash) -> BoundLookupV1 {
    let find = |segment: &SegmentV1| digest_node(conn, segment, digest);
    first_found(path.iter().rev(), find)
}

/// The node of each artifact digest, with its bound `seq`.
fn digest_nodes(conn: &Connection, path: &[SegmentV1], digests: &[Hash]) -> BoundListV1 {
    each_of(digests, |digest| node_of_digest(conn, path, digest))
}

/// The latest step node of an owner, searching from the newest segment.
fn last_step(conn: &Connection, path: &[SegmentV1], owner: &FactualOwnerIdV1) -> NodeLookupV1 {
    let find = |segment: &SegmentV1| step_node(conn, segment, owner.as_str());
    first_found(path.iter().rev(), find)
}

/// The stored row counts of the Timeline's own committed prefix set.
fn prefix_counts(
    conn: &Connection,
    timeline: TimelineId,
) -> Result<RecordedSetCountsV1, CoreError> {
    let set = DependencySetV1::new(timeline, PREFIX_GENERATION);
    let state = unstaged(read_set_state(conn, &set));
    state.map(|read| read.counts)
}

impl SqliteStore {
    /// The Timeline's ancestry as segments, once it is visible and readable.
    fn factual_path(&self, timeline: TimelineId) -> Result<Vec<SegmentV1>, CoreError> {
        self.ensure_generic_timeline_visibility(timeline)
            .and_then(|()| self.authorized_fork_chain(timeline, READ))
            .and_then(|chain| path_of(&self.conn, timeline, &chain))
    }

    /// Run a factual read under the Timeline's erasure read fence and its
    /// inherited scopes, at one read point.
    fn read_factual<T>(
        &self,
        timeline: TimelineId,
        read: impl Fn(&Connection, &[SegmentV1]) -> Result<T, CoreError>,
    ) -> Result<T, CoreError> {
        let fenced = self.with_erasure_read_fence(timeline, READ, |store| {
            store.in_counterfactual_read(|held| {
                let path = held.factual_path(timeline);
                path.and_then(|found| read(&held.conn, &found)).map(Ok)
            })
        });
        unstaged(fenced)
    }
}

impl FactualPrefixReadPortV1 for SqliteStore {
    fn last_committed_factual_tick(
        &self,
        timeline: TimelineId,
    ) -> Result<FactualHeadV1, CoreError> {
        self.read_factual(timeline, last_head)
    }

    fn cut_tick_at(&self, timeline: TimelineId, seq: Seq) -> Result<FactualCutV1, CoreError> {
        self.read_factual(timeline, |conn, path| cut_at(conn, path, seq))
    }

    fn nodes_for_committed_events(
        &self,
        timeline: TimelineId,
        seqs: &[Seq],
    ) -> Result<Vec<Option<DependencyNodeRecordV1>>, CoreError> {
        self.read_factual(timeline, |conn, path| event_nodes(conn, path, seqs))
    }

    fn nodes_by_digest(
        &self,
        timeline: TimelineId,
        digests: &[Hash],
    ) -> Result<Vec<Option<BoundFactualNodeV1>>, CoreError> {
        self.read_factual(timeline, |conn, path| digest_nodes(conn, path, digests))
    }

    fn last_step_node(
        &self,
        timeline: TimelineId,
        owner: &FactualOwnerIdV1,
    ) -> Result<Option<DependencyNodeRecordV1>, CoreError> {
        self.read_factual(timeline, |conn, path| last_step(conn, path, owner))
    }

    fn factual_set_counts(&self, timeline: TimelineId) -> Result<RecordedSetCountsV1, CoreError> {
        self.read_factual(timeline, |conn, _| prefix_counts(conn, timeline))
    }
}

#[cfg(any(test, feature = "test-support"))]
const INSERT_RANGE_SQL: &str = "INSERT INTO counterfactual_dependency_commit_ranges
     (timeline_id, tick, first_seq, last_seq) VALUES (?1, ?2, ?3, ?4)";

#[cfg(any(test, feature = "test-support"))]
const INSERT_BINDING_SQL: &str = "INSERT INTO counterfactual_dependency_event_nodes
     (timeline_id, seq, tick, artifact_digest) VALUES (?1, ?2, ?3, ?4)";

/// Insert the commit range of a seeded Tick.
#[cfg(any(test, feature = "test-support"))]
fn insert_commit_range(
    conn: &Connection,
    timeline: &str,
    tick: i64,
    seeded: &SeededFactualTickV1,
) -> Result<(), CoreError> {
    let first = seq_as_i64(seeded.first_seq);
    let last = seq_as_i64(seeded.last_seq);
    conn.execute(INSERT_RANGE_SQL, params![timeline, tick, first, last])
        .map(|_| ())
        .map_err(SqliteStore::into_storage_error)
}

/// Insert the Event bindings of a seeded Tick.
#[cfg(any(test, feature = "test-support"))]
fn insert_event_nodes(
    conn: &Connection,
    timeline: &str,
    tick: i64,
    seeded: &SeededFactualTickV1,
) -> Result<(), CoreError> {
    let bindings = &seeded.event_nodes;
    conn.prepare_cached(INSERT_BINDING_SQL)
        .and_then(|mut statement| {
            bindings.iter().try_for_each(|(seq, digest)| {
                let bytes = digest.as_bytes().as_slice();
                statement
                    .execute(params![timeline, seq_as_i64(*seq), tick, bytes])
                    .map(|_| ())
            })
        })
        .map_err(SqliteStore::into_storage_error)
}

/// Install one committed Tick of the Timeline's prefix set: its record,
/// nodes, and edges, its commit range, and its Event bindings.
///
/// The one insert path of a committed prefix: the `test-support` seeding
/// function calls it now, and the pipeline commit calls it once it records
/// factual Ticks.
#[cfg(any(test, feature = "test-support"))]
fn install_factual_tick(
    conn: &Connection,
    timeline: TimelineId,
    seeded: &SeededFactualTickV1,
) -> Result<(), CoreError> {
    let set = DependencySetV1::new(timeline, PREFIX_GENERATION);
    let tick = sql_tick(seeded.record.tick());
    insert_dependency_record(conn, &set, tick, &seeded.record)
        .and_then(|()| insert_commit_range(conn, &set.timeline, tick, seeded))
        .and_then(|()| insert_event_nodes(conn, &set.timeline, tick, seeded))
}

#[cfg(any(test, feature = "test-support"))]
impl SqliteStore {
    /// Seed committed factual Ticks into a Timeline's committed prefix set,
    /// through the install path the pipeline commit uses, in one transaction.
    ///
    /// Test seam only: it checks nothing about the Ticks it is given.
    ///
    /// # Errors
    /// Returns `TimelineNotFound` for an unknown Timeline, or the store's
    /// error when a row cannot be inserted.
    #[doc(hidden)]
    pub fn seed_factual_prefix(
        &mut self,
        timeline: TimelineId,
        ticks: &[SeededFactualTickV1],
    ) -> Result<(), CoreError> {
        self.ensure_timeline_exists(timeline).and_then(|()| {
            self.conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(Self::into_storage_error)
                .and_then(|tx| {
                    ticks
                        .iter()
                        .try_for_each(|held| install_factual_tick(&tx, timeline, held))
                        .and_then(|()| tx.commit().map_err(Self::into_storage_error))
                })
        })
    }
}

#[cfg(test)]
mod tests {
    use pos_core::{
        CounterfactualStorePortV1, Seq, MAX_DEPENDENCY_EDGE_BYTES_V1,
        MAX_DEPENDENCY_NODE_INPUTS_V1, MAX_DEPENDENCY_OWNER_ID_BYTES_V1,
    };

    use super::super::tests::{
        command, drafts, fail_commits, ok, open_file_store, publish_fork, published_store,
    };
    use super::*;

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn one_node_record(tick: u64, digest: u8) -> TickDependencyRecordV1 {
        let coordinate = ok(DependencyNodeCoordinateV1::try_new(
            tick,
            0,
            "a".to_owned(),
            0,
            7,
            Hash::from_bytes([digest; 32]),
        ));
        let node = ok(DependencyNodeRecordV1::try_new(
            coordinate,
            RecordedDependencyClassV1::EndogenousRecomputed,
            RecordedNodeOriginV1::Provisional,
            Vec::new(),
            Hash::from_bytes([9; 32]),
        ));
        ok(TickDependencyRecordV1::try_new(
            tick,
            RecordedNodeOriginV1::Provisional,
            vec![node],
            Vec::new(),
        ))
    }

    /// Rows of the three dependency tables.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn recorded(store: &SqliteStore) -> i64 {
        ok(store.conn.query_row(
            "SELECT (SELECT count(*) FROM counterfactual_dependency_records)
                  + (SELECT count(*) FROM counterfactual_dependency_nodes)
                  + (SELECT count(*) FROM counterfactual_dependency_edges)",
            [],
            |row| row.get::<_, i64>(0),
        ))
    }

    /// Rows an invalidation writes beside the Events: generations, quarantine,
    /// and artifacts.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn written(store: &SqliteStore) -> i64 {
        ok(store.conn.query_row(
            "SELECT (SELECT count(*) FROM counterfactual_generations)
                  + (SELECT count(*) FROM counterfactual_quarantine)
                  + (SELECT count(*) FROM counterfactual_artifacts)",
            [],
            |row| row.get::<_, i64>(0),
        ))
    }

    /// An in-doubt invalidation with a record is `OutcomeUnknown`, records
    /// nothing, and the same command and record commit on the retry.
    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn an_in_doubt_invalidation_with_dependencies_records_nothing() {
        let (mut store, fork) = published_store();
        let command = command(fork);
        let record = one_node_record(1, 1);

        fail_commits(&store, true);
        let in_doubt =
            store.commit_counterfactual_invalidation_with_dependencies(&command, &record);
        fail_commits(&store, false);

        assert_eq!(in_doubt, Err(StoreError::OutcomeUnknown));
        assert_eq!(recorded(&store), 0);
        assert_eq!(
            store.committed_generation_receipt(command.new_generation()),
            Ok(None)
        );
        assert!(matches!(
            store.commit_counterfactual_invalidation_with_dependencies(&command, &record),
            Ok(CounterfactualInvalidationOutcomeV1::Committed(_))
        ));
        assert_eq!(recorded(&store), 2);
    }

    /// An in-doubt later Tick with a record is `OutcomeUnknown` and records
    /// nothing; the unmoved basis proves it and the retry commits.
    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn an_in_doubt_tick_with_dependencies_records_nothing() {
        let (mut store, fork) = published_store();
        ok(store.commit_counterfactual_invalidation_with_dependencies(
            &command(fork),
            &one_node_record(1, 1),
        ));
        let expected = ok(store.current_counterfactual_basis(fork));
        let record = one_node_record(2, 2);

        fail_commits(&store, true);
        let in_doubt =
            store.append_counterfactual_tick_with_dependencies(fork, &expected, &drafts(), &record);
        fail_commits(&store, false);

        assert_eq!(in_doubt, Err(StoreError::OutcomeUnknown));
        assert_eq!(recorded(&store), 2);
        assert_eq!(store.current_counterfactual_basis(fork), Ok(expected));
        assert_eq!(
            store
                .append_counterfactual_tick_with_dependencies(fork, &expected, &drafts(), &record,),
            Ok(CounterfactualTickOutcomeV1::Committed {
                head: Seq::from_u64(3)
            })
        );
        assert_eq!(recorded(&store), 4);
    }

    /// A file-backed in-doubt write leaves no partial row once the file is
    /// reopened, and the retry of the same command and record commits.
    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn a_file_backed_in_doubt_write_leaves_no_partial_rows_after_reopen() {
        let directory = ok(tempfile::tempdir());
        let path = directory
            .path()
            .join("in-doubt.db")
            .to_string_lossy()
            .into_owned();
        let (mut store, fork) = publish_fork(open_file_store(&path));
        let command = command(fork);
        let record = one_node_record(1, 1);

        fail_commits(&store, true);
        let in_doubt =
            store.commit_counterfactual_invalidation_with_dependencies(&command, &record);
        fail_commits(&store, false);
        assert_eq!(in_doubt, Err(StoreError::OutcomeUnknown));
        drop(store);

        let mut reopened = open_file_store(&path);
        assert_eq!([recorded(&reopened), written(&reopened)], [0, 0]);
        assert_eq!(
            reopened.committed_generation_receipt(command.new_generation()),
            Ok(None)
        );
        assert!(matches!(
            reopened.commit_counterfactual_invalidation_with_dependencies(&command, &record),
            Ok(CounterfactualInvalidationOutcomeV1::Committed(_))
        ));
        assert_eq!(recorded(&reopened), 2);
        let expected = ok(reopened.current_counterfactual_basis(fork));
        let later = one_node_record(2, 2);

        fail_commits(&reopened, true);
        let tick_in_doubt = reopened.append_counterfactual_tick_with_dependencies(
            fork,
            &expected,
            &drafts(),
            &later,
        );
        fail_commits(&reopened, false);
        assert_eq!(tick_in_doubt, Err(StoreError::OutcomeUnknown));
        drop(reopened);

        let mut again = open_file_store(&path);
        assert_eq!(recorded(&again), 2);
        assert_eq!(again.current_counterfactual_basis(fork), Ok(expected));
        assert_eq!(
            again.append_counterfactual_tick_with_dependencies(fork, &expected, &drafts(), &later,),
            Ok(CounterfactualTickOutcomeV1::Committed {
                head: Seq::from_u64(3)
            })
        );
        assert_eq!(recorded(&again), 4);
    }

    /// The `CHECK` text repeats the contract's bounds as literals; each must
    /// appear in it and equal the `pos-core` constant.
    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn the_check_literals_equal_the_contract_bounds() {
        let owner = MAX_DEPENDENCY_OWNER_ID_BYTES_V1;
        let word = u32::MAX;
        let inputs = MAX_DEPENDENCY_NODE_INPUTS_V1 * HASH_BYTES;
        let edge_bytes = MAX_DEPENDENCY_EDGE_BYTES_V1;
        let node_text = NODES_TABLE.constraints.join("\n");
        let edge_text = EDGES_TABLE.constraints.join("\n");
        let checks = [
            (&node_text, format!("BETWEEN 1 AND {owner})")),
            (
                &node_text,
                format!("scheduler_position BETWEEN 0 AND {word})"),
            ),
            (&node_text, format!("output_ordinal BETWEEN 0 AND {word})")),
            (&node_text, format!("schema_id BETWEEN 1 AND {word})")),
            (&node_text, format!("length(input_digests) <= {inputs})")),
            (&edge_text, format!("BETWEEN 1 AND {owner})")),
            (
                &edge_text,
                format!("scheduler_position BETWEEN 0 AND {word})"),
            ),
            (&edge_text, format!("output_ordinal BETWEEN 0 AND {word})")),
            (
                &edge_text,
                format!("consumer_schema_id BETWEEN 1 AND {word})"),
            ),
            (&edge_text, format!("length(edge_bytes) <= {edge_bytes})")),
        ];
        for (text, needle) in &checks {
            assert!(text.contains(needle.as_str()), "{needle}");
        }
    }
}
