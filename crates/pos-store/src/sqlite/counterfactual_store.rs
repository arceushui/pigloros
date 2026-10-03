//! `SQLite` adapter and additive schema for the ADR-064 counterfactual
//! storage port.
//!
//! [`CounterfactualStorePortV1::commit_counterfactual_invalidation`] runs in
//! one `BEGIN IMMEDIATE` transaction: it reads the persisted
//! [`CounterfactualBasisV1`], and either reports the first conflict or appends
//! the first recomputation Tick's Events to the Fork Timeline, records the
//! exact `RCF1`/`SIV1` bytes under the new generation, quarantines the
//! invalid-artifact index and the eviction set, and advances the Fork
//! generation. Any failure rolls the whole transaction back.
//!
//! # Schema
//!
//! Four additive tables (`counterfactual_forks`, `counterfactual_generations`,
//! `counterfactual_quarantine`, `counterfactual_artifacts`), one lookup index,
//! and four guard triggers are created with `IF NOT EXISTS` by every writable
//! open, so migration is additive and idempotent. Every open, including a
//! read-only one, validates the exact table shapes, the index, and the trigger
//! bodies, and fails closed with a storage error on any drift. The triggers
//! make the database itself refuse to decrease a Fork generation, delete a
//! Fork's counterfactual state, or delete or rewrite a quarantine row, so a
//! rolled-back coordinator version cannot reactivate an invalidated artifact.
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
//!   [`SqliteStore::publish_counterfactual_facts`]; the first publication
//!   starts the Fork at generation `0`, and a republication replaces only the
//!   facts, never the generation or the stored artifacts.
//! - **Readable artifacts.** The committed `RCF1` and `SIV1` bytes become
//!   readable by their self-digests at the new generation. Staging later
//!   recomputed outputs is owned by the coordinator slices, not this adapter.
//! - **Quarantine.** The invalid-artifact index (kind `0`) and the
//!   cache/checkpoint eviction set (kind `1`) are both stored exactly, per
//!   generation, and every member is quarantined permanently: a read reports
//!   it as [`StoredCounterfactualArtifactV1::Quarantined`] even when this
//!   store holds its bytes, which stay retained for audit only.
//! - **Containment.** The commit appends Events, so it runs under the ADR-060
//!   erasure write fence and, like every generic Fork append, is rejected on an
//!   ADR-099 admitted Fork whose appends are reserved for the classified append
//!   authority. Publishing facts and reads touch no Timeline Events and are
//!   not fenced.
//! - **Timeline deletion.** Deleting a Fork Timeline keeps its counterfactual
//!   rows, which the triggers protect; a Timeline later created with the same
//!   ID continues at the retained generation rather than resetting it.
//! - **Errors.** A missing, deleted, non-Fork, unpublished, or protected
//!   Timeline is `ForkNotFound`; every other backend failure, including a
//!   containment denial, is `StorageFailure`. Unlike the in-memory adapter,
//!   `SQLite` stores signed 64-bit integers: a generation, epoch, or Tick
//!   above `i64::MAX` is `FieldOutOfBounds` before any transaction, and a
//!   persisted value outside its range is `CorruptState`. Every rejection is
//!   decided by reads before the first write, so a rejected transaction
//!   commits nothing.

use pos_core::{
    CoreError, CounterfactualBasisV1, CounterfactualInvalidationCommandV1,
    CounterfactualInvalidationOutcomeV1, CounterfactualStoreErrorV1, CounterfactualStorePortV1,
    ErasureProtectedOperationV1, ForkGenerationV1, Hash, Seq, StoredCounterfactualArtifactV1,
    TimelineId,
};
use rusqlite::{params, Connection, OptionalExtension};

use super::{
    begin_immediate_scope, finish_immediate_scope, normalize_schema_sql, sqlite_schema_ddl,
    SqliteSchemaColumn, SqliteSchemaTable, SqliteStore,
};

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
        ],
        constraints: &[
            "CHECK (generation >= 1)",
            "CHECK (length(frontier_digest) = 32)",
            "CHECK (length(invalidation_digest) = 32)",
            "CHECK (first_tick >= 0)",
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
                primary_key: false,
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
];

/// One named index or trigger and the exact body every open requires.
struct CounterfactualSchemaObjectV1 {
    kind: &'static str,
    name: &'static str,
    body: &'static str,
}

/// The quarantine lookup index and the guards that keep generations
/// monotonic and quarantine permanent.
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
               BEGIN SELECT RAISE(ABORT, 'counterfactual generation is retained'); END",
    },
    CounterfactualSchemaObjectV1 {
        kind: "trigger",
        name: "counterfactual_quarantine_retained",
        body: "BEFORE DELETE ON counterfactual_quarantine
               BEGIN SELECT RAISE(ABORT, 'quarantined artifact cannot be reactivated'); END",
    },
    CounterfactualSchemaObjectV1 {
        kind: "trigger",
        name: "counterfactual_quarantine_immutable",
        body: "BEFORE UPDATE ON counterfactual_quarantine
               BEGIN SELECT RAISE(ABORT, 'quarantined artifact cannot be reactivated'); END",
    },
];

/// Host-published facts every invalidation of one Fork is rechecked against;
/// the generation and Logical Head are owned by the store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqliteCounterfactualFactsV1 {
    /// Admitted counterfactual plan digest.
    pub plan_digest: Hash,
    /// Committed dependency-graph digest frontiers are derived from.
    pub dependency_graph_digest: Hash,
    /// Current trust-policy epoch.
    pub trust_epoch: u64,
    /// Current authority revocation epoch.
    pub revocation_epoch: u64,
    /// Current erasure epoch.
    pub erasure_epoch: u64,
}

/// Decoded `counterfactual_forks` row.
#[derive(Clone, Copy)]
struct ForkStateV1 {
    generation: u64,
    plan_digest: Hash,
    dependency_graph_digest: Hash,
    trust_epoch: u64,
    revocation_epoch: u64,
    erasure_epoch: u64,
}

impl ForkStateV1 {
    /// The persisted basis at the Fork's live Logical Head.
    const fn basis(self, fork_logical_head: Seq) -> CounterfactualBasisV1 {
        CounterfactualBasisV1 {
            fork_logical_head,
            plan_digest: self.plan_digest,
            dependency_graph_digest: self.dependency_graph_digest,
            generation: self.generation,
            trust_epoch: self.trust_epoch,
            revocation_epoch: self.revocation_epoch,
            erasure_epoch: self.erasure_epoch,
        }
    }
}

/// Raw `counterfactual_forks` columns before range validation.
type ForkStateRowV1 = (i64, Vec<u8>, Vec<u8>, i64, i64, i64);

/// Raw generation, quarantine flag, and staged bytes of one artifact lookup.
type StoredArtifactRowV1 = (i64, bool, Option<Vec<u8>>);

fn decode_fork_state(row: ForkStateRowV1) -> Result<ForkStateV1, StoreError> {
    let (generation, plan_digest, dependency_graph_digest, trust, revocation, erasure) = row;
    Ok(ForkStateV1 {
        generation: stored_u64(generation)?,
        plan_digest: stored_hash(plan_digest)?,
        dependency_graph_digest: stored_hash(dependency_graph_digest)?,
        trust_epoch: stored_u64(trust)?,
        revocation_epoch: stored_u64(revocation)?,
        erasure_epoch: stored_u64(erasure)?,
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

/// Classify one artifact lookup; quarantine wins over staged bytes.
fn stored_artifact(quarantined: bool, bytes: Option<Vec<u8>>) -> StoredCounterfactualArtifactV1 {
    match (quarantined, bytes) {
        (true, _) => StoredCounterfactualArtifactV1::Quarantined,
        (false, None) => StoredCounterfactualArtifactV1::Absent,
        (false, Some(bytes)) => StoredCounterfactualArtifactV1::Authoritative(bytes),
    }
}

/// A missing Timeline is `ForkNotFound`; every other backend error is a
/// storage failure whose outcome the caller must not assume.
const fn port_error(error: &CoreError) -> StoreError {
    if matches!(error, CoreError::TimelineNotFound(_)) {
        StoreError::ForkNotFound
    } else {
        StoreError::StorageFailure
    }
}

fn settle<T>(staged: Staged<T>) -> Result<T, StoreError> {
    staged.unwrap_or_else(|error| Err(port_error(&error)))
}

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

/// Read the generation and one artifact's state in a single statement, so
/// the pair is one consistent snapshot.
fn read_artifact_state(
    conn: &Connection,
    fork: TimelineId,
    artifact_digest: Hash,
) -> Staged<(u64, StoredCounterfactualArtifactV1)> {
    conn.query_row(
        "SELECT forks.generation,
                EXISTS (
                    SELECT 1 FROM counterfactual_quarantine AS quarantine
                    WHERE quarantine.fork_id = forks.fork_id
                      AND quarantine.artifact_digest = ?2
                ),
                (
                    SELECT artifacts.artifact_bytes FROM counterfactual_artifacts AS artifacts
                    WHERE artifacts.fork_id = forks.fork_id
                      AND artifacts.artifact_digest = ?2
                )
         FROM counterfactual_forks AS forks WHERE forks.fork_id = ?1",
        params![fork.to_string(), artifact_digest.as_bytes().as_slice()],
        |row| <StoredArtifactRowV1>::try_from(row),
    )
    .optional()
    .map_err(SqliteStore::into_storage_error)
    .map(|row| {
        row.ok_or(StoreError::ForkNotFound)
            .and_then(|(generation, quarantined, bytes)| {
                stored_u64(generation)
                    .map(|generation| (generation, stored_artifact(quarantined, bytes)))
            })
    })
}

/// Read the committed generation before publishing, or `0` for a first
/// publication.
fn published_generation(conn: &Connection, fork: TimelineId) -> Staged<u64> {
    conn.query_row(
        "SELECT generation FROM counterfactual_forks WHERE fork_id = ?1",
        params![fork.to_string()],
        |row| row.get::<_, i64>(0),
    )
    .optional()
    .map_err(SqliteStore::into_storage_error)
    .map(|generation| generation.map_or(Ok(0), stored_u64))
}

fn upsert_fork_facts(
    conn: &Connection,
    fork: TimelineId,
    facts: &SqliteCounterfactualFactsV1,
    epochs: [i64; 3],
) -> Result<(), CoreError> {
    conn.execute(
        "INSERT INTO counterfactual_forks
         (fork_id, generation, plan_digest, dependency_graph_digest,
          trust_epoch, revocation_epoch, erasure_epoch)
         VALUES (?1, 0, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(fork_id) DO UPDATE SET
             plan_digest = excluded.plan_digest,
             dependency_graph_digest = excluded.dependency_graph_digest,
             trust_epoch = excluded.trust_epoch,
             revocation_epoch = excluded.revocation_epoch,
             erasure_epoch = excluded.erasure_epoch",
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

/// Record the exact `RCF1`/`SIV1` bytes, make them readable by their
/// digests, and advance the Fork generation.
fn insert_generation(
    conn: &Connection,
    command: &CounterfactualInvalidationCommandV1,
    generation: i64,
    first_tick: i64,
) -> Result<(), CoreError> {
    let fork = command.fork().to_string();
    conn.execute(
        "INSERT INTO counterfactual_generations
         (fork_id, generation, frontier_digest, frontier_bytes,
          invalidation_digest, invalidation_bytes, first_tick)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            fork,
            generation,
            command.frontier().digest().as_bytes().as_slice(),
            command.frontier().as_bytes(),
            command.invalidation().digest().as_bytes().as_slice(),
            command.invalidation().as_bytes(),
            first_tick,
        ],
    )
    .and_then(|_| {
        conn.prepare_cached(
            "INSERT OR IGNORE INTO counterfactual_artifacts
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
    /// triggers, then validate their shape.
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
    /// creating them.
    pub(super) fn validate_counterfactual_schema(&self) -> Result<(), CoreError> {
        COUNTERFACTUAL_SCHEMA_TABLES
            .iter()
            .try_for_each(|table| self.validate_sqlite_schema_table(table))
            .and_then(|()| {
                COUNTERFACTUAL_SCHEMA_OBJECTS
                    .iter()
                    .try_for_each(|object| self.validate_counterfactual_schema_object(object))
            })
    }

    /// Require one index or trigger with its exact body.
    fn validate_counterfactual_schema_object(
        &self,
        object: &CounterfactualSchemaObjectV1,
    ) -> Result<(), CoreError> {
        let expected = normalize_schema_sql(object.body);
        self.conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = ?1 AND name = ?2",
                params![object.kind, object.name],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(Self::into_storage_error)
            .and_then(|sql| {
                if sql.is_some_and(|sql| normalize_schema_sql(&sql).contains(&expected)) {
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
    /// inventory. Rejections are decided before the first write, so an inner
    /// rejection commits nothing.
    fn in_counterfactual_scope<T>(&self, work: impl FnOnce(&Self) -> Staged<T>) -> Staged<T> {
        begin_immediate_scope(&self.conn).and_then(|scope| {
            let result = self
                .validate_erasure_inventory_data_version()
                .and_then(|()| work(self));
            finish_immediate_scope(&self.conn, scope, result)
        })
    }

    /// Require a visible Fork; a root Timeline is not a Fork.
    fn visible_counterfactual_fork(&self, fork: TimelineId) -> Staged<()> {
        self.ensure_generic_timeline_visibility(fork)
            .and_then(|()| Self::fork_chain_on(&self.conn, fork))
            .map(|chain| {
                if chain.len() > 1 {
                    Ok(())
                } else {
                    Err(StoreError::ForkNotFound)
                }
            })
    }

    /// Read the persisted basis an invalidation is rechecked against.
    fn persisted_counterfactual_basis(&self, fork: TimelineId) -> Staged<CounterfactualBasisV1> {
        self.ensure_generic_fork_append_is_rejected(fork)
            .and_then(|()| {
                then_staged(self.visible_counterfactual_fork(fork), |()| {
                    then_staged(read_fork_state(&self.conn, fork), |state| {
                        Self::logical_head_unchecked_on(&self.conn, fork)
                            .map(|head| Ok(state.basis(head)))
                    })
                })
            })
    }

    /// Append the first Tick, then record the generation and quarantine;
    /// return the Fork Logical Head after the first Tick.
    fn write_counterfactual_generation(
        &self,
        command: &CounterfactualInvalidationCommandV1,
        generation: i64,
        first_tick: i64,
    ) -> Result<Seq, CoreError> {
        let fork = command.fork();
        command
            .first_tick_drafts()
            .drafts()
            .iter()
            .try_for_each(|draft| {
                Self::append_one_in_transaction(
                    &self.conn,
                    self.hasher.as_ref(),
                    fork,
                    draft.clone(),
                )
                .map(|_| ())
            })
            .and_then(|()| insert_generation(&self.conn, command, generation, first_tick))
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
            .and_then(|()| Self::logical_head_unchecked_on(&self.conn, fork))
    }

    /// Publish the host-owned counterfactual facts of one Fork.
    ///
    /// The first publication starts the Fork at generation `0`. A later one
    /// replaces only the facts; the committed generation and artifacts stay.
    ///
    /// # Errors
    /// Returns `FieldOutOfBounds` for an epoch above `i64::MAX`, `ForkNotFound`
    /// unless `fork` is a visible Fork Timeline, `CorruptState` for a stored
    /// generation outside its range, and `StorageFailure` when the database
    /// rejects the write.
    pub fn publish_counterfactual_facts(
        &mut self,
        fork: TimelineId,
        facts: SqliteCounterfactualFactsV1,
    ) -> Result<ForkGenerationV1, CounterfactualStoreErrorV1> {
        let epochs = sql_integer(facts.trust_epoch).and_then(|trust| {
            sql_integer(facts.revocation_epoch).and_then(|revocation| {
                sql_integer(facts.erasure_epoch).map(|erasure| [trust, revocation, erasure])
            })
        })?;
        settle(self.in_counterfactual_scope(|store| {
            then_staged(store.visible_counterfactual_fork(fork), |()| {
                then_staged(published_generation(&store.conn, fork), |generation| {
                    upsert_fork_facts(&store.conn, fork, &facts, epochs)
                        .map(|()| Ok(ForkGenerationV1 { fork, generation }))
                })
            })
        }))
    }
}

impl CounterfactualStorePortV1 for SqliteStore {
    fn commit_counterfactual_invalidation(
        &mut self,
        command: &CounterfactualInvalidationCommandV1,
    ) -> Result<CounterfactualInvalidationOutcomeV1, StoreError> {
        let fork = command.fork();
        let generation = sql_integer(command.new_generation().generation)?;
        let first_tick = sql_integer(command.first_tick())?;
        settle(
            self.with_erasure_fence(fork, ErasureProtectedOperationV1::Append, |store| {
                store.in_counterfactual_scope(|store| {
                    then_staged(store.persisted_counterfactual_basis(fork), |persisted| {
                        match command.expected_basis().first_conflict(&persisted) {
                            Some(conflict) => Ok(Ok(
                                CounterfactualInvalidationOutcomeV1::InvalidationConflict(conflict),
                            )),
                            None => store
                                .write_counterfactual_generation(command, generation, first_tick)
                                .map(|head| {
                                    Ok(CounterfactualInvalidationOutcomeV1::Committed(
                                        command.committed_receipt(head),
                                    ))
                                }),
                        }
                    })
                })
            }),
        )
    }

    fn current_fork_generation(&self, fork: TimelineId) -> Result<ForkGenerationV1, StoreError> {
        settle(then_staged(self.visible_counterfactual_fork(fork), |()| {
            read_fork_state(&self.conn, fork)
        }))
        .map(|state| ForkGenerationV1 {
            fork,
            generation: state.generation,
        })
    }

    fn read_generation_artifact(
        &self,
        at: ForkGenerationV1,
        artifact_digest: Hash,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        settle(then_staged(
            self.visible_counterfactual_fork(at.fork),
            |()| read_artifact_state(&self.conn, at.fork, artifact_digest),
        ))
        .and_then(|(current, stored)| at.resolve_read(current, stored))
    }
}
