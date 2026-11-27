#![cfg(all(target_os = "linux", any(test, feature = "test-support")))]
//! ADR-097 B6 readiness reconciliation of the erasure fence rows.
//!
//! The fence rows are written in the erasure CAS transaction, so a crash, an
//! older store or a writer that predates [`super::erasure_fence_rows`] can
//! leave frozen Timelines without a row. Before the Gateway reports Ready,
//! [`SqliteStore::reconcile_erasure_fence_rows`] derives the rows the verified
//! ERS1, ERSC1 and ERSE1 chains require and repairs the table to match, in one
//! `BEGIN IMMEDIATE` transaction.
//!
//! The only evidence is an [`ErasureVerifiedInventoryV1`], which core builds
//! after recovering and authorizing every request's complete ERCRP1 graph. The
//! rules follow ADR-097 B6:
//!
//! - `Submitted` and `Authorized` requests expect no row.
//! - `Rejected` requests expect no row, and their rows are the only ones the
//!   reconciliation deletes: the verified `Rejected` state is the canonical
//!   proof. A Rejected request's row is never recreated.
//! - `AccessFrozen` through `PartialFailure` expect one row per resolved scope
//!   Timeline and per ERSE1 child Timeline, all at the verified lifecycle.
//!   A missing row is inserted. A row at another lifecycle is changed to the
//!   verified one only when ADR-060's forward edges lead from the stored
//!   lifecycle to it; the numeric order of the codes is never consulted.
//!
//! Everything else refuses and leaves the table untouched: a row the chains do
//! not require (a row of a pre-freeze or unknown request, or an extra
//! Timeline), a row ahead of or beside its verified lifecycle, and a row that
//! does not parse. A fence is never deleted without `Rejected` proof. The
//! transaction also re-reads every request head and refuses when the
//! inventory no longer describes the store, so a chain that advanced after the
//! recovery cannot be reconciled against a stale view.
//!
//! The Gateway reports Ready only after this returns `Ok`. Like the table
//! itself, this module stays test-support gated until owner activation
//! (#1438); ungating removes the `cfg` gates of all three fence modules and
//! the calls in `sqlite.rs` together.

use std::collections::{BTreeMap, BTreeSet};

use pos_core::{
    ErasureLifecycleV1, ErasureVerifiedInventoryV1, ErasureVerifiedStateV1, TimelineId,
};
use rusqlite::{params, Connection, TransactionBehavior};

use super::SqliteStore;

const HEADS_SQL: &str = "SELECT request_digest, manifest_digest FROM erasure_records";
const ROWS_SQL: &str =
    "SELECT timeline_id, erasure_request_id, lifecycle_code FROM erasure_fence_rows";
const DELETE_SQL: &str = "DELETE FROM erasure_fence_rows WHERE erasure_request_id = ?1";
const UPSERT_SQL: &str = "INSERT INTO erasure_fence_rows
         (timeline_id, erasure_request_id, lifecycle_code) VALUES (?1, ?2, ?3)
     ON CONFLICT (timeline_id, erasure_request_id)
     DO UPDATE SET lifecycle_code = excluded.lifecycle_code";

/// The lifecycles B6 mirrors into rows, `AccessFrozen` through `PartialFailure`.
const MIRRORED: [ErasureLifecycleV1; 5] = [
    ErasureLifecycleV1::AccessFrozen,
    ErasureLifecycleV1::DestructionDispatched,
    ErasureLifecycleV1::AwaitingAcknowledgements,
    ErasureLifecycleV1::Complete,
    ErasureLifecycleV1::PartialFailure,
];

/// The longest simple path of ADR-060 edges among the mirrored lifecycles
/// (`AccessFrozen`, `DestructionDispatched`, `AwaitingAcknowledgements`,
/// `PartialFailure`, `Complete`); `PartialFailure` also loops on itself.
const MAX_EDGES: u8 = 4;

/// A stored row's key: the canonical Timeline text and the 32-byte request.
type RowKey = (String, Vec<u8>);

/// Why the reconciliation refused. Every variant fails closed and rolls back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErasureFenceReconcileErrorV1 {
    /// The store could not be read or written, or a stored value has the wrong
    /// type.
    Unreadable,
    /// The inventory does not describe the store's current request heads.
    StaleInventory,
    /// The rows and the verified chains contradict each other.
    Contradictory,
}

/// What the verified chains require of the table.
#[derive(Default)]
struct Expectation {
    /// Every row that must exist, with its lifecycle code.
    expected: BTreeMap<RowKey, i64>,
    /// Requests proven `Rejected`, whose rows are deleted.
    cleared: BTreeSet<Vec<u8>>,
}

fn unreadable(_: rusqlite::Error) -> ErasureFenceReconcileErrorV1 {
    ErasureFenceReconcileErrorV1::Unreadable
}

fn code_of(lifecycle: ErasureLifecycleV1) -> i64 {
    i64::from(lifecycle as u8)
}

fn lifecycle_of(code: i64) -> Option<ErasureLifecycleV1> {
    MIRRORED
        .into_iter()
        .find(|lifecycle| code_of(*lifecycle) == code)
}

/// Whether the forward edges lead from `from` to `to` in at most `edges` steps.
fn reaches(from: ErasureLifecycleV1, to: ErasureLifecycleV1, edges: u8) -> bool {
    from == to
        || (edges > 0
            && MIRRORED
                .iter()
                .any(|next| from.permits(*next) && reaches(*next, to, edges - 1)))
}

/// The Timelines of a frozen request: its scope and its ERSE1 children.
fn frozen_timelines(
    state: &ErasureVerifiedStateV1,
) -> Result<Vec<TimelineId>, ErasureFenceReconcileErrorV1> {
    state
        .scope()
        .ok_or(ErasureFenceReconcileErrorV1::Contradictory)
        .map(|scope| {
            scope
                .scope_timeline_ids()
                .iter()
                .copied()
                .chain(
                    state
                        .scope_extensions()
                        .iter()
                        .map(pos_core::ErasureScopeExtensionV1::child_timeline),
                )
                .collect()
        })
}

fn add_state(
    mut plan: Expectation,
    state: &ErasureVerifiedStateV1,
) -> Result<Expectation, ErasureFenceReconcileErrorV1> {
    let request = state.request().reference().digest().to_vec();
    match state.lifecycle() {
        ErasureLifecycleV1::Submitted | ErasureLifecycleV1::Authorized => Ok(plan),
        ErasureLifecycleV1::Rejected => {
            plan.cleared.insert(request);
            Ok(plan)
        }
        mirrored => frozen_timelines(state).map(|timelines| {
            let code = code_of(mirrored);
            plan.expected.extend(
                timelines
                    .into_iter()
                    .map(|timeline| ((timeline.to_string(), request.clone()), code)),
            );
            plan
        }),
    }
}

fn expectation(
    inventory: &ErasureVerifiedInventoryV1,
) -> Result<Expectation, ErasureFenceReconcileErrorV1> {
    inventory
        .states()
        .try_fold(Expectation::default(), add_state)
}

fn read_heads(conn: &Connection) -> rusqlite::Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    conn.prepare(HEADS_SQL).and_then(|mut statement| {
        statement
            .query_map([], |row| {
                row.get::<_, Vec<u8>>(0)
                    .and_then(|request| row.get::<_, Vec<u8>>(1).map(|head| (request, head)))
            })
            .and_then(Iterator::collect)
    })
}

/// Refuse unless the store's request heads are exactly the inventory's.
fn require_current_heads(
    conn: &Connection,
    inventory: &ErasureVerifiedInventoryV1,
) -> Result<(), ErasureFenceReconcileErrorV1> {
    let verified: BTreeMap<Vec<u8>, Vec<u8>> = inventory
        .states()
        .map(|state| {
            (
                state.request().reference().digest().to_vec(),
                state.manifest_digest().digest().to_vec(),
            )
        })
        .collect();
    read_heads(conn).map_err(unreadable).and_then(|stored| {
        (stored == verified)
            .then_some(())
            .ok_or(ErasureFenceReconcileErrorV1::StaleInventory)
    })
}

fn read_rows(conn: &Connection) -> rusqlite::Result<BTreeMap<RowKey, i64>> {
    conn.prepare(ROWS_SQL).and_then(|mut statement| {
        statement
            .query_map([], |row| {
                row.get::<_, String>(0).and_then(|timeline| {
                    row.get::<_, Vec<u8>>(1).and_then(|request| {
                        row.get::<_, i64>(2).map(|code| ((timeline, request), code))
                    })
                })
            })
            .and_then(Iterator::collect)
    })
}

/// Refuse any stored row the verified chains do not explain.
fn require_explained(
    stored: &BTreeMap<RowKey, i64>,
    plan: &Expectation,
) -> Result<(), ErasureFenceReconcileErrorV1> {
    stored.iter().try_for_each(|(key, code)| {
        plan.expected.get(key).map_or_else(
            || {
                plan.cleared
                    .contains(&key.1)
                    .then_some(())
                    .ok_or(ErasureFenceReconcileErrorV1::Contradictory)
            },
            |want| {
                lifecycle_of(*code)
                    .zip(lifecycle_of(*want))
                    .filter(|(from, to)| reaches(*from, *to, MAX_EDGES))
                    .map(|_| ())
                    .ok_or(ErasureFenceReconcileErrorV1::Contradictory)
            },
        )
    })
}

/// Delete the Rejected requests' rows, then insert or change the rest.
fn apply(
    conn: &Connection,
    stored: &BTreeMap<RowKey, i64>,
    plan: &Expectation,
) -> rusqlite::Result<()> {
    plan.cleared
        .iter()
        .try_for_each(|request| {
            conn.execute(DELETE_SQL, params![request.as_slice()])
                .map(|_| ())
        })
        .and_then(|()| {
            plan.expected
                .iter()
                .filter(|&(key, code)| stored.get(key) != Some(code))
                .try_for_each(|((timeline, request), code)| {
                    conn.execute(UPSERT_SQL, params![timeline, request.as_slice(), code])
                        .map(|_| ())
                })
        })
}

fn reconcile(
    conn: &Connection,
    inventory: &ErasureVerifiedInventoryV1,
) -> Result<(), ErasureFenceReconcileErrorV1> {
    require_current_heads(conn, inventory)
        .and_then(|()| expectation(inventory))
        .and_then(|plan| {
            read_rows(conn).map_err(unreadable).and_then(|stored| {
                require_explained(&stored, &plan)
                    .and_then(|()| apply(conn, &stored, &plan).map_err(unreadable))
            })
        })
}

impl SqliteStore {
    /// Reconcile the B6 fence rows against the verified erasure chains.
    ///
    /// Call it before the Gateway reports Ready, with the inventory that core
    /// verified from this store. It runs in one `BEGIN IMMEDIATE` transaction
    /// that commits only on `Ok`; any error leaves the table unchanged.
    ///
    /// # Errors
    /// Returns [`ErasureFenceReconcileErrorV1::Unreadable`] when the store or
    /// a stored value cannot be read or written,
    /// [`ErasureFenceReconcileErrorV1::StaleInventory`] when a request head
    /// differs from the inventory's, and
    /// [`ErasureFenceReconcileErrorV1::Contradictory`] when a row is not
    /// explained by the verified chains or cannot advance to the verified
    /// lifecycle.
    pub fn reconcile_erasure_fence_rows(
        &mut self,
        inventory: &ErasureVerifiedInventoryV1,
    ) -> Result<(), ErasureFenceReconcileErrorV1> {
        self.conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(unreadable)
            .and_then(|transaction| {
                reconcile(&transaction, inventory)
                    .and_then(|()| transaction.commit().map_err(unreadable))
            })
    }
}
