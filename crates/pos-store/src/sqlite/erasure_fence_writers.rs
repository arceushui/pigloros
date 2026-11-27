#![cfg(all(target_os = "linux", any(test, feature = "test-support")))]
//! ADR-097 B6 writers: mirror the ADR-060 erasure lifecycle into fence rows.
//!
//! [`write_erasure_fence_rows`] runs inside the transaction of
//! `apply_sqlite_erasure_cas`, so the rows commit or roll back together with
//! the ERCRP1 manifest advance that proves them. A failed compare-and-swap
//! therefore leaves no fence-row change, and an exact retry returns before
//! this module runs, so it writes nothing.
//!
//! The head state of the prepared mutation (its last ERS1 state) selects the
//! rule, exactly as B6 states it:
//!
//! - `Submitted` and `Authorized` write no row.
//! - `Rejected` deletes that request's rows and no other request's.
//! - `AccessFrozen` through `PartialFailure` set every row of the request to
//!   that exact lifecycle code, never to a numeric maximum. The mutation that
//!   carries the immutable ERSC1 scope commitment (the canonical freeze)
//!   inserts one row per resolved scope Timeline. A mutation that carries an
//!   ERSE1 extension (a future Fork) inserts one row for its child Timeline at
//!   the request's exact current lifecycle.
//!
//! Core builds every mutation, so its ERSC1 and ERSE1 objects are
//! content-addressed and bound to the request before they reach this module.
//! The writers read both from the mutation's own objects because the
//! manifest that names them is opaque to adapters.
//!
//! Like the table in [`super::erasure_fence_rows`], this module stays
//! test-support gated until owner activation (#1438). Ungating must remove
//! the `cfg` gates of both modules and the call in `sqlite.rs` together.

use pos_core::{
    ErasureErrorV1, ErasureLifecycleV1, ErasureScopeCommitmentV1, ErasureScopeExtensionV1,
    PreparedErasureCasV1, TimelineId,
};
use rusqlite::{params, Connection, Params};

const UPDATE_SQL: &str =
    "UPDATE erasure_fence_rows SET lifecycle_code = ?1 WHERE erasure_request_id = ?2";
const INSERT_SQL: &str = "INSERT INTO erasure_fence_rows
         (timeline_id, erasure_request_id, lifecycle_code) VALUES (?1, ?2, ?3)";
const DELETE_SQL: &str = "DELETE FROM erasure_fence_rows WHERE erasure_request_id = ?1";

/// What B6 requires of the fence rows for one head lifecycle.
#[derive(Clone, Copy, Debug)]
enum FenceDisposition {
    /// Before `AccessFrozen`: no row exists and none is written.
    NoRow,
    /// `Rejected`: delete the request's rows.
    Clear,
    /// `AccessFrozen` onward: the rows carry this `ErasureLifecycleV1` code.
    Mirror(i64),
}

const fn disposition(lifecycle: ErasureLifecycleV1) -> FenceDisposition {
    match lifecycle {
        ErasureLifecycleV1::Submitted | ErasureLifecycleV1::Authorized => FenceDisposition::NoRow,
        ErasureLifecycleV1::Rejected => FenceDisposition::Clear,
        ErasureLifecycleV1::AccessFrozen => FenceDisposition::Mirror(2),
        ErasureLifecycleV1::DestructionDispatched => FenceDisposition::Mirror(3),
        ErasureLifecycleV1::AwaitingAcknowledgements => FenceDisposition::Mirror(4),
        ErasureLifecycleV1::Complete => FenceDisposition::Mirror(5),
        ErasureLifecycleV1::PartialFailure => FenceDisposition::Mirror(6),
    }
}

/// Mirror the lifecycle a prepared erasure mutation commits into fence rows.
///
/// Call it inside the `BEGIN IMMEDIATE` of the compare-and-swap, after the
/// manifest predecessor check and before the transaction finishes. Any write
/// failure returns `ReceiptCommitFailed`, which rolls the whole transaction
/// back.
pub(super) fn write_erasure_fence_rows(
    conn: &Connection,
    mutation: &PreparedErasureCasV1,
) -> Result<(), ErasureErrorV1> {
    mutation.new_states().last().map_or(Ok(()), |head| {
        let request = mutation.request().digest();
        match disposition(head.state().lifecycle()) {
            FenceDisposition::NoRow => Ok(()),
            FenceDisposition::Clear => execute(conn, DELETE_SQL, params![request.as_slice()]),
            FenceDisposition::Mirror(code) => mirror(conn, mutation, &request, code),
        }
    })
}

/// Set the request's rows to `code`, then add the rows this mutation creates.
fn mirror(
    conn: &Connection,
    mutation: &PreparedErasureCasV1,
    request: &[u8; 32],
    code: i64,
) -> Result<(), ErasureErrorV1> {
    execute(conn, UPDATE_SQL, params![code, request.as_slice()])?;
    new_row_timelines(mutation).try_for_each(|timeline| {
        execute(
            conn,
            INSERT_SQL,
            params![timeline.to_string(), request.as_slice(), code],
        )
    })
}

/// The Timelines that gain a row in this mutation, in object order.
///
/// An ERSC1 object yields its resolved scope Timelines and an ERSE1 object its
/// child Timeline. Every other object fails both decoders on its tag.
fn new_row_timelines(mutation: &PreparedErasureCasV1) -> impl Iterator<Item = TimelineId> + '_ {
    mutation.new_objects().iter().flat_map(|object| {
        let scope = ErasureScopeCommitmentV1::from_canonical_cbor(object.canonical_cbor())
            .ok()
            .into_iter()
            .flat_map(|scope| scope.scope_timeline_ids().to_vec());
        let child = ErasureScopeExtensionV1::from_canonical_cbor(object.canonical_cbor())
            .ok()
            .map(|extension| extension.child_timeline());
        scope.chain(child)
    })
}

fn execute(conn: &Connection, sql: &str, bound: impl Params) -> Result<(), ErasureErrorV1> {
    conn.execute(sql, bound)
        .map(|_| ())
        .map_err(|_| ErasureErrorV1::ReceiptCommitFailed)
}
