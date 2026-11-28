//! Effect encoding step of `apply_sqlite_erasure_cas`, with the ADR-097 B6
//! fence-row writers joined to it when they are compiled in.
//!
//! The module exists in every build so the caller carries no `cfg` branch. The
//! writers live in [`mirror`] and stay test-support gated until owner
//! activation (#1438). Ungating must remove the gates of `mirror`, of
//! `erasure_fence_rows` and the statements in `fenced_effect_cbor` together.

use pos_core::{ErasureErrorV1, PreparedErasureCasV1};
use rusqlite::Connection;

#[cfg(all(target_os = "linux", any(test, feature = "test-support")))]
mod mirror;

/// Write the fence rows when compiled in, then encode the mutation's effect.
///
/// Wraps the effect encoding that `apply_sqlite_erasure_cas` already performs
/// so the writer joins its existing fallible step. Without the writers the
/// body is the original encoding line.
pub(super) fn fenced_effect_cbor(
    conn: &Connection,
    mutation: &PreparedErasureCasV1,
) -> Result<Vec<u8>, ErasureErrorV1> {
    #[cfg(all(target_os = "linux", any(test, feature = "test-support")))]
    mirror::write_erasure_fence_rows(conn, mutation)?;
    #[cfg(not(all(target_os = "linux", any(test, feature = "test-support"))))]
    let _ = conn;
    mutation.effect().to_canonical_cbor()
}
