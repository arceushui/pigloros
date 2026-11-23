//! `piglor-gateway erasure-admissions close|open|status <sqlite-path>`: the
//! operator's durable switch for `requestErasure` (ADR-136 follow-up F3,
//! #1408).
//!
//! The command writes the store's admissions record as an offline writer
//! (ADR-134 §8): under the store's shared mode lock and attached to its
//! execution-mode binding, so an unbound store is refused. Both verbs run
//! in every execution mode, Air-Gapped included: closing only reduces what
//! the host admits, and reopening restores the admission the mode already
//! serves.
//!
//! The Local erasure host reads the record on every fresh submission.
//! While it is closed, a fresh `requestErasure` is
//! `503 erasure-admissions-closed`; an exact retry of an admitted request,
//! `getErasure`, the erasure driver and its startup sweep never read it.

use pos_core::{ErasureAdmissionsPortV1, ErasureAdmissionsStateV1};
use pos_store::sqlite::SqliteStore;
use thiserror::Error;

use crate::mode_profile::{attach_offline_writer_v1, GatewayModeErrorV1, GatewayModeStoreLockV1};

/// The failures of one `erasure-admissions` command.
#[derive(Debug, Error)]
pub enum ErasureAdmissionsCommandErrorV1 {
    /// The arguments are not one verb and one store path.
    #[error("Usage: piglor-gateway erasure-admissions <close|open|status> <sqlite-path>")]
    Usage,
    /// The store or its admissions record cannot be opened, read or
    /// written; the record is unchanged.
    #[error("erasure admissions record is unavailable")]
    RecordUnavailable,
    /// The store's execution-mode binding refuses this offline writer.
    #[error(transparent)]
    ModeBinding(#[from] GatewayModeErrorV1),
}

/// Execute one `erasure-admissions` command and return its terminal output:
/// for `close` and `open` the audit line naming the previous and the new
/// state, for `status` the persisted state.
///
/// # Errors
/// Returns [`ErasureAdmissionsCommandErrorV1::Usage`] for any other
/// arguments, the mode binding's refusal of an unbound or locked store, and
/// [`ErasureAdmissionsCommandErrorV1::RecordUnavailable`] when the record
/// cannot be read or written.
pub fn execute(arguments: &[String]) -> Result<String, ErasureAdmissionsCommandErrorV1> {
    let [command, sqlite_path] = arguments else {
        return Err(ErasureAdmissionsCommandErrorV1::Usage);
    };
    let change = match command.as_str() {
        "close" => Some(ErasureAdmissionsStateV1::Closed),
        "open" => Some(ErasureAdmissionsStateV1::Open),
        "status" => None,
        _ => return Err(ErasureAdmissionsCommandErrorV1::Usage),
    };
    bound_store(sqlite_path).and_then(|(_lock, mut store)| {
        match change {
            Some(state) => store.set_erasure_admissions(state).map(|previous| {
                format!(
                    "Erasure admissions {} (were {})",
                    changed_to(state),
                    label(previous)
                )
            }),
            None => store
                .erasure_admissions()
                .map(|state| format!("Erasure admissions: {}", label(state))),
        }
        .map_err(|_| ErasureAdmissionsCommandErrorV1::RecordUnavailable)
    })
}

/// Open the store at `sqlite_path` as an offline writer: under its shared
/// mode lock, attached to its execution-mode binding. Every bound mode is
/// accepted. The lock lives as long as the returned guard.
fn bound_store(
    sqlite_path: &str,
) -> Result<(GatewayModeStoreLockV1, SqliteStore), ErasureAdmissionsCommandErrorV1> {
    GatewayModeStoreLockV1::shared(sqlite_path)
        .map_err(ErasureAdmissionsCommandErrorV1::from)
        .and_then(|lock| {
            SqliteStore::open(sqlite_path)
                .map(|store| (lock, store))
                .map_err(|_| ErasureAdmissionsCommandErrorV1::RecordUnavailable)
        })
        .and_then(|(lock, mut store)| {
            attach_offline_writer_v1(&mut store)
                .map(|_mode| (lock, store))
                .map_err(ErasureAdmissionsCommandErrorV1::from)
        })
}

const fn label(state: ErasureAdmissionsStateV1) -> &'static str {
    match state {
        ErasureAdmissionsStateV1::Open => "open",
        ErasureAdmissionsStateV1::Closed => "closed",
    }
}

const fn changed_to(state: ErasureAdmissionsStateV1) -> &'static str {
    match state {
        ErasureAdmissionsStateV1::Open => "opened",
        ErasureAdmissionsStateV1::Closed => "closed",
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
