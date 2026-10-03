//! Protected Timeline snapshots: `Unavailable` until #502.
//!
//! Protected Snapshot capture, verification and reuse need a PSS1 Snapshot
//! commit whose placement under ADR-112's guard is deferred to #502
//! (ADR-113 §9). Until then both entry points return `Unavailable` before any
//! read or fold, and change nothing.

use std::collections::HashMap;

use pos_core::{CoreError, EntityId, Seq, StateRegistry, TimelineId, WorldReplayClosureV1};
use pos_runtime::ErasureReadSenderV1;
use pos_state::ProjectionRegistry;

/// A snapshot of all per-reducer entity states at a specific sequence number
/// on a timeline.
///
/// The `registry` field is a map from reducer name → [`StateRegistry`] that
/// mirrors the full [`ProjectionRegistry`] state at capture time. It is kept
/// serialisable so snapshots can be persisted and loaded without re-running
/// every registered reducer.
///
/// Protected Snapshot capture, verification and reuse are `Unavailable`
/// (ADR-113 §9), so nothing constructs a `Snapshot` in this release. The
/// type, including its `registry` and `inventory_generation` fields, is
/// retained deliberately for #502 (protected Snapshot PSS1 placement), which
/// owns its future shape; this unsupported contract is deferred explicitly,
/// not dead.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Snapshot {
    /// The timeline this snapshot was taken from.
    pub timeline: TimelineId,
    /// The sequence number at which the snapshot was taken (inclusive).
    pub at_seq: Seq,
    /// Per-reducer, per-entity state at `at_seq`.
    pub registry: HashMap<String, StateRegistry>,
    /// Inventory generation installed by the host at capture. Snapshots
    /// without this field are outside the current wire format.
    pub inventory_generation: [u8; 32],
}

/// Take a protected snapshot of the current head of `timeline`.
///
/// Protected Snapshot capture is unavailable until #502 decides where its
/// PSS1 commit happens under the guard (ADR-113 §9).
///
/// # Errors
/// Always returns [`CoreError::ArtifactUnavailable`], before any read or
/// fold; `registry` is borrowed immutably and cannot change.
pub const fn snapshot(
    _sender: &ErasureReadSenderV1<'_>,
    _timeline: TimelineId,
    _registry: &ProjectionRegistry,
    _closure: &WorldReplayClosureV1,
) -> Result<Snapshot, CoreError> {
    Err(CoreError::ArtifactUnavailable)
}

/// Error type for snapshot consistency checks.
///
/// While protected Snapshots are `Unavailable` (ADR-113 §9), this module's
/// checks return only [`Self::ArtifactUnavailable`]; [`Self::Store`] arises
/// only from the `From<CoreError>` conversion. The other variants are
/// retained deliberately for #502 (protected Snapshot PSS1 placement), which
/// owns them; this unsupported contract is deferred explicitly, not dead.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    /// ADR-060 no longer permits the snapshot as authoritative state.
    #[error("snapshot artifact is unavailable for authoritative use")]
    ArtifactUnavailable,
    /// The host inventory changed after this snapshot was captured.
    #[error("snapshot inventory generation is stale")]
    StaleGeneration,
    /// A non-artifact host, containment, or store error occurred.
    #[error("host or store error: {0}")]
    Store(CoreError),
    /// The snapshot and full-replay state disagree for an entity.
    #[error("snapshot inconsistent: entity {entity:?} differs")]
    Inconsistent { entity: EntityId },
    /// The snapshot contains a reducer or entity absent from current history.
    #[error("snapshot contains state outside the current Timeline replay")]
    InconsistentState,
    /// The snapshot claims a sequence beyond the Timeline's logical head.
    #[error("snapshot sequence is beyond the Timeline's logical head")]
    SequenceBeyondHead,
}

impl From<CoreError> for SnapshotError {
    fn from(error: CoreError) -> Self {
        if matches!(error, CoreError::ArtifactUnavailable) {
            Self::ArtifactUnavailable
        } else {
            Self::Store(error)
        }
    }
}

/// Verify a protected snapshot against a full replay.
///
/// Protected Snapshot verification and reuse are unavailable until #502
/// (ADR-113 §9).
///
/// # Errors
/// Always returns [`SnapshotError::ArtifactUnavailable`], before any read or
/// fold; `registry` is borrowed immutably and cannot change.
pub const fn verify_snapshot_consistency(
    _sender: &ErasureReadSenderV1<'_>,
    _snap: &Snapshot,
    _registry: &ProjectionRegistry,
    _closure: &WorldReplayClosureV1,
) -> Result<(), SnapshotError> {
    Err(SnapshotError::ArtifactUnavailable)
}
