#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-time` — timeline replay, snapshots, and fork-comparison utilities.
//!
//! Builds on top of `pos-core` (traits/types), `pos-store` (backend factory),
//! and `pos-state` (projection registry).
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`mod@replay`] | Fold all (or partial) events through a `ProjectionRegistry` |
//! | [`mod@snapshot`] | Capture and verify state snapshots |
//! | [`compare()`] | Diff two divergent timelines after a fork |
//! | [`merge()`] | Conflict-free / strategy-guided timeline merge |
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

pub mod compare;
pub mod merge;
pub mod replay;
pub mod snapshot;

pub use compare::{compare, ForkDiff};
pub use merge::{
    can_merge_conflict_free, merge, merge_with_strategy, MergeConflict, MergeResult, MergeSpec,
    MergeStrategy,
};
pub use replay::{replay, replay_at};
pub use snapshot::{snapshot, verify_snapshot_consistency, Snapshot, SnapshotError};
