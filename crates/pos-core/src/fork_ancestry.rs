//! Fork ancestry for inherited erasure-scope gating.
//!
//! ADR-021 Revision 4 Decision 3: a stitched read or Driver pass of a Fork
//! applies each inherited ancestor's own erasure decision for the same
//! protected operation, under one fence. The ancestor chain always comes from
//! the store through [`fork_ancestry`]; hosts never assemble it by hand.

use crate::{
    erasure::{ErasureContainmentErrorV1, ErasureGate, ErasureProtectedOperationV1},
    error::CoreError,
    ids::TimelineId,
    store::EventStore,
    timeline::TimelineMeta,
};

/// Return one Timeline's Fork ancestry from the store, nearest first.
///
/// The chain starts at `timeline` and follows each
/// [`TimelineMeta::fork_point`] parent through [`EventStore::get_timeline`]
/// until it reaches a root. Fork ancestry is immutable once a Fork exists, so
/// a host may compute it before entering the operation's fence.
///
/// # Errors
/// Returns [`CoreError::TimelineNotFound`] for an absent or hidden member,
/// [`CoreError::Storage`] when the parent links form a cycle, or the store's
/// own read error, including the closed erasure error for a denied member.
pub fn fork_ancestry<S: EventStore + ?Sized>(
    store: &S,
    timeline: TimelineId,
) -> Result<Vec<TimelineMeta>, CoreError> {
    let mut ancestry: Vec<TimelineMeta> = Vec::new();
    let mut next = Some(timeline);
    while let Some(member) = next {
        if ancestry.iter().any(|known| known.id == member) {
            return Err(CoreError::Storage(format!(
                "fork ancestry contains a cycle at timeline {member}"
            )));
        }
        let meta = store
            .get_timeline(member)
            .and_then(|found| found.ok_or(CoreError::TimelineNotFound(member)))?
            .meta;
        next = meta.fork_point.map(|(parent, _)| parent);
        ancestry.push(meta);
    }
    Ok(ancestry)
}

/// Check that a host-supplied chain is `timeline`'s complete Fork ancestry.
///
/// The chain must start at `timeline`, link every member to the next through
/// its `fork_point` parent, and end at a root.
///
/// # Errors
/// Returns [`ErasureContainmentErrorV1::RecoveryUnavailable`] for an empty,
/// wrongly rooted, non-contiguous, or unterminated chain.
pub fn validate_fork_ancestry(
    timeline: TimelineId,
    ancestry: &[TimelineMeta],
) -> Result<(), ErasureContainmentErrorV1> {
    let starts_at_timeline = ancestry.first().is_some_and(|first| first.id == timeline);
    let contiguous = ancestry
        .windows(2)
        .all(|pair| pair[0].fork_point.map(|(parent, _)| parent) == Some(pair[1].id));
    let ends_at_root = ancestry.last().is_some_and(TimelineMeta::is_root);
    if starts_at_timeline && contiguous && ends_at_root {
        Ok(())
    } else {
        Err(ErasureContainmentErrorV1::RecoveryUnavailable)
    }
}

/// Authorize every scope that contributes Events to one stitched operation.
///
/// Call it inside the operation's fence, so every decision uses the same
/// fence serialization and inventory generation.
///
/// # Errors
/// Returns the first contributing scope's closed containment error.
pub fn authorize_fork_scopes<G: ErasureGate + ?Sized>(
    gate: &G,
    scopes: impl IntoIterator<Item = TimelineId>,
    operation: ErasureProtectedOperationV1,
) -> Result<(), ErasureContainmentErrorV1> {
    scopes
        .into_iter()
        .try_for_each(|scope| gate.authorize(scope, operation))
}

/// Run one protected effect under `timeline`'s fence only when every member
/// of its host-supplied Fork ancestry also permits `operation`.
///
/// The chain is validated before the fence. The effect does not run when any
/// contributing scope denies.
///
/// # Errors
/// Returns [`ErasureContainmentErrorV1::RecoveryUnavailable`] for an invalid
/// chain, or the first contributing scope's closed containment error.
pub fn with_fork_ancestry_fence<G: ErasureGate + ?Sized>(
    gate: &G,
    timeline: TimelineId,
    ancestry: &[TimelineMeta],
    operation: ErasureProtectedOperationV1,
    effect: &mut dyn FnMut(),
) -> Result<(), ErasureContainmentErrorV1> {
    validate_fork_ancestry(timeline, ancestry).and_then(|()| {
        // A gate that returns without running the effect leaves this closed.
        let mut decision = Err(ErasureContainmentErrorV1::RecoveryUnavailable);
        let mut gated = || {
            decision = authorize_fork_scopes(gate, ancestry.iter().map(|meta| meta.id), operation);
            if decision.is_ok() {
                effect();
            }
        };
        gate.with_fence(timeline, operation, &mut gated)
            .and(decision)
    })
}
