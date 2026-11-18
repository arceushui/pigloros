//! `LocalErasureExecutorV1`: the Local implementation of the ADR-075 §3
//! execution port (ADR-136 §1 and §4a; ticket #1430).
//!
//! The executor holds no key and no authority. It runs each
//! coordinator-dispatched command as a Local owner host command of the
//! execution host and returns the ELO1 owner result that command made
//! durable. A negative owner outcome is an owner result, not an error.

use pos_core::{
    ErasureAuthorityExecutionV1, ErasureErrorV1, ErasureHostErrorV1, ErasureInventoryCategoryV1,
    ErasureOwnerCommandV1, ErasureOwnerResultV1, ErasureReferenceV1, TimelineId,
};

use crate::ErasureExecutionHostV1;

/// The single-host erasure executor of one store.
///
/// It destroys keys under the store's Erasure Host Timeline, which the
/// composition root supplies: the host-owned root Timeline every bundle of
/// the store lists in `host_timelines`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalErasureExecutorV1 {
    host_timeline: TimelineId,
}

/// The order a replay runs the owners of one attempt in: keys first, so an
/// artifact whose keys the attempt destroys is then redacted (Q7); the
/// single local replica last, after every other owner of the request (F1).
const fn execution_rank(category: ErasureInventoryCategoryV1) -> u8 {
    match category {
        ErasureInventoryCategoryV1::Key => 0,
        ErasureInventoryCategoryV1::Artifact => 1,
        ErasureInventoryCategoryV1::Backup => 2,
        ErasureInventoryCategoryV1::Replica => 3,
    }
}

/// The execution error of a host command that made no owner result
/// durable: the command was not dispatched in the request's active attempt,
/// the host is not ready, or the store refused the write.
const fn execution_failure(_error: ErasureHostErrorV1) -> ErasureErrorV1 {
    ErasureErrorV1::ProvenanceMissing
}

impl LocalErasureExecutorV1 {
    /// An executor that fences key destruction on `host_timeline`, the
    /// store's Erasure Host Timeline.
    #[must_use]
    pub const fn new(host_timeline: TimelineId) -> Self {
        Self { host_timeline }
    }

    /// Replay the dispatch outbox of `request`: execute every command of
    /// its active attempt that has no acknowledgement yet, keys first and
    /// the local replica last, and return their owner results in that
    /// order.
    ///
    /// The outbox is durable before dispatch, so a crash anywhere in a
    /// replay is recovered by replaying again: every owner is idempotent.
    ///
    /// # Errors
    /// [`ErasureErrorV1::ProvenanceMissing`] when the outbox cannot be read
    /// or a command made no owner result durable; the replay stops at that
    /// command.
    pub fn replay(
        &mut self,
        host: &mut ErasureExecutionHostV1,
        request: ErasureReferenceV1,
    ) -> Result<Vec<ErasureOwnerResultV1>, ErasureErrorV1> {
        host.command_sender()
            .and_then(|mut sender| sender.dispatched_owner_commands(request))
            .map_err(execution_failure)
            .and_then(|mut commands| {
                commands.sort_by_key(|command| execution_rank(command.destruction.category));
                commands
                    .iter()
                    .map(|command| self.execute(command, host))
                    .collect()
            })
    }
}

impl ErasureAuthorityExecutionV1 for LocalErasureExecutorV1 {
    type Context = ErasureExecutionHostV1;

    /// Run the owner work of `command` as one Local owner host command.
    ///
    /// # Errors
    /// [`ErasureErrorV1::ProvenanceMissing`] when `command` is not
    /// dispatched in its request's active attempt, the host is not ready,
    /// or no owner result could be made durable.
    fn execute(
        &mut self,
        command: &ErasureOwnerCommandV1,
        context: &mut ErasureExecutionHostV1,
    ) -> Result<ErasureOwnerResultV1, ErasureErrorV1> {
        context
            .command_sender()
            .and_then(|mut sender| sender.execute_local_owner(command, self.host_timeline))
            .map_err(execution_failure)
    }
}
