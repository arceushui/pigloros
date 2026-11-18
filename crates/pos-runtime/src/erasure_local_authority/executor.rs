//! `LocalErasureExecutorV1`: the Local implementation of the ADR-075 §3
//! execution port (ADR-136 §1 and §4a; ticket #1430).
//!
//! The executor holds no key and no authority. It runs each
//! coordinator-dispatched command as a Local owner host command of the
//! execution host and returns the ELO1 owner result that command made
//! durable. A negative owner outcome is an owner result, not an error.

use pos_core::{
    ErasureAuthorityExecutionV1, ErasureErrorV1, ErasureHostErrorV1, ErasureOwnerCommandV1,
    ErasureOwnerResultV1, ErasureReferenceV1,
};

use crate::{ErasureCommandSenderV1, ErasureExecutionHostV1};

/// The single-host erasure executor of one store.
///
/// It destroys keys under the store's Erasure Host Timeline, which the host
/// derives inside each owner command as `ELHT1` of the store's erasure store
/// identity: the host-owned root Timeline every bundle of the store lists in
/// `host_timelines`. No caller supplies that Timeline (owner decision of
/// 2026-11-18 on #1431). A caller that executes single commands must keep
/// [`Self::replay`]'s order: the local replica runs only after every other
/// owner of the attempt, and is otherwise refused with
/// [`ErasureErrorV1::PolicyConflict`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LocalErasureExecutorV1;

/// The execution error of a host command that made no owner result
/// durable: `PolicyConflict` for a command that cannot run yet or at all
/// (not dispatched in its request's active attempt, or a local replica
/// before every other owner), `ProvenanceMissing` for a host that is not
/// ready or a store that could not be read or written.
const fn execution_error(error: ErasureHostErrorV1) -> ErasureErrorV1 {
    match error {
        ErasureHostErrorV1::Conflict => ErasureErrorV1::PolicyConflict,
        _ => ErasureErrorV1::ProvenanceMissing,
    }
}

impl LocalErasureExecutorV1 {
    /// Replay the dispatch outbox of `request`: execute every command of
    /// its active attempt that has no acknowledgement yet, in the outbox's
    /// order (keys first, the local replica last), and return their owner
    /// results in that order.
    ///
    /// The outbox is durable before dispatch, so a crash anywhere in a
    /// replay is recovered by replaying again: every owner is idempotent.
    ///
    /// # Errors
    /// The payload-free host error of the outbox read, or of the first
    /// command that made no owner result durable; the replay stops there.
    pub fn replay(
        host: &mut ErasureExecutionHostV1,
        request: ErasureReferenceV1,
    ) -> Result<Vec<ErasureOwnerResultV1>, ErasureHostErrorV1> {
        host.command_sender().and_then(|mut sender| {
            sender
                .dispatched_owner_commands(request)
                .and_then(|commands| {
                    commands
                        .iter()
                        .map(|command| Self::run(&mut sender, command))
                        .collect()
                })
        })
    }

    /// Run the owner work of one dispatched `command` as one Local owner
    /// host command of `sender`'s host, keeping the payload-free host
    /// error: the path [`super::LocalErasureDriverV1`] runs each outbox
    /// command on.
    pub(super) fn run(
        sender: &mut ErasureCommandSenderV1<'_>,
        command: &ErasureOwnerCommandV1,
    ) -> Result<ErasureOwnerResultV1, ErasureHostErrorV1> {
        sender.execute_local_owner(command)
    }
}

impl ErasureAuthorityExecutionV1 for LocalErasureExecutorV1 {
    type Context = ErasureExecutionHostV1;

    /// Run the owner work of `command` as one Local owner host command.
    ///
    /// Commands must run in the order [`LocalErasureExecutorV1::replay`]
    /// runs them: the local replica only after every other owner of the
    /// attempt has an owner result. A local replica run out of that order
    /// returns [`ErasureErrorV1::PolicyConflict`] and purges nothing.
    ///
    /// # Errors
    /// [`ErasureErrorV1::PolicyConflict`] when `command` is not dispatched
    /// in its request's active attempt, or is a local replica that comes
    /// before another owner of the attempt; [`ErasureErrorV1::ProvenanceMissing`]
    /// when the host is not ready or no owner result could be made durable.
    fn execute(
        &mut self,
        command: &ErasureOwnerCommandV1,
        context: &mut ErasureExecutionHostV1,
    ) -> Result<ErasureOwnerResultV1, ErasureErrorV1> {
        context
            .command_sender()
            .and_then(|mut sender| Self::run(&mut sender, command))
            .map_err(execution_error)
    }
}
