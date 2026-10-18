//! The closed error of the composition fallback registry port.

use pos_core::FallbackRecordErrorV1;
use thiserror::Error;

/// Closed, secret-free failures of the composition fallback registry (ADR-119 section 4.3).
///
/// The runtime-only refusals of section 4.3 (`TargetNotStepped`, and `PrimaryNotEffective` for an
/// entry the registry has never recorded) belong to the runtime `declare`, which knows the
/// composer's base composition; the port reports only what its own rows and Events decide.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CompositionFallbackRegistryErrorV1 {
    /// The registry tables are absent: the store is not provisioned.
    #[error("composition fallback state is not provisioned")]
    MissingState,
    /// A partial or different table set, an undecodable row, or a row that differs from the
    /// fold of its Timeline's declaration and activation Events.
    #[error("composition fallback state is corrupt")]
    CorruptState,
    /// The DFP1 bytes or the activation arguments fail the ADR-119 record rules.
    #[error("invalid ADR-119 record: {0}")]
    InvalidRecord(#[from] FallbackRecordErrorV1),
    /// The DFP1 scope is not the scope the operation names.
    #[error("policy scope differs from the operation scope")]
    ScopeMismatch,
    /// The target entity is not the entity recorded for `(scope, timeline)`.
    #[error("target entity differs from the recorded entity")]
    EntityMismatch,
    /// Another request already occupies the operation's key.
    #[error("another request occupies this key")]
    Conflict,
    /// `expected_state_revision` is not the current state revision.
    #[error("state revision is stale")]
    StaleState,
    /// `expected_logical_head` is not the target Timeline's Logical Head.
    #[error("logical head is stale")]
    StaleHead,
    /// The policy's `previous_policy_digest` is not the current policy digest.
    #[error("previous policy digest is not the current policy")]
    StalePolicy,
    /// A first policy (no predecessor) has no entries: there is nothing to withdraw.
    #[error("a first policy must declare at least one entry")]
    EmptyFirstPolicy,
    /// A declared primary is not the entry's recorded effective implementation.
    #[error("declared primary is not the effective implementation")]
    PrimaryNotEffective,
    /// No current policy, or the current policy has no such entry.
    #[error("entry is not in the current policy")]
    UnknownEntry,
    /// `closing_tenure_ordinal` or `from` is not the entry's current tenure and implementation.
    #[error("activation does not close the current tenure")]
    StaleActivation,
    /// `to` is not a permitted next implementation of the entry.
    #[error("activation target is not permitted")]
    InvalidTarget,
    /// A candidate activation names a trigger code the entry does not declare.
    #[error("trigger code is not declared for the entry")]
    TriggerNotDeclared,
    /// An automatic activation of an entry in manual mode.
    #[error("entry requires an owner activation")]
    ManualEntry,
    /// A skipped implementation is not another candidate of the entry.
    #[error("skipped implementation is not another candidate")]
    InvalidSkipped,
    /// The target Timeline is missing or unreadable.
    #[error("target Timeline is unavailable")]
    TimelineUnavailable,
    /// The erasure fence, an Event guard, the payload hash, or the append refused.
    #[error("fallback Event was rejected")]
    EventRejected,
    /// The operation began inside a transaction or savepoint.
    #[error("registry operation entered inside a transaction")]
    NestedTransaction,
    /// The journal mode is not WAL.
    #[error("registry storage requires WAL journal mode")]
    WalRequired,
    /// The database was busy.
    #[error("registry storage is busy")]
    StorageBusy,
    /// A statement, `BEGIN`, or constraint failed; nothing changed and no Event was appended.
    #[error("registry storage operation failed")]
    StorageFailed,
    /// The commit outcome is unknown, or a durability set, read-back, or restore failed.
    #[error("registry storage commit outcome is unknown")]
    StorageIndeterminate,
    /// A durability restore failed earlier on this handle.
    #[error("registry storage handle is poisoned")]
    StorePoisoned,
}
