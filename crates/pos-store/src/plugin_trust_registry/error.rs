//! The closed error of the Plugin trust policy registry port.

use pos_conformance::{PluginFloorErrorV1, PluginTrustBridgeErrorV1};
use pos_crypto::plugin_trust::PluginTrustErrorV1;
use thiserror::Error;

/// Closed, secret-free failures of the Plugin trust policy registry.
///
/// The variants are exactly the ADR-103 revision 4 error table plus the two
/// variants that revision 5 adds for the read-only evaluation. Every other
/// name in the contract is a variant of a wrapped enum.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PluginTrustPolicyRegistryErrorV1 {
    /// The scope row is absent, or all Plugin trust tables are absent.
    #[error("Plugin trust state is not provisioned")]
    MissingState,
    /// A partial floor pair, a stored-invariant violation, or a schema violation.
    #[error("Plugin trust state is corrupt")]
    CorruptState,
    /// The supplied anchor differs from the persisted anchor in any field.
    #[error("Plugin trust anchor differs from the persisted anchor")]
    AnchorMismatch,
    /// The trusted clock source failed. Only `TrustedUtcSecondV1::from_source` returns it.
    #[error("trusted UTC source is unavailable")]
    TrustedTimeUnavailable,
    /// The trusted UTC second is below the retained highest second.
    #[error("trusted UTC second is below the retained highest second")]
    TrustedTimeRegressed,
    /// The release is neither the first, the same content, nor the direct successor.
    #[error("release does not continue the active release chain")]
    ReleaseChainViolation,
    /// The same PMF1 digest was presented with a changed decision identity.
    #[error("release decision already retained with a different identity")]
    ReleaseConflict,
    /// The rollback digest was never admitted in this scope.
    #[error("rollback target was never admitted in this scope")]
    UnknownRollbackTarget,
    /// Rollback needs an active release and none exists.
    #[error("no active release to roll back")]
    NoActiveRelease,
    /// The rollback target is already the active release.
    #[error("rollback target is already active")]
    RollbackTargetActive,
    /// The erasure gate, a fence, an Event guard, the append, or the payload digest refused.
    #[error("activation Event was rejected")]
    ActivationEventRejected,
    /// The operation began inside a transaction or savepoint.
    #[error("registry operation entered inside a transaction")]
    NestedTransaction,
    /// The journal mode is not WAL.
    #[error("registry storage requires WAL journal mode")]
    WalRequired,
    /// The database was busy: under the admission lock, or at a read statement of a read.
    #[error("registry storage is busy")]
    StorageBusy,
    /// A statement, `BEGIN`, or constraint failed; nothing changed and no Event was appended.
    /// A read fails with it too, including a nested `BEGIN` and a failed closing `COMMIT`.
    #[error("registry storage operation failed")]
    StorageFailed,
    /// The commit outcome is unknown, or a durability set, read-back, or restore failed.
    #[error("registry storage commit outcome is unknown")]
    StorageIndeterminate,
    /// A durability restore failed earlier on this handle, or a read left its own transaction
    /// open.
    #[error("registry storage handle is poisoned")]
    StorePoisoned,
    /// The evaluated policy is not the retained one: a valid TPS1 successor, or a floor that the
    /// evidence would create or move. The registry has not adopted it and an evaluation never does.
    #[error("Plugin trust policy has not been adopted by the registry")]
    PolicyNotAdvanced,
    /// The release is not the active release of its Plugin ID. Unlike `NoActiveRelease`, which
    /// only `rollback` returns, this covers a missing pointer and a pointer naming another release.
    #[error("release is not the active release of its Plugin ID")]
    ReleaseNotActive,
    /// A pure TPS1 bridge check failed.
    #[error("TPS1 bridge: {0}")]
    Bridge(#[from] PluginTrustBridgeErrorV1),
    /// A PTR1/PRV1 floor check failed.
    #[error("trust floor: {0}")]
    Floor(#[from] PluginFloorErrorV1),
    /// `authorize_release` denied the release.
    #[error("release authorization: {0}")]
    Trust(#[from] PluginTrustErrorV1),
}
