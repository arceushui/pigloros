//! Root-owned recovery of one pending SIR1 transaction (ADR-069 R12).
//!
//! A pending SIR1 is loaded only from the fixed installation root, and only
//! when the selector can rebuild it byte for byte from the installed objects
//! (R12 §4.1). The loaded [`PendingRecoveryTarget`] names its exact
//! transaction through [`RecoveryTransactionIdentity`], and each load draws
//! a fresh in-memory [`RecoveryOperationId`]. Neither type can be
//! constructed, cloned, serialized or decoded outside this module.
//!
//! One recovery operation (R12 §6) runs in this order:
//! 1. [`ProviderTerminationAuthority::terminate_previous_runtime`] has the
//!    port terminate and reconcile the previous runtime and its recovery
//!    slot, checks each observation against the target and the kernel, and
//!    mints a [`PreviousRuntimeTerminationProof`];
//! 2. [`ProviderTerminationAuthority::start_recovery_peer`] consumes that
//!    proof into a [`RecoveryPeerSession`], which starts nothing;
//! 3. [`RecoveryPeerSession::conclude`] starts the one peer, runs the 100 ms
//!    exchange, always cleans the slot under 5 s, and only then mints the
//!    [`RecoveryPeerTerminationProof`];
//! 4. [`complete_recovery`] publishes the next SIC1 and removes SIR1.
//!
//! Any failure drops every proof; the next operation starts again at `load`.
//! While a target is pending the selector stays closed: it exposes no
//! evaluator endpoint and its administrative listener answers only the
//! mode-1 challenge of this transaction (R12 §8).

mod authority;
// A public module keeps the selector's crate-only host view compatible with
// both `unreachable_pub` and Clippy's `redundant_pub_crate` lint.
#[doc(hidden)]
pub mod host;
mod port;
mod session;

use crate::sandbox_provider_protocol::AuthenticatedRevocationAcknowledgement;
use crate::selector::installation::authority::{
    fresh_selector_id, AuthenticatedSelectorBootstrap, InstallationChallenge,
    PendingRecoveryRecords, VerifiedPendingRecovery,
};
use crate::selector::installation::InstalledSelectorState;
use crate::selector::runtime_lifecycle::{ProviderLifecycleError, ProviderLifecyclePort};
use crate::selector::SelectorBoundaryError;

pub use authority::{
    Consumed, PreviousRuntimeTerminationProof, ProofState, ProviderTerminationAuthority, Unconsumed,
};
pub(crate) use host::RecoveryHost;
pub use port::{
    PreviousRuntimeObservation, PreviousRuntimeTarget, RecoveryPeerLaunch, RecoveryPeerObservation,
    RecoverySlotObservation, RecoverySlotTarget, VerifiedProviderBinary,
};
pub use session::{ConcludedRecovery, RecoveryPeerSession, RecoveryPeerTerminationProof};

/// Closed failures of one recovery operation. Every one leaves SIR1 in
/// place and the selector closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RecoveryError {
    /// The pending SIR1, or a record or object it names, failed authentication.
    #[error(transparent)]
    Boundary(#[from] SelectorBoundaryError),
    /// The evaluator endpoint pathname exists while a SIR1 is pending.
    ///
    /// The selector never unlinks a crash-stale node, so recovery stops
    /// closed until an operator removes it (ADR-069 R12 §8 M4).
    #[error("the evaluator endpoint exists while recovery is pending")]
    EvaluatorEndpointPresent,
    /// The lifecycle port refused an operation.
    #[error(transparent)]
    Lifecycle(ProviderLifecycleError),
    /// An observation does not echo its challenge or names another scope or
    /// attempt set.
    #[error("a lifecycle observation does not match its target")]
    Observation,
    /// The recorded previous main process is still alive.
    #[error("the previous main process is alive")]
    ProcessAlive,
    /// A control group is present, or the cgroup2 mount cannot be proved.
    #[error("a control group was not proven absent")]
    CgroupPresent,
    /// The recovery leaf is not the exact root-owned socket.
    #[error("the recovery leaf is not the exact socket")]
    Leaf,
    /// The started peer is not the observed process running the SIR1 binary.
    #[error("the recovery peer is not the observed process")]
    PeerBinding,
    /// The previous provider binary no longer has the SIR1 digest.
    #[error("the previous provider binary changed")]
    Binary,
    /// The control exchange failed or missed its deadline.
    #[error("the recovery exchange failed")]
    Exchange,
    /// The RCA1 is malformed, forged or names another transaction.
    #[error("the recovery acknowledgement was refused")]
    Acknowledgement,
    /// A proof names another transaction, operation or RCA1.
    #[error("recovery evidence names another transaction or operation")]
    Mismatch,
    /// A bound of the operation passed.
    #[error("a recovery deadline passed")]
    DeadlineExceeded,
}

impl From<RecoveryError> for SelectorBoundaryError {
    fn from(error: RecoveryError) -> Self {
        error.into_boundary_error()
    }
}

impl RecoveryError {
    /// Classifies this refusal as the selector boundary error it reports.
    const fn into_boundary_error(self) -> SelectorBoundaryError {
        match self {
            Self::Boundary(error) => error,
            Self::Lifecycle(_) | Self::Exchange | Self::DeadlineExceeded => {
                SelectorBoundaryError::SelectorUnavailable
            }
            Self::EvaluatorEndpointPresent
            | Self::Observation
            | Self::ProcessAlive
            | Self::CgroupPresent
            | Self::Leaf
            | Self::PeerBinding
            | Self::Binary
            | Self::Acknowledgement
            | Self::Mismatch => SelectorBoundaryError::ArtifactInvalid,
        }
    }
}

/// Requires that no node exists at the evaluator endpoint `pathname`.
///
/// It only inspects the pathname, without following a symlink, and never
/// removes anything.
///
/// # Errors
/// Returns [`RecoveryError::EvaluatorEndpointPresent`] for any node at
/// `pathname`, and [`RecoveryError::Boundary`] when it cannot be inspected.
pub(crate) fn require_absent_evaluator_endpoint(
    pathname: &std::path::Path,
) -> Result<(), RecoveryError> {
    std::fs::symlink_metadata(pathname).map_or_else(
        |error| {
            (error.kind() == std::io::ErrorKind::NotFound)
                .then_some(())
                .ok_or(RecoveryError::Boundary(SelectorBoundaryError::Io))
        },
        |_| Err(RecoveryError::EvaluatorEndpointPresent),
    )
}

/// One authenticated pending SIR1, loaded only from the fixed installation
/// root.
///
/// Its fields are private, so no other module can build one, even naming
/// every field:
///
/// ```compile_fail,E0451
/// use pos_reference::selector::recovery::PendingRecoveryTarget;
///
/// let _ = PendingRecoveryTarget {
///     identity: todo!(),
///     operation: todo!(),
///     previous_installation_digest: [0; 32],
///     selector_nonce: [0; 16],
///     pending_update: Vec::new(),
///     records: todo!(),
/// };
/// ```
///
/// It is not `Clone`:
///
/// ```compile_fail,E0277
/// use pos_reference::selector::recovery::PendingRecoveryTarget;
///
/// fn duplicate<T: Clone>() {}
/// duplicate::<PendingRecoveryTarget>();
/// ```
///
/// and it has no decoder:
///
/// ```compile_fail,E0599
/// use pos_reference::selector::recovery::PendingRecoveryTarget;
///
/// let _ = PendingRecoveryTarget::from_canonical_cbor(&[]);
/// ```
#[derive(Debug)]
pub struct PendingRecoveryTarget {
    identity: RecoveryTransactionIdentity,
    operation: RecoveryOperationId,
    previous_installation_digest: [u8; 32],
    selector_nonce: [u8; 16],
    pending_update: Vec<u8>,
    records: Box<PendingRecoveryRecords>,
}

impl PendingRecoveryTarget {
    /// Loads the pending SIR1 of `installed` for one new recovery operation.
    ///
    /// SIR1 is decoded within its 48 MiB bound and must be rebuilt byte for
    /// byte: the current SIC1 equals its previous or next SIC1, both states
    /// and every object they name are revalidated, RCU1 is re-authenticated
    /// against the previous state, RCC1 is re-derived, and the previous
    /// role-3 runtime key is resolved from the previous SIC1, TRS1, RVS1 and
    /// SPM1 even when the next RVS1 revokes it. Each load draws a fresh
    /// [`RecoveryOperationId`].
    ///
    /// # Errors
    /// Returns [`RecoveryError::Boundary`] for any SIR1, record or object that
    /// fails those checks, or when no fresh operation ID can be drawn.
    pub(crate) fn load(installed: &InstalledSelectorState) -> Result<Self, RecoveryError> {
        VerifiedPendingRecovery::load(installed)
            .and_then(|verified| {
                RecoveryOperationId::fresh()
                    .map(|operation| Self::from_verified(verified, operation))
            })
            .map_err(RecoveryError::from)
    }

    fn from_verified(verified: VerifiedPendingRecovery, operation: RecoveryOperationId) -> Self {
        Self {
            identity: RecoveryTransactionIdentity {
                sir1_digest: verified.sir1_digest,
                previous_provider_binding_digest: verified.previous_provider_binding_digest,
                previous_runtime_instance_id: verified.previous_runtime_instance_id,
                previous_lifecycle_scope_id: verified.previous_lifecycle_scope_id,
                previous_live_attempt_ids: verified.previous_live_attempt_ids,
                recovery_peer_slot: verified.recovery_peer_slot,
            },
            operation,
            previous_installation_digest: verified.previous_installation_digest,
            selector_nonce: verified.selector_nonce,
            pending_update: verified.pending_update,
            records: Box::new(verified.records),
        }
    }

    /// The exact transaction this target names.
    #[must_use]
    pub const fn identity(&self) -> &RecoveryTransactionIdentity {
        &self.identity
    }

    /// The exact SIU1 that committed this SIR1, rebuilt from it.
    pub(crate) fn pending_update_bytes(&self) -> &[u8] {
        &self.pending_update
    }

    /// A fresh SICN1 mode-1 challenge: the previous SIC1 digest and the
    /// nonce of the committed RCU1.
    pub(crate) fn challenge(&self) -> InstallationChallenge {
        InstallationChallenge::for_pending_transaction(
            self.previous_installation_digest,
            self.selector_nonce,
        )
    }

    /// Authenticates one RCA1 under the previous SIR1 runtime key, even when
    /// the next RVS1 revokes it, and requires it to match this RCC1, RCU1
    /// request ID and next RVS1 digest (R12 §6 step 11).
    ///
    /// # Errors
    /// Returns [`RecoveryError::Acknowledgement`] for a malformed, forged,
    /// foreign-key or foreign-transaction RCA1.
    pub(crate) fn authenticate_recovery_acknowledgement(
        &self,
        rca1: &[u8],
    ) -> Result<AuthenticatedRevocationAcknowledgement, RecoveryError> {
        self.records
            .authenticate_acknowledgement(rca1)
            .map_err(|_| RecoveryError::Acknowledgement)
    }

    /// The SIR1 recovery-peer lifecycle-scope ID.
    const fn recovery_lifecycle_scope_id(&self) -> [u8; 16] {
        self.identity.recovery_peer_slot[1]
    }

    /// The SIR1 recovery-endpoint ID.
    const fn endpoint_id(&self) -> [u8; 16] {
        self.identity.recovery_peer_slot[2]
    }
}

/// One recovery operation's in-memory identity.
///
/// It is fresh and nonzero for every load of a [`PendingRecoveryTarget`], is
/// never written to disk or sent on any wire, and binds every proof of the
/// operation, so proofs of two operations on one SIR1 never combine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryOperationId([u8; 16]);

impl RecoveryOperationId {
    fn fresh() -> Result<Self, SelectorBoundaryError> {
        fresh_selector_id().map(Self)
    }
}

/// Completes one recovery: publishes the next SIC1 and removes SIR1, only
/// with both proofs and the RCA1 of one operation (R12 §6 steps 14 to 17).
///
/// The three pieces of evidence must name `pending_sir1`'s transaction and
/// operation, the RCA1 must be the one the peer proof records, and it must
/// match the target's RCC1. Then the recovery floor is verified, the next
/// SIC1 is published (or verified when already current) and SIR1 is removed
/// durably.
///
/// # Errors
/// Returns [`RecoveryError::Mismatch`] for evidence of another transaction,
/// operation or RCA1, and [`RecoveryError::Boundary`] when the floor changed
/// or a durable step failed. SIR1 then stays.
pub fn complete_recovery(
    pending_sir1: PendingRecoveryTarget,
    consumed_previous_runtime_termination_proof: PreviousRuntimeTerminationProof<Consumed>,
    authenticated_rca1: AuthenticatedRevocationAcknowledgement,
    recovery_peer_termination_proof: RecoveryPeerTerminationProof,
) -> Result<AuthenticatedSelectorBootstrap, RecoveryError> {
    // Every piece of evidence is consumed here, whatever the outcome.
    let PreviousRuntimeTerminationProof {
        identity: previous_identity,
        operation: previous_operation,
        ..
    } = consumed_previous_runtime_termination_proof;
    let RecoveryPeerTerminationProof {
        identity: peer_identity,
        operation: peer_operation,
        acknowledgement_digest,
        ..
    } = recovery_peer_termination_proof;
    let acknowledgement = authenticated_rca1;
    authority::require(
        previous_identity == pending_sir1.identity
            && previous_operation == pending_sir1.operation
            && peer_identity == pending_sir1.identity
            && peer_operation == pending_sir1.operation
            && acknowledgement.acknowledgement_digest() == acknowledgement_digest
            && pending_sir1
                .records
                .acknowledgement_matches(&acknowledgement),
        RecoveryError::Mismatch,
    )
    .and_then(|()| {
        pending_sir1
            .records
            .publish_successor()
            .map_err(RecoveryError::Boundary)
    })
}

/// One completed recovery: the next state, and the exact RCA1 the peer sent.
pub(crate) struct CompletedRecovery {
    pub(crate) bootstrap: AuthenticatedSelectorBootstrap,
    pub(crate) acknowledgement: Vec<u8>,
}

impl<P: ProviderLifecyclePort + ?Sized> ProviderTerminationAuthority<P> {
    /// Runs one whole recovery operation on `target` (R12 §6): termination,
    /// the one peer session, and completion.
    ///
    /// # Errors
    /// Returns the operation's first [`RecoveryError`]. Every proof is then
    /// dropped and SIR1 stays.
    pub(crate) fn recover(
        &self,
        target: PendingRecoveryTarget,
    ) -> Result<CompletedRecovery, RecoveryError> {
        self.terminate_previous_runtime(&target)
            .and_then(|proof| self.start_recovery_peer(&target, proof))
            .and_then(RecoveryPeerSession::conclude)
            .and_then(|(consumed, acknowledgement, peer)| {
                let bytes = peer.acknowledgement_bytes().to_vec();
                complete_recovery(target, consumed, acknowledgement, peer).map(|bootstrap| {
                    CompletedRecovery {
                        bootstrap,
                        acknowledgement: bytes,
                    }
                })
            })
    }
}

/// The tuple that names one pending transaction (ADR-069 §4.1).
///
/// Its elements are the SIR1 digest, the previous-provider binding digest,
/// the previous runtime and lifecycle-scope IDs, the complete previous-live
/// attempt set, and the recovery-peer slot.
///
/// Equality compares every element. The type is not `Clone`, `Copy`,
/// `Serialize` or `Deserialize`; its fields are private:
///
/// ```compile_fail,E0451
/// use pos_reference::selector::recovery::RecoveryTransactionIdentity;
///
/// let _ = RecoveryTransactionIdentity {
///     sir1_digest: [0; 32],
///     previous_provider_binding_digest: [0; 32],
///     previous_runtime_instance_id: [0; 16],
///     previous_lifecycle_scope_id: [0; 16],
///     previous_live_attempt_ids: Vec::new(),
///     recovery_peer_slot: [[0; 16]; 3],
/// };
/// ```
///
/// ```compile_fail,E0277
/// use pos_reference::selector::recovery::RecoveryTransactionIdentity;
///
/// fn duplicate<T: Clone>() {}
/// duplicate::<RecoveryTransactionIdentity>();
/// ```
///
/// ```compile_fail,E0599
/// use pos_reference::selector::recovery::RecoveryTransactionIdentity;
///
/// let _ = RecoveryTransactionIdentity::from_canonical_cbor(&[]);
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct RecoveryTransactionIdentity {
    sir1_digest: [u8; 32],
    previous_provider_binding_digest: [u8; 32],
    previous_runtime_instance_id: [u8; 16],
    previous_lifecycle_scope_id: [u8; 16],
    previous_live_attempt_ids: Vec<[u8; 16]>,
    /// Recovery runtime, lifecycle-scope and endpoint IDs, in that order.
    recovery_peer_slot: [[u8; 16]; 3],
}

impl RecoveryTransactionIdentity {
    /// The copy a proof holds of its transaction's identity.
    fn duplicate(&self) -> Self {
        Self {
            sir1_digest: self.sir1_digest,
            previous_provider_binding_digest: self.previous_provider_binding_digest,
            previous_runtime_instance_id: self.previous_runtime_instance_id,
            previous_lifecycle_scope_id: self.previous_lifecycle_scope_id,
            previous_live_attempt_ids: self.previous_live_attempt_ids.clone(),
            recovery_peer_slot: self.recovery_peer_slot,
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[doc(hidden)]
pub mod tests;
