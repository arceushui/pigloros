//! Private durable delivery coordination for local Fork admission.
//!
//! The journal is deliberately a tuple ledger.  It never receives a FAL1 or
//! FARL1 frame, a Principal, an Owner, a command, a signature, or a result to
//! persist.  Those values belong to the local Gateway composition root.

use pos_core::{
    ErasureAdmittedForkContextV1, ForkAdmissionErrorV1, ForkAdmissionHostCommandV1,
    ForkAdmissionOperationKindV1, ForkAdmissionOperationResultV1, ForkAdmissionRecoveryProofV1,
    Hash,
};

use crate::ForkAdmissionAuthoritySessionV1;

/// Durable state of a single local listener delivery tuple.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForkDeliveryStateV1 {
    /// One owner may construct and submit FAC1.
    Pending,
    /// FAC1 or response delivery needs graph-backed reconciliation.
    Uncertain,
    /// A response was completely written after a verified committed recovery.
    Delivered,
}

impl ForkDeliveryStateV1 {
    /// Adapter-local durable wire value of this state.
    #[must_use]
    pub const fn to_wire(self) -> u8 {
        match self {
            Self::Pending => 1,
            Self::Uncertain => 2,
            Self::Delivered => 3,
        }
    }

    /// Decodes an adapter-local durable wire value, rejecting unknown states.
    #[must_use]
    pub const fn from_wire(wire: u8) -> Option<Self> {
        match wire {
            1 => Some(Self::Pending),
            2 => Some(Self::Uncertain),
            3 => Some(Self::Delivered),
            _ => None,
        }
    }
}

/// The only durable values for one listener delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkDeliveryTupleV1 {
    /// BLAKE3 domain digest of the complete FAL1 payload.
    pub host_request_id: Hash,
    /// The POC1 or FCC1 operation kind.
    pub kind: ForkAdmissionOperationKindV1,
    /// Caller supplied operation identity.
    pub operation_id: Hash,
}

impl ForkDeliveryTupleV1 {
    /// Constructs a nonzero, exact delivery tuple.
    ///
    /// # Errors
    /// Returns [`ForkDeliveryJournalErrorV1::InvalidTuple`] for a zero digest.
    pub fn new(
        host_request_id: Hash,
        kind: ForkAdmissionOperationKindV1,
        operation_id: Hash,
    ) -> Result<Self, ForkDeliveryJournalErrorV1> {
        if host_request_id == Hash::zero() || operation_id == Hash::zero() {
            return Err(ForkDeliveryJournalErrorV1::InvalidTuple);
        }
        Ok(Self {
            host_request_id,
            kind,
            operation_id,
        })
    }

    /// Re-applies the constructor checks to a tuple built from public fields.
    pub(crate) fn revalidate(self) -> Result<Self, ForkDeliveryJournalErrorV1> {
        Self::new(self.host_request_id, self.kind, self.operation_id)
    }
}

/// One retained journal row, shared by the store adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ForkDeliveryRowV1 {
    pub(crate) tuple: ForkDeliveryTupleV1,
    pub(crate) state: ForkDeliveryStateV1,
    pub(crate) owner_fence: u64,
}

impl ForkDeliveryRowV1 {
    /// True when `claim` still owns this exact row in `state`.
    pub(crate) fn matches_claim(
        &self,
        claim: ForkDeliveryClaimV1,
        state: ForkDeliveryStateV1,
    ) -> bool {
        self.tuple == claim.tuple && self.owner_fence == claim.owner_fence && self.state == state
    }
}

/// A fenced ownership lease returned only by a successful first claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkDeliveryClaimV1 {
    /// The claimed tuple.
    pub tuple: ForkDeliveryTupleV1,
    /// Monotonic adapter-local compare-and-set fence.
    pub owner_fence: u64,
}

/// Result of atomically claiming a tuple.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForkDeliveryClaimOutcomeV1 {
    /// This connection exclusively owns FAC1 construction and submission.
    Owner(ForkDeliveryClaimV1),
    /// Another live Pending owner holds the tuple.
    Busy,
    /// A terminal or indeterminate tuple requires private FRP1 recovery.
    Reconcile(ForkDeliveryClaimV1, ForkDeliveryStateV1),
}

/// Closed failures at the private journal boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ForkDeliveryJournalErrorV1 {
    /// A caller supplied a zero or internally inconsistent tuple.
    #[error("invalid Fork delivery tuple")]
    InvalidTuple,
    /// A request digest and operation tuple were not one-to-one.
    #[error("Fork delivery tuple conflicts with retained journal state")]
    Conflict,
    /// The claimed row changed, disappeared, or belongs to another owner.
    #[error("Fork delivery owner fence does not match")]
    Fenced,
    /// Durable journal or authority bytes are malformed or inconsistent.
    #[error("Fork delivery journal is corrupt")]
    Corrupt,
    /// The durable write outcome cannot be established.
    #[error("Fork delivery storage outcome is indeterminate")]
    StorageIndeterminate,
}

/// FAC1 execution result with the journal disposition made explicit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ForkDeliveryExecutionV1 {
    /// FAC1 committed and the response still needs delivery.
    Committed(Box<ForkAdmissionOperationResultV1>),
    /// FAC1 was definitely rejected and Pending was deleted atomically.
    Rejected(ForkAdmissionErrorV1),
    /// The caller must use FRP1; no second FAC1 may be attempted.
    Uncertain,
}

/// Classifies one FAC1 outcome for the journal (ADR-109).
///
/// Only a definite rejection releases Pending; `StorageIndeterminate` never
/// deletes the tuple and must be recorded as Uncertain.
pub(crate) fn fork_delivery_execution(
    outcome: Result<ForkAdmissionOperationResultV1, ForkAdmissionErrorV1>,
) -> ForkDeliveryExecutionV1 {
    match outcome {
        Ok(result) => ForkDeliveryExecutionV1::Committed(Box::new(result)),
        Err(ForkAdmissionErrorV1::StorageIndeterminate) => ForkDeliveryExecutionV1::Uncertain,
        Err(error) => ForkDeliveryExecutionV1::Rejected(error),
    }
}

/// Whether a permit-bearing delivery outcome may have added a child to the
/// store topology, so the adapter's captured inventory generation must be
/// re-established (ADR-109 revision 9, Decision 2 step 6).
pub(crate) const fn fork_delivery_may_have_changed_topology(
    result: Result<&ForkDeliveryExecutionV1, &ForkDeliveryJournalErrorV1>,
) -> bool {
    matches!(
        result,
        Ok(ForkDeliveryExecutionV1::Committed(_) | ForkDeliveryExecutionV1::Uncertain)
            | Err(ForkDeliveryJournalErrorV1::StorageIndeterminate)
    )
}

/// Result of graph-backed startup reconciliation, without releasing a result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForkDeliveryStartupOutcomeV1 {
    /// An abandoned Pending claim had no FAC1 operation and was deleted.
    ReleasedPending,
    /// The exact durable operation was verified and the tuple is Uncertain.
    RetainedUncertain,
}

/// Private store composition boundary used by the local Fork listener.
///
/// The Gateway keeps peer credentials, FAE1 creation, host signing, FAC1,
/// FRP1, and response bytes outside this port.  Adapters persist only the
/// tuple/state/fence represented above.
pub trait ForkAdmissionDeliveryJournalPortV1 {
    /// CAS an absent tuple to Pending, or inspect its exact retained state.
    ///
    /// # Errors
    /// Returns a closed journal error when retained identities disagree.
    fn claim_fork_delivery(
        &mut self,
        session: &ForkAdmissionAuthoritySessionV1,
        tuple: ForkDeliveryTupleV1,
    ) -> Result<ForkDeliveryClaimOutcomeV1, ForkDeliveryJournalErrorV1>;

    /// Delete a fenced Pending row after a definite failure before FAC1 submission.
    ///
    /// # Errors
    /// Returns [`ForkDeliveryJournalErrorV1::Fenced`] if ownership or state changed.
    fn cancel_pending_fork_delivery(
        &mut self,
        session: &ForkAdmissionAuthoritySessionV1,
        claim: ForkDeliveryClaimV1,
    ) -> Result<(), ForkDeliveryJournalErrorV1>;

    /// Execute one already-signed FAC1 while the matching Pending fence is held.
    ///
    /// Definite FAC1 rejection deletes Pending.  A committed FAC1 becomes
    /// Uncertain until the caller confirms complete response delivery.
    ///
    /// # Errors
    /// Returns a journal failure without exposing stored delivery payloads.
    fn execute_claimed_fork_delivery(
        &mut self,
        session: &ForkAdmissionAuthoritySessionV1,
        policy: &pos_core::ForkAuthenticationPolicyV1,
        claim: ForkDeliveryClaimV1,
        command: &ForkAdmissionHostCommandV1,
    ) -> Result<ForkDeliveryExecutionV1, ForkDeliveryJournalErrorV1>;

    /// Execute one already-signed FCC1 inside the erasure host's admitted-Fork
    /// topology transition while the matching Pending fence is held
    /// (ADR-109 revision 9, Decision 2).
    ///
    /// The session, FAC1 signature and policy, and the claimed tuple are
    /// checked before the write boundary opens. A POC1 is not a topology
    /// mutation and is refused as [`ForkDeliveryJournalErrorV1::Conflict`].
    /// The write boundary opens through `context`, and a mismatched Pending
    /// row is [`ForkDeliveryJournalErrorV1::Fenced`] with nothing written. The
    /// FCC1 applies the ADR-106 revision 3 permit containment of `context`.
    /// In the same transaction a commit moves Pending to Uncertain, and a
    /// definite rejection rolls back only the FAC1 portion through `context`
    /// before it deletes Pending. A FAC1 `StorageIndeterminate` rolls the
    /// whole transaction back and records Uncertain in a fresh one.
    ///
    /// # Errors
    /// Returns a closed journal error. A failed final commit is
    /// [`ForkDeliveryJournalErrorV1::StorageIndeterminate`]; `context` then
    /// reports that nothing was written only when the FAC1 portion had
    /// already been rolled back.
    fn execute_claimed_fork_delivery_in_topology_transition(
        &mut self,
        context: &ErasureAdmittedForkContextV1<'_>,
        session: &ForkAdmissionAuthoritySessionV1,
        policy: &pos_core::ForkAuthenticationPolicyV1,
        claim: ForkDeliveryClaimV1,
        command: &ForkAdmissionHostCommandV1,
    ) -> Result<ForkDeliveryExecutionV1, ForkDeliveryJournalErrorV1>;

    /// Recover the exact retained graph through a fresh private FRP1 proof.
    ///
    /// `current_principal_digest` is transient peer evidence.  It is compared
    /// with POB1/FAR1 graph state and is never written to the journal.
    ///
    /// # Errors
    /// Returns a closed journal error for a missing, mismatched, or corrupt
    /// tuple/graph.  It never creates an operation.
    fn recover_fork_delivery(
        &mut self,
        session: &ForkAdmissionAuthoritySessionV1,
        tuple: ForkDeliveryTupleV1,
        proof: &ForkAdmissionRecoveryProofV1,
        current_principal_digest: Hash,
    ) -> Result<ForkAdmissionOperationResultV1, ForkDeliveryJournalErrorV1>;

    /// Fences a committed owner after a post-commit response failure.
    /// A fresh Pending claim is never advanced through this method.
    ///
    /// # Errors
    /// Returns a closed journal error when ownership or state changed.
    fn mark_fork_delivery_uncertain(
        &mut self,
        session: &ForkAdmissionAuthoritySessionV1,
        claim: ForkDeliveryClaimV1,
    ) -> Result<(), ForkDeliveryJournalErrorV1>;

    /// Records a successful complete response write after private recovery.
    ///
    /// # Errors
    /// Returns a closed journal error when ownership or state changed.
    fn mark_fork_delivery_delivered(
        &mut self,
        session: &ForkAdmissionAuthoritySessionV1,
        claim: ForkDeliveryClaimV1,
    ) -> Result<(), ForkDeliveryJournalErrorV1>;

    /// Enumerates retained pending/uncertain tuples before accepting clients.
    ///
    /// Implementations never expose a result, Principal, Owner, or command.
    ///
    /// # Errors
    /// Returns a closed journal error when the session or retained state is invalid.
    fn reconcile_fork_delivery_journal(
        &mut self,
        session: &ForkAdmissionAuthoritySessionV1,
    ) -> Result<Vec<ForkDeliveryTupleV1>, ForkDeliveryJournalErrorV1>;

    /// Reconcile one abandoned startup tuple using a host-signed private FRP1.
    /// Missing operations delete only Pending. A verified committed operation
    /// advances Pending to Uncertain; a missing Uncertain operation fails closed.
    /// No result or Principal is returned or persisted.
    ///
    /// # Errors
    /// Returns a closed error for stale sessions, tuple/proof mismatch, or a
    /// corrupt retained graph.
    fn reconcile_fork_delivery_startup(
        &mut self,
        session: &ForkAdmissionAuthoritySessionV1,
        tuple: ForkDeliveryTupleV1,
        proof: &ForkAdmissionRecoveryProofV1,
    ) -> Result<ForkDeliveryStartupOutcomeV1, ForkDeliveryJournalErrorV1>;

    /// Deletes an exact Delivered tuple after the authority retention owner
    /// has established expiry.  The retention decision is deliberately host
    /// owned and is not persisted in the journal.
    ///
    /// # Errors
    /// Returns a closed journal error when the tuple is not exact Delivered state.
    fn purge_expired_fork_delivery(
        &mut self,
        session: &ForkAdmissionAuthoritySessionV1,
        tuple: ForkDeliveryTupleV1,
    ) -> Result<(), ForkDeliveryJournalErrorV1>;
}
