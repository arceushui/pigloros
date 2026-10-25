//! Trusted owner field-read protocol from ADR-121 decision revision 3.
//!
//! These types define the public seam, without providing a protected adapter or
//! constructor. A real binding requires the separately approved canonical store
//! identity/lease and complete supported-handle inventory. Production activation
//! also requires the durable intent/receipt decision and ADR-097 B7 / ADR-110 E15.

use pos_core::{EntityId, FieldStateV1, TimelineId};

/// Closed selection of an accepted protected field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubjectFieldSelectorV1 {
    /// The accepted `persona.preference_weights` field.
    PersonaPreferenceWeights,
}

/// Field outcomes delivered through the callback, rather than outer refusals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubjectFieldReadError {
    /// Session locked, destruction pending, or the owner adapter unavailable.
    /// This is transient and must not be cached as a field state or Projection.
    KeyUnavailable,
    /// Context, authentication, canonical decoding, or semantic validation failed.
    Integrity,
    /// No latest committed value exists for the selected field.
    NoValue,
}

/// Exactly five outcomes: `Present`, `RedactedDestroyed`, or the three field errors.
/// Only a committed destroyed-key tombstone produces `RedactedDestroyed`.
pub type SubjectFieldReadResultV1 = Result<FieldStateV1, SubjectFieldReadError>;

/// Fixed payload-free callback failure; diagnostics remain caller-owned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubjectFieldReadCallbackErrorV1 {
    /// The trusted callback declined or failed after receiving its result.
    Failed,
}

/// Closed outer results, separate from the five callback outcomes.
///
/// The first six variants imply zero callbacks. `CallbackFailed` and
/// `TransactionFinishFailedAfterDelivery` imply exactly one. An uncertain
/// transaction finish permanently quarantines the bound context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubjectFieldOwnerReadErrorV1 {
    /// Earlier cleanup/closure was unproved; no lower lock was acquired.
    ContextQuarantined,
    /// Another supported operation owns admission; no lower lock was acquired.
    OperationActive,
    /// The exact-Timeline erasure row was present, unreadable, or malformed;
    /// no decrypt occurred and transaction closure succeeded.
    ErasureFenced,
    /// Erasure was fenced and transaction closure also failed or was unproved.
    /// The distinct erasure classification is preserved; the context is quarantined.
    ErasureFencedTransactionFinishFailed,
    /// Non-erasure infrastructure failed before an outcome; closure was proved.
    ReadUnavailableBeforeDelivery,
    /// Non-erasure infrastructure failed before delivery and closure was unproved.
    /// The context is quarantined; this never replaces an erasure-fenced result.
    TransactionFinishFailedBeforeDelivery,
    /// Callback returned `Failed`; adapter cleanup and transaction closure succeeded.
    CallbackFailed,
    /// Delivery occurred, then closure failed or was unproved; context quarantined.
    /// This dominates callback success/failure. Blind retry can repeat caller effects.
    TransactionFinishFailedAfterDelivery,
}

/// Synchronous trusted owner-read boundary; separate from the broad `EventStore`.
///
/// Every supported bound alias shares `Idle` / `Active` / `Quarantined` admission,
/// acquired before owner/session locks and the shared-store `BEGIN IMMEDIATE`.
/// The same protection covers the final exact-Timeline erasure check, latest
/// matching committed Event in Timeline Order (without fallback), key verification,
/// decrypt/validation, callback, adapter-buffer wipe and explicit rollback. Only
/// proved closure and released lower locks restore `Idle`; an armed admission
/// token defaults to permanent quarantine. Raw SQL/other processes remain outside
/// this in-process admission proof.
///
/// An admitted field result is delivered exactly once, including field errors;
/// erasure and pre-outcome infrastructure refusals deliver zero times. `Present`
/// moves one fresh independent allocation at the linearization point while the
/// adapter retains its `Zeroizing` staging through cleanup. Caller-owned plaintext
/// can survive callback return or later failure. Callers can consume the last
/// unique logical range with [`pos_core::CanonicalBytes::try_zeroize_owned`].
///
/// The inherited raw plaintext cap is 8,192 logical bytes per invocation/field
/// result. The sole selector's accepted grammar permits at most 5,442 canonical
/// bytes, hence at most 10,884 validated logical bytes in staging plus the fresh
/// handoff immediately before delivery. This excludes capacity, malformed staging,
/// crypto scratch, prior copies and caller-retained/copied data, with no cross-call
/// budget. Invalid plaintext, including raw-cap overflow, delivers `Integrity`.
///
/// Replay may use this port, but does not automatically replay callback effects.
/// Protected plaintext/results never enter a Projection; only accepted clear
/// metadata may fold. `KeyUnavailable` remains a transient cap on that run's claim.
pub trait SubjectFieldOwnerReadPortV1 {
    /// Reads one field and synchronously hands its outcome to a bounded callback.
    ///
    /// The trusted callback must not block on same-store work or reenter through
    /// any supported alias; same-thread/cross-thread reentry fails before locks.
    /// Adapter plaintext/key/scratch buffers are wiped before explicit rollback.
    /// Catch only callback unwind, clean up/finish, then resume its original panic;
    /// uncertain cleanup quarantines. Abort/process termination cleanup is unclaimed.
    ///
    /// # Errors
    ///
    /// Returns the closed outer error with the delivery count and finish state
    /// documented above. A failed finish dominates callback success/`Failed`;
    /// before delivery, erasure plus failed finish retains its combined variant.
    fn with_subject_field_read(
        &mut self,
        timeline_id: TimelineId,
        subject_id: EntityId,
        field: SubjectFieldSelectorV1,
        deliver: &mut dyn FnMut(
            SubjectFieldReadResultV1,
        ) -> Result<(), SubjectFieldReadCallbackErrorV1>,
    ) -> Result<(), SubjectFieldOwnerReadErrorV1>;
}
