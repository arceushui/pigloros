//! The composition fallback registry port (ADR-119 section 4.3).

use pos_core::{Hash, TimelineId};

use super::error::CompositionFallbackRegistryErrorV1;
use super::types::{
    FallbackActivateRequestV1, FallbackCommitReceiptV1, FallbackDeclareRequestV1,
    FallbackLedgerRowV1, FallbackProvisionOutcomeV1, FallbackRegistryRowV1,
};

/// The durable composition fallback registry (ADR-119 section 4.3).
///
/// State is keyed by `(scope, timeline)`. Each write commits, in one transaction on the
/// `EventStore`'s own connection, the row change, the guarded declaration or activation Event on
/// the target Timeline, and one ledger row, or nothing. The row must equal the fold of its
/// Timeline's declaration and activation Events; any divergence is `CorruptState`.
///
/// A write checks, in the order of ADR-119 clarification 7: record decode (`InvalidRecord`,
/// `ScopeMismatch`); the fold invariant (`CorruptState`); `EntityMismatch`; idempotency (a
/// byte-identical repeat returns the original ledger row, any other request for the occupied key
/// is a `Conflict`); staleness (`StaleState`, then `StaleHead`); then the operation's own checks.
/// `scripts/check_composition_fallback_registry_impls.py` restricts implementations and call
/// sites to the trusted host.
pub trait CompositionFallbackRegistryV1 {
    /// Create the registry tables, or confirm the complete set already exists.
    ///
    /// # Errors
    /// `CorruptState` for a partial or different table set, or a storage error.
    fn provision_fallback_registry(
        &mut self,
    ) -> Result<FallbackProvisionOutcomeV1, CompositionFallbackRegistryErrorV1>;

    /// Declare, re-base, or withdraw the policy of `(scope, timeline)`.
    ///
    /// The identity of a repeat is the entity, the policy digest, and the conformance sets; the
    /// expected revision and head are not part of it, so a retry after an indeterminate commit
    /// replays even though it names the old revision.
    ///
    /// `PrimaryNotEffective` is checked only for entries the registry has recorded. An entry it
    /// has never recorded is in tenure 0 on the composer's base implementation, which the port
    /// cannot see: the runtime `declare` (slice 4) must pre-check every such entry's primary
    /// against the composer's base composition before it calls the port.
    ///
    /// # Errors
    /// The closed registry error of the first failing check.
    fn declare(
        &mut self,
        request: &FallbackDeclareRequestV1,
    ) -> Result<FallbackCommitReceiptV1, CompositionFallbackRegistryErrorV1>;

    /// Close one entry's tenure and open the next on another declared implementation.
    ///
    /// Idempotency compares every argument, the expected revision, the expected head, and the
    /// Tick included. A retry with re-read expected values is therefore a `Conflict`, not a
    /// replay; recovery after an indeterminate commit goes through `lookup_activation`.
    ///
    /// # Errors
    /// The closed registry error of the first failing check.
    fn activate(
        &mut self,
        request: &FallbackActivateRequestV1,
    ) -> Result<FallbackCommitReceiptV1, CompositionFallbackRegistryErrorV1>;

    /// The stored row of `(scope, timeline)`, or `None` before its first operation.
    ///
    /// # Errors
    /// `MissingState` before provisioning, `CorruptState`, or a storage error.
    fn registry_row(
        &self,
        scope: &str,
        timeline: TimelineId,
    ) -> Result<Option<FallbackRegistryRowV1>, CompositionFallbackRegistryErrorV1>;

    /// The ledger row of the declaration of `policy_digest` on `(scope, timeline)`.
    ///
    /// # Errors
    /// `MissingState` before provisioning, `CorruptState`, or a storage error.
    fn lookup_declaration(
        &self,
        scope: &str,
        timeline: TimelineId,
        policy_digest: Hash,
    ) -> Result<Option<FallbackLedgerRowV1>, CompositionFallbackRegistryErrorV1>;

    /// The ledger row of the activation that closed `(entry_key, closing_tenure_ordinal)`.
    ///
    /// # Errors
    /// `MissingState` before provisioning, `CorruptState`, or a storage error.
    fn lookup_activation(
        &self,
        scope: &str,
        timeline: TimelineId,
        entry_key: &str,
        closing_tenure_ordinal: u64,
    ) -> Result<Option<FallbackLedgerRowV1>, CompositionFallbackRegistryErrorV1>;

    /// The retained DFP1 bytes of `policy_digest`.
    ///
    /// # Errors
    /// `MissingState` before provisioning, `CorruptState`, or a storage error.
    fn retained_policy(
        &self,
        policy_digest: Hash,
    ) -> Result<Option<Vec<u8>>, CompositionFallbackRegistryErrorV1>;

    /// The append-only ledger of `(scope, timeline)` in row order.
    ///
    /// # Errors
    /// `MissingState` before provisioning, `CorruptState`, or a storage error.
    fn fallback_ledger(
        &self,
        scope: &str,
        timeline: TimelineId,
    ) -> Result<Vec<FallbackLedgerRowV1>, CompositionFallbackRegistryErrorV1>;
}
