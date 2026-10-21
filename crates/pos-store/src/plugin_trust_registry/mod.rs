//! The Plugin trust policy registry port (ADR-103 revisions 4 and 5, slices #568 and #580).
//!
//! The registry persists the operator-pinned anchor, the authenticated TPS1
//! continuity, the PTR1/PRV1 floors, the highest trusted UTC second, the
//! scoped release chain, and an append-only ledger. Every admission and every
//! rollback commits its decision, its activation Event, the active pointer,
//! and its ledger row in one transaction, or commits nothing. The read-only
//! `evaluate_current_release` (revision 5) re-runs the admission checks at a
//! fresh UTC second and Tick against the retained state and writes nothing.
//!
//! A decision, receipt, retained record, or ledger row claims trust-policy
//! admission only. The PMF1 publisher signature is verified nowhere in this
//! module, and no type here has a signature-validity field.
//!
//! The registry exists only on Linux, because `pos-conformance` builds only
//! there: a non-Linux build exposes no Plugin admission surface, which fails
//! closed by absence. The Memory adapter lives beside `MemoryStore`; the
//! shared decision logic in `logic` is adapter-independent.

mod error;
#[doc(hidden)]
pub mod logic;
mod port;
// A public module keeps its crate-only items compatible with both `unreachable_pub` and
// Clippy's `redundant_pub_crate`.
pub mod types;
mod utc;

pub use error::PluginTrustPolicyRegistryErrorV1;
pub use port::PluginTrustPolicyRegistryV1;
pub use types::{
    ActivationEventIdentityV1, ActivationEventInputV1, ActiveReleaseV1,
    AdmittedPluginReleaseReceiptV1, CurrentReleaseEvaluationV1, PluginRollbackReceiptV1,
    PluginTrustCommitOutcomeV1, PluginTrustLedgerKindV1, PluginTrustLedgerRowV1,
    PolicyAdvanceKindV1, PolicyAdvanceOutcomeV1, ProvisionOutcomeV1, RetainedPolicyStateV1,
    RetainedReleaseDecisionV1,
};
pub use utc::TrustedUtcSecondV1;
