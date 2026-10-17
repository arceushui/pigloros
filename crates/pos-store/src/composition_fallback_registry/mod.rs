//! The composition fallback registry port (ADR-119 section 4.3, slice #663).
//!
//! The registry keeps, per `(scope, timeline)`, the state revision, the current DFP1 policy
//! digest, each entry's tenure, effective implementation and chain position, and the activation
//! ordinal; it retains every declared DFP1 by digest and an append-only ledger of every
//! operation. A `declare` or `activate` commits the row change, its guarded Event on the target
//! Timeline, and its ledger row in one transaction on the `EventStore`'s own connection, using
//! the trust registry's durability protocol on `SQLite`, or commits nothing.
//!
//! The port is not Linux-only and does not depend on `pos-conformance`; ADR-103 does not own
//! it. The Memory adapter lives beside `MemoryStore` behind `&mut self`; the decisions in
//! `logic` are adapter-independent.

mod derived;
mod error;
#[doc(hidden)]
pub mod logic;
mod port;
// A public module keeps its crate-only items compatible with both `unreachable_pub` and
// Clippy's `redundant_pub_crate`.
pub mod types;

pub use derived::derived_fallback_state_v1;
pub use error::CompositionFallbackRegistryErrorV1;
pub use port::CompositionFallbackRegistryV1;
pub use types::{
    CompositionFallbackTargetV1, FallbackActivateRequestV1, FallbackCommitOutcomeV1,
    FallbackCommitReceiptV1, FallbackConformanceSetsV1, FallbackDeclareRequestV1,
    FallbackEntryStateV1, FallbackEventIdentityV1, FallbackLedgerBodyV1, FallbackLedgerRowV1,
    FallbackProvisionOutcomeV1, FallbackRegistryRowV1, FallbackRegistryStateV1,
};
