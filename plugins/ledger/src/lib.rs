#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-plugin-ledger` — public Prediction Ledger domain (ADR-017 / Redmine #58, #108).
//!
//! Owns event types `"ledger.prediction"` and `"ledger.outcome"` and the
//! [`LedgerStore`] port. Two adapters are first-class (ADR-017 Decision 1):
//! [`TomlLedgerStore`] (curated tier: git + OSF anchoring) and, from #109, an
//! `EventStore` adapter (live tier: signed, hash-chained events). The same
//! fold, validation, and view schema serve both.
//!
//! ```rust
//! use pos_core::ids::EntityId;
//! use pos_plugin_ledger::{decode_prediction, draft_prediction, LedgerPrediction};
//!
//! let prediction = LedgerPrediction {
//!     prediction_id: "01J3B0Y5ZK2J6MGK8D7QW3N0P4".to_owned(),
//!     title: "Kyoto vs Osaka".to_owned(),
//!     statement: "Kyoto will be chosen for the weekend trip".to_owned(),
//!     predicted_outcome: "Kyoto".to_owned(),
//!     confidence: 0.8,
//!     scenario: Some("places".to_owned()),
//!     made_at: "2026-07-25T12:00:00Z".to_owned(),
//!     resolve_by: "2026-08-01".to_owned(),
//!     osf_link: "https://osf.io/example".to_owned(),
//! };
//! let draft = draft_prediction(EntityId::new(), &prediction);
//! assert_eq!(draft.event_type.as_str(), "ledger.prediction");
//! let back = decode_prediction(draft.payload.as_slice()).unwrap();
//! assert_eq!(back, prediction);
//! ```
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

mod entry;
mod event_store;
mod ledger;
pub(crate) mod payload;
mod plugin;
pub(crate) mod store;
mod toml_store;

pub use entry::{LedgerEntry, LedgerEntryView, LedgerView, Status};
pub use event_store::EventLedgerStore;
pub use ledger::{Ledger, LedgerWarning};
pub use payload::{
    decode_outcome, decode_prediction, draft_outcome, draft_prediction, LedgerOutcome,
    LedgerPrediction, ENTITY_KIND, EVENT_TYPE_OUTCOME, EVENT_TYPE_PREDICTION,
};
pub use plugin::LedgerPlugin;
pub use store::{is_valid_osf_link, LedgerError, LedgerStore, NewPrediction, ResolveStatus};
pub use toml_store::TomlLedgerStore;

#[cfg(test)]
mod contract;
