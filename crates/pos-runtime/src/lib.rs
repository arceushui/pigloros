#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-runtime` — the Wave 3 plugin host.
//!
//! This is the single wiring point for all kernel extension kinds.
//! It connects the `Plugin` port (pos-core) to the `EventStore` + `ProjectionRegistry`
//! infrastructure (pos-store + pos-state), and enforces the determinism contract
//! via the `Recorder`.
//!
//! # Architecture
//!
//! ```text
//! Plugin (pos-core trait)
//!   ├── Capability  → PluginRegistry validates + stores
//!   ├── Reducer     → ProjectionRegistry::register
//!   ├── Driver      → Runtime::step() calls per tick
//!   └── event schemas → SchemaRegistry validates payloads
//!
//! Recorder (this crate)
//!   ├── Live mode  → records nondeterministic outputs as events
//!   └── Replay mode → reads outputs from event log (bit-exact)
//! ```
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod composition;
pub mod driver;
pub mod error;
pub mod recorder;
pub mod registry;
pub mod scheduler;
pub mod schema;

/// Host-owned Event emitted when a session's consent revocation becomes durable.
///
/// The host registers this schema without assigning ownership to a Plugin so a
/// revocation can be recovered from a Timeline without granting a Plugin the
/// ability to revoke consent itself.
pub const HOST_CONSENT_REVOCATION_EVENT_TYPE: &str = "pos.host.consent.revoked.v1";

pub use composition::{PluginComposition, RegisteredEventSchema, RegisteredPlugin};
pub use driver::{
    Driver, DriverRecoveryEvidence, ObservationView, ProjectionKey, RecoveryEvent,
    RecoveryEventHeader, SnapshotAnchor, StepOutput, TimelineHistorySegment,
};
pub use error::RuntimeError;
pub use recorder::{RecordedOutput, Recorder, RunMode};
pub use registry::PluginRegistry;
pub use scheduler::TickScheduler;
pub use schema::SchemaRegistry;
