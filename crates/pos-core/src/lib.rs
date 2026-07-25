#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-core` — the five kernel primitives.
//!
//! No I/O, no async, no domain logic. Everything else depends on this crate.
//! Plugins are forbidden from importing domain concepts through this crate.
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

pub mod clock;
pub mod crypto;
pub mod entity;
pub mod error;
pub mod event;
pub mod hasher;
pub mod ids;
pub mod manifest;
pub mod plugin;
pub mod schema;
pub mod state;
pub mod store;
pub mod timeline;

// Re-export commonly used types at the crate root.
pub use clock::{Seq, SimDuration, SimTime, WallTime};
pub use crypto::{Hash, PublicKey, Signature};
pub use entity::{Entity, EntityKind, Relationship, RelationshipKind};
pub use error::CoreError;
pub use event::{CanonicalBytes, Determinism, Event, EventDraft, Kind, RunMode, SchemaVersion};
pub use hasher::Hasher;
pub use ids::{CorrelationId, EntityId, EventId, PluginId, RelationshipId, TimelineId};
pub use manifest::{AdapterRecord, ReproManifest};
pub use plugin::{Capability, Plugin};
pub use schema::{SchemaVersionMap, Upcaster, UpcasterRegistry};
pub use state::{Reducer, State, StateRegistry};
pub use store::{
    export_timeline, export_timeline_cow, export_timeline_own, export_timeline_raw,
    import_committed_with_rollback, import_timeline, import_timeline_with_id,
    validate_committed_batch, EventStore, SeqRange, TimelineExport,
};
pub use timeline::{Timeline, TimelineMeta, TimelineMode};
