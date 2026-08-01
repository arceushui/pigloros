#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-core` — the five kernel primitives.
//!
//! No I/O or async. Everything else depends on this crate.
//! Core-owned security policy may live here when an accepted ADR requires a
//! non-bypassable cross-cutting boundary; Plugins remain forbidden from owning
//! those protected domain concepts.
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

pub mod clock;
pub mod crypto;
pub mod entity;
pub mod error;
pub mod event;
pub mod geo_access;
pub mod geo_admission;
pub mod hasher;
pub mod ids;
pub mod manifest;
pub mod plugin;
pub mod state;
pub mod store;
pub mod timeline;

// Re-export commonly used types at the crate root.
pub use clock::{
    AdmissionClock, FixedAdmissionClock, Seq, SimDuration, SimTime, SystemAdmissionClock, WallTime,
};
pub use crypto::{Hash, PublicKey, Signature};
pub use entity::{Entity, EntityKind, Relationship, RelationshipKind};
pub use error::CoreError;
pub use event::{CanonicalBytes, Determinism, Event, EventDraft, Kind, RunMode, SchemaVersion};
pub use geo_access::{is_geographic_event_type, GEOGRAPHIC_CELL_EVENT_TYPE, GEOGRAPHIC_EVENT_TYPE};
pub use hasher::Hasher;
pub use ids::{CorrelationId, EntityId, EventId, PluginId, RelationshipId, TimelineId};
pub use manifest::{AdapterRecord, ReproManifest};
pub use plugin::{Capability, Plugin};
pub use state::{Reducer, State, StateRegistry};
pub use store::{
    append_identity_expires_at, checked_append_identity_expires_at, export_timeline,
    export_timeline_cow, export_timeline_own, export_timeline_raw, import_committed_with_rollback,
    import_timeline, import_timeline_with_id, validate_committed_batch, AppendDedupKey,
    AppendDedupScope, AppendIdentity, AppendIntent, AppendOrDuplicateOutcome, EventReadBounds,
    EventStore, PurgeOutcome, SeqRange, TimelineExport, APPEND_IDENTITY_RETENTION_MICROS,
};
pub use timeline::{Timeline, TimelineMeta, TimelineMode};
