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
pub mod erasure_host;
pub mod error;
pub mod output_admission;
pub mod recorder;
pub mod registry;
pub mod reviewed_policy;
pub mod scheduler;
pub mod schema;

pub use composition::{
    DomainImplementationKindV1, PluginAvailabilityV1, PluginComposition, PluginCompositionErrorV1,
    PluginExecutionModeV1, PluginIsolationV1, PluginPinFieldV1, PluginPinV1, PluginRegistrationV1,
    RegisteredEventSchema, RegisteredPlugin, RequiredPluginCompositionV1, RequiredPluginV1,
    ResolvedPluginCompositionV1, ResolvedPluginV1, MAX_REQUIRED_PLUGINS_V1,
};
pub use driver::{
    Driver, DriverRecoveryEvidence, ObservationView, ProjectionKey, RecoveryEvent,
    RecoveryEventHeader, SnapshotAnchor, StepOutput, TimelineHistorySegment,
};
pub use erasure_host::{
    ClosedErasureCoordinatorAuthorityV1, ErasureCommandSenderV1, ErasureCoordinatorAuthorityV1,
    ErasureCoordinatorCompositionV1, ErasureExecutionHostV1, ErasureHostStatusV1,
    ErasureReadSenderV1,
};
pub use error::{ActionSubmissionError, RuntimeError};
pub use output_admission::{OutputAdmissionErrorV1, OutputAdmissionV1};
pub use recorder::{RecordedOutput, Recorder, RunMode};
pub use registry::{AuthorizedDriverTargetV1, OperationContext, PluginRegistry};
pub use reviewed_policy::{
    canonical_plugin_configuration_v1, execution_profile_artifact_hash_v1, host_artifact_hash_v1,
    implementation_artifact_hash_v1, reviewed_retention_policy_hash_v1,
};
pub use scheduler::TickScheduler;
pub use schema::SchemaRegistry;
