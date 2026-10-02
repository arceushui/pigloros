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

pub mod authorization_cache;
pub mod composition;
pub mod driver;
pub mod erasure_host;
pub mod error;
pub mod measured_process_image;
pub mod output_admission;
pub mod recorder;
pub mod registry;
pub mod reviewed_policy;
pub mod scheduled_admission_host;
pub mod scheduler;
pub mod schema;
pub mod world_profile;
pub mod world_replay;

pub use authorization_cache::AuthorizationCacheKeyV1;
pub use composition::{
    AdmittedCompositionV1, AdmittedManifestPolicySourceV1, DomainImplementationKindV1,
    ManifestRegistrationErrorV1, PluginAvailabilityV1, PluginComposition, PluginCompositionErrorV1,
    PluginExecutionModeV1, PluginIsolationV1, PluginPinFieldV1, PluginPinV1, PluginRegistrationV1,
    RegisteredEventSchema, RegisteredPlugin, RequiredPluginCompositionV1, RequiredPluginV1,
    ResolvedPluginCompositionV1, ResolvedPluginV1, MAX_REQUIRED_PLUGINS_V1,
};
pub use driver::{
    CommittedForkHandoff, Driver, DriverRecoveryEvidence, ObservationView, ProjectionKey,
    RecoveryEvent, RecoveryEventHeader, SnapshotAnchor, StepOutput, TimelineHistorySegment,
};
pub use erasure_host::{
    ClosedErasureCoordinatorAuthorityV1, ErasureCommandSenderV1, ErasureCoordinatorAuthorityV1,
    ErasureCoordinatorCompositionV1, ErasureExecutionHostV1, ErasureHostStatusV1,
    ErasureReadSenderV1,
};
pub use error::{ActionSubmissionError, RuntimeError, WorldInstallationErrorV1};
pub use measured_process_image::MeasuredProcessImageV1;
pub use output_admission::{
    validate_output_policy_artifacts_v1, OutputAdmissionErrorV1, OutputAdmissionV1,
    OutputPolicyBindingV1, OutputPolicyClosureV1, OutputPolicySourceV1,
    MAX_OUTPUT_POLICY_CLOSURE_BYTES_V1,
};
pub use recorder::{RecordedOutput, Recorder, RunMode};
pub use registry::{
    recover_local_cut_owner_retry_v1, recover_manifest_owner_admission_retry_v1,
    AuthorizedDriverViewV1, AuthorizedViewAuthorityV1, ClosedAdapterTranscriptV1,
    HostCatalogueEntryV1, HumanActionAdmissionErrorV1, HumanActionAdmissionV1,
    HumanActionReceiptV1, InstalledPluginFactoryV1, InstalledPluginProductV1, LocalAdapterErrorV1,
    LocalAdapterIdempotencyKeyV1, LocalAdapterProviderResponseV1, LocalAdapterProviderV1,
    LocalAdapterSessionV1, OperationContext, PluginRegistry, ScheduledPassAdmissionV1,
};
pub use reviewed_policy::{
    canonical_plugin_configuration_v1, execution_profile_artifact_hash_v1, host_artifact_hash_v1,
    implementation_artifact_hash_v1, installed_plugin_role_v1, reviewed_retention_policy_bytes_v1,
    reviewed_retention_policy_hash_v1, ReviewedPolicyArtifactErrorV1,
    MAX_PLUGIN_CONFIGURATION_ARTIFACT_BYTES_V1, MAX_PLUGIN_CONFIGURATION_DETAILS_BYTES_V1,
    MAX_PLUGIN_IMPLEMENTATION_ARTIFACT_BYTES_V1,
};
#[cfg(feature = "local-admission-host")]
pub use scheduled_admission_host::LocalScheduledAdmissionHostV1;
pub use scheduled_admission_host::{ScheduledAdmissionPortsV1, ScheduledAdmissionStoreV1};
pub use scheduler::TickScheduler;
pub use schema::SchemaRegistry;
pub use world_profile::HostWorldProfileV1;
pub use world_replay::{
    VerifiedWorldReplayV1, WorldReplayUseV1, WorldReplayVerificationErrorV1, WorldReplayVerifierV1,
};
