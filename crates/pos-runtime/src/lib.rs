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
#[cfg(target_os = "linux")]
pub mod counterfactual;
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
pub mod staged_executor;
pub mod trusted_clock;
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
pub use pos_state::{
    DetachedProjectionCandidateV1, InitialStateV1, ProjectionCandidateErrorV1,
    ProtectedProjectionProviderV1, RecordedConsumerV1,
};
pub use recorder::{RecordedOutput, Recorder, RunMode};
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub use registry::is_reviewed_staged_factory;
pub use registry::{
    fold_detached_candidate_v1, recover_local_cut_owner_retry_v1,
    recover_manifest_owner_admission_retry_v1, AuthorizedDriverViewV1, AuthorizedViewAuthorityV1,
    ClosedAdapterTranscriptV1, HostCatalogueEntryV1, HostProjectionProviderV1,
    HumanActionAdmissionErrorV1, HumanActionAdmissionV1, HumanActionReceiptV1,
    InstalledPluginFactoryV1, InstalledPluginProductV1, LocalAdapterErrorV1,
    LocalAdapterIdempotencyKeyV1, LocalAdapterProviderResponseV1, LocalAdapterProviderV1,
    LocalAdapterSessionV1, NoActionApproverV1, OperationContext, PluginRegistry,
    ScheduledDriverBindingV1, ScheduledPassAdmissionV1, ScheduledProfileErrorV1,
    StagedGrowthBoundV1, StagedReducerAdmissionErrorV1, StagedReducerAdmissionV1,
    EMPTY_CONFIGURATION_DETAILS_V1, MAX_STAGED_CALLBACK_BOUND_V1,
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
pub use staged_executor::{
    check_handoff_reserve, require_staged_release, teardown_signal, ExecutorHealthV1,
    GuardedFoldWindowV1, StagedFoldErrorV1, StagedFoldExecutorV1, StagedFoldPlanV1,
    GUARD_RELEASE_LATE_SIGNAL, MAX_STAGED_INPUT_BYTES_V1, MEASURED_PREPARE_BOUND_V1,
    MEASURED_TEARDOWN_BOUND_V1, STAGED_ACCOUNTING_PASS_BOUND_V1, STAGED_FOLD_DEADLINE_V1,
    STAGED_FOLD_WORKER_NAME_V1, STAGED_HANDOFF_DEADLINE_V1,
};
pub use trusted_clock::handoff;
pub use world_profile::HostWorldProfileV1;
pub use world_replay::{
    VerifiedWorldReplayV1, WorldReplayUseV1, WorldReplayVerificationErrorV1, WorldReplayVerifierV1,
};
