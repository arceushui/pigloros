//! The G-OPS capture adapters of the non-interference harness (ADR-062
//! Revision 8 slice N3, #1231; owner note
//! `ADR-062_R8_NonInterference_Operations`).
//!
//! Four ADR-059 rows are captured here, all over the same subject:
//!
//! - `NI-CACHE-002`: the authorization cache of a host-owned
//!   [`pos_runtime::ErasureExecutionHostV1`] (its hit, miss and eviction
//!   counts) and the warm or cold seam store.
//! - `NI-OBS-004`: the operational logs, metering and trace annotations of
//!   the community Plugin path, and a crash artifact.
//! - `NI-TIME-005`: Simulation Time and the deterministic budget against the
//!   host's wall clock and the worker watchdog.
//! - `NI-CRASH-012`: a guest's declared failure, a trap, its host error
//!   mapping and quarantine, and the next Tick's status.
//!
//! # Subject
//!
//! [`g_ops_experiment_v1`] composes an Experiment of one Tick whose one Driver
//! is a supervisor-backed `CommunityDriverV1`: every `drive` runs the
//! checked-in WAT guest (`g_ops_guest.wat`) in a fresh `pos-plugin-worker`
//! process. The guest records the invocation's observation (the permitted
//! input) as one operational log and returns one constant `EventDraft` and
//! one trace annotation. Each mode produces the subject's Event its own way:
//! - Local: a live run in a fresh process ([`serve_g_ops_local_subject_v1`]).
//! - Replay: the recorded run.
//! - Fork: the Fork's stitched Events, cut at the first Tick Boundary.
//!
//! # Denied siblings
//!
//! After the subject run the host places the unauthorized value in denied
//! sibling work the subject never sees:
//! - `NI-CACHE-002`: one to three sibling decisions cached under grants
//!   derived from the value, then invalidated, so the value decides the
//!   cache's entries, size and evictions.
//! - `NI-OBS-004` and `NI-CRASH-012`: a sibling invocation whose observation
//!   is the value, so the value becomes its log message and its declared
//!   failure's canonical coordinate; for `NI-CRASH-012` the value is the
//!   observation of two sibling community Drivers, one declaring a failure
//!   and one trapping, and names the support archive.
//! - `NI-TIME-005`: a wall-clock offset before a sibling invocation and its
//!   watchdog margin. Neither reaches Simulation Time, and the margin never
//!   fires.
//!
//! # Normalization
//!
//! The authoritative and public facets are the same closed records, built
//! only from the subject run, the host's closed categories and counts, and
//! the row's declared bounds; they are byte-exact. Each operational facet is
//! the raw typed capture of the row's #181 profile: the run's own
//! wall-clock durations, paths, metering, global counters, log messages,
//! coordinates and file names are kept only as its `excluded_sensitive`
//! bytes, which the normalizer removes. Any other normalization is refused.
//! Padded lengths are the next power of two of the surface's record length.
//!
//! The support bundle, crash report and support archive are host-built capture
//! records of this harness, not product features.
//!
//! # Warm and cold
//!
//! The cache seam store is the `SQLite` file [`G_OPS_STORE_FILE_V1`] in the
//! run's working directory. A warm case keeps one directory for its priming,
//! control and canary runs; a cold run always starts from a new file.
//!
//! The executions are engineering evidence signed with the repository
//! test-fixture-only executor key
//! ([`super::fixture_evidence::non_interference_fixture_executor_key_v1`]),
//! not an attestation.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ciborium::Value;
use pos_conformance::{
    ExecutionModeV1, NonInterferenceExecutionErrorV1, NonInterferenceFixturePairV1,
    NonInterferenceHostRunV1, NonInterferenceRawCaptureV1, NonInterferenceRawOperationalV1,
    NonInterferenceVariantV1,
};
use pos_core::{
    event::Kind,
    ids::{EntityId, PluginId, TimelineId},
    plugin::{Capability, Plugin},
    AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1,
    AuthorityGranteeV1, AuthorityPersistenceHostV1, AuthorityPersistenceStateV1,
    AuthorityRegistrySnapshotV1, AuthorityRoleV1, AuthorizationRequestDraftV1,
    AuthorizationRequestV1, CapabilityGrantDraftV1, CapabilityGrantV1, CapabilityScopeDraftV1,
    CapabilityScopeV1, ConsentEvidenceV1, ErasureRecoveryLimitsV1, Event, Hash,
    PersistedAuthorityV1, PrincipalRefV1, Seq, WallTime,
};
use pos_crypto::plugin_execution::DeterministicBudgetV1;
use pos_plugin_supervisor::test_support::{
    authorization_for, gated_with, invocation, invocation_for, negotiated_under,
};
use pos_plugin_supervisor::{
    CommunityDriverConfigV1, CommunityDriverSettingsV1, CommunityDriverV1,
    CommunityInvocationReceiptV1, CommunityPluginHandleV1, CommunityPluginSupervisorV1,
    CommunityStateV1, InvocationBindingV1, InvocationContextSourceV1, InvocationContextV1,
    ReceiptDispositionV1, WorkerProgramV1,
};
use pos_runtime::community_plugin_host::{
    classify_pass_failure, pinned_runtime_v1, CommunityPluginCeilingsV1,
    CommunityPluginExecutionProfileV1, CommunityPluginHostAbiV1, CommunityPluginHostErrorV1,
    CommunityPluginModeV1, HostInputs, InvocationReportV1, MeteringV1, NegotiatedCommunityPluginV1,
    PassFailureV1, PluginErrorCodeV1, PluginOutputV1,
};
use pos_runtime::{
    AuthorizationCacheKeyV1, Driver, ErasureCommandSenderV1, ErasureExecutionHostV1,
    ObservationView, PluginRegistry, RuntimeError,
};
use pos_state::ProjectionRegistry;
use pos_store::StoreConfig;

use super::capture::{encode, event_stream, text, uint, variant_name, SurfacesV1};
use super::{
    hex, serve_non_interference_local_subject_v1, session::recorded,
    NonInterferenceNonExecutedCauseV1, NonInterferencePreparationV1,
    NonInterferenceSessionObservationV1, NonInterferenceSessionSubjectV1,
};
use crate::{Experiment, ExperimentConfig, StopCondition};

/// The authorization, materialization and query cache row.
pub const G_OPS_CACHE_FIXTURE_ID_V1: &str = "NI-CACHE-002";
/// The logs, metrics, traces and crash reports row.
pub const G_OPS_OBSERVABILITY_FIXTURE_ID_V1: &str = "NI-OBS-004";
/// The wall clock, latency and watchdog row.
pub const G_OPS_TIME_FIXTURE_ID_V1: &str = "NI-TIME-005";
/// The failure and archive handoff row.
pub const G_OPS_CRASH_FIXTURE_ID_V1: &str = "NI-CRASH-012";
/// The G-OPS rows in matrix order.
pub const G_OPS_FIXTURE_IDS_V1: [&str; 4] = [
    G_OPS_CACHE_FIXTURE_ID_V1,
    G_OPS_OBSERVABILITY_FIXTURE_ID_V1,
    G_OPS_TIME_FIXTURE_ID_V1,
    G_OPS_CRASH_FIXTURE_ID_V1,
];
/// The `SQLite` file of a run's cache seam store.
pub const G_OPS_STORE_FILE_V1: &str = "g-ops-cache.sqlite";
/// The environment variable that names the worker program of a Local subject.
pub const G_OPS_WORKER_ENV_V1: &str = "PIGLOROS_NI_G_OPS_WORKER";
/// The subject Driver's worker watchdog: far beyond any run, so a canary
/// never fires it.
pub const G_OPS_SUBJECT_WATCHDOG_V1: Duration = Duration::from_secs(30);
/// The PMF1 Plugin ID text of the guest.
pub const G_OPS_PLUGIN_NAME_V1: &str = "ni-g-ops";
/// The Event type of the guest's one draft.
pub const G_OPS_EVENT_TYPE_V1: &str = "ni-g-ops.observed";
/// The invocation ID the host fixes for every guest invocation.
pub const G_OPS_INVOCATION_ID_V1: [u8; 16] = [0x47; 16];
/// The canonical payload of the guest's one draft: the CBOR `["g-ops", 1]`.
pub const G_OPS_EVENT_PAYLOAD_V1: &[u8] = b"\x82\x65g-ops\x01";
/// The next state the guest returns.
pub const G_OPS_NEXT_STATE_V1: &[u8] = b"g-ops-state";
/// The V1 output digest the guest embeds for its constant output.
pub const G_OPS_OUTPUT_DIGEST_V1: [u8; 32] = [
    0x4a, 0xd4, 0x14, 0x72, 0xc3, 0xa9, 0x4f, 0xa2, 0xbc, 0x9f, 0xdf, 0xf2, 0xd2, 0x1e, 0x27, 0x6b,
    0x6a, 0xd4, 0x86, 0x94, 0x7b, 0xa1, 0x37, 0x28, 0x06, 0x11, 0x08, 0x3a, 0x24, 0xb7, 0x57, 0x03,
];
/// The observation of the `NI-TIME-005` sibling invocation.
pub const G_OPS_TIME_SIBLING_OBSERVATION_V1: &[u8] = b"g-ops-time-sibling";
/// The control member's unauthorized value of every G-OPS fixture.
pub const G_OPS_CONTROL_UNAUTHORIZED_V1: &[u8] = b"ops-denied-control-1";
/// The canary member's unauthorized value of every G-OPS fixture.
pub const G_OPS_CANARY_UNAUTHORIZED_V1: &[u8] = b"canary-operational-secret-value-0042";
/// The deterministic budget of every guest invocation.
pub const G_OPS_BUDGET_V1: DeterministicBudgetV1 = DeterministicBudgetV1 {
    memory_bytes: 65_536,
    fuel: 1_000_000,
    host_calls: DeterministicBudgetV1::MAXIMA.host_calls,
    event_count: DeterministicBudgetV1::MAXIMA.event_count,
    event_bytes: DeterministicBudgetV1::MAXIMA.event_bytes,
    state_bytes: DeterministicBudgetV1::MAXIMA.state_bytes,
    log_calls: DeterministicBudgetV1::MAXIMA.log_calls,
    log_bytes: DeterministicBudgetV1::MAXIMA.log_bytes,
};

/// The guest's Simulation Time selectors.
const SELECT_OUTPUT: u64 = 0;
const SELECT_DECLARED_FAILURE: u64 = 1;
const SELECT_TRAP: u64 = 2;
/// The declared bounds the logs and coordinates are padded to.
const LOG_MESSAGE_BOUND: u64 = 256;
const COORDINATE_BOUND: u64 = 128;
const LOG_SCHEMA: &str = "pigloros.operational-log.v1";
const NONE: &str = "none";
const SIBLING_WATCHDOG: Duration = Duration::from_secs(30);
/// The run-independent identity of the subject Plugin, so every mode and
/// every Fork registers the same composition.
const G_OPS_PLUGIN_ID: PluginId = PluginId::from_ulid(ulid::Ulid::from_parts(1, 0x474f_5053));
const DRIVER_NAME: &str = "ni-g-ops.driver";
const STATE_SCHEMA: [u8; 32] = [0x53; 32];
const INITIAL_STATE: &[u8] = b"g-ops-initial";
const AUTHORITY_TIMELINE: &str = "ni-g-ops-authority";
const RESOURCE_TIMELINE: &str = "ni-g-ops-resource";
const TRUST_DOMAIN: &str = "local.test";
const GUEST_WAT: &str = include_str!("g_ops_guest.wat");

/// The host side of the G-OPS subject: the compiled guest and the supervisor
/// that runs the subject Driver's workers.
#[derive(Clone, Debug)]
pub struct GOpsHostV1 {
    component: Vec<u8>,
    worker: PathBuf,
    supervisor: CommunityPluginSupervisorV1,
}

impl GOpsHostV1 {
    /// The host whose workers run `worker`, an absolute path, with the
    /// subject Driver's watchdog `subject_watchdog`; `None` for a relative
    /// path or a watchdog the supervisor refuses.
    #[must_use]
    pub fn new(worker: PathBuf, subject_watchdog: Duration) -> Option<Self> {
        supervisor(&worker, subject_watchdog).and_then(|supervisor| {
            wat::parse_str(GUEST_WAT).ok().map(|component| Self {
                component,
                worker,
                supervisor,
            })
        })
    }
}

fn supervisor(worker: &Path, watchdog: Duration) -> Option<CommunityPluginSupervisorV1> {
    WorkerProgramV1::new(worker.to_path_buf())
        .and_then(|program| CommunityPluginSupervisorV1::new(program, watchdog))
}

/// The permitted input of one G-OPS fixture. It is the same in every mode.
#[must_use]
pub fn g_ops_permitted_input_v1(fixture_id: &str, variant: NonInterferenceVariantV1) -> Vec<u8> {
    format!(
        "g-ops permitted input v1/{fixture_id}/{}",
        variant_name(variant)
    )
    .into_bytes()
}

/// The admitted control/canary pair of one G-OPS coordinate. The two members
/// differ only in their unauthorized value.
///
/// # Errors
/// Returns the #181 admission error of an invalid coordinate.
pub fn g_ops_fixture_v1(
    fixture_id: &str,
    variant: NonInterferenceVariantV1,
    mode: ExecutionModeV1,
) -> Result<NonInterferenceFixturePairV1, NonInterferenceExecutionErrorV1> {
    NonInterferenceFixturePairV1::try_new(
        fixture_id,
        variant,
        mode,
        g_ops_permitted_input_v1(fixture_id, variant),
        G_OPS_CONTROL_UNAUTHORIZED_V1.to_vec(),
        G_OPS_CANARY_UNAUTHORIZED_V1.to_vec(),
    )
}

/// The execution profile of the real worker: Local, the V1 ceilings and the
/// worker engine's pinned runtime.
#[must_use]
pub fn g_ops_profile_v1() -> CommunityPluginExecutionProfileV1 {
    CommunityPluginExecutionProfileV1::new(
        CommunityPluginModeV1::Local,
        CommunityPluginCeilingsV1::V1,
        Some(pinned_runtime_v1()),
    )
}

fn negotiated() -> NegotiatedCommunityPluginV1 {
    negotiated_under(
        G_OPS_PLUGIN_NAME_V1,
        G_OPS_BUDGET_V1,
        Vec::new(),
        &g_ops_profile_v1(),
    )
}

/// The handles of the subject Drivers one run built: the parent's, then a
/// Fork's. The capture reads the last.
#[derive(Clone, Debug, Default)]
pub struct GOpsSubjectHandlesV1 {
    handles: Arc<Mutex<Vec<CommunityPluginHandleV1>>>,
}

impl GOpsSubjectHandlesV1 {
    fn push(&self, handle: CommunityPluginHandleV1) {
        drop(self.handles.lock().map(|mut handles| handles.push(handle)));
    }

    /// The handle of the last subject Driver built.
    #[must_use]
    pub fn current(&self) -> Option<CommunityPluginHandleV1> {
        self.handles
            .lock()
            .ok()
            .and_then(|handles| handles.last().cloned())
    }
}

/// Builds every subject invocation from the permitted input alone, at
/// Simulation Time 0, under the fixed invocation ID.
struct GOpsSource {
    observation: Vec<u8>,
    selector: u64,
}

impl InvocationContextSourceV1 for GOpsSource {
    fn context(
        &mut self,
        _timeline: TimelineId,
        _observation: &ObservationView<'_>,
        binding: InvocationBindingV1,
    ) -> Result<InvocationContextV1, CommunityPluginHostErrorV1> {
        let mut invocation =
            pos_plugin_supervisor::test_support::bound(invocation(&self.observation), binding);
        invocation.invocation_id = G_OPS_INVOCATION_ID_V1;
        Ok(InvocationContextV1 {
            invocation,
            host_inputs: HostInputs {
                simulation_time: self.selector,
            },
        })
    }
}

/// A community Driver of the guest whose invocations carry `observation` at
/// Simulation Time `selector`, holding its pass authorization, and its
/// handle.
fn community_driver(
    host: &GOpsHostV1,
    observation: &[u8],
    selector: u64,
) -> Result<(CommunityDriverV1, CommunityPluginHandleV1), CommunityPluginHostErrorV1> {
    let settings = CommunityDriverSettingsV1 {
        plugin_id: G_OPS_PLUGIN_ID,
        name: DRIVER_NAME,
        tick_interval: Duration::from_millis(100),
        subscriptions: Vec::new(),
        supervisor: host.supervisor.clone(),
        source: Box::new(GOpsSource {
            observation: observation.to_vec(),
            selector,
        }),
        initial_state: CommunityStateV1 {
            schema: STATE_SCHEMA,
            bytes: INITIAL_STATE.to_vec(),
        },
    };
    CommunityDriverConfigV1::from_gated(
        gated_with(
            G_OPS_PLUGIN_NAME_V1,
            G_OPS_BUDGET_V1,
            Vec::new(),
            host.component.clone(),
        ),
        &CommunityPluginHostAbiV1::v1(),
        &g_ops_profile_v1(),
        // The Plugin's name is its PMF1 Plugin ID text.
        GOpsPlugin.name(),
        settings,
    )
    .map(CommunityDriverV1::new)
    .and_then(|(driver, handle)| {
        handle
            .offer_authorization(authorization_for(&negotiated(), &host.component))
            .map(|()| (driver, handle))
    })
}

/// A subject Driver over `permitted_input`, recorded in `handles`.
fn subject_driver(
    host: &GOpsHostV1,
    permitted_input: &[u8],
    handles: &GOpsSubjectHandlesV1,
) -> Result<CommunityDriverV1, CommunityPluginHostErrorV1> {
    community_driver(host, permitted_input, SELECT_OUTPUT).map(|(driver, handle)| {
        handles.push(handle);
        driver
    })
}

/// Compose the G-OPS subject Experiment of one Tick for one run, with the
/// handles of its subject Drivers.
///
/// # Errors
/// Returns `Unavailable` when the Driver cannot be built or registered.
pub fn g_ops_experiment_v1(
    host: &GOpsHostV1,
    permitted_input: &[u8],
) -> Result<(Experiment, GOpsSubjectHandlesV1), NonInterferenceNonExecutedCauseV1> {
    let handles = GOpsSubjectHandlesV1::default();
    let (fork_host, fork_input, fork_handles) =
        (host.clone(), permitted_input.to_vec(), handles.clone());
    let mut experiment = Experiment::new(ExperimentConfig {
        name: "ni-g-ops".to_owned(),
        stop: StopCondition::MaxTicks(1),
        store_config: StoreConfig::Memory,
    })
    .with_fork_registry_factory(move |_| {
        subject_driver(&fork_host, &fork_input, &fork_handles)
            .map_err(RuntimeError::from)
            .and_then(|driver| {
                let mut registry = PluginRegistry::new();
                registry
                    .register_generated(&GOpsPlugin, None, Some(Box::new(driver)))
                    .map(|()| registry)
            })
    });
    subject_driver(host, permitted_input, &handles)
        .ok()
        .and_then(|driver| {
            experiment
                .register_generated(&GOpsPlugin, None, Some(Box::new(driver)))
                .ok()
        })
        .map(|()| (experiment, handles))
        .ok_or(NonInterferenceNonExecutedCauseV1::Unavailable)
}

/// One host run as the capture adapters see it. It has no `Debug` form: the
/// unauthorized value never reaches a diagnostic.
#[derive(Clone, Copy)]
pub struct GOpsRunV1<'a> {
    pub fixture_id: &'a str,
    pub variant: NonInterferenceVariantV1,
    pub permitted_input: &'a [u8],
    /// Host-owned: placed only in the denied sibling work.
    pub unauthorized_value: &'a [u8],
}

/// What the subject run left for the capture: its Events in Timeline Order
/// and its Driver's handle.
#[derive(Clone, Copy)]
pub struct GOpsObservationV1<'a> {
    pub events: &'a [Event],
    pub handle: &'a CommunityPluginHandleV1,
}

/// Capture one run's G-OPS surfaces, with the run's working directory
/// `directory`.
///
/// # Errors
/// Returns `Missing` for a row without a G-OPS capture adapter, and
/// `Unavailable` when the subject's Events, its receipt or a host seam cannot
/// be read.
pub fn g_ops_capture_v1(
    host: &GOpsHostV1,
    run: &GOpsRunV1<'_>,
    observation: &GOpsObservationV1<'_>,
    directory: &Path,
) -> Result<NonInterferenceRawCaptureV1, NonInterferenceNonExecutedCauseV1> {
    let subject = SubjectV1::read(run, observation)?;
    match run.fixture_id {
        G_OPS_CACHE_FIXTURE_ID_V1 => cache_surfaces(run, &subject, directory),
        G_OPS_OBSERVABILITY_FIXTURE_ID_V1 => observability_surfaces(host, run, &subject, directory),
        G_OPS_TIME_FIXTURE_ID_V1 => time_surfaces(host, run, &subject),
        G_OPS_CRASH_FIXTURE_ID_V1 => crash_surfaces(host, run, observation.handle),
        _ => Err(NonInterferenceNonExecutedCauseV1::Missing),
    }
    .map(|surfaces| surfaces.into_capture(run.fixture_id))
}

/// Serve one Local run of the G-OPS subject in a fresh host process whose
/// working directory is `directory`.
///
/// # Errors
/// Returns the cause of a request, subject, capture or frame failure.
pub fn serve_g_ops_local_subject_v1<R: Read, W: Write>(
    host: &GOpsHostV1,
    input: R,
    output: W,
    directory: &Path,
) -> Result<(), NonInterferenceNonExecutedCauseV1> {
    serve_non_interference_local_subject_v1(input, output, |request| {
        g_ops_experiment_v1(host, &request.permitted_input).and_then(|(experiment, handles)| {
            live_events(experiment).and_then(|events| {
                handles
                    .current()
                    .ok_or(NonInterferenceNonExecutedCauseV1::Unavailable)
                    .and_then(|handle| {
                        g_ops_capture_v1(
                            host,
                            &GOpsRunV1 {
                                fixture_id: &request.fixture_id,
                                variant: request.variant,
                                permitted_input: &request.permitted_input,
                                unauthorized_value: &request.unauthorized_value,
                            },
                            &GOpsObservationV1 {
                                events: &events,
                                handle: &handle,
                            },
                            directory,
                        )
                    })
            })
        })
    })
}

/// Run a Local subject live to its stop condition and read its Events.
fn live_events(experiment: Experiment) -> Result<Vec<Event>, NonInterferenceNonExecutedCauseV1> {
    experiment
        .start()
        .map_err(NonInterferenceNonExecutedCauseV1::from)
        .and_then(|mut session| recorded(&mut session))
        .map(|(_, events)| events)
}

/// The G-OPS subject of the Replay and Fork runners.
#[derive(Debug)]
pub struct GOpsSessionSubjectV1 {
    host: GOpsHostV1,
    work_root: PathBuf,
    directories: u64,
    warm: Option<PathBuf>,
    directory: PathBuf,
    handles: GOpsSubjectHandlesV1,
}

impl GOpsSessionSubjectV1 {
    /// A subject whose run directories are created below `work_root`.
    #[must_use]
    pub fn new(host: GOpsHostV1, work_root: PathBuf) -> Self {
        Self {
            host,
            directory: work_root.clone(),
            work_root,
            directories: 0,
            warm: None,
            handles: GOpsSubjectHandlesV1::default(),
        }
    }

    fn fresh_directory(&mut self) -> Result<PathBuf, NonInterferenceNonExecutedCauseV1> {
        self.directories += 1;
        let directory = self.work_root.join(format!("run-{}", self.directories));
        fs::create_dir_all(&directory)
            .map(|()| directory)
            .map_err(NonInterferenceNonExecutedCauseV1::from)
    }
}

impl NonInterferenceSessionSubjectV1 for GOpsSessionSubjectV1 {
    fn prepare(
        &mut self,
        preparation: NonInterferencePreparationV1,
    ) -> Result<(), NonInterferenceNonExecutedCauseV1> {
        self.warm = None;
        match preparation {
            NonInterferencePreparationV1::Warm => self
                .fresh_directory()
                .map(|directory| self.warm = Some(directory)),
            NonInterferencePreparationV1::Cold => Ok(()),
        }
    }

    fn compose(
        &mut self,
        run: &NonInterferenceHostRunV1<'_>,
        _preparation: NonInterferencePreparationV1,
    ) -> Result<Experiment, NonInterferenceNonExecutedCauseV1> {
        self.warm
            .clone()
            .map_or_else(|| self.fresh_directory(), Ok)
            .and_then(|directory| {
                self.directory = directory;
                g_ops_experiment_v1(&self.host, run.subject.permitted_input)
            })
            .map(|(experiment, handles)| {
                self.handles = handles;
                experiment
            })
    }

    fn projections(&self) -> ProjectionRegistry {
        ProjectionRegistry::new()
            .with_erasure_gate(Arc::new(pos_core::ErasureContainmentGateV1::new_test_open()))
    }

    fn capture(
        &mut self,
        run: &NonInterferenceHostRunV1<'_>,
        observation: &NonInterferenceSessionObservationV1<'_>,
    ) -> Result<NonInterferenceRawCaptureV1, NonInterferenceNonExecutedCauseV1> {
        self.handles
            .current()
            .ok_or(NonInterferenceNonExecutedCauseV1::Unavailable)
            .and_then(|handle| {
                g_ops_capture_v1(
                    &self.host,
                    &GOpsRunV1 {
                        fixture_id: run.subject.fixture_id,
                        variant: run.subject.variant,
                        permitted_input: run.subject.permitted_input,
                        unauthorized_value: run.unauthorized_value,
                    },
                    &GOpsObservationV1 {
                        events: observation.events,
                        handle: &handle,
                    },
                    &self.directory,
                )
            })
    }
}

// ---------------------------------------------------------------------------
// Subject
// ---------------------------------------------------------------------------

struct GOpsPlugin;

impl Plugin for GOpsPlugin {
    fn id(&self) -> PluginId {
        G_OPS_PLUGIN_ID
    }

    fn name(&self) -> &'static str {
        G_OPS_PLUGIN_NAME_V1
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(G_OPS_EVENT_TYPE_V1)],
            owned_entity_kinds: Vec::new(),
            has_driver: true,
            has_reducer: false,
        }
    }
}

/// What every row reads of the subject run.
struct SubjectV1 {
    /// The position-relative Event stream.
    stream: Vec<u8>,
    events: u64,
    /// `[observation, Simulation Time, Tick]` of the subject invocation.
    imports: Vec<u8>,
    receipt: CommunityInvocationReceiptV1,
    receipts: u64,
}

impl SubjectV1 {
    /// The subject's one receipt and position-relative Events. A run with no
    /// receipt, or Events whose causes leave the stream, is refused.
    fn read(
        run: &GOpsRunV1<'_>,
        observation: &GOpsObservationV1<'_>,
    ) -> Result<Self, NonInterferenceNonExecutedCauseV1> {
        let receipts = observation.handle.receipts();
        receipts
            .last()
            .cloned()
            .zip(event_stream(observation.events, None))
            .map(|(receipt, stream)| Self {
                stream: encode(&stream),
                events: observation.events.len() as u64,
                imports: encode(&Value::Array(vec![
                    Value::Bytes(run.permitted_input.to_vec()),
                    uint(SELECT_OUTPUT),
                    uint(pos_plugin_supervisor::test_support::TICK),
                ])),
                receipt,
                receipts: receipts.len() as u64,
            })
            .ok_or(NonInterferenceNonExecutedCauseV1::Unavailable)
    }

    fn disposition(&self) -> Value {
        disposition_code(self.receipt.disposition)
    }

    fn failure(&self) -> Value {
        failure_text(self.receipt.failure)
    }

    /// The subject's metering, operational only.
    fn metering(&self) -> Vec<u8> {
        self.receipt
            .metering
            .as_ref()
            .map_or_else(Vec::new, metering_bytes)
    }
}

/// The guest's declared failure: `guest-declared-failure(7)`.
const DECLARED_FAILURE: u16 = 7;
const DECLARED_FAILURE_CASE: &str = "guest-declared-failure";

/// The closed code of a receipt disposition: its declaration ordinal
/// (`Staged` 0, `Committed` 1, `Discarded` 2), pinned by a test.
fn disposition_code(disposition: ReceiptDispositionV1) -> Value {
    uint(disposition as u64)
}

/// The closed code of a Plugin's availability: its declaration ordinal
/// (`Available` 0, `Disabled` 1, `Unavailable` 2, `Revoked` 3, `Trapped` 4,
/// `ResourceExhausted` 5), pinned by a test.
fn availability(handle: &CommunityPluginHandleV1) -> Value {
    uint(handle.availability() as u64)
}

/// `[case, code, whether the guest declared exactly that failure]`.
fn declared_code(code: &PluginErrorCodeV1) -> Value {
    array([
        text(DECLARED_FAILURE_CASE),
        uint(u64::from(DECLARED_FAILURE)),
        Value::Bool(*code == PluginErrorCodeV1::GuestDeclaredFailure(DECLARED_FAILURE)),
    ])
}

/// The metering's four counters, big-endian: operational only.
fn metering_bytes(metering: &MeteringV1) -> Vec<u8> {
    [
        metering.startup_fuel,
        metering.call_fuel,
        metering.memory_bytes,
        metering.host_calls,
    ]
    .iter()
    .flat_map(|value| value.to_be_bytes())
    .collect()
}

fn failure_text(failure: Option<CommunityPluginHostErrorV1>) -> Value {
    text(failure.map_or(NONE, CommunityPluginHostErrorV1::name))
}

fn records(values: impl IntoIterator<Item = Value>) -> Vec<Vec<u8>> {
    values.into_iter().map(|value| encode(&value)).collect()
}

fn array(values: impl IntoIterator<Item = Value>) -> Value {
    Value::Array(values.into_iter().collect())
}

fn pair(name: &str, value: u64) -> Value {
    array([text(name), uint(value)])
}

fn count(items: u64) -> u32 {
    u32::try_from(items).unwrap_or(u32::MAX)
}

/// The surfaces whose authoritative and public facets are the same records.
fn surfaces(
    authoritative: Vec<Vec<u8>>,
    operational: Vec<NonInterferenceRawOperationalV1>,
) -> SurfacesV1 {
    SurfacesV1 {
        public: authoritative.clone(),
        authoritative,
        operational,
    }
}

/// The padded length of a record: the next power of two of its length.
fn padded(record: &[u8]) -> u32 {
    count(record.len().next_power_of_two() as u64)
}

/// A `CategoryCountPaddedLength` facet of `record`.
fn padded_facet(
    record: &[u8],
    category: u16,
    items: u64,
    excluded_sensitive: Vec<u8>,
) -> NonInterferenceRawOperationalV1 {
    NonInterferenceRawOperationalV1::CategoryCountPaddedLength {
        category,
        count: count(items),
        padded_length: padded(record),
        excluded_sensitive,
    }
}

/// Microseconds since `start`, as operational text.
fn elapsed(start: Instant) -> Vec<u8> {
    format!("{}us", start.elapsed().as_micros()).into_bytes()
}

// ---------------------------------------------------------------------------
// Denied sibling invocations
// ---------------------------------------------------------------------------

/// One host-owned sibling invocation of the guest with `observation`, at
/// Simulation Time `selector`, under a supervisor with `watchdog`.
///
/// The `NI-OBS-004` and `NI-TIME-005` siblings call the supervisor's
/// `drive` directly because it is the only path that returns the guest's
/// `InvocationReportV1::operational_log`: the community Driver adapter keeps
/// only a receipt. The subject and the `NI-CRASH-012` siblings run through
/// `CommunityDriverV1`.
fn sibling(
    host: &GOpsHostV1,
    observation: &[u8],
    selector: u64,
    watchdog: Duration,
) -> Result<
    Result<InvocationReportV1<PluginOutputV1>, CommunityPluginHostErrorV1>,
    NonInterferenceNonExecutedCauseV1,
> {
    let negotiated = negotiated();
    let mut call = invocation_for(observation, &negotiated);
    call.invocation_id = G_OPS_INVOCATION_ID_V1;
    supervisor(&host.worker, watchdog)
        .map(|supervisor| {
            supervisor.drive(
                Some(authorization_for(&negotiated, &host.component)),
                &negotiated,
                &host.component,
                &call,
                HostInputs {
                    simulation_time: selector,
                },
            )
        })
        .ok_or(NonInterferenceNonExecutedCauseV1::Unavailable)
}

/// The sibling that declares a failure over `observation`: its log messages
/// and log categories, and its guest error's code and coordinate.
struct DeclaredV1 {
    messages: Vec<u8>,
    categories: Vec<u16>,
    code: Value,
    coordinate: Vec<u8>,
}

impl DeclaredV1 {
    fn run(
        host: &GOpsHostV1,
        observation: &[u8],
    ) -> Result<Self, NonInterferenceNonExecutedCauseV1> {
        sibling(host, observation, SELECT_DECLARED_FAILURE, SIBLING_WATCHDOG).and_then(|report| {
            report
                .ok()
                .and_then(|report| {
                    report.result.err().map(|guest| Self {
                        messages: report
                            .operational_log
                            .iter()
                            .flat_map(|record| record.message.bytes())
                            .collect(),
                        categories: report
                            .operational_log
                            .iter()
                            .map(|record| record.category)
                            .collect(),
                        code: declared_code(&guest.code),
                        coordinate: guest.canonical_coordinate.unwrap_or_default(),
                    })
                })
                .ok_or(NonInterferenceNonExecutedCauseV1::Unavailable)
        })
    }

    /// The secret-bearing diagnostics, operational only.
    fn diagnostics(&self) -> Vec<u8> {
        [self.messages.as_slice(), self.coordinate.as_slice()].concat()
    }
}

// ---------------------------------------------------------------------------
// NI-CACHE-002: authorization cache and seam store
// ---------------------------------------------------------------------------

/// One cached decision: its request, authority and registry.
struct DecisionV1 {
    request: AuthorizationRequestV1,
    authority: PersistedAuthorityV1,
    registry: AuthorityRegistrySnapshotV1,
    grant_id: Hash,
}

impl DecisionV1 {
    /// An active one-grant decision over `authority_timeline` for the grant
    /// `grant_id`.
    fn active(authority_timeline: TimelineId, grant_id: Hash) -> Option<Self> {
        PrincipalRefV1::try_new([3; 16], TRUST_DOMAIN)
            .ok()
            .zip(PrincipalRefV1::try_new([1; 16], TRUST_DOMAIN).ok())
            .zip(AssuranceLevelV1::try_new(1).ok())
            .and_then(|((principal, grantor), assurance)| {
                authorization_request(principal.clone(), assurance, authority_timeline).zip(
                    capability_grant(principal, grantor, authority_timeline, grant_id),
                )
            })
            .and_then(|(request, grant)| {
                grant
                    .binding_digest()
                    .ok()
                    .and_then(|binding| {
                        AuthorityRegistrySnapshotV1::try_new(
                            Hash::from_bytes(REGISTRY_DIGEST),
                            vec![request.authenticated().registry_binding_digest()],
                            vec![binding],
                            vec![],
                        )
                        .ok()
                    })
                    .and_then(|registry| {
                        let mut state = AuthorityPersistenceStateV1::new();
                        AuthorityPersistenceHostV1::new(&registry)
                            .authorize_grant(&grant)
                            .ok()
                            .and_then(|permit| state.issue_grant(permit, grant).ok())
                            .and_then(|_| state.resolve(grant_id).ok())
                            .map(|authority| Self {
                                request,
                                authority,
                                registry,
                                grant_id,
                            })
                    })
            })
    }
}

const REGISTRY_DIGEST: [u8; 32] = [7; 32];
const POLICY: [u8; 32] = [4; 32];
const ACTOR: EntityId = EntityId::from_ulid(ulid::Ulid::from_parts(1, 0x474f_4143));
const SUBJECT_GRANT: [u8; 32] = [16; 32];

/// The one root grant from `grantor` to `principal`: read the profile.
fn capability_grant(
    principal: PrincipalRefV1,
    grantor: PrincipalRefV1,
    authority_timeline: TimelineId,
    grant_id: Hash,
) -> Option<CapabilityGrantV1> {
    CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
        resources: vec!["profile".to_owned()],
        actions: vec!["read".to_owned()],
        purposes: vec!["planning".to_owned()],
        audiences: vec!["local-host".to_owned()],
        actor_entity_ids: vec![ACTOR],
        subject_ids: vec![],
        participant_ids: vec![],
        plugin_id: None,
        principal_roles: vec![AuthorityRoleV1::Actor],
        max_uses: 2,
        budget: 10,
        environment_constraints: vec!["local-only".to_owned()],
    })
    .ok()
    .and_then(|scope| {
        CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
            grant_id,
            grantor,
            grantee: AuthorityGranteeV1::Principal(principal),
            trust_domain: TRUST_DOMAIN.to_owned(),
            scope,
            valid_from_position: Seq::from_u64(1),
            valid_until_position: Seq::from_u64(80),
            parent_grant_id: None,
            delegation_depth: 0,
            max_delegation_depth: 0,
            permitted_delegate_classes: vec![],
            consent_references: vec![],
            policy_revision: Hash::from_bytes(POLICY),
            issuance_timeline: authority_timeline,
            issuance_seq: Seq::from_u64(1),
            revocation_epoch: 0,
            revocation_fence: None,
            authority_registry_digest: Hash::from_bytes(REGISTRY_DIGEST),
        })
        .ok()
    })
}

/// The request of `principal` to read the profile at position 10.
fn authorization_request(
    principal: PrincipalRefV1,
    assurance: AssuranceLevelV1,
    authority_timeline: TimelineId,
) -> Option<AuthorizationRequestV1> {
    AuthenticatedPrincipalResultV1::try_from_draft(AuthenticatedPrincipalDraftV1 {
        principal,
        adapter_id: "ni-g-ops-adapter".to_owned(),
        assurance,
        issued_at: WallTime::from_micros(1),
        expires_at: WallTime::from_micros(100),
        binding_digest: Hash::from_bytes([3; 32]),
    })
    .ok()
    .and_then(|authenticated| {
        AuthorizationRequestV1::try_from_draft(AuthorizationRequestDraftV1 {
            authenticated,
            actor_entity_id: ACTOR,
            subject_id: None,
            participant_id: None,
            plugin_id: None,
            installation_id: None,
            principal_role: AuthorityRoleV1::Actor,
            resource: "profile".to_owned(),
            data_category: "public".to_owned(),
            action: "read".to_owned(),
            purpose: "planning".to_owned(),
            audience: "local-host".to_owned(),
            at_time: WallTime::from_micros(10),
            authority_timeline,
            at_position: Seq::from_u64(10),
            consent_timeline: None,
            consent_at_position: None,
            use_count: 1,
            budget: 5,
            consent_policy_revision: Hash::from_bytes(POLICY),
            capability_policy_revision: Hash::from_bytes(POLICY),
            revocation_epoch: 0,
            revocation_state_current: true,
            authority_registry_digest: Hash::from_bytes(REGISTRY_DIGEST),
            consent: ConsentEvidenceV1::NotRequired,
            environment_constraints: vec!["local-only".to_owned()],
        })
        .ok()
    })
}

/// The denied sibling's grants: one more than the value's length modulo 3,
/// each derived from the value.
fn sibling_grants(unauthorized_value: &[u8]) -> Vec<Hash> {
    (0..=unauthorized_value.len() % 3)
        .map(|index| {
            let mut hasher = blake3::Hasher::new();
            hasher.update(unauthorized_value);
            hasher.update(&index.to_be_bytes());
            Hash::from_bytes(*hasher.finalize().as_bytes())
        })
        .collect()
}

/// What the cache seam showed the subject.
struct CacheSeamV1 {
    /// Per subject lookup: whether it returned an allowed cached decision.
    lookups: Vec<bool>,
    hits: u64,
    misses: u64,
    /// Operational: the global counters and the latency.
    excluded: Vec<u8>,
    /// Operational: what each sibling invalidation evicted, in its order.
    evictions: Vec<u8>,
}

/// Whether the cached decision of `key` is still returned, and allowed.
fn lookup(
    sender: &mut ErasureCommandSenderV1<'_>,
    key: &AuthorizationCacheKeyV1,
    decision: &DecisionV1,
) -> Option<bool> {
    sender
        .cached_authorization(
            key,
            WallTime::from_micros(20),
            Seq::from_u64(20),
            &decision.request,
            &decision.authority,
            &decision.registry,
        )
        .ok()
        .map(|cached| cached.is_some_and(|decision| decision.is_allowed()))
}

/// Cache `decision` for `resource`.
fn cache(
    sender: &mut ErasureCommandSenderV1<'_>,
    resource: TimelineId,
    decision: &DecisionV1,
) -> Option<AuthorizationCacheKeyV1> {
    sender
        .cache_authorization(
            resource,
            &decision.request,
            &decision.authority,
            &decision.registry,
        )
        .ok()
        .flatten()
}

/// Cache the denied sibling's decisions, then invalidate their grants, which
/// the value derives, in their order; what each invalidation evicted.
fn sibling_evictions(
    sender: &mut ErasureCommandSenderV1<'_>,
    authority: TimelineId,
    resource: TimelineId,
    unauthorized_value: &[u8],
) -> Option<Vec<u8>> {
    sibling_grants(unauthorized_value)
        .into_iter()
        .map(|grant| DecisionV1::active(authority, grant))
        .collect::<Option<Vec<_>>>()
        .and_then(|siblings| {
            siblings
                .iter()
                .try_for_each(|decision| cache(sender, resource, decision).map(drop))
                .map(|()| {
                    siblings
                        .iter()
                        .map(|decision| {
                            u8::try_from(sender.invalidate_cached_grant(decision.grant_id))
                                .unwrap_or(u8::MAX)
                        })
                        .collect()
                })
        })
}

/// The subject's decision, looked up before and after the denied sibling's
/// work: `(lookups, sibling evictions)`.
fn subject_lookups(
    sender: &mut ErasureCommandSenderV1<'_>,
    authority: TimelineId,
    resource: TimelineId,
    unauthorized_value: &[u8],
) -> Option<(Vec<bool>, Vec<u8>)> {
    DecisionV1::active(authority, Hash::from_bytes(SUBJECT_GRANT)).and_then(|subject| {
        cache(sender, resource, &subject).and_then(|key| {
            let before = lookup(sender, &key, &subject);
            let evictions = sibling_evictions(sender, authority, resource, unauthorized_value);
            let after = lookup(sender, &key, &subject);
            before
                .zip(evictions)
                .zip(after)
                .map(|((before, evictions), after)| (vec![before, after], evictions))
        })
    })
}

/// Run the subject's decision and the denied sibling's decisions through
/// the host's authorization cache over the seam store `store`.
fn cache_seam(store: &Path, unauthorized_value: &[u8]) -> Option<CacheSeamV1> {
    let start = Instant::now();
    ErasureExecutionHostV1::open_verified_empty(
        StoreConfig::Sqlite {
            path: store.to_string_lossy().into_owned(),
        },
        ErasureRecoveryLimitsV1::compiled_maximum(),
    )
    .ok()
    .and_then(|mut host| {
        host.command_sender()
            .ok()
            .and_then(|mut sender| {
                sender
                    .create_timeline(AUTHORITY_TIMELINE)
                    .ok()
                    .zip(sender.create_timeline(RESOURCE_TIMELINE).ok())
                    .and_then(|(authority, resource)| {
                        subject_lookups(
                            &mut sender,
                            authority.id(),
                            resource.id(),
                            unauthorized_value,
                        )
                    })
            })
            .map(|(lookups, evictions)| {
                let counts = host.authorization_cache_counts();
                CacheSeamV1 {
                    lookups,
                    hits: counts.hits,
                    misses: counts.misses,
                    excluded: [
                        counts.hits.to_be_bytes(),
                        counts.misses.to_be_bytes(),
                        counts.evictions.to_be_bytes(),
                    ]
                    .concat()
                    .into_iter()
                    .chain(elapsed(start))
                    .collect(),
                    evictions,
                }
            })
    })
}

/// The six `NI-CACHE-002` surfaces.
///
/// - Cache API return: per subject lookup, whether it returned the allowed
///   cached decision.
/// - snapshot bytes: the position-relative Event stream.
/// - Plugin inputs: `[observation, Simulation Time, Tick]`.
/// - typed errors: the subject's failure, or `none`.
/// - logs/metrics: the cache's hit and miss counts.
/// - evaluator bundle: `[fixture id, variant, Event stream]`.
///
/// Operationally each is a bounded count class: the hit class and count of
/// the subject's lookups, whether the seam store was reused, and counts; the
/// global counters, the evictions, the latency, the store path and the
/// reused store's earlier contents are excluded.
fn cache_surfaces(
    run: &GOpsRunV1<'_>,
    subject: &SubjectV1,
    directory: &Path,
) -> Result<SurfacesV1, NonInterferenceNonExecutedCauseV1> {
    let store = directory.join(G_OPS_STORE_FILE_V1);
    let reused = store.exists();
    let earlier = fs::metadata(&store)
        .map(|metadata| metadata.len().to_be_bytes().to_vec())
        .unwrap_or_default();
    cache_seam(&store, run.unauthorized_value)
        .map(|seam| {
            let hits = seam.lookups.iter().filter(|hit| **hit).count() as u64;
            let records = records([
                array(seam.lookups.iter().copied().map(Value::Bool)),
                Value::Bytes(subject.stream.clone()),
                Value::Bytes(subject.imports.clone()),
                array([subject.failure()]),
                array([
                    pair("authorization_cache.hits", seam.hits),
                    pair("authorization_cache.misses", seam.misses),
                ]),
                array([
                    text(run.fixture_id),
                    text(variant_name(run.variant)),
                    Value::Bytes(subject.stream.clone()),
                ]),
            ]);
            let class = |class: u16, items: u64, excluded_sensitive: Vec<u8>| {
                NonInterferenceRawOperationalV1::CountClass {
                    class,
                    count: count(items),
                    excluded_sensitive,
                }
            };
            surfaces(
                records,
                vec![
                    class(u16::from(hits == 2), hits, seam.excluded),
                    class(u16::from(reused), subject.events, earlier),
                    class(0, 1, Vec::new()),
                    class(0, 0, seam.evictions),
                    class(0, 2, Vec::new()),
                    class(0, 1, store.to_string_lossy().into_owned().into_bytes()),
                ],
            )
        })
        .ok_or(NonInterferenceNonExecutedCauseV1::Unavailable)
}

// ---------------------------------------------------------------------------
// NI-OBS-004: logs, metrics, traces, crash artifact and support bundle
// ---------------------------------------------------------------------------

/// The five `NI-OBS-004` surfaces.
///
/// - Structured logs: `[schema, [[category, message bound]...]]` of the
///   denied sibling's logs.
/// - metric names/labels/counts: the subject's receipt count, dropped trace
///   annotations and output usage.
/// - trace spans: `[["drive", disposition, annotations]]` of the subject.
/// - crash artifact: `[code, coordinate present, coordinate bound]` of the
///   sibling's declared failure.
/// - public support bundle: the member counts of the four records above.
///
/// Operationally each keeps category, count and padded length; the log
/// messages, the metering, the run path and the coordinate are excluded.
fn observability_surfaces(
    host: &GOpsHostV1,
    run: &GOpsRunV1<'_>,
    subject: &SubjectV1,
    directory: &Path,
) -> Result<SurfacesV1, NonInterferenceNonExecutedCauseV1> {
    DeclaredV1::run(host, run.unauthorized_value).and_then(|declared| {
        subject
            .receipt
            .output_usage
            .ok_or(NonInterferenceNonExecutedCauseV1::Unavailable)
            .map(|usage| {
                let logs = declared
                    .categories
                    .iter()
                    .map(|category| array([uint(u64::from(*category)), uint(LOG_MESSAGE_BOUND)]))
                    .collect::<Vec<_>>();
                let metrics = vec![
                    pair("receipts", subject.receipts),
                    pair(
                        "dropped_trace_annotations",
                        subject.receipt.dropped_trace_annotations as u64,
                    ),
                    pair("event_count", usage.event_count),
                    pair("event_payload_bytes", usage.event_payload_bytes),
                    pair("state_bytes", usage.state_bytes),
                ];
                let members = [
                    ("logs", logs.len()),
                    ("metrics", metrics.len()),
                    ("traces", 1),
                    ("crash", 1),
                ];
                let records = records([
                    array([text(LOG_SCHEMA), Value::Array(logs.clone())]),
                    Value::Array(metrics.clone()),
                    array([array([
                        text("drive"),
                        subject.disposition(),
                        uint(subject.receipt.dropped_trace_annotations as u64),
                    ])]),
                    array([
                        declared.code.clone(),
                        Value::Bool(!declared.coordinate.is_empty()),
                        uint(COORDINATE_BOUND),
                    ]),
                    array(
                        members
                            .iter()
                            .map(|(name, items)| pair(name, *items as u64)),
                    ),
                ]);
                let category = declared.categories.first().copied().unwrap_or_default();
                let operational = vec![
                    padded_facet(
                        &records[0],
                        category,
                        logs.len() as u64,
                        declared.messages.clone(),
                    ),
                    padded_facet(&records[1], 0, metrics.len() as u64, subject.metering()),
                    padded_facet(
                        &records[2],
                        0,
                        1,
                        directory.to_string_lossy().into_owned().into_bytes(),
                    ),
                    padded_facet(&records[3], 0, 1, declared.coordinate.clone()),
                    padded_facet(&records[4], 0, members.len() as u64, declared.diagnostics()),
                ];
                surfaces(records, operational)
            })
    })
}

// ---------------------------------------------------------------------------
// NI-TIME-005: Simulation Time, deterministic budget and watchdog
// ---------------------------------------------------------------------------

/// The six `NI-TIME-005` surfaces.
///
/// - Plugin imports: `[observation, Simulation Time, Tick]`.
/// - deterministic deadline: `["fuel", fuel limit, "simulation_time", 0]`.
/// - safe-stop record: the subject's and the sibling's failure, or `none`.
/// - status/error: `[subject disposition, sibling outcome]`.
/// - logs/metrics: `[[category, count]]` of the sibling's logs.
/// - evaluator input: the position-relative Event stream.
///
/// The host waits a wall-clock offset of the value's length modulo 3
/// milliseconds before the sibling, whose watchdog margin is the value's
/// first byte in milliseconds; both, the measured durations and the
/// metering are excluded.
fn time_surfaces(
    host: &GOpsHostV1,
    run: &GOpsRunV1<'_>,
    subject: &SubjectV1,
) -> Result<SurfacesV1, NonInterferenceNonExecutedCauseV1> {
    // The timing channels are deliberately small (a 0-2 ms offset and a
    // 0-255 ms watchdog margin under a 30 s watchdog): they only show that the
    // normalizer excludes wall time, and the margin never fires.
    let offset = Duration::from_millis((run.unauthorized_value.len() % 3) as u64);
    let margin = Duration::from_millis(u64::from(
        run.unauthorized_value.first().copied().unwrap_or_default(),
    ));
    let watchdog = SIBLING_WATCHDOG + margin;
    std::thread::sleep(offset);
    let start = Instant::now();
    sibling(
        host,
        G_OPS_TIME_SIBLING_OBSERVATION_V1,
        SELECT_OUTPUT,
        watchdog,
    )
    .and_then(|report| {
        report
            .ok()
            .filter(|report| report.result.is_ok())
            .ok_or(NonInterferenceNonExecutedCauseV1::Unavailable)
    })
    .map(|report| {
        let wall = [
            elapsed(start),
            format!(
                "{}ms+{}ms/{}ms",
                offset.as_millis(),
                margin.as_millis(),
                watchdog.as_millis()
            )
            .into_bytes(),
        ]
        .concat();
        let logs = report
            .operational_log
            .iter()
            .map(|record| array([uint(u64::from(record.category)), uint(1)]))
            .collect::<Vec<_>>();
        let records = records([
            Value::Bytes(subject.imports.clone()),
            array([
                text("fuel"),
                uint(negotiated().limits().values().fuel),
                text("simulation_time"),
                uint(SELECT_OUTPUT),
            ]),
            array([subject.failure(), text(NONE)]),
            array([subject.disposition(), text("output")]),
            Value::Array(logs.clone()),
            Value::Bytes(subject.stream.clone()),
        ]);
        let category = report
            .operational_log
            .first()
            .map_or(0, |record| record.category);
        let operational = vec![
            NonInterferenceRawOperationalV1::ByteExact(records[0].clone()),
            NonInterferenceRawOperationalV1::OmitOperational {
                excluded_sensitive: wall.clone(),
            },
            NonInterferenceRawOperationalV1::ByteExact(records[2].clone()),
            NonInterferenceRawOperationalV1::CategoryCount {
                category: 0,
                count: 2,
                excluded_sensitive: margin.as_millis().to_be_bytes().to_vec(),
            },
            NonInterferenceRawOperationalV1::CategoryCount {
                category,
                count: count(logs.len() as u64),
                excluded_sensitive: [metering_bytes(&report.metering), wall].concat(),
            },
            NonInterferenceRawOperationalV1::ByteExact(records[5].clone()),
        ];
        surfaces(records, operational)
    })
}

// ---------------------------------------------------------------------------
// NI-CRASH-012: failure and archive handoff
// ---------------------------------------------------------------------------

/// Run `ticks` Ticks of a host-owned denied sibling Driver over
/// `observation` at Simulation Time `selector`, outside the subject's
/// Timeline: its handle and the error of its last Tick.
fn sibling_ticks(
    host: &GOpsHostV1,
    observation: &[u8],
    selector: u64,
    ticks: usize,
) -> Result<(CommunityPluginHandleV1, Option<RuntimeError>), NonInterferenceNonExecutedCauseV1> {
    community_driver(host, observation, selector)
        .map(|(mut driver, handle)| {
            let timeline = TimelineId::new();
            let mut last = None;
            for _ in 0..ticks {
                last = driver.step(timeline, ObservationView::empty()).err();
            }
            (handle, last)
        })
        .map_err(|_| NonInterferenceNonExecutedCauseV1::Unavailable)
}

/// The six `NI-CRASH-012` surfaces, from two denied sibling community
/// Drivers over the value: one declares a failure on its one Tick, the other
/// traps on its first Tick and is refused on its next.
///
/// - Guest error: `[code, coordinate present]` of the declared failure.
/// - host error mapping: `[error name, error text]` of the trap.
/// - quarantine: the availability of the declaring and the trapping sibling.
/// - crash report: `[["guest-error", code], ["host-error", name],
///   ["quarantine", trapping sibling's availability]]`.
/// - support archive: `[["crash-report.cbor", padded crash report length]]`.
/// - next Tick status: `[subject availability, trapping sibling's
///   availability, its receipts, whether its next Tick was refused as no
///   community host failure]`. The quarantined sibling's next Tick is refused
///   before the host runs it, so it adds no receipt.
///
/// Availabilities and dispositions are closed codes: their declaration
/// ordinals. No record holds `Debug` text.
///
/// Operationally each keeps category, count and padded length; the
/// coordinate and the archive's file name, which the value names, are
/// excluded.
fn crash_surfaces(
    host: &GOpsHostV1,
    run: &GOpsRunV1<'_>,
    handle: &CommunityPluginHandleV1,
) -> Result<SurfacesV1, NonInterferenceNonExecutedCauseV1> {
    sibling_ticks(host, run.unauthorized_value, SELECT_DECLARED_FAILURE, 1).and_then(
        |(declared, _)| {
            sibling_ticks(host, run.unauthorized_value, SELECT_TRAP, 2).and_then(
                |(trapped, next)| {
                    declared
                        .receipts()
                        .last()
                        .and_then(|receipt| receipt.guest_error.clone())
                        .zip(trapped.last_failure())
                        .ok_or(NonInterferenceNonExecutedCauseV1::Unavailable)
                        .map(|(guest, error)| {
                            let code = declared_code(&guest.code);
                            let coordinate = guest.canonical_coordinate.unwrap_or_default();
                            let report = array([
                                array([text("guest-error"), code.clone()]),
                                array([text("host-error"), text(error.name())]),
                                array([text("quarantine"), availability(&trapped)]),
                            ]);
                            let report_bytes = encode(&report);
                            let records = records([
                                array([code, Value::Bool(!coordinate.is_empty())]),
                                array([text(error.name()), text(&error.to_string())]),
                                array([availability(&declared), availability(&trapped)]),
                                report,
                                array([array([
                                    text("crash-report.cbor"),
                                    uint(u64::from(padded(&report_bytes))),
                                ])]),
                                array([
                                    availability(handle),
                                    availability(&trapped),
                                    uint(trapped.receipts().len() as u64),
                                    Value::Bool(next.as_ref().is_some_and(|error| {
                                        classify_pass_failure(error) == PassFailureV1::Unrelated
                                    })),
                                ]),
                            ]);
                            let archive = format!("crash-{}.cbor", hex(run.unauthorized_value));
                            let operational = vec![
                                padded_facet(&records[0], 0, 1, coordinate.clone()),
                                padded_facet(&records[1], 0, 1, Vec::new()),
                                padded_facet(&records[2], 0, 2, Vec::new()),
                                padded_facet(&records[3], 0, 3, coordinate),
                                padded_facet(&records[4], 0, 1, archive.into_bytes()),
                                padded_facet(&records[5], 0, 4, Vec::new()),
                            ];
                            surfaces(records, operational)
                        })
                },
            )
        },
    )
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use pos_runtime::community_plugin_host::{
        plugin_output_digest_v1, EventDraftV1, TraceAnnotationV1,
    };
    use pos_runtime::PluginAvailabilityV1;

    #[test]
    fn the_guest_embeds_the_output_digest_of_its_documented_output() {
        let output = PluginOutputV1 {
            invocation_id: G_OPS_INVOCATION_ID_V1,
            event_drafts: vec![EventDraftV1 {
                event_schema_id: 1,
                entity_id: [0x4f; 16],
                event_type: G_OPS_EVENT_TYPE_V1.to_owned(),
                canonical_payload: G_OPS_EVENT_PAYLOAD_V1.to_vec(),
                dependency_digests: Vec::new(),
            }],
            next_state_schema: STATE_SCHEMA,
            next_state_bytes: G_OPS_NEXT_STATE_V1.to_vec(),
            trace_annotations: vec![TraceAnnotationV1 {
                annotation_schema_id: 1,
                canonical_bytes: b"\x64span".to_vec(),
                dependency_digests: Vec::new(),
            }],
            consumed_dependencies: Vec::new(),
            output_digest: [0; 32],
        };
        assert_eq!(plugin_output_digest_v1(&output), G_OPS_OUTPUT_DIGEST_V1);
        let embedded = G_OPS_OUTPUT_DIGEST_V1
            .iter()
            .fold(String::new(), |mut text, byte| {
                text.push('\\');
                text.push_str(&hex(&[*byte]));
                text
            });
        assert!(GUEST_WAT.contains(&embedded));
    }

    #[test]
    fn the_closed_codes_are_the_declaration_ordinals() {
        let codes = [
            ReceiptDispositionV1::Staged,
            ReceiptDispositionV1::Committed,
            ReceiptDispositionV1::Discarded,
        ]
        .map(disposition_code);
        assert_eq!(codes, [uint(0), uint(1), uint(2)]);
        let availabilities = [
            PluginAvailabilityV1::Available,
            PluginAvailabilityV1::Disabled,
            PluginAvailabilityV1::Unavailable,
            PluginAvailabilityV1::Revoked,
            PluginAvailabilityV1::Trapped,
            PluginAvailabilityV1::ResourceExhausted,
        ]
        .map(|availability| availability as u64);
        assert_eq!(availabilities, [0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn padded_lengths_are_the_next_power_of_two() {
        assert_eq!(padded(&[0; 5]), 8);
        assert_eq!(padded(&[0; 8]), 8);
        assert_eq!(padded(&[0; 9]), 16);
    }

    #[test]
    fn the_sibling_grants_follow_the_value_length() {
        assert_eq!(sibling_grants(b"abc").len(), 1);
        assert_eq!(sibling_grants(b"abcd").len(), 2);
        assert_eq!(sibling_grants(b"abcde").len(), 3);
        assert_ne!(sibling_grants(b"abcd")[0], sibling_grants(b"abcx")[0]);
    }
}
