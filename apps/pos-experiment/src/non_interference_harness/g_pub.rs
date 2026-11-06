//! The G-PUB capture adapters of the non-interference harness (ADR-062
//! Revision 8 slice N1, #1229; owner note
//! `ADR-062_R8_NonInterference_Executions`).
//!
//! Two ADR-059 rows are captured here; both use the same subject:
//!
//! - `NI-PUBLIC-006` captures the public Gateway protocol. The capture
//!   speaks HTTP to a fresh `piglor-gateway` router.
//! - `NI-EVAL-007` captures the evaluator inputs: the identity-preserving
//!   Timeline export ([`export_timeline_own`]) and the EAI1 attempt the
//!   evaluator streams to a public subject adapter.
//!
//! `NI-ARCHIVE-009` moved to slice N1b (#1284): it has no capture adapter
//! here, so [`execute_g_pub_case_v1`] reports its cases as non-executed
//! `Missing` and never runs them.
//!
//! # Subject
//!
//! [`g_pub_experiment_v1`] composes an Experiment whose one Driver emits
//! [`G_PUB_SIGNALS_PER_TICK_V1`] Society Signals per Tick for
//! [`G_PUB_TICKS_V1`] Ticks. The signals are derived from the permitted
//! input alone. Each mode produces those Events in its own way:
//! - Local: a live run in a fresh process ([`serve_g_pub_local_subject_v1`]).
//! - Replay: the recorded run.
//! - Fork: the Fork's stitched Events.
//!
//! The capture imports exactly those Events into the public seam, in
//! Timeline Order, as the root Timeline [`G_PUB_SUBJECT_TIMELINE_V1`].
//!
//! # Denied sibling
//!
//! The host also places the unauthorized value in a denied sibling Timeline
//! of the same seam store. The public client never names that Timeline, and
//! the subject never receives the unauthorized value.
//! - The sibling's Society Signals carry the value as hex text, so the
//!   secret's length becomes their payload length.
//! - The value's length sets how many signals there are.
//! - The parity of its first byte decides whether the sibling is created
//!   before or after the subject Timeline (the internal ordinal).
//!
//! # Position-relative identity
//!
//! Run-local identities are random ULIDs, and `wall_time`, first-commit
//! `origin` and signatures differ per run. So each surface replaces every
//! run-local identity by its Timeline Order position or first-appearance
//! ordinal:
//! - Events by `seq`, entities by ordinal, and `causation_id` by the `seq`
//!   it names.
//! - A cursor's inventory generation and Timeline by their ordinals.
//!
//! `wall_time`, `origin` and signatures are declared operational and are not
//! captured. The subject's Events carry no `correlation_id`, so none is
//! captured; the payload hash is the digest of the captured payload bytes.
//! The seam import re-appends each Event's entity, type and payload; its
//! schema version and causation are read back from the seam. Every other byte stays exact. Response lengths are exact, since
//! a ULID's text always has the same width.
//!
//! # Warm and cold
//!
//! The seam store is the `SQLite` file [`G_PUB_STORE_FILE_V1`] in the run's
//! working directory. A warm case keeps one directory for its priming run,
//! control run and canary run. A cold run always starts from a new file.
//!
//! The executions are engineering evidence signed with the repository
//! test-fixture-only executor key ([`g_pub_fixture_executor_key_v1`]), not
//! an attestation.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header::CONTENT_TYPE, Method, Request};
use ciborium::Value;
use pos_conformance::{
    non_interference_surface_names_v1, ExecutionModeV1, NonInterferenceExecutionErrorV1,
    NonInterferenceFixturePairV1, NonInterferenceHostRunV1, NonInterferenceRawCaptureV1,
    NonInterferenceRawOperationalV1, NonInterferenceVariantV1,
};
use pos_core::{
    event::{EventDraft, Kind},
    ids::{EntityId, PluginId, TimelineId},
    plugin::{Capability, Plugin},
    store::{export_timeline_own, EventStore, TimelineExport},
    ErasureContainmentGateV1, ErasureReferenceV1, Event,
};
use pos_plugin_society::{draft_signal, SocietyDimension, SocietySignal, EVENT_TYPE_SIGNAL};
use pos_reference::adapter_transport::{read_attempt, write_attempt};
use pos_reference::evaluator::{AttemptArtifact, AttemptTransportCaps, CaseAttempt};
use pos_reference::evaluator_domain::{ClaimLayer, ExecutionMode, FixtureFamily};
use pos_reference::profile::DeterministicBudget;
use pos_runtime::{Driver, ObservationView, PluginRegistry, RuntimeError, StepOutput};
use pos_state::ProjectionRegistry;
use pos_store::StoreConfig;
use serde_json::json;
use tower::ServiceExt;

use super::{
    hex, serve_non_interference_local_subject_v1, session::recorded, HostExecutorKeyV1,
    NonInterferenceHarnessV1, NonInterferenceNonExecutedCauseV1, NonInterferencePreparationV1,
    NonInterferenceRunOutcomeV1, NonInterferenceSessionObservationV1,
    NonInterferenceSessionSubjectV1,
};
use crate::{Experiment, ExperimentConfig, StopCondition};

/// The public Gateway protocol row.
pub const G_PUB_PUBLIC_FIXTURE_ID_V1: &str = "NI-PUBLIC-006";
/// The evaluator-input row.
pub const G_PUB_EVAL_FIXTURE_ID_V1: &str = "NI-EVAL-007";
/// The archive row, deferred to slice N1b (#1284).
pub const G_PUB_ARCHIVE_FIXTURE_ID_V1: &str = "NI-ARCHIVE-009";
/// The G-PUB rows in matrix order.
pub const G_PUB_FIXTURE_IDS_V1: [&str; 3] = [
    G_PUB_PUBLIC_FIXTURE_ID_V1,
    G_PUB_EVAL_FIXTURE_ID_V1,
    G_PUB_ARCHIVE_FIXTURE_ID_V1,
];
/// The `SQLite` file of a run's public seam store.
pub const G_PUB_STORE_FILE_V1: &str = "g-pub-seam.sqlite";
/// The Ticks of one subject run.
pub const G_PUB_TICKS_V1: u64 = 2;
/// The Society Signals the Driver emits per Tick.
pub const G_PUB_SIGNALS_PER_TICK_V1: usize = 2;
/// The page limit of every public page read.
pub const G_PUB_PAGE_LIMIT_V1: usize = 3;
/// The name of the subject Timeline in the public seam.
pub const G_PUB_SUBJECT_TIMELINE_V1: &str = "ni-g-pub-subject";
/// The schema member of the evaluator attempt.
pub const G_PUB_EVALUATOR_SCHEMA_V1: &[u8] = b"pigloros.g-pub.evaluator-input.v1";
/// The member name of the Timeline export in the evaluator bundle.
pub const G_PUB_EXPORT_MEMBER_V1: &str = "timeline-export";
/// The control member's unauthorized value of every G-PUB fixture.
pub const G_PUB_CONTROL_UNAUTHORIZED_V1: &[u8] = b"denied-control-0";
/// The canary member's unauthorized value of every G-PUB fixture.
pub const G_PUB_CANARY_UNAUTHORIZED_V1: &[u8] = b"canary-denied-object-value-002";
/// The key id of the repository test-fixture-only executor key.
pub const G_PUB_EXECUTOR_KEY_ID_V1: &str = "pigloros.fixture.non-interference-executor";

const DENIED_TIMELINE: &str = "ni-g-pub-denied";
const EXECUTOR_KEY_CONTEXT: &str =
    "PiglorOS repository test-fixture-only non-interference executor key v1";
/// Every runner replaces a capture's provenance digest with its own
/// execution provenance; the subject's placeholder is never compared.
const RUNNER_BOUND_PROVENANCE: [u8; 32] = [0xff; 32];
/// The run-independent identity of the subject Plugin, so every mode and
/// every Fork registers the same composition.
const G_PUB_PLUGIN_ID: PluginId = PluginId::from_ulid(ulid::Ulid::from_parts(1, 0x4750_5550));
/// The one simulation entity of every subject signal.
const G_PUB_ENTITY: EntityId = EntityId::from_ulid(ulid::Ulid::from_parts(1, 0x4750_5542));
const ATTEMPT_OUTCOME: &str = "admitted";
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const EXPORT_DIGEST: ErasureReferenceV1 = ErasureReferenceV1::from_digest([0x47; 32]);
const EXPORT_PROVENANCE: ErasureReferenceV1 = ErasureReferenceV1::from_digest([0x48; 32]);
const BUDGET_UNIT: u64 = 1024 * 1024;

/// The repository test-fixture-only executor key of the G-PUB evidence. Its
/// secret is a public derivation, so its signatures are engineering
/// evidence and attest nothing.
#[must_use]
pub fn g_pub_fixture_executor_key_v1() -> HostExecutorKeyV1 {
    HostExecutorKeyV1::from_secret_bytes(&blake3::derive_key(EXECUTOR_KEY_CONTEXT, b""))
}

/// The permitted input of one G-PUB fixture. It is the same in every mode.
#[must_use]
pub fn g_pub_permitted_input_v1(fixture_id: &str, variant: NonInterferenceVariantV1) -> Vec<u8> {
    format!(
        "g-pub permitted input v1/{fixture_id}/{}",
        variant_name(variant)
    )
    .into_bytes()
}

/// The admitted control/canary pair of one G-PUB coordinate. The two
/// members differ only in their unauthorized value.
///
/// # Errors
/// Returns the #181 admission error of an invalid coordinate.
pub fn g_pub_fixture_v1(
    fixture_id: &str,
    variant: NonInterferenceVariantV1,
    mode: ExecutionModeV1,
) -> Result<NonInterferenceFixturePairV1, NonInterferenceExecutionErrorV1> {
    NonInterferenceFixturePairV1::try_new(
        fixture_id,
        variant,
        mode,
        g_pub_permitted_input_v1(fixture_id, variant),
        G_PUB_CONTROL_UNAUTHORIZED_V1.to_vec(),
        G_PUB_CANARY_UNAUTHORIZED_V1.to_vec(),
    )
}

/// Run one G-PUB case. An `NI-ARCHIVE-009` case is not run: it is
/// non-executed `Missing` until slice N1b (#1284).
#[must_use]
pub fn execute_g_pub_case_v1(
    harness: &mut NonInterferenceHarnessV1,
    fixture: &NonInterferenceFixturePairV1,
) -> NonInterferenceRunOutcomeV1 {
    if fixture.fixture_id == G_PUB_ARCHIVE_FIXTURE_ID_V1 {
        NonInterferenceRunOutcomeV1::NonExecuted {
            fixture_id: fixture.fixture_id.clone(),
            variant: fixture.variant,
            mode: fixture.mode,
            cause: NonInterferenceNonExecutedCauseV1::Missing,
        }
    } else {
        harness.execute_case(fixture)
    }
}

/// The Society Signals the Driver emits on every Tick, derived from the
/// permitted input alone.
#[must_use]
pub fn g_pub_signals_v1(permitted_input: &[u8]) -> Vec<SocietySignal> {
    permitted_input
        .iter()
        .cycle()
        .take(G_PUB_SIGNALS_PER_TICK_V1)
        .map(|byte| SocietySignal {
            dimension: SocietyDimension::all()[usize::from(byte % 5)],
            value: f64::from(byte % 4) / 4.0,
            subject: None,
            object: None,
        })
        .collect()
}

/// Compose the G-PUB subject Experiment for one run.
///
/// # Errors
/// Returns `Unavailable` when the Plugin cannot be registered.
pub fn g_pub_experiment_v1(
    permitted_input: &[u8],
) -> Result<Experiment, NonInterferenceNonExecutedCauseV1> {
    let signals = g_pub_signals_v1(permitted_input);
    let child = signals.clone();
    let mut experiment = Experiment::new(ExperimentConfig {
        name: "ni-g-pub".to_owned(),
        stop: StopCondition::MaxTicks(G_PUB_TICKS_V1),
        store_config: StoreConfig::Memory,
    })
    .with_fork_registry_factory(move |_| g_pub_registry(child.clone()));
    experiment
        .register_generated(&GPubPlugin, None, Some(Box::new(GPubDriver { signals })))
        .ok()
        .map(|()| experiment)
        .ok_or(NonInterferenceNonExecutedCauseV1::Unavailable)
}

/// One host run as the capture adapters see it. It has no `Debug` form: the
/// unauthorized value never reaches a diagnostic.
#[derive(Clone, Copy)]
pub struct GPubRunV1<'a> {
    pub fixture_id: &'a str,
    pub variant: NonInterferenceVariantV1,
    pub permitted_input: &'a [u8],
    /// Host-owned: placed only in the denied sibling Timeline.
    pub unauthorized_value: &'a [u8],
}

/// Capture one run's public seam from the Events the mode produced, with the
/// seam store at `store`.
///
/// # Errors
/// Returns `Missing` for a row without a G-PUB capture adapter, and
/// `Unavailable` when the seam cannot be opened or answered.
pub fn g_pub_capture_v1(
    run: &GPubRunV1<'_>,
    events: &[Event],
    store: &Path,
) -> Result<NonInterferenceRawCaptureV1, NonInterferenceNonExecutedCauseV1> {
    match run.fixture_id {
        G_PUB_PUBLIC_FIXTURE_ID_V1 => public_surfaces(run, events, store),
        G_PUB_EVAL_FIXTURE_ID_V1 => evaluator_surfaces(run, events, store),
        _ => Err(NonInterferenceNonExecutedCauseV1::Missing),
    }
    .map(|surfaces| surfaces.into_capture(run.fixture_id))
}

/// Serve one Local run of the G-PUB subject in a fresh host process whose
/// working directory is `directory`.
///
/// # Errors
/// Returns the cause of a request, subject, capture or frame failure.
pub fn serve_g_pub_local_subject_v1<R: Read, W: Write>(
    input: R,
    output: W,
    directory: &Path,
) -> Result<(), NonInterferenceNonExecutedCauseV1> {
    serve_non_interference_local_subject_v1(input, output, |request| {
        g_pub_experiment_v1(&request.permitted_input)
            .and_then(live_events)
            .and_then(|events| {
                g_pub_capture_v1(
                    &GPubRunV1 {
                        fixture_id: &request.fixture_id,
                        variant: request.variant,
                        permitted_input: &request.permitted_input,
                        unauthorized_value: &request.unauthorized_value,
                    },
                    &events,
                    &directory.join(G_PUB_STORE_FILE_V1),
                )
            })
    })
}

/// The G-PUB subject of the Replay and Fork runners.
#[derive(Debug)]
pub struct GPubSessionSubjectV1 {
    work_root: PathBuf,
    directories: u64,
    warm: Option<PathBuf>,
    store: PathBuf,
}

impl GPubSessionSubjectV1 {
    /// A subject whose run directories are created below `work_root`.
    #[must_use]
    pub fn new(work_root: PathBuf) -> Self {
        Self {
            store: work_root.join(G_PUB_STORE_FILE_V1),
            work_root,
            directories: 0,
            warm: None,
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

impl NonInterferenceSessionSubjectV1 for GPubSessionSubjectV1 {
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
                self.store = directory.join(G_PUB_STORE_FILE_V1);
                g_pub_experiment_v1(run.subject.permitted_input)
            })
    }

    fn projections(&self) -> ProjectionRegistry {
        ProjectionRegistry::new()
            .with_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))
    }

    fn capture(
        &mut self,
        run: &NonInterferenceHostRunV1<'_>,
        observation: &NonInterferenceSessionObservationV1<'_>,
    ) -> Result<NonInterferenceRawCaptureV1, NonInterferenceNonExecutedCauseV1> {
        g_pub_capture_v1(
            &GPubRunV1 {
                fixture_id: run.subject.fixture_id,
                variant: run.subject.variant,
                permitted_input: run.subject.permitted_input,
                unauthorized_value: run.unauthorized_value,
            },
            observation.events,
            &self.store,
        )
    }
}

// ---------------------------------------------------------------------------
// Subject
// ---------------------------------------------------------------------------

struct GPubPlugin;

impl Plugin for GPubPlugin {
    fn id(&self) -> PluginId {
        G_PUB_PLUGIN_ID
    }

    fn name(&self) -> &'static str {
        "ni-g-pub"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(EVENT_TYPE_SIGNAL)],
            owned_entity_kinds: Vec::new(),
            has_driver: true,
            has_reducer: false,
        }
    }
}

/// Emits the same Society Signals on every Tick, so a Fork's fresh Driver
/// continues exactly as the parent would.
struct GPubDriver {
    signals: Vec<SocietySignal>,
}

impl Driver for GPubDriver {
    fn name(&self) -> &'static str {
        "ni-g-pub.driver"
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::new(
            self.signals
                .iter()
                .map(|signal| draft_signal(G_PUB_ENTITY, signal))
                .collect(),
        ))
    }
}

fn g_pub_registry(signals: Vec<SocietySignal>) -> Result<PluginRegistry, RuntimeError> {
    let mut registry = PluginRegistry::new();
    registry
        .register_generated(&GPubPlugin, None, Some(Box::new(GPubDriver { signals })))
        .map(|()| registry)
}

/// Run a Local subject live to its stop condition and read its Events.
fn live_events(experiment: Experiment) -> Result<Vec<Event>, NonInterferenceNonExecutedCauseV1> {
    experiment
        .start()
        .map_err(NonInterferenceNonExecutedCauseV1::from)
        .and_then(|mut session| recorded(&mut session))
        .map(|(_, events)| events)
}

// ---------------------------------------------------------------------------
// Surfaces
// ---------------------------------------------------------------------------

/// The three facets of every surface of one row, in surface order.
struct SurfacesV1 {
    authoritative: Vec<Vec<u8>>,
    public: Vec<Vec<u8>>,
    operational: Vec<NonInterferenceRawOperationalV1>,
}

impl SurfacesV1 {
    fn into_capture(self, fixture_id: &str) -> NonInterferenceRawCaptureV1 {
        NonInterferenceRawCaptureV1 {
            surface_names: non_interference_surface_names_v1(fixture_id)
                .unwrap_or_default()
                .into_iter()
                .map(str::to_owned)
                .collect(),
            authoritative: self.authoritative,
            public: self.public,
            operational: self.operational,
            unexpected_network_accesses: 0,
            provenance_digest: RUNNER_BOUND_PROVENANCE,
        }
    }
}

/// The canonical CBOR encoding of one record. An encoding failure yields no
/// bytes, which the #181 normalizer refuses as out of bounds.
fn encode(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).map_or(Vec::new(), |()| bytes)
}

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

const fn variant_name(variant: NonInterferenceVariantV1) -> &'static str {
    match variant {
        NonInterferenceVariantV1::Success => "success",
        NonInterferenceVariantV1::Denial => "denial",
        NonInterferenceVariantV1::WarmCache => "warm_cache",
        NonInterferenceVariantV1::ColdCache => "cold_cache",
    }
}

/// The first-appearance ordinal of `value` in `seen`.
fn ordinal<T: PartialEq + Clone>(seen: &mut Vec<T>, value: &T) -> u64 {
    let position = seen
        .iter()
        .position(|known| known == value)
        .unwrap_or_else(|| {
            seen.push(value.clone());
            seen.len() - 1
        });
    position as u64
}

/// The position-relative record of an Event stream in Timeline Order:
/// `[seq, entity ordinal, event type, schema version, causation seq or
/// null, payload]` per Event.
fn event_stream(events: &[Event]) -> Value {
    let mut entities = Vec::new();
    Value::Array(
        events
            .iter()
            .map(|event| {
                Value::Array(vec![
                    uint(event.seq.as_u64()),
                    uint(ordinal(&mut entities, &event.entity)),
                    text(event.event_type.as_str()),
                    uint(u64::from(event.schema_version.as_u32())),
                    event
                        .causation_id
                        .and_then(|cause| events.iter().find(|candidate| candidate.id == cause))
                        .map_or(Value::Null, |cause| uint(cause.seq.as_u64())),
                    Value::Bytes(event.payload.as_slice().to_vec()),
                ])
            })
            .collect(),
    )
}

/// Whether the denied sibling is created before the subject Timeline.
fn denied_first(unauthorized_value: &[u8]) -> bool {
    unauthorized_value.first().is_some_and(|byte| byte % 2 == 0)
}

/// The denied sibling's signals: one more than the value's length modulo 3,
/// each carrying the value as hex text.
fn denied_signals(unauthorized_value: &[u8]) -> Vec<SocietySignal> {
    (0..=unauthorized_value.len() % 3)
        .map(|_| SocietySignal {
            dimension: SocietyDimension::Trust,
            value: 0.5,
            subject: Some(hex(unauthorized_value)),
            object: None,
        })
        .collect()
}

/// The order in which the host writes the subject and the denied sibling.
#[derive(Clone, Copy)]
enum SeamRole {
    Denied,
    Subject,
}

fn seam_order(unauthorized_value: &[u8]) -> [SeamRole; 2] {
    if denied_first(unauthorized_value) {
        [SeamRole::Denied, SeamRole::Subject]
    } else {
        [SeamRole::Subject, SeamRole::Denied]
    }
}

// ---------------------------------------------------------------------------
// NI-EVAL-007: exported artifact and evaluator input
// ---------------------------------------------------------------------------

fn evaluator_surfaces(
    run: &GPubRunV1<'_>,
    events: &[Event],
    store: &Path,
) -> Result<SurfacesV1, NonInterferenceNonExecutedCauseV1> {
    pos_store::sqlite::SqliteStore::open(&store.to_string_lossy())
        .ok()
        .and_then(|mut store| {
            store
                .bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))
                .ok()
                .and_then(|()| imported_timeline(&mut store, run, events))
                .and_then(|timeline| {
                    export_evaluation().and_then(|evaluation| {
                        export_timeline_own(&store, timeline, EXPORT_DIGEST, &evaluation).ok()
                    })
                })
        })
        .and_then(|export| evaluator_records(run, &export))
        .ok_or(NonInterferenceNonExecutedCauseV1::Unavailable)
}

/// Write the denied sibling and the subject Timeline in the seam order and
/// return the subject Timeline.
fn imported_timeline(
    store: &mut dyn EventStore,
    run: &GPubRunV1<'_>,
    events: &[Event],
) -> Option<TimelineId> {
    seam_order(run.unauthorized_value)
        .iter()
        .try_fold(None, |subject, role| match role {
            SeamRole::Denied => {
                let drafts = denied_signals(run.unauthorized_value)
                    .iter()
                    .map(|signal| draft_signal(EntityId::new(), signal))
                    .collect::<Vec<_>>();
                store
                    .create_timeline(DENIED_TIMELINE)
                    .ok()
                    .and_then(|denied| store.append(denied.id(), &drafts).ok())
                    .map(|_| subject)
            }
            SeamRole::Subject => {
                let drafts = events
                    .iter()
                    .map(|event| {
                        EventDraft::new(
                            event.entity,
                            event.event_type.clone(),
                            event.payload.clone(),
                        )
                    })
                    .collect::<Vec<_>>();
                store
                    .create_timeline(G_PUB_SUBJECT_TIMELINE_V1)
                    .ok()
                    .and_then(|timeline| {
                        store
                            .append(timeline.id(), &drafts)
                            .ok()
                            .map(|_| Some(timeline.id()))
                    })
            }
        })
        .flatten()
}

/// The `ReplayClaim` evaluation that admits the export artifact exactly.
fn export_evaluation() -> Option<pos_core::ReplayClaimEvaluationV1> {
    pos_core::ReplayClaimEvaluatorV1::evaluate(
        pos_core::ErasureReplayClaimV1::Exact,
        &[pos_core::ArtifactClaimInputV1 {
            registration: pos_core::RegisteredArtifactV1::new(
                pos_core::ErasureArtifactClassV1::Export,
                EXPORT_DIGEST,
                pos_core::ArtifactDataClassV1::StructuralAuditMetadata,
                None,
                EXPORT_PROVENANCE,
                pos_core::ArtifactOptionalityV1::Required,
                pos_core::ArtifactTransitionRuleV1::PreserveExact,
            ),
            current_claim: pos_core::ErasureReplayClaimV1::Exact,
            state: pos_core::ArtifactStateV1::Retained,
        }],
    )
    .ok()
}

/// The five `NI-EVAL-007` surfaces from the export.
///
/// - Export bundle: the Event stream; publicly the export record
///   `[name, head, stream]`; operationally its digest.
/// - manifest: the bundle member table `[[name, size, digest]]`.
/// - fixture descriptor: `[fixture id, variant, permitted-input digest,
///   subject Plugin id, Plugin name, Driver name]`.
/// - evaluator stdin/files: `[case id, member count, member digests]` of the
///   EAI1 attempt as the evaluator imports it; operationally the exact EAI1
///   stream.
/// - `ConformanceReport`: the ordered case outcomes `[[case id, outcome,
///   payload digest]]`.
fn evaluator_records(run: &GPubRunV1<'_>, export: &TimelineExport) -> Option<SurfacesV1> {
    let stream = event_stream(&export.events);
    let stream_bytes = encode(&stream);
    let exported = encode(&Value::Array(vec![
        text(export.timeline.meta.name.as_deref().unwrap_or_default()),
        uint(export.timeline.head.as_u64()),
        stream,
    ]));
    let manifest = encode(&Value::Array(vec![Value::Array(vec![
        text(G_PUB_EXPORT_MEMBER_V1),
        uint(exported.len() as u64),
        Value::Bytes(digest(&exported).to_vec()),
    ])]));
    let descriptor = encode(&Value::Array(vec![
        text(run.fixture_id),
        text(variant_name(run.variant)),
        Value::Bytes(digest(run.permitted_input).to_vec()),
        text(&GPubPlugin.id().to_string()),
        text(GPubPlugin.name()),
        text(
            GPubDriver {
                signals: Vec::new(),
            }
            .name(),
        ),
    ]));
    let case_id = format!("{}-{}", run.fixture_id, variant_name(run.variant));
    let attempt = evaluator_attempt(&case_id, &descriptor, &exported, &manifest);
    let mut stream_out = Vec::new();
    write_attempt(&mut stream_out, &attempt)
        .ok()
        .and_then(|()| read_attempt(stream_out.as_slice()).ok())
        .map(|imported| {
            let members = std::iter::once(&imported.schema)
                .chain(std::iter::once(&imported.payload))
                .chain(&imported.auxiliary)
                .map(|member| Value::Bytes(member.digest.to_vec()))
                .collect::<Vec<_>>();
            let stdin = encode(&Value::Array(vec![
                text(&imported.case_id),
                uint(members.len() as u64),
                Value::Array(members),
            ]));
            let report = encode(&Value::Array(vec![Value::Array(vec![
                text(&imported.case_id),
                text(ATTEMPT_OUTCOME),
                Value::Bytes(digest(&imported.payload.bytes).to_vec()),
            ])]));
            let operational = vec![
                NonInterferenceRawOperationalV1::ByteExact(digest(&exported).to_vec()),
                NonInterferenceRawOperationalV1::ByteExact(manifest.clone()),
                NonInterferenceRawOperationalV1::ByteExact(descriptor.clone()),
                NonInterferenceRawOperationalV1::ByteExact(stream_out),
                NonInterferenceRawOperationalV1::ByteExact(report.clone()),
            ];
            SurfacesV1 {
                authoritative: vec![
                    stream_bytes,
                    manifest.clone(),
                    descriptor.clone(),
                    stdin.clone(),
                    report.clone(),
                ],
                public: vec![exported, manifest, descriptor, stdin, report],
                operational,
            }
        })
}

fn artifact(bytes: &[u8]) -> AttemptArtifact {
    AttemptArtifact {
        digest: digest(bytes),
        bytes: bytes.to_vec(),
    }
}

/// The EAI1 attempt over the export. Its Execution Mode is the same in
/// every harness mode: the evaluator input must not depend on the mode.
fn evaluator_attempt(
    case_id: &str,
    descriptor: &[u8],
    exported: &[u8],
    manifest: &[u8],
) -> CaseAttempt {
    CaseAttempt {
        case_id: case_id.to_owned(),
        claim_layer: ClaimLayer::KnowledgeNonInterference,
        family: FixtureFamily::Positive,
        mode: ExecutionMode::Local,
        fixture_digest: digest(descriptor),
        schema: artifact(G_PUB_EVALUATOR_SCHEMA_V1),
        payload: artifact(exported),
        auxiliary: vec![artifact(manifest)],
        budget: DeterministicBudget {
            memory_bytes: BUDGET_UNIT,
            cpu_fuel: BUDGET_UNIT,
            host_calls: BUDGET_UNIT,
            event_count: BUDGET_UNIT,
            output_bytes: BUDGET_UNIT,
            storage_bytes: BUDGET_UNIT,
            execution_steps: BUDGET_UNIT,
            simulation_time_ns: BUDGET_UNIT,
        },
        watchdog_ms: 1_000,
        network_allowed: false,
        capability_ids: Vec::new(),
        transport_caps: AttemptTransportCaps {
            max_member_bytes: BUDGET_UNIT,
            max_attempt_bytes: 4 * BUDGET_UNIT,
        },
    }
}

// ---------------------------------------------------------------------------
// NI-PUBLIC-006: public Gateway protocol
// ---------------------------------------------------------------------------

fn public_surfaces(
    run: &GPubRunV1<'_>,
    events: &[Event],
    store: &Path,
) -> Result<SurfacesV1, NonInterferenceNonExecutedCauseV1> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()
        .and_then(|runtime| public_transcript(&runtime, run, events, store))
        .map(PublicTranscriptV1::into_surfaces)
        .ok_or(NonInterferenceNonExecutedCauseV1::Unavailable)
}

/// Open a fresh Gateway over the seam store, run the public exchange and
/// shut the Gateway down.
fn public_transcript(
    runtime: &tokio::runtime::Runtime,
    run: &GPubRunV1<'_>,
    events: &[Event],
    store: &Path,
) -> Option<PublicTranscriptV1> {
    pos_runtime::ErasureExecutionHostV1::open_verified_empty(
        StoreConfig::Sqlite {
            path: store.to_string_lossy().into_owned(),
        },
        pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
    )
    .ok()
    .and_then(|host| piglor_gateway::Gateway::new_with_erasure_host(host).ok())
    .and_then(|gateway| {
        let mut client = PublicClientV1 {
            runtime,
            app: piglor_gateway::router(piglor_gateway::AppState {
                gateway: gateway.clone(),
                ledger_view: pos_plugin_ledger::LedgerView::default(),
                ledger_write: piglor_gateway::LedgerWriteMode::Disabled,
            }),
            transcript: PublicTranscriptV1::default(),
        };
        let exchanged = client.exchange(run, events);
        runtime
            .block_on(gateway.shutdown())
            .ok()
            .and(exchanged)
            .map(|()| client.transcript)
    })
}

/// What the public client saw of the subject Timeline.
#[derive(Default)]
struct PublicTranscriptV1 {
    /// The status of every subject request, in request order.
    statuses: Vec<u16>,
    /// The body of every page read.
    pages: Vec<Vec<u8>>,
    /// The raw `next_cursor` of every page.
    cursors: Vec<Option<String>>,
    /// The denial probe's status and body (the `Denial` variant only).
    denial: Option<(u16, Vec<u8>)>,
}

struct PublicClientV1<'a> {
    runtime: &'a tokio::runtime::Runtime,
    app: axum::Router,
    transcript: PublicTranscriptV1,
}

impl PublicClientV1<'_> {
    /// One HTTP request through the public router.
    fn send(
        &self,
        method: Method,
        uri: &str,
        body: Option<serde_json::Value>,
    ) -> Option<(u16, Vec<u8>)> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(CONTENT_TYPE, "application/json")
            .body(body.map_or_else(Body::empty, |value| Body::from(value.to_string())))
            .ok()
            .and_then(|request| {
                self.runtime
                    .block_on(self.app.clone().oneshot(request))
                    .ok()
            })
            .and_then(|response| {
                let status = response.status().as_u16();
                self.runtime
                    .block_on(axum::body::to_bytes(
                        response.into_body(),
                        MAX_RESPONSE_BYTES,
                    ))
                    .ok()
                    .map(|bytes| (status, bytes.to_vec()))
            })
    }

    /// Create a Timeline and return its id.
    fn create(&self, name: &str) -> Option<(u16, String)> {
        self.send(Method::POST, "/v1/timelines", Some(json!({ "name": name })))
            .and_then(|(status, body)| {
                serde_json::from_slice::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|value| {
                        value
                            .get("id")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_owned)
                    })
                    .map(|id| (status, id))
            })
    }

    /// Post one Society Signal and return the response status.
    fn post_signal(&self, timeline: &str, entity: &str, signal: &SocietySignal) -> Option<u16> {
        self.send(
            Method::POST,
            &format!("/v1/timelines/{timeline}/signals"),
            Some(json!({
                "entity_id": entity,
                "dimension": signal.dimension,
                "value": signal.value,
                "subject": signal.subject,
                "object": signal.object,
            })),
        )
        .map(|(status, _)| status)
    }

    /// Write both seam roles in the seam order, read every page of the
    /// subject Timeline and, for the `Denial` variant, probe a denied page
    /// request.
    fn exchange(&mut self, run: &GPubRunV1<'_>, events: &[Event]) -> Option<()> {
        seam_order(run.unauthorized_value)
            .iter()
            .try_fold(None, |subject, role| match role {
                SeamRole::Denied => self.write_denied(run.unauthorized_value).map(|()| subject),
                SeamRole::Subject => self.write_subject(events).map(Some),
            })
            .flatten()
            .and_then(|timeline| {
                self.read_pages(
                    &timeline,
                    &format!("limit={G_PUB_PAGE_LIMIT_V1}"),
                    events.len(),
                )
                .and_then(|()| self.probe_denial(run.variant, &timeline))
            })
    }

    /// The host's denied sibling. Its statuses are not part of the subject's
    /// transcript.
    fn write_denied(&self, unauthorized_value: &[u8]) -> Option<()> {
        self.create(DENIED_TIMELINE).and_then(|(_, denied)| {
            denied_signals(unauthorized_value)
                .iter()
                .try_for_each(|signal| {
                    self.post_signal(&denied, &EntityId::new().to_string(), signal)
                        .map(drop)
                })
        })
    }

    /// Import the mode's Events as the subject Timeline, in Timeline Order.
    fn write_subject(&mut self, events: &[Event]) -> Option<String> {
        self.create(G_PUB_SUBJECT_TIMELINE_V1)
            .and_then(|(status, timeline)| {
                self.transcript.statuses.push(status);
                events
                    .iter()
                    .try_for_each(|event| {
                        ciborium::from_reader::<SocietySignal, _>(event.payload.as_slice())
                            .ok()
                            .and_then(|signal| {
                                self.post_signal(&timeline, &event.entity.to_string(), &signal)
                            })
                            .map(|status| self.transcript.statuses.push(status))
                    })
                    .map(|()| timeline)
            })
    }

    /// Read one page, then follow its cursor; at most `remaining` further
    /// pages are read.
    fn read_pages(&mut self, timeline: &str, query: &str, remaining: usize) -> Option<()> {
        self.send(
            Method::GET,
            &format!("/v1/timelines/{timeline}/events?{query}"),
            None,
        )
        .and_then(|(status, body)| {
            let cursor = serde_json::from_slice::<serde_json::Value>(&body)
                .ok()
                .and_then(|value| {
                    value
                        .get("next_cursor")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                });
            self.transcript.statuses.push(status);
            self.transcript.pages.push(body);
            self.transcript.cursors.push(cursor.clone());
            cursor.map_or(Some(()), |cursor| {
                remaining.checked_sub(1).and_then(|remaining| {
                    self.read_pages(
                        timeline,
                        &format!("cursor={cursor}&limit={G_PUB_PAGE_LIMIT_V1}"),
                        remaining,
                    )
                })
            })
        })
    }

    /// The `Denial` variant's probe: a page request beyond the public page
    /// bound, which the Gateway refuses with its closed error.
    fn probe_denial(&mut self, variant: NonInterferenceVariantV1, timeline: &str) -> Option<()> {
        if variant == NonInterferenceVariantV1::Denial {
            self.send(
                Method::GET,
                &format!("/v1/timelines/{timeline}/events?limit=101"),
                None,
            )
            .map(|(status, body)| {
                self.transcript.statuses.push(status);
                self.transcript.denial = Some((status, body));
            })
        } else {
            Some(())
        }
    }
}

impl PublicTranscriptV1 {
    /// The five `NI-PUBLIC-006` surfaces. The authoritative and public facets
    /// are the same closed record; the operational facet keeps only
    /// category/count, every raw diagnostic is excluded.
    ///
    /// - HTTP/Plugin error: `[status, body]` of the denial probe, or `[]`.
    /// - status transition: every subject request status, in order.
    /// - cursor bytes: every page's cursor, position-relative, or null.
    /// - page count: the number of pages.
    /// - response length/padding: the length of every page and denial body.
    fn into_surfaces(self) -> SurfacesV1 {
        let mut generations = Vec::new();
        let mut timelines = Vec::new();
        let cursors = self
            .cursors
            .iter()
            .map(|cursor| {
                cursor.as_deref().map_or(Value::Null, |cursor| {
                    Value::Text(relative_cursor(cursor, &mut generations, &mut timelines))
                })
            })
            .collect::<Vec<_>>();
        let lengths = self
            .pages
            .iter()
            .chain(self.denial.iter().map(|(_, body)| body))
            .map(|body| uint(body.len() as u64))
            .collect::<Vec<_>>();
        let (error, error_status, error_body) = match self.denial {
            Some((status, body)) => (
                Value::Array(vec![uint(u64::from(status)), Value::Bytes(body.clone())]),
                status,
                body,
            ),
            None => (Value::Array(Vec::new()), 0, Vec::new()),
        };
        let records = [
            encode(&error),
            encode(&Value::Array(
                self.statuses
                    .iter()
                    .map(|status| uint(u64::from(*status)))
                    .collect(),
            )),
            encode(&Value::Array(cursors)),
            encode(&uint(self.pages.len() as u64)),
            encode(&Value::Array(lengths.clone())),
        ];
        let count = |items: usize| u32::try_from(items).unwrap_or(u32::MAX);
        let operational = vec![
            NonInterferenceRawOperationalV1::CategoryCount {
                category: error_status,
                count: count(usize::from(error_status != 0)),
                excluded_sensitive: error_body,
            },
            NonInterferenceRawOperationalV1::CategoryCount {
                category: self.statuses.last().copied().unwrap_or_default(),
                count: count(self.statuses.len()),
                excluded_sensitive: Vec::new(),
            },
            NonInterferenceRawOperationalV1::CategoryCount {
                category: 0,
                count: count(self.cursors.iter().flatten().count()),
                excluded_sensitive: self
                    .cursors
                    .iter()
                    .flatten()
                    .flat_map(|cursor| cursor.bytes())
                    .collect(),
            },
            NonInterferenceRawOperationalV1::CategoryCount {
                category: 0,
                count: count(self.pages.len()),
                excluded_sensitive: Vec::new(),
            },
            NonInterferenceRawOperationalV1::CategoryCount {
                category: 0,
                count: count(lengths.len()),
                excluded_sensitive: Vec::new(),
            },
        ];
        SurfacesV1 {
            authoritative: records.to_vec(),
            public: Vec::from(records),
            operational,
        }
    }
}

/// A Gateway cursor `v1.<generation>.<timeline>.<seq>` with its generation
/// and Timeline replaced by their first-appearance ordinals.
fn relative_cursor(
    cursor: &str,
    generations: &mut Vec<String>,
    timelines: &mut Vec<String>,
) -> String {
    let parts = cursor.split('.').collect::<Vec<_>>();
    let part = |index: usize| parts.get(index).copied().unwrap_or_default().to_owned();
    format!(
        "{}.G{}.T{}.{}",
        part(0),
        ordinal(generations, &part(1)),
        ordinal(timelines, &part(2)),
        part(3)
    )
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use pos_core::{
        clock::{Seq, WallTime},
        crypto::Hash,
        event::{CanonicalBytes, SchemaVersion},
        ids::EventId,
    };

    fn event(seq: u8, entity: u128, causation: Option<EventId>) -> Event {
        Event {
            id: EventId::new(),
            entity: EntityId::from_ulid(ulid::Ulid::from(entity)),
            event_type: Kind::new(EVENT_TYPE_SIGNAL),
            payload: CanonicalBytes::from_vec(vec![seq]),
            wall_time: WallTime::from_micros(u64::from(seq)),
            seq: Seq::from_u64(u64::from(seq)),
            causation_id: causation,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            origin: None,
            payload_hash: Hash::from_bytes([0; 32]),
        }
    }

    #[test]
    fn the_event_stream_is_position_relative() {
        let first = event(1, 7, None);
        let second = event(2, 9, Some(first.id));
        let third = event(3, 7, Some(EventId::new()));
        let expected = Value::Array(vec![
            Value::Array(vec![
                uint(1),
                uint(0),
                text(EVENT_TYPE_SIGNAL),
                uint(1),
                Value::Null,
                Value::Bytes(vec![1]),
            ]),
            Value::Array(vec![
                uint(2),
                uint(1),
                text(EVENT_TYPE_SIGNAL),
                uint(1),
                uint(1),
                Value::Bytes(vec![2]),
            ]),
            Value::Array(vec![
                uint(3),
                uint(0),
                text(EVENT_TYPE_SIGNAL),
                uint(1),
                Value::Null,
                Value::Bytes(vec![3]),
            ]),
        ]);
        assert_eq!(event_stream(&[first, second, third]), expected);
    }

    #[test]
    fn a_cursor_is_position_relative() {
        let mut generations = Vec::new();
        let mut timelines = Vec::new();
        assert_eq!(
            relative_cursor("v1.aa.tl-1.4", &mut generations, &mut timelines),
            "v1.G0.T0.4"
        );
        assert_eq!(
            relative_cursor("v1.bb.tl-1.7", &mut generations, &mut timelines),
            "v1.G1.T0.7"
        );
        assert_eq!(
            relative_cursor("v1.aa.tl-2", &mut generations, &mut timelines),
            "v1.G0.T1."
        );
    }
}
