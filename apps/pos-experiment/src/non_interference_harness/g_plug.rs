//! The G-PLUG capture adapters of the non-interference harness (ADR-062
//! Revision 8 slice N2, #1230; owner note `ADR-062_R8_NonInterference_Plugin`,
//! scoping `ADR-059_R9_State_Migration_Scoping`).
//!
//! Four ADR-059 rows are captured here, over one subject:
//! - `NI-TOOL-001`: host tools and imported services;
//! - `NI-STATE-003`: Plugin state, on its state members;
//! - `NI-NET-010`: the network and tool-call sequence;
//! - `NI-SERVICE-011`: the frozen imported response sequence.
//!
//! # Plugin seam
//!
//! The subject's Plugin is reached only through the public Plugin protocol:
//! the host encodes PWQ1 requests and decodes PWR1 responses with the
//! `pos-plugin-supervisor` codec, and [`serve_g_plug_fixture_guest_v1`] is an
//! in-process deterministic fixture guest that answers `describe`, `reduce`
//! and `drive`. `migrate-state` has no call in the protocol: a request that
//! names it is refused by the codec ([`GPlugProtocolHostV1::migrate_state`]).
//! The executions are engineering evidence; they are re-run on the Wasm worker
//! path later.
//!
//! # Modes
//!
//! [`g_plug_experiment_v1`] composes an Experiment whose one Driver calls the
//! guest's `drive` on every Tick, for [`G_PLUG_TICKS_V1`] Ticks, with an
//! observation derived from the permitted input alone. Local runs it live in a
//! fresh process ([`serve_g_plug_local_subject_v1`]), Replay records it, and
//! Fork stitches the Fork's Events. The capture then rebuilds the Plugin's
//! state from those Events through `reduce` alone, never `drive`.
//!
//! # Host-owned records
//!
//! The V1 Plugin world imports no tool, service or network. The tool registry,
//! the frozen service records and the network sequence are host-owned code
//! constants. A frozen service is resolved by its exact request digest before
//! invocation, and only its permitted projection reaches the guest. A request
//! with no frozen record would need a live call: the capture counts it as an
//! unexpected network access, so the case is non-executed `LiveCall`, never a
//! pass.
//!
//! # Denied channel
//!
//! The host writes the row's unauthorized value only to its own record file
//! [`G_PLUG_HOST_STORE_FILE_V1`] in the run's working directory:
//! - `NI-TOOL-001`: the denied tool response (value, size and error text)
//!   behind a capability the Plugin is not granted;
//! - `NI-SERVICE-011`: the unauthorized field of the admitted frozen record;
//! - `NI-NET-010`: the denied endpoint, DNS result, retry timing, response
//!   body and hidden tool-call branch, which never run;
//! - `NI-STATE-003`: the unauthorized state member, stripped before the prior
//!   state reaches the guest.
//!
//! Operationally those bytes are only ever `excluded_sensitive`.
//!
//! # Migration
//!
//! A V1 host never migrates state. `NI-STATE-003` captures its migration
//! surface as the closed record "migrate-state refused" with the count of
//! answered migrate-state requests (zero). The migration-only canary is a
//! separate pair ([`g_plug_migration_canary_v1`]) that is non-executed
//! `Unsupported` ([`execute_g_plug_migration_canary_v1`]) until PMF1 v2
//! (#621).
//!
//! # Warm and cold
//!
//! The host caches the guest's descriptor record in
//! [`G_PLUG_CACHE_FILE_V1`]. A warm case keeps one directory for its priming,
//! control and canary runs, so they read the cached descriptor; a cold run
//! starts from a new directory and calls `describe`.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ciborium::Value;
use pos_conformance::{
    ExecutionModeV1, NonInterferenceExecutionErrorV1, NonInterferenceFixturePairV1,
    NonInterferenceHostRunV1, NonInterferenceRawCaptureV1, NonInterferenceRawOperationalV1,
    NonInterferenceVariantV1,
};
use pos_core::{
    event::{CanonicalBytes, EventDraft, Kind},
    ids::{EntityId, PluginId, TimelineId},
    plugin::{Capability, Plugin},
    ErasureContainmentGateV1, Event,
};
use pos_crypto::plugin_execution::{DeterministicBudgetV1, PluginCapabilityDescriptorV1};
use pos_plugin_supervisor::ipc::{
    decode_worker_request_v1, decode_worker_response_v1, encode_worker_request_v1,
    encode_worker_response_v1,
};
use pos_plugin_supervisor::{WorkerCallV1, WorkerRequestV1, WorkerReturnV1};
use pos_runtime::community_plugin_host::{
    plugin_output_digest_v1, ArtifactRefV1, CommunityPluginModeV1, EventDraftV1,
    GuestPluginErrorV1, GuestReturnV1, HostInputs, InvocationReportV1, MeteringV1,
    NegotiatedTransportV1, PluginDescriptorV1, PluginErrorCodeV1, PluginInvocationV1,
    PluginOutputV1, TimelinePositionV1, COMMUNITY_PLUGIN_ABI_MAJOR_V1,
};
use pos_runtime::{Driver, ObservationView, PluginRegistry, RuntimeError, StepOutput};
use pos_state::ProjectionRegistry;
use pos_store::StoreConfig;

use super::capture::{digest, encode, event_stream, text, uint, variant_name, SurfacesV1};
use super::{
    hex, serve_non_interference_local_subject_v1, session::recorded,
    NonInterferenceNonExecutedCauseV1, NonInterferencePreparationV1, NonInterferenceRunOutcomeV1,
    NonInterferenceSessionObservationV1, NonInterferenceSessionSubjectV1,
};
use crate::{Experiment, ExperimentConfig, StopCondition};

/// The host tools and imported services row.
pub const G_PLUG_TOOL_FIXTURE_ID_V1: &str = "NI-TOOL-001";
/// The Plugin state row (state members only).
pub const G_PLUG_STATE_FIXTURE_ID_V1: &str = "NI-STATE-003";
/// The network and tool-call sequence row.
pub const G_PLUG_NET_FIXTURE_ID_V1: &str = "NI-NET-010";
/// The frozen imported response sequence row.
pub const G_PLUG_SERVICE_FIXTURE_ID_V1: &str = "NI-SERVICE-011";
/// The G-PLUG rows in matrix order.
pub const G_PLUG_FIXTURE_IDS_V1: [&str; 4] = [
    G_PLUG_TOOL_FIXTURE_ID_V1,
    G_PLUG_STATE_FIXTURE_ID_V1,
    G_PLUG_NET_FIXTURE_ID_V1,
    G_PLUG_SERVICE_FIXTURE_ID_V1,
];
/// The host's own record file in a run's working directory: the only place
/// the unauthorized value is written.
pub const G_PLUG_HOST_STORE_FILE_V1: &str = "g-plug-host.cbor";
/// The host's descriptor cache in a run's working directory.
pub const G_PLUG_CACHE_FILE_V1: &str = "g-plug-cache.cbor";
/// The Ticks of one subject run.
pub const G_PLUG_TICKS_V1: u64 = 2;
/// The Event type of every `drive` draft.
pub const G_PLUG_EVENT_TYPE_V1: &str = "ni.g-plug.output";
/// The PMF1 Plugin ID text the fixture guest describes.
pub const G_PLUG_GUEST_PLUGIN_ID_V1: &str = "ni.g-plug";
/// The Component bytes the host sends; the fixture guest answers only these.
pub const G_PLUG_COMPONENT_V1: &[u8] = b"pigloros.ni.g-plug.fixture-guest.v1";
/// The prefix of a capability probe observation: the guest answers it with
/// `capability-required`.
pub const G_PLUG_PROBE_PREFIX_V1: &[u8] = b"ni.g-plug.probe:";
/// The denied tool of `NI-TOOL-001`.
pub const G_PLUG_TOOL_ID_V1: &str = "ni.tool.lookup";
/// The capability every row's `Denial` probe asks for, in row order. None is
/// granted.
pub const G_PLUG_CAPABILITIES_V1: [&str; 4] = [
    "ni.cap.tool",
    "ni.cap.state-migrate",
    "ni.cap.network",
    "ni.cap.service-live",
];
/// The control member's unauthorized value of every G-PLUG fixture.
pub const G_PLUG_CONTROL_UNAUTHORIZED_V1: &[u8] = b"denied-plug-control-0";
/// The canary member's unauthorized value of every G-PLUG fixture.
pub const G_PLUG_CANARY_UNAUTHORIZED_V1: &[u8] = b"canary-denied-plugin-value-0003";
/// The control member of the `NI-STATE-003` migration-only canary.
pub const G_PLUG_MIGRATION_CONTROL_V1: &[u8] = b"migration-control-0";
/// The canary member of the `NI-STATE-003` migration-only canary.
pub const G_PLUG_MIGRATION_CANARY_V1: &[u8] = b"migration-only-canary-0002";

/// The fixture guest's world text.
const WORLD: &str = "pigloros:plugin/community-plugin";
const STATE_SCHEMA_TEXT: &[u8] = b"pigloros.ni.g-plug.state.v1";
const EVENT_SCHEMA_ID: u32 = 1;
const BUDGET_ID: &str = "ni.g-plug";
const BUDGET_UNIT: u64 = 1_048_576;
const WATCHDOG_MILLIS: u64 = 1_000;
/// The authorized initial state: 32 zero bytes.
const INITIAL_STATE: [u8; 32] = [0; 32];
/// The run-independent identity of the subject Plugin.
const G_PLUG_PLUGIN_ID: PluginId = PluginId::from_ulid(ulid::Ulid::from_parts(1, 0x4750_4c47));
/// The one simulation entity of every `drive` draft.
const G_PLUG_ENTITY: ulid::Ulid = ulid::Ulid::from_parts(1, 0x4750_4c45);

/// One host run as the capture adapters see it. It has no `Debug` form: the
/// unauthorized value never reaches a diagnostic.
#[derive(Clone, Copy)]
pub struct GPlugRunV1<'a> {
    pub fixture_id: &'a str,
    pub variant: NonInterferenceVariantV1,
    pub permitted_input: &'a [u8],
    /// Host-owned: written only to the host's own record file.
    pub unauthorized_value: &'a [u8],
}

/// The permitted input of one G-PLUG fixture. It is the same in every mode.
#[must_use]
pub fn g_plug_permitted_input_v1(fixture_id: &str, variant: NonInterferenceVariantV1) -> Vec<u8> {
    format!(
        "g-plug permitted input v1/{fixture_id}/{}",
        variant_name(variant)
    )
    .into_bytes()
}

/// The admitted control/canary pair of one G-PLUG coordinate. The two
/// members differ only in their unauthorized value.
///
/// # Errors
/// Returns the #181 admission error of an invalid coordinate.
pub fn g_plug_fixture_v1(
    fixture_id: &str,
    variant: NonInterferenceVariantV1,
    mode: ExecutionModeV1,
) -> Result<NonInterferenceFixturePairV1, NonInterferenceExecutionErrorV1> {
    NonInterferenceFixturePairV1::try_new(
        fixture_id,
        variant,
        mode,
        g_plug_permitted_input_v1(fixture_id, variant),
        G_PLUG_CONTROL_UNAUTHORIZED_V1.to_vec(),
        G_PLUG_CANARY_UNAUTHORIZED_V1.to_vec(),
    )
}

/// The `NI-STATE-003` migration-only canary pair of one coordinate.
///
/// # Errors
/// Returns the #181 admission error of an invalid coordinate.
pub fn g_plug_migration_canary_v1(
    variant: NonInterferenceVariantV1,
    mode: ExecutionModeV1,
) -> Result<NonInterferenceFixturePairV1, NonInterferenceExecutionErrorV1> {
    NonInterferenceFixturePairV1::try_new(
        G_PLUG_STATE_FIXTURE_ID_V1,
        variant,
        mode,
        format!("g-plug migration-only canary v1/{}", variant_name(variant)).into_bytes(),
        G_PLUG_MIGRATION_CONTROL_V1.to_vec(),
        G_PLUG_MIGRATION_CANARY_V1.to_vec(),
    )
}

/// The migration-only canary on a V1 host, which never has an NIA1.
///
/// There is no migrate-state call, so an admitted pair is non-executed
/// `Unsupported` (scoped to PMF1 v2, #621) and an invalid one `Missing`.
#[must_use]
pub fn execute_g_plug_migration_canary_v1(
    fixture: &NonInterferenceFixturePairV1,
) -> NonInterferenceRunOutcomeV1 {
    NonInterferenceRunOutcomeV1::NonExecuted {
        fixture_id: fixture.fixture_id.clone(),
        variant: fixture.variant,
        mode: fixture.mode,
        cause: fixture
            .validate()
            .map_or(NonInterferenceNonExecutedCauseV1::Missing, |()| {
                NonInterferenceNonExecutedCauseV1::Unsupported
            }),
    }
}

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RowV1 {
    Tool,
    State,
    Net,
    Service,
}

impl RowV1 {
    fn of(fixture_id: &str) -> Option<Self> {
        match fixture_id {
            G_PLUG_TOOL_FIXTURE_ID_V1 => Some(Self::Tool),
            G_PLUG_STATE_FIXTURE_ID_V1 => Some(Self::State),
            G_PLUG_NET_FIXTURE_ID_V1 => Some(Self::Net),
            G_PLUG_SERVICE_FIXTURE_ID_V1 => Some(Self::Service),
            _ => None,
        }
    }

    const fn capability(self) -> &'static str {
        match self {
            Self::Tool => G_PLUG_CAPABILITIES_V1[0],
            Self::State => G_PLUG_CAPABILITIES_V1[1],
            Self::Net => G_PLUG_CAPABILITIES_V1[2],
            Self::Service => G_PLUG_CAPABILITIES_V1[3],
        }
    }
}

/// The exact request of a frozen service or network lookup.
fn service_request(kind: &str, permitted_input: &[u8]) -> Vec<u8> {
    encode(&Value::Array(vec![
        text("ni.g-plug.request"),
        text(kind),
        Value::Bytes(permitted_input.to_vec()),
    ]))
}

/// The permitted projection of a frozen admitted response.
fn service_projection(kind: &str, permitted_input: &[u8]) -> Vec<u8> {
    encode(&Value::Array(vec![
        text("admitted"),
        text(kind),
        Value::Bytes(digest(permitted_input).to_vec()),
    ]))
}

/// The frozen projection the host resolves by exact request digest: the
/// admitted records are those of the row's four permitted inputs. A request
/// without a record has none and would need a live call.
fn frozen_projection(fixture_id: &str, kind: &str, permitted_input: &[u8]) -> Option<Vec<u8>> {
    let wanted = digest(&service_request(kind, permitted_input));
    [
        NonInterferenceVariantV1::Success,
        NonInterferenceVariantV1::Denial,
        NonInterferenceVariantV1::WarmCache,
        NonInterferenceVariantV1::ColdCache,
    ]
    .iter()
    .any(|variant| {
        digest(&service_request(
            kind,
            &g_plug_permitted_input_v1(fixture_id, *variant),
        )) == wanted
    })
    .then(|| service_projection(kind, permitted_input))
}

/// The lookup kind of a row that resolves a frozen record.
const fn lookup_kind(row: RowV1) -> Option<&'static str> {
    match row {
        RowV1::Net => Some("network"),
        RowV1::Service => Some("service"),
        RowV1::Tool | RowV1::State => None,
    }
}

/// The permitted record of one frozen lookup: its kind, exact request digest
/// and frozen projection, or null when no record exists.
fn lookup(fixture_id: &str, kind: &str, permitted_input: &[u8]) -> Value {
    Value::Array(vec![
        text(kind),
        Value::Bytes(digest(&service_request(kind, permitted_input)).to_vec()),
        frozen_projection(fixture_id, kind, permitted_input).map_or(Value::Null, Value::Bytes),
    ])
}

/// The row's permitted host record in the `drive` observation.
fn channel(row: RowV1, fixture_id: &str, permitted_input: &[u8]) -> Value {
    match row {
        RowV1::Tool => Value::Array(vec![
            text("tool"),
            text(G_PLUG_TOOL_ID_V1),
            text("capability-denied"),
        ]),
        RowV1::State => Value::Array(vec![text("state")]),
        RowV1::Net => lookup(fixture_id, "network", permitted_input),
        RowV1::Service => lookup(fixture_id, "service", permitted_input),
    }
}

/// The observation of every `drive` call: the row, the permitted input and
/// the row's permitted host record.
fn drive_observation(row: RowV1, fixture_id: &str, permitted_input: &[u8]) -> Vec<u8> {
    encode(&Value::Array(vec![
        text(fixture_id),
        Value::Bytes(permitted_input.to_vec()),
        channel(row, fixture_id, permitted_input),
    ]))
}

/// Whether the run's lookup has no frozen record and so would need a live
/// call.
fn live_call(row: RowV1, fixture_id: &str, permitted_input: &[u8]) -> bool {
    lookup_kind(row)
        .is_some_and(|kind| frozen_projection(fixture_id, kind, permitted_input).is_none())
}

/// The host-owned record of the row, which carries the unauthorized value.
fn host_record(row: RowV1, run: &GPlugRunV1<'_>, state: &[u8]) -> Value {
    let value = run.unauthorized_value;
    let bytes = |bytes: &[u8]| Value::Bytes(bytes.to_vec());
    match row {
        RowV1::Tool => Value::Array(vec![
            text(G_PLUG_TOOL_ID_V1),
            bytes(value),
            uint(value.len() as u64),
            text(&format!("denied tool response: {}", hex(value))),
        ]),
        RowV1::State => Value::Array(vec![bytes(state), bytes(value)]),
        RowV1::Net => Value::Array(vec![
            text(&format!("{}.denied.invalid", hex(value))),
            text(&format!(
                "203.0.113.{}",
                value.first().copied().unwrap_or_default()
            )),
            text(&format!("retry-after-{}ms", value.len())),
            bytes(value),
            text(&format!("hidden-branch-{}", hex(value))),
        ]),
        RowV1::Service => Value::Array(vec![
            bytes(&digest(&service_request("service", run.permitted_input))),
            bytes(value),
        ]),
    }
}

// ---------------------------------------------------------------------------
// The public Plugin protocol
// ---------------------------------------------------------------------------

/// The endpoint the host sends one PWQ1 request to; it returns one PWR1
/// response, or nothing for a refused request.
pub type GPlugEndpointV1 = fn(&[u8]) -> Option<zeroize::Zeroizing<Vec<u8>>>;

/// The host side of the public Plugin protocol.
///
/// It encodes PWQ1 requests, decodes PWR1 responses and admits only a
/// response for the export it invoked whose output echoes the invocation and
/// carries its output digest.
#[derive(Clone, Debug)]
pub struct GPlugProtocolHostV1 {
    endpoint: GPlugEndpointV1,
}

impl GPlugProtocolHostV1 {
    /// A host that speaks to `endpoint`.
    #[must_use]
    pub const fn new(endpoint: GPlugEndpointV1) -> Self {
        Self { endpoint }
    }

    /// `describe`.
    #[must_use]
    pub fn describe(&self) -> Option<PluginDescriptorV1> {
        self.exchange(WorkerCallV1::Describe).and_then(described)
    }

    /// `drive`; a guest error is no output.
    #[must_use]
    pub fn drive(&self, invocation: &PluginInvocationV1) -> Option<PluginOutputV1> {
        self.exchange(WorkerCallV1::Drive(invocation.clone()))
            .and_then(produced)
            .filter(|result| admitted(invocation, result))
            .and_then(Result::ok)
    }

    /// `reduce`: the guest's output or its own typed error.
    #[must_use]
    pub fn reduce(&self, invocation: &PluginInvocationV1) -> Option<GuestReturnV1<PluginOutputV1>> {
        self.exchange(WorkerCallV1::Reduce(invocation.clone()))
            .and_then(produced)
            .filter(|result| admitted(invocation, result))
    }

    /// Send a migrate-state request over `invocation`; return the raw answer.
    ///
    /// The protocol has no migrate-state call: the request is the `reduce`
    /// envelope with the call code set to 3, which the codec refuses.
    #[must_use]
    pub fn migrate_state(
        &self,
        invocation: &PluginInvocationV1,
    ) -> Option<zeroize::Zeroizing<Vec<u8>>> {
        let reduce = encode_worker_request_v1(&request(WorkerCallV1::Reduce(invocation.clone())));
        let drive = encode_worker_request_v1(&request(WorkerCallV1::Drive(invocation.clone())));
        reduce
            .ok()
            .zip(drive.ok())
            .and_then(|(mut migrate, drive)| {
                migrate
                    .iter()
                    .zip(drive.iter())
                    .position(|(left, right)| left != right)
                    .map(|code| {
                        migrate[code] = 3;
                        migrate
                    })
            })
            .and_then(|migrate| (self.endpoint)(&migrate))
    }

    fn exchange(&self, call: WorkerCallV1) -> Option<WorkerReturnV1> {
        encode_worker_request_v1(&request(call))
            .ok()
            .and_then(|bytes| (self.endpoint)(&bytes))
            .and_then(|bytes| decode_worker_response_v1(&bytes).ok())
            .and_then(Result::ok)
    }
}

/// The PWQ1 request of one call: the fixture Component, the negotiated
/// record with every G-PLUG capability not granted, and Local mode.
fn request(call: WorkerCallV1) -> WorkerRequestV1 {
    WorkerRequestV1 {
        component: G_PLUG_COMPONENT_V1.to_vec().into(),
        negotiation: NegotiatedTransportV1 {
            world: WORLD.to_owned(),
            plugin_id: G_PLUG_GUEST_PLUGIN_ID_V1.to_owned(),
            pmf1_digest: digest(G_PLUG_COMPONENT_V1),
            release_digest: digest(G_PLUG_COMPONENT_V1),
            abi_major: COMMUNITY_PLUGIN_ABI_MAJOR_V1,
            abi_minor: 0,
            declared_minors: (0, 0),
            required_features: Vec::new(),
            not_granted_capabilities: G_PLUG_CAPABILITIES_V1
                .iter()
                .map(|capability| PluginCapabilityDescriptorV1 {
                    capability_id: (*capability).to_owned(),
                    operation: "call".to_owned(),
                    resource_pattern: "*".to_owned(),
                    purpose: "non-interference".to_owned(),
                    audience: "host".to_owned(),
                    required: false,
                    max_calls: 0,
                    max_request_bytes: 0,
                    max_response_bytes: 0,
                })
                .collect(),
            mode: CommunityPluginModeV1::Local,
            limits: DeterministicBudgetV1 {
                memory_bytes: BUDGET_UNIT,
                fuel: BUDGET_UNIT,
                host_calls: BUDGET_UNIT,
                event_count: BUDGET_UNIT,
                event_bytes: BUDGET_UNIT,
                state_bytes: BUDGET_UNIT,
                log_calls: BUDGET_UNIT,
                log_bytes: BUDGET_UNIT,
            },
            execution_profile_digest: None,
        },
        watchdog_millis: WATCHDOG_MILLIS,
        host_inputs: HostInputs { simulation_time: 0 },
        call,
    }
}

fn described(returned: WorkerReturnV1) -> Option<PluginDescriptorV1> {
    match returned {
        WorkerReturnV1::Described(report) => report.result.ok(),
        WorkerReturnV1::Produced(_) => None,
    }
}

fn produced(returned: WorkerReturnV1) -> Option<GuestReturnV1<PluginOutputV1>> {
    match returned {
        WorkerReturnV1::Produced(report) => Some(report.result),
        WorkerReturnV1::Described(_) => None,
    }
}

/// An output must echo its invocation and carry its own output digest; a
/// guest error is admitted as the guest's typed outcome.
fn admitted(invocation: &PluginInvocationV1, result: &GuestReturnV1<PluginOutputV1>) -> bool {
    result.as_ref().map_or(true, |output| {
        output.invocation_id == invocation.invocation_id
            && output.output_digest == plugin_output_digest_v1(output)
    })
}

/// The invocation the host builds for one call. Its Timeline is the
/// position-relative ordinal 0 (16 zero bytes), its Tick the Event's `seq`.
#[must_use]
pub fn g_plug_invocation_v1(
    ordinal: u64,
    seq: u64,
    observation: Vec<u8>,
    prior_state: Vec<u8>,
) -> PluginInvocationV1 {
    let full = digest(&encode(&Value::Array(vec![
        text("ni.g-plug.invocation"),
        uint(ordinal),
    ])));
    let mut invocation_id = [0; 16];
    invocation_id.copy_from_slice(&full[..16]);
    let none = ArtifactRefV1 {
        schema_id: 0,
        byte_length: 0,
        digest: [0; 32],
    };
    PluginInvocationV1 {
        invocation_id,
        timeline_position: TimelinePositionV1 {
            timeline_id: [0; 16],
            seq,
            tick: seq,
            scheduler_position: 0,
        },
        output_base_ordinal: 0,
        principal_ref: none,
        authorization_decision: none,
        observation_snapshot: none,
        observation_bytes: observation,
        prior_state_schema: digest(STATE_SCHEMA_TEXT),
        prior_state_bytes: prior_state,
        execution_profile_digest: [0; 32],
        trust_policy_snapshot_digest: [0; 32],
        deterministic_budget_id: BUDGET_ID.to_owned(),
        deterministic_random_domain: [0; 32],
        provenance_root: [0; 32],
    }
}

// ---------------------------------------------------------------------------
// The fixture guest
// ---------------------------------------------------------------------------

/// The in-process deterministic fixture guest.
///
/// It decodes one PWQ1 request with the protocol codec and answers `describe`, `reduce` or `drive` with
/// one PWR1 response. A request for another Component, or one the codec
/// refuses (a migrate-state request included), gets no response.
///
/// - `describe`: the fixed descriptor of [`G_PLUG_GUEST_PLUGIN_ID_V1`].
/// - `drive`: one draft of [`G_PLUG_EVENT_TYPE_V1`] whose payload is
///   `["drive", observation]`, depending on the observation's digest; the
///   state is unchanged.
/// - `reduce`: the next state is the BLAKE3 of the prior state and the
///   observation; an observation with [`G_PLUG_PROBE_PREFIX_V1`] is answered
///   with `capability-required` for the capability that follows it.
#[must_use]
pub fn serve_g_plug_fixture_guest_v1(request: &[u8]) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    decode_worker_request_v1(request)
        .ok()
        .filter(|request| request.component.as_slice() == G_PLUG_COMPONENT_V1)
        .and_then(|request| encode_worker_response_v1(&Ok(guest_return(&request.call))).ok())
}

fn guest_return(call: &WorkerCallV1) -> WorkerReturnV1 {
    match call {
        WorkerCallV1::Describe => WorkerReturnV1::Described(report(Ok(descriptor()))),
        WorkerCallV1::Drive(invocation) => {
            WorkerReturnV1::Produced(report(Ok(drive_output(invocation))))
        }
        WorkerCallV1::Reduce(invocation) => {
            WorkerReturnV1::Produced(report(reduce_output(invocation)))
        }
    }
}

const fn report<T>(result: GuestReturnV1<T>) -> InvocationReportV1<T> {
    InvocationReportV1 {
        result,
        metering: MeteringV1 {
            startup_fuel: 0,
            call_fuel: 0,
            memory_bytes: 0,
            host_calls: 0,
        },
        operational_log: Vec::new(),
    }
}

fn descriptor() -> PluginDescriptorV1 {
    PluginDescriptorV1 {
        plugin_id: G_PLUG_GUEST_PLUGIN_ID_V1.to_owned(),
        release_semver: "1.0.0".to_owned(),
        world: WORLD.to_owned(),
        abi_major: COMMUNITY_PLUGIN_ABI_MAJOR_V1,
        min_abi_minor: 0,
        max_abi_minor: 0,
        required_features: Vec::new(),
        event_schema_digests: vec![digest(G_PLUG_EVENT_TYPE_V1.as_bytes())],
        state_schema_digest: digest(STATE_SCHEMA_TEXT),
        manifest_digest: [0; 32],
        release_digest: [0; 32],
    }
}

fn output(
    invocation: &PluginInvocationV1,
    event_drafts: Vec<EventDraftV1>,
    next_state_bytes: Vec<u8>,
) -> PluginOutputV1 {
    let mut output = PluginOutputV1 {
        invocation_id: invocation.invocation_id,
        event_drafts,
        next_state_schema: digest(STATE_SCHEMA_TEXT),
        next_state_bytes,
        trace_annotations: Vec::new(),
        consumed_dependencies: vec![digest(&invocation.observation_bytes)],
        output_digest: [0; 32],
    };
    output.output_digest = plugin_output_digest_v1(&output);
    output
}

fn drive_output(invocation: &PluginInvocationV1) -> PluginOutputV1 {
    let observation = &invocation.observation_bytes;
    output(
        invocation,
        vec![EventDraftV1 {
            event_schema_id: EVENT_SCHEMA_ID,
            entity_id: G_PLUG_ENTITY.to_bytes(),
            event_type: G_PLUG_EVENT_TYPE_V1.to_owned(),
            canonical_payload: encode(&Value::Array(vec![
                text("drive"),
                Value::Bytes(observation.clone()),
            ])),
            dependency_digests: vec![digest(observation)],
        }],
        invocation.prior_state_bytes.clone(),
    )
}

fn reduce_output(invocation: &PluginInvocationV1) -> GuestReturnV1<PluginOutputV1> {
    invocation
        .observation_bytes
        .strip_prefix(G_PLUG_PROBE_PREFIX_V1)
        .map_or_else(
            || {
                let mut folded = invocation.prior_state_bytes.clone();
                folded.extend_from_slice(&invocation.observation_bytes);
                Ok(output(invocation, Vec::new(), digest(&folded).to_vec()))
            },
            |capability| {
                Err(GuestPluginErrorV1 {
                    code: PluginErrorCodeV1::CapabilityRequired(
                        String::from_utf8_lossy(capability).into_owned(),
                    ),
                    canonical_coordinate: None,
                    related_digest: None,
                })
            },
        )
}

// ---------------------------------------------------------------------------
// Subject
// ---------------------------------------------------------------------------

struct GPlugPlugin;

impl Plugin for GPlugPlugin {
    fn id(&self) -> PluginId {
        G_PLUG_PLUGIN_ID
    }

    fn name(&self) -> &'static str {
        "ni-g-plug"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(G_PLUG_EVENT_TYPE_V1)],
            owned_entity_kinds: Vec::new(),
            has_driver: true,
            has_reducer: false,
        }
    }
}

/// Calls the guest's `drive` with the same observation on every Tick, so a
/// Fork's fresh Driver continues exactly as the parent would.
struct GPlugDriver {
    observation: Vec<u8>,
}

impl Driver for GPlugDriver {
    fn name(&self) -> &'static str {
        "ni-g-plug.driver"
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        let refused = RuntimeError::InvalidPayload {
            event_type: G_PLUG_EVENT_TYPE_V1.to_owned(),
            reason: "the fixture guest refused the drive call".to_owned(),
        };
        GPlugProtocolHostV1::new(serve_g_plug_fixture_guest_v1)
            .drive(&g_plug_invocation_v1(
                0,
                0,
                self.observation.clone(),
                Vec::new(),
            ))
            .map(|mut output| {
                StepOutput::new(
                    std::mem::take(&mut output.event_drafts)
                        .into_iter()
                        .map(|draft| {
                            EventDraft::new(
                                EntityId::from_ulid(ulid::Ulid::from_bytes(draft.entity_id)),
                                Kind::new(draft.event_type),
                                CanonicalBytes::from_vec(draft.canonical_payload),
                            )
                        })
                        .collect(),
                )
            })
            .ok_or(refused)
    }
}

fn g_plug_registry(observation: Vec<u8>) -> Result<PluginRegistry, RuntimeError> {
    let mut registry = PluginRegistry::new();
    registry
        .register_generated(
            &GPlugPlugin,
            None,
            Some(Box::new(GPlugDriver { observation })),
        )
        .map(|()| registry)
}

/// Compose the G-PLUG subject Experiment for one run, from the permitted
/// input alone.
///
/// # Errors
/// Returns `Missing` for a row without a G-PLUG capture adapter and
/// `Unavailable` when the Plugin cannot be registered.
pub fn g_plug_experiment_v1(
    fixture_id: &str,
    permitted_input: &[u8],
) -> Result<Experiment, NonInterferenceNonExecutedCauseV1> {
    RowV1::of(fixture_id)
        .ok_or(NonInterferenceNonExecutedCauseV1::Missing)
        .and_then(|row| {
            let observation = drive_observation(row, fixture_id, permitted_input);
            let child = observation.clone();
            let mut experiment = Experiment::new(ExperimentConfig {
                name: "ni-g-plug".to_owned(),
                stop: StopCondition::MaxTicks(G_PLUG_TICKS_V1),
                store_config: StoreConfig::Memory,
            })
            .with_fork_registry_factory(move |_| g_plug_registry(child.clone()));
            experiment
                .register_generated(
                    &GPlugPlugin,
                    None,
                    Some(Box::new(GPlugDriver { observation })),
                )
                .ok()
                .map(|()| experiment)
                .ok_or(NonInterferenceNonExecutedCauseV1::Unavailable)
        })
}

/// Serve one Local run of the G-PLUG subject in a fresh host process whose
/// working directory is `directory`.
///
/// # Errors
/// Returns the cause of a request, subject, capture or frame failure.
pub fn serve_g_plug_local_subject_v1<R: Read, W: Write>(
    input: R,
    output: W,
    directory: &Path,
) -> Result<(), NonInterferenceNonExecutedCauseV1> {
    serve_non_interference_local_subject_v1(input, output, |request| {
        g_plug_experiment_v1(&request.fixture_id, &request.permitted_input)
            .and_then(|experiment| {
                experiment
                    .start()
                    .map_err(NonInterferenceNonExecutedCauseV1::from)
            })
            .and_then(|mut session| recorded(&mut session))
            .and_then(|(_, events)| {
                g_plug_capture_v1(
                    &GPlugRunV1 {
                        fixture_id: &request.fixture_id,
                        variant: request.variant,
                        permitted_input: &request.permitted_input,
                        unauthorized_value: &request.unauthorized_value,
                    },
                    &events,
                    directory,
                )
            })
    })
}

/// The G-PLUG subject of the Replay and Fork runners.
#[derive(Debug)]
pub struct GPlugSessionSubjectV1 {
    work_root: PathBuf,
    directories: u64,
    warm: Option<PathBuf>,
    directory: PathBuf,
}

impl GPlugSessionSubjectV1 {
    /// A subject whose run directories are created below `work_root`.
    #[must_use]
    pub fn new(work_root: PathBuf) -> Self {
        Self {
            directory: work_root.clone(),
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

impl NonInterferenceSessionSubjectV1 for GPlugSessionSubjectV1 {
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
                g_plug_experiment_v1(run.subject.fixture_id, run.subject.permitted_input)
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
        g_plug_capture_v1(
            &GPlugRunV1 {
                fixture_id: run.subject.fixture_id,
                variant: run.subject.variant,
                permitted_input: run.subject.permitted_input,
                unauthorized_value: run.unauthorized_value,
            },
            observation.events,
            &self.directory,
        )
    }
}

// ---------------------------------------------------------------------------
// Capture
// ---------------------------------------------------------------------------

/// Capture one run from the Events the mode produced, with the host's files
/// in `directory`.
///
/// The capture describes the guest (or reads the cached descriptor), then
/// rebuilds the Plugin's state through `reduce` over the Events in Timeline
/// Order (and, for the `Denial` variant, one capability probe), writes the
/// row's host-owned record, and maps everything to the row's surfaces. A
/// lookup without a frozen record counts as one unexpected network access.
///
/// # Errors
/// Returns `Missing` for a row without a G-PLUG capture adapter, and
/// `Unavailable` when the guest, the Events or the host files fail.
pub fn g_plug_capture_v1(
    run: &GPlugRunV1<'_>,
    events: &[Event],
    directory: &Path,
) -> Result<NonInterferenceRawCaptureV1, NonInterferenceNonExecutedCauseV1> {
    RowV1::of(run.fixture_id)
        .ok_or(NonInterferenceNonExecutedCauseV1::Missing)
        .and_then(|row| {
            capture_row(row, run, events, directory)
                .ok_or(NonInterferenceNonExecutedCauseV1::Unavailable)
        })
}

fn capture_row(
    row: RowV1,
    run: &GPlugRunV1<'_>,
    events: &[Event],
    directory: &Path,
) -> Option<NonInterferenceRawCaptureV1> {
    let host = GPlugProtocolHostV1::new(serve_g_plug_fixture_guest_v1);
    let cache = directory.join(G_PLUG_CACHE_FILE_V1);
    fs::read(&cache)
        .ok()
        .or_else(|| {
            host.describe()
                .map(|descriptor| encode(&descriptor_record(&descriptor)))
                .filter(|record| fs::write(&cache, record).is_ok())
        })
        .zip(event_stream(events, None).map(|stream| encode(&stream)))
        .zip(rebuild(&host, row, run.variant, events))
        .and_then(|((descriptor, stream), rebuilt)| {
            let record = encode(&host_record(row, run, &rebuilt.state));
            fs::write(directory.join(G_PLUG_HOST_STORE_FILE_V1), &record)
                .ok()
                .map(|()| {
                    let context = ContextV1 {
                        row,
                        run,
                        events,
                        descriptor,
                        stream,
                        record,
                        rebuilt,
                        host: &host,
                    };
                    let mut capture = context.surfaces().into_capture(run.fixture_id);
                    capture.unexpected_network_accesses =
                        u32::from(live_call(row, run.fixture_id, run.permitted_input));
                    capture
                })
        })
}

/// The descriptor record: `[plugin id, semver, world, ABI major, min minor,
/// max minor, [features], [event schema digests], state schema digest]`.
fn descriptor_record(descriptor: &PluginDescriptorV1) -> Value {
    Value::Array(vec![
        text(&descriptor.plugin_id),
        text(&descriptor.release_semver),
        text(&descriptor.world),
        uint(u64::from(descriptor.abi_major)),
        uint(u64::from(descriptor.min_abi_minor)),
        uint(u64::from(descriptor.max_abi_minor)),
        Value::Array(
            descriptor
                .required_features
                .iter()
                .map(|feature| text(feature))
                .collect(),
        ),
        Value::Array(
            descriptor
                .event_schema_digests
                .iter()
                .map(|digest| Value::Bytes(digest.to_vec()))
                .collect(),
        ),
        Value::Bytes(descriptor.state_schema_digest.to_vec()),
    ])
}

/// What the `reduce` rebuild recorded.
struct RebuiltV1 {
    /// `[ordinal, seq, observation digest, prior state digest]` per call.
    invocations: Vec<Value>,
    /// `["output", draft count, next state, [consumed]]` or `["error",
    /// code]` per call.
    outputs: Vec<Value>,
    /// `[ordinal, [consumed]]` per output.
    edges: Vec<Value>,
    /// The error records alone.
    errors: Vec<Value>,
    /// The authorized state after the last output.
    state: Vec<u8>,
}

/// Rebuild the Plugin's state through `reduce` over the Events in Timeline
/// Order; the `Denial` variant then probes the row's capability once.
fn rebuild(
    host: &GPlugProtocolHostV1,
    row: RowV1,
    variant: NonInterferenceVariantV1,
    events: &[Event],
) -> Option<RebuiltV1> {
    let probe = (variant == NonInterferenceVariantV1::Denial).then(|| {
        let mut observation = G_PLUG_PROBE_PREFIX_V1.to_vec();
        observation.extend_from_slice(row.capability().as_bytes());
        (
            events.last().map_or(0, |event| event.seq.as_u64()),
            observation,
        )
    });
    events
        .iter()
        .map(|event| (event.seq.as_u64(), event.payload.as_slice().to_vec()))
        .chain(probe)
        .zip(1_u64..)
        .try_fold(
            RebuiltV1 {
                invocations: Vec::new(),
                outputs: Vec::new(),
                edges: Vec::new(),
                errors: Vec::new(),
                state: INITIAL_STATE.to_vec(),
            },
            |mut rebuilt, ((seq, observation), ordinal)| {
                let invocation =
                    g_plug_invocation_v1(ordinal, seq, observation, rebuilt.state.clone());
                host.reduce(&invocation).map(|result| {
                    rebuilt.invocations.push(Value::Array(vec![
                        uint(ordinal),
                        uint(seq),
                        Value::Bytes(digest(&invocation.observation_bytes).to_vec()),
                        Value::Bytes(digest(&invocation.prior_state_bytes).to_vec()),
                    ]));
                    match result {
                        Ok(mut output) => {
                            let consumed = Value::Array(
                                output
                                    .consumed_dependencies
                                    .iter()
                                    .map(|digest| Value::Bytes(digest.to_vec()))
                                    .collect(),
                            );
                            rebuilt.outputs.push(Value::Array(vec![
                                text("output"),
                                uint(output.event_drafts.len() as u64),
                                Value::Bytes(output.next_state_bytes.clone()),
                                consumed.clone(),
                            ]));
                            rebuilt
                                .edges
                                .push(Value::Array(vec![uint(ordinal), consumed]));
                            rebuilt.state = std::mem::take(&mut output.next_state_bytes);
                        }
                        Err(error) => {
                            let record = Value::Array(vec![
                                text("error"),
                                text(guest_error_code(&error.code)),
                            ]);
                            rebuilt.outputs.push(record.clone());
                            rebuilt.errors.push(record);
                        }
                    }
                    rebuilt
                })
            },
        )
}

/// The closed contract-v1 name of a guest error code, so the capture never
/// depends on Rust `Debug` text.
const fn guest_error_code(code: &PluginErrorCodeV1) -> &'static str {
    match code {
        PluginErrorCodeV1::InvalidInvocation(_) => "invalid-invocation",
        PluginErrorCodeV1::UnsupportedSchema(_) => "unsupported-schema",
        PluginErrorCodeV1::CapabilityRequired(_) => "capability-required",
        PluginErrorCodeV1::DependencyMissing(_) => "dependency-missing",
        PluginErrorCodeV1::DeterministicBudgetExhausted => "deterministic-budget-exhausted",
        PluginErrorCodeV1::InvalidState(_) => "invalid-state",
        PluginErrorCodeV1::MigrationRejected(_) => "migration-rejected",
        PluginErrorCodeV1::GuestDeclaredFailure(_) => "guest-declared-failure",
    }
}

/// Everything one row's surfaces are built from.
struct ContextV1<'a> {
    row: RowV1,
    run: &'a GPlugRunV1<'a>,
    events: &'a [Event],
    descriptor: Vec<u8>,
    stream: Vec<u8>,
    record: Vec<u8>,
    rebuilt: RebuiltV1,
    host: &'a GPlugProtocolHostV1,
}

/// One `CategoryCountDigest` facet over the surface's own bytes.
fn category_count_digest(
    category: u16,
    count: usize,
    surface: &[u8],
    excluded_sensitive: &[u8],
) -> NonInterferenceRawOperationalV1 {
    NonInterferenceRawOperationalV1::CategoryCountDigest {
        category,
        count: u32::try_from(count).unwrap_or(u32::MAX),
        digest: digest(surface),
        excluded_sensitive: excluded_sensitive.to_vec(),
    }
}

/// One `CategoryCount` facet.
fn category_count(
    category: u16,
    count: usize,
    excluded_sensitive: &[u8],
) -> NonInterferenceRawOperationalV1 {
    NonInterferenceRawOperationalV1::CategoryCount {
        category,
        count: u32::try_from(count).unwrap_or(u32::MAX),
        excluded_sensitive: excluded_sensitive.to_vec(),
    }
}

impl ContextV1<'_> {
    /// `[descriptor record bytes, [Plugin name, Driver name],
    /// [invocation...]]`: the guest's descriptor, the host composition that
    /// invokes it, and every invocation.
    fn invocations(&self) -> Vec<u8> {
        encode(&Value::Array(vec![
            Value::Bytes(self.descriptor.clone()),
            Value::Array(vec![
                text(GPlugPlugin.name()),
                text(
                    GPlugDriver {
                        observation: Vec::new(),
                    }
                    .name(),
                ),
            ]),
            Value::Array(self.rebuilt.invocations.clone()),
        ]))
    }

    fn outputs(&self) -> Vec<u8> {
        encode(&Value::Array(self.rebuilt.outputs.clone()))
    }

    /// Each row's surfaces in ADR-059 order. The authoritative and public
    /// facets are the same record.
    fn surfaces(&self) -> SurfacesV1 {
        let (authoritative, operational) = match self.row {
            RowV1::Tool => self.tool(),
            RowV1::State => self.state(),
            RowV1::Net => self.network(),
            RowV1::Service => self.service(),
        };
        SurfacesV1 {
            public: authoritative.clone(),
            authoritative,
            operational,
        }
    }

    /// `NI-TOOL-001`: registry, tool result handle, Plugin imports, staged
    /// `EventDrafts`, public outcome and audit record; operationally
    /// count/category/digest, the denied response excluded.
    fn tool(&self) -> (Vec<Vec<u8>>, Vec<NonInterferenceRawOperationalV1>) {
        let tool = |status: &str| {
            Value::Array(vec![Value::Array(vec![
                text(G_PLUG_TOOL_ID_V1),
                text(RowV1::Tool.capability()),
                text(status),
            ])])
        };
        let registry = encode(&Value::Array(vec![Value::Array(vec![
            text(G_PLUG_TOOL_ID_V1),
            text(RowV1::Tool.capability()),
            Value::Bool(false),
        ])]));
        let handle = encode(&Value::Array(vec![Value::Array(vec![
            uint(0),
            text(G_PLUG_TOOL_ID_V1),
            text("capability-denied"),
        ])]));
        let imports = self.invocations();
        let outcome = self.outputs();
        let audit = encode(&tool("denied"));
        let operational = vec![
            category_count_digest(1, 1, &registry, &self.record),
            category_count_digest(1, 1, &handle, &self.record),
            category_count_digest(0, self.rebuilt.invocations.len(), &imports, &[]),
            category_count_digest(0, self.events.len(), &self.stream, &[]),
            category_count_digest(0, self.rebuilt.outputs.len(), &outcome, &[]),
            category_count_digest(1, 1, &audit, &self.record),
        ];
        (
            vec![
                registry,
                handle,
                imports,
                self.stream.clone(),
                outcome,
                audit,
            ],
            operational,
        )
    }

    /// `NI-STATE-003` (state members): the closed migrate-state record,
    /// activated state, `PluginInvocation`, `PluginOutput`, `EventDrafts` and
    /// quarantine/error; operationally category/count, the unauthorized
    /// member excluded.
    fn state(&self) -> (Vec<Vec<u8>>, Vec<NonInterferenceRawOperationalV1>) {
        let answered = usize::from(
            self.host
                .migrate_state(&g_plug_invocation_v1(
                    0,
                    0,
                    Vec::new(),
                    self.rebuilt.state.clone(),
                ))
                .is_some(),
        );
        let migration = encode(&Value::Array(vec![
            text("migrate-state refused"),
            uint(answered as u64),
        ]));
        let activated = encode(&Value::Bytes(self.rebuilt.state.clone()));
        let quarantine = encode(&Value::Array(self.rebuilt.errors.clone()));
        let operational = vec![
            category_count(1, answered, &[]),
            category_count(0, 1, &self.record),
            category_count(0, self.rebuilt.invocations.len(), &[]),
            category_count(0, self.rebuilt.outputs.len(), &[]),
            category_count(0, self.events.len(), &[]),
            category_count(0, self.rebuilt.errors.len(), &[]),
        ];
        (
            vec![
                migration,
                activated,
                self.invocations(),
                self.outputs(),
                self.stream.clone(),
                quarantine,
            ],
            operational,
        )
    }

    /// `NI-NET-010`: capability checks, attempted-call records, retry count,
    /// Plugin output, Timeline, logs and evaluator bundle; operationally
    /// category/count, endpoint, DNS, body and timing excluded.
    fn network(&self) -> (Vec<Vec<u8>>, Vec<NonInterferenceRawOperationalV1>) {
        let live = usize::from(live_call(
            self.row,
            self.run.fixture_id,
            self.run.permitted_input,
        ));
        let capability = encode(&Value::Array(vec![Value::Array(vec![
            text(RowV1::Net.capability()),
            Value::Bool(false),
        ])]));
        let attempted = encode(&Value::Array(vec![Value::Array(vec![
            text("network"),
            text("absent"),
            uint(live as u64),
        ])]));
        let bundle = encode(&Value::Array(vec![
            Value::Bytes(digest(&self.stream).to_vec()),
            Value::Bytes(self.rebuilt.state.clone()),
        ]));
        let operational = vec![
            category_count(1, 1, &self.record),
            category_count(0, live, &self.record),
            category_count(0, 0, &self.record),
            category_count(0, self.rebuilt.outputs.len(), &[]),
            category_count(0, self.events.len(), &[]),
            category_count(0, 0, &self.record),
            category_count(0, 1, &[]),
        ];
        (
            vec![
                capability,
                attempted,
                encode(&uint(0)),
                self.outputs(),
                self.stream.clone(),
                encode(&Value::Array(Vec::new())),
                bundle,
            ],
            operational,
        )
    }

    /// `NI-SERVICE-011`: exact request digests, frozen response projections,
    /// call ordinals, `PluginInvocation` and generated dependency edges, one
    /// call per Event; every facet is byte-exact.
    fn service(&self) -> (Vec<Vec<u8>>, Vec<NonInterferenceRawOperationalV1>) {
        let permitted = self.run.permitted_input;
        let request = Value::Bytes(digest(&service_request("service", permitted)).to_vec());
        let projection = frozen_projection(self.run.fixture_id, "service", permitted)
            .map_or(Value::Null, Value::Bytes);
        let per_call = |value: &Value| {
            encode(&Value::Array(
                self.events.iter().map(|_| value.clone()).collect(),
            ))
        };
        let ordinals = encode(&Value::Array(
            self.events
                .iter()
                .zip(0_u64..)
                .map(|(event, ordinal)| Value::Array(vec![uint(ordinal), uint(event.seq.as_u64())]))
                .collect(),
        ));
        let surfaces = vec![
            per_call(&request),
            per_call(&projection),
            ordinals,
            self.invocations(),
            encode(&Value::Array(self.rebuilt.edges.clone())),
        ];
        let operational = surfaces
            .iter()
            .map(|surface| NonInterferenceRawOperationalV1::ByteExact(surface.clone()))
            .collect();
        (surfaces, operational)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use pos_runtime::community_plugin_host::FieldRefV1;

    #[test]
    fn every_guest_error_code_has_its_closed_contract_name() {
        let at = FieldRefV1 {
            schema_id: 1,
            field_ordinal: 2,
        };
        let codes = [
            (
                PluginErrorCodeV1::InvalidInvocation(at),
                "invalid-invocation",
            ),
            (
                PluginErrorCodeV1::UnsupportedSchema(1),
                "unsupported-schema",
            ),
            (
                PluginErrorCodeV1::CapabilityRequired("ni.cap.tool".to_owned()),
                "capability-required",
            ),
            (
                PluginErrorCodeV1::DependencyMissing([1; 32]),
                "dependency-missing",
            ),
            (
                PluginErrorCodeV1::DeterministicBudgetExhausted,
                "deterministic-budget-exhausted",
            ),
            (PluginErrorCodeV1::InvalidState(at), "invalid-state"),
            (
                PluginErrorCodeV1::MigrationRejected(at),
                "migration-rejected",
            ),
            (
                PluginErrorCodeV1::GuestDeclaredFailure(3),
                "guest-declared-failure",
            ),
        ];
        for (code, name) in codes {
            assert_eq!(guest_error_code(&code), name);
        }
    }
}
