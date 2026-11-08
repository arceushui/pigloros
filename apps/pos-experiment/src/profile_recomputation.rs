//! `ProfileRecomputation` and `CrossProfileConformance` execution through the
//! Experiment host.
//!
//! ADR-062 Revision 8 slice R3 (#1221). [`execute_profile_recomputation_v1`]
//! is the execution step after [`preflight_verification_v1`] for a
//! recomputation: it recomputes the run from the complete frozen closure
//! under the named EPF1 on a fresh [`Experiment`] host, compares the
//! recomputed stream with the expected stream through
//! [`first_divergence_v1`](crate::authoritative_comparison::first_divergence_v1)
//! and emits one sealed `VRR1`. [`execute_cross_profile_conformance_v1`]
//! runs the same closure under `deterministic-local-v1` and
//! `deterministic-air-gapped-v1` and compares both runs with one expected
//! stream.
//!
//! # Order
//!
//! 1. The `ArtifactClosure` members: the recomputation subject and a
//!    non-empty licence member must both be supplied. When either is
//!    missing, the unchanged preflight runs with `Incomplete` closure
//!    evidence, so the refusal is its own `ClosureIncomplete` at
//!    `artifact_closure` (as for `RecordedReplay`).
//! 2. The preflight; its first error becomes the result's first error. The
//!    closure members bind the request's `artifact_closure_digest` (slice R4,
//!    #1222): when the composition of the subject's artifact digest and the
//!    licence ([`recomputation_closure_digest_v1`]) is not that digest, the
//!    closure is refused at `artifact_closure` with `DigestMismatch`
//!    (`InvalidManifest`), after any earlier preflight coordinate.
//! 3. The reproducibility class: `ProfileRecomputation` or `LiveUnverified`
//!    for a single run, `CrossProfileConformance` for each leg of a
//!    cross-profile run. Any other class is `IncompatibleProfile` at
//!    `profile_class`.
//! 4. The host's checks of the request against the named EPF1 (#1266), each
//!    `IncompatibleProfile` with `ProfileUnsupported` at `execution_profile`:
//!    - a cross-profile leg must name its own EPF1 (`deterministic-local-v1`
//!      or `deterministic-air-gapped-v1`) and its manifest must be in its
//!      own Execution Mode (Local or Air-Gapped);
//!    - the manifest Execution Mode must be Local or Air-Gapped;
//!    - the network gate: a manifest that enables network is refused when
//!      the EPF1 denies network or the mode is Air-Gapped.
//! 5. The execution-step budget: a frozen number of Ticks above the EPF1
//!    execution-step budget is `ResourceLimitExceeded`, before any run.
//! 6. The subject composes its frozen Plugins on a fresh Experiment host in
//!    the manifest's Execution Mode ([`Experiment::new`] or
//!    [`Experiment::new_air_gapped`]) under the named EPF1. A subject that
//!    reports it cannot run under the EPF1
//!    ([`RecomputationComposeErrorV1::ProfileUnsupported`]) is
//!    `IncompatibleProfile` with `ProfileUnsupported` at `execution_profile`,
//!    and so is a composition the host itself refused: a host that is no
//!    longer in the manifest's mode, or one that refused a mode-gated
//!    operation ([`Experiment::refused_mode_gated_operation`]), even when the
//!    subject ignored the refusal. A registration error
//!    ([`RecomputationComposeErrorV1::Registration`]) is not a profile
//!    refusal: it is the run's typed failure, with no Events.
//! 7. The host applies the manifest `resource_limit` as its per-Tick Event
//!    budget and its own stop condition, and steps exactly the frozen number
//!    of Ticks, whatever stop condition the composed host carried. A step error is the run's typed
//!    failure and ends the run; an exhausted host budget is
//!    `ResourceLimitExceeded` instead. A recomputed Timeline with more
//!    Events than the smaller of `resource_limit` and the EPF1 Event-count
//!    budget is `ResourceLimitExceeded` too.
//! 8. The recomputed Events are folded into the caller's
//!    [`ProjectionRegistry`] from empty State and its Snapshot is read under
//!    the registry's erasure fence; a denied fence is
//!    `UnverifiableArtifactsMissing`.
//! 9. When the admitted request can claim exact verification, the stream is
//!    compared: `VerifiedExact` or `Diverged` with the `DVR1` digest. A
//!    `LiveUnverified` run (or a non-exact claim) is never compared and
//!    never exact: its `VRR1` keeps its class and claim, records the
//!    recomputed result digest and is `UnverifiableArtifactsMissing` with
//!    `ProvenanceMissing` at `replay_claim` (ADR-062 Revision 8, Q4).
//!
//! # EPF1 enforcement
//!
//! The owner decisions are recorded on the wiki page
//! `ADR-062_R8_Profile_Recomputation_Enforcement` (2026-11-07). The host
//! enforces, independently of the subject:
//!
//! - the network gate on the request inputs (step 4). It is an input check:
//!   the subject's native Plugins run in the host process, and the host
//!   claims no runtime network denial;
//! - the Execution Mode, through the composition mode of the host it builds
//!   (steps 4 and 6). It claims no isolation;
//! - the Event-count budget (EPF1 budget slot [`EVENT_COUNT_BUDGET_SLOT_V1`])
//!   and the execution-step budget (slot [`EXECUTION_STEPS_BUDGET_SLOT_V1`]),
//!   whose steps are Ticks here (steps 5 and 7). The EPF1 budget slots follow
//!   the order of `pos_conformance::DeterministicBudgetV1`.
//!
//! It does not enforce `scheduler_driver_order`, `schemas_and_upcasters`,
//! `capability_ids`, the numeric and architecture rules, or the memory,
//! fuel, host-call, output, storage and Simulation Time budgets. Until the
//! Sandbox Provider runs Air-Gapped (Q6), results are Local-relaxation
//! engineering evidence.
//!
//! # Recomputed stream
//!
//! The owner decisions for this slice are recorded on the wiki page
//! `ADR-062_R8_Recorded_Replay_Digests`, section 6 (2026-10-30), and its
//! section 2 digest table. The stream uses that accepted `RecordedReplay`
//! digest scheme, documented in [`crate::verification_execution`], with
//! tick 0. A recomputed run mints a fresh Timeline id and fresh Event ids
//! (ULIDs that carry the wall clock), so those identifiers are operational:
//! the stream is addressed by [`RECOMPUTED_TIMELINE_ID_V1`] and every Event
//! identity digest covers 16 zero bytes in place of the Event id. Entity ids,
//! Event types, schema versions, payloads, Timeline Order and the Projection
//! Snapshot are authoritative.
//!
//! A typed failure is one Driver output at the host coordinate: Timeline
//! [`RECOMPUTED_TIMELINE_ID_V1`], the Fold Cursor of the last committed Event,
//! tick 0, scheduler position 0, Driver id [`HOST_FAILURE_DRIVER_ID_V1`] and
//! output ordinal 0. Its canonical bytes are the four bytes of
//! [`HostFailureV1::to_be_bytes`]: the closed [`HostFailureCodeV1`] as a
//! big-endian `u16`, then the sub-code as a big-endian `u16` (the
//! [`RuntimeErrorKindV1`] of a runtime failure, 0 otherwise), never error
//! text. Its numeric profile digest is 32 zero bytes. The typed failure is
//! part of the `authoritative_result_digest`. A typed failure the expected
//! stream also holds verifies as exact (Q4).
//!
//! The store configuration, wall clock and logging are operational: they are
//! not inputs to the stream, so they cannot change the `VRR1`.
//!
//! [`preflight_verification_v1`]: pos_conformance::preflight_verification_v1

use std::collections::HashMap;

use pos_conformance::{
    ExecutionModeV1, ExecutionProfileV1, ReproducibilityClassV1, SafeErrorCodeV1,
    VerificationPreflightCoordinateV1, VerificationPreflightInputV1, VerificationPreflightResultV1,
};
use pos_core::{CoreError, Event, StateRegistry, TimelineId};
use pos_runtime::{PluginExecutionModeV1, RuntimeError};
use pos_state::ProjectionRegistry;
use pos_store::StoreConfig;

use crate::authoritative_comparison::{
    AuthoritativeStreamV1, ComparedDriverOutputV1, DriverOutcomeV1, DriverOutputCoordinateV1,
};
use crate::verification_execution::{
    admit_class, authoritative_stream, event_count, incompatible, preflight_bound_closure,
    rebuild_projections, recomputation_closure_digest_v1, refuse_incomplete_closure,
    resource_limit_exceeded, Refusal, ResultHeader, VerificationExecutionOutcomeV1,
};
use crate::{Experiment, ExperimentConfig, ExperimentError, ExperimentSession, StopCondition};

/// The EPF1 of the Local leg of a cross-profile run.
pub const LOCAL_PROFILE_ID_V1: &str = "deterministic-local-v1";
/// The EPF1 of the Air-Gapped leg of a cross-profile run.
pub const AIR_GAPPED_PROFILE_ID_V1: &str = "deterministic-air-gapped-v1";
/// The Timeline id that addresses a recomputed stream.
pub const RECOMPUTED_TIMELINE_ID_V1: [u8; 16] = [0; 16];
/// The Driver id of a host typed failure.
pub const HOST_FAILURE_DRIVER_ID_V1: &str = "experiment-host";
/// The EPF1 `deterministic_budgets` slot of the Event-count budget: a cap on
/// the total Events of a recomputed Timeline.
pub const EVENT_COUNT_BUDGET_SLOT_V1: usize = 3;
/// The EPF1 `deterministic_budgets` slot of the execution-step budget: a cap
/// on the Ticks a recomputation steps.
pub const EXECUTION_STEPS_BUDGET_SLOT_V1: usize = 6;

const EXPERIMENT_NAME: &str = "profile-recomputation";

/// The closed code of a host typed failure, one per [`ExperimentError`]
/// variant; see [`HostFailureV1`] for its canonical bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum HostFailureCodeV1 {
    /// [`ExperimentError::Runtime`]: a Driver, Plugin or runtime failure.
    Runtime = 1,
    /// [`ExperimentError::ActionRejected`].
    ActionRejected = 2,
    /// [`ExperimentError::Store`].
    Store = 3,
    /// [`ExperimentError::ManifestRoster`].
    ManifestRoster = 4,
    /// [`ExperimentError::MissingForkRegistryFactory`].
    MissingForkRegistryFactory = 5,
    /// [`ExperimentError::MissingStoreRecoveryRecipe`].
    MissingStoreRecoveryRecipe = 6,
    /// [`ExperimentError::SharedStoreLockPoisoned`].
    SharedStoreLockPoisoned = 7,
    /// [`ExperimentError::IncompatibleForkRegistry`].
    IncompatibleForkRegistry = 8,
    /// [`ExperimentError::SessionFaulted`].
    SessionFaulted = 9,
    /// [`ExperimentError::ConsentRevokedV1`].
    ConsentRevoked = 10,
    /// [`ExperimentError::ActionNotAdmitted`].
    ActionNotAdmitted = 11,
    /// [`ExperimentError::DuplicatePipelineEvaluator`].
    DuplicatePipelineEvaluator = 12,
    /// [`ExperimentError::CadenceTimeRegressed`].
    CadenceTimeRegressed = 13,
    /// [`ExperimentError::StepModeMismatch`].
    StepModeMismatch = 14,
}

impl From<&ExperimentError> for HostFailureCodeV1 {
    fn from(error: &ExperimentError) -> Self {
        match error {
            ExperimentError::Runtime(_) => Self::Runtime,
            ExperimentError::ActionRejected(_) => Self::ActionRejected,
            ExperimentError::Store(_) => Self::Store,
            ExperimentError::ManifestRoster(_) => Self::ManifestRoster,
            ExperimentError::MissingForkRegistryFactory => Self::MissingForkRegistryFactory,
            ExperimentError::MissingStoreRecoveryRecipe => Self::MissingStoreRecoveryRecipe,
            ExperimentError::SharedStoreLockPoisoned => Self::SharedStoreLockPoisoned,
            ExperimentError::IncompatibleForkRegistry => Self::IncompatibleForkRegistry,
            ExperimentError::SessionFaulted => Self::SessionFaulted,
            ExperimentError::ConsentRevokedV1 => Self::ConsentRevoked,
            ExperimentError::ActionNotAdmitted(_) => Self::ActionNotAdmitted,
            ExperimentError::DuplicatePipelineEvaluator => Self::DuplicatePipelineEvaluator,
            ExperimentError::CadenceTimeRegressed { .. } => Self::CadenceTimeRegressed,
            ExperimentError::StepModeMismatch { .. } => Self::StepModeMismatch,
        }
    }
}

/// Define [`RuntimeErrorKindV1`] and its exhaustive mapping from one list,
/// so each `RuntimeError` variant and its stable value are written once.
macro_rules! runtime_error_kinds {
    ($($variant:ident $(($tuple:tt))? $({$fields:tt})? = $value:literal,)+) => {
        /// The closed kind of a [`RuntimeError`], one per variant in
        /// declaration order from 1; the sub-code of a
        /// [`HostFailureCodeV1::Runtime`] failure.
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        #[repr(u16)]
        pub enum RuntimeErrorKindV1 {
            $(
                #[doc = concat!("[`RuntimeError::", stringify!($variant), "`].")]
                $variant = $value,
            )+
        }

        impl From<&RuntimeError> for RuntimeErrorKindV1 {
            fn from(error: &RuntimeError) -> Self {
                match error {
                    $(RuntimeError::$variant $(($tuple))? $({$fields})? => Self::$variant,)+
                }
            }
        }
    };
}

// Append only; never renumber: these values are part of the result digest.
runtime_error_kinds! {
    ManifestRegistration (_) = 1,
    ManifestSlot (_) = 2,
    OutputAdmission (_) = 3,
    WorldInstallation (_) = 4,
    Composition (_) = 5,
    DuplicatePlugin { .. } = 6,
    UnknownEventType (_) = 7,
    InvalidPayload { .. } = 8,
    NoDriver { .. } = 9,
    DriverPanicked { .. } = 10,
    DriverAbortPanicked { .. } = 11,
    DriverCommitPanicked { .. } = 12,
    DriverRestorePanicked { .. } = 13,
    DriverForkPanicked { .. } = 14,
    DriverForkRollbackFailed { .. } = 15,
    ResourceExhausted { .. } = 16,
    CapabilityMismatch { .. } = 17,
    ReservedGeographicEventType { .. } = 18,
    GeographicDraft { .. } = 19,
    ReservedHostDraft { .. } = 20,
    ReservedHostEventType { .. } = 21,
    ReservedConsentEventType { .. } = 22,
    ConsentDraft { .. } = 23,
    ConsentOperationUnavailable = 24,
    ErasureOperationUnavailable = 25,
    Consent (_) = 26,
    ErasureContainment (_) = 27,
    Authority (_) = 28,
    AuthorityFenceRequired = 29,
    ScheduledProfile (_) = 30,
    AuthorityPersistence (_) = 31,
    PipelineContract (_) = 32,
    ScheduledPassNotAdmitted (_) = 33,
    NoScheduledAdmissionInDoubt = 34,
    DependencyDeclaration (_) = 35,
    CadenceOverflow { .. } = 36,
    MissingSnapshotAnchor { .. } = 37,
    SnapshotTimelineMismatch { .. } = 38,
    PendingDriverStep = 39,
    UnappendedDriverOutput = 40,
    DriverRecoveryNotFresh { .. } = 41,
    DriverTickOverflow { .. } = 42,
    InvalidRecoveryEvidence { .. } = 43,
    CommunityPlugin (_) = 44,
    FallbackSwap (_) = 45,
    Store (_) = 46,
    ModeMismatch { .. } = 47,
}

/// One closed host typed failure: its code and, for a runtime failure, the
/// runtime kind. It carries no error text and no path.
///
/// It is built only from an [`ExperimentError`], so its runtime kind is
/// present exactly when its code is [`HostFailureCodeV1::Runtime`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostFailureV1 {
    code: HostFailureCodeV1,
    runtime_kind: Option<RuntimeErrorKindV1>,
}

impl HostFailureV1 {
    /// The closed code of the [`ExperimentError`] variant.
    #[must_use]
    pub const fn code(self) -> HostFailureCodeV1 {
        self.code
    }

    /// The closed kind of the [`RuntimeError`]; `Some` exactly when the code
    /// is [`HostFailureCodeV1::Runtime`].
    #[must_use]
    pub const fn runtime_kind(self) -> Option<RuntimeErrorKindV1> {
        self.runtime_kind
    }

    /// The canonical bytes of the failure: the code as a big-endian `u16`,
    /// then the sub-code as a big-endian `u16` (the runtime kind, or 0 for
    /// every code other than [`HostFailureCodeV1::Runtime`]).
    #[must_use]
    pub fn to_be_bytes(self) -> [u8; 4] {
        let [code_high, code_low] = (self.code as u16).to_be_bytes();
        let [kind_high, kind_low] = self
            .runtime_kind
            .map_or(0, |kind| kind as u16)
            .to_be_bytes();
        [code_high, code_low, kind_high, kind_low]
    }
}

impl From<&ExperimentError> for HostFailureV1 {
    fn from(error: &ExperimentError) -> Self {
        let runtime_kind = if let ExperimentError::Runtime(runtime) = error {
            Some(RuntimeErrorKindV1::from(runtime))
        } else {
            None
        };
        Self {
            code: HostFailureCodeV1::from(error),
            runtime_kind,
        }
    }
}

/// Why a subject did not compose.
#[derive(Debug)]
pub enum RecomputationComposeErrorV1 {
    /// The subject cannot run under the named EPF1; the run is
    /// `IncompatibleProfile`.
    ProfileUnsupported,
    /// A Plugin of the subject cannot be registered; the run is this typed
    /// failure, with no Events.
    Registration(RuntimeError),
}

/// The frozen subject of a recomputation: the Plugins, Reducers and Drivers
/// of the run, composed from the closure.
pub trait RecomputationSubjectV1 {
    /// Register the frozen composition on a fresh Experiment host that runs
    /// under `profile`, in the manifest's Execution Mode.
    ///
    /// # Errors
    /// Returns [`RecomputationComposeErrorV1::ProfileUnsupported`] when the
    /// subject cannot run under `profile`, and
    /// [`RecomputationComposeErrorV1::Registration`] when its Plugins cannot
    /// be registered.
    fn compose(
        &self,
        experiment: &mut Experiment,
        profile: &ExecutionProfileV1,
    ) -> Result<(), RecomputationComposeErrorV1>;
}

/// The subject member of a recomputation closure.
///
/// `artifact_digest`, composed with the licence
/// ([`recomputation_closure_digest_v1`]), must be the request's
/// `artifact_closure_digest` (ADR-062 Revision 8 slice R4).
#[derive(Clone, Copy)]
pub struct RecomputationSubjectMemberV1<'a> {
    /// The frozen subject.
    pub subject: &'a dyn RecomputationSubjectV1,
    /// Artifact digest of the frozen subject.
    pub artifact_digest: [u8; 32],
    /// The frozen number of Ticks the host steps.
    pub ticks: u64,
}

/// The materialized closure members a recomputation reads.
#[derive(Clone, Copy)]
pub struct RecomputationClosureV1<'a> {
    /// The frozen subject, when it is materialized.
    pub subject: Option<RecomputationSubjectMemberV1<'a>>,
    /// The licence member bytes, when they are materialized; empty bytes
    /// count as missing.
    pub licence: Option<&'a [u8]>,
}

/// Inputs to one `ProfileRecomputation` or `LiveUnverified` execution.
pub struct ProfileRecomputationInputV1<'a> {
    /// The preflight input of the request.
    pub preflight: VerificationPreflightInputV1<'a>,
    /// The materialized closure members.
    pub closure: RecomputationClosureV1<'a>,
    /// The expected authoritative stream.
    pub expected: &'a AuthoritativeStreamV1,
    /// Digest of the fixture, when the run has one.
    pub fixture_digest: Option<[u8; 32]>,
    /// Where the host keeps its store; operational, never a stream input.
    pub store_config: StoreConfig,
}

/// Inputs to one `CrossProfileConformance` execution.
pub struct CrossProfileConformanceInputV1<'a> {
    /// The preflight input of the `deterministic-local-v1` request.
    pub local: VerificationPreflightInputV1<'a>,
    /// The preflight input of the `deterministic-air-gapped-v1` request.
    pub air_gapped: VerificationPreflightInputV1<'a>,
    /// The materialized closure members both legs run.
    pub closure: RecomputationClosureV1<'a>,
    /// The one expected authoritative stream both legs are compared with.
    pub expected: &'a AuthoritativeStreamV1,
    /// Digest of the fixture, when the run has one.
    pub fixture_digest: Option<[u8; 32]>,
    /// Where the host keeps its stores; operational, never a stream input.
    pub store_config: StoreConfig,
}

/// The two results of one `CrossProfileConformance` execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrossProfileConformanceOutcomeV1 {
    /// The `deterministic-local-v1` leg.
    pub local: VerificationExecutionOutcomeV1,
    /// The `deterministic-air-gapped-v1` leg.
    pub air_gapped: VerificationExecutionOutcomeV1,
}

/// Execute one `ProfileRecomputation` (or `LiveUnverified`) request through
/// the Experiment host and emit one `VRR1`.
///
/// Every refusal is a sealed result with one closed first error, not an
/// `Err`. `projections` must hold the subject's Reducers and a host-bound
/// erasure gate; its State is cleared and rebuilt from the recomputed Events.
///
/// # Errors
/// Returns the host error when the Experiment host cannot start or its
/// Timeline cannot be read, and the codec error when the Snapshot or the
/// result cannot be encoded.
pub fn execute_profile_recomputation_v1(
    input: ProfileRecomputationInputV1<'_>,
    projections: &mut ProjectionRegistry,
) -> Result<VerificationExecutionOutcomeV1, ExperimentError> {
    execute(
        input,
        projections,
        &Leg {
            classes: &[
                ReproducibilityClassV1::ProfileRecomputation,
                ReproducibilityClassV1::LiveUnverified,
            ],
            own_leg: None,
        },
    )
}

/// Execute one `CrossProfileConformance` request: the same closure under
/// `deterministic-local-v1`, then under `deterministic-air-gapped-v1`, each
/// compared with the one expected stream.
///
/// # Errors
/// Returns the first host or codec error of either leg, as
/// [`execute_profile_recomputation_v1`].
pub fn execute_cross_profile_conformance_v1(
    input: CrossProfileConformanceInputV1<'_>,
    projections: &mut ProjectionRegistry,
) -> Result<CrossProfileConformanceOutcomeV1, ExperimentError> {
    let CrossProfileConformanceInputV1 {
        local,
        air_gapped,
        closure,
        expected,
        fixture_digest,
        store_config,
    } = input;
    let leg = |preflight, leg, projections: &mut ProjectionRegistry| {
        execute(
            ProfileRecomputationInputV1 {
                preflight,
                closure,
                expected,
                fixture_digest,
                store_config: store_config.clone(),
            },
            projections,
            &Leg {
                classes: &[ReproducibilityClassV1::CrossProfileConformance],
                own_leg: Some(leg),
            },
        )
    };
    let local_leg = (LOCAL_PROFILE_ID_V1, ExecutionModeV1::Local);
    let air_gapped_leg = (AIR_GAPPED_PROFILE_ID_V1, ExecutionModeV1::AirGapped);
    leg(local, local_leg, &mut *projections).and_then(|local| {
        leg(air_gapped, air_gapped_leg, &mut *projections)
            .map(|air_gapped| CrossProfileConformanceOutcomeV1 { local, air_gapped })
    })
}

/// What one execution admits.
struct Leg {
    classes: &'static [ReproducibilityClassV1],
    /// The EPF1 and the Execution Mode a cross-profile leg must name.
    own_leg: Option<(&'static str, ExecutionModeV1)>,
}

/// Why an execution stopped before its comparison.
enum Halt {
    Refused(Refusal),
    Host(ExperimentError),
}

/// The Events and typed failure of one recomputed run.
struct Recomputed {
    timeline: TimelineId,
    events: Vec<Event>,
    failure: Option<HostFailureV1>,
}

fn execute(
    input: ProfileRecomputationInputV1<'_>,
    projections: &mut ProjectionRegistry,
    leg: &Leg,
) -> Result<VerificationExecutionOutcomeV1, ExperimentError> {
    let ProfileRecomputationInputV1 {
        preflight,
        closure,
        expected,
        fixture_digest,
        store_config,
    } = input;
    let header = ResultHeader::new(
        &preflight,
        closure.subject.map(|member| member.artifact_digest),
        closure.licence,
        fixture_digest,
    );
    let recomputed = match (closure.subject, closure.licence) {
        (Some(member), Some(licence)) if !licence.is_empty() => admit(
            &preflight,
            recomputation_closure_digest_v1(member.artifact_digest, licence),
            leg,
        )
        .map_err(Halt::Refused)
        .and_then(|(admitted, mode)| {
            recompute(member, &preflight, admitted, mode, store_config).map(|run| (admitted, run))
        })
        .and_then(|(admitted, run)| {
            rebuild_projections(
                projections,
                admitted.replay_claim,
                run.timeline,
                &run.events,
            )
            .map_err(Halt::Refused)
            .map(|snapshot| (admitted, run, snapshot))
        }),
        _ => Err(Halt::Refused(refuse_incomplete_closure(preflight))),
    };
    match recomputed {
        Ok((admitted, run, snapshot)) => run
            .stream(&snapshot)
            .and_then(|actual| {
                if admitted.can_claim_exact_verification() {
                    header.compare(admitted.replay_claim, expected, &actual)
                } else {
                    header.unverified(admitted.replay_claim, &actual)
                }
            })
            .map_err(ExperimentError::from),
        Err(Halt::Refused(refusal)) => header.refuse(refusal).map_err(ExperimentError::from),
        Err(Halt::Host(error)) => Err(error),
    }
}

/// The preflight, the class and the host's checks of the request against
/// the named EPF1 (steps 2 to 4); the admitted result and the composition
/// mode of the host.
fn admit(
    preflight: &VerificationPreflightInputV1<'_>,
    closure_digest: [u8; 32],
    leg: &Leg,
) -> Result<(VerificationPreflightResultV1, PluginExecutionModeV1), Refusal> {
    preflight_bound_closure(preflight, closure_digest)
        .and_then(|admitted| admit_class(admitted, leg.classes))
        .and_then(|admitted| {
            let manifest = preflight.manifest;
            let profile = preflight.execution_profile;
            let own_leg = leg.own_leg.is_none_or(|(profile_id, mode)| {
                profile.profile_id == profile_id && manifest.execution_mode == mode
            });
            let mode = host_mode(manifest.execution_mode);
            let network_denied = manifest.network_enabled
                && (!profile.capabilities_and_network.network_allowed
                    || mode == Some(PluginExecutionModeV1::AirGapped));
            match mode {
                Some(mode) if own_leg && !network_denied => Ok((admitted, mode)),
                _ => Err(profile_unsupported()),
            }
        })
}

/// The composition mode of the host of a manifest Execution Mode; only Local
/// and Air-Gapped recompute.
const fn host_mode(mode: ExecutionModeV1) -> Option<PluginExecutionModeV1> {
    match mode {
        ExecutionModeV1::Local => Some(PluginExecutionModeV1::Local),
        ExecutionModeV1::AirGapped => Some(PluginExecutionModeV1::AirGapped),
        ExecutionModeV1::Replay | ExecutionModeV1::Fork => None,
    }
}

const fn profile_unsupported() -> Refusal {
    incompatible(
        SafeErrorCodeV1::ProfileUnsupported,
        VerificationPreflightCoordinateV1::ExecutionProfile,
    )
}

/// The host after `compose`, or the run's typed registration failure.
enum Composed {
    Host(Box<Experiment>),
    Failed(Recomputed),
}

/// Steps 5 to 7: the execution-step budget, the composition and the run.
fn recompute(
    member: RecomputationSubjectMemberV1<'_>,
    preflight: &VerificationPreflightInputV1<'_>,
    admitted: VerificationPreflightResultV1,
    mode: PluginExecutionModeV1,
    store_config: StoreConfig,
) -> Result<Recomputed, Halt> {
    let manifest = preflight.manifest;
    let budgets = preflight.execution_profile.deterministic_budgets;
    let event_cap = manifest
        .resource_limit
        .min(budgets[EVENT_COUNT_BUDGET_SLOT_V1]);
    step_budget(
        member.ticks,
        budgets[EXECUTION_STEPS_BUDGET_SLOT_V1],
        admitted,
    )
    .and_then(|()| compose(member, preflight, mode, store_config))
    .and_then(|composed| match composed {
        Composed::Host(experiment) => run(
            (*experiment).with_resource_limit(manifest.resource_limit),
            member.ticks,
            event_cap,
            admitted,
        ),
        Composed::Failed(failed) => Ok(failed),
    })
}

/// The frozen Ticks must not exceed the EPF1 execution-step budget.
const fn step_budget(
    ticks: u64,
    budget: u64,
    admitted: VerificationPreflightResultV1,
) -> Result<(), Halt> {
    if ticks > budget {
        Err(Halt::Refused(resource_limit_exceeded(
            admitted.replay_claim,
        )))
    } else {
        Ok(())
    }
}

/// Compose the subject on a fresh host in `mode`. The host's own stop
/// condition is the frozen Ticks, whatever host the subject left.
fn compose(
    member: RecomputationSubjectMemberV1<'_>,
    preflight: &VerificationPreflightInputV1<'_>,
    mode: PluginExecutionModeV1,
    store_config: StoreConfig,
) -> Result<Composed, Halt> {
    let config = ExperimentConfig {
        name: EXPERIMENT_NAME.to_owned(),
        stop: StopCondition::MaxTicks(member.ticks),
        store_config,
    };
    let mut experiment = if mode == PluginExecutionModeV1::AirGapped {
        Experiment::new_air_gapped(config)
    } else {
        Experiment::new(config)
    };
    match member
        .subject
        .compose(&mut experiment, preflight.execution_profile)
    {
        Err(RecomputationComposeErrorV1::ProfileUnsupported) => {
            Err(Halt::Refused(profile_unsupported()))
        }
        Err(RecomputationComposeErrorV1::Registration(error)) => Ok(Composed::Failed(Recomputed {
            timeline: TimelineId::new(),
            events: Vec::new(),
            failure: Some(HostFailureV1::from(&ExperimentError::Runtime(error))),
        })),
        Ok(())
            if experiment.execution_mode() != mode || experiment.refused_mode_gated_operation() =>
        {
            Err(Halt::Refused(profile_unsupported()))
        }
        Ok(()) => {
            experiment.config.stop = StopCondition::MaxTicks(member.ticks);
            Ok(Composed::Host(Box::new(experiment)))
        }
    }
}

/// Run the composed host for `ticks` Ticks and cap its Events at
/// `event_cap`.
fn run(
    experiment: Experiment,
    ticks: u64,
    event_cap: u64,
    admitted: VerificationPreflightResultV1,
) -> Result<Recomputed, Halt> {
    experiment
        .start()
        .map_err(Halt::Host)
        .and_then(|mut session| {
            let failure = drive(&mut session, ticks);
            session
                .source_events()
                .map_err(Halt::Host)
                .map(|events| (session.timeline().id(), events, failure))
        })
        .and_then(|(timeline, events, failure)| {
            let exhausted = matches!(
                failure,
                Some(ExperimentError::Runtime(
                    RuntimeError::ResourceExhausted { .. }
                ))
            );
            if exhausted || event_count(&events) > event_cap {
                Err(Halt::Refused(resource_limit_exceeded(
                    admitted.replay_claim,
                )))
            } else {
                Ok(Recomputed {
                    timeline,
                    events,
                    failure: failure.as_ref().map(HostFailureV1::from),
                })
            }
        })
}

/// Step the session exactly `ticks` Ticks; a step error ends the run and is
/// returned.
fn drive(session: &mut ExperimentSession, ticks: u64) -> Option<ExperimentError> {
    (0..ticks).find_map(|_| session.step().err())
}

impl Recomputed {
    fn stream(
        &self,
        snapshot: &HashMap<String, StateRegistry>,
    ) -> Result<AuthoritativeStreamV1, CoreError> {
        let fold_cursor = self.events.last().map_or(0, |event| event.seq.as_u64());
        authoritative_stream(RECOMPUTED_TIMELINE_ID_V1, &self.events, snapshot, |_| {
            [0; 16]
        })
        .map(|mut stream| {
            stream
                .driver_outputs
                .extend(self.failure.iter().map(|failure| {
                    (
                        DriverOutputCoordinateV1 {
                            timeline_id: RECOMPUTED_TIMELINE_ID_V1,
                            fold_cursor,
                            tick: 0,
                            scheduler_position: 0,
                            driver_id: HOST_FAILURE_DRIVER_ID_V1.to_owned(),
                            output_ordinal: 0,
                        },
                        ComparedDriverOutputV1 {
                            outcome: DriverOutcomeV1::TypedFailure(failure.to_be_bytes().to_vec()),
                            numeric_profile_digest: [0; 32],
                            prohibited_operational_input: None,
                        },
                    )
                }));
            stream
        })
    }
}
