//! `ProfileRecomputation` and `CrossProfileConformance` execution through the
//! Experiment host.
//!
//! ADR-062 Revision 8 slice R3 (#1221). [`execute_profile_recomputation_v1`]
//! is the execution step after [`preflight_verification_v1`] for a
//! recomputation: it recomputes the run from the complete frozen
//! closure under the named EPF1 on a fresh [`Experiment`] host, compares the
//! recomputed stream with the expected stream through
//! [`first_divergence_v1`](crate::authoritative_comparison::first_divergence_v1)
//! and emits one sealed `VRR1`.
//! [`execute_cross_profile_conformance_v1`] runs the same closure under
//! `deterministic-local-v1` and `deterministic-air-gapped-v1` and compares
//! both runs with one expected stream.
//!
//! # Order
//!
//! 1. The `ArtifactClosure` members: the recomputation subject and a
//!    non-empty licence member must both be supplied. When either is
//!    missing, the unchanged preflight runs with `Incomplete` closure
//!    evidence, so the refusal is its own `ClosureIncomplete` at
//!    `artifact_closure` (as for `RecordedReplay`).
//! 2. The preflight; its first error becomes the result's first error.
//! 3. The reproducibility class: `ProfileRecomputation` or `LiveUnverified`
//!    for a single run, `CrossProfileConformance` for each leg of a
//!    cross-profile run. Any other class is `IncompatibleProfile` at
//!    `profile_class`.
//! 4. A cross-profile leg must name its own EPF1 (`deterministic-local-v1`
//!    or `deterministic-air-gapped-v1`); another profile is
//!    `IncompatibleProfile` with `ProfileUnsupported` at `execution_profile`.
//! 5. The subject composes its frozen Plugins on a fresh Experiment host
//!    under the named EPF1, with the manifest `resource_limit` as the host's
//!    per-Tick Event budget. A subject that cannot run under the EPF1 is
//!    `IncompatibleProfile` with `ProfileUnsupported` at `execution_profile`.
//!    Every `compose` error currently maps to `ProfileUnsupported`, including
//!    a Plugin registration error that is not about the profile.
//! 6. The host steps the frozen number of Ticks, or until the run is
//!    quiescent. A step error is the run's typed failure and ends the run;
//!    an exhausted host budget is `ResourceLimitExceeded` instead. A
//!    recomputed Timeline with more Events than `resource_limit` is
//!    `ResourceLimitExceeded` too (`resource_limit` counts Events).
//! 7. The recomputed Events are folded into the caller's
//!    [`ProjectionRegistry`] from empty State and its Snapshot is read under
//!    the registry's erasure fence; a denied fence is
//!    `UnverifiableArtifactsMissing`.
//! 8. When the admitted request can claim exact verification, the stream is
//!    compared: `VerifiedExact` or `Diverged` with the `DVR1` digest. A
//!    `LiveUnverified` run (or a non-exact claim) is never compared and
//!    never exact: its `VRR1` keeps its class and claim, records the
//!    recomputed result digest and is `UnverifiableArtifactsMissing` with
//!    `ProvenanceMissing` at `replay_claim` (ADR-062 Revision 8, Q4).
//!
//! # ExecutionProfile enforcement
//!
//! The named EPF1 is enforced by the subject's
//! [`RecomputationSubjectV1::compose`], not by the host: the host passes the
//! EPF1 to the subject and applies only the manifest `resource_limit`.
//! Host-side enforcement of the EPF1, and a finer mapping of `compose`
//! errors than `ProfileUnsupported`, are follow-up #1266. Until then, and
//! until the Sandbox Provider runs Air-Gapped (Q6), results are
//! Local-relaxation engineering evidence.
//!
//! # Recomputed stream
//!
//! The owner decisions for this slice are recorded on the wiki page
//! `ADR-062_R8_Recorded_Replay_Digests`, section 6 (2026-10-30), and its
//! section 2 digest table. The stream uses that accepted `RecordedReplay`
//! digest scheme, documented in [`crate::verification_execution`], with
//! tick 0. A recomputed run mints a
//! fresh Timeline id and fresh Event ids (ULIDs that carry the wall clock), so
//! those identifiers are operational: the stream is addressed by
//! [`RECOMPUTED_TIMELINE_ID_V1`] and every Event identity digest covers 16
//! zero bytes in place of the Event id. Entity ids, Event types, schema
//! versions, payloads, Timeline Order and the Projection Snapshot are
//! authoritative.
//!
//! A typed failure is one Driver output at the host coordinate: Timeline
//! [`RECOMPUTED_TIMELINE_ID_V1`], the Fold Cursor of the last committed Event,
//! tick 0, scheduler position 0, Driver id [`HOST_FAILURE_DRIVER_ID_V1`] and
//! output ordinal 0. Its canonical bytes are its closed
//! [`HostFailureCodeV1`] as a big-endian `u16` (two bytes), never error
//! text; its numeric profile digest is 32 zero bytes. The typed failure is
//! part of the `authoritative_result_digest`. A typed failure the expected
//! stream also holds verifies as exact (Q4).
//!
//! The store configuration, wall clock and logging are operational: they are
//! not inputs to the stream, so they cannot change the `VRR1`.

use std::collections::HashMap;

use pos_conformance::{
    preflight_verification_v1, ExecutionProfileV1, ReproducibilityClassV1, SafeErrorCodeV1,
    VerificationPreflightCoordinateV1, VerificationPreflightInputV1, VerificationPreflightResultV1,
};
use pos_core::{CoreError, Event, StateRegistry, TimelineId};
use pos_runtime::RuntimeError;
use pos_state::ProjectionRegistry;
use pos_store::StoreConfig;

use crate::authoritative_comparison::{
    AuthoritativeStreamV1, ComparedDriverOutputV1, DriverOutcomeV1, DriverOutputCoordinateV1,
};
use crate::verification_execution::{
    admit_class, authoritative_stream, event_count, incompatible, preflight_refusal,
    rebuild_projections, refuse_incomplete_closure, resource_limit_exceeded, Refusal, ResultHeader,
    VerificationExecutionOutcomeV1,
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

const EXPERIMENT_NAME: &str = "profile-recomputation";

/// The closed code of a host typed failure, one per [`ExperimentError`]
/// variant. Its canonical bytes are the code as a big-endian `u16`.
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

impl HostFailureCodeV1 {
    /// The canonical bytes of the code: a big-endian `u16`.
    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }
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

/// The frozen subject of a recomputation: the Plugins, Reducers and Drivers
/// of the run, composed from the closure.
pub trait RecomputationSubjectV1 {
    /// Register the frozen composition on a fresh Experiment host that runs
    /// under `profile`.
    ///
    /// # Errors
    /// Returns the runtime error when the subject cannot run under `profile`
    /// or its Plugins cannot be registered; the run is then
    /// `IncompatibleProfile`.
    fn compose(
        &self,
        experiment: &mut Experiment,
        profile: &ExecutionProfileV1,
    ) -> Result<(), RuntimeError>;
}

/// The subject member of a recomputation closure.
///
/// The closure-digest binding of `artifact_digest` to the request's
/// `artifact_closure_digest` is deferred to ADR-062 Revision 8 slice R4.
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
            profile_id: None,
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
    let leg = |preflight, profile_id, projections: &mut ProjectionRegistry| {
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
                profile_id: Some(profile_id),
            },
        )
    };
    leg(local, LOCAL_PROFILE_ID_V1, &mut *projections).and_then(|local| {
        leg(air_gapped, AIR_GAPPED_PROFILE_ID_V1, &mut *projections)
            .map(|air_gapped| CrossProfileConformanceOutcomeV1 { local, air_gapped })
    })
}

/// What one execution admits.
struct Leg {
    classes: &'static [ReproducibilityClassV1],
    profile_id: Option<&'static str>,
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
    failure: Option<HostFailureCodeV1>,
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
        (Some(member), Some(licence)) if !licence.is_empty() => admit(&preflight, leg)
            .map_err(Halt::Refused)
            .and_then(|admitted| {
                recompute(member, &preflight, admitted, store_config).map(|run| (admitted, run))
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

fn admit(
    preflight: &VerificationPreflightInputV1<'_>,
    leg: &Leg,
) -> Result<VerificationPreflightResultV1, Refusal> {
    let declared_claim = preflight.manifest.replay_claim;
    preflight_verification_v1(preflight)
        .map_err(|error| preflight_refusal(error, declared_claim))
        .and_then(|admitted| admit_class(admitted, leg.classes))
        .and_then(|admitted| {
            if leg
                .profile_id
                .is_none_or(|profile_id| preflight.execution_profile.profile_id == profile_id)
            {
                Ok(admitted)
            } else {
                Err(profile_unsupported())
            }
        })
}

const fn profile_unsupported() -> Refusal {
    incompatible(
        SafeErrorCodeV1::ProfileUnsupported,
        VerificationPreflightCoordinateV1::ExecutionProfile,
    )
}

fn recompute(
    member: RecomputationSubjectMemberV1<'_>,
    preflight: &VerificationPreflightInputV1<'_>,
    admitted: VerificationPreflightResultV1,
    store_config: StoreConfig,
) -> Result<Recomputed, Halt> {
    let resource_limit = preflight.manifest.resource_limit;
    let mut experiment = Experiment::new(ExperimentConfig {
        name: EXPERIMENT_NAME.to_owned(),
        stop: StopCondition::MaxTicks(member.ticks),
        store_config,
    })
    .with_resource_limit(resource_limit);
    member
        .subject
        .compose(&mut experiment, preflight.execution_profile)
        .map_err(|_| Halt::Refused(profile_unsupported()))
        .and_then(|()| experiment.start().map_err(Halt::Host))
        .and_then(|mut session| {
            let failure = drive(&mut session);
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
            if exhausted || event_count(&events) > resource_limit {
                Err(Halt::Refused(resource_limit_exceeded(
                    admitted.replay_claim,
                )))
            } else {
                Ok(Recomputed {
                    timeline,
                    events,
                    failure: failure.as_ref().map(HostFailureCodeV1::from),
                })
            }
        })
}

/// Step the session until it stops or is quiescent; a step error ends the
/// run and is returned.
fn drive(session: &mut ExperimentSession) -> Option<ExperimentError> {
    loop {
        match session.step() {
            Ok(true) => {}
            Ok(false) => return None,
            Err(error) => return Some(error),
        }
    }
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
