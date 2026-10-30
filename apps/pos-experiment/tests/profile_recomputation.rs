#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Public-interface tests for the ADR-062 Revision 8 slice R3
//! `ProfileRecomputation` and `CrossProfileConformance` execution step
//! (#1221): PRF-001, PRF-002, DIV-001, LIVE-001 and SEC-001, a missing
//! closure member, an incompatible profile and operational variation.
//!
//! Expected streams are hand-derived from the frozen subject's script (Q3):
//! the digests below follow the documented `verification_execution` and
//! `profile_recomputation` conventions and do not call the execution step.

use pos_conformance::{
    draft_execution_profile_bytes_v1, draft_trust_policy_snapshot_bytes_v1,
    ArtifactClosureStatusV1, ArtifactRevocationStatusV1, DivergenceLocationKindV1,
    DivergenceMismatchKindV1, DivergenceReportV1, ExecutionModeV1, ExecutionProfileV1,
    ProfileSupportStatusV1, ReplayClaimV1, ReproManifestV1, ReproVerificationRequestV1,
    ReproducibilityClassV1, SafeErrorCodeV1, TrustPolicySnapshotV1, TrustRootStatusV1,
    TrustSignatureStatusV1, TrustSnapshotContinuityV1, VerificationOutcomeV1,
    VerificationPreflightEvidenceV1, VerificationPreflightInputV1, VerificationResultV1,
};
use pos_core::{
    clock::WallTime,
    event::{CanonicalBytes, EventDraft, Kind},
    ids::{EntityId, PluginId, TimelineId},
    plugin::{Capability, Plugin},
    ErasureContainmentGateV1, Event, Reducer, State,
};
use pos_experiment::authoritative_comparison::{
    AuthoritativeStreamV1, CheckpointDigestV1, ComparedDriverOutputV1, ComparedEventV1,
    DriverOutcomeV1, DriverOutputCoordinateV1, TickBoundaryCoordinateV1, TimelinePositionV1,
};
use pos_experiment::profile_recomputation::{
    execute_cross_profile_conformance_v1, execute_profile_recomputation_v1,
    CrossProfileConformanceInputV1, CrossProfileConformanceOutcomeV1, HostFailureCodeV1,
    ProfileRecomputationInputV1, RecomputationClosureV1, RecomputationSubjectMemberV1,
    RecomputationSubjectV1, AIR_GAPPED_PROFILE_ID_V1, HOST_FAILURE_DRIVER_ID_V1,
    LOCAL_PROFILE_ID_V1, RECOMPUTED_TIMELINE_ID_V1,
};
use pos_experiment::verification_execution::VerificationExecutionOutcomeV1;
use pos_experiment::{Experiment, ExperimentError};
use pos_runtime::{
    Driver, HumanActionAdmissionErrorV1, ManifestRegistrationErrorV1, ManifestRosterBuildErrorV1,
    ObservationView, RuntimeError, StepOutput,
};
use pos_state::ProjectionRegistry;
use pos_store::StoreConfig;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const EVENT_TYPE: &str = "recompute.tick";
const PLUGIN_NAME: &str = "counter";
const REDUCER: &str = "counter";
const LICENCE: &[u8] = b"SPDX-License-Identifier: MIT\n";
const SUBJECT_DIGEST: [u8; 32] = [0xd1; 32];
const FIXTURE_DIGEST: [u8; 32] = [0xf1; 32];
const RESOURCE_LIMIT: u64 = 16;
const SECRET_DENIED: &str = "secret read denied";
/// The closed host-failure code of a runtime failure (wiki section 6).
const RUNTIME_FAILURE_CODE: u16 = 1;

/// What the subject's Driver emits at each Tick.
#[derive(Clone, Copy)]
enum Script {
    /// One Event per Tick whose payload is the Tick number.
    Count,
    /// One Event at the first Tick, then a typed security failure.
    DeniedSecret,
    /// Three Events in one Tick.
    Burst,
}

/// The operational environment of one run; none of it is authoritative.
#[derive(Clone)]
struct Operational {
    wall_clock_micros: u64,
    log_level: u8,
    log: Arc<Mutex<Vec<String>>>,
}

impl Operational {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn new(wall_clock_micros: u64, log_level: u8) -> Self {
        Self {
            wall_clock_micros,
            log_level,
            log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn log_lines(&self) -> usize {
        self.log.lock().map_or(0, |log| log.len())
    }
}

/// The frozen recomputation subject: one Plugin with one scripted Driver.
struct Subject {
    script: Script,
    entity: EntityId,
    operational: Operational,
    refused_profile: Option<&'static str>,
}

impl Subject {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn new(script: Script) -> Self {
        Self {
            script,
            entity: entity(),
            operational: Operational::new(1_000, 0),
            refused_profile: None,
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    const fn member(&self, ticks: u64) -> RecomputationSubjectMemberV1<'_> {
        RecomputationSubjectMemberV1 {
            subject: self,
            artifact_digest: SUBJECT_DIGEST,
            ticks,
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    const fn closure(&self, ticks: u64) -> RecomputationClosureV1<'_> {
        RecomputationClosureV1 {
            subject: Some(self.member(ticks)),
            licence: Some(LICENCE),
        }
    }
}

impl RecomputationSubjectV1 for Subject {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn compose(
        &self,
        experiment: &mut Experiment,
        profile: &ExecutionProfileV1,
    ) -> Result<(), RuntimeError> {
        if self.refused_profile == Some(profile.profile_id.as_str()) {
            return Err(RuntimeError::CapabilityMismatch {
                name: PLUGIN_NAME.to_owned(),
                reason: "the subject needs a network capability".to_owned(),
            });
        }
        experiment.register_generated(
            &CounterPlugin {
                id: PluginId::new(),
            },
            None,
            Some(Box::new(ScriptDriver {
                script: self.script,
                entity: self.entity,
                tick: 0,
                operational: self.operational.clone(),
            })),
        )
    }
}

struct CounterPlugin {
    id: PluginId,
}

impl Plugin for CounterPlugin {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn id(&self) -> PluginId {
        self.id
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn name(&self) -> &'static str {
        PLUGIN_NAME
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(EVENT_TYPE)],
            owned_entity_kinds: Vec::new(),
            has_driver: true,
            has_reducer: false,
        }
    }
}

struct ScriptDriver {
    script: Script,
    entity: EntityId,
    tick: u8,
    operational: Operational,
}

impl ScriptDriver {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn draft(&self, payload: u8) -> EventDraft {
        EventDraft::new(
            self.entity,
            Kind::new(EVENT_TYPE),
            CanonicalBytes::from_vec(vec![payload]),
        )
        .with_wall_time(WallTime::from_micros(
            self.operational.wall_clock_micros + u64::from(payload),
        ))
    }
}

impl Driver for ScriptDriver {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn name(&self) -> &'static str {
        PLUGIN_NAME
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        self.tick += 1;
        if self.operational.log_level > 0 {
            if let Ok(mut log) = self.operational.log.lock() {
                log.push(format!("tick {}", self.tick));
            }
        }
        match self.script {
            Script::DeniedSecret if self.tick > 1 => Err(secret_denied()),
            Script::Count | Script::DeniedSecret => {
                Ok(StepOutput::new(vec![self.draft(self.tick)]))
            }
            Script::Burst => Ok(StepOutput::new(vec![
                self.draft(1),
                self.draft(2),
                self.draft(3),
            ])),
        }
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn secret_denied() -> RuntimeError {
    RuntimeError::CapabilityMismatch {
        name: PLUGIN_NAME.to_owned(),
        reason: SECRET_DENIED.to_owned(),
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn entity() -> EntityId {
    EntityId::from_ulid(ulid::Ulid::from(0x0123_4567_89ab_cdef_u128))
}

/// Counts every Reducer-visible Event per entity.
struct CountReducer;

impl Reducer for CountReducer {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn initial(&self) -> State {
        State::new()
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn apply(&self, state: &mut State, _event: &Event) {
        let count = state
            .fields
            .get("count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        state.set("count", serde_json::json!(count + 1));
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn projections() -> ProjectionRegistry {
    let mut projections = ProjectionRegistry::new()
        .with_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()));
    projections.register(REDUCER, Box::new(CountReducer));
    projections
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn digest(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    for part in parts {
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

/// The expected stream, hand-derived from the subject's script: one Event
/// per payload at tick 0 addressed by the recomputed Timeline id with a
/// zero Event id, the count checkpoint and an optional typed failure.
#[cfg_attr(coverage_nightly, coverage(off))]
fn expected(payloads: &[u8], failure: Option<u16>) -> TestResult<AuthoritativeStreamV1> {
    let timeline_id = RECOMPUTED_TIMELINE_ID_V1;
    let entity = entity();
    let mut events = BTreeMap::new();
    for (seq, &payload) in (1_u64..).zip(payloads) {
        let identity = digest(
            b"PiglorOS.RecordedReplayEventIdentity.v1",
            &[&[0; 16], &entity.inner().to_bytes(), EVENT_TYPE.as_bytes()],
        );
        let schema = digest(
            b"PiglorOS.RecordedReplayEventSchema.v1",
            &[EVENT_TYPE.as_bytes(), &[0], &1_u32.to_be_bytes()],
        );
        events.insert(
            TimelinePositionV1 { timeline_id, seq },
            ComparedEventV1 {
                tick: 0,
                identity,
                schema,
                payload: vec![payload],
            },
        );
    }
    let count = u64::try_from(payloads.len())?;
    let mut states = serde_json::Map::new();
    if count > 0 {
        states.insert(
            entity.inner().to_string(),
            serde_json::json!({"fields": {"count": count}}),
        );
    }
    let mut snapshot = serde_json::Map::new();
    snapshot.insert(REDUCER.to_owned(), serde_json::json!({"states": states}));
    let bytes = pos_crypto::canonical::encode(&snapshot)?;
    let checkpoint = CheckpointDigestV1 {
        digest: digest(b"PiglorOS.RecordedReplayCheckpoint.v1", &[bytes.as_slice()]),
        size: u64::try_from(bytes.as_slice().len())?,
    };
    let coordinate = TickBoundaryCoordinateV1 {
        timeline_id,
        fold_cursor: count,
        tick: 0,
    };
    let driver_outputs = failure
        .map(|failure| {
            (
                DriverOutputCoordinateV1 {
                    timeline_id,
                    fold_cursor: count,
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
        })
        .into_iter()
        .collect();
    Ok(AuthoritativeStreamV1 {
        events,
        checkpoints: BTreeMap::from([(coordinate, checkpoint)]),
        driver_outputs,
        ..AuthoritativeStreamV1::default()
    })
}

/// The documented authoritative result digest of a stream.
#[cfg_attr(coverage_nightly, coverage(off))]
fn result_digest(stream: &AuthoritativeStreamV1) -> TestResult<[u8; 32]> {
    let mut parts: Vec<Vec<u8>> = vec![u64::try_from(stream.events.len())?.to_be_bytes().to_vec()];
    for (position, event) in &stream.events {
        parts.push(position.timeline_id.to_vec());
        parts.push(position.seq.to_be_bytes().to_vec());
        parts.push(event.identity.to_vec());
        parts.push(event.schema.to_vec());
        parts.push(blake3::hash(&event.payload).as_bytes().to_vec());
    }
    parts.push(
        u64::try_from(stream.checkpoints.len())?
            .to_be_bytes()
            .to_vec(),
    );
    for (coordinate, checkpoint) in &stream.checkpoints {
        parts.push(coordinate.timeline_id.to_vec());
        parts.push(coordinate.fold_cursor.to_be_bytes().to_vec());
        parts.push(coordinate.tick.to_be_bytes().to_vec());
        parts.push(checkpoint.digest.to_vec());
        parts.push(checkpoint.size.to_be_bytes().to_vec());
    }
    parts.push(
        u64::try_from(stream.driver_outputs.len())?
            .to_be_bytes()
            .to_vec(),
    );
    for (coordinate, output) in &stream.driver_outputs {
        parts.push(coordinate.timeline_id.to_vec());
        parts.push(coordinate.fold_cursor.to_be_bytes().to_vec());
        parts.push(coordinate.tick.to_be_bytes().to_vec());
        parts.push(coordinate.scheduler_position.to_be_bytes().to_vec());
        parts.push(
            u64::try_from(coordinate.driver_id.len())?
                .to_be_bytes()
                .to_vec(),
        );
        parts.push(coordinate.driver_id.as_bytes().to_vec());
        parts.push(coordinate.output_ordinal.to_be_bytes().to_vec());
        let (DriverOutcomeV1::Output(bytes) | DriverOutcomeV1::TypedFailure(bytes)) =
            &output.outcome;
        parts.push(bytes.clone());
    }
    let parts: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    Ok(digest(b"PiglorOS.RecordedReplayResult.v1", &parts))
}

/// A preflight input that admits, as in the #326 public tests.
struct Fixture {
    request: ReproVerificationRequestV1,
    canonical_request_bytes: Vec<u8>,
    canonical_request_digest: [u8; 32],
    manifest: ReproManifestV1,
    execution_profile: ExecutionProfileV1,
    trust_policy_snapshot: TrustPolicySnapshotV1,
    evidence: VerificationPreflightEvidenceV1,
}

impl Fixture {
    /// A request of `class` under the draft EPF1 `source`, renamed to
    /// `profile_id` and restricted to `class`.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn new(class: ReproducibilityClassV1, source: &str, profile_id: &str) -> TestResult<Self> {
        let mut execution_profile =
            ExecutionProfileV1::from_canonical_cbor(&draft_execution_profile_bytes_v1(source)?)?;
        let trust_policy_snapshot =
            TrustPolicySnapshotV1::from_canonical_cbor(&draft_trust_policy_snapshot_bytes_v1()?)?;
        profile_id.clone_into(&mut execution_profile.profile_id);
        execution_profile.reproducibility_classes = vec![class];
        execution_profile.profile_digest = execution_profile.digest();
        let profile_digest = execution_profile.profile_digest;
        let trust_digest = trust_policy_snapshot.digest()?;
        let mode = if source == AIR_GAPPED_PROFILE_ID_V1 {
            ExecutionModeV1::AirGapped
        } else {
            ExecutionModeV1::Local
        };
        let manifest = ReproManifestV1 {
            format_version: 1,
            input_digest: [10; 32],
            execution_mode: mode,
            fork_cut_seq: None,
            seed: 11,
            resource_limit: RESOURCE_LIMIT,
            network_enabled: false,
            reproducibility_class: class,
            execution_profile: execution_profile.profile_id.clone(),
            execution_profile_digest: profile_digest,
            trust_policy_snapshot_digest: trust_digest,
            artifact_closure_digest: [8; 32],
            evaluator_digest: [9; 32],
            replay_claim: ReplayClaimV1::Exact,
            plugin_versions: BTreeMap::new(),
            scenario_room_digest: [13; 32],
            scheduler_digest: [14; 32],
            budget_digest: [15; 32],
        };
        let request = ReproVerificationRequestV1 {
            request_digest: [1; 32],
            manifest_digest: manifest_digest(&manifest)?,
            reproducibility_class: class,
            execution_profile_digest: profile_digest,
            trust_policy_snapshot_digest: trust_digest,
            artifact_closure_digest: [8; 32],
            evaluator_digest: [9; 32],
            report_bytes_limit: 1024,
        };
        let canonical_request_bytes = request.to_canonical_cbor()?;
        let canonical_request_digest = request.digest()?;
        Ok(Self {
            request,
            canonical_request_bytes,
            canonical_request_digest,
            manifest,
            execution_profile,
            trust_policy_snapshot,
            evidence: VerificationPreflightEvidenceV1 {
                trust_root: TrustRootStatusV1::Known,
                trust_signature: TrustSignatureStatusV1::Valid,
                artifact_revocation: ArtifactRevocationStatusV1::Clear,
                trust_continuity: TrustSnapshotContinuityV1 {
                    previous_epoch: None,
                    previous_snapshot_digest: None,
                },
                artifact_closure: ArtifactClosureStatusV1::Complete,
                profile_support: ProfileSupportStatusV1::Supported,
            },
        })
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn recomputation() -> TestResult<Self> {
        Self::new(
            ReproducibilityClassV1::ProfileRecomputation,
            LOCAL_PROFILE_ID_V1,
            LOCAL_PROFILE_ID_V1,
        )
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cross(profile_id: &str) -> TestResult<Self> {
        Self::new(
            ReproducibilityClassV1::CrossProfileConformance,
            profile_id,
            profile_id,
        )
    }

    /// Re-bind RVR1 to the edited manifest.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn refresh_manifest_binding(&mut self) -> TestResult {
        self.request.manifest_digest = manifest_digest(&self.manifest)?;
        self.canonical_request_bytes = self.request.to_canonical_cbor()?;
        self.canonical_request_digest = self.request.digest()?;
        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn preflight(&self) -> VerificationPreflightInputV1<'_> {
        VerificationPreflightInputV1 {
            request: &self.request,
            canonical_request_bytes: &self.canonical_request_bytes,
            canonical_request_digest: self.canonical_request_digest,
            manifest: &self.manifest,
            execution_profile: &self.execution_profile,
            trust_policy_snapshot: &self.trust_policy_snapshot,
            evidence: self.evidence.clone(),
        }
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn manifest_digest(manifest: &ReproManifestV1) -> TestResult<[u8; 32]> {
    let bytes = pos_crypto::canonical::encode(manifest)?;
    let mut input = b"PiglorOS.ReproManifest.v1\0".to_vec();
    input.extend_from_slice(bytes.as_slice());
    Ok(*blake3::hash(&input).as_bytes())
}

/// Check that a result is a valid `VRR1` bound to the fixture's request.
#[cfg_attr(coverage_nightly, coverage(off))]
fn assert_bound(outcome: &VerificationExecutionOutcomeV1, fixture: &Fixture) -> TestResult {
    let decoded = VerificationResultV1::from_canonical_cbor(&outcome.result.to_canonical_cbor()?)?;
    assert_eq!(decoded, outcome.result);
    assert_eq!(
        outcome.result.request_digest,
        fixture.canonical_request_digest
    );
    assert_eq!(
        outcome.result.manifest_digest,
        fixture.request.manifest_digest
    );
    assert_eq!(
        outcome.result.execution_profile_digest,
        fixture.execution_profile.profile_digest
    );
    assert_eq!(
        outcome.result.reproducibility_class,
        fixture.request.reproducibility_class
    );
    Ok(())
}

/// Run one single-profile execution and check its `VRR1` binding.
#[cfg_attr(coverage_nightly, coverage(off))]
fn run(
    fixture: &Fixture,
    closure: RecomputationClosureV1<'_>,
    expected: &AuthoritativeStreamV1,
    store_config: StoreConfig,
) -> TestResult<VerificationExecutionOutcomeV1> {
    let outcome = execute_profile_recomputation_v1(
        ProfileRecomputationInputV1 {
            preflight: fixture.preflight(),
            closure,
            expected,
            fixture_digest: Some(FIXTURE_DIGEST),
            store_config,
        },
        &mut projections(),
    )?;
    assert_bound(&outcome, fixture)?;
    assert_eq!(outcome.result.fixture_digest, Some(FIXTURE_DIGEST));
    Ok(outcome)
}

/// Run one cross-profile execution and check both `VRR1` bindings.
#[cfg_attr(coverage_nightly, coverage(off))]
fn run_cross(
    local: &Fixture,
    air_gapped: &Fixture,
    closure: RecomputationClosureV1<'_>,
    expected: &AuthoritativeStreamV1,
) -> TestResult<CrossProfileConformanceOutcomeV1> {
    let outcome = execute_cross_profile_conformance_v1(
        CrossProfileConformanceInputV1 {
            local: local.preflight(),
            air_gapped: air_gapped.preflight(),
            closure,
            expected,
            fixture_digest: Some(FIXTURE_DIGEST),
            store_config: StoreConfig::Memory,
        },
        &mut projections(),
    )?;
    assert_bound(&outcome.local, local)?;
    assert_bound(&outcome.air_gapped, air_gapped)?;
    Ok(outcome)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn assert_exact(
    outcome: &VerificationExecutionOutcomeV1,
    expected: &AuthoritativeStreamV1,
) -> TestResult {
    assert_eq!(
        outcome.result.verification_outcome,
        VerificationOutcomeV1::VerifiedExact
    );
    assert_eq!(outcome.result.replay_claim, ReplayClaimV1::Exact);
    assert_eq!(
        outcome.result.authoritative_result_digest,
        Some(result_digest(expected)?)
    );
    assert_eq!(outcome.result.divergence_report_digest, None);
    assert_eq!(outcome.result.first_error, None);
    assert_eq!(outcome.result.checked_artifact_count, 2);
    assert_eq!(outcome.divergence, None);
    Ok(())
}

/// Assert a refusal with one closed first error and no comparison.
#[cfg_attr(coverage_nightly, coverage(off))]
fn assert_refused(
    outcome: &VerificationExecutionOutcomeV1,
    expected: (VerificationOutcomeV1, ReplayClaimV1, SafeErrorCodeV1),
    coordinate: Option<&str>,
) {
    let (verification_outcome, replay_claim, code) = expected;
    assert_eq!(outcome.result.verification_outcome, verification_outcome);
    assert_eq!(outcome.result.replay_claim, replay_claim);
    assert_eq!(outcome.result.authoritative_result_digest, None);
    assert_eq!(outcome.result.divergence_report_digest, None);
    assert_eq!(outcome.divergence, None);
    let error = outcome.result.first_error.as_ref();
    assert_eq!(error.map(|error| error.code), Some(code));
    assert_eq!(
        error.and_then(|error| error.canonical_coordinate.clone()),
        coordinate.map(|coordinate| coordinate.as_bytes().to_vec())
    );
}

const INCOMPATIBLE: (VerificationOutcomeV1, ReplayClaimV1, SafeErrorCodeV1) = (
    VerificationOutcomeV1::IncompatibleProfile,
    ReplayClaimV1::IncompatibleProfile,
    SafeErrorCodeV1::ProfileUnsupported,
);

const RESOURCE: (VerificationOutcomeV1, ReplayClaimV1, SafeErrorCodeV1) = (
    VerificationOutcomeV1::ResourceLimitExceeded,
    ReplayClaimV1::Exact,
    SafeErrorCodeV1::ResourceLimitExceeded,
);

#[test]
fn prf_001_profile_recomputation_is_verified_exact() -> TestResult {
    let subject = Subject::new(Script::Count);
    let fixture = Fixture::recomputation()?;
    let expected = expected(&[1, 2], None)?;
    let outcome = run(&fixture, subject.closure(2), &expected, StoreConfig::Memory)?;
    assert_exact(&outcome, &expected)?;

    // A second recomputation of the same closure gives the identical result.
    let again = run(&fixture, subject.closure(2), &expected, StoreConfig::Memory)?;
    assert_eq!(again, outcome);
    Ok(())
}

#[test]
fn prf_002_local_and_air_gapped_are_verified_exact_against_one_record() -> TestResult {
    let subject = Subject::new(Script::Count);
    let local = Fixture::cross(LOCAL_PROFILE_ID_V1)?;
    let air_gapped = Fixture::cross(AIR_GAPPED_PROFILE_ID_V1)?;
    let expected = expected(&[1, 2, 3], None)?;
    let outcome = run_cross(&local, &air_gapped, subject.closure(3), &expected)?;
    assert_exact(&outcome.local, &expected)?;
    assert_exact(&outcome.air_gapped, &expected)?;
    assert_eq!(
        outcome.local.result.authoritative_result_digest,
        outcome.air_gapped.result.authoritative_result_digest
    );
    assert_ne!(
        outcome.local.result.execution_profile_digest,
        outcome.air_gapped.result.execution_profile_digest
    );
    Ok(())
}

#[test]
fn div_001_a_recomputation_that_differs_is_diverged_with_the_r1_dvr1() -> TestResult {
    let subject = Subject::new(Script::Count);
    let fixture = Fixture::recomputation()?;
    let expected = expected(&[1, 9], None)?;
    let outcome = run(&fixture, subject.closure(2), &expected, StoreConfig::Memory)?;
    assert_eq!(
        outcome.result.verification_outcome,
        VerificationOutcomeV1::Diverged
    );
    assert_eq!(outcome.result.replay_claim, ReplayClaimV1::Exact);
    assert_eq!(outcome.result.first_error, None);
    let report = outcome.divergence.as_ref().ok_or("diverged without DVR1")?;
    assert_eq!(
        outcome.result.divergence_report_digest,
        Some(report.report_digest)
    );
    assert_eq!(report.location_kind, DivergenceLocationKindV1::TimelineSeq);
    assert_eq!(
        report.mismatch_kind,
        DivergenceMismatchKindV1::CanonicalBytes
    );
    assert_eq!(report.timeline_or_worldcut_id, RECOMPUTED_TIMELINE_ID_V1);
    assert_eq!(report.timeline_seq_or_cut_ordinal, 2);
    assert_eq!(report.tick, 0);
    assert_eq!(
        report.reproducibility_class,
        ReproducibilityClassV1::ProfileRecomputation
    );
    assert_eq!(report.request_digest, fixture.canonical_request_digest);
    assert_eq!(report.fixture_digest, Some(FIXTURE_DIGEST));
    assert_eq!(report.expected.digest, Some(*blake3::hash(&[9]).as_bytes()));
    assert_eq!(report.actual.digest, Some(*blake3::hash(&[2]).as_bytes()));
    assert_eq!(report.follow_on_counts, Vec::new());
    let decoded = DivergenceReportV1::from_canonical_cbor(&report.to_canonical_cbor()?)?;
    assert_eq!(&decoded, report);
    // The recomputed stream, not the expected one, is the authoritative result.
    assert_eq!(
        outcome.result.authoritative_result_digest,
        Some(result_digest(&self::expected(&[1, 2], None)?)?)
    );
    Ok(())
}

#[test]
fn live_001_live_unverified_is_never_verified_exact() -> TestResult {
    let subject = Subject::new(Script::Count);
    let mut fixture = Fixture::new(
        ReproducibilityClassV1::LiveUnverified,
        LOCAL_PROFILE_ID_V1,
        "live-local-v1",
    )?;
    fixture.manifest.replay_claim = ReplayClaimV1::StructuralOnly;
    fixture.refresh_manifest_binding()?;
    // Even a stream equal to the expected record is not claimed exact.
    let expected = expected(&[1, 2], None)?;
    let outcome = run(&fixture, subject.closure(2), &expected, StoreConfig::Memory)?;
    assert_eq!(
        outcome.result.reproducibility_class,
        ReproducibilityClassV1::LiveUnverified
    );
    assert_eq!(
        outcome.result.verification_outcome,
        VerificationOutcomeV1::UnverifiableArtifactsMissing
    );
    assert_ne!(
        outcome.result.verification_outcome,
        VerificationOutcomeV1::VerifiedExact
    );
    assert_eq!(outcome.result.replay_claim, ReplayClaimV1::StructuralOnly);
    assert_eq!(
        outcome.result.authoritative_result_digest,
        Some(result_digest(&expected)?)
    );
    assert_eq!(outcome.result.divergence_report_digest, None);
    assert_eq!(outcome.divergence, None);
    let error = outcome
        .result
        .first_error
        .as_ref()
        .ok_or("no first error")?;
    assert_eq!(error.code, SafeErrorCodeV1::ProvenanceMissing);
    assert_eq!(
        error.canonical_coordinate.as_deref(),
        Some(b"replay_claim".as_slice())
    );

    // An exact claim for a live run is refused by the preflight.
    fixture.manifest.replay_claim = ReplayClaimV1::Exact;
    fixture.refresh_manifest_binding()?;
    let outcome = run(&fixture, subject.closure(2), &expected, StoreConfig::Memory)?;
    assert_refused(
        &outcome,
        (
            VerificationOutcomeV1::IncompatibleProfile,
            ReplayClaimV1::IncompatibleProfile,
            SafeErrorCodeV1::ProfileClassMismatch,
        ),
        Some("replay_claim"),
    );
    Ok(())
}

#[test]
fn sec_001_an_expected_typed_failure_is_verified_exact_in_both_profiles() -> TestResult {
    let subject = Subject::new(Script::DeniedSecret);
    let expected = expected(&[1], Some(RUNTIME_FAILURE_CODE))?;

    let fixture = Fixture::recomputation()?;
    let outcome = run(&fixture, subject.closure(3), &expected, StoreConfig::Memory)?;
    assert_exact(&outcome, &expected)?;

    let local = Fixture::cross(LOCAL_PROFILE_ID_V1)?;
    let air_gapped = Fixture::cross(AIR_GAPPED_PROFILE_ID_V1)?;
    let outcome = run_cross(&local, &air_gapped, subject.closure(3), &expected)?;
    assert_exact(&outcome.local, &expected)?;
    assert_exact(&outcome.air_gapped, &expected)?;

    // A run that omits the expected typed failure diverges at it.
    let without_failure = Subject::new(Script::Count);
    let outcome = run(
        &fixture,
        without_failure.closure(1),
        &expected,
        StoreConfig::Memory,
    )?;
    let report = outcome.divergence.as_ref().ok_or("diverged without DVR1")?;
    assert_eq!(report.location_kind, DivergenceLocationKindV1::DriverOutput);
    assert_eq!(report.mismatch_kind, DivergenceMismatchKindV1::TypedFailure);
    assert_eq!(
        report.driver_or_plugin_id.as_deref(),
        Some(HOST_FAILURE_DRIVER_ID_V1)
    );
    Ok(())
}

#[test]
fn a_missing_closure_member_is_refused_at_artifact_closure() -> TestResult {
    let subject = Subject::new(Script::Count);
    let fixture = Fixture::recomputation()?;
    let expected = expected(&[1, 2], None)?;
    let missing = (
        VerificationOutcomeV1::UnverifiableArtifactsMissing,
        ReplayClaimV1::UnverifiableArtifactsMissing,
        SafeErrorCodeV1::ClosureIncomplete,
    );
    for closure in [
        RecomputationClosureV1 {
            subject: None,
            ..subject.closure(2)
        },
        RecomputationClosureV1 {
            licence: None,
            ..subject.closure(2)
        },
        RecomputationClosureV1 {
            licence: Some(b"".as_slice()),
            ..subject.closure(2)
        },
    ] {
        let outcome = run(&fixture, closure, &expected, StoreConfig::Memory)?;
        assert_refused(&outcome, missing, Some("artifact_closure"));
        // Only the member that is present is counted.
        assert_eq!(outcome.result.checked_artifact_count, 1);
    }

    // Both legs of a cross-profile run are refused the same way.
    let local = Fixture::cross(LOCAL_PROFILE_ID_V1)?;
    let air_gapped = Fixture::cross(AIR_GAPPED_PROFILE_ID_V1)?;
    let closure = RecomputationClosureV1 {
        subject: None,
        ..subject.closure(2)
    };
    let outcome = run_cross(&local, &air_gapped, closure, &expected)?;
    assert_refused(&outcome.local, missing, Some("artifact_closure"));
    assert_refused(&outcome.air_gapped, missing, Some("artifact_closure"));
    Ok(())
}

#[test]
fn an_incompatible_profile_is_refused() -> TestResult {
    let subject = Subject::new(Script::Count);
    let expected = expected(&[1, 2], None)?;

    // The deployment does not support the EPF1.
    let mut unsupported = Fixture::recomputation()?;
    unsupported.evidence.profile_support = ProfileSupportStatusV1::Unsupported;
    let outcome = run(
        &unsupported,
        subject.closure(2),
        &expected,
        StoreConfig::Memory,
    )?;
    assert_refused(&outcome, INCOMPATIBLE, Some("execution_profile"));

    // A class this step does not execute.
    let recorded = Fixture::new(
        ReproducibilityClassV1::RecordedReplay,
        LOCAL_PROFILE_ID_V1,
        LOCAL_PROFILE_ID_V1,
    )?;
    let outcome = run(
        &recorded,
        subject.closure(2),
        &expected,
        StoreConfig::Memory,
    )?;
    assert_refused(
        &outcome,
        (
            VerificationOutcomeV1::IncompatibleProfile,
            ReplayClaimV1::IncompatibleProfile,
            SafeErrorCodeV1::ProfileClassMismatch,
        ),
        Some("profile_class"),
    );

    // A cross-profile leg under another leg's EPF1.
    let local = Fixture::cross(LOCAL_PROFILE_ID_V1)?;
    let outcome = run_cross(&local, &local, subject.closure(2), &expected)?;
    assert_exact(&outcome.local, &expected)?;
    assert_refused(&outcome.air_gapped, INCOMPATIBLE, Some("execution_profile"));

    // A subject that cannot run under the Air-Gapped EPF1.
    let air_gapped = Fixture::cross(AIR_GAPPED_PROFILE_ID_V1)?;
    let networked = Subject {
        refused_profile: Some(AIR_GAPPED_PROFILE_ID_V1),
        ..Subject::new(Script::Count)
    };
    let outcome = run_cross(&local, &air_gapped, networked.closure(2), &expected)?;
    assert_exact(&outcome.local, &expected)?;
    assert_refused(&outcome.air_gapped, INCOMPATIBLE, Some("execution_profile"));
    Ok(())
}

#[test]
fn operational_variation_does_not_change_the_vrr1() -> TestResult {
    let fixture = Fixture::recomputation()?;
    let expected = expected(&[1, 2], None)?;
    let first = tempfile::tempdir()?;
    let second = tempfile::tempdir()?;
    let sqlite = |directory: &tempfile::TempDir, file: &str| StoreConfig::Sqlite {
        path: directory.path().join(file).to_string_lossy().into_owned(),
    };
    let runs = [
        (Operational::new(1_000, 0), StoreConfig::Memory),
        (Operational::new(9_000_000, 2), sqlite(&first, "a.db")),
        (Operational::new(42, 1), sqlite(&second, "nested-b.db")),
    ];
    let mut results = Vec::new();
    for (operational, store_config) in runs {
        let subject = Subject {
            operational: operational.clone(),
            ..Subject::new(Script::Count)
        };
        let outcome = run(&fixture, subject.closure(2), &expected, store_config)?;
        assert_exact(&outcome, &expected)?;
        results.push((outcome, operational.log_lines()));
    }
    assert_eq!(results[0].1, 0);
    assert_eq!(results[1].1, 2);
    assert_eq!(results[1].0, results[0].0);
    assert_eq!(results[2].0, results[0].0);
    Ok(())
}

#[test]
fn the_resource_limit_counts_recomputed_events() -> TestResult {
    let fixture = Fixture::recomputation()?;
    let mut limited = Fixture::recomputation()?;
    limited.manifest.resource_limit = 2;
    limited.refresh_manifest_binding()?;

    // Exactly the limit is admitted.
    let subject = Subject::new(Script::Count);
    let outcome = run(
        &limited,
        subject.closure(2),
        &expected(&[1, 2], None)?,
        StoreConfig::Memory,
    )?;
    assert_exact(&outcome, &expected(&[1, 2], None)?)?;

    // One Event over the limit across Ticks.
    let outcome = run(
        &limited,
        subject.closure(3),
        &expected(&[1, 2, 3], None)?,
        StoreConfig::Memory,
    )?;
    assert_refused(&outcome, RESOURCE, None);

    // One Tick over the host's per-Tick Event budget.
    let burst = Subject::new(Script::Burst);
    let outcome = run(
        &limited,
        burst.closure(1),
        &expected(&[1, 2, 3], None)?,
        StoreConfig::Memory,
    )?;
    assert_refused(&outcome, RESOURCE, None);

    // The same burst within the limit is exact.
    let outcome = run(
        &fixture,
        burst.closure(1),
        &expected(&[1, 2, 3], None)?,
        StoreConfig::Memory,
    )?;
    assert_exact(&outcome, &expected(&[1, 2, 3], None)?)?;
    Ok(())
}

#[test]
fn a_host_that_cannot_start_is_an_error_not_a_result() -> TestResult {
    let subject = Subject::new(Script::Count);
    let fixture = Fixture::recomputation()?;
    let directory = tempfile::tempdir()?;
    let unreachable = StoreConfig::Sqlite {
        path: directory
            .path()
            .join("missing")
            .join("store.db")
            .to_string_lossy()
            .into_owned(),
    };
    let outcome = execute_profile_recomputation_v1(
        ProfileRecomputationInputV1 {
            preflight: fixture.preflight(),
            closure: subject.closure(2),
            expected: &expected(&[1, 2], None)?,
            fixture_digest: None,
            store_config: unreachable,
        },
        &mut projections(),
    );
    assert!(outcome.is_err());
    Ok(())
}

#[test]
fn host_failure_codes_are_closed_and_stable() {
    let errors = [
        (ExperimentError::Runtime(secret_denied()), 1),
        (
            ExperimentError::ActionRejected(pos_core::ActionRejected::UnknownEventType),
            2,
        ),
        (
            ExperimentError::Store(pos_core::CoreError::ErasureContainmentUnavailable),
            3,
        ),
        (
            ExperimentError::ManifestRoster(ManifestRosterBuildErrorV1::Admission(
                ManifestRegistrationErrorV1::EmptyBatch,
            )),
            4,
        ),
        (ExperimentError::MissingForkRegistryFactory, 5),
        (ExperimentError::MissingStoreRecoveryRecipe, 6),
        (ExperimentError::SharedStoreLockPoisoned, 7),
        (ExperimentError::IncompatibleForkRegistry, 8),
        (ExperimentError::SessionFaulted, 9),
        (ExperimentError::ConsentRevokedV1, 10),
        (
            ExperimentError::ActionNotAdmitted(Box::new(
                HumanActionAdmissionErrorV1::IdempotencyConflict,
            )),
            11,
        ),
        (ExperimentError::DuplicatePipelineEvaluator, 12),
        (
            ExperimentError::CadenceTimeRegressed {
                previous_ns: 2,
                requested_ns: 1,
            },
            13,
        ),
        (
            ExperimentError::StepModeMismatch {
                active: "cadenced",
                requested: "all-drivers",
            },
            14,
        ),
    ];
    for (error, code) in &errors {
        let closed = HostFailureCodeV1::from(error);
        assert_eq!(closed.to_be_bytes(), u16::to_be_bytes(*code));
    }
    // The code ignores free text: two runtime failures share one code.
    assert_eq!(
        HostFailureCodeV1::from(&ExperimentError::Runtime(RuntimeError::NoDriver {
            name: "/tmp/elsewhere".to_owned(),
        })),
        HostFailureCodeV1::Runtime
    );
}

#[test]
fn operational_variation_does_not_change_a_typed_failure_vrr1() -> TestResult {
    let fixture = Fixture::recomputation()?;
    let expected = expected(&[1], Some(RUNTIME_FAILURE_CODE))?;
    let first = tempfile::tempdir()?;
    let second = tempfile::tempdir()?;
    let sqlite = |directory: &tempfile::TempDir, file: &str| StoreConfig::Sqlite {
        path: directory.path().join(file).to_string_lossy().into_owned(),
    };
    let runs = [
        (Operational::new(1_000, 0), StoreConfig::Memory),
        (
            Operational::new(7_000_000, 2),
            sqlite(&first, "failure-a.db"),
        ),
        (Operational::new(3, 1), sqlite(&second, "failure-b.db")),
    ];
    let mut results = Vec::new();
    for (operational, store_config) in runs {
        let subject = Subject {
            operational,
            ..Subject::new(Script::DeniedSecret)
        };
        let outcome = run(&fixture, subject.closure(3), &expected, store_config)?;
        assert_exact(&outcome, &expected)?;
        results.push(outcome);
    }
    assert_eq!(results[1], results[0]);
    assert_eq!(results[2], results[0]);
    Ok(())
}

#[test]
fn a_typed_failure_changes_the_authoritative_result_digest() -> TestResult {
    // The same committed Event, once followed by a typed failure and once not.
    let failing = Subject::new(Script::DeniedSecret);
    let succeeding = Subject::new(Script::Count);
    let with_failure = expected(&[1], Some(RUNTIME_FAILURE_CODE))?;
    let without_failure = expected(&[1], None)?;
    assert_ne!(
        result_digest(&with_failure)?,
        result_digest(&without_failure)?
    );

    let fixture = Fixture::recomputation()?;
    let failed = run(
        &fixture,
        failing.closure(3),
        &with_failure,
        StoreConfig::Memory,
    )?;
    let succeeded = run(
        &fixture,
        succeeding.closure(1),
        &without_failure,
        StoreConfig::Memory,
    )?;
    assert_exact(&failed, &with_failure)?;
    assert_exact(&succeeded, &without_failure)?;
    assert_ne!(
        failed.result.authoritative_result_digest,
        succeeded.result.authoritative_result_digest
    );

    // LiveUnverified results are never compared, but their digests differ too.
    let mut live = Fixture::new(
        ReproducibilityClassV1::LiveUnverified,
        LOCAL_PROFILE_ID_V1,
        "live-local-v1",
    )?;
    live.manifest.replay_claim = ReplayClaimV1::StructuralOnly;
    live.refresh_manifest_binding()?;
    let failed = run(
        &live,
        failing.closure(3),
        &without_failure,
        StoreConfig::Memory,
    )?;
    let succeeded = run(
        &live,
        succeeding.closure(1),
        &without_failure,
        StoreConfig::Memory,
    )?;
    assert_eq!(
        failed.result.authoritative_result_digest,
        Some(result_digest(&with_failure)?)
    );
    assert_eq!(
        succeeded.result.authoritative_result_digest,
        Some(result_digest(&without_failure)?)
    );
    assert_ne!(
        failed.result.verification_outcome,
        VerificationOutcomeV1::VerifiedExact
    );
    Ok(())
}
