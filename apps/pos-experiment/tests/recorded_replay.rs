#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Public-interface tests for the ADR-062 Revision 8 slice R2 `RecordedReplay`
//! execution step (#1220): RPL-001, ERA-001, INV-001..003 and RES-001.
//!
//! Expected streams are hand-derived from the recorded drafts (Q3): the
//! digests below follow the documented `recorded_replay` conventions and do
//! not call the execution step.

use pos_conformance::{
    draft_execution_profile_bytes_v1, draft_trust_policy_snapshot_bytes_v1,
    ArtifactClosureStatusV1, ArtifactRevocationStatusV1, DivergenceLocationKindV1,
    DivergenceMismatchKindV1, ExecutionModeV1, ExecutionProfileV1, ProfileSupportStatusV1,
    ReplayClaimV1, ReproManifestV1, ReproVerificationRequestV1, ReproducibilityClassV1,
    SafeErrorCodeV1, TrustPolicySnapshotV1, TrustRootStatusV1, TrustSignatureStatusV1,
    TrustSnapshotContinuityV1, VerificationOutcomeV1, VerificationPreflightEvidenceV1,
    VerificationPreflightInputV1, VerificationResultV1,
};
use pos_core::{
    store::{export_timeline, EventStore, SeqRange},
    ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactStateV1,
    ArtifactTransitionRuleV1, CanonicalBytes, EntityId, ErasureArtifactClassV1,
    ErasureContainmentGateV1, ErasureReferenceV1, ErasureReplayClaimV1, Event, EventDraft, Kind,
    Reducer, RegisteredArtifactV1, ReplayClaimEvaluationV1, ReplayClaimEvaluatorV1, State,
    TimelineExport, TimelineId,
};
use pos_experiment::authoritative_comparison::{
    AuthoritativeStreamV1, CheckpointDigestV1, ComparedEventV1, TickBoundaryCoordinateV1,
    TimelinePositionV1,
};
use pos_experiment::recorded_replay::{
    execute_recorded_replay_v1, ExportedTimelineMemberV1, RecordedReplayClosureV1,
    RecordedReplayInputV1,
};
use pos_experiment::verification_execution::VerificationExecutionOutcomeV1;
use pos_runtime::{Driver, ObservationView, RuntimeError, StepOutput};
use pos_state::ProjectionRegistry;
use pos_store::memory::MemoryStore;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const EXPORT_DIGEST: ErasureReferenceV1 = ErasureReferenceV1::from_digest([0xe1; 32]);
const FOREIGN_DIGEST: ErasureReferenceV1 = ErasureReferenceV1::from_digest([0xe2; 32]);
const OWNER: ErasureReferenceV1 = ErasureReferenceV1::from_digest([0xe3; 32]);
const EVENT_TYPE: &str = "replay.tick";
const PAYLOADS: [u8; 2] = [7, 9];
const LICENCE: &[u8] = b"SPDX-License-Identifier: MIT\n";
const FIXTURE_DIGEST: [u8; 32] = [0xf1; 32];
const REDUCER: &str = "counter";

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

/// A live Driver of the recording host. `RecordedReplay` must never step it.
struct CountingDriver(Arc<AtomicU64>);

impl Driver for CountingDriver {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn step(
        &mut self,
        _timeline: TimelineId,
        _observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(StepOutput::default())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn name(&self) -> &'static str {
        "counting"
    }
}

/// The recording host: its store, its live Driver and the exported Timeline.
struct Recording {
    store: MemoryStore,
    timeline: TimelineId,
    entity: EntityId,
    export: TimelineExport,
    payloads: Vec<u8>,
    driver_calls: Arc<AtomicU64>,
    _driver: Box<dyn Driver>,
}

impl Recording {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn new() -> TestResult<Self> {
        Self::with_payloads(&PAYLOADS)
    }

    /// Record one Event per payload, all for one entity.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn with_payloads(payloads: &[u8]) -> TestResult<Self> {
        let mut store = MemoryStore::new();
        store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
        let timeline = store.create_timeline("recorded-replay")?.id();
        let entity = EntityId::new();
        for &payload in payloads {
            let draft = EventDraft::new(
                entity,
                Kind::new(EVENT_TYPE),
                CanonicalBytes::from_vec(vec![payload]),
            );
            store.append(timeline, &[draft])?;
        }
        let export = export_timeline(&store, timeline, EXPORT_DIGEST, &evaluation_exact()?)?;
        let driver_calls = Arc::new(AtomicU64::new(0));
        let driver: Box<dyn Driver> = Box::new(CountingDriver(Arc::clone(&driver_calls)));
        Ok(Self {
            store,
            timeline,
            entity,
            export,
            payloads: payloads.to_vec(),
            driver_calls,
            _driver: driver,
        })
    }

    /// The Driver-call and store-append counters stay 0.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn assert_side_effect_free(&self) -> TestResult {
        assert_eq!(self.driver_calls.load(Ordering::SeqCst), 0);
        let recorded = self.store.read(self.timeline, SeqRange::all())?.len();
        assert_eq!(recorded, self.payloads.len());
        let head = self
            .store
            .get_timeline(self.timeline)?
            .map(|timeline| timeline.head.as_u64());
        assert_eq!(head, Some(u64::try_from(self.payloads.len())?));
        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    const fn member(&self) -> ExportedTimelineMemberV1<'_> {
        ExportedTimelineMemberV1 {
            export: &self.export,
            artifact_digest: EXPORT_DIGEST,
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    const fn closure(&self) -> RecordedReplayClosureV1<'_> {
        RecordedReplayClosureV1 {
            timeline_export: Some(self.member()),
            licence: Some(LICENCE),
        }
    }

    /// The expected stream, hand-derived from the recorded drafts.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn expected(&self, count: u64) -> TestResult<AuthoritativeStreamV1> {
        let timeline_id = self.timeline.inner().to_bytes();
        let mut events = BTreeMap::new();
        for (event, &payload) in self.export.events.iter().zip(&self.payloads) {
            let identity = digest(
                b"PiglorOS.RecordedReplayEventIdentity.v1",
                &[
                    &event.id.inner().to_bytes(),
                    &self.entity.inner().to_bytes(),
                    EVENT_TYPE.as_bytes(),
                ],
            );
            let schema = digest(
                b"PiglorOS.RecordedReplayEventSchema.v1",
                &[EVENT_TYPE.as_bytes(), &[0], &1_u32.to_be_bytes()],
            );
            events.insert(
                TimelinePositionV1 {
                    timeline_id,
                    seq: event.seq.as_u64(),
                },
                ComparedEventV1 {
                    tick: 0,
                    identity,
                    schema,
                    payload: vec![payload],
                },
            );
        }
        let mut states = serde_json::Map::new();
        if count > 0 {
            states.insert(
                self.entity.inner().to_string(),
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
            fold_cursor: u64::try_from(self.payloads.len())?,
            tick: 0,
        };
        Ok(AuthoritativeStreamV1 {
            events,
            checkpoints: BTreeMap::from([(coordinate, checkpoint)]),
            ..AuthoritativeStreamV1::default()
        })
    }
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

/// The documented authoritative result digest of a rebuilt stream.
#[cfg_attr(coverage_nightly, coverage(off))]
fn result_digest(stream: &AuthoritativeStreamV1) -> [u8; 32] {
    let mut parts: Vec<Vec<u8>> = vec![u64::try_from(stream.events.len())
        .unwrap_or(u64::MAX)
        .to_be_bytes()
        .to_vec()];
    for (position, event) in &stream.events {
        parts.push(position.timeline_id.to_vec());
        parts.push(position.seq.to_be_bytes().to_vec());
        parts.push(event.identity.to_vec());
        parts.push(event.schema.to_vec());
        parts.push(blake3::hash(&event.payload).as_bytes().to_vec());
    }
    parts.push(
        u64::try_from(stream.checkpoints.len())
            .unwrap_or(u64::MAX)
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
    // A recorded export has no typed failures: the typed-failure count is 0.
    parts.push(0_u64.to_be_bytes().to_vec());
    let parts: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    digest(b"PiglorOS.RecordedReplayResult.v1", &parts)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn evaluation(
    enclosing: ErasureReplayClaimV1,
    digest: ErasureReferenceV1,
    rule: ArtifactTransitionRuleV1,
    state: ArtifactStateV1,
) -> TestResult<ReplayClaimEvaluationV1> {
    Ok(ReplayClaimEvaluatorV1::evaluate(
        enclosing,
        &[ArtifactClaimInputV1 {
            registration: RegisteredArtifactV1::new(
                ErasureArtifactClassV1::Export,
                digest,
                ArtifactDataClassV1::StructuralAuditMetadata,
                None,
                OWNER,
                ArtifactOptionalityV1::Required,
                rule,
            ),
            current_claim: ErasureReplayClaimV1::Exact,
            state,
        }],
    )
    .map_err(|error| format!("{error:?}"))?)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn evaluation_exact() -> TestResult<ReplayClaimEvaluationV1> {
    evaluation(
        ErasureReplayClaimV1::Exact,
        EXPORT_DIGEST,
        ArtifactTransitionRuleV1::PreserveExact,
        ArtifactStateV1::Retained,
    )
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn projections() -> ProjectionRegistry {
    let mut projections = ProjectionRegistry::new()
        .with_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()));
    projections.register(REDUCER, Box::new(CountReducer));
    projections
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
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn new(class: ReproducibilityClassV1) -> TestResult<Self> {
        let mut execution_profile = ExecutionProfileV1::from_canonical_cbor(
            &draft_execution_profile_bytes_v1("deterministic-local-v1")?,
        )?;
        let trust_policy_snapshot =
            TrustPolicySnapshotV1::from_canonical_cbor(&draft_trust_policy_snapshot_bytes_v1()?)?;
        execution_profile.reproducibility_classes = vec![class];
        execution_profile.profile_digest = execution_profile.digest();
        let profile_digest = execution_profile.profile_digest;
        let trust_digest = trust_policy_snapshot.digest()?;
        let manifest = ReproManifestV1 {
            format_version: 1,
            input_digest: [10; 32],
            execution_mode: ExecutionModeV1::Local,
            fork_cut_seq: None,
            seed: 11,
            resource_limit: 2,
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
    fn recorded() -> TestResult<Self> {
        Self::new(ReproducibilityClassV1::RecordedReplay)
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

/// Run one execution, then check the side-effect counters and `VRR1` codec.
#[cfg_attr(coverage_nightly, coverage(off))]
fn run(
    recording: &Recording,
    fixture: &Fixture,
    closure: RecordedReplayClosureV1<'_>,
    evaluation: &ReplayClaimEvaluationV1,
    projections: &mut ProjectionRegistry,
) -> TestResult<VerificationExecutionOutcomeV1> {
    let expected = recording.expected(u64::try_from(recording.payloads.len())?)?;
    let outcome = execute_recorded_replay_v1(
        RecordedReplayInputV1 {
            preflight: fixture.preflight(),
            closure,
            replay_claim_evaluation: evaluation,
            expected: &expected,
            fixture_digest: Some(FIXTURE_DIGEST),
        },
        projections,
    )?;
    recording.assert_side_effect_free()?;
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
    assert_eq!(outcome.result.fixture_digest, Some(FIXTURE_DIGEST));
    assert_eq!(
        outcome.result.reproducibility_class,
        fixture.request.reproducibility_class
    );
    Ok(outcome)
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

#[test]
fn rpl_001_recorded_replay_is_verified_exact() -> TestResult {
    let recording = Recording::new()?;
    let fixture = Fixture::recorded()?;
    let mut projections = projections();
    let outcome = run(
        &recording,
        &fixture,
        recording.closure(),
        &evaluation_exact()?,
        &mut projections,
    )?;
    assert_eq!(
        outcome.result.verification_outcome,
        VerificationOutcomeV1::VerifiedExact
    );
    assert_eq!(outcome.result.replay_claim, ReplayClaimV1::Exact);
    assert_eq!(
        outcome.result.authoritative_result_digest,
        Some(result_digest(&recording.expected(2)?))
    );
    assert_eq!(outcome.result.divergence_report_digest, None);
    assert_eq!(outcome.result.first_error, None);
    assert_eq!(outcome.result.checked_artifact_count, 2);
    assert_eq!(outcome.divergence, None);
    assert_eq!(
        projections.state_for(recording.timeline, &recording.entity)?,
        Some(State {
            fields: [("count".to_owned(), serde_json::json!(2))].into(),
        })
    );

    // State is rebuilt from empty, so a second run over the same registry
    // gives the identical result.
    let again = run(
        &recording,
        &fixture,
        recording.closure(),
        &evaluation_exact()?,
        &mut projections,
    )?;
    assert_eq!(again, outcome);
    Ok(())
}

#[test]
fn era_001_degraded_replay_claim_is_verified_exact_with_degraded_claim() -> TestResult {
    let recording = Recording::new()?;
    let fixture = Fixture::recorded()?;
    let redacted = evaluation(
        ErasureReplayClaimV1::Exact,
        EXPORT_DIGEST,
        ArtifactTransitionRuleV1::RedactViews,
        ArtifactStateV1::TransitionApplied,
    )?;
    let outcome = run(
        &recording,
        &fixture,
        recording.closure(),
        &redacted,
        &mut projections(),
    )?;
    assert_eq!(
        outcome.result.verification_outcome,
        VerificationOutcomeV1::VerifiedExact
    );
    assert_eq!(
        outcome.result.replay_claim,
        ReplayClaimV1::ExactAuthoritativeWithRedactedViews
    );
    assert_eq!(outcome.result.first_error, None);
    Ok(())
}

#[test]
fn a_rebuilt_state_that_differs_is_diverged_with_one_dvr1() -> TestResult {
    let recording = Recording::new()?;
    let fixture = Fixture::recorded()?;
    let expected = recording.expected(3)?;
    let outcome = execute_recorded_replay_v1(
        RecordedReplayInputV1 {
            preflight: fixture.preflight(),
            closure: recording.closure(),
            replay_claim_evaluation: &evaluation_exact()?,
            expected: &expected,
            fixture_digest: None,
        },
        &mut projections(),
    )?;
    recording.assert_side_effect_free()?;
    assert_eq!(
        outcome.result.verification_outcome,
        VerificationOutcomeV1::Diverged
    );
    let report = outcome.divergence.as_ref().ok_or("diverged without DVR1")?;
    assert_eq!(report.location_kind, DivergenceLocationKindV1::TickBoundary);
    assert_eq!(
        report.mismatch_kind,
        DivergenceMismatchKindV1::ProjectionCheckpoint
    );
    assert_eq!(report.timeline_seq_or_cut_ordinal, 2);
    assert_eq!(report.request_digest, fixture.canonical_request_digest);
    assert_eq!(report.fixture_digest, None);
    assert_eq!(
        outcome.result.divergence_report_digest,
        Some(report.report_digest)
    );
    // The rebuilt stream, not the expected one, is the authoritative result.
    assert_eq!(
        outcome.result.authoritative_result_digest,
        Some(result_digest(&recording.expected(2)?))
    );
    assert_ne!(
        outcome.result.authoritative_result_digest,
        Some(result_digest(&expected))
    );
    assert_eq!(outcome.result.first_error, None);
    Ok(())
}

#[test]
fn inv_001_invalid_manifest_is_refused_by_the_preflight() -> TestResult {
    let recording = Recording::new()?;
    let mut fixture = Fixture::recorded()?;
    fixture.manifest.format_version = 2;
    fixture.refresh_manifest_binding()?;
    let outcome = run(
        &recording,
        &fixture,
        recording.closure(),
        &evaluation_exact()?,
        &mut projections(),
    )?;
    assert_refused(
        &outcome,
        (
            VerificationOutcomeV1::InvalidManifest,
            ReplayClaimV1::Exact,
            SafeErrorCodeV1::UnsupportedVersion,
        ),
        Some("manifest"),
    );
    Ok(())
}

#[test]
fn inv_002_a_missing_licence_member_is_refused_at_artifact_closure() -> TestResult {
    let recording = Recording::new()?;
    let fixture = Fixture::recorded()?;
    let closure = RecordedReplayClosureV1 {
        licence: None,
        ..recording.closure()
    };
    let outcome = run(
        &recording,
        &fixture,
        closure,
        &evaluation_exact()?,
        &mut projections(),
    )?;
    assert_refused(
        &outcome,
        (
            VerificationOutcomeV1::UnverifiableArtifactsMissing,
            ReplayClaimV1::UnverifiableArtifactsMissing,
            SafeErrorCodeV1::ClosureIncomplete,
        ),
        Some("artifact_closure"),
    );
    assert_eq!(outcome.result.checked_artifact_count, 1);
    Ok(())
}

#[test]
fn inv_002_an_incomplete_closure_is_unverifiable_artifacts_missing() -> TestResult {
    let recording = Recording::new()?;
    let missing = (
        VerificationOutcomeV1::UnverifiableArtifactsMissing,
        ReplayClaimV1::UnverifiableArtifactsMissing,
        SafeErrorCodeV1::ClosureIncomplete,
    );

    let fixture = Fixture::recorded()?;
    let no_export = RecordedReplayClosureV1 {
        timeline_export: None,
        ..recording.closure()
    };
    let outcome = run(
        &recording,
        &fixture,
        no_export,
        &evaluation_exact()?,
        &mut projections(),
    )?;
    assert_refused(&outcome, missing, Some("artifact_closure"));

    let empty_licence = RecordedReplayClosureV1 {
        licence: Some(b"".as_slice()),
        ..recording.closure()
    };
    let outcome = run(
        &recording,
        &fixture,
        empty_licence,
        &evaluation_exact()?,
        &mut projections(),
    )?;
    assert_refused(&outcome, missing, Some("artifact_closure"));
    assert_eq!(outcome.result.checked_artifact_count, 1);

    let mut reported_incomplete = Fixture::recorded()?;
    reported_incomplete.evidence.artifact_closure = ArtifactClosureStatusV1::Incomplete;
    let outcome = run(
        &recording,
        &reported_incomplete,
        recording.closure(),
        &evaluation_exact()?,
        &mut projections(),
    )?;
    assert_refused(&outcome, missing, Some("artifact_closure"));

    let mut unverifiable = Fixture::recorded()?;
    unverifiable.manifest.replay_claim = ReplayClaimV1::UnverifiableArtifactsMissing;
    unverifiable.refresh_manifest_binding()?;
    let outcome = run(
        &recording,
        &unverifiable,
        recording.closure(),
        &evaluation_exact()?,
        &mut projections(),
    )?;
    assert_refused(
        &outcome,
        (
            VerificationOutcomeV1::UnverifiableArtifactsMissing,
            ReplayClaimV1::UnverifiableArtifactsMissing,
            SafeErrorCodeV1::ProvenanceMissing,
        ),
        Some("replay_claim"),
    );
    Ok(())
}

#[test]
fn inv_003_an_unsupported_profile_is_incompatible_profile() -> TestResult {
    let recording = Recording::new()?;
    let mut fixture = Fixture::recorded()?;
    fixture.evidence.profile_support = ProfileSupportStatusV1::Unsupported;
    let outcome = run(
        &recording,
        &fixture,
        recording.closure(),
        &evaluation_exact()?,
        &mut projections(),
    )?;
    assert_refused(
        &outcome,
        (
            VerificationOutcomeV1::IncompatibleProfile,
            ReplayClaimV1::IncompatibleProfile,
            SafeErrorCodeV1::ProfileUnsupported,
        ),
        Some("execution_profile"),
    );
    Ok(())
}

#[test]
fn another_reproducibility_class_is_incompatible_profile() -> TestResult {
    let recording = Recording::new()?;
    let fixture = Fixture::new(ReproducibilityClassV1::ProfileRecomputation)?;
    let outcome = run(
        &recording,
        &fixture,
        recording.closure(),
        &evaluation_exact()?,
        &mut projections(),
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
    Ok(())
}

#[test]
fn adr_060_degradation_never_strengthens_the_claim() -> TestResult {
    let recording = Recording::new()?;
    let fixture = Fixture::recorded()?;
    let missing = (
        VerificationOutcomeV1::UnverifiableArtifactsMissing,
        ReplayClaimV1::UnverifiableArtifactsMissing,
        SafeErrorCodeV1::ProvenanceMissing,
    );
    let structural = evaluation(
        ErasureReplayClaimV1::Exact,
        EXPORT_DIGEST,
        ArtifactTransitionRuleV1::RetainStructure,
        ArtifactStateV1::TransitionApplied,
    )?;
    let erased = evaluation(
        ErasureReplayClaimV1::Exact,
        EXPORT_DIGEST,
        ArtifactTransitionRuleV1::PreserveExact,
        ArtifactStateV1::Erased,
    )?;
    let foreign = evaluation(
        ErasureReplayClaimV1::Exact,
        FOREIGN_DIGEST,
        ArtifactTransitionRuleV1::PreserveExact,
        ArtifactStateV1::Retained,
    )?;
    let structural_claim = (
        VerificationOutcomeV1::UnverifiableArtifactsMissing,
        ReplayClaimV1::StructuralOnly,
        SafeErrorCodeV1::ProvenanceMissing,
    );
    for (evaluation, expected) in [
        (structural, structural_claim),
        (erased, missing),
        (foreign, missing),
    ] {
        let outcome = run(
            &recording,
            &fixture,
            recording.closure(),
            &evaluation,
            &mut projections(),
        )?;
        assert_refused(&outcome, expected, Some("replay_claim"));
    }

    let mut structural_manifest = Fixture::recorded()?;
    structural_manifest.manifest.replay_claim = ReplayClaimV1::StructuralOnly;
    structural_manifest.refresh_manifest_binding()?;
    let outcome = run(
        &recording,
        &structural_manifest,
        recording.closure(),
        &evaluation_exact()?,
        &mut projections(),
    )?;
    assert_refused(&outcome, structural_claim, Some("replay_claim"));

    // A missing closure member keeps a structural claim distinct too.
    let outcome = run(
        &recording,
        &structural_manifest,
        RecordedReplayClosureV1 {
            licence: None,
            ..recording.closure()
        },
        &evaluation_exact()?,
        &mut projections(),
    )?;
    assert_refused(
        &outcome,
        (
            VerificationOutcomeV1::UnverifiableArtifactsMissing,
            ReplayClaimV1::StructuralOnly,
            SafeErrorCodeV1::ClosureIncomplete,
        ),
        Some("artifact_closure"),
    );

    let incompatible = evaluation(
        ErasureReplayClaimV1::IncompatibleProfile,
        EXPORT_DIGEST,
        ArtifactTransitionRuleV1::PreserveExact,
        ArtifactStateV1::Retained,
    )?;
    let outcome = run(
        &recording,
        &fixture,
        recording.closure(),
        &incompatible,
        &mut projections(),
    )?;
    assert_refused(
        &outcome,
        (
            VerificationOutcomeV1::IncompatibleProfile,
            ReplayClaimV1::IncompatibleProfile,
            SafeErrorCodeV1::ProfileUnsupported,
        ),
        Some("replay_claim"),
    );
    Ok(())
}

#[test]
fn res_001_an_export_over_the_resource_limit_is_refused_before_any_fold() -> TestResult {
    let recording = Recording::new()?;
    let mut fixture = Fixture::recorded()?;
    fixture.manifest.resource_limit = 1;
    fixture.refresh_manifest_binding()?;
    let mut projections = projections();
    let outcome = run(
        &recording,
        &fixture,
        recording.closure(),
        &evaluation_exact()?,
        &mut projections,
    )?;
    assert_refused(
        &outcome,
        (
            VerificationOutcomeV1::ResourceLimitExceeded,
            ReplayClaimV1::Exact,
            SafeErrorCodeV1::ResourceLimitExceeded,
        ),
        None,
    );
    assert_eq!(
        projections.state_for(recording.timeline, &recording.entity)?,
        None
    );
    Ok(())
}

#[test]
fn a_denied_snapshot_fence_is_unverifiable_artifacts_missing() -> TestResult {
    let recording = Recording::new()?;
    let fixture = Fixture::recorded()?;
    let mut fail_closed = ProjectionRegistry::new();
    fail_closed.register(REDUCER, Box::new(CountReducer));
    let outcome = run(
        &recording,
        &fixture,
        recording.closure(),
        &evaluation_exact()?,
        &mut fail_closed,
    )?;
    assert_refused(
        &outcome,
        (
            VerificationOutcomeV1::UnverifiableArtifactsMissing,
            ReplayClaimV1::UnverifiableArtifactsMissing,
            SafeErrorCodeV1::ProvenanceMissing,
        ),
        Some("replay_claim"),
    );
    Ok(())
}

#[test]
fn a_revoked_artifact_is_invalid_manifest_at_revocation() -> TestResult {
    let recording = Recording::new()?;
    let mut fixture = Fixture::recorded()?;
    fixture.evidence.artifact_revocation = ArtifactRevocationStatusV1::Revoked;
    let outcome = run(
        &recording,
        &fixture,
        recording.closure(),
        &evaluation_exact()?,
        &mut projections(),
    )?;
    assert_refused(
        &outcome,
        (
            VerificationOutcomeV1::InvalidManifest,
            ReplayClaimV1::Exact,
            SafeErrorCodeV1::ArtifactRevoked,
        ),
        Some("revocation"),
    );
    Ok(())
}

#[test]
fn an_export_out_of_timeline_order_is_refused_before_any_fold() -> TestResult {
    let recording = Recording::with_payloads(&[7, 9, 11])?;
    // The budget check (step 5) runs before the order check (step 6), so
    // the budget must admit all three Events.
    let mut fixture = Fixture::recorded()?;
    fixture.manifest.resource_limit = 3;
    fixture.refresh_manifest_binding()?;
    let mut duplicate = recording.export.clone();
    duplicate.events[2].seq = duplicate.events[1].seq;
    let mut decreasing = recording.export.clone();
    decreasing.events.swap(0, 2);
    for export in [&duplicate, &decreasing] {
        let mut projections = projections();
        let outcome = run(
            &recording,
            &fixture,
            RecordedReplayClosureV1 {
                timeline_export: Some(ExportedTimelineMemberV1 {
                    export,
                    artifact_digest: EXPORT_DIGEST,
                }),
                licence: Some(LICENCE),
            },
            &evaluation_exact()?,
            &mut projections,
        )?;
        assert_refused(
            &outcome,
            (
                VerificationOutcomeV1::InvalidManifest,
                ReplayClaimV1::Exact,
                SafeErrorCodeV1::NonCanonicalOrder,
            ),
            Some("artifact_closure"),
        );
        assert_eq!(
            projections.state_for(recording.timeline, &recording.entity)?,
            None
        );
    }
    Ok(())
}

#[test]
fn an_empty_export_is_verified_exact_at_fold_cursor_zero() -> TestResult {
    let recording = Recording::with_payloads(&[])?;
    let fixture = Fixture::recorded()?;
    let outcome = run(
        &recording,
        &fixture,
        recording.closure(),
        &evaluation_exact()?,
        &mut projections(),
    )?;
    assert_eq!(
        outcome.result.verification_outcome,
        VerificationOutcomeV1::VerifiedExact
    );
    assert_eq!(
        outcome.result.authoritative_result_digest,
        Some(result_digest(&recording.expected(0)?))
    );
    Ok(())
}
