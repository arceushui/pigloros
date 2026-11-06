#![cfg(target_os = "linux")]
//! ADR-062 Revision 8 slice R6 (Redmine #1225): ADR-064 Fork artifacts are
//! exported through their public encodings and compared with the R1
//! comparator.
//!
//! Acceptance criteria (page section 3.2):
//!
//! - A fixture whose factual suffix differs must not appear in the result
//!   (no factual-suffix splicing):
//!   `a_differing_factual_suffix_never_reaches_an_artifact`.
//! - A frontier or invalidation mismatch yields a `DVR1` at the artifact
//!   coordinate: `a_frontier_mismatch_is_a_divergence_at_the_frontier` and
//!   `an_invalidation_mismatch_is_a_divergence_at_the_invalidation`.
//! - Local = Air-Gapped for every artifact comparison: every test above runs
//!   each fixture in both modes and requires the same exports and the same
//!   `DVR1`.

use pos_conformance::counterfactual::checkpoint::RecomputeCheckpointV1;
use pos_conformance::counterfactual::plan::CounterfactualPlanV1;
use pos_conformance::counterfactual::result::CounterfactualResultV1;
use pos_conformance::counterfactual::{InterventionOperationV1, InterventionV1};
use pos_conformance::{
    draft_execution_profile_bytes_v1, draft_trust_policy_snapshot_bytes_v1, DigestSizeV1,
    DivergenceLocationKindV1, DivergenceMismatchKindV1, DivergenceReportV1, ExecutionModeV1,
    ExecutionProfileV1, FollowOnMismatchV1, RecomputationFrontierV1, ReplayClaimV1,
    ReproducibilityClassV1, SuffixInvalidationReasonV1, SuffixInvalidationV1,
    TrustPolicySnapshotV1,
};
use pos_core::{
    factual_event_schema_id, ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1,
    ArtifactStateV1, ArtifactTransitionRuleV1, ErasureArtifactClassV1, ErasureReferenceV1,
    ErasureReplayClaimV1, RegisteredArtifactV1, ReplayClaimEvaluationV1, ReplayClaimEvaluatorV1,
    FACTUAL_STEP_SCHEMA_ID_V1,
};
use pos_experiment::authoritative_comparison::DivergenceContextV1;
use pos_experiment::fork_artifacts::{
    compare_fork_artifacts_v1, run_fork_v1, ForkArtifactExportV1, ForkArtifactKindV1, ForkDriverV1,
    ForkFixtureV1, ForkRunErrorV1, FACTUAL_TIMELINE_ID_V1, FORK_TIMELINE_ID_V1, LEAD_EVENT_TYPE_V1,
};
use pos_runtime::counterfactual::coordinator::CounterfactualAdmissionErrorV1;
use pos_runtime::counterfactual::suffix::CounterfactualSuffixErrorV1;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Factual Ticks before the cut.
const CUT_TICK: u64 = 2;
/// The factual Timeline holds one input, then three Driver outputs per Tick.
const CUT_SEQ: u64 = 1 + 3 * CUT_TICK;
const FIRST_TICK: u64 = CUT_TICK + 1;
const HORIZON_SPAN: u64 = 2;
const HORIZON_TICK: u64 = FIRST_TICK + HORIZON_SPAN;
/// Export ordinals: the Intervention, the plan, the frontier, the
/// invalidation, one checkpoint per Tick, the result.
const FRONTIER_ORDINAL: u32 = 2;
const INVALIDATION_ORDINAL: u32 = 3;
const MODES: [ExecutionModeV1; 2] = [ExecutionModeV1::Local, ExecutionModeV1::AirGapped];

fn intervention() -> InterventionV1 {
    InterventionV1 {
        intervention_id: [1; 16],
        target_schema_id: factual_event_schema_id(LEAD_EVENT_TYPE_V1),
        target_entity_id: "body".to_owned(),
        target_field: "velocity".to_owned(),
        operation: InterventionOperationV1::AssignValue,
        value_digest: [2; 32],
        effective_tick: FIRST_TICK,
        ordinal: 0,
        principal_id: "principal:operator".to_owned(),
        capability: "intervene".to_owned(),
        consent_epoch: 3,
        consent_decision_digest: [4; 32],
        rationale: "what if".to_owned(),
        provenance_digest: [5; 32],
    }
}

/// The host's evaluation of one retained `Exact` Export artifact under the
/// enclosing `claim`.
fn evaluation(claim: ErasureReplayClaimV1) -> TestResult<ReplayClaimEvaluationV1> {
    Ok(ReplayClaimEvaluatorV1::evaluate(
        claim,
        &[ArtifactClaimInputV1 {
            registration: RegisteredArtifactV1::new(
                ErasureArtifactClassV1::Export,
                ErasureReferenceV1::from_digest([0x31; 32]),
                ArtifactDataClassV1::StructuralAuditMetadata,
                None,
                ErasureReferenceV1::from_digest([0x32; 32]),
                ArtifactOptionalityV1::Required,
                ArtifactTransitionRuleV1::PreserveExact,
            ),
            current_claim: ErasureReplayClaimV1::Exact,
            state: ArtifactStateV1::Retained,
        }],
    )?)
}

fn local_profile() -> TestResult<ExecutionProfileV1> {
    let bytes = draft_execution_profile_bytes_v1("deterministic-local-v1")?;
    Ok(ExecutionProfileV1::from_canonical_cbor(&bytes)?)
}

fn fixture() -> TestResult<ForkFixtureV1> {
    let snapshot = draft_trust_policy_snapshot_bytes_v1()?;
    Ok(ForkFixtureV1 {
        cut_tick: CUT_TICK,
        factual_suffix: Vec::new(),
        horizon_span: HORIZON_SPAN,
        plan_id: [0x11; 16],
        room_id: "room.alpha".to_owned(),
        room_digest: [0x12; 32],
        parent_cut_digest: [0x13; 32],
        intervention: intervention(),
        plugin_composition_digest: [0x14; 32],
        scheduler_digest: [0x15; 32],
        numeric_profile_digest: [0x16; 32],
        budget_digest: [0x17; 32],
        failure_policy_digest: [0x18; 32],
        replay_claim: ReplayClaimV1::Exact,
        execution_profile: local_profile()?,
        trust_policy: TrustPolicySnapshotV1::from_canonical_cbor(&snapshot)?,
        evaluated_claim: evaluation(ErasureReplayClaimV1::Exact)?,
        revocation_epoch: 7,
        erasure_epoch: 8,
        frontier_id: [0x81; 16],
        invalidation_id: [0x91; 16],
        provenance_digest: [0x82; 32],
        result_id: [0xa1; 16],
        evaluator_identity_digest: [0xa2; 32],
    })
}

const fn context(fixture: &ForkFixtureV1) -> DivergenceContextV1 {
    DivergenceContextV1 {
        request_digest: [0x41; 32],
        manifest_digest: [0x42; 32],
        execution_profile_digest: fixture.execution_profile.profile_digest,
        fixture_digest: None,
        evaluator_digest: [0x43; 32],
        reproducibility_class: ReproducibilityClassV1::ProfileRecomputation,
        replay_claim: ReplayClaimV1::Exact,
    }
}

/// Run `fixture` Local and Air-Gapped; the two exports must be equal and
/// compare without a divergence.
fn run_both(fixture: &ForkFixtureV1) -> TestResult<ForkArtifactExportV1> {
    let local = run_fork_v1(fixture, ExecutionModeV1::Local)?;
    let air_gapped = run_fork_v1(fixture, ExecutionModeV1::AirGapped)?;
    assert_eq!(local, air_gapped);
    assert_eq!(
        compare_fork_artifacts_v1(&context(fixture), &local, &air_gapped)?,
        None
    );
    Ok(local)
}

fn artifact(export: &ForkArtifactExportV1, ordinal: usize) -> TestResult<&[u8]> {
    export
        .artifacts
        .get(ordinal)
        .map(|artifact| artifact.bytes.as_slice())
        .ok_or_else(|| "no artifact at the ordinal".into())
}

fn digest_size(bytes: &[u8]) -> DigestSizeV1 {
    DigestSizeV1 {
        digest: Some(*blake3::hash(bytes).as_bytes()),
        size: Some(bytes.len() as u64),
    }
}

#[test]
fn every_artifact_is_exported_at_the_world_cut_and_decodes() -> TestResult {
    let fixture = fixture()?;
    let export = run_both(&fixture)?;
    let kinds: Vec<ForkArtifactKindV1> = export.artifacts.iter().map(|a| a.kind).collect();
    assert_eq!(
        kinds,
        [
            ForkArtifactKindV1::Intervention,
            ForkArtifactKindV1::CounterfactualPlan,
            ForkArtifactKindV1::RecomputationFrontier,
            ForkArtifactKindV1::SuffixInvalidation,
            ForkArtifactKindV1::Checkpoint,
            ForkArtifactKindV1::Checkpoint,
            ForkArtifactKindV1::Checkpoint,
            ForkArtifactKindV1::Result,
        ]
    );
    for (ordinal, exported) in (0_u32..).zip(&export.artifacts) {
        let coordinate = exported.coordinate;
        assert_eq!(coordinate.world_cut_id, FACTUAL_TIMELINE_ID_V1);
        assert_eq!(coordinate.cut_ordinal, CUT_SEQ);
        assert_eq!(coordinate.tick, CUT_TICK);
        assert_eq!(coordinate.artifact_ordinal, ordinal);
    }
    let stream = export.stream();
    assert_eq!(stream.world_cut_artifacts.len(), export.artifacts.len());
    assert!(stream.events.is_empty() && stream.checkpoints.is_empty());
    assert!(stream.scheduler.is_empty() && stream.driver_outputs.is_empty());
    assert_eq!(export.factual_head.tick, CUT_TICK);
    assert_eq!(export.factual_head.last_seq.as_u64(), CUT_SEQ);

    let decoded_intervention = InterventionV1::from_canonical_cbor(artifact(&export, 0)?)?;
    assert_eq!(decoded_intervention, fixture.intervention);
    let plan = CounterfactualPlanV1::from_canonical_cbor(artifact(&export, 1)?)?;
    assert_eq!(plan.parent_timeline_id, FACTUAL_TIMELINE_ID_V1);
    assert_eq!(
        (plan.parent_cut_seq, plan.parent_cut_tick),
        (CUT_SEQ, CUT_TICK)
    );
    assert_eq!(
        (plan.first_tick, plan.horizon_tick),
        (FIRST_TICK, HORIZON_TICK)
    );
    assert_eq!(
        plan.interventions,
        std::slice::from_ref(&fixture.intervention)
    );
    assert_eq!(plan.plan_id, fixture.plan_id);
    assert_eq!(
        plan.execution_profile.profile_digest,
        fixture.execution_profile.profile_digest
    );
    assert_eq!(plan.plan_digest, plan.digest()?);

    let frontier = RecomputationFrontierV1::from_canonical_cbor(artifact(&export, 2)?)?;
    check_frontier(&frontier, &plan, &fixture)?;
    check_drivers(&export.drivers, &frontier);

    let invalidation = SuffixInvalidationV1::from_canonical_cbor(artifact(&export, 3)?)?;
    check_invalidation(&invalidation, &plan, &frontier, &fixture);
    check_recomputation(&export, &plan, &frontier, &fixture)
}

/// The invalidation binds the plan, the Fork and the frontier, and commits
/// generation 1 at the first Tick.
fn check_invalidation(
    invalidation: &SuffixInvalidationV1,
    plan: &CounterfactualPlanV1,
    frontier: &RecomputationFrontierV1,
    fixture: &ForkFixtureV1,
) {
    assert_eq!(invalidation.invalidation_id, fixture.invalidation_id);
    assert_eq!(invalidation.plan_digest, plan.plan_digest);
    assert_eq!(invalidation.fork_id, FORK_TIMELINE_ID_V1);
    assert_eq!(invalidation.frontier_digest, frontier.frontier_digest);
    assert_eq!(
        (invalidation.prior_generation, invalidation.new_generation),
        (0, 1)
    );
    assert_eq!(
        invalidation.reason,
        SuffixInvalidationReasonV1::NewIntervention
    );
    assert_eq!(invalidation.commit_timeline_id, FORK_TIMELINE_ID_V1);
    assert_eq!(invalidation.commit_tick, FIRST_TICK);
    assert_eq!(invalidation.provenance_digest, fixture.provenance_digest);
}

/// One checkpoint per recomputed Tick, and a complete result that lists
/// them and roots in the frontier.
fn check_recomputation(
    export: &ForkArtifactExportV1,
    plan: &CounterfactualPlanV1,
    frontier: &RecomputationFrontierV1,
    fixture: &ForkFixtureV1,
) -> TestResult {
    let checkpoints = (4..7)
        .map(|ordinal| {
            Ok(RecomputeCheckpointV1::from_canonical_cbor(artifact(
                export, ordinal,
            )?)?)
        })
        .collect::<TestResult<Vec<_>>>()?;
    let ticks: Vec<u64> = checkpoints
        .iter()
        .map(|checkpoint| checkpoint.tick)
        .collect();
    assert_eq!(ticks, (FIRST_TICK..=HORIZON_TICK).collect::<Vec<_>>());
    for checkpoint in &checkpoints {
        assert_eq!(checkpoint.plan_digest, plan.plan_digest);
    }

    let result = CounterfactualResultV1::from_canonical_cbor(artifact(export, 7)?)?;
    assert!(result.is_complete());
    assert_eq!(result.result_id, fixture.result_id);
    assert_eq!(result.plan_digest, plan.plan_digest);
    assert_eq!(result.fork_id, FORK_TIMELINE_ID_V1);
    assert_eq!(result.fork_generation, 1);
    assert_eq!(
        (result.first_tick, result.horizon_tick),
        (FIRST_TICK, HORIZON_TICK)
    );
    assert_eq!(result.committed_through_tick, Some(HORIZON_TICK));
    assert_eq!(result.dependency_root, frontier.frontier_digest);
    assert_eq!(result.provenance_root, fixture.provenance_digest);
    assert_eq!(
        result.evaluator_identity_digest,
        fixture.evaluator_identity_digest
    );
    assert_eq!(
        result.execution_profile_digest,
        fixture.execution_profile.profile_digest
    );
    let references: Vec<(u64, [u8; 32])> = result
        .checkpoints
        .iter()
        .map(|reference| (reference.tick, reference.checkpoint_digest))
        .collect();
    let recorded: Vec<(u64, [u8; 32])> = checkpoints
        .iter()
        .map(|checkpoint| (checkpoint.tick, checkpoint.checkpoint_digest))
        .collect();
    assert_eq!(references, recorded);
    Ok(())
}

/// The three Drivers in schedule order, each the owner of its frontier.
fn check_drivers(drivers: &[ForkDriverV1], frontier: &RecomputationFrontierV1) {
    let names: Vec<(&str, &str, u32)> = drivers
        .iter()
        .map(|driver| {
            let names = (driver.plugin_name.as_str(), driver.driver_name.as_str());
            (names.0, names.1, driver.scheduler_position)
        })
        .collect();
    assert_eq!(
        names,
        [
            ("alpha", "alpha", 1),
            ("beta", "beta", 2),
            ("gamma", "gamma", 3)
        ]
    );
    // The records form declares the lead Driver's step nodes with the step
    // schema and its output nodes with its Event schema; the Intervention
    // assigns the lead output, so both are affected.
    let lead = &drivers[0].owner_id;
    let lead_nodes: Vec<(u32, u32)> = frontier
        .affected_nodes
        .iter()
        .filter(|node| node.owner_id == *lead)
        .map(|node| (node.output_ordinal, node.schema_id))
        .collect();
    assert!(lead_nodes.contains(&(1, factual_event_schema_id(LEAD_EVENT_TYPE_V1))));
    for (ordinal, schema) in lead_nodes {
        let expected = if ordinal == 0 {
            FACTUAL_STEP_SCHEMA_ID_V1
        } else {
            factual_event_schema_id(LEAD_EVENT_TYPE_V1)
        };
        assert_eq!(schema, expected);
    }
    for driver in drivers {
        let owned = frontier
            .owner_frontiers
            .iter()
            .filter(|owner| owner.owner_id == driver.owner_id)
            .map(|owner| owner.earliest_scheduler_position);
        assert_eq!(owned.collect::<Vec<_>>(), [driver.scheduler_position]);
    }
}

/// The frontier the Intervention implies: the Intervention root at the
/// first Tick, the lead Driver (scheduler position 1) at its output of the
/// first Tick, caused by the root, and the other two Drivers at their step of
/// the next Tick, which consumes the lead output.
fn check_frontier(
    frontier: &RecomputationFrontierV1,
    plan: &CounterfactualPlanV1,
    fixture: &ForkFixtureV1,
) -> TestResult {
    assert_eq!(frontier.frontier_id, fixture.frontier_id);
    assert_eq!(frontier.plan_digest, plan.plan_digest);
    assert_eq!(frontier.parent_cut_digest, fixture.parent_cut_digest);
    assert_eq!(frontier.provenance_digest, fixture.provenance_digest);
    assert_eq!(
        (
            frontier.global_frontier_tick,
            frontier.global_frontier_scheduler_position
        ),
        (FIRST_TICK, 0)
    );
    assert_eq!(frontier.endogenous_suffix_end_tick, HORIZON_TICK);
    let root = fixture.intervention.digest()?;
    let seeds: Vec<[u8; 32]> = frontier
        .intervention_seed_nodes
        .iter()
        .map(|seed| seed.artifact_digest)
        .collect();
    assert_eq!(seeds, [root]);
    let mut owners: Vec<(u64, u32, u32, bool)> = frontier
        .owner_frontiers
        .iter()
        .map(|owner| {
            let at = (
                owner.earliest_tick,
                owner.earliest_scheduler_position,
                owner.earliest_output_ordinal,
            );
            (at.0, at.1, at.2, owner.cause_node_digests == [root])
        })
        .collect();
    owners.sort_unstable();
    assert_eq!(
        owners,
        [
            (FIRST_TICK, 0, 0, true),
            (FIRST_TICK, 1, 1, true),
            (FIRST_TICK + 1, 2, 0, false),
            (FIRST_TICK + 1, 3, 0, false),
        ]
    );
    let intervention_owner = frontier
        .owner_frontiers
        .iter()
        .find(|owner| owner.earliest_scheduler_position == 0)
        .ok_or("no Intervention owner frontier")?;
    assert_eq!(intervention_owner.owner_id, "intervention");
    Ok(())
}

#[test]
fn a_differing_factual_suffix_never_reaches_an_artifact() -> TestResult {
    let base = fixture()?;
    let expected = run_both(&base)?;
    let suffixes: [&[&[u8]]; 2] = [&[b"one", b"two"], &[b"other"]];
    for suffix in suffixes {
        let fixture = ForkFixtureV1 {
            factual_suffix: suffix.iter().copied().map(<[u8]>::to_vec).collect(),
            ..base.clone()
        };
        let actual = run_both(&fixture)?;
        // The factual Timeline really ran past the cut: one input and three
        // Driver outputs per suffix Tick.
        let ticks = suffix.len() as u64;
        assert_eq!(actual.factual_head.tick, CUT_TICK + ticks);
        assert_eq!(actual.factual_head.last_seq.as_u64(), CUT_SEQ + 4 * ticks);
        assert_ne!(actual.factual_head, expected.factual_head);
        assert_eq!(actual.artifacts, expected.artifacts);
        assert_eq!(
            compare_fork_artifacts_v1(&context(&base), &expected, &actual)?,
            None
        );
    }
    Ok(())
}

/// The `DVR1` of `expected` against `actual`, the same in both modes.
fn divergence(
    base: &ForkFixtureV1,
    changed: &ForkFixtureV1,
) -> TestResult<(
    DivergenceReportV1,
    ForkArtifactExportV1,
    ForkArtifactExportV1,
)> {
    let mut reports = Vec::new();
    let mut exports = Vec::new();
    for mode in MODES {
        let expected = run_fork_v1(base, mode)?;
        let actual = run_fork_v1(changed, mode)?;
        let report = compare_fork_artifacts_v1(&context(base), &expected, &actual)?
            .ok_or("the exports do not diverge")?;
        reports.push(report);
        exports.push((expected, actual));
    }
    assert_eq!(reports[0], reports[1]);
    assert_eq!(exports[0], exports[1]);
    let (expected, actual) = exports.swap_remove(0);
    Ok((reports.swap_remove(0), expected, actual))
}

/// The report is at the artifact `ordinal` of the run's `WorldCut`, with the
/// digests of both artifacts and `follow_on` later artifact mismatches.
fn check_report(
    report: &DivergenceReportV1,
    (expected, actual): (&ForkArtifactExportV1, &ForkArtifactExportV1),
    ordinal: u32,
    follow_on: u32,
) -> TestResult {
    assert_eq!(report.location_kind, DivergenceLocationKindV1::WorldCut);
    assert_eq!(report.timeline_or_worldcut_id, FACTUAL_TIMELINE_ID_V1);
    assert_eq!(report.timeline_seq_or_cut_ordinal, CUT_SEQ);
    assert_eq!(report.tick, CUT_TICK);
    assert_eq!(report.scheduler_position, None);
    assert_eq!(report.driver_or_plugin_id, None);
    assert_eq!(report.output_ordinal, Some(ordinal));
    assert_eq!(report.mismatch_kind, DivergenceMismatchKindV1::Artifact);
    let at = usize::try_from(ordinal)?;
    assert_eq!(report.expected, digest_size(artifact(expected, at)?));
    assert_eq!(report.actual, digest_size(artifact(actual, at)?));
    assert_eq!(
        report.follow_on_counts,
        [FollowOnMismatchV1 {
            kind: DivergenceMismatchKindV1::Artifact,
            count: follow_on,
        }]
    );
    // Every artifact before the reported one is equal.
    assert_eq!(expected.artifacts[..at], actual.artifacts[..at]);
    Ok(())
}

#[test]
fn a_frontier_mismatch_is_a_divergence_at_the_frontier() -> TestResult {
    let base = fixture()?;
    let changed = ForkFixtureV1 {
        frontier_id: [0x83; 16],
        ..base.clone()
    };
    let (report, expected, actual) = divergence(&base, &changed)?;
    // The invalidation binds the frontier digest and every checkpoint chains
    // the invalidation digest, so they and the result follow on.
    check_report(&report, (&expected, &actual), FRONTIER_ORDINAL, 5)
}

#[test]
fn an_invalidation_mismatch_is_a_divergence_at_the_invalidation() -> TestResult {
    let base = fixture()?;
    let changed = ForkFixtureV1 {
        invalidation_id: [0x92; 16],
        ..base.clone()
    };
    let (report, expected, actual) = divergence(&base, &changed)?;
    check_report(&report, (&expected, &actual), INVALIDATION_ORDINAL, 4)
}

#[test]
fn every_refusal_is_described() {
    let errors = [
        ForkRunErrorV1::ModeUnsupported,
        ForkRunErrorV1::NetworkDenied,
        ForkRunErrorV1::Host,
        ForkRunErrorV1::Admission(Box::new(
            CounterfactualAdmissionErrorV1::ReplayClaimInsufficient,
        )),
        ForkRunErrorV1::Suffix(CounterfactualSuffixErrorV1::InvalidResultIdentity),
    ];
    let texts: Vec<String> = errors.iter().map(ToString::to_string).collect();
    assert_eq!(
        texts[..3],
        [
            "the execution mode is not Local or Air-Gapped",
            "an Air-Gapped run cannot use network",
            "the Fork host failed",
        ]
    );
    assert!(texts[3].starts_with("the counterfactual admission was refused: "));
    assert!(texts[4].starts_with("the suffix recomputation was refused: "));
}

#[test]
fn a_run_outside_local_and_air_gapped_is_refused() -> TestResult {
    let fixture = fixture()?;
    for mode in [ExecutionModeV1::Replay, ExecutionModeV1::Fork] {
        assert_eq!(
            run_fork_v1(&fixture, mode),
            Err(ForkRunErrorV1::ModeUnsupported)
        );
    }
    Ok(())
}

#[test]
fn a_network_profile_is_denied_air_gapped_only() -> TestResult {
    let mut profile = local_profile()?;
    profile.capabilities_and_network.network_allowed = true;
    profile.profile_digest = profile.digest();
    let fixture = ForkFixtureV1 {
        execution_profile: profile,
        ..fixture()?
    };
    assert_eq!(
        run_fork_v1(&fixture, ExecutionModeV1::AirGapped),
        Err(ForkRunErrorV1::NetworkDenied)
    );
    // Local network enforcement belongs to the host EPF1 work (#1266).
    let local = run_fork_v1(&fixture, ExecutionModeV1::Local)?;
    assert_eq!(local.artifacts.len(), 8);
    Ok(())
}

#[test]
fn refused_runs_export_nothing() -> TestResult {
    let base = fixture()?;
    let no_cut = ForkFixtureV1 {
        cut_tick: 0,
        ..base.clone()
    };
    let weaker_claim = ForkFixtureV1 {
        evaluated_claim: evaluation(ErasureReplayClaimV1::StructuralOnly)?,
        ..base.clone()
    };
    let no_result_identity = ForkFixtureV1 {
        result_id: [0; 16],
        ..base
    };
    for mode in MODES {
        assert_eq!(run_fork_v1(&no_cut, mode), Err(ForkRunErrorV1::Host));
        assert_eq!(
            run_fork_v1(&weaker_claim, mode),
            Err(ForkRunErrorV1::Admission(Box::new(
                CounterfactualAdmissionErrorV1::ReplayClaimInsufficient
            )))
        );
        assert_eq!(
            run_fork_v1(&no_result_identity, mode),
            Err(ForkRunErrorV1::Suffix(
                CounterfactualSuffixErrorV1::InvalidResultIdentity
            ))
        );
    }
    Ok(())
}
