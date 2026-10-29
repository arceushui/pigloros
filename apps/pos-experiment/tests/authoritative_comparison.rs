#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Public-interface tests for the ADR-062 Revision 8 slice R1 first-divergence
//! comparator (#1218).

use pos_conformance::{
    DigestSizeV1, DivergenceLocationKindV1 as Location, DivergenceMismatchKindV1 as Kind,
    DivergenceReportV1, FollowOnMismatchV1, ReplayClaimV1, ReproducibilityClassV1,
};
use pos_experiment::authoritative_comparison::{
    first_divergence_v1, AuthoritativeStreamV1, CheckpointDigestV1, ComparedDriverOutputV1,
    ComparedEventV1, DivergenceContextV1, DriverOutcomeV1, DriverOutputCoordinateV1,
    SchedulerSlotV1, TickBoundaryCoordinateV1, TimelinePositionV1, WorldCutArtifactCoordinateV1,
    MAX_FOLLOW_ON_COUNT_V1,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const TIMELINE: [u8; 16] = [0x11; 16];
const WORLD_CUT: [u8; 16] = [0x22; 16];
const SCHEMA: [u8; 32] = [0x51; 32];
const NUMERIC_PROFILE: [u8; 32] = [0x4e; 32];
const CHECKPOINT_1: [u8; 32] = [0xc1; 32];
const CHECKPOINT_2: [u8; 32] = [0xc2; 32];
const WORLD_DRIVER: &str = "world.driver";
const AGENT_DRIVER: &str = "agent.driver";

#[cfg_attr(coverage_nightly, coverage(off))]
const fn context() -> DivergenceContextV1 {
    DivergenceContextV1 {
        request_digest: [1; 32],
        manifest_digest: [2; 32],
        execution_profile_digest: [3; 32],
        fixture_digest: Some([4; 32]),
        evaluator_digest: [5; 32],
        reproducibility_class: ReproducibilityClassV1::RecordedReplay,
        replay_claim: ReplayClaimV1::Exact,
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
const fn position(seq: u64) -> TimelinePositionV1 {
    TimelinePositionV1 {
        timeline_id: TIMELINE,
        seq,
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
const fn identity(seed: u8) -> [u8; 32] {
    [seed; 32]
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn event(tick: u64, seed: u8) -> ComparedEventV1 {
    ComparedEventV1 {
        tick,
        identity: identity(seed),
        schema: SCHEMA,
        payload: format!("payload-{seed}").into_bytes(),
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
const fn artifact(artifact_ordinal: u32) -> WorldCutArtifactCoordinateV1 {
    WorldCutArtifactCoordinateV1 {
        world_cut_id: WORLD_CUT,
        cut_ordinal: 0,
        tick: 2,
        artifact_ordinal,
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
const fn boundary(fold_cursor: u64, tick: u64) -> TickBoundaryCoordinateV1 {
    TickBoundaryCoordinateV1 {
        timeline_id: TIMELINE,
        fold_cursor,
        tick,
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
const fn slot(position: u32) -> SchedulerSlotV1 {
    SchedulerSlotV1 {
        timeline_id: TIMELINE,
        fold_cursor: 2,
        tick: 2,
        position,
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn output(position: u32, driver: &str, output_ordinal: u32) -> DriverOutputCoordinateV1 {
    DriverOutputCoordinateV1 {
        timeline_id: TIMELINE,
        fold_cursor: 2,
        tick: 2,
        scheduler_position: position,
        driver_id: driver.to_owned(),
        output_ordinal,
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
const fn driver_output(outcome: DriverOutcomeV1) -> ComparedDriverOutputV1 {
    ComparedDriverOutputV1 {
        outcome,
        numeric_profile_digest: NUMERIC_PROFILE,
        prohibited_operational_input: None,
    }
}

/// One Timeline with three Events over two ticks, one `WorldCut` with two
/// artifacts, two checkpoints, a two-Driver step and its two outputs.
#[cfg_attr(coverage_nightly, coverage(off))]
fn baseline() -> AuthoritativeStreamV1 {
    let mut stream = AuthoritativeStreamV1::default();
    stream.events.insert(position(1), event(1, 1));
    stream.events.insert(position(2), event(1, 2));
    stream.events.insert(position(3), event(2, 3));
    stream
        .world_cut_artifacts
        .insert(artifact(0), b"int1-artifact".to_vec());
    stream
        .world_cut_artifacts
        .insert(artifact(1), b"plan-artifact".to_vec());
    stream.checkpoints.insert(
        boundary(2, 1),
        CheckpointDigestV1 {
            digest: CHECKPOINT_1,
            size: 100,
        },
    );
    stream.checkpoints.insert(
        boundary(3, 2),
        CheckpointDigestV1 {
            digest: CHECKPOINT_2,
            size: 120,
        },
    );
    stream.scheduler.insert(slot(0), WORLD_DRIVER.to_owned());
    stream.scheduler.insert(slot(1), AGENT_DRIVER.to_owned());
    stream.driver_outputs.insert(
        output(0, WORLD_DRIVER, 0),
        driver_output(DriverOutcomeV1::Output(b"world-output".to_vec())),
    );
    stream.driver_outputs.insert(
        output(1, AGENT_DRIVER, 0),
        driver_output(DriverOutcomeV1::TypedFailure(b"agent-timeout".to_vec())),
    );
    stream
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn bytes(value: &[u8]) -> DigestSizeV1 {
    DigestSizeV1 {
        digest: Some(*blake3::hash(value).as_bytes()),
        size: u64::try_from(value.len()).ok(),
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
const fn digest_only(value: [u8; 32]) -> DigestSizeV1 {
    DigestSizeV1 {
        digest: Some(value),
        size: None,
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
const fn absent() -> DigestSizeV1 {
    DigestSizeV1 {
        digest: None,
        size: None,
    }
}

/// Run the comparator and check that its report round-trips through the
/// pos-conformance `DVR1` validator unchanged.
#[cfg_attr(coverage_nightly, coverage(off))]
fn compare(
    expected: &AuthoritativeStreamV1,
    actual: &AuthoritativeStreamV1,
) -> TestResult<Option<DivergenceReportV1>> {
    let report = first_divergence_v1(&context(), expected, actual)?;
    if let Some(report) = &report {
        let encoded = report.to_canonical_cbor()?;
        assert_eq!(&DivergenceReportV1::from_canonical_cbor(&encoded)?, report);
        assert_eq!(report.report_digest, report.digest()?);
        assert_ne!(report.report_digest, [0; 32]);
        let context = context();
        assert_eq!(report.request_digest, context.request_digest);
        assert_eq!(report.manifest_digest, context.manifest_digest);
        assert_eq!(
            report.execution_profile_digest,
            context.execution_profile_digest
        );
        assert_eq!(report.fixture_digest, context.fixture_digest);
        assert_eq!(report.evaluator_digest, context.evaluator_digest);
        assert_eq!(report.reproducibility_class, context.reproducibility_class);
        assert_eq!(report.replay_claim, context.replay_claim);
    }
    Ok(report)
}

/// The expected first divergence of one case.
struct ExpectedReport {
    location: Location,
    kind: Kind,
    id: [u8; 16],
    seq_or_ordinal: u64,
    tick: u64,
    scheduler_position: Option<u32>,
    driver: Option<&'static str>,
    output_ordinal: Option<u32>,
    expected: DigestSizeV1,
    actual: DigestSizeV1,
    prior_checkpoint: Option<[u8; 32]>,
    follow_on: Vec<(Kind, u32)>,
}

type Mutation = fn(&mut AuthoritativeStreamV1) -> Option<()>;

type PayloadMutation = fn(&mut AuthoritativeStreamV1, Vec<u8>) -> Option<()>;

struct Case {
    name: &'static str,
    mutate_actual: Mutation,
    expected: ExpectedReport,
}

#[cfg_attr(coverage_nightly, coverage(off))]
const fn timeline(
    kind: Kind,
    seq: u64,
    tick: u64,
    sides: (DigestSizeV1, DigestSizeV1),
) -> ExpectedReport {
    ExpectedReport {
        location: Location::TimelineSeq,
        kind,
        id: TIMELINE,
        seq_or_ordinal: seq,
        tick,
        scheduler_position: None,
        driver: None,
        output_ordinal: None,
        expected: sides.0,
        actual: sides.1,
        prior_checkpoint: None,
        follow_on: Vec::new(),
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn timeline_cases() -> Vec<Case> {
    vec![
        Case {
            name: "event identity differs",
            mutate_actual: |s| {
                s.events.get_mut(&position(2))?.identity = identity(9);
                Some(())
            },
            expected: timeline(
                Kind::EventIdentity,
                2,
                1,
                (digest_only(identity(2)), digest_only(identity(9))),
            ),
        },
        Case {
            name: "event missing from actual",
            mutate_actual: |s| s.events.remove(&position(3)).map(|_| ()),
            expected: ExpectedReport {
                prior_checkpoint: Some(CHECKPOINT_1),
                ..timeline(
                    Kind::EventIdentity,
                    3,
                    2,
                    (digest_only(identity(3)), absent()),
                )
            },
        },
        Case {
            name: "extra event in actual",
            mutate_actual: |s| {
                s.events.insert(position(4), event(3, 4));
                Some(())
            },
            expected: ExpectedReport {
                prior_checkpoint: Some(CHECKPOINT_2),
                ..timeline(
                    Kind::EventIdentity,
                    4,
                    3,
                    (absent(), digest_only(identity(4))),
                )
            },
        },
    ]
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn timeline_order_cases() -> Vec<Case> {
    vec![
        Case {
            name: "event identities swapped",
            mutate_actual: |s| {
                s.events.get_mut(&position(1))?.identity = identity(2);
                s.events.get_mut(&position(2))?.identity = identity(1);
                Some(())
            },
            expected: ExpectedReport {
                follow_on: vec![(Kind::EventOrder, 1)],
                ..timeline(
                    Kind::EventOrder,
                    1,
                    1,
                    (digest_only(identity(1)), digest_only(identity(2))),
                )
            },
        },
        Case {
            name: "expected event moved later in actual",
            mutate_actual: |s| {
                s.events.get_mut(&position(2))?.identity = identity(7);
                s.events.get_mut(&position(3))?.identity = identity(2);
                Some(())
            },
            expected: ExpectedReport {
                follow_on: vec![(Kind::EventOrder, 1)],
                ..timeline(
                    Kind::EventOrder,
                    2,
                    1,
                    (digest_only(identity(2)), digest_only(identity(7))),
                )
            },
        },
        Case {
            name: "event committed at another tick",
            mutate_actual: |s| {
                s.events.get_mut(&position(3))?.tick = 3;
                Some(())
            },
            expected: ExpectedReport {
                prior_checkpoint: Some(CHECKPOINT_1),
                ..timeline(
                    Kind::EventOrder,
                    3,
                    2,
                    (digest_only(identity(3)), digest_only(identity(3))),
                )
            },
        },
    ]
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn timeline_content_cases() -> Vec<Case> {
    vec![
        Case {
            name: "event canonical bytes differ",
            mutate_actual: |s| {
                s.events.get_mut(&position(1))?.payload = b"payload-x".to_vec();
                Some(())
            },
            expected: timeline(
                Kind::CanonicalBytes,
                1,
                1,
                (bytes(b"payload-1"), bytes(b"payload-x")),
            ),
        },
        Case {
            name: "event schema or upcaster differs",
            mutate_actual: |s| {
                s.events.get_mut(&position(1))?.schema = [0x52; 32];
                Some(())
            },
            expected: timeline(
                Kind::SchemaOrUpcaster,
                1,
                1,
                (digest_only(SCHEMA), digest_only([0x52; 32])),
            ),
        },
    ]
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn world_cut(ordinal: u32, sides: (DigestSizeV1, DigestSizeV1)) -> ExpectedReport {
    ExpectedReport {
        location: Location::WorldCut,
        kind: Kind::Artifact,
        id: WORLD_CUT,
        seq_or_ordinal: 0,
        tick: 2,
        output_ordinal: Some(ordinal),
        prior_checkpoint: Some(CHECKPOINT_1),
        ..timeline(Kind::Artifact, 0, 2, sides)
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn checkpoint(
    fold_cursor: u64,
    tick: u64,
    sides: (DigestSizeV1, DigestSizeV1),
    prior_checkpoint: Option<[u8; 32]>,
) -> ExpectedReport {
    ExpectedReport {
        location: Location::TickBoundary,
        prior_checkpoint,
        ..timeline(Kind::ProjectionCheckpoint, fold_cursor, tick, sides)
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
const fn checkpoint_digest(digest: [u8; 32], size: u64) -> DigestSizeV1 {
    DigestSizeV1 {
        digest: Some(digest),
        size: Some(size),
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn artifact_and_checkpoint_cases() -> Vec<Case> {
    vec![
        Case {
            name: "artifact bytes differ",
            mutate_actual: |s| {
                *s.world_cut_artifacts.get_mut(&artifact(1))? = b"plan-changed".to_vec();
                Some(())
            },
            expected: world_cut(1, (bytes(b"plan-artifact"), bytes(b"plan-changed"))),
        },
        Case {
            name: "artifact missing from actual",
            mutate_actual: |s| s.world_cut_artifacts.remove(&artifact(0)).map(|_| ()),
            expected: world_cut(0, (bytes(b"int1-artifact"), absent())),
        },
        Case {
            name: "extra artifact in actual",
            mutate_actual: |s| {
                s.world_cut_artifacts
                    .insert(artifact(2), b"result-artifact".to_vec());
                Some(())
            },
            expected: world_cut(2, (absent(), bytes(b"result-artifact"))),
        },
        Case {
            name: "checkpoint digest differs",
            mutate_actual: |s| {
                s.checkpoints.get_mut(&boundary(3, 2))?.digest = [0xee; 32];
                Some(())
            },
            expected: checkpoint(
                3,
                2,
                (
                    checkpoint_digest(CHECKPOINT_2, 120),
                    checkpoint_digest([0xee; 32], 120),
                ),
                Some(CHECKPOINT_1),
            ),
        },
        Case {
            name: "checkpoint missing from actual",
            mutate_actual: |s| s.checkpoints.remove(&boundary(2, 1)).map(|_| ()),
            expected: checkpoint(2, 1, (checkpoint_digest(CHECKPOINT_1, 100), absent()), None),
        },
        Case {
            name: "extra checkpoint in actual",
            mutate_actual: |s| {
                s.checkpoints.insert(
                    boundary(4, 3),
                    CheckpointDigestV1 {
                        digest: [0xc3; 32],
                        size: 140,
                    },
                );
                Some(())
            },
            expected: checkpoint(
                4,
                3,
                (absent(), checkpoint_digest([0xc3; 32], 140)),
                Some(CHECKPOINT_2),
            ),
        },
    ]
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn scheduler(
    position: u32,
    driver: &'static str,
    sides: (DigestSizeV1, DigestSizeV1),
) -> ExpectedReport {
    ExpectedReport {
        location: Location::Scheduler,
        scheduler_position: Some(position),
        driver: Some(driver),
        prior_checkpoint: Some(CHECKPOINT_1),
        ..timeline(Kind::EventOrder, 2, 2, sides)
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn driver(
    kind: Kind,
    position: u32,
    driver: &'static str,
    ordinal: u32,
    sides: (DigestSizeV1, DigestSizeV1),
) -> ExpectedReport {
    ExpectedReport {
        location: Location::DriverOutput,
        scheduler_position: Some(position),
        driver: Some(driver),
        output_ordinal: Some(ordinal),
        prior_checkpoint: Some(CHECKPOINT_1),
        ..timeline(kind, 2, 2, sides)
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn world_output(stream: &mut AuthoritativeStreamV1) -> Option<&mut ComparedDriverOutputV1> {
    stream.driver_outputs.get_mut(&output(0, WORLD_DRIVER, 0))
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn scheduler_cases() -> Vec<Case> {
    vec![
        Case {
            name: "scheduler runs another Driver",
            mutate_actual: |s| {
                "other.driver".clone_into(s.scheduler.get_mut(&slot(1))?);
                Some(())
            },
            expected: scheduler(
                1,
                AGENT_DRIVER,
                (bytes(AGENT_DRIVER.as_bytes()), bytes(b"other.driver")),
            ),
        },
        Case {
            name: "scheduler slot missing from actual",
            mutate_actual: |s| s.scheduler.remove(&slot(0)).map(|_| ()),
            expected: scheduler(0, WORLD_DRIVER, (bytes(WORLD_DRIVER.as_bytes()), absent())),
        },
        Case {
            name: "extra scheduler slot in actual",
            mutate_actual: |s| {
                s.scheduler.insert(slot(2), "late.driver".to_owned());
                Some(())
            },
            expected: scheduler(2, "late.driver", (absent(), bytes(b"late.driver"))),
        },
    ]
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn driver_output_cases() -> Vec<Case> {
    vec![
        Case {
            name: "driver output bytes differ",
            mutate_actual: |s| {
                world_output(s)?.outcome = DriverOutcomeV1::Output(b"world-changed".to_vec());
                Some(())
            },
            expected: driver(
                Kind::CanonicalBytes,
                0,
                WORLD_DRIVER,
                0,
                (bytes(b"world-output"), bytes(b"world-changed")),
            ),
        },
        Case {
            name: "driver output became a typed failure",
            mutate_actual: |s| {
                world_output(s)?.outcome = DriverOutcomeV1::TypedFailure(b"world-failed".to_vec());
                Some(())
            },
            expected: driver(
                Kind::TypedFailure,
                0,
                WORLD_DRIVER,
                0,
                (bytes(b"world-output"), bytes(b"world-failed")),
            ),
        },
        Case {
            name: "typed failure differs",
            mutate_actual: |s| {
                s.driver_outputs
                    .get_mut(&output(1, AGENT_DRIVER, 0))?
                    .outcome = DriverOutcomeV1::TypedFailure(b"agent-crash".to_vec());
                Some(())
            },
            expected: driver(
                Kind::TypedFailure,
                1,
                AGENT_DRIVER,
                0,
                (bytes(b"agent-timeout"), bytes(b"agent-crash")),
            ),
        },
    ]
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn driver_profile_and_presence_cases() -> Vec<Case> {
    vec![
        Case {
            name: "numeric profile differs",
            mutate_actual: |s| {
                world_output(s)?.numeric_profile_digest = [0x4f; 32];
                Some(())
            },
            expected: driver(
                Kind::NumericProfile,
                0,
                WORLD_DRIVER,
                0,
                (digest_only(NUMERIC_PROFILE), digest_only([0x4f; 32])),
            ),
        },
        Case {
            name: "prohibited operational input consumed",
            mutate_actual: |s| {
                world_output(s)?.prohibited_operational_input = Some(b"wall-clock-read".to_vec());
                Some(())
            },
            expected: driver(
                Kind::ProhibitedOperationalInput,
                0,
                WORLD_DRIVER,
                0,
                (absent(), bytes(b"wall-clock-read")),
            ),
        },
        Case {
            name: "driver output missing from actual",
            mutate_actual: |s| {
                s.driver_outputs
                    .remove(&output(0, WORLD_DRIVER, 0))
                    .map(|_| ())
            },
            expected: driver(
                Kind::CanonicalBytes,
                0,
                WORLD_DRIVER,
                0,
                (bytes(b"world-output"), absent()),
            ),
        },
        Case {
            name: "extra typed failure in actual",
            mutate_actual: |s| {
                s.driver_outputs.insert(
                    output(1, AGENT_DRIVER, 1),
                    driver_output(DriverOutcomeV1::TypedFailure(b"agent-retry".to_vec())),
                );
                Some(())
            },
            expected: driver(
                Kind::TypedFailure,
                1,
                AGENT_DRIVER,
                1,
                (absent(), bytes(b"agent-retry")),
            ),
        },
    ]
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn follow_on(entries: &[(Kind, u32)]) -> Vec<FollowOnMismatchV1> {
    entries
        .iter()
        .map(|&(kind, count)| FollowOnMismatchV1 { kind, count })
        .collect()
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn assert_case(name: &str, report: &DivergenceReportV1, expected: &ExpectedReport) {
    assert_eq!(report.location_kind, expected.location, "{name}");
    assert_eq!(report.mismatch_kind, expected.kind, "{name}");
    assert_eq!(report.timeline_or_worldcut_id, expected.id, "{name}");
    assert_eq!(
        report.timeline_seq_or_cut_ordinal, expected.seq_or_ordinal,
        "{name}"
    );
    assert_eq!(report.tick, expected.tick, "{name}");
    assert_eq!(
        report.scheduler_position, expected.scheduler_position,
        "{name}"
    );
    assert_eq!(
        report.driver_or_plugin_id.as_deref(),
        expected.driver,
        "{name}"
    );
    assert_eq!(report.output_ordinal, expected.output_ordinal, "{name}");
    assert_eq!(report.expected, expected.expected, "{name}");
    assert_eq!(report.actual, expected.actual, "{name}");
    assert_eq!(
        report.prior_matching_checkpoint_digest, expected.prior_checkpoint,
        "{name}"
    );
    assert_eq!(
        report.follow_on_counts,
        follow_on(&expected.follow_on),
        "{name}"
    );
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn every_location_and_mismatch_kind_produces_the_expected_report() -> TestResult {
    let cases: Vec<Case> = [
        timeline_cases(),
        timeline_order_cases(),
        timeline_content_cases(),
        artifact_and_checkpoint_cases(),
        scheduler_cases(),
        driver_output_cases(),
        driver_profile_and_presence_cases(),
    ]
    .into_iter()
    .flatten()
    .collect();
    let mut locations = Vec::new();
    let mut kinds = Vec::new();
    for case in &cases {
        let expected = baseline();
        let mut actual = baseline();
        assert_eq!((case.mutate_actual)(&mut actual), Some(()), "{}", case.name);
        let report = compare(&expected, &actual)?.ok_or(case.name)?;
        assert_case(case.name, &report, &case.expected);
        locations.push(report.location_kind);
        kinds.push(report.mismatch_kind);
    }
    locations.sort();
    locations.dedup();
    kinds.sort();
    kinds.dedup();
    assert_eq!(
        locations,
        [
            Location::TimelineSeq,
            Location::WorldCut,
            Location::TickBoundary,
            Location::Scheduler,
            Location::DriverOutput,
        ]
    );
    assert_eq!(
        kinds,
        [
            Kind::EventIdentity,
            Kind::EventOrder,
            Kind::CanonicalBytes,
            Kind::ProjectionCheckpoint,
            Kind::TypedFailure,
            Kind::Artifact,
            Kind::SchemaOrUpcaster,
            Kind::NumericProfile,
            Kind::ProhibitedOperationalInput,
        ]
    );
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn equal_streams_give_no_report() -> TestResult {
    assert_eq!(compare(&baseline(), &baseline())?, None);
    let empty = AuthoritativeStreamV1::default();
    assert_eq!(compare(&empty, &empty)?, None);
    Ok(())
}

/// A test-only run record: the operational fields are captured but are not
/// part of the authoritative stream.
struct RunCapture {
    temp_dir: &'static str,
    wall_clock_ns: u64,
    rendered_frames: u32,
    log_lines: Vec<&'static str>,
    authoritative: AuthoritativeStreamV1,
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn operational_variation_gives_no_report() -> TestResult {
    let first = RunCapture {
        temp_dir: "/tmp/run-a",
        wall_clock_ns: 1_000,
        rendered_frames: 60,
        log_lines: vec!["level=info start"],
        authoritative: baseline(),
    };
    let second = RunCapture {
        temp_dir: "/var/tmp/run-b",
        wall_clock_ns: 9_999_999,
        rendered_frames: 3,
        log_lines: vec!["level=debug start", "level=debug tick 1"],
        authoritative: baseline(),
    };
    assert_ne!(first.temp_dir, second.temp_dir);
    assert_ne!(first.wall_clock_ns, second.wall_clock_ns);
    assert_ne!(first.rendered_frames, second.rendered_frames);
    assert_ne!(first.log_lines, second.log_lines);
    assert_eq!(compare(&first.authoritative, &second.authoritative)?, None);
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn only_the_first_mismatch_is_reported_and_the_rest_are_counted() -> TestResult {
    let expected = baseline();
    let mut actual = baseline();
    world_output(&mut actual).ok_or("world output")?.outcome =
        DriverOutcomeV1::Output(b"world-changed".to_vec());
    actual
        .checkpoints
        .get_mut(&boundary(3, 2))
        .ok_or("checkpoint")?
        .digest = [0xee; 32];
    *actual
        .world_cut_artifacts
        .get_mut(&artifact(0))
        .ok_or("artifact")? = b"int1-changed".to_vec();
    actual
        .events
        .get_mut(&position(3))
        .ok_or("event 3")?
        .payload = b"payload-z".to_vec();
    actual.events.get_mut(&position(2)).ok_or("event 2")?.schema = [0x52; 32];

    // The TimelineSeq location ranks first, and inside it seq 2 ranks before
    // seq 3 although CanonicalBytes ranks before SchemaOrUpcaster.
    let report = compare(&expected, &actual)?.ok_or("report")?;
    assert_case(
        "first of several",
        &report,
        &ExpectedReport {
            follow_on: vec![
                (Kind::CanonicalBytes, 2),
                (Kind::ProjectionCheckpoint, 1),
                (Kind::Artifact, 1),
            ],
            ..timeline(
                Kind::SchemaOrUpcaster,
                2,
                1,
                (digest_only(SCHEMA), digest_only([0x52; 32])),
            )
        },
    );

    // At one coordinate the mismatch kind order decides.
    let mut same_coordinate = baseline();
    let event = same_coordinate
        .events
        .get_mut(&position(1))
        .ok_or("event 1")?;
    event.payload = b"payload-y".to_vec();
    event.schema = [0x53; 32];
    let report = compare(&expected, &same_coordinate)?.ok_or("report")?;
    assert_case(
        "same coordinate",
        &report,
        &ExpectedReport {
            follow_on: vec![(Kind::SchemaOrUpcaster, 1)],
            ..timeline(
                Kind::CanonicalBytes,
                1,
                1,
                (bytes(b"payload-1"), bytes(b"payload-y")),
            )
        },
    );

    // A WorldCut mismatch outranks every later location kind.
    let mut later_locations = baseline();
    later_locations.events = expected.events.clone();
    later_locations.world_cut_artifacts = actual.world_cut_artifacts.clone();
    later_locations.checkpoints = actual.checkpoints.clone();
    later_locations.driver_outputs = actual.driver_outputs.clone();
    let report = compare(&expected, &later_locations)?.ok_or("report")?;
    assert_eq!(report.location_kind, Location::WorldCut);
    assert_eq!(
        report.follow_on_counts,
        follow_on(&[(Kind::CanonicalBytes, 1), (Kind::ProjectionCheckpoint, 1)])
    );
    Ok(())
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn many_payload_mismatches(count: u64) -> (AuthoritativeStreamV1, AuthoritativeStreamV1) {
    let mut expected = AuthoritativeStreamV1::default();
    let mut actual = AuthoritativeStreamV1::default();
    for seq in 1..=count {
        let mut event = ComparedEventV1 {
            tick: 1,
            identity: *blake3::hash(&seq.to_be_bytes()).as_bytes(),
            schema: SCHEMA,
            payload: vec![0],
        };
        expected.events.insert(position(seq), event.clone());
        event.payload = vec![1];
        actual.events.insert(position(seq), event);
    }
    (expected, actual)
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn follow_on_counts_are_bounded() -> TestResult {
    let bound = u64::from(MAX_FOLLOW_ON_COUNT_V1);
    for (others, reported) in [
        (3, 3),
        (bound - 1, MAX_FOLLOW_ON_COUNT_V1 - 1),
        (bound, MAX_FOLLOW_ON_COUNT_V1),
        (bound + 1, MAX_FOLLOW_ON_COUNT_V1),
    ] {
        let (expected, actual) = many_payload_mismatches(others + 1);
        let report = compare(&expected, &actual)?.ok_or("report")?;
        assert_eq!(report.timeline_seq_or_cut_ordinal, 1);
        assert_eq!(report.mismatch_kind, Kind::CanonicalBytes);
        assert_eq!(
            report.follow_on_counts,
            follow_on(&[(Kind::CanonicalBytes, reported)])
        );
    }
    Ok(())
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn reports_carry_digest_and_size_and_never_payload_bytes() -> TestResult {
    let secret_expected = b"SECRET-EXPECTED-PAYLOAD-0123456789".to_vec();
    let secret_actual = b"SECRET-ACTUAL-PAYLOAD-9876543210".to_vec();
    let mutations: [PayloadMutation; 5] = [
        |s, payload| {
            s.events.get_mut(&position(1))?.payload = payload;
            Some(())
        },
        |s, payload| {
            *s.world_cut_artifacts.get_mut(&artifact(0))? = payload;
            Some(())
        },
        |s, payload| {
            world_output(s)?.outcome = DriverOutcomeV1::Output(payload);
            Some(())
        },
        |s, payload| {
            world_output(s)?.outcome = DriverOutcomeV1::TypedFailure(payload);
            Some(())
        },
        |s, payload| {
            world_output(s)?.prohibited_operational_input = Some(payload);
            Some(())
        },
    ];
    for mutate in mutations {
        let mut expected = baseline();
        let mut actual = baseline();
        assert_eq!(mutate(&mut expected, secret_expected.clone()), Some(()));
        assert_eq!(mutate(&mut actual, secret_actual.clone()), Some(()));
        let report = compare(&expected, &actual)?.ok_or("report")?;
        let encoded = report.to_canonical_cbor()?;
        assert!(!contains(&encoded, &secret_expected));
        assert!(!contains(&encoded, &secret_actual));
        assert!(!contains(&encoded, b"SECRET"));
        assert_eq!(report.expected, bytes(&secret_expected));
        assert_eq!(report.actual, bytes(&secret_actual));
    }
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn a_coordinate_the_dvr1_shape_rejects_is_an_error() -> TestResult {
    let expected = baseline();
    let at_limit = "d".repeat(128);
    let over_limit = "d".repeat(129);

    let mut actual = baseline();
    actual.scheduler.insert(slot(2), at_limit.clone());
    let report = compare(&expected, &actual)?.ok_or("report")?;
    assert_eq!(report.driver_or_plugin_id, Some(at_limit));

    let mut actual = baseline();
    actual.scheduler.insert(slot(2), over_limit);
    assert!(first_divergence_v1(&context(), &expected, &actual).is_err());

    let mut actual = baseline();
    actual
        .scheduler
        .insert(slot(u32::from(u16::MAX)), WORLD_DRIVER.to_owned());
    assert!(compare(&expected, &actual)?.is_some());

    let mut actual = baseline();
    actual
        .scheduler
        .insert(slot(u32::from(u16::MAX) + 1), WORLD_DRIVER.to_owned());
    assert!(first_divergence_v1(&context(), &expected, &actual).is_err());

    let mut actual = baseline();
    actual.events.insert(position(u64::MAX), event(1, 9));
    assert!(first_divergence_v1(&context(), &expected, &actual).is_err());
    Ok(())
}
