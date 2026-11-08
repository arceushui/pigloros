#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
// The ADR-064 counterfactual Fork exists only on Linux.
#![cfg(target_os = "linux")]

//! Public-interface tests for the G-FORK non-interference capture adapter
//! (ADR-062 Revision 8 slice N4, #1232; owner note
//! `ADR-062_R8_NonInterference_Fork`).
//!
//! Acceptance criteria, for each variant S, D, W and C in modes L, R and F:
//!
//! - Control/canary one-delta proof over the Fork artifacts:
//!   `every_g_fork_pair_differs_only_in_its_declared_unauthorized_value` and
//!   `the_unauthorized_value_reaches_the_factual_timeline_and_no_fork_artifact`.
//! - Raw typed captures go through the #181 normalization:
//!   `a_raw_g_fork_capture_is_admitted_only_through_the_normalizer`.
//! - Row-specific equality and first-coordinate order: the matrix test
//!   requires equality at every surface and one result digest in every mode;
//!   `a_leaking_capture_diverges_at_the_first_surface_it_reaches` requires the
//!   #181 comparison to report the first surface a leak reaches.
//! - No factual-suffix splicing and no unauthorized bytes in Fork artifacts:
//!   `the_unauthorized_value_reaches_the_factual_timeline_and_no_fork_artifact`.
//! - One verifier-accepted signed NIA1 per executed case, only those flipped,
//!   mode A non-executed: the matrix test, with
//!   `non_interference_evidence.rs` for the verifier and the flips.
//! - Snapshots and `ReproManifest` are empty surfaces, and no `RCP1` carries a
//!   Plugin or Projection snapshot digest:
//!   `the_snapshot_surfaces_are_empty_and_no_checkpoint_holds_a_snapshot`.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use pos_conformance::counterfactual::checkpoint::RecomputeCheckpointV1;
use pos_conformance::{
    execute_non_interference_pair, non_interference_surface_names_v1,
    normalize_non_interference_capture_v1, ExecutionModeV1, NonInterferenceExecutionArtifactV1,
    NonInterferenceExecutionErrorV1, NonInterferenceFixturePairV1, NonInterferenceRawCaptureV1,
    NonInterferenceRawOperationalV1, NonInterferenceVariantV1,
    MAX_NON_INTERFERENCE_EXECUTION_ARTIFACT_BYTES_V1,
};
use pos_core::{EventStore, SeqRange, TimelineId};
use pos_experiment::fork_artifacts::{
    record_fork_v1, run_fork_v1, ForkArtifactKindV1, FACTUAL_TIMELINE_ID_V1,
};
use pos_experiment::non_interference_harness::fixture_evidence::non_interference_fixture_executor_key_v1;
use pos_experiment::non_interference_harness::g_fork::{
    g_fork_capture_v1, g_fork_fixture_v1, g_fork_permitted_input_v1, g_fork_subject_fixture_v1,
    serve_g_fork_local_subject_v1, GForkRunnerV1, G_FORK_CANARY_UNAUTHORIZED_V1,
    G_FORK_CONTROL_UNAUTHORIZED_V1, G_FORK_CUT_TICK_V1, G_FORK_FIXTURE_ID_V1,
    G_FORK_STORE_DIRECTORY_V1,
};
use pos_experiment::non_interference_harness::{
    NonInterferenceHarnessV1, NonInterferenceLocalProcessRunnerV1, NonInterferenceLocalRequestV1,
    NonInterferenceNonExecutedCauseV1, NonInterferencePreparationV1,
    NonInterferenceSignedExecutionV1, NON_INTERFERENCE_LOCAL_REQUEST_MAGIC_V1,
    NON_INTERFERENCE_PUBLICATION_DIRECTORY_V1,
};
use serde_json::{json, Value};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Coordinate = (NonInterferenceVariantV1, ExecutionModeV1);

const SUBJECT: &str = env!("CARGO_BIN_EXE_pos-ni-g-fork-subject");
const VARIANTS: [NonInterferenceVariantV1; 4] = [
    NonInterferenceVariantV1::Success,
    NonInterferenceVariantV1::Denial,
    NonInterferenceVariantV1::WarmCache,
    NonInterferenceVariantV1::ColdCache,
];
const MODES: [ExecutionModeV1; 4] = [
    ExecutionModeV1::Local,
    ExecutionModeV1::AirGapped,
    ExecutionModeV1::Replay,
    ExecutionModeV1::Fork,
];
/// The surface ordinal of the `CounterfactualPlan` surface.
const PLAN_SURFACE: u16 = 1;
/// The surface ordinal of the exports surface, the last one.
const EXPORTS_SURFACE: u16 = 8;

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/conformance")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        text.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        text.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
        text
    })
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// No unauthorized value appears in `bytes`, raw or as hex.
fn assert_no_unauthorized_bytes(bytes: &[u8], context: &str) {
    for value in [
        G_FORK_CONTROL_UNAUTHORIZED_V1,
        G_FORK_CANARY_UNAUTHORIZED_V1,
    ] {
        assert!(!contains(bytes, value), "unauthorized bytes in {context}");
        assert!(
            !contains(bytes, hex(value).as_bytes()),
            "hex unauthorized bytes in {context}"
        );
    }
}

const fn variant_letter(variant: NonInterferenceVariantV1) -> &'static str {
    match variant {
        NonInterferenceVariantV1::Success => "S",
        NonInterferenceVariantV1::Denial => "D",
        NonInterferenceVariantV1::WarmCache => "W",
        NonInterferenceVariantV1::ColdCache => "C",
    }
}

const fn mode_letter(mode: ExecutionModeV1) -> &'static str {
    match mode {
        ExecutionModeV1::Local => "L",
        ExecutionModeV1::AirGapped => "A",
        ExecutionModeV1::Replay => "R",
        ExecutionModeV1::Fork => "F",
    }
}

fn case_id(variant: NonInterferenceVariantV1, mode: ExecutionModeV1) -> String {
    format!(
        "{G_FORK_FIXTURE_ID_V1}-{}-{}",
        variant_letter(variant),
        mode_letter(mode)
    )
}

/// The Local runner of the G-FORK subject binary. The coverage profile
/// variable is the one declared environment variable it passes on.
#[cfg_attr(coverage_nightly, coverage(off))]
fn local_runner(work: &Path) -> TestResult<NonInterferenceLocalProcessRunnerV1> {
    let runner =
        NonInterferenceLocalProcessRunnerV1::new(PathBuf::from(SUBJECT), work.join("local"))?;
    Ok(match std::env::var("LLVM_PROFILE_FILE") {
        Ok(value) => runner.with_env("LLVM_PROFILE_FILE", value),
        Err(_) => runner,
    })
}

fn g_fork_harness(work: &Path) -> TestResult<NonInterferenceHarnessV1> {
    let public = non_interference_fixture_executor_key_v1().public_key();
    Ok(
        NonInterferenceHarnessV1::new(non_interference_fixture_executor_key_v1(), vec![public])
            .with_runner(Box::new(local_runner(work)?))
            .with_runner(Box::new(GForkRunnerV1::replay(work.join("replay"))))
            .with_runner(Box::new(GForkRunnerV1::fork(work.join("fork")))),
    )
}

fn matrix_case(id: &str) -> TestResult<Value> {
    let matrix: Value = serde_json::from_slice(&fs::read(
        fixtures_root().join("matrix/execution-matrix.json"),
    )?)?;
    matrix["cases"]
        .as_array()
        .and_then(|cases| cases.iter().find(|case| case["case_id"] == json!(id)))
        .cloned()
        .ok_or_else(|| format!("no matrix case {id}").into())
}

/// Every checked-in NIA1 of the row by coordinate, with its file name.
fn checked_in() -> TestResult<BTreeMap<Coordinate, (String, NonInterferenceExecutionArtifactV1)>> {
    let mut artifacts = BTreeMap::new();
    for entry in fs::read_dir(fixtures_root().join(NON_INTERFERENCE_PUBLICATION_DIRECTORY_V1))? {
        let path = entry?.path();
        let artifact = NonInterferenceExecutionArtifactV1::from_canonical_cbor(&fs::read(&path)?)?;
        if artifact.fixture_id == G_FORK_FIXTURE_ID_V1 {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or("unnamed NIA1")?
                .to_owned();
            artifacts.insert((artifact.variant, artifact.mode), (name, artifact));
        }
    }
    Ok(artifacts)
}

/// The raw capture of one in-process records-form Fork run.
fn fork_capture(
    variant: NonInterferenceVariantV1,
    unauthorized_value: &[u8],
) -> TestResult<NonInterferenceRawCaptureV1> {
    let fixture =
        g_fork_subject_fixture_v1(&g_fork_permitted_input_v1(variant), unauthorized_value)?;
    Ok(g_fork_capture_v1(&run_fork_v1(
        &fixture,
        ExecutionModeV1::Local,
    )?)?)
}

// ---------------------------------------------------------------------------
// Matrix
// ---------------------------------------------------------------------------

/// Run every G-FORK coordinate once and return the executed cases. Every
/// Air-Gapped case must be the typed non-executed `Unavailable` with no claim.
fn execute_every_coordinate(
    work: &Path,
) -> TestResult<BTreeMap<Coordinate, NonInterferenceSignedExecutionV1>> {
    let mut harness = g_fork_harness(work)?;
    let mut executed = BTreeMap::new();
    for variant in VARIANTS {
        for mode in MODES {
            let fixture = g_fork_fixture_v1(variant, mode)?;
            let outcome = harness.execute_case(&fixture);
            assert_no_unauthorized_bytes(format!("{outcome:?}").as_bytes(), "an outcome");
            let id = case_id(variant, mode);
            if mode == ExecutionModeV1::AirGapped {
                assert_eq!(
                    outcome.non_executed_cause(),
                    Some(NonInterferenceNonExecutedCauseV1::Unavailable),
                    "{id}"
                );
                assert_eq!(outcome.claim(), None, "{id}");
            } else {
                assert_eq!(outcome.claim(), Some(true), "{id}: {outcome:?}");
                let execution = outcome.execution().ok_or("not executed")?.clone();
                executed.insert((variant, mode), execution);
            }
        }
    }
    Ok(executed)
}

/// TEMPORARY (removed before review): the directory the matrix test exports
/// its NIA1 to, for the recorded CI run.
const EXPORT_ENV: &str = "PIGLOROS_NI_G_FORK_EXPORT";

#[cfg_attr(coverage_nightly, coverage(off))]
fn export(
    directory: &Path,
    executed: &BTreeMap<Coordinate, NonInterferenceSignedExecutionV1>,
) -> TestResult {
    for execution in executed.values() {
        pos_experiment::non_interference_harness::publish_non_interference_execution_v1(
            directory, execution,
        )?;
    }
    Ok(())
}

#[test]
fn every_g_fork_coordinate_executes_or_stays_typed_non_executed_and_matches_its_nia1() -> TestResult
{
    let work = tempfile::tempdir()?;
    let executed = execute_every_coordinate(work.path())?;
    if let Ok(directory) = std::env::var(EXPORT_ENV) {
        export(Path::new(&directory), &executed)?;
    }
    assert_eq!(executed.len(), 12);

    let checked_in = checked_in()?;
    for ((variant, mode), execution) in &executed {
        let id = case_id(*variant, *mode);
        let artifact = execution.artifact();
        assert!(
            execution.canonical_bytes().len() <= MAX_NON_INTERFERENCE_EXECUTION_ARTIFACT_BYTES_V1
        );
        assert_no_unauthorized_bytes(execution.canonical_bytes(), &id);
        assert_eq!(
            execution.preparation(),
            NonInterferencePreparationV1::for_variant(*variant)
        );
        // `AuthEq` = `PublicEq` = `OpEq` across L = R = F: one result in every mode.
        let local = executed
            .get(&(*variant, ExecutionModeV1::Local))
            .ok_or("no Local execution")?;
        assert_eq!(
            artifact.result_digest,
            local.artifact().result_digest,
            "{id}"
        );
        // The independently derived expected digest.
        let case = matrix_case(&id)?;
        assert_eq!(case["executed"], json!(true), "{id}");
        assert_eq!(
            case["expected_result_digest"],
            json!(hex(&artifact.result_digest)),
            "{id}"
        );
        // The checked-in NIA1 of the coordinate: every body field but the
        // execution provenance and the signature.
        let (name, recorded) = checked_in
            .get(&(*variant, *mode))
            .ok_or_else(|| format!("no checked-in NIA1 for {id}"))?;
        let mut reproduced = artifact.clone();
        reproduced.execution_provenance_digest = recorded.execution_provenance_digest;
        reproduced.signature = recorded.signature;
        assert_eq!(&reproduced, recorded, "{id}");
        assert_eq!(
            case["expected_result"]["nia1_content_digest"],
            json!(name.trim_end_matches(".nia1"))
        );
    }
    // The Replay runner binds its mode into the provenance: Replay and Fork
    // differ there, and only there.
    let replay = executed
        .get(&(NonInterferenceVariantV1::Success, ExecutionModeV1::Replay))
        .ok_or("no Replay execution")?;
    let fork = executed
        .get(&(NonInterferenceVariantV1::Success, ExecutionModeV1::Fork))
        .ok_or("no Fork execution")?;
    assert_ne!(
        replay.artifact().execution_provenance_digest,
        fork.artifact().execution_provenance_digest
    );
    // Every cold run gets a new directory and every warm case one shared
    // directory: three cold variants of two runs and one warm case. The warm
    // directory's artifact store holds one export: the priming, control and
    // canary runs export the same artifacts.
    for runner in ["local", "replay", "fork"] {
        let directories = fs::read_dir(work.path().join(runner))?.collect::<Result<Vec<_>, _>>()?;
        assert_eq!(directories.len(), 7, "{runner}");
        for directory in directories {
            let stored = fs::read_dir(directory.path().join(G_FORK_STORE_DIRECTORY_V1))?.count();
            assert_eq!(stored, 7, "{runner}");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Fixtures: the one-delta proof
// ---------------------------------------------------------------------------

#[test]
fn every_g_fork_pair_differs_only_in_its_declared_unauthorized_value() -> TestResult {
    for variant in VARIANTS {
        let pairs = MODES
            .iter()
            .map(|mode| g_fork_fixture_v1(variant, *mode))
            .collect::<Result<Vec<_>, _>>()?;
        for pair in &pairs {
            pair.validate()?;
            assert_eq!(pair.permitted_input, g_fork_permitted_input_v1(variant));
            assert_eq!(
                pair.control_unauthorized_value,
                G_FORK_CONTROL_UNAUTHORIZED_V1
            );
            assert_eq!(
                pair.canary_unauthorized_value,
                G_FORK_CANARY_UNAUTHORIZED_V1
            );
            for value in [
                G_FORK_CONTROL_UNAUTHORIZED_V1,
                G_FORK_CANARY_UNAUTHORIZED_V1,
            ] {
                assert!(!contains(&pair.permitted_input, value));
            }
            // Every mode runs the same admitted pair.
            assert_eq!(pair.fixture_digest, pairs[0].fixture_digest);
        }
        // The subject fixtures of the two members differ only where the host
        // places the unauthorized value: the factual suffix and the hidden
        // participant field.
        let permitted = g_fork_permitted_input_v1(variant);
        let control = g_fork_subject_fixture_v1(&permitted, G_FORK_CONTROL_UNAUTHORIZED_V1)?;
        let canary = g_fork_subject_fixture_v1(&permitted, G_FORK_CANARY_UNAUTHORIZED_V1)?;
        assert_ne!(control.factual_suffix, canary.factual_suffix);
        assert_ne!(
            control.hidden_participant_field,
            canary.hidden_participant_field
        );
        let mut aligned = canary.clone();
        aligned.factual_suffix.clone_from(&control.factual_suffix);
        aligned
            .hidden_participant_field
            .clone_from(&control.hidden_participant_field);
        assert_eq!(aligned, control);
        // The permitted input alone decides the Intervention.
        assert_eq!(
            control.intervention.value_digest,
            *blake3::hash(&permitted).as_bytes()
        );
    }
    // One to three factual suffix inputs, by the value's length.
    let permitted = g_fork_permitted_input_v1(NonInterferenceVariantV1::Success);
    for (value, ticks) in [(&b"abc"[..], 1), (b"abcd", 2), (b"abcde", 3)] {
        let fixture = g_fork_subject_fixture_v1(&permitted, value)?;
        assert_eq!(fixture.factual_suffix, vec![value.to_vec(); ticks]);
        assert_eq!(fixture.hidden_participant_field, value);
    }
    assert_eq!(
        NonInterferenceFixturePairV1::try_new(
            G_FORK_FIXTURE_ID_V1,
            NonInterferenceVariantV1::Success,
            ExecutionModeV1::Local,
            permitted,
            G_FORK_CONTROL_UNAUTHORIZED_V1.to_vec(),
            G_FORK_CONTROL_UNAUTHORIZED_V1.to_vec(),
        ),
        Err(NonInterferenceExecutionErrorV1::FixtureInvalid)
    );
    Ok(())
}

#[test]
fn the_unauthorized_value_reaches_the_factual_timeline_and_no_fork_artifact() -> TestResult {
    let permitted = g_fork_permitted_input_v1(NonInterferenceVariantV1::Success);
    let mut captures = Vec::new();
    for value in [
        G_FORK_CONTROL_UNAUTHORIZED_V1,
        G_FORK_CANARY_UNAUTHORIZED_V1,
    ] {
        let fixture = g_fork_subject_fixture_v1(&permitted, value)?;
        let (export, recorded) = record_fork_v1(&fixture, ExecutionModeV1::Local)?;
        // The host really placed the value after the cut: in every factual
        // suffix input and in the participant Driver's Events.
        let events = recorded.store().read(
            TimelineId::from_ulid(ulid::Ulid::from_bytes(FACTUAL_TIMELINE_ID_V1)),
            SeqRange::all(),
        )?;
        let carrying = events
            .iter()
            .filter(|event| contains(event.payload.as_slice(), value))
            .count();
        assert_eq!(carrying, 2 * fixture.factual_suffix.len());
        assert!(export.factual_head.tick > G_FORK_CUT_TICK_V1);
        // ... and no artifact carries it.
        for artifact in &export.artifacts {
            assert_no_unauthorized_bytes(&artifact.bytes, "a Fork artifact");
        }
        let capture = g_fork_capture_v1(&export)?;
        for record in capture.authoritative.iter().chain(&capture.public) {
            assert_no_unauthorized_bytes(record, "a capture surface");
        }
        captures.push((export, capture));
    }
    // The factual Timelines differ, the Fork artifacts and captures do not.
    assert_ne!(captures[0].0.factual_head, captures[1].0.factual_head);
    assert_eq!(captures[0].0.artifacts, captures[1].0.artifacts);
    assert_eq!(captures[0].1, captures[1].1);
    Ok(())
}

// ---------------------------------------------------------------------------
// Capture adapter through its public seam
// ---------------------------------------------------------------------------

#[test]
fn the_snapshot_surfaces_are_empty_and_no_checkpoint_holds_a_snapshot() -> TestResult {
    let fixture = g_fork_subject_fixture_v1(
        &g_fork_permitted_input_v1(NonInterferenceVariantV1::Success),
        G_FORK_CONTROL_UNAUTHORIZED_V1,
    )?;
    let export = run_fork_v1(&fixture, ExecutionModeV1::Local)?;
    let checkpoints = export
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind == ForkArtifactKindV1::Checkpoint)
        .map(|artifact| RecomputeCheckpointV1::from_canonical_cbor(&artifact.bytes))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(checkpoints.len(), 2);
    for checkpoint in &checkpoints {
        assert!(checkpoint.plugin_state_digests.is_empty());
        assert!(checkpoint.projection_digests.is_empty());
    }
    let capture = g_fork_capture_v1(&export)?;
    let names = non_interference_surface_names_v1(G_FORK_FIXTURE_ID_V1).ok_or("no profile")?;
    assert_eq!(capture.surface_names, names);
    for surface in ["snapshots", "ReproManifest"] {
        let at = names
            .iter()
            .position(|name| *name == surface)
            .ok_or("no surface")?;
        // The empty CBOR array.
        assert_eq!(capture.authoritative[at], [0x80]);
        assert_eq!(capture.public[at], [0x80]);
    }
    // The exports surface lists every artifact; the plan's parent cut is the
    // factual Timeline at the cut.
    assert_eq!(names[8], "exports");
    assert_eq!(capture.public[8][0], 0x80 | 7);
    assert!(contains(&capture.authoritative[0], &FACTUAL_TIMELINE_ID_V1));
    Ok(())
}

#[test]
fn a_raw_g_fork_capture_is_admitted_only_through_the_normalizer() -> TestResult {
    let raw = fork_capture(
        NonInterferenceVariantV1::Success,
        G_FORK_CONTROL_UNAUTHORIZED_V1,
    )?;
    let normalized = normalize_non_interference_capture_v1(G_FORK_FIXTURE_ID_V1, raw.clone())?;
    assert_eq!(normalized.authoritative, raw.authoritative);
    assert_eq!(normalized.public, raw.public);
    // Each operational surface is the digest of its authoritative record.
    for ((raw_operational, operational), authoritative) in raw
        .operational
        .iter()
        .zip(&normalized.operational)
        .zip(&raw.authoritative)
    {
        let digest = blake3::hash(authoritative).as_bytes().to_vec();
        assert_eq!(operational, &digest);
        assert_eq!(
            raw_operational,
            &NonInterferenceRawOperationalV1::ByteExact(digest)
        );
    }
    let mut missing = raw.clone();
    missing.surface_names.pop();
    assert_eq!(
        normalize_non_interference_capture_v1(G_FORK_FIXTURE_ID_V1, missing),
        Err(NonInterferenceExecutionErrorV1::CaptureUnavailable)
    );
    let mut empty = raw.clone();
    empty.authoritative[0].clear();
    assert_eq!(
        normalize_non_interference_capture_v1(G_FORK_FIXTURE_ID_V1, empty),
        Err(NonInterferenceExecutionErrorV1::CaptureOutOfBounds)
    );
    let mut other_normalizer = raw;
    other_normalizer.operational[0] = NonInterferenceRawOperationalV1::OmitOperational {
        excluded_sensitive: Vec::new(),
    };
    assert_eq!(
        normalize_non_interference_capture_v1(G_FORK_FIXTURE_ID_V1, other_normalizer),
        Err(NonInterferenceExecutionErrorV1::CaptureUnavailable)
    );
    // An export without a plan is no capture.
    let mut export = run_fork_v1(
        &g_fork_subject_fixture_v1(
            &g_fork_permitted_input_v1(NonInterferenceVariantV1::Success),
            G_FORK_CONTROL_UNAUTHORIZED_V1,
        )?,
        ExecutionModeV1::Local,
    )?;
    export
        .artifacts
        .retain(|artifact| artifact.kind != ForkArtifactKindV1::CounterfactualPlan);
    assert_eq!(
        g_fork_capture_v1(&export),
        Err(NonInterferenceNonExecutedCauseV1::Unavailable)
    );
    Ok(())
}

/// Compare the pair of `fixture` through the #181 framework with a control
/// capture of the honest subject and a canary capture that `leak` alters.
fn leaking_case(
    fixture: &NonInterferenceFixturePairV1,
    leak: impl Fn(&[u8], &[u8]) -> Option<NonInterferenceRawCaptureV1>,
) -> TestResult<pos_conformance::NonInterferenceCaseV1> {
    Ok(execute_non_interference_pair(fixture, |run| {
        let raw = if run.unauthorized_value == G_FORK_CANARY_UNAUTHORIZED_V1 {
            leak(run.subject.permitted_input, run.unauthorized_value)
        } else {
            fork_capture(NonInterferenceVariantV1::Success, run.unauthorized_value).ok()
        };
        let mut raw = raw.ok_or(NonInterferenceExecutionErrorV1::CaptureUnavailable)?;
        raw.provenance_digest = [1; 32];
        normalize_non_interference_capture_v1(run.subject.fixture_id, raw)
    })?)
}

#[test]
fn a_leaking_capture_diverges_at_the_first_surface_it_reaches() -> TestResult {
    let fixture = g_fork_fixture_v1(NonInterferenceVariantV1::Success, ExecutionModeV1::Fork)?;
    // A value that reached the plan reaches the plan surface first: here it
    // decides the Intervention. The Fork parent/cut before it stays equal.
    let case = leaking_case(&fixture, |permitted, value| {
        let spliced = [permitted, value].concat();
        g_fork_subject_fixture_v1(&spliced, value)
            .ok()
            .and_then(|leaked| run_fork_v1(&leaked, ExecutionModeV1::Local).ok())
            .and_then(|export| g_fork_capture_v1(&export).ok())
    })?;
    assert!(!case.authoritative_equal && !case.public_equal && !case.operational_equal);
    let divergence = case.first_divergence.ok_or("no divergence")?;
    assert_eq!(divergence.surface_ordinal, PLAN_SURFACE);
    // A value that reached only the last surface is reported there: every
    // surface before it is equal.
    let case = leaking_case(&fixture, |_, value| {
        fork_capture(NonInterferenceVariantV1::Success, value)
            .ok()
            .map(|mut raw| {
                raw.authoritative[8].extend_from_slice(value);
                raw
            })
    })?;
    assert!(!case.authoritative_equal && case.public_equal && case.operational_equal);
    let divergence = case.first_divergence.ok_or("no divergence")?;
    assert_eq!(divergence.surface_ordinal, EXPORTS_SURFACE);
    Ok(())
}

// ---------------------------------------------------------------------------
// The Local subject
// ---------------------------------------------------------------------------

/// Spawn the subject binary in `directory` with `request` on its standard
/// input and return its exit status and standard output.
#[cfg_attr(coverage_nightly, coverage(off))]
fn spawn_subject(directory: &Path, request: &[u8]) -> TestResult<(bool, Vec<u8>)> {
    let mut command = Command::new(SUBJECT);
    command
        .current_dir(directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Ok(value) = std::env::var("LLVM_PROFILE_FILE") {
        command.env("LLVM_PROFILE_FILE", value);
    }
    let mut child = command.spawn()?;
    child.stdin.take().ok_or("no stdin")?.write_all(request)?;
    let output = child.wait_with_output()?;
    Ok((output.status.success(), output.stdout))
}

#[test]
fn the_local_subject_serves_one_request_or_writes_nothing() -> TestResult {
    let work = tempfile::tempdir()?;
    let request = NonInterferenceLocalRequestV1 {
        magic: NON_INTERFERENCE_LOCAL_REQUEST_MAGIC_V1.to_owned(),
        version: 1,
        fixture_id: G_FORK_FIXTURE_ID_V1.to_owned(),
        variant: NonInterferenceVariantV1::Success,
        mode: ExecutionModeV1::Local,
        preparation: NonInterferencePreparationV1::Cold,
        permitted_input: g_fork_permitted_input_v1(NonInterferenceVariantV1::Success),
        unauthorized_value: G_FORK_CONTROL_UNAUTHORIZED_V1.to_vec(),
    };
    let bytes = pos_crypto::canonical::encode(&request)?.as_slice().to_vec();
    // In-process: the frame is written and the store holds the export.
    let mut output = Vec::new();
    serve_g_fork_local_subject_v1(bytes.as_slice(), &mut output, work.path())?;
    assert!(!output.is_empty());
    assert_eq!(
        fs::read_dir(work.path().join(G_FORK_STORE_DIRECTORY_V1))?.count(),
        7
    );
    // A fresh process serves the same request.
    let (success, stdout) = spawn_subject(work.path(), &bytes)?;
    assert!(success);
    assert_eq!(stdout, output);
    // A malformed request writes nothing and fails.
    let mut nothing = Vec::new();
    assert_eq!(
        serve_g_fork_local_subject_v1(&b"not a request"[..], &mut nothing, work.path()),
        Err(NonInterferenceNonExecutedCauseV1::Unavailable)
    );
    assert!(nothing.is_empty());
    let (success, stdout) = spawn_subject(work.path(), b"not a request")?;
    assert!(!success);
    assert!(stdout.is_empty());
    // A run directory that cannot hold the store is unavailable.
    let blocked = work.path().join("blocked");
    fs::write(&blocked, b"a file, not a directory")?;
    assert_eq!(
        serve_g_fork_local_subject_v1(bytes.as_slice(), &mut nothing, &blocked),
        Err(NonInterferenceNonExecutedCauseV1::Unavailable)
    );
    assert!(nothing.is_empty());
    Ok(())
}
