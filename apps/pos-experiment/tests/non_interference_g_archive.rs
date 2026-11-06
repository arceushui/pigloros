#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
// The Local runner spawns the G-PUB subject binary as a POSIX process.
#![cfg(unix)]

//! Public-interface tests for the `NI-ARCHIVE-009` capture adapter over the
//! RVA1 run-evidence archive (ADR-062 Revision 8 slice N1b, #1284;
//! ADR-127).
//!
//! The matrix test runs every `NI-ARCHIVE-009` coordinate once:
//! - Local spawns `pos-ni-g-pub-subject` as a fresh process.
//! - Replay and Fork drive the subject through the Experiment host.
//! - Air-Gapped stays the typed non-executed `Unavailable`.
//!
//! Every executed case must:
//! - be equal at every surface;
//! - have the same result digest in every mode;
//! - match the independently derived expected digest in `execution-matrix.json`
//!   (the oracle `scripts/generate_non_interference_g_archive_fixtures.py`);
//! - equal the checked-in NIA1 in every body field except its provenance and
//!   signature.
//!
//! `non_interference_evidence.rs` checks that the verifier accepts the
//! checked-in NIA1 and that they flip exactly their matrix cases.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use ciborium::Value as Cbor;
use pos_conformance::run_evidence_archive::run_evidence_event_member_name_v1;
use pos_conformance::{
    non_interference_surface_names_v1, ExecutionModeV1, NonInterferenceExecutionArtifactV1,
    NonInterferenceRawCaptureV1, NonInterferenceRawOperationalV1, NonInterferenceVariantV1,
    MAX_NON_INTERFERENCE_EXECUTION_ARTIFACT_BYTES_V1,
};
use pos_core::Event;
use pos_experiment::non_interference_harness::fixture_evidence::non_interference_fixture_executor_key_v1;
use pos_experiment::non_interference_harness::g_archive::G_ARCHIVE_STAGING_DIRECTORY_V1;
use pos_experiment::non_interference_harness::g_pub::{
    g_pub_capture_v1, g_pub_experiment_v1, g_pub_fixture_v1, g_pub_permitted_input_v1, GPubRunV1,
    GPubSessionSubjectV1, G_PUB_ARCHIVE_FIXTURE_ID_V1, G_PUB_CANARY_UNAUTHORIZED_V1,
    G_PUB_CONTROL_UNAUTHORIZED_V1, G_PUB_STORE_FILE_V1,
};
use pos_experiment::non_interference_harness::{
    NonInterferenceForkRunnerV1, NonInterferenceHarnessV1, NonInterferenceLocalProcessRunnerV1,
    NonInterferenceNonExecutedCauseV1, NonInterferencePreparationV1, NonInterferenceReplayRunnerV1,
    NonInterferenceSignedExecutionV1, NON_INTERFERENCE_PUBLICATION_DIRECTORY_V1,
};
use pos_reference::run_evidence_archive::{
    import_run_evidence_archive_v1, RunEvidenceArchiveErrorV1,
};
use serde_json::{json, Value};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Coordinate = (NonInterferenceVariantV1, ExecutionModeV1);

const SUBJECT: &str = env!("CARGO_BIN_EXE_pos-ni-g-pub-subject");
const ROW: &str = G_PUB_ARCHIVE_FIXTURE_ID_V1;
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
/// The subject's two Ticks of two signals.
const EVENTS: u64 = 4;

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

/// No unauthorized value, raw or as hex, appears in `bytes`.
fn assert_no_unauthorized_bytes(bytes: &[u8], context: &str) {
    for value in [G_PUB_CONTROL_UNAUTHORIZED_V1, G_PUB_CANARY_UNAUTHORIZED_V1] {
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
    format!("{ROW}-{}-{}", variant_letter(variant), mode_letter(mode))
}

/// The Local runner of the G-PUB subject binary. The coverage profile
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

fn harness(work: &Path) -> TestResult<NonInterferenceHarnessV1> {
    let public = non_interference_fixture_executor_key_v1().public_key();
    Ok(
        NonInterferenceHarnessV1::new(non_interference_fixture_executor_key_v1(), vec![public])
            .with_runner(Box::new(local_runner(work)?))
            .with_runner(Box::new(NonInterferenceReplayRunnerV1::new(
                GPubSessionSubjectV1::new(work.join("replay")),
            )))
            .with_runner(Box::new(NonInterferenceForkRunnerV1::new(
                GPubSessionSubjectV1::new(work.join("fork")),
                1,
            ))),
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

/// Every checked-in `NI-ARCHIVE-009` NIA1 by coordinate, with its file name.
fn checked_in() -> TestResult<BTreeMap<Coordinate, (String, NonInterferenceExecutionArtifactV1)>> {
    let mut artifacts = BTreeMap::new();
    for entry in fs::read_dir(fixtures_root().join(NON_INTERFERENCE_PUBLICATION_DIRECTORY_V1))? {
        let path = entry?.path();
        let artifact = NonInterferenceExecutionArtifactV1::from_canonical_cbor(&fs::read(&path)?)?;
        if artifact.fixture_id == ROW {
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

/// Run every `NI-ARCHIVE-009` coordinate once and return the executed cases.
fn execute_every_coordinate(
    work: &Path,
) -> TestResult<BTreeMap<Coordinate, NonInterferenceSignedExecutionV1>> {
    let mut harness = harness(work)?;
    let mut executed = BTreeMap::new();
    for variant in VARIANTS {
        for mode in MODES {
            let outcome = harness.execute_case(&g_pub_fixture_v1(ROW, variant, mode)?);
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

#[test]
fn every_archive_coordinate_executes_or_stays_typed_non_executed_and_matches_its_nia1() -> TestResult
{
    let work = tempfile::tempdir()?;
    let executed = execute_every_coordinate(work.path())?;
    assert_eq!(executed.len(), 12);
    let checked_in = checked_in()?;
    assert_eq!(checked_in.len(), 12);
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
        // The result is mode-independent.
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
        // The checked-in NIA1, in every body field but the execution
        // provenance and the signature.
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
    // Three cold variants of two runs and one warm case per runner, and no
    // staging directory survives a capture.
    for runner in ["local", "replay", "fork"] {
        let directories = fs::read_dir(work.path().join(runner))?.collect::<Result<Vec<_>, _>>()?;
        assert_eq!(directories.len(), 7, "{runner}");
        for directory in directories {
            assert!(!directory
                .path()
                .join(G_ARCHIVE_STAGING_DIRECTORY_V1)
                .exists());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The capture through its public seam
// ---------------------------------------------------------------------------

fn subject_events(permitted_input: &[u8]) -> TestResult<Vec<Event>> {
    let mut session = g_pub_experiment_v1(permitted_input)?.start()?;
    while session.step()? {}
    Ok(session.source_events()?)
}

fn capture(
    variant: NonInterferenceVariantV1,
    unauthorized_value: &[u8],
    store: &Path,
) -> TestResult<NonInterferenceRawCaptureV1> {
    let permitted = g_pub_permitted_input_v1(ROW, variant);
    Ok(g_pub_capture_v1(
        &GPubRunV1 {
            fixture_id: ROW,
            variant,
            permitted_input: &permitted,
            unauthorized_value,
        },
        &subject_events(&permitted)?,
        store,
    )?)
}

fn decode(bytes: &[u8]) -> TestResult<Cbor> {
    Ok(ciborium::from_reader(bytes)?)
}

fn operational(capture: &NonInterferenceRawCaptureV1, index: usize) -> TestResult<Vec<u8>> {
    match &capture.operational[index] {
        NonInterferenceRawOperationalV1::ByteExact(bytes) => Ok(bytes.clone()),
        other => Err(format!("unexpected operational surface {other:?}").into()),
    }
}

fn text(value: &str) -> Cbor {
    Cbor::Text(value.to_owned())
}

fn uint(value: u64) -> Cbor {
    Cbor::Integer(value.into())
}

#[test]
fn the_archive_capture_imports_the_rva1_archive_of_the_export() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = directory.path().join(G_PUB_STORE_FILE_V1);
    let captured = capture(
        NonInterferenceVariantV1::Success,
        G_PUB_CANARY_UNAUTHORIZED_V1,
        &store,
    )?;
    assert_eq!(
        captured.surface_names,
        non_interference_surface_names_v1(ROW).ok_or("no names")?
    );
    // The staging directory is gone, and no facet holds the value.
    assert!(!directory
        .path()
        .join(G_ARCHIVE_STAGING_DIRECTORY_V1)
        .exists());
    for index in 0..6 {
        assert_no_unauthorized_bytes(&captured.authoritative[index], "an authoritative facet");
        assert_no_unauthorized_bytes(&captured.public[index], "a public facet");
        assert_no_unauthorized_bytes(&operational(&captured, index)?, "an operational facet");
    }
    // The archive is the exact public facet of `archive bytes`, and the
    // evaluator imports it.
    let archive = &captured.public[1];
    let digest = *blake3::hash(archive).as_bytes();
    let imported = import_run_evidence_archive_v1(archive, &digest)?;
    let names = imported
        .members
        .iter()
        .map(|member| member.name.clone())
        .collect::<Vec<_>>();
    let mut expected = vec!["RVA1".to_owned()];
    expected.extend((1..=EVENTS).map(run_evidence_event_member_name_v1));
    expected.push("timeline.cbor".to_owned());
    assert_eq!(names, expected);
    assert_eq!(operational(&captured, 1)?, *archive);
    // The Timeline record of a fresh root `Live` Timeline without owner.
    assert_eq!(
        decode(&imported.members[names.len() - 1].data)?,
        Cbor::Array(vec![
            uint(1),
            text("ni-g-pub-subject"),
            Cbor::Null,
            uint(EVENTS)
        ])
    );
    Ok(())
}

#[test]
fn the_archive_capture_records_every_facet_of_an_admitted_import() -> TestResult {
    let directory = tempfile::tempdir()?;
    let captured = capture(
        NonInterferenceVariantV1::Success,
        G_PUB_CONTROL_UNAUTHORIZED_V1,
        &directory.path().join(G_PUB_STORE_FILE_V1),
    )?;
    let archive = &captured.public[1];
    let digest = *blake3::hash(archive).as_bytes();
    let imported = import_run_evidence_archive_v1(archive, &digest)?;
    // The member table and the bundle.
    let table = Cbor::Array(
        imported
            .members
            .iter()
            .map(|member| {
                Cbor::Array(vec![
                    text(&member.name),
                    uint(0o644),
                    uint(member.size),
                    Cbor::Bytes(member.digest.to_vec()),
                ])
            })
            .collect(),
    );
    let bundle = Cbor::Array(
        imported
            .members
            .iter()
            .map(|member| Cbor::Array(vec![text(&member.name), Cbor::Bytes(member.data.clone())]))
            .collect(),
    );
    for (facet, expected) in [
        (&captured.authoritative[0], &table),
        (&captured.public[0], &table),
        (&captured.authoritative[1], &bundle),
        (&captured.authoritative[2], &bundle),
        (&captured.public[2], &bundle),
        (&captured.authoritative[3], &table),
    ] {
        assert_eq!(&decode(facet)?, expected);
    }
    // The header walk is the six 512-byte headers.
    let walk = operational(&captured, 0)?;
    assert_eq!(walk.len(), 6 * 512);
    assert_eq!(&walk[..512], &archive[..512]);
    // The digests, the one admitted import and the logs.
    assert_eq!(
        decode(&captured.public[3])?,
        Cbor::Array(vec![
            Cbor::Bytes(digest.to_vec()),
            Cbor::Array(
                imported
                    .members
                    .iter()
                    .map(|member| Cbor::Bytes(member.digest.to_vec()))
                    .collect()
            ),
        ])
    );
    let admitted = Cbor::Array(vec![text("admitted"), uint(1), uint(6)]);
    assert_eq!(
        decode(&captured.authoritative[4])?,
        Cbor::Array(vec![admitted.clone()])
    );
    assert_eq!(
        decode(&captured.public[4])?,
        Cbor::Array(vec![
            Cbor::Array(vec![admitted]),
            Cbor::Bytes(digest.to_vec())
        ])
    );
    assert_eq!(
        decode(&captured.public[5])?,
        Cbor::Array(vec![
            Cbor::Array(vec![
                text("write"),
                text("ok"),
                uint(6),
                uint(archive.len() as u64)
            ]),
            Cbor::Array(vec![text("import"), text("admitted")]),
        ])
    );
    for index in 2..6 {
        assert_eq!(operational(&captured, index)?, captured.public[index]);
    }
    assert_eq!(captured.authoritative[5], captured.public[5]);
    Ok(())
}

#[test]
fn the_denial_variant_also_records_a_refused_import_with_a_wrong_digest() -> TestResult {
    let directory = tempfile::tempdir()?;
    let captured = capture(
        NonInterferenceVariantV1::Denial,
        G_PUB_CONTROL_UNAUTHORIZED_V1,
        &directory.path().join(G_PUB_STORE_FILE_V1),
    )?;
    let refused = Cbor::Array(vec![text("refused"), text("DigestMismatch")]);
    assert_eq!(
        decode(&captured.authoritative[4])?,
        Cbor::Array(vec![
            Cbor::Array(vec![text("admitted"), uint(1), uint(6)]),
            refused
        ])
    );
    match decode(&captured.public[5])? {
        Cbor::Array(logs) => assert_eq!(
            logs[1..],
            [
                Cbor::Array(vec![text("import"), text("admitted")]),
                Cbor::Array(vec![text("import"), text("DigestMismatch")]),
            ]
        ),
        other => return Err(format!("unexpected logs {other:?}").into()),
    }
    // The wrong digest is the archive digest with byte 0 XORed with 0xff.
    let mut wrong = *blake3::hash(&captured.public[1]).as_bytes();
    wrong[0] ^= 0xff;
    assert_eq!(
        import_run_evidence_archive_v1(&captured.public[1], &wrong),
        Err(RunEvidenceArchiveErrorV1::DigestMismatch)
    );
    Ok(())
}

#[test]
fn an_archive_capture_without_a_seam_is_typed_non_executed() -> TestResult {
    let directory = tempfile::tempdir()?;
    assert_eq!(
        capture(
            NonInterferenceVariantV1::Success,
            b"x",
            &directory.path().join("absent").join(G_PUB_STORE_FILE_V1),
        )
        .err()
        .map(|error| error.to_string()),
        Some(NonInterferenceNonExecutedCauseV1::Unavailable.to_string())
    );
    Ok(())
}
