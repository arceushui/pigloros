#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
// The Local runner spawns the G-PUB subject binary as a POSIX process.
#![cfg(unix)]

//! Public-interface tests for the G-PUB non-interference capture adapters
//! (ADR-062 Revision 8 slice N1, #1229; owner note
//! `ADR-062_R8_NonInterference_Executions`).
//!
//! The matrix test runs every G-PUB coordinate once:
//! - Local spawns `pos-ni-g-pub-subject` as a fresh process.
//! - Replay and Fork drive the subject through the Experiment host.
//! - Air-Gapped stays the typed non-executed `Unavailable`.
//! - `NI-ARCHIVE-009` shares the subject; its RVA1 capture is exercised by
//!   `non_interference_g_archive.rs` (slice N1b, #1284).
//!
//! Every executed case must:
//! - be equal at every surface;
//! - have the same result digest in every mode;
//! - match the independently derived expected digest in `execution-matrix.json`
//!   (the G-PUB oracle `scripts/generate_non_interference_g_pub_fixtures.py`);
//! - equal the checked-in NIA1 in every body field except its provenance and
//!   signature.
//!
//! The checked-in NIA1 are engineering evidence signed with the repository
//! test-fixture-only executor key; `non_interference_evidence.rs` checks that
//! the verifier accepts them and that they flip exactly their matrix cases.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use pos_conformance::{
    non_interference_surface_names_v1, ExecutionModeV1, NonInterferenceExecutionArtifactV1,
    NonInterferenceExecutionErrorV1, NonInterferenceFixturePairV1, NonInterferenceRawCaptureV1,
    NonInterferenceRawOperationalV1, NonInterferenceVariantV1,
    MAX_NON_INTERFERENCE_EXECUTION_ARTIFACT_BYTES_V1,
};
use pos_core::{
    clock::Seq,
    event::CanonicalBytes,
    store::{EventStore, SeqRange},
    ErasureContainmentGateV1, Event,
};
use pos_experiment::non_interference_harness::fixture_evidence::non_interference_fixture_executor_key_v1;
use pos_experiment::non_interference_harness::g_pub::{
    g_pub_capture_v1, g_pub_experiment_v1, g_pub_fixture_v1, g_pub_permitted_input_v1,
    g_pub_signals_v1, serve_g_pub_local_subject_v1, GPubRunV1, GPubSessionSubjectV1,
    G_PUB_CANARY_UNAUTHORIZED_V1, G_PUB_CONTROL_UNAUTHORIZED_V1, G_PUB_EVALUATOR_SCHEMA_V1,
    G_PUB_EVAL_FIXTURE_ID_V1, G_PUB_FIXTURE_IDS_V1, G_PUB_PUBLIC_FIXTURE_ID_V1,
    G_PUB_STORE_FILE_V1, G_PUB_SUBJECT_TIMELINE_V1,
};
use pos_experiment::non_interference_harness::{
    NonInterferenceForkRunnerV1, NonInterferenceHarnessV1, NonInterferenceLocalProcessRunnerV1,
    NonInterferenceLocalRequestV1, NonInterferenceNonExecutedCauseV1, NonInterferencePreparationV1,
    NonInterferenceReplayRunnerV1, NonInterferenceSignedExecutionV1,
    NON_INTERFERENCE_LOCAL_REQUEST_MAGIC_V1, NON_INTERFERENCE_PUBLICATION_DIRECTORY_V1,
};
use pos_plugin_society::{SocietyDimension, SocietySignal};
use pos_reference::adapter_transport::read_attempt;
use pos_reference::evaluator_domain::{ClaimLayer, ExecutionMode, FixtureFamily};
use serde_json::{json, Value};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Coordinate = (String, NonInterferenceVariantV1, ExecutionModeV1);

const SUBJECT: &str = env!("CARGO_BIN_EXE_pos-ni-g-pub-subject");
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
const EXECUTED_ROWS: [&str; 2] = [G_PUB_PUBLIC_FIXTURE_ID_V1, G_PUB_EVAL_FIXTURE_ID_V1];
/// The Gateway v1 problem body of the over-limit page request: sorted keys and the matched
/// route template as `instance`, so it carries no run-local identity.
const PAGE_LIMIT_ERROR: &[u8] = b"{\"code\":\"invalid-request\",\"detail\":\"event poll limit must be between 1 and 100\",\"instance\":\"/v1/timelines/{timeline_id}/events\",\"retryable\":false,\"schema_id\":\"urn:pigloros:gateway:v1:schema:problem\",\"status\":400,\"title\":\"Invalid request\",\"type\":\"urn:pigloros:gateway:v1:problem:invalid-request\"}";

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

/// No unauthorized value appears in `bytes`.
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

fn case_id(fixture_id: &str, variant: NonInterferenceVariantV1, mode: ExecutionModeV1) -> String {
    format!(
        "{fixture_id}-{}-{}",
        variant_letter(variant),
        mode_letter(mode)
    )
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

fn g_pub_harness(work: &Path) -> TestResult<NonInterferenceHarnessV1> {
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

fn matrix() -> TestResult<Value> {
    Ok(serde_json::from_slice(&fs::read(
        fixtures_root().join("matrix/execution-matrix.json"),
    )?)?)
}

fn matrix_case<'a>(matrix: &'a Value, id: &str) -> TestResult<&'a Value> {
    matrix["cases"]
        .as_array()
        .and_then(|cases| cases.iter().find(|case| case["case_id"] == json!(id)))
        .ok_or_else(|| format!("no matrix case {id}").into())
}

/// Every checked-in NIA1 by coordinate, with its file name.
fn checked_in() -> TestResult<BTreeMap<Coordinate, (String, NonInterferenceExecutionArtifactV1)>> {
    let mut artifacts = BTreeMap::new();
    let directory = fixtures_root().join(NON_INTERFERENCE_PUBLICATION_DIRECTORY_V1);
    if !directory.exists() {
        return Ok(artifacts);
    }
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        let artifact = NonInterferenceExecutionArtifactV1::from_canonical_cbor(&fs::read(&path)?)?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("unnamed NIA1")?
            .to_owned();
        artifacts.insert(
            (artifact.fixture_id.clone(), artifact.variant, artifact.mode),
            (name, artifact),
        );
    }
    Ok(artifacts)
}

/// The subject's Events of one live run.
fn subject_events(permitted_input: &[u8]) -> TestResult<Vec<Event>> {
    let mut session = g_pub_experiment_v1(permitted_input)?.start()?;
    while session.step()? {}
    let events = session.source_events()?;
    // Signatures and their identities are operational and not captured, so
    // the subject must emit none; the independent oracle derives the payload
    // hash as the BLAKE3 digest of the payload.
    let hasher = pos_crypto::chain::Blake3Hasher;
    for event in &events {
        assert!(event.signature.is_none());
        assert!(event.signature_identity.is_none());
        assert_eq!(
            event.payload_hash,
            pos_core::Hasher::hash_payload(&hasher, &event.payload)
        );
    }
    Ok(events)
}

// ---------------------------------------------------------------------------
// Matrix
// ---------------------------------------------------------------------------

/// Run every G-PUB coordinate once and return the executed cases. Every
/// non-executed case must carry its typed cause and no claim.
fn execute_every_coordinate(
    work: &Path,
) -> TestResult<BTreeMap<Coordinate, NonInterferenceSignedExecutionV1>> {
    let mut harness = g_pub_harness(work)?;
    let mut executed = BTreeMap::new();
    for fixture_id in EXECUTED_ROWS {
        for variant in VARIANTS {
            for mode in MODES {
                let fixture = g_pub_fixture_v1(fixture_id, variant, mode)?;
                let outcome = harness.execute_case(&fixture);
                assert_no_unauthorized_bytes(format!("{outcome:?}").as_bytes(), "an outcome");
                let id = case_id(fixture_id, variant, mode);
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
                    executed.insert((fixture_id.to_owned(), variant, mode), execution);
                }
            }
        }
    }
    Ok(executed)
}

#[test]
fn every_g_pub_coordinate_executes_or_stays_typed_non_executed_and_matches_its_nia1() -> TestResult
{
    let work = tempfile::tempdir()?;
    let executed = execute_every_coordinate(work.path())?;
    assert_eq!(executed.len(), 24);

    let matrix = matrix()?;
    let checked_in = checked_in()?;
    for ((fixture_id, variant, mode), execution) in &executed {
        let id = case_id(fixture_id, *variant, *mode);
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
            .get(&(fixture_id.clone(), *variant, ExecutionModeV1::Local))
            .ok_or("no Local execution")?;
        assert_eq!(
            artifact.result_digest,
            local.artifact().result_digest,
            "{id}"
        );
        // The independently derived expected digest.
        let case = matrix_case(&matrix, &id)?;
        assert_eq!(case["executed"], json!(true), "{id}");
        assert_eq!(
            case["expected_result_digest"],
            json!(hex(&artifact.result_digest)),
            "{id}"
        );
        // The checked-in NIA1 of the coordinate.
        let (name, recorded) = checked_in
            .get(&(fixture_id.clone(), *variant, *mode))
            .ok_or_else(|| format!("no checked-in NIA1 for {id}"))?;
        // Every body field but the execution provenance and the signature.
        let mut reproduced = artifact.clone();
        reproduced.execution_provenance_digest = recorded.execution_provenance_digest;
        reproduced.signature = recorded.signature;
        assert_eq!(&reproduced, recorded, "{id}");
        assert_eq!(
            case["expected_result"]["nia1_content_digest"],
            json!(name.trim_end_matches(".nia1"))
        );
    }
    // Every cold run gets a new seam store and every warm case one shared
    // store: three cold variants of two runs and one warm case, per row.
    for runner in ["local", "replay", "fork"] {
        assert_eq!(
            fs::read_dir(work.path().join(runner))?.count(),
            14,
            "{runner}"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Fixtures: the one-delta proof
// ---------------------------------------------------------------------------

#[test]
fn every_g_pub_pair_differs_only_in_its_declared_unauthorized_value() -> TestResult {
    for fixture_id in G_PUB_FIXTURE_IDS_V1 {
        for variant in VARIANTS {
            let pairs = MODES
                .iter()
                .map(|mode| g_pub_fixture_v1(fixture_id, variant, *mode))
                .collect::<Result<Vec<_>, _>>()?;
            for pair in &pairs {
                pair.validate()?;
                assert_eq!(
                    pair.permitted_input,
                    g_pub_permitted_input_v1(fixture_id, variant)
                );
                assert_eq!(
                    pair.control_unauthorized_value,
                    G_PUB_CONTROL_UNAUTHORIZED_V1
                );
                assert_eq!(pair.canary_unauthorized_value, G_PUB_CANARY_UNAUTHORIZED_V1);
                assert_ne!(
                    pair.control_unauthorized_value,
                    pair.canary_unauthorized_value
                );
                assert!(!contains(
                    &pair.permitted_input,
                    G_PUB_CONTROL_UNAUTHORIZED_V1
                ));
                assert!(!contains(
                    &pair.permitted_input,
                    G_PUB_CANARY_UNAUTHORIZED_V1
                ));
                // Every mode runs the same admitted pair.
                assert_eq!(pair.fixture_digest, pairs[0].fixture_digest);
            }
        }
    }
    assert_eq!(
        NonInterferenceFixturePairV1::try_new(
            G_PUB_PUBLIC_FIXTURE_ID_V1,
            NonInterferenceVariantV1::Success,
            ExecutionModeV1::Local,
            g_pub_permitted_input_v1(
                G_PUB_PUBLIC_FIXTURE_ID_V1,
                NonInterferenceVariantV1::Success
            ),
            G_PUB_CONTROL_UNAUTHORIZED_V1.to_vec(),
            G_PUB_CONTROL_UNAUTHORIZED_V1.to_vec(),
        ),
        Err(NonInterferenceExecutionErrorV1::FixtureInvalid)
    );
    // The permitted input alone decides the subject's signals.
    let signal = |dimension, value| SocietySignal {
        dimension,
        value,
        subject: None,
        object: None,
    };
    assert_eq!(
        g_pub_signals_v1(&g_pub_permitted_input_v1(
            G_PUB_EVAL_FIXTURE_ID_V1,
            NonInterferenceVariantV1::Denial
        )),
        vec![
            signal(SocietyDimension::Culture, 0.75),
            signal(SocietyDimension::Trust, 0.25)
        ]
    );
    assert_eq!(
        g_pub_signals_v1(b"\x05"),
        vec![
            signal(SocietyDimension::Trust, 0.25),
            signal(SocietyDimension::Trust, 0.25)
        ]
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Capture adapters through their public seam
// ---------------------------------------------------------------------------

fn capture(
    fixture_id: &str,
    variant: NonInterferenceVariantV1,
    unauthorized_value: &[u8],
    store: &Path,
) -> TestResult<NonInterferenceRawCaptureV1> {
    let permitted = g_pub_permitted_input_v1(fixture_id, variant);
    Ok(g_pub_capture_v1(
        &GPubRunV1 {
            fixture_id,
            variant,
            permitted_input: &permitted,
            unauthorized_value,
        },
        &subject_events(&permitted)?,
        store,
    )?)
}

/// The denied sibling the host placed in the seam store: whether it was
/// created before the subject Timeline, and the subject text of each of its
/// signals.
fn denied_sibling(store: &Path) -> TestResult<(bool, Vec<Option<String>>)> {
    let mut seam = pos_store::sqlite::SqliteStore::open(&store.to_string_lossy())?;
    seam.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let mut timelines = seam.list_timelines()?;
    timelines.sort_by_key(pos_core::timeline::Timeline::id);
    let names = timelines
        .iter()
        .map(|timeline| timeline.meta.name.clone().unwrap_or_default())
        .collect::<Vec<_>>();
    assert_eq!(names.len(), 2, "{names:?}");
    let denied = timelines
        .iter()
        .find(|timeline| timeline.meta.name.as_deref() != Some(G_PUB_SUBJECT_TIMELINE_V1))
        .ok_or("no denied sibling")?;
    let subjects = seam
        .read(
            denied.id(),
            SeqRange {
                from: Seq::from_u64(1),
                to: None,
            },
        )?
        .iter()
        .map(|event| {
            ciborium::from_reader::<SocietySignal, _>(event.payload.as_slice())
                .map(|signal| signal.subject)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((names[0] != G_PUB_SUBJECT_TIMELINE_V1, subjects))
}

#[test]
fn the_host_places_the_unauthorized_value_only_in_the_denied_sibling() -> TestResult {
    for fixture_id in EXECUTED_ROWS {
        // An even first byte puts the sibling first; the value's length
        // modulo 3, plus one, is its signal count.
        for (value, first, count) in [
            (G_PUB_CONTROL_UNAUTHORIZED_V1, true, 2),
            (G_PUB_CANARY_UNAUTHORIZED_V1, false, 1),
        ] {
            let directory = tempfile::tempdir()?;
            let store = directory.path().join(G_PUB_STORE_FILE_V1);
            let captured = capture(fixture_id, NonInterferenceVariantV1::Success, value, &store)?;
            for surface in captured.authoritative.iter().chain(&captured.public) {
                assert_no_unauthorized_bytes(surface, fixture_id);
            }
            assert_eq!(
                denied_sibling(&store)?,
                (first, vec![Some(hex(value)); count]),
                "{fixture_id}"
            );
        }
    }
    Ok(())
}

#[test]
fn the_public_gateway_capture_keeps_only_category_and_count_operationally() -> TestResult {
    let names = non_interference_surface_names_v1(G_PUB_PUBLIC_FIXTURE_ID_V1).ok_or("no names")?;
    let directory = tempfile::tempdir()?;
    let success = capture(
        G_PUB_PUBLIC_FIXTURE_ID_V1,
        NonInterferenceVariantV1::Success,
        G_PUB_CONTROL_UNAUTHORIZED_V1,
        &directory.path().join("success.sqlite"),
    )?;
    assert_eq!(success.surface_names, names);
    assert_eq!(success.authoritative, success.public);
    assert_eq!(success.unexpected_network_accesses, 0);
    assert_eq!(success.provenance_digest, [0xff; 32]);
    let category_count = |category, count, excluded_sensitive: Vec<u8>| {
        NonInterferenceRawOperationalV1::CategoryCount {
            category,
            count,
            excluded_sensitive,
        }
    };
    let cursor = match &success.operational[2] {
        NonInterferenceRawOperationalV1::CategoryCount {
            excluded_sensitive, ..
        } => excluded_sensitive.clone(),
        other => return Err(format!("unexpected cursor surface {other:?}").into()),
    };
    // `v1.` + generation + `.` + Timeline ULID + `.4`.
    assert_eq!(cursor.len(), 3 + 64 + 1 + 26 + 2);
    assert!(cursor.starts_with(b"v1.") && cursor.ends_with(b".4"));
    assert_eq!(
        success.operational,
        vec![
            category_count(0, 0, Vec::new()),
            category_count(200, 7, Vec::new()),
            category_count(0, 1, cursor),
            category_count(0, 2, Vec::new()),
            category_count(0, 2, Vec::new()),
        ]
    );
    let denial = capture(
        G_PUB_PUBLIC_FIXTURE_ID_V1,
        NonInterferenceVariantV1::Denial,
        G_PUB_CONTROL_UNAUTHORIZED_V1,
        &directory.path().join("denial.sqlite"),
    )?;
    assert_eq!(
        denial.operational[0],
        category_count(400, 1, PAGE_LIMIT_ERROR.to_vec())
    );
    assert_eq!(denial.operational[1], category_count(400, 8, Vec::new()));
    assert_eq!(denial.operational[4], category_count(0, 3, Vec::new()));
    Ok(())
}

#[test]
fn the_evaluator_capture_binds_the_exact_eai1_attempt_over_the_export() -> TestResult {
    let names = non_interference_surface_names_v1(G_PUB_EVAL_FIXTURE_ID_V1).ok_or("no names")?;
    let directory = tempfile::tempdir()?;
    let captured = capture(
        G_PUB_EVAL_FIXTURE_ID_V1,
        NonInterferenceVariantV1::Success,
        G_PUB_CANARY_UNAUTHORIZED_V1,
        &directory.path().join(G_PUB_STORE_FILE_V1),
    )?;
    assert_eq!(captured.surface_names, names);
    assert_eq!(captured.authoritative[1..], captured.public[1..]);
    let exact = |index: usize| match &captured.operational[index] {
        NonInterferenceRawOperationalV1::ByteExact(bytes) => Ok(bytes.clone()),
        other => Err(format!("unexpected operational surface {other:?}")),
    };
    assert_eq!(
        exact(0)?,
        blake3::hash(&captured.public[0]).as_bytes().to_vec()
    );
    for index in [1, 2, 4] {
        assert_eq!(exact(index)?, captured.public[index]);
    }
    let attempt = read_attempt(exact(3)?.as_slice())?;
    assert_eq!(
        attempt.case_id,
        format!("{G_PUB_EVAL_FIXTURE_ID_V1}-success")
    );
    assert_eq!(attempt.claim_layer, ClaimLayer::KnowledgeNonInterference);
    assert_eq!(attempt.family, FixtureFamily::Positive);
    assert_eq!(attempt.mode, ExecutionMode::Local);
    assert_eq!(
        attempt.fixture_digest,
        *blake3::hash(&captured.public[2]).as_bytes()
    );
    assert_eq!(attempt.schema.bytes, G_PUB_EVALUATOR_SCHEMA_V1);
    assert_eq!(attempt.payload.bytes, captured.public[0]);
    assert_eq!(attempt.auxiliary.len(), 1);
    assert_eq!(attempt.auxiliary[0].bytes, captured.public[1]);
    assert_eq!(attempt.budget.values(), [1024 * 1024; 8]);
    assert_eq!(attempt.watchdog_ms, 1_000);
    assert!(!attempt.network_allowed);
    assert!(attempt.capability_ids.is_empty());
    assert_eq!(attempt.transport_caps.max_member_bytes, 1024 * 1024);
    assert_eq!(attempt.transport_caps.max_attempt_bytes, 4 * 1024 * 1024);
    Ok(())
}

#[test]
fn a_capture_without_an_adapter_or_a_seam_is_typed_non_executed() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = directory.path().join(G_PUB_STORE_FILE_V1);
    assert_eq!(
        capture(
            "NI-TOOL-001",
            NonInterferenceVariantV1::Success,
            b"x",
            &store
        )
        .err()
        .map(|error| error.to_string()),
        Some(NonInterferenceNonExecutedCauseV1::Missing.to_string())
    );
    let unreachable = directory.path().join("absent").join(G_PUB_STORE_FILE_V1);
    for fixture_id in EXECUTED_ROWS {
        assert_eq!(
            capture(
                fixture_id,
                NonInterferenceVariantV1::Success,
                b"x",
                &unreachable
            )
            .err()
            .map(|error| error.to_string()),
            Some(NonInterferenceNonExecutedCauseV1::Unavailable.to_string()),
            "{fixture_id}"
        );
    }
    // The public Gateway seam accepts only Society Signal Events.
    let permitted = g_pub_permitted_input_v1(
        G_PUB_PUBLIC_FIXTURE_ID_V1,
        NonInterferenceVariantV1::Success,
    );
    let mut events = subject_events(&permitted)?;
    events[0].payload = CanonicalBytes::from_vec(vec![0xff]);
    assert_eq!(
        g_pub_capture_v1(
            &GPubRunV1 {
                fixture_id: G_PUB_PUBLIC_FIXTURE_ID_V1,
                variant: NonInterferenceVariantV1::Success,
                permitted_input: &permitted,
                unauthorized_value: b"x",
            },
            &events,
            &directory.path().join("non-signal.sqlite"),
        )
        .err(),
        Some(NonInterferenceNonExecutedCauseV1::Unavailable)
    );
    Ok(())
}

#[test]
fn the_local_subject_serves_one_request_or_writes_nothing() -> TestResult {
    let directory = tempfile::tempdir()?;
    let request = NonInterferenceLocalRequestV1 {
        magic: NON_INTERFERENCE_LOCAL_REQUEST_MAGIC_V1.to_owned(),
        version: 1,
        fixture_id: G_PUB_EVAL_FIXTURE_ID_V1.to_owned(),
        variant: NonInterferenceVariantV1::ColdCache,
        mode: ExecutionModeV1::Local,
        preparation: NonInterferencePreparationV1::Cold,
        permitted_input: g_pub_permitted_input_v1(
            G_PUB_EVAL_FIXTURE_ID_V1,
            NonInterferenceVariantV1::ColdCache,
        ),
        unauthorized_value: G_PUB_CONTROL_UNAUTHORIZED_V1.to_vec(),
    };
    let bytes = pos_crypto::canonical::encode(&request)?;
    let mut output = Vec::new();
    serve_g_pub_local_subject_v1(bytes.as_slice(), &mut output, directory.path())?;
    assert!(!output.is_empty());
    assert_no_unauthorized_bytes(&output, "a Local capture frame");
    let mut refused = Vec::new();
    assert!(
        serve_g_pub_local_subject_v1(&b"not a request"[..], &mut refused, directory.path())
            .is_err()
    );
    assert!(refused.is_empty());
    // The binary exits non-zero without a frame for a malformed request.
    let mut child = Command::new(SUBJECT)
        .current_dir(directory.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("no stdin")?
        .write_all(b"not a request")?;
    let finished = child.wait_with_output()?;
    assert!(!finished.status.success());
    assert!(finished.stdout.is_empty());
    Ok(())
}
