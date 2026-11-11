#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
// The Local runner spawns the G-PLUG subject binary as a POSIX process.
#![cfg(unix)]

//! Public-interface tests for the G-PLUG non-interference capture adapters
//! (ADR-062 Revision 8 slice N2, #1230; owner note
//! `ADR-062_R8_NonInterference_Plugin`, scoping
//! `ADR-059_R9_State_Migration_Scoping`).
//!
//! The matrix test runs every G-PLUG coordinate once (one shared run):
//! - Local spawns `pos-ni-g-plug-subject` as a fresh process.
//! - Replay and Fork drive the subject through the Experiment host.
//! - Air-Gapped stays the typed non-executed `Unavailable`.
//!
//! Every executed case must:
//! - be equal at every surface;
//! - have the same result digest in every mode;
//! - match the independently derived expected digest in `execution-matrix.json`
//!   (the G-PLUG oracle `scripts/generate_non_interference_g_plug_fixtures.py`);
//! - equal the checked-in NIA1 in every body field except its provenance and
//!   signature.
//!
//! The Plugin is reached only through the PWQ1/PWR1 public Plugin protocol
//! (`describe`, `reduce`, `drive`); a migrate-state request is refused. The
//! checked-in NIA1 are engineering evidence signed with the repository
//! test-fixture-only executor key; `non_interference_evidence.rs` checks that
//! the verifier accepts them and that they flip exactly their matrix cases.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use pos_conformance::{
    non_interference_surface_names_v1, ExecutionModeV1, NonInterferenceExecutionArtifactV1,
    NonInterferenceFixturePairV1, NonInterferenceRawCaptureV1, NonInterferenceRawOperationalV1,
    NonInterferenceVariantV1, MAX_NON_INTERFERENCE_EXECUTION_ARTIFACT_BYTES_V1,
};
use pos_core::Event;
use pos_experiment::non_interference_harness::fixture_evidence::non_interference_fixture_executor_key_v1;
use pos_experiment::non_interference_harness::g_plug::{
    execute_g_plug_migration_canary_v1, g_plug_capture_v1, g_plug_experiment_v1, g_plug_fixture_v1,
    g_plug_invocation_v1, g_plug_migration_canary_v1, g_plug_permitted_input_v1,
    serve_g_plug_fixture_guest_v1, serve_g_plug_local_subject_v1, GPlugProtocolHostV1, GPlugRunV1,
    GPlugSessionSubjectV1, G_PLUG_CACHE_FILE_V1, G_PLUG_CANARY_UNAUTHORIZED_V1,
    G_PLUG_COMPONENT_V1, G_PLUG_CONTROL_UNAUTHORIZED_V1, G_PLUG_EVENT_TYPE_V1,
    G_PLUG_FIXTURE_IDS_V1, G_PLUG_GUEST_PLUGIN_ID_V1, G_PLUG_HOST_STORE_FILE_V1,
    G_PLUG_MIGRATION_CANARY_V1, G_PLUG_MIGRATION_CONTROL_V1, G_PLUG_NET_FIXTURE_ID_V1,
    G_PLUG_PROBE_PREFIX_V1, G_PLUG_SERVICE_FIXTURE_ID_V1, G_PLUG_STATE_FIXTURE_ID_V1,
    G_PLUG_TOOL_FIXTURE_ID_V1,
};
use pos_experiment::non_interference_harness::{
    NonInterferenceForkRunnerV1, NonInterferenceHarnessV1, NonInterferenceLocalProcessRunnerV1,
    NonInterferenceLocalRequestV1, NonInterferenceNonExecutedCauseV1, NonInterferencePreparationV1,
    NonInterferenceReplayRunnerV1, NonInterferenceSignedExecutionV1,
    NON_INTERFERENCE_LOCAL_REQUEST_MAGIC_V1, NON_INTERFERENCE_PUBLICATION_DIRECTORY_V1,
};
use pos_plugin_supervisor::ipc::{
    decode_worker_request_v1, decode_worker_response_v1, encode_worker_response_v1,
};
use pos_plugin_supervisor::{WorkerCallV1, WorkerReturnV1};
use pos_runtime::community_plugin_host::{CommunityPluginHostErrorV1, PluginErrorCodeV1};
use serde_json::{json, Value};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Coordinate = (String, NonInterferenceVariantV1, ExecutionModeV1);

const SUBJECT: &str = env!("CARGO_BIN_EXE_pos-ni-g-plug-subject");
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
        G_PLUG_CONTROL_UNAUTHORIZED_V1,
        G_PLUG_CANARY_UNAUTHORIZED_V1,
        G_PLUG_MIGRATION_CONTROL_V1,
        G_PLUG_MIGRATION_CANARY_V1,
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

fn case_id(fixture_id: &str, variant: NonInterferenceVariantV1, mode: ExecutionModeV1) -> String {
    format!(
        "{fixture_id}-{}-{}",
        variant_letter(variant),
        mode_letter(mode)
    )
}

/// The Local runner of the G-PLUG subject binary. The coverage profile
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

fn g_plug_harness(work: &Path) -> TestResult<NonInterferenceHarnessV1> {
    let public = non_interference_fixture_executor_key_v1().public_key();
    Ok(
        NonInterferenceHarnessV1::new(non_interference_fixture_executor_key_v1(), vec![public])
            .with_runner(Box::new(local_runner(work)?))
            .with_runner(Box::new(NonInterferenceReplayRunnerV1::new(
                GPlugSessionSubjectV1::new(work.join("replay")),
            )))
            .with_runner(Box::new(NonInterferenceForkRunnerV1::new(
                GPlugSessionSubjectV1::new(work.join("fork")),
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
    for entry in fs::read_dir(fixtures_root().join(NON_INTERFERENCE_PUBLICATION_DIRECTORY_V1))? {
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
fn subject_events(fixture_id: &str, permitted_input: &[u8]) -> TestResult<Vec<Event>> {
    let mut session = g_plug_experiment_v1(fixture_id, permitted_input)?.start()?;
    while session.step()? {}
    Ok(session.source_events()?)
}

fn capture(
    fixture_id: &str,
    variant: NonInterferenceVariantV1,
    permitted_input: &[u8],
    unauthorized_value: &[u8],
    directory: &Path,
) -> Result<NonInterferenceRawCaptureV1, NonInterferenceNonExecutedCauseV1> {
    let events = subject_events(fixture_id, permitted_input)
        .map_err(|_| NonInterferenceNonExecutedCauseV1::Unavailable)?;
    g_plug_capture_v1(
        &GPlugRunV1 {
            fixture_id,
            variant,
            permitted_input,
            unauthorized_value,
        },
        &events,
        directory,
    )
}

// ---------------------------------------------------------------------------
// Matrix
// ---------------------------------------------------------------------------

/// Run every G-PLUG coordinate once and return the executed cases. Every
/// Air-Gapped case must carry its typed cause and no claim.
fn execute_every_coordinate(
    work: &Path,
) -> TestResult<BTreeMap<Coordinate, NonInterferenceSignedExecutionV1>> {
    let mut harness = g_plug_harness(work)?;
    let mut executed = BTreeMap::new();
    for fixture_id in G_PLUG_FIXTURE_IDS_V1 {
        for variant in VARIANTS {
            for mode in MODES {
                let fixture = g_plug_fixture_v1(fixture_id, variant, mode)?;
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
fn every_g_plug_coordinate_executes_or_stays_typed_non_executed_and_matches_its_nia1() -> TestResult
{
    let work = tempfile::tempdir()?;
    let executed = execute_every_coordinate(work.path())?;
    assert_eq!(executed.len(), 48);

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
        // The checked-in NIA1 of the coordinate: every body field but the
        // execution provenance and the signature.
        let (name, recorded) = checked_in
            .get(&(fixture_id.clone(), *variant, *mode))
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
    // Every cold run gets a new directory and every warm case one shared
    // directory: three cold variants of two runs and one warm case, per row.
    for runner in ["local", "replay", "fork"] {
        assert_eq!(
            fs::read_dir(work.path().join(runner))?.count(),
            28,
            "{runner}"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Fixtures: the one-delta proof and the migration-only canary
// ---------------------------------------------------------------------------

#[test]
fn every_g_plug_pair_differs_only_in_its_declared_unauthorized_value() -> TestResult {
    for fixture_id in G_PLUG_FIXTURE_IDS_V1 {
        for variant in VARIANTS {
            let pairs = MODES
                .iter()
                .map(|mode| g_plug_fixture_v1(fixture_id, variant, *mode))
                .collect::<Result<Vec<_>, _>>()?;
            for pair in &pairs {
                pair.validate()?;
                assert_eq!(
                    pair.permitted_input,
                    g_plug_permitted_input_v1(fixture_id, variant)
                );
                assert_eq!(
                    pair.control_unauthorized_value,
                    G_PLUG_CONTROL_UNAUTHORIZED_V1
                );
                assert_eq!(
                    pair.canary_unauthorized_value,
                    G_PLUG_CANARY_UNAUTHORIZED_V1
                );
                // Every mode runs the same admitted pair.
                assert_eq!(pair.fixture_digest, pairs[0].fixture_digest);
            }
        }
    }
    // The canary differs in value, size and text.
    assert_ne!(
        G_PLUG_CONTROL_UNAUTHORIZED_V1.len(),
        G_PLUG_CANARY_UNAUTHORIZED_V1.len()
    );
    assert_eq!(
        g_plug_permitted_input_v1(G_PLUG_NET_FIXTURE_ID_V1, NonInterferenceVariantV1::Denial),
        b"g-plug permitted input v1/NI-NET-010/denial"
    );
    Ok(())
}

#[test]
fn the_migration_only_canary_is_non_executed_unsupported_without_an_nia1() -> TestResult {
    for variant in VARIANTS {
        for mode in MODES {
            let pair = g_plug_migration_canary_v1(variant, mode)?;
            assert_eq!(pair.fixture_id, G_PLUG_STATE_FIXTURE_ID_V1);
            assert_eq!(pair.control_unauthorized_value, G_PLUG_MIGRATION_CONTROL_V1);
            assert_eq!(pair.canary_unauthorized_value, G_PLUG_MIGRATION_CANARY_V1);
            assert_ne!(
                pair.fixture_digest,
                g_plug_fixture_v1(G_PLUG_STATE_FIXTURE_ID_V1, variant, mode)?.fixture_digest
            );
            let outcome = execute_g_plug_migration_canary_v1(&pair);
            assert_eq!(
                outcome.non_executed_cause(),
                Some(NonInterferenceNonExecutedCauseV1::Unsupported)
            );
            assert_eq!(outcome.claim(), None);
            assert!(outcome.execution().is_none());
        }
    }
    // A pair whose content address does not hold is missing, not unsupported.
    let mut tampered =
        g_plug_migration_canary_v1(NonInterferenceVariantV1::Success, ExecutionModeV1::Local)?;
    tampered.fixture_digest = [1; 32];
    assert_eq!(
        execute_g_plug_migration_canary_v1(&tampered).non_executed_cause(),
        Some(NonInterferenceNonExecutedCauseV1::Missing)
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Capture adapters
// ---------------------------------------------------------------------------

#[test]
fn the_host_writes_the_unauthorized_value_only_to_its_own_record() -> TestResult {
    for fixture_id in G_PLUG_FIXTURE_IDS_V1 {
        for value in [
            G_PLUG_CONTROL_UNAUTHORIZED_V1,
            G_PLUG_CANARY_UNAUTHORIZED_V1,
        ] {
            let directory = tempfile::tempdir()?;
            let permitted =
                g_plug_permitted_input_v1(fixture_id, NonInterferenceVariantV1::Success);
            let captured = capture(
                fixture_id,
                NonInterferenceVariantV1::Success,
                &permitted,
                value,
                directory.path(),
            )?;
            for surface in captured.authoritative.iter().chain(&captured.public) {
                assert_no_unauthorized_bytes(surface, fixture_id);
            }
            assert_eq!(captured.authoritative, captured.public);
            assert_eq!(captured.unexpected_network_accesses, 0);
            assert_eq!(
                captured.surface_names,
                non_interference_surface_names_v1(fixture_id).ok_or("no names")?
            );
            let record = fs::read(directory.path().join(G_PLUG_HOST_STORE_FILE_V1))?;
            assert!(contains(&record, value), "{fixture_id}");
            assert!(directory.path().join(G_PLUG_CACHE_FILE_V1).exists());
        }
    }
    Ok(())
}

/// The operational facet of every row's `Denial` capture, exactly.
#[test]
fn each_row_keeps_only_its_declared_operational_facet() -> TestResult {
    let directory = tempfile::tempdir()?;
    let value = G_PLUG_CONTROL_UNAUTHORIZED_V1;
    let run = |fixture_id: &str| {
        let work = directory.path().join(fixture_id);
        fs::create_dir_all(&work)?;
        let permitted = g_plug_permitted_input_v1(fixture_id, NonInterferenceVariantV1::Denial);
        let captured = capture(
            fixture_id,
            NonInterferenceVariantV1::Denial,
            &permitted,
            value,
            &work,
        )?;
        let record = fs::read(work.join(G_PLUG_HOST_STORE_FILE_V1))?;
        Ok::<_, Box<dyn std::error::Error>>((captured, record))
    };
    let count = |category, count, excluded_sensitive: &[u8]| {
        NonInterferenceRawOperationalV1::CategoryCount {
            category,
            count,
            excluded_sensitive: excluded_sensitive.to_vec(),
        }
    };

    let (tool, record) = run(G_PLUG_TOOL_FIXTURE_ID_V1)?;
    let digest_of = |index: usize| *blake3::hash(&tool.authoritative[index]).as_bytes();
    let counted = |category, count, index: usize, excluded_sensitive: &[u8]| {
        NonInterferenceRawOperationalV1::CategoryCountDigest {
            category,
            count,
            digest: digest_of(index),
            excluded_sensitive: excluded_sensitive.to_vec(),
        }
    };
    // Two drive Events, three reduce calls (the third is the Denial probe).
    assert_eq!(
        tool.operational,
        vec![
            counted(1, 1, 0, &record),
            counted(1, 1, 1, &record),
            counted(0, 3, 2, &[]),
            counted(0, 2, 3, &[]),
            counted(0, 3, 4, &[]),
            counted(1, 1, 5, &record),
        ]
    );
    assert!(contains(
        &record,
        format!("denied tool response: {}", hex(value)).as_bytes()
    ));

    let (state, record) = run(G_PLUG_STATE_FIXTURE_ID_V1)?;
    assert_eq!(
        state.operational,
        vec![
            count(1, 0, &[]),
            count(0, 1, &record),
            count(0, 3, &[]),
            count(0, 3, &[]),
            count(0, 2, &[]),
            count(0, 1, &[]),
        ]
    );
    // The migrate-state request was refused: the closed record, count 0.
    let mut migration = Vec::new();
    ciborium::into_writer(
        &ciborium::Value::Array(vec![
            ciborium::Value::Text("migrate-state refused".to_owned()),
            ciborium::Value::Integer(0.into()),
        ]),
        &mut migration,
    )?;
    assert_eq!(state.authoritative[0], migration);
    assert!(contains(&state.authoritative[5], b"capability-required"));
    // The host composition that invokes the guest is part of the capture.
    for name in [&b"ni-g-plug"[..], b"ni-g-plug.driver"] {
        assert!(contains(&state.authoritative[2], name));
    }

    let (network, record) = run(G_PLUG_NET_FIXTURE_ID_V1)?;
    assert_eq!(
        network.operational,
        vec![
            count(1, 1, &record),
            count(0, 0, &record),
            count(0, 0, &record),
            count(0, 3, &[]),
            count(0, 2, &[]),
            count(0, 0, &record),
            count(0, 1, &[]),
        ]
    );
    assert!(contains(&record, b".denied.invalid"));
    assert!(contains(&record, b"203.0.113.100"));
    assert!(contains(&record, b"retry-after-21ms"));
    assert!(contains(&record, b"hidden-branch-"));

    let (service, _) = run(G_PLUG_SERVICE_FIXTURE_ID_V1)?;
    assert_eq!(
        service.operational,
        service
            .authoritative
            .iter()
            .map(|surface| NonInterferenceRawOperationalV1::ByteExact(surface.clone()))
            .collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn a_lookup_without_a_frozen_record_is_a_live_call_and_never_a_pass() -> TestResult {
    let work = tempfile::tempdir()?;
    let mut harness = g_plug_harness(work.path())?;
    for fixture_id in [G_PLUG_NET_FIXTURE_ID_V1, G_PLUG_SERVICE_FIXTURE_ID_V1] {
        let unadmitted = format!("g-plug unadmitted request/{fixture_id}").into_bytes();
        let directory = tempfile::tempdir()?;
        let captured = capture(
            fixture_id,
            NonInterferenceVariantV1::Success,
            &unadmitted,
            G_PLUG_CONTROL_UNAUTHORIZED_V1,
            directory.path(),
        )?;
        assert_eq!(captured.unexpected_network_accesses, 1, "{fixture_id}");
        for mode in [
            ExecutionModeV1::Local,
            ExecutionModeV1::Replay,
            ExecutionModeV1::Fork,
        ] {
            let pair = NonInterferenceFixturePairV1::try_new(
                fixture_id,
                NonInterferenceVariantV1::Success,
                mode,
                unadmitted.clone(),
                G_PLUG_CONTROL_UNAUTHORIZED_V1.to_vec(),
                G_PLUG_CANARY_UNAUTHORIZED_V1.to_vec(),
            )?;
            let outcome = harness.execute_case(&pair);
            assert_eq!(
                outcome.non_executed_cause(),
                Some(NonInterferenceNonExecutedCauseV1::LiveCall),
                "{fixture_id} {mode:?}"
            );
            assert_eq!(outcome.claim(), None);
        }
    }
    // The tool and state rows resolve no frozen record, so they make no call.
    let directory = tempfile::tempdir()?;
    let captured = capture(
        G_PLUG_TOOL_FIXTURE_ID_V1,
        NonInterferenceVariantV1::Success,
        b"g-plug unadmitted request/tool",
        G_PLUG_CONTROL_UNAUTHORIZED_V1,
        directory.path(),
    )?;
    assert_eq!(captured.unexpected_network_accesses, 0);
    Ok(())
}

#[test]
fn a_capture_without_an_adapter_or_its_host_files_is_typed_non_executed() -> TestResult {
    let directory = tempfile::tempdir()?;
    assert_eq!(
        g_plug_experiment_v1("NI-CACHE-002", b"x").err(),
        Some(NonInterferenceNonExecutedCauseV1::Missing)
    );
    let events = subject_events(G_PLUG_TOOL_FIXTURE_ID_V1, b"x")?;
    let run = |fixture_id| GPlugRunV1 {
        fixture_id,
        variant: NonInterferenceVariantV1::Success,
        permitted_input: b"x",
        unauthorized_value: b"y",
    };
    assert_eq!(
        g_plug_capture_v1(&run("NI-CACHE-002"), &events, directory.path()).err(),
        Some(NonInterferenceNonExecutedCauseV1::Missing)
    );
    // No directory for the host's files.
    assert_eq!(
        g_plug_capture_v1(
            &run(G_PLUG_TOOL_FIXTURE_ID_V1),
            &events,
            &directory.path().join("absent")
        )
        .err(),
        Some(NonInterferenceNonExecutedCauseV1::Unavailable)
    );
    // A cached descriptor but no writable host record.
    let cached = directory.path().join("cached");
    fs::create_dir_all(cached.join(G_PLUG_HOST_STORE_FILE_V1))?;
    fs::write(cached.join(G_PLUG_CACHE_FILE_V1), b"cached")?;
    assert_eq!(
        g_plug_capture_v1(&run(G_PLUG_TOOL_FIXTURE_ID_V1), &events, &cached).err(),
        Some(NonInterferenceNonExecutedCauseV1::Unavailable)
    );
    // A cause outside the captured stream refuses the capture.
    let mut dangling = events.clone();
    dangling[1].causation_id = Some(pos_core::ids::EventId::new());
    assert_eq!(
        g_plug_capture_v1(&run(G_PLUG_TOOL_FIXTURE_ID_V1), &dangling, directory.path()).err(),
        Some(NonInterferenceNonExecutedCauseV1::Unavailable)
    );
    // A warm directory reads the cached descriptor record instead of calling
    // describe.
    let warm = directory.path().join("warm");
    fs::create_dir_all(&warm)?;
    fs::write(warm.join(G_PLUG_CACHE_FILE_V1), b"cached-descriptor")?;
    let captured = g_plug_capture_v1(&run(G_PLUG_TOOL_FIXTURE_ID_V1), &events, &warm)?;
    assert!(contains(&captured.authoritative[2], b"cached-descriptor"));
    Ok(())
}

// ---------------------------------------------------------------------------
// The public Plugin protocol
// ---------------------------------------------------------------------------

fn invocation() -> pos_runtime::community_plugin_host::PluginInvocationV1 {
    g_plug_invocation_v1(1, 1, b"observation".to_vec(), vec![0; 32])
}

/// Answers every request with a `describe` report.
fn describes_everything(_: &[u8]) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    serve_g_plug_fixture_guest_v1(&request_bytes(&WorkerCallV1::Describe))
}

/// Answers every request with a `reduce` report.
fn produces_everything(_: &[u8]) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    serve_g_plug_fixture_guest_v1(&request_bytes(&WorkerCallV1::Reduce(invocation())))
}

/// Answers with the guest's output, its output digest tampered.
fn tampers_outputs(request: &[u8]) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    serve_g_plug_fixture_guest_v1(request)
        .and_then(|bytes| decode_worker_response_v1(&bytes).ok())
        .and_then(Result::ok)
        .and_then(|returned| match returned {
            WorkerReturnV1::Produced(mut report) => {
                if let Ok(output) = report.result.as_mut() {
                    output.output_digest = [7; 32];
                }
                encode_worker_response_v1(&Ok(WorkerReturnV1::Produced(report))).ok()
            }
            WorkerReturnV1::Described(_) => None,
        })
}

/// Answers every request with a closed engine failure.
fn fails_everything(_: &[u8]) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    encode_worker_response_v1(&Err(CommunityPluginHostErrorV1::FuelExhausted)).ok()
}

/// Answers every request, even one the codec refuses, with garbage.
fn answers_garbage(request: &[u8]) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    (!request.is_empty()).then(|| zeroize::Zeroizing::new(b"not a response".to_vec()))
}

thread_local! {
    /// The last request the recording endpoint received.
    static SEEN: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Records the request it receives and answers nothing.
fn record(request: &[u8]) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    SEEN.with(|seen| *seen.borrow_mut() = request.to_vec());
    None
}

fn seen() -> Vec<u8> {
    SEEN.with(|seen| seen.borrow().clone())
}

/// A PWQ1 request the real host sends for `call`, taken from what the host
/// hands its endpoint.
fn request_bytes(call: &WorkerCallV1) -> Vec<u8> {
    let host = GPlugProtocolHostV1::new(record);
    match call {
        WorkerCallV1::Describe => {
            assert!(host.describe().is_none());
        }
        WorkerCallV1::Reduce(invocation) => {
            assert!(host.reduce(invocation).is_none());
        }
        WorkerCallV1::Drive(invocation) => {
            assert!(host.drive(invocation).is_none());
        }
    }
    seen()
}

#[test]
fn the_fixture_guest_answers_describe_reduce_and_drive_over_the_protocol() -> TestResult {
    let host = GPlugProtocolHostV1::new(serve_g_plug_fixture_guest_v1);
    let descriptor = host.describe().ok_or("no descriptor")?;
    assert_eq!(descriptor.plugin_id, G_PLUG_GUEST_PLUGIN_ID_V1);
    assert_eq!(
        descriptor.event_schema_digests,
        vec![*blake3::hash(G_PLUG_EVENT_TYPE_V1.as_bytes()).as_bytes()]
    );

    let drive = host.drive(&invocation()).ok_or("no drive output")?;
    assert_eq!(drive.event_drafts.len(), 1);
    assert_eq!(drive.event_drafts[0].event_type, G_PLUG_EVENT_TYPE_V1);
    assert_eq!(drive.next_state_bytes, vec![0; 32]);

    let reduce = host
        .reduce(&invocation())
        .ok_or("no reduce output")?
        .map_err(|error| format!("{error:?}"))?;
    let mut folded = vec![0; 32];
    folded.extend_from_slice(b"observation");
    assert_eq!(
        reduce.next_state_bytes,
        blake3::hash(&folded).as_bytes().to_vec()
    );
    assert!(reduce.event_drafts.is_empty());

    let mut probe = G_PLUG_PROBE_PREFIX_V1.to_vec();
    probe.extend_from_slice(b"ni.cap.tool");
    let refused = host
        .reduce(&g_plug_invocation_v1(2, 1, probe, vec![0; 32]))
        .ok_or("no probe answer")?;
    assert_eq!(
        refused.err().map(|error| error.code),
        Some(PluginErrorCodeV1::CapabilityRequired(
            "ni.cap.tool".to_owned()
        ))
    );

    // Every request the host sends is a PWQ1 for the fixture Component.
    for call in [
        WorkerCallV1::Describe,
        WorkerCallV1::Reduce(invocation()),
        WorkerCallV1::Drive(invocation()),
    ] {
        let decoded =
            decode_worker_request_v1(&request_bytes(&call)).map_err(|_| "undecodable request")?;
        assert_eq!(decoded.component.as_slice(), G_PLUG_COMPONENT_V1);
        assert_eq!(decoded.call, call);
        assert_eq!(decoded.negotiation.not_granted_capabilities.len(), 4);
        // Every negotiated limit is 1 MiB.
        assert_eq!(decoded.negotiation.limits.memory_bytes, 1_048_576);
        assert_eq!(decoded.negotiation.limits.log_bytes, 1_048_576);
    }
    Ok(())
}

#[test]
fn a_migrate_state_request_is_refused_by_the_protocol() -> TestResult {
    let host = GPlugProtocolHostV1::new(serve_g_plug_fixture_guest_v1);
    assert_eq!(host.migrate_state(&invocation()), None);
    // The host still sends it: an endpoint that answers everything answers it.
    assert_eq!(
        GPlugProtocolHostV1::new(answers_garbage).migrate_state(&invocation()),
        Some(zeroize::Zeroizing::new(b"not a response".to_vec()))
    );
    // The migrate-state request is the reduce envelope with call code 3,
    // which the codec refuses.
    let reduce = request_bytes(&WorkerCallV1::Reduce(invocation()));
    let mut migrate = reduce.clone();
    let code = reduce
        .iter()
        .zip(&request_bytes(&WorkerCallV1::Drive(invocation())))
        .position(|(left, right)| left != right)
        .ok_or("no call code")?;
    assert_eq!(reduce[code], 1);
    migrate[code] = 3;
    assert!(decode_worker_request_v1(&migrate).is_err());
    // That is exactly what the host sends.
    assert_eq!(
        GPlugProtocolHostV1::new(record).migrate_state(&invocation()),
        None
    );
    assert_eq!(seen(), migrate);
    assert_eq!(serve_g_plug_fixture_guest_v1(&migrate), None);
    Ok(())
}

#[test]
fn the_host_admits_only_a_response_for_the_export_it_invoked() -> TestResult {
    // A response for the other export.
    assert_eq!(
        GPlugProtocolHostV1::new(produces_everything).describe(),
        None
    );
    assert_eq!(
        GPlugProtocolHostV1::new(describes_everything).reduce(&invocation()),
        None
    );
    // A tampered output digest.
    let tampered = GPlugProtocolHostV1::new(tampers_outputs);
    assert_eq!(tampered.drive(&invocation()), None);
    assert_eq!(tampered.reduce(&invocation()), None);
    // An output for another invocation.
    let other = g_plug_invocation_v1(9, 1, b"observation".to_vec(), vec![0; 32]);
    assert_eq!(
        GPlugProtocolHostV1::new(produces_everything).reduce(&other),
        None
    );
    // A closed engine failure and an undecodable response.
    assert_eq!(GPlugProtocolHostV1::new(fails_everything).describe(), None);
    assert_eq!(GPlugProtocolHostV1::new(answers_garbage).describe(), None);
    // The guest answers only its own Component and a well-formed envelope.
    assert_eq!(serve_g_plug_fixture_guest_v1(b"not a request"), None);
    let mut foreign = request_bytes(&WorkerCallV1::Describe);
    let at = foreign
        .windows(G_PLUG_COMPONENT_V1.len())
        .position(|window| window == G_PLUG_COMPONENT_V1)
        .ok_or("no Component")?;
    foreign[at] ^= 1;
    assert_eq!(serve_g_plug_fixture_guest_v1(&foreign), None);
    // The engine failure the endpoint answered decodes as one.
    let failed = fails_everything(b"").ok_or("no failure")?;
    assert_eq!(
        decode_worker_response_v1(&failed).map_err(|_| "undecodable")?,
        Err(CommunityPluginHostErrorV1::FuelExhausted)
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Local subject
// ---------------------------------------------------------------------------

#[test]
fn the_local_subject_serves_one_request_or_writes_nothing() -> TestResult {
    let directory = tempfile::tempdir()?;
    let request = NonInterferenceLocalRequestV1 {
        magic: NON_INTERFERENCE_LOCAL_REQUEST_MAGIC_V1.to_owned(),
        version: 1,
        fixture_id: G_PLUG_STATE_FIXTURE_ID_V1.to_owned(),
        variant: NonInterferenceVariantV1::ColdCache,
        mode: ExecutionModeV1::Local,
        preparation: NonInterferencePreparationV1::Cold,
        permitted_input: g_plug_permitted_input_v1(
            G_PLUG_STATE_FIXTURE_ID_V1,
            NonInterferenceVariantV1::ColdCache,
        ),
        unauthorized_value: G_PLUG_CONTROL_UNAUTHORIZED_V1.to_vec(),
    };
    let bytes = pos_crypto::canonical::encode(&request)?;
    let mut output = Vec::new();
    serve_g_plug_local_subject_v1(bytes.as_slice(), &mut output, directory.path())?;
    assert!(!output.is_empty());
    assert_no_unauthorized_bytes(&output, "a Local capture frame");
    let mut refused = Vec::new();
    assert!(
        serve_g_plug_local_subject_v1(&b"not a request"[..], &mut refused, directory.path())
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
