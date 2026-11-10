#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
// The G-OPS subject runs its guest through the community Plugin supervisor,
// which launches workers only on Linux.
#![cfg(target_os = "linux")]

//! Public-interface tests for the G-OPS non-interference capture adapters
//! (ADR-062 Revision 8 slice N3, #1231; owner note
//! `ADR-062_R8_NonInterference_Operations`).
//!
//! The matrix test runs every G-OPS coordinate once:
//! - Local spawns `pos-ni-g-ops-subject` as a fresh process.
//! - Replay and Fork drive the subject through the Experiment host.
//! - Air-Gapped stays the typed non-executed `Unavailable`.
//!
//! Every executed case must:
//! - be equal at every surface;
//! - have the same result digest in every mode;
//! - match the independently derived expected digest in `execution-matrix.json`
//!   (the G-OPS oracle `scripts/generate_non_interference_g_ops_fixtures.py`);
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
use std::time::Duration;

use pos_conformance::{
    non_interference_capture_profiles_v1, normalize_non_interference_capture_v1, ExecutionModeV1,
    NonInterferenceExecutionArtifactV1, NonInterferenceExecutionErrorV1,
    NonInterferenceFixturePairV1, NonInterferenceNormalizationV1, NonInterferenceRawCaptureV1,
    NonInterferenceRawOperationalV1, NonInterferenceVariantV1,
    MAX_NON_INTERFERENCE_EXECUTION_ARTIFACT_BYTES_V1,
};
use pos_core::Event;
use pos_experiment::non_interference_harness::fixture_evidence::non_interference_fixture_executor_key_v1;
use pos_experiment::non_interference_harness::g_ops::{
    g_ops_capture_v1, g_ops_experiment_v1, g_ops_fixture_v1, g_ops_permitted_input_v1,
    serve_g_ops_local_subject_v1, GOpsHostV1, GOpsObservationV1, GOpsRunV1, GOpsSessionSubjectV1,
    G_OPS_CACHE_FIXTURE_ID_V1, G_OPS_CANARY_UNAUTHORIZED_V1, G_OPS_CONTROL_UNAUTHORIZED_V1,
    G_OPS_CRASH_FIXTURE_ID_V1, G_OPS_EVENT_PAYLOAD_V1, G_OPS_EVENT_TYPE_V1, G_OPS_FIXTURE_IDS_V1,
    G_OPS_OBSERVABILITY_FIXTURE_ID_V1, G_OPS_STORE_FILE_V1, G_OPS_SUBJECT_WATCHDOG_V1,
    G_OPS_TIME_FIXTURE_ID_V1, G_OPS_WORKER_ENV_V1,
};
use pos_experiment::non_interference_harness::{
    NonInterferenceForkRunnerV1, NonInterferenceHarnessV1, NonInterferenceLocalProcessRunnerV1,
    NonInterferenceLocalRequestV1, NonInterferenceNonExecutedCauseV1, NonInterferencePreparationV1,
    NonInterferenceReplayRunnerV1, NonInterferenceSignedExecutionV1,
    NON_INTERFERENCE_LOCAL_REQUEST_MAGIC_V1, NON_INTERFERENCE_PUBLICATION_DIRECTORY_V1,
};
use pos_runtime::community_plugin_host::{quarantine_for, CommunityPluginHostErrorV1};
use pos_runtime::PluginAvailabilityV1;
use serde_json::{json, Value};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Coordinate = (String, NonInterferenceVariantV1, ExecutionModeV1);

const SUBJECT: &str = env!("CARGO_BIN_EXE_pos-ni-g-ops-subject");
const WORKER: &str = env!("CARGO_BIN_EXE_pos-ni-g-ops-worker");
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

/// No unauthorized value, nor its hex text, appears in `bytes`.
fn assert_no_unauthorized_bytes(bytes: &[u8], context: &str) {
    for value in [G_OPS_CONTROL_UNAUTHORIZED_V1, G_OPS_CANARY_UNAUTHORIZED_V1] {
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

fn host() -> TestResult<GOpsHostV1> {
    Ok(GOpsHostV1::new(PathBuf::from(WORKER), G_OPS_SUBJECT_WATCHDOG_V1).ok_or("no host")?)
}

/// The Local runner of the G-OPS subject binary. It passes on the worker
/// program and the coverage profile variable.
#[cfg_attr(coverage_nightly, coverage(off))]
fn local_runner(work: &Path) -> TestResult<NonInterferenceLocalProcessRunnerV1> {
    let runner =
        NonInterferenceLocalProcessRunnerV1::new(PathBuf::from(SUBJECT), work.join("local"))?
            .with_env(G_OPS_WORKER_ENV_V1, WORKER);
    Ok(match std::env::var("LLVM_PROFILE_FILE") {
        Ok(value) => runner.with_env("LLVM_PROFILE_FILE", value),
        Err(_) => runner,
    })
}

fn g_ops_harness(work: &Path) -> TestResult<NonInterferenceHarnessV1> {
    let public = non_interference_fixture_executor_key_v1().public_key();
    Ok(
        NonInterferenceHarnessV1::new(non_interference_fixture_executor_key_v1(), vec![public])
            .with_runner(Box::new(local_runner(work)?))
            .with_runner(Box::new(NonInterferenceReplayRunnerV1::new(
                GOpsSessionSubjectV1::new(host()?, work.join("replay")),
            )))
            .with_runner(Box::new(NonInterferenceForkRunnerV1::new(
                GOpsSessionSubjectV1::new(host()?, work.join("fork")),
                0,
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

/// One live subject run: its Events and the capture of `fixture_id` with
/// `unauthorized_value` in a fresh directory below `work`.
fn capture(
    host: &GOpsHostV1,
    fixture_id: &str,
    variant: NonInterferenceVariantV1,
    unauthorized_value: &[u8],
    directory: &Path,
) -> TestResult<(Vec<Event>, NonInterferenceRawCaptureV1)> {
    let permitted = g_ops_permitted_input_v1(fixture_id, variant);
    let (experiment, handles) = g_ops_experiment_v1(host, &permitted)?;
    let mut session = experiment.start()?;
    while session.step()? {}
    let events = session.source_events()?;
    let handle = handles.current().ok_or("no subject handle")?;
    let captured = g_ops_capture_v1(
        host,
        &GOpsRunV1 {
            fixture_id,
            variant,
            permitted_input: &permitted,
            unauthorized_value,
        },
        &GOpsObservationV1 {
            events: &events,
            handle: &handle,
        },
        directory,
    )?;
    Ok((events, captured))
}

// ---------------------------------------------------------------------------
// Matrix
// ---------------------------------------------------------------------------

/// Run every G-OPS coordinate once and return the executed cases. Every
/// Air-Gapped case must carry its typed cause and no claim.
fn execute_every_coordinate(
    work: &Path,
) -> TestResult<BTreeMap<Coordinate, NonInterferenceSignedExecutionV1>> {
    let mut harness = g_ops_harness(work)?;
    let mut executed = BTreeMap::new();
    for fixture_id in G_OPS_FIXTURE_IDS_V1 {
        for variant in VARIANTS {
            for mode in MODES {
                let fixture = g_ops_fixture_v1(fixture_id, variant, mode)?;
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
fn every_g_ops_coordinate_executes_or_stays_typed_non_executed_and_matches_its_nia1() -> TestResult
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
        // The checked-in NIA1 of the coordinate, in every body field but the
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
// Fixtures: the one-delta proof
// ---------------------------------------------------------------------------

#[test]
fn every_g_ops_pair_differs_only_in_its_declared_unauthorized_value() -> TestResult {
    for fixture_id in G_OPS_FIXTURE_IDS_V1 {
        for variant in VARIANTS {
            let pairs = MODES
                .iter()
                .map(|mode| g_ops_fixture_v1(fixture_id, variant, *mode))
                .collect::<Result<Vec<_>, _>>()?;
            for pair in &pairs {
                pair.validate()?;
                assert_eq!(
                    pair.permitted_input,
                    g_ops_permitted_input_v1(fixture_id, variant)
                );
                assert_eq!(
                    pair.control_unauthorized_value,
                    G_OPS_CONTROL_UNAUTHORIZED_V1
                );
                assert_eq!(pair.canary_unauthorized_value, G_OPS_CANARY_UNAUTHORIZED_V1);
                assert!(!contains(
                    &pair.permitted_input,
                    G_OPS_CONTROL_UNAUTHORIZED_V1
                ));
                assert!(!contains(
                    &pair.permitted_input,
                    G_OPS_CANARY_UNAUTHORIZED_V1
                ));
                // Every mode runs the same admitted pair.
                assert_eq!(pair.fixture_digest, pairs[0].fixture_digest);
            }
        }
    }
    // The two values differ in length modulo 3, first byte and parity, so
    // every value-driven host channel actually changes.
    assert_ne!(
        G_OPS_CONTROL_UNAUTHORIZED_V1.len() % 3,
        G_OPS_CANARY_UNAUTHORIZED_V1.len() % 3
    );
    assert_ne!(
        G_OPS_CONTROL_UNAUTHORIZED_V1[0],
        G_OPS_CANARY_UNAUTHORIZED_V1[0]
    );
    assert_eq!(
        NonInterferenceFixturePairV1::try_new(
            G_OPS_TIME_FIXTURE_ID_V1,
            NonInterferenceVariantV1::Success,
            ExecutionModeV1::Local,
            g_ops_permitted_input_v1(G_OPS_TIME_FIXTURE_ID_V1, NonInterferenceVariantV1::Success),
            G_OPS_CANARY_UNAUTHORIZED_V1.to_vec(),
            G_OPS_CANARY_UNAUTHORIZED_V1.to_vec(),
        ),
        Err(NonInterferenceExecutionErrorV1::FixtureInvalid)
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Captures: raw typed facets through the #181 normalizer
// ---------------------------------------------------------------------------

/// The excluded bytes of every operational facet, in surface order.
fn excluded(capture: &NonInterferenceRawCaptureV1) -> Vec<Vec<u8>> {
    capture
        .operational
        .iter()
        .map(|facet| match facet {
            NonInterferenceRawOperationalV1::CategoryCountDigest {
                excluded_sensitive, ..
            }
            | NonInterferenceRawOperationalV1::CountClass {
                excluded_sensitive, ..
            }
            | NonInterferenceRawOperationalV1::CategoryCount {
                excluded_sensitive, ..
            }
            | NonInterferenceRawOperationalV1::CategoryCountPaddedLength {
                excluded_sensitive,
                ..
            }
            | NonInterferenceRawOperationalV1::OmitOperational { excluded_sensitive } => {
                excluded_sensitive.clone()
            }
            NonInterferenceRawOperationalV1::ByteExact(_) => Vec::new(),
        })
        .collect()
}

/// A facet of another typed normalizer than `normalization`.
fn other_facet(normalization: NonInterferenceNormalizationV1) -> NonInterferenceRawOperationalV1 {
    match normalization {
        NonInterferenceNormalizationV1::ByteExact => {
            NonInterferenceRawOperationalV1::OmitOperational {
                excluded_sensitive: Vec::new(),
            }
        }
        _ => NonInterferenceRawOperationalV1::ByteExact(vec![1]),
    }
}

/// The value-driven details each row keeps only in its excluded bytes.
fn assert_row_operational_details(
    fixture_id: &str,
    value: &[u8],
    directory: &Path,
    excluded: &[Vec<u8>],
) {
    // One to three sibling decisions, by the value's length.
    let siblings = value.len() % 3 + 1;
    match fixture_id {
        G_OPS_CACHE_FIXTURE_ID_V1 => {
            let counts = [2_u64, 0, siblings as u64]
                .iter()
                .flat_map(|count| count.to_be_bytes())
                .collect::<Vec<_>>();
            assert!(excluded[0].starts_with(&counts));
            assert!(excluded[0].ends_with(b"us"));
            assert_eq!(excluded[3], vec![1; siblings]);
            assert_eq!(
                excluded[5],
                directory
                    .join(G_OPS_STORE_FILE_V1)
                    .to_string_lossy()
                    .as_bytes()
            );
        }
        G_OPS_OBSERVABILITY_FIXTURE_ID_V1 => {
            // The subject's four metering counters.
            assert_eq!(excluded[1].len(), 32);
            assert_eq!(excluded[2], directory.to_string_lossy().as_bytes());
        }
        G_OPS_TIME_FIXTURE_ID_V1 => {
            let margin = u64::from(value[0]);
            let wall = format!("{}ms+{margin}ms/{}ms", value.len() % 3, 30_000 + margin);
            assert!(contains(&excluded[1], wall.as_bytes()), "{wall}");
            assert!(contains(&excluded[3], &u128::from(margin).to_be_bytes()));
            // The sibling's four metering counters, then the wall clock.
            assert!(excluded[4].len() > 32 && excluded[4].ends_with(wall.as_bytes()));
        }
        _ => assert_eq!(
            excluded[4],
            format!("crash-{}.cbor", hex(value)).into_bytes()
        ),
    }
}

#[test]
fn every_g_ops_capture_normalizes_only_its_row_listed_operational_fields() -> TestResult {
    let host = host()?;
    let profiles = non_interference_capture_profiles_v1();
    // The surface whose excluded bytes carry the value, per row.
    let carriers: [(&str, &[usize]); 4] = [
        (G_OPS_CACHE_FIXTURE_ID_V1, &[]),
        (G_OPS_OBSERVABILITY_FIXTURE_ID_V1, &[0, 3, 4]),
        (G_OPS_TIME_FIXTURE_ID_V1, &[]),
        (G_OPS_CRASH_FIXTURE_ID_V1, &[0, 3]),
    ];
    for (fixture_id, carrying) in carriers {
        let profile = profiles
            .iter()
            .find(|profile| profile.fixture_id == fixture_id)
            .ok_or("no profile")?;
        let work = tempfile::tempdir()?;
        let mut normalized = Vec::new();
        for (index, value) in [G_OPS_CONTROL_UNAUTHORIZED_V1, G_OPS_CANARY_UNAUTHORIZED_V1]
            .iter()
            .enumerate()
        {
            let directory = work.path().join(index.to_string());
            fs::create_dir_all(&directory)?;
            let (events, captured) = capture(
                &host,
                fixture_id,
                NonInterferenceVariantV1::Success,
                value,
                &directory,
            )?;
            // The subject's one Event is the guest's constant draft.
            assert_eq!(events.len(), 1, "{fixture_id}");
            assert_eq!(events[0].event_type.as_str(), G_OPS_EVENT_TYPE_V1);
            assert_eq!(events[0].payload.as_slice(), G_OPS_EVENT_PAYLOAD_V1);
            // Authoritative and public facets are the same closed records,
            // with no unauthorized byte.
            assert_eq!(captured.authoritative, captured.public, "{fixture_id}");
            for record in &captured.authoritative {
                assert_no_unauthorized_bytes(record, fixture_id);
            }
            // The value reaches only the excluded operational bytes.
            let excluded = excluded(&captured);
            for surface in carrying {
                assert!(
                    contains(&excluded[*surface], value),
                    "{fixture_id} surface {surface}"
                );
            }
            assert_row_operational_details(fixture_id, value, &directory, &excluded);
            // Any other normalizer for any surface is refused.
            for (surface, normalization) in profile.surface_normalizations.iter().enumerate() {
                let mut renormalized = captured.clone();
                renormalized.operational[surface] = other_facet(*normalization);
                assert_eq!(
                    normalize_non_interference_capture_v1(fixture_id, renormalized).err(),
                    Some(NonInterferenceExecutionErrorV1::CaptureUnavailable),
                    "{fixture_id} surface {surface}"
                );
            }
            let normal = normalize_non_interference_capture_v1(fixture_id, captured)?;
            for value in [G_OPS_CONTROL_UNAUTHORIZED_V1, G_OPS_CANARY_UNAUTHORIZED_V1] {
                for facet in &normal.operational {
                    assert!(!contains(facet, value), "{fixture_id}");
                }
            }
            normalized.push(normal);
        }
        // Control and canary are equal on every facet once normalized.
        assert_eq!(normalized[0].authoritative, normalized[1].authoritative);
        assert_eq!(normalized[0].operational, normalized[1].operational);
    }
    Ok(())
}

#[test]
fn the_cache_capture_counts_hits_and_reuses_a_warm_store() -> TestResult {
    let host = host()?;
    let directory = tempfile::tempdir()?;
    let classes = |captured: &NonInterferenceRawCaptureV1| {
        captured
            .operational
            .iter()
            .map(|facet| match facet {
                NonInterferenceRawOperationalV1::CountClass { class, count, .. } => {
                    Some((*class, *count))
                }
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    for (reused, value) in [
        (0, G_OPS_CONTROL_UNAUTHORIZED_V1),
        (1, G_OPS_CANARY_UNAUTHORIZED_V1),
    ] {
        let (_, captured) = capture(
            &host,
            G_OPS_CACHE_FIXTURE_ID_V1,
            NonInterferenceVariantV1::WarmCache,
            value,
            directory.path(),
        )?;
        assert_eq!(
            classes(&captured),
            vec![
                Some((1, 2)),
                Some((reused, 1)),
                Some((0, 1)),
                Some((0, 0)),
                Some((0, 2)),
                Some((0, 1)),
            ]
        );
    }
    assert!(directory.path().join(G_OPS_STORE_FILE_V1).exists());
    Ok(())
}

// ---------------------------------------------------------------------------
// Watchdog and non-executed causes
// ---------------------------------------------------------------------------

#[test]
fn an_operational_watchdog_expiry_is_non_executed_and_never_resource_exhaustion() -> TestResult {
    // A subject whose worker cannot reply within its watchdog stops with the
    // operational watchdog: the case is non-executed `Unavailable`, never
    // `Budget`, and claims nothing.
    let work = tempfile::tempdir()?;
    let stopped =
        GOpsHostV1::new(PathBuf::from(WORKER), Duration::from_millis(1)).ok_or("no host")?;
    let public = non_interference_fixture_executor_key_v1().public_key();
    let permitted = g_ops_permitted_input_v1(
        G_OPS_TIME_FIXTURE_ID_V1,
        NonInterferenceVariantV1::ColdCache,
    );
    let (experiment, handles) = g_ops_experiment_v1(&stopped, &permitted)?;
    let mut session = experiment.start()?;
    assert!(session.step().is_err());
    let handle = handles.current().ok_or("no subject handle")?;
    assert_eq!(
        handle.last_failure(),
        Some(CommunityPluginHostErrorV1::OperationalWatchdogStop)
    );
    // It quarantines nothing: the Plugin stays available.
    assert_eq!(handle.availability(), PluginAvailabilityV1::Available);
    let mut harness =
        NonInterferenceHarnessV1::new(non_interference_fixture_executor_key_v1(), vec![public])
            .with_runner(Box::new(NonInterferenceReplayRunnerV1::new(
                GOpsSessionSubjectV1::new(stopped, work.path().join("replay")),
            )));
    for fixture_id in G_OPS_FIXTURE_IDS_V1 {
        let fixture = g_ops_fixture_v1(
            fixture_id,
            NonInterferenceVariantV1::ColdCache,
            ExecutionModeV1::Replay,
        )?;
        let outcome = harness.execute_case(&fixture);
        assert_eq!(
            outcome.non_executed_cause(),
            Some(NonInterferenceNonExecutedCauseV1::Unavailable),
            "{fixture_id}"
        );
        assert_eq!(outcome.claim(), None);
    }
    // The watchdog stop quarantines nothing; only a deterministic budget is
    // resource exhaustion.
    assert_eq!(
        quarantine_for(CommunityPluginHostErrorV1::OperationalWatchdogStop),
        None
    );
    assert_eq!(
        quarantine_for(CommunityPluginHostErrorV1::FuelExhausted),
        Some(PluginAvailabilityV1::ResourceExhausted)
    );
    // A watchdog the supervisor refuses, or a relative worker, has no host.
    assert!(GOpsHostV1::new(PathBuf::from(WORKER), Duration::ZERO).is_none());
    assert!(GOpsHostV1::new(PathBuf::from("worker"), G_OPS_SUBJECT_WATCHDOG_V1).is_none());
    Ok(())
}

#[test]
fn a_capture_without_an_adapter_or_a_seam_is_typed_non_executed() -> TestResult {
    let host = host()?;
    let directory = tempfile::tempdir()?;
    assert_eq!(
        capture(
            &host,
            "NI-TOOL-001",
            NonInterferenceVariantV1::Success,
            b"x",
            directory.path()
        )
        .err()
        .map(|error| error.to_string()),
        Some(NonInterferenceNonExecutedCauseV1::Missing.to_string())
    );
    // The cache seam store cannot be opened below a missing directory.
    assert_eq!(
        capture(
            &host,
            G_OPS_CACHE_FIXTURE_ID_V1,
            NonInterferenceVariantV1::Success,
            b"x",
            &directory.path().join("absent")
        )
        .err()
        .map(|error| error.to_string()),
        Some(NonInterferenceNonExecutedCauseV1::Unavailable.to_string())
    );
    // A run whose Driver left no receipt has nothing to capture.
    let permitted =
        g_ops_permitted_input_v1(G_OPS_TIME_FIXTURE_ID_V1, NonInterferenceVariantV1::Success);
    let (_, handles) = g_ops_experiment_v1(&host, &permitted)?;
    let handle = handles.current().ok_or("no subject handle")?;
    assert_eq!(
        g_ops_capture_v1(
            &host,
            &GOpsRunV1 {
                fixture_id: G_OPS_TIME_FIXTURE_ID_V1,
                variant: NonInterferenceVariantV1::Success,
                permitted_input: &permitted,
                unauthorized_value: b"x",
            },
            &GOpsObservationV1 {
                events: &[],
                handle: &handle,
            },
            directory.path(),
        )
        .err(),
        Some(NonInterferenceNonExecutedCauseV1::Unavailable)
    );
    Ok(())
}

#[test]
fn the_local_subject_serves_one_request_or_writes_nothing() -> TestResult {
    let host = host()?;
    let directory = tempfile::tempdir()?;
    let request = NonInterferenceLocalRequestV1 {
        magic: NON_INTERFERENCE_LOCAL_REQUEST_MAGIC_V1.to_owned(),
        version: 1,
        fixture_id: G_OPS_CRASH_FIXTURE_ID_V1.to_owned(),
        variant: NonInterferenceVariantV1::ColdCache,
        mode: ExecutionModeV1::Local,
        preparation: NonInterferencePreparationV1::Cold,
        permitted_input: g_ops_permitted_input_v1(
            G_OPS_CRASH_FIXTURE_ID_V1,
            NonInterferenceVariantV1::ColdCache,
        ),
        unauthorized_value: G_OPS_CONTROL_UNAUTHORIZED_V1.to_vec(),
    };
    let bytes = pos_crypto::canonical::encode(&request)?;
    let mut output = Vec::new();
    serve_g_ops_local_subject_v1(&host, bytes.as_slice(), &mut output, directory.path())?;
    assert!(!output.is_empty());
    assert_no_unauthorized_bytes(&output, "a Local capture frame");
    let mut refused = Vec::new();
    assert!(serve_g_ops_local_subject_v1(
        &host,
        &b"not a request"[..],
        &mut refused,
        directory.path()
    )
    .is_err());
    assert!(refused.is_empty());
    // The binary exits non-zero without a frame for a malformed request, and
    // without a worker program.
    for worker in [Some(WORKER), None] {
        let mut command = Command::new(SUBJECT);
        command
            .current_dir(directory.path())
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(worker) = worker {
            command.env(G_OPS_WORKER_ENV_V1, worker);
        }
        if let Ok(profile) = std::env::var("LLVM_PROFILE_FILE") {
            command.env("LLVM_PROFILE_FILE", profile);
        }
        let mut child = command.spawn()?;
        // A subject without a worker exits before it reads: the write may
        // then meet a closed pipe.
        drop(
            child
                .stdin
                .take()
                .ok_or("no stdin")?
                .write_all(b"not a request"),
        );
        let finished = child.wait_with_output()?;
        assert!(!finished.status.success());
        assert!(finished.stdout.is_empty());
    }
    Ok(())
}
