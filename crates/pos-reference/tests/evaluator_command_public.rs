pub mod support;

use std::error::Error;
#[cfg(unix)]
use std::ffi::OsString;
use std::fs;
#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
use std::io::{Cursor, Write};
use std::path::Path;
use std::process::{Command, Stdio};
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(target_os = "linux")]
use std::os::{
    fd::AsRawFd,
    unix::fs::{symlink, OpenOptionsExt},
};

#[cfg(unix)]
use ciborium::value::Value;
#[cfg(target_os = "linux")]
use pos_reference::evaluator_build_identity::{
    verify_evaluator_build_identity, EvaluatorBuildEvidence, EvaluatorBuildIdentityError,
    VerifiedEvaluatorBuildIdentity,
};
#[cfg(target_os = "linux")]
use pos_reference::evaluator_protocol::IndependenceEvidence;
use pos_reference::evaluator_protocol::{CaseStatus, ConformanceReport, EvaluationRequest};
use pos_reference::profile::Profile;
use pos_reference::signed_bundle::preflight_signed_bundle;
use support::{
    gzip_bytes, pax_record, source_archive, source_tar, tar_header, write_checksum_inventory,
    write_evaluator_package, write_evaluator_provenance, write_tar_checksum,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[cfg(target_os = "linux")]
const FIFO_READY_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(target_os = "linux")]
fn open_fifo_writer_after_child_ready(
    path: &Path,
    child: &mut std::process::Child,
) -> TestResult<fs::File> {
    let deadline = Instant::now() + FIFO_READY_TIMEOUT;
    loop {
        match OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
        {
            Ok(readiness_writer) => {
                let reader_guard = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(path)?;
                let writer = OpenOptions::new().write(true).open(path)?;
                drop(reader_guard);
                drop(readiness_writer);
                return Ok(writer);
            }
            Err(error) if error.raw_os_error() == Some(libc::ENXIO) => {}
            Err(error) => return Err(error.into()),
        }
        if let Some(status) = child.try_wait()? {
            return Err(format!("evaluator exited before opening request FIFO: {status}").into());
        }
        if Instant::now() >= deadline {
            drop(child.kill());
            drop(child.wait());
            return Err("evaluator did not open request FIFO before the deadline".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn evaluator() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pos-reference-evaluator"))
}

#[cfg(unix)]
fn replacing_argument(command: &Command, option: &str, value: &Path) -> TestResult<Command> {
    let mut arguments: Vec<OsString> = command.get_args().map(OsString::from).collect();
    let index = arguments
        .iter()
        .position(|argument| argument.to_str() == Some(option))
        .ok_or("command option is absent")?;
    let target = arguments
        .get_mut(index + 1)
        .ok_or("command option has no value")?;
    value.as_os_str().clone_into(target);
    let mut replacement = evaluator();
    replacement.args(arguments);
    Ok(replacement)
}

fn complete_command(directory: &Path) -> TestResult<Command> {
    complete_command_with_adapter(directory, "/bin/cat")
}

fn complete_command_with_adapter(directory: &Path, adapter: &str) -> TestResult<Command> {
    let corpus = support::corpus()?;
    command_for_corpus(directory, adapter, &corpus)
}

fn command_for_corpus(
    directory: &Path,
    adapter: &str,
    corpus: &support::Corpus,
) -> TestResult<Command> {
    let request = directory.join("request.cbor");
    let bundle = directory.join("bundle.cfb1");
    let policy = directory.join("policy.tps1");
    let source = directory.join("source/pigloros-source.tar.gz");
    let provenance = directory.join("provenance.json");
    fs::write(&request, &corpus.request)?;
    fs::write(&bundle, &corpus.archive)?;
    fs::write(&policy, &corpus.trust_policy)?;
    write_evaluator_package(
        directory,
        Path::new(env!("CARGO_BIN_EXE_pos-reference-evaluator")),
    )?;
    let digest = "01".repeat(32);
    let declaration_digest = "2f".repeat(32);
    let mut command = evaluator();
    command.args([
        "--request",
        request.to_str().ok_or("request path is not UTF-8")?,
        "--bundle",
        bundle.to_str().ok_or("bundle path is not UTF-8")?,
        "--trust-policy",
        policy.to_str().ok_or("policy path is not UTF-8")?,
        "--evaluator-source",
        source.to_str().ok_or("source path is not UTF-8")?,
        "--evaluator-provenance",
        provenance.to_str().ok_or("provenance path is not UTF-8")?,
        "--declaration-digest",
        declaration_digest.as_str(),
        "--shared-code-audit-digest",
        digest.as_str(),
        "--reviewer",
        "reviewer-one",
        "--authorship-independent",
        "--organizational-independent",
        "--adapter",
        adapter,
    ]);
    Ok(command)
}

fn verify_staged_corpus() -> TestResult {
    let corpus = support::corpus()?;
    let request = EvaluationRequest::from_canonical_cbor(&corpus.request)?;
    let mut archive = Cursor::new(corpus.archive);
    let preflight = preflight_signed_bundle(&mut archive, &corpus.trust_policy, &request)?;
    let caps = Profile::authenticated_hard_caps(preflight.profile_bytes(), &request)?;
    preflight.enforce_selected_caps(caps.into())?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn write_public_verifier_package(directory: &Path) -> TestResult {
    write_evaluator_package(directory, &std::env::current_exe()?)
}

#[cfg(target_os = "linux")]
fn public_verifier_result(
    directory: &Path,
    source_archive: &Path,
) -> Result<VerifiedEvaluatorBuildIdentity, EvaluatorBuildIdentityError> {
    public_verifier_result_with_expansion(directory, source_archive, 100)
}

#[cfg(target_os = "linux")]
fn public_verifier_result_with_expansion(
    directory: &Path,
    source_archive: &Path,
    max_compression_expansion: u64,
) -> Result<VerifiedEvaluatorBuildIdentity, EvaluatorBuildIdentityError> {
    verify_evaluator_build_identity(
        &EvaluatorBuildEvidence::new(source_archive, directory.join("provenance.json")),
        IndependenceEvidence {
            technical_independent: true,
            authorship_independent: true,
            organizational_independent: false,
            declaration_digest: [47; 32],
            shared_code_audit_digest: [64; 32],
            reviewer_ids: vec!["reviewer-one".to_owned()],
        },
        max_compression_expansion,
    )
}

#[cfg(target_os = "linux")]
fn assert_public_verifier_error(
    directory: &Path,
    source_archive: &Path,
    expected: EvaluatorBuildIdentityError,
) {
    assert_eq!(
        public_verifier_result(directory, source_archive),
        Err(expected)
    );
}

fn source_archive_with_entry(
    header: &[u8; 512],
    payload: &[u8],
    pad_and_terminate: bool,
) -> TestResult<Vec<u8>> {
    let mut tar = Vec::from(header.as_slice());
    tar.extend_from_slice(payload);
    if pad_and_terminate {
        tar.resize(tar.len().div_ceil(512) * 512, 0);
        tar.extend_from_slice(&[0; 1024]);
    }
    gzip_bytes(&tar)
}

fn rebind_source_archive(directory: &Path, source: &[u8]) -> TestResult {
    fs::write(directory.join("source/pigloros-source.tar.gz"), source)?;
    let path = directory.join("provenance.json");
    let mut provenance: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
    provenance["evaluator_source_blake3"] =
        serde_json::Value::String(blake3::hash(source).to_hex().to_string());
    let mut bytes = serde_json::to_vec(&provenance)?;
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    write_checksum_inventory(directory)
}

#[cfg(unix)]
fn request_with_version(request: &[u8], version: u64) -> TestResult<Vec<u8>> {
    let mut value: ciborium::value::Value = ciborium::from_reader(request)?;
    let ciborium::value::Value::Array(fields) = &mut value else {
        return Err("request is not an array".into());
    };
    fields[1] = ciborium::value::Value::Integer(version.into());
    let mut bytes = Vec::new();
    ciborium::into_writer(&value, &mut bytes)?;
    Ok(bytes)
}

#[cfg(unix)]
fn request_without_diagnostics(request: &[u8]) -> TestResult<Vec<u8>> {
    let mut request = EvaluationRequest::from_canonical_cbor(request)?;
    request.output_capability.diagnostic_bytes_limit = 0;
    request.output_capability.capability_digest = request.expected_output_capability_digest()?;
    request.request_digest = request.digest()?;
    Ok(request.to_canonical_cbor()?)
}

#[cfg(unix)]
enum IndependentObservation {
    Output(Vec<u8>),
    Failure,
    Divergence,
    Unavailable,
}

#[cfg(unix)]
fn unsigned(value: u64) -> Value {
    Value::Integer(value.into())
}

#[cfg(unix)]
fn canonical_value(value: &Value) -> TestResult<Vec<u8>> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded)?;
    Ok(encoded)
}

#[cfg(unix)]
fn framed_value(value: &Value) -> TestResult<Vec<u8>> {
    let encoded = canonical_value(value)?;
    let length = u32::try_from(encoded.len())?;
    let mut framed = Vec::with_capacity(4 + encoded.len());
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(&encoded);
    Ok(framed)
}

#[cfg(unix)]
fn push_transcript_frame(
    stream: &mut Vec<u8>,
    transcript: &mut blake3::Hasher,
    value: &Value,
) -> TestResult {
    let frame = framed_value(value)?;
    transcript.update(&frame);
    stream.extend_from_slice(&frame);
    Ok(())
}

#[cfg(unix)]
fn independent_observation_bytes(
    result: IndependentObservation,
    usage: [u64; 8],
) -> TestResult<Vec<u8>> {
    let mut stream = Vec::new();
    let mut transcript = blake3::Hasher::new();
    transcript.update(b"PiglorOS.EvaluatorObservationStream.v1\0");
    push_transcript_frame(
        &mut stream,
        &mut transcript,
        &Value::Array(vec![Value::Text("EAO1".to_owned()), unsigned(1)]),
    )?;

    let (kind, length, digest, failure, divergence) = match result {
        IndependentObservation::Output(output) => {
            if !output.is_empty() {
                push_transcript_frame(
                    &mut stream,
                    &mut transcript,
                    &Value::Array(vec![
                        Value::Text("EOB1".to_owned()),
                        unsigned(1),
                        unsigned(0),
                        Value::Bytes(output.clone()),
                    ]),
                )?;
            }
            (
                0,
                unsigned(u64::try_from(output.len())?),
                Value::Bytes(blake3::hash(&output).as_bytes().to_vec()),
                Value::Null,
                Value::Null,
            )
        }
        IndependentObservation::Failure => (
            1,
            Value::Null,
            Value::Null,
            Value::Array(vec![
                Value::Text("test-provider".to_owned()),
                Value::Text("1.0.0".to_owned()),
                Value::Text("denied".to_owned()),
            ]),
            Value::Null,
        ),
        IndependentObservation::Divergence => (
            2,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Array(vec![unsigned(2), Value::Bytes(vec![1, 2])]),
        ),
        IndependentObservation::Unavailable => {
            (3, Value::Null, Value::Null, Value::Null, Value::Null)
        }
    };
    stream.extend_from_slice(&framed_value(&Value::Array(vec![
        Value::Text("EOE1".to_owned()),
        unsigned(1),
        unsigned(kind),
        length,
        digest,
        failure,
        divergence,
        Value::Array(usage.into_iter().map(unsigned).collect()),
        Value::Bytes(transcript.finalize().as_bytes().to_vec()),
    ]))?);
    Ok(stream)
}

#[cfg(unix)]
fn write_adapter(directory: &Path, body: &str) -> TestResult<std::path::PathBuf> {
    let adapter = directory.join("fixture-adapter");
    fs::write(&adapter, body)?;
    fs::set_permissions(&adapter, fs::Permissions::from_mode(0o500))?;
    Ok(adapter)
}

#[cfg(unix)]
fn command_with_observation(
    directory: &Path,
    corpus: &support::Corpus,
    observation: &[u8],
) -> TestResult<Command> {
    let response = directory.join("observation.eao1");
    fs::write(&response, observation)?;
    let adapter = write_adapter(
        directory,
        "#!/bin/sh\nset -eu\n/bin/cat >/dev/null\nexec /bin/cat -- \"$1\"\n",
    )?;
    let mut command = command_for_corpus(
        directory,
        adapter.to_str().ok_or("adapter path is not UTF-8")?,
        corpus,
    )?;
    command.args([
        "--adapter-arg",
        response.to_str().ok_or("response path is not UTF-8")?,
    ]);
    Ok(command)
}

#[cfg(unix)]
fn independent_report(bytes: &[u8]) -> TestResult<Vec<Value>> {
    let value: Value = ciborium::from_reader(bytes)?;
    assert_eq!(canonical_value(&value)?, bytes);
    let Value::Array(mut fields) = value else {
        return Err("CNR1 is not an array".into());
    };
    assert_eq!(fields.len(), 24);
    assert_eq!(fields[0], Value::Text("CNR1".to_owned()));
    assert_eq!(fields[1], unsigned(1));
    let Value::Bytes(report_digest) = fields.pop().ok_or("CNR1 digest is absent")? else {
        return Err("CNR1 digest is not bytes".into());
    };
    let unsigned_report = canonical_value(&Value::Array(fields.clone()))?;
    let mut digest_input = b"PiglorOS.ConformanceReport.v1\0".to_vec();
    digest_input.extend_from_slice(&unsigned_report);
    assert_eq!(
        report_digest.as_slice(),
        blake3::hash(&digest_input).as_bytes()
    );
    fields.push(Value::Bytes(report_digest));
    Ok(fields)
}

#[cfg(unix)]
fn assert_report_counts(report: &[Value], expected: [u64; 5]) {
    for (field, count) in report[14..19].iter().zip(expected) {
        assert_eq!(field, &unsigned(count));
    }
}

#[cfg(unix)]
fn report_case<'a>(report: &'a [Value], case_id: &str) -> TestResult<&'a [Value]> {
    let Value::Array(cases) = &report[13] else {
        return Err("CNR1 cases are not an array".into());
    };
    cases
        .iter()
        .find_map(|case| {
            let Value::Array(fields) = case else {
                return None;
            };
            (fields.first() == Some(&Value::Text(case_id.to_owned()))).then_some(fields.as_slice())
        })
        .ok_or_else(|| format!("CNR1 case is absent: {case_id}").into())
}

#[cfg(unix)]
fn assert_case_status(report: &[Value], case_id: &str, status: u64) -> TestResult {
    assert_eq!(report_case(report, case_id)?[5], unsigned(status));
    Ok(())
}

#[cfg(unix)]
fn assert_diagnostic_digest(stderr: &[u8], report: &[Value]) -> TestResult {
    let diagnostic: serde_json::Value = serde_json::from_slice(stderr)?;
    let Value::Bytes(report_digest) = &report[23] else {
        return Err("CNR1 digest is not bytes".into());
    };
    let digest = <[u8; 32]>::try_from(report_digest.as_slice())?;
    assert_eq!(
        diagnostic["report_digest"],
        serde_json::Value::String(blake3::Hash::from_bytes(digest).to_hex().to_string())
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn command_process_boundary_exercises_output_failure_and_divergence_oracles() -> TestResult {
    let scenarios = [
        (
            IndependentObservation::Output(b"accepted".to_vec()),
            "case-0",
            [5, 2, 0, 0, 0],
        ),
        (IndependentObservation::Failure, "case-1", [1, 6, 0, 0, 0]),
        (
            IndependentObservation::Divergence,
            "case-2",
            [1, 6, 0, 0, 0],
        ),
    ];
    for (observation, passing_case, counts) in scenarios {
        let directory = tempfile::tempdir()?;
        let corpus = support::mixed_oracle_corpus()?;
        let response = independent_observation_bytes(observation, [0; 8])?;
        let output = command_with_observation(directory.path(), &corpus, &response)?.output()?;
        assert!(
            output.status.success(),
            "evaluator stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report = independent_report(&output.stdout)?;
        assert_report_counts(&report, counts);
        assert_case_status(&report, passing_case, 0)?;
        assert_eq!(report[16], unsigned(0));
        assert_eq!(report[18], unsigned(0));
        assert_diagnostic_digest(&output.stderr, &report)?;

        if passing_case == "case-1" {
            let case = report_case(&report, passing_case)?;
            assert_eq!(case[9], unsigned(0));
            assert_eq!(case[10], unsigned(0));
        } else if passing_case == "case-2" {
            let case = report_case(&report, passing_case)?;
            assert_eq!(case[6], Value::Bytes(vec![1, 2]));
            assert_ne!(case[8], case[7]);
        }
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn command_process_boundary_classifies_resource_protocol_and_lifecycle_failures() -> TestResult {
    let corpus = support::corpus()?;

    let directory = tempfile::tempdir()?;
    let mut usage = [0; 8];
    usage[0] = 101;
    let response =
        independent_observation_bytes(IndependentObservation::Output(b"accepted".to_vec()), usage)?;
    let output = command_with_observation(directory.path(), &corpus, &response)?.output()?;
    assert!(output.status.success());
    let report = independent_report(&output.stdout)?;
    assert_report_counts(&report, [0, 7, 0, 0, 0]);
    assert_eq!(report_case(&report, "case-0")?[10], unsigned(13));
    assert_diagnostic_digest(&output.stderr, &report)?;

    for response in [
        independent_observation_bytes(IndependentObservation::Unavailable, [0; 8])?,
        independent_observation_bytes(IndependentObservation::Output(vec![0; 101]), [0; 8])?,
        vec![0xff],
    ] {
        let directory = tempfile::tempdir()?;
        let output = command_with_observation(directory.path(), &corpus, &response)?.output()?;
        assert!(output.status.success());
        let report = independent_report(&output.stdout)?;
        assert_report_counts(&report, [0, 0, 0, 7, 0]);
        assert_diagnostic_digest(&output.stderr, &report)?;
    }

    let directory = tempfile::tempdir()?;
    let output = command_for_corpus(directory.path(), "/bin/false", &corpus)?.output()?;
    assert!(output.status.success());
    assert_report_counts(&independent_report(&output.stdout)?, [0, 0, 0, 7, 0]);

    let directory = tempfile::tempdir()?;
    let short_watchdog = support::corpus_with_watchdog_ms(25)?;
    let adapter = write_adapter(
        directory.path(),
        "#!/bin/sh\nset -eu\n/bin/cat >/dev/null\nexec /bin/sleep 60\n",
    )?;
    let output = command_for_corpus(
        directory.path(),
        adapter.to_str().ok_or("adapter path is not UTF-8")?,
        &short_watchdog,
    )?
    .output()?;
    assert!(output.status.success());
    assert_report_counts(&independent_report(&output.stdout)?, [0, 0, 0, 7, 0]);
    Ok(())
}

#[cfg(unix)]
#[test]
fn air_gapped_process_declaration_and_cnr1_bytes_are_repeatable() -> TestResult {
    let corpus = support::air_gapped_corpus()?;
    let response = independent_observation_bytes(
        IndependentObservation::Output(b"accepted".to_vec()),
        [0; 8],
    )?;
    let mut executions = Vec::new();

    for _ in 0..2 {
        let directory = tempfile::tempdir()?;
        let response_path = directory.path().join("observation.eao1");
        let capture_path = directory.path().join("attempt.eai1");
        fs::write(&response_path, &response)?;
        let adapter = write_adapter(
            directory.path(),
            "#!/bin/sh\nset -eu\n/bin/cat >\"$1\"\nexec /bin/cat -- \"$2\"\n",
        )?;
        let mut command = command_for_corpus(
            directory.path(),
            adapter.to_str().ok_or("adapter path is not UTF-8")?,
            &corpus,
        )?;
        command.args([
            "--adapter-arg",
            capture_path.to_str().ok_or("capture path is not UTF-8")?,
            "--adapter-arg",
            response_path.to_str().ok_or("response path is not UTF-8")?,
        ]);
        let output = command.output()?;
        assert!(
            output.status.success(),
            "evaluator stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report = independent_report(&output.stdout)?;
        assert_report_counts(&report, [7, 0, 0, 0, 0]);
        assert_diagnostic_digest(&output.stderr, &report)?;

        let attempt = fs::read(capture_path)?;
        let prefix = <[u8; 4]>::try_from(attempt.get(..4).ok_or("EAI1 prefix is absent")?)?;
        let frame_length = usize::try_from(u32::from_be_bytes(prefix))?;
        let frame_end = 4_usize
            .checked_add(frame_length)
            .ok_or("EAI1 frame overflow")?;
        let header: Value = ciborium::from_reader(
            attempt
                .get(4..frame_end)
                .ok_or("EAI1 header is truncated")?,
        )?;
        let Value::Array(header) = header else {
            return Err("EAI1 header is not an array".into());
        };
        assert_eq!(header[0], Value::Text("EAI1".to_owned()));
        assert_eq!(header[5], unsigned(1));
        assert_eq!(header[9], Value::Bool(false));
        executions.push((output.stdout, output.stderr, attempt));
    }

    assert_eq!(executions[0], executions[1]);
    Ok(())
}

#[test]
fn command_rejects_incomplete_duplicate_and_noncanonical_identity_arguments() -> TestResult {
    assert!(!evaluator().output()?.status.success());

    let duplicated = evaluator()
        .args(["--request", "one", "--request", "two"])
        .output()?;
    assert!(!duplicated.status.success());

    let unknown = evaluator().arg("--legacy-protocol").output()?;
    assert!(!unknown.status.success());

    for option in [
        "--request",
        "--bundle",
        "--trust-policy",
        "--evaluator-source",
        "--evaluator-provenance",
        "--declaration-digest",
        "--shared-code-audit-digest",
        "--reviewer",
        "--adapter",
        "--adapter-arg",
    ] {
        assert!(!evaluator().arg(option).output()?.status.success());
    }

    for flag in ["--authorship-independent", "--organizational-independent"] {
        assert!(!evaluator().args([flag, flag]).output()?.status.success());
    }
    Ok(())
}

#[test]
fn command_rejects_each_missing_required_option() -> TestResult {
    let digest = "01".repeat(32);
    let prefixes = [
        vec!["--reviewer", "reviewer-one"],
        vec!["--request", "request", "--reviewer", "reviewer-one"],
        vec![
            "--request",
            "request",
            "--bundle",
            "bundle",
            "--reviewer",
            "reviewer-one",
        ],
        vec![
            "--request",
            "request",
            "--bundle",
            "bundle",
            "--trust-policy",
            "policy",
            "--reviewer",
            "reviewer-one",
        ],
        vec![
            "--request",
            "request",
            "--bundle",
            "bundle",
            "--trust-policy",
            "policy",
            "--evaluator-source",
            "source",
            "--reviewer",
            "reviewer-one",
        ],
    ];
    for arguments in prefixes {
        assert!(!evaluator().args(arguments).output()?.status.success());
    }
    for arguments in [
        vec![
            "--request",
            "request",
            "--bundle",
            "bundle",
            "--trust-policy",
            "policy",
            "--evaluator-source",
            "source",
            "--evaluator-provenance",
            "provenance",
            "--reviewer",
            "reviewer-one",
        ],
        vec![
            "--request",
            "request",
            "--bundle",
            "bundle",
            "--trust-policy",
            "policy",
            "--evaluator-source",
            "source",
            "--evaluator-provenance",
            "provenance",
            "--declaration-digest",
            digest.as_str(),
            "--reviewer",
            "reviewer-one",
        ],
        vec![
            "--request",
            "request",
            "--bundle",
            "bundle",
            "--trust-policy",
            "policy",
            "--evaluator-source",
            "source",
            "--evaluator-provenance",
            "provenance",
            "--declaration-digest",
            digest.as_str(),
            "--shared-code-audit-digest",
            digest.as_str(),
            "--reviewer",
            "reviewer-one",
        ],
    ] {
        assert!(!evaluator().args(arguments).output()?.status.success());
    }
    Ok(())
}

#[test]
fn command_bounds_files_before_decoding_untrusted_requests() -> TestResult {
    let directory = tempfile::tempdir()?;
    let request = directory.path().join("request.cbor");
    let bundle = directory.path().join("bundle.cfb1");
    let policy = directory.path().join("policy.tps1");
    fs::write(&request, [0xff])?;
    fs::write(&bundle, [0xff])?;
    fs::write(&policy, [0xff])?;
    let digest = "01".repeat(32);
    let output = evaluator()
        .args([
            "--request",
            request.to_str().ok_or("request path is not UTF-8")?,
            "--bundle",
            bundle.to_str().ok_or("bundle path is not UTF-8")?,
            "--trust-policy",
            policy.to_str().ok_or("policy path is not UTF-8")?,
            "--evaluator-source",
            "source",
            "--evaluator-provenance",
            "provenance",
            "--declaration-digest",
            digest.as_str(),
            "--shared-code-audit-digest",
            digest.as_str(),
            "--reviewer",
            "reviewer-one",
            "--adapter",
            "/bin/false",
        ])
        .output()?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());

    let oversized = directory.path().join("oversized-request.cbor");
    fs::File::create(&oversized)?.set_len(16 * 1024 * 1024 + 1)?;
    let oversized_output = evaluator()
        .args([
            "--request",
            oversized.to_str().ok_or("oversized path is not UTF-8")?,
            "--bundle",
            bundle.to_str().ok_or("bundle path is not UTF-8")?,
            "--trust-policy",
            policy.to_str().ok_or("policy path is not UTF-8")?,
            "--evaluator-source",
            "source",
            "--evaluator-provenance",
            "provenance",
            "--declaration-digest",
            digest.as_str(),
            "--shared-code-audit-digest",
            digest.as_str(),
            "--reviewer",
            "reviewer-one",
            "--adapter",
            "/bin/false",
        ])
        .output()?;
    assert!(!oversized_output.status.success());
    assert!(oversized_output.stdout.is_empty());
    Ok(())
}

#[cfg(unix)]
#[test]
fn command_emits_a_self_verified_report_through_the_public_process_boundary() -> TestResult {
    verify_staged_corpus()?;
    let directory = tempfile::tempdir()?;
    let output = complete_command(directory.path())?
        .args(["--adapter-arg", "--ignored-by-cat"])
        .output()?;
    assert!(
        output.status.success(),
        "evaluator stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = ConformanceReport::from_canonical_cbor(&output.stdout)?;
    assert_eq!(report.cases.len(), 7);
    let source = fs::read(directory.path().join("source/pigloros-source.tar.gz"))?;
    assert_eq!(
        report.evaluator_source_digest,
        *blake3::hash(&source).as_bytes()
    );
    let provenance = fs::read(directory.path().join("provenance.json"))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.EvaluatorBuildProvenance.v1");
    hasher.update(&[0]);
    hasher.update(&provenance);
    assert_eq!(
        report.evaluator_build_provenance_digest,
        *hasher.finalize().as_bytes()
    );
    assert_eq!(
        report.independence.reviewer_ids,
        vec!["reviewer-one".to_owned()]
    );
    assert!(report.independence.authorship_independent);
    assert!(report.independence.organizational_independent);
    assert!(!output.stderr.is_empty());
    Ok(())
}

#[cfg(unix)]
#[test]
fn command_accepts_supported_git_commit_and_ustar_path_forms() -> TestResult {
    for (commit, split_evaluator_path) in [("2".repeat(64), false), ("a".repeat(40), true)] {
        let directory = tempfile::tempdir()?;
        let mut command = complete_command(directory.path())?;
        let mut tar = source_tar(&commit);
        if split_evaluator_path {
            let evaluator_header = 5 * 512;
            let mut header = <[u8; 512]>::try_from(&tar[evaluator_header..evaluator_header + 512])?;
            header[..100].fill(0);
            header[..26].copy_from_slice(b"pos-reference-evaluator.rs");
            header[345..373].copy_from_slice(b"crates/pos-reference/src/bin");
            write_tar_checksum(&mut header);
            tar[evaluator_header..evaluator_header + 512].copy_from_slice(&header);
        }
        let source = gzip_bytes(&tar)?;
        rebind_source_archive(directory.path(), &source)?;
        replace_provenance_field(
            directory.path(),
            "source_commit",
            serde_json::Value::String(commit),
        )?;
        write_checksum_inventory(directory.path())?;
        let output = command.output()?;
        assert!(
            output.status.success(),
            "evaluator stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn command_honours_a_zero_diagnostic_output_cap() -> TestResult {
    let directory = tempfile::tempdir()?;
    let corpus = support::corpus()?;
    let mut command = complete_command(directory.path())?;
    fs::write(
        directory.path().join("request.cbor"),
        request_without_diagnostics(&corpus.request)?,
    )?;
    let output = command.output()?;
    assert!(output.status.success());
    assert!(!output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    Ok(())
}

#[cfg(unix)]
#[test]
fn command_accepts_an_exact_authenticated_profile_byte_cap() -> TestResult {
    let directory = tempfile::tempdir()?;
    let corpus = support::corpus_with_profile_mutation(
        support::ProfileMutation::SelectedProfileByteCapExact,
    )?;
    let output = command_for_corpus(directory.path(), "/bin/cat", &corpus)?.output()?;
    assert!(
        output.status.success(),
        "evaluator stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn command_binds_the_loaded_executable_after_its_path_is_replaced() -> TestResult {
    let directory = tempfile::tempdir()?;
    let base = complete_command(directory.path())?;
    let request_path = directory.path().join("request.cbor");
    let request = fs::read(&request_path)?;
    fs::remove_file(&request_path)?;
    assert!(Command::new("mkfifo")
        .arg(&request_path)
        .status()?
        .success());

    let executable = directory.path().join("running-evaluator");
    fs::copy(env!("CARGO_BIN_EXE_pos-reference-evaluator"), &executable)?;
    let mut command = Command::new(&executable);
    command
        .args(base.get_args())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;

    // Opening the FIFO synchronizes with the evaluator after exec and before
    // the executable path is replaced.
    let mut request_writer = open_fifo_writer_after_child_ready(&request_path, &mut child)?;
    fs::rename(&executable, directory.path().join("loaded-evaluator"))?;
    fs::write(&executable, b"replacement path contents")?;
    request_writer.write_all(&request)?;
    drop(request_writer);

    let output = child.wait_with_output()?;
    assert!(
        output.status.success(),
        "evaluator stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn command_closes_input_adapter_and_evaluation_failures() -> TestResult {
    for input in [
        "request.cbor",
        "bundle.cfb1",
        "policy.tps1",
        "source/pigloros-source.tar.gz",
        "bin/pos-reference-evaluator",
        "Cargo.lock",
        "sbom.cdx.json",
        "licences.json",
        "provenance.json",
        "BLAKE3SUMS",
    ] {
        let directory = tempfile::tempdir()?;
        let mut missing_input = complete_command(directory.path())?;
        fs::remove_file(directory.path().join(input))?;
        assert!(!missing_input.output()?.status.success());
    }

    let directory = tempfile::tempdir()?;
    let mut oversized_source = complete_command(directory.path())?;
    fs::File::create(directory.path().join("source/pigloros-source.tar.gz"))?
        .set_len(1024 * 1024 * 1024 + 1)?;
    assert!(!oversized_source.output()?.status.success());

    let directory = tempfile::tempdir()?;
    assert!(
        !complete_command_with_adapter(directory.path(), "relative-adapter")?
            .output()?
            .status
            .success()
    );

    let directory = tempfile::tempdir()?;
    let unavailable = complete_command_with_adapter(directory.path(), "/bin/false")?.output()?;
    assert!(
        unavailable.status.success(),
        "evaluator stderr: {}",
        String::from_utf8_lossy(&unavailable.stderr)
    );
    let report = ConformanceReport::from_canonical_cbor(&unavailable.stdout)?;
    assert!(report
        .cases
        .iter()
        .all(|case| case.outcome == CaseStatus::Unavailable));

    let directory = tempfile::tempdir()?;
    let mut malformed_bundle = complete_command(directory.path())?;
    fs::write(directory.path().join("bundle.cfb1"), [0xff])?;
    assert!(!malformed_bundle.output()?.status.success());
    Ok(())
}

#[cfg(unix)]
#[test]
fn command_rejects_duplicate_and_unsorted_public_identity_options() -> TestResult {
    let directory = tempfile::tempdir()?;
    for duplicate in [
        ["--bundle", "second"],
        ["--trust-policy", "second"],
        ["--evaluator-source", "second-source"],
        ["--evaluator-provenance", "second-provenance"],
        [
            "--declaration-digest",
            "0101010101010101010101010101010101010101010101010101010101010101",
        ],
        [
            "--shared-code-audit-digest",
            "0101010101010101010101010101010101010101010101010101010101010101",
        ],
        ["--adapter", "/bin/false"],
    ] {
        let output = complete_command(directory.path())?
            .args(duplicate)
            .output()?;
        assert!(!output.status.success());
    }

    let output = complete_command(directory.path())?
        .args(["--reviewer", "reviewer-one"])
        .output()?;
    assert!(!output.status.success());

    let output = complete_command(directory.path())?
        .args(["--reviewer", "reviewer-alpha"])
        .output()?;
    assert!(!output.status.success());
    Ok(())
}

#[cfg(unix)]
#[test]
fn command_rejects_noncanonical_digest_and_argument_boundaries() -> TestResult {
    for digest in [
        "01".to_owned(),
        "g1".repeat(32),
        "1g".repeat(32),
        "AA".repeat(32),
        "00".repeat(32),
    ] {
        assert!(!evaluator()
            .args(["--declaration-digest", digest.as_str()])
            .output()?
            .status
            .success());
    }
    assert!(!evaluator()
        .arg(OsString::from_vec(vec![0xff]))
        .output()?
        .status
        .success());
    Ok(())
}

#[cfg(unix)]
#[test]
fn command_preserves_unsupported_request_version_and_source_read_failures() -> TestResult {
    let directory = tempfile::tempdir()?;
    let mut unsupported = complete_command(directory.path())?;
    let corpus = support::corpus()?;
    fs::write(
        directory.path().join("request.cbor"),
        request_with_version(&corpus.request, 2)?,
    )?;
    assert!(!unsupported.output()?.status.success());

    let directory = tempfile::tempdir()?;
    let mut unreadable_source = complete_command(directory.path())?;
    let source = directory.path().join("source/pigloros-source.tar.gz");
    fs::remove_file(&source)?;
    fs::create_dir(&source)?;
    assert!(!unreadable_source.output()?.status.success());
    Ok(())
}

#[cfg(unix)]
#[test]
fn command_rejects_source_and_binary_not_bound_by_build_provenance() -> TestResult {
    let directory = tempfile::tempdir()?;
    let mut unrelated_source = complete_command(directory.path())?;
    fs::write(
        directory.path().join("source/pigloros-source.tar.gz"),
        b"unrelated source bytes",
    )?;
    assert!(!unrelated_source.output()?.status.success());

    let directory = tempfile::tempdir()?;
    let mut unrelated_binary = complete_command(directory.path())?;
    let provenance_path = directory.path().join("provenance.json");
    let mut provenance: serde_json::Value = serde_json::from_slice(&fs::read(&provenance_path)?)?;
    provenance["evaluator_binary_blake3"] = serde_json::Value::String("55".repeat(32));
    let mut bytes = serde_json::to_vec(&provenance)?;
    bytes.push(b'\n');
    fs::write(provenance_path, bytes)?;
    assert!(!unrelated_binary.output()?.status.success());
    Ok(())
}

#[cfg(unix)]
#[test]
fn command_closes_remaining_public_io_and_identity_boundaries() -> TestResult {
    let directory = tempfile::tempdir()?;
    let mut malformed_request = complete_command(directory.path())?;
    fs::write(directory.path().join("request.cbor"), [0xf6])?;
    assert!(!malformed_request.output()?.status.success());

    let directory = tempfile::tempdir()?;
    let mut renamed_provenance = complete_command(directory.path())?;
    fs::rename(
        directory.path().join("provenance.json"),
        directory.path().join("renamed.json"),
    )?;
    std::os::unix::fs::symlink(
        directory.path().join("renamed.json"),
        directory.path().join("provenance.json"),
    )?;
    assert!(!renamed_provenance.output()?.status.success());

    let directory = tempfile::tempdir()?;
    let mut substituted_binary = complete_command(directory.path())?;
    fs::copy(
        "/bin/false",
        directory.path().join("bin/pos-reference-evaluator"),
    )?;
    let source = fs::read(directory.path().join("source/pigloros-source.tar.gz"))?;
    write_evaluator_provenance(directory.path(), &source)?;
    write_checksum_inventory(directory.path())?;
    assert!(!substituted_binary.output()?.status.success());

    let directory = tempfile::tempdir()?;
    let complete = complete_command(directory.path())?;
    let alternate_source = directory.path().join("alternate-source.tar.gz");
    fs::copy(
        directory.path().join("source/pigloros-source.tar.gz"),
        &alternate_source,
    )?;
    assert!(
        !replacing_argument(&complete, "--evaluator-source", &alternate_source)?
            .output()?
            .status
            .success()
    );

    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn command_closes_post_preflight_and_output_failures() -> TestResult {
    for corpus in [
        support::corpus_with_profile_mutation(
            support::ProfileMutation::SelectedProfileByteCapBoundary,
        )?,
        support::corpus_with_profile_mutation(
            support::ProfileMutation::SelectedClosureCapBoundary(0),
        )?,
        support::corpus_with_bundle_mutation(support::BundleMutation::MemberBytes)?,
    ] {
        let directory = tempfile::tempdir()?;
        let mut command = complete_command(directory.path())?;
        fs::write(directory.path().join("request.cbor"), corpus.request)?;
        fs::write(directory.path().join("bundle.cfb1"), corpus.archive)?;
        fs::write(directory.path().join("policy.tps1"), corpus.trust_policy)?;
        assert!(!command.output()?.status.success());
    }

    let directory = tempfile::tempdir()?;
    let diagnostics_sink = fs::OpenOptions::new().write(true).open("/dev/full")?;
    let status = complete_command(directory.path())?
        .stdout(Stdio::null())
        .stderr(Stdio::from(diagnostics_sink))
        .status()?;
    assert!(!status.success());

    let directory = tempfile::tempdir()?;
    let report_sink = fs::OpenOptions::new().write(true).open("/dev/full")?;
    let status = complete_command(directory.path())?
        .stdout(Stdio::from(report_sink))
        .stderr(Stdio::null())
        .status()?;
    assert!(!status.success());
    Ok(())
}

#[cfg(unix)]
#[test]
fn command_bounds_special_files_that_grow_after_metadata() -> TestResult {
    for path in ["BLAKE3SUMS", "Cargo.lock"] {
        let directory = tempfile::tempdir()?;
        let mut command = complete_command(directory.path())?;
        fs::remove_file(directory.path().join(path))?;
        std::os::unix::fs::symlink("/dev/zero", directory.path().join(path))?;
        assert!(!command.output()?.status.success());
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn command_rejects_the_staged_archive_grammar_through_file_io() -> TestResult {
    let mutations = (0..6)
        .map(support::BundleMutation::RawManifestField)
        .chain((0..4).map(support::BundleMutation::RawDescriptorField))
        .chain((0..3).map(support::BundleMutation::RawMemberField))
        .chain((0..6).map(support::BundleMutation::RawExpectedField))
        .chain((0..4).map(support::BundleMutation::RawArchiveField))
        .chain((0..8).map(support::BundleMutation::PathBoundary))
        .chain((0..2).map(support::BundleMutation::ExpectedCaseBoundary));

    for mutation in mutations {
        let corpus = support::corpus_with_bundle_mutation(mutation)?;
        let directory = tempfile::tempdir()?;
        let mut command = complete_command(directory.path())?;
        fs::write(directory.path().join("request.cbor"), corpus.request)?;
        fs::write(directory.path().join("bundle.cfb1"), corpus.archive)?;
        fs::write(directory.path().join("policy.tps1"), corpus.trust_policy)?;
        assert!(!command.output()?.status.success());
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn command_rejects_malformed_or_oversized_build_provenance() -> TestResult {
    for bytes in [b"null".to_vec(), b"{".to_vec()] {
        let directory = tempfile::tempdir()?;
        let mut command = complete_command(directory.path())?;
        fs::write(directory.path().join("provenance.json"), bytes)?;
        assert!(!command.output()?.status.success());
    }

    let invalid_fields = [
        ("schema", serde_json::json!("wrong-schema")),
        ("source_commit", serde_json::json!("1".repeat(39))),
        ("source_commit", serde_json::json!("1".repeat(41))),
        ("source_commit", serde_json::json!("1".repeat(63))),
        ("source_commit", serde_json::json!("1".repeat(65))),
        ("source_commit", serde_json::json!("A".repeat(40))),
        ("build_target", serde_json::json!("")),
        ("build_target", serde_json::json!("x".repeat(257))),
        ("build_target", serde_json::json!("target\nname")),
        ("rust_toolchain", serde_json::json!("rustc\\escaped")),
        ("cargo_locked", serde_json::json!(false)),
        (
            "evaluator_source_blake3",
            serde_json::json!("00".repeat(32)),
        ),
        (
            "evaluator_binary_blake3",
            serde_json::json!("00".repeat(32)),
        ),
        ("dependency_lock_blake3", serde_json::json!("00".repeat(32))),
        ("sbom_blake3", serde_json::json!("00".repeat(32))),
        ("licences_blake3", serde_json::json!("00".repeat(32))),
    ];
    for (field, value) in invalid_fields {
        let directory = tempfile::tempdir()?;
        let mut command = complete_command(directory.path())?;
        replace_provenance_field(directory.path(), field, value)?;
        assert!(!command.output()?.status.success());
    }

    for field in ["schema", "source_commit"] {
        let directory = tempfile::tempdir()?;
        let mut command = complete_command(directory.path())?;
        let path = directory.path().join("provenance.json");
        let mut provenance: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
        provenance
            .as_object_mut()
            .ok_or("provenance is not an object")?
            .remove(field);
        let mut bytes = serde_json::to_vec(&provenance)?;
        bytes.push(b'\n');
        fs::write(path, bytes)?;
        assert!(!command.output()?.status.success());
    }

    let directory = tempfile::tempdir()?;
    let mut command = complete_command(directory.path())?;
    replace_provenance_field(directory.path(), "unexpected", serde_json::json!(true))?;
    assert!(!command.output()?.status.success());

    let directory = tempfile::tempdir()?;
    let mut command = complete_command(directory.path())?;
    fs::File::create(directory.path().join("provenance.json"))?.set_len(4_097)?;
    assert!(!command.output()?.status.success());

    let directory = tempfile::tempdir()?;
    let mut duplicate = complete_command(directory.path())?;
    let path = directory.path().join("provenance.json");
    let bytes = fs::read_to_string(&path)?;
    fs::write(
        path,
        bytes.replacen(
            "\"build_target\":",
            "\"build_target\":\"duplicate\",\"build_target\":",
            1,
        ),
    )?;
    assert!(!duplicate.output()?.status.success());

    let directory = tempfile::tempdir()?;
    let mut noncanonical = complete_command(directory.path())?;
    let path = directory.path().join("provenance.json");
    let bytes = fs::read(&path)?;
    let mut prefixed = vec![b' '];
    prefixed.extend(bytes);
    fs::write(path, prefixed)?;
    assert!(!noncanonical.output()?.status.success());

    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn public_verifier_rejects_noncanonical_digest_encodings_at_their_use_sites() -> TestResult {
    for source_digest in ["1".to_owned(), "g1".repeat(32), "1g".repeat(32)] {
        let directory = tempfile::tempdir()?;
        write_public_verifier_package(directory.path())?;
        replace_provenance_field(
            directory.path(),
            "evaluator_source_blake3",
            serde_json::json!(source_digest),
        )?;
        assert_public_verifier_error(
            directory.path(),
            &directory.path().join("source/pigloros-source.tar.gz"),
            EvaluatorBuildIdentityError::Invalid,
        );
    }

    let directory = tempfile::tempdir()?;
    write_public_verifier_package(directory.path())?;
    replace_provenance_field(
        directory.path(),
        "dependency_lock_blake3",
        serde_json::json!("g1".repeat(32)),
    )?;
    assert_public_verifier_error(
        directory.path(),
        &directory.path().join("source/pigloros-source.tar.gz"),
        EvaluatorBuildIdentityError::Invalid,
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn public_verifier_rejects_path_and_bounded_file_failures() -> TestResult {
    let directory = tempfile::tempdir()?;
    write_public_verifier_package(directory.path())?;
    let source = directory.path().join("source/pigloros-source.tar.gz");
    let alternate_source = directory.path().join("alternate-source.tar.gz");
    fs::rename(&source, &alternate_source)?;
    assert_public_verifier_error(
        directory.path(),
        &alternate_source,
        EvaluatorBuildIdentityError::Input,
    );

    let directory = tempfile::tempdir()?;
    write_public_verifier_package(directory.path())?;
    let provenance = directory.path().join("provenance.json");
    fs::remove_file(&provenance)?;
    fs::create_dir(&provenance)?;
    assert_public_verifier_error(
        directory.path(),
        &directory.path().join("source/pigloros-source.tar.gz"),
        EvaluatorBuildIdentityError::Input,
    );

    let directory = tempfile::tempdir()?;
    write_public_verifier_package(directory.path())?;
    fs::OpenOptions::new()
        .write(true)
        .open(directory.path().join("Cargo.lock"))?
        .set_len(16 * 1024 * 1024 + 1)?;
    assert_public_verifier_error(
        directory.path(),
        &directory.path().join("source/pigloros-source.tar.gz"),
        EvaluatorBuildIdentityError::Input,
    );

    let directory = tempfile::tempdir()?;
    write_public_verifier_package(directory.path())?;
    let dependency_lock = directory.path().join("Cargo.lock");
    fs::remove_file(&dependency_lock)?;
    fs::create_dir(&dependency_lock)?;
    assert_public_verifier_error(
        directory.path(),
        &directory.path().join("source/pigloros-source.tar.gz"),
        EvaluatorBuildIdentityError::Input,
    );

    let directory = tempfile::tempdir()?;
    write_public_verifier_package(directory.path())?;
    let dependency_lock = directory.path().join("Cargo.lock");
    fs::remove_file(&dependency_lock)?;
    assert!(Command::new("mkfifo")
        .arg(&dependency_lock)
        .status()?
        .success());
    assert_public_verifier_error(
        directory.path(),
        &directory.path().join("source/pigloros-source.tar.gz"),
        EvaluatorBuildIdentityError::Input,
    );

    let directory = tempfile::tempdir()?;
    write_public_verifier_package(directory.path())?;
    let dependency_lock = directory.path().join("Cargo.lock");
    fs::remove_file(&dependency_lock)?;
    let mut child = Command::new("true").stdout(Stdio::piped()).spawn()?;
    let pipe = child.stdout.take().ok_or("child stdout is unavailable")?;
    let pipe_fd = pipe.as_raw_fd();
    symlink(format!("/proc/self/fd/{pipe_fd}"), &dependency_lock)?;
    assert_public_verifier_error(
        directory.path(),
        &directory.path().join("source/pigloros-source.tar.gz"),
        EvaluatorBuildIdentityError::Input,
    );
    drop(pipe);
    assert!(child.wait()?.success());

    let directory = tempfile::tempdir()?;
    write_public_verifier_package(directory.path())?;
    fs::remove_file(directory.path().join("Cargo.lock"))?;
    assert_public_verifier_error(
        directory.path(),
        &directory.path().join("source/pigloros-source.tar.gz"),
        EvaluatorBuildIdentityError::Input,
    );

    let directory = tempfile::tempdir()?;
    write_public_verifier_package(directory.path())?;
    fs::remove_file(directory.path().join("BLAKE3SUMS"))?;
    assert_public_verifier_error(
        directory.path(),
        &directory.path().join("source/pigloros-source.tar.gz"),
        EvaluatorBuildIdentityError::Input,
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn public_verifier_rejects_decoder_failures_and_trailing_archive_data() -> TestResult {
    const INCOMPLETE_GZIP_MEMBER: [u8; 4] = [0x1f, 0x8b, 0x08, 0x00];

    let mut termination_failure = source_archive("1111111111111111111111111111111111111111")?;
    termination_failure.extend_from_slice(&INCOMPLETE_GZIP_MEMBER);

    let mut body_failure = gzip_bytes(&tar_header("file", 1_024, b'0'))?;
    body_failure.extend_from_slice(&INCOMPLETE_GZIP_MEMBER);

    let mut trailing_nonzero = source_archive("1111111111111111111111111111111111111111")?;
    trailing_nonzero.extend_from_slice(&gzip_bytes(&[1])?);

    for source in [termination_failure, body_failure, trailing_nonzero] {
        let directory = tempfile::tempdir()?;
        write_public_verifier_package(directory.path())?;
        rebind_source_archive(directory.path(), &source)?;
        assert_public_verifier_error(
            directory.path(),
            &directory.path().join("source/pigloros-source.tar.gz"),
            EvaluatorBuildIdentityError::Invalid,
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn public_verifier_enforces_selected_compression_expansion() -> TestResult {
    let directory = tempfile::tempdir()?;
    write_public_verifier_package(directory.path())?;
    let source = directory.path().join("source/pigloros-source.tar.gz");
    let compressed_bytes = fs::metadata(&source)?.len();
    let expanded_bytes = source_tar("1111111111111111111111111111111111111111").len() as u64;
    let exact_expansion = expanded_bytes.div_ceil(compressed_bytes);

    public_verifier_result_with_expansion(directory.path(), &source, exact_expansion)?;
    assert_eq!(
        public_verifier_result_with_expansion(
            directory.path(),
            &source,
            exact_expansion.saturating_sub(1),
        ),
        Err(EvaluatorBuildIdentityError::Invalid)
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn command_rejects_incomplete_or_substituted_evaluator_evidence() -> TestResult {
    for path in [
        "Cargo.lock",
        "bin/pos-reference-evaluator",
        "licences.json",
        "sbom.cdx.json",
    ] {
        let directory = tempfile::tempdir()?;
        let mut command = complete_command(directory.path())?;
        fs::write(directory.path().join(path), b"substituted artifact\n")?;
        assert!(!command.output()?.status.success());
    }

    let directory = tempfile::tempdir()?;
    let mut wrong_commit = complete_command(directory.path())?;
    let source = source_archive("2222222222222222222222222222222222222222")?;
    fs::write(
        directory.path().join("source/pigloros-source.tar.gz"),
        &source,
    )?;
    write_evaluator_provenance(directory.path(), &source)?;
    write_checksum_inventory(directory.path())?;
    assert!(!wrong_commit.output()?.status.success());

    for inventory in ["", "00  Cargo.lock\n", "extra  record\n"] {
        let directory = tempfile::tempdir()?;
        let mut command = complete_command(directory.path())?;
        fs::write(directory.path().join("BLAKE3SUMS"), inventory)?;
        assert!(!command.output()?.status.success());
    }
    Ok(())
}

#[cfg(unix)]
fn malformed_tar_archives() -> TestResult<Vec<Vec<u8>>> {
    let mut corrupted_checksum = tar_header("pax_global_header", 0, b'g');
    corrupted_checksum[0] ^= 1;

    let mut invalid_checksum_field = tar_header("pax_global_header", 0, b'g');
    invalid_checksum_field[148..156].fill(b'x');

    let mut invalid_size_field = tar_header("pax_global_header", 0, b'g');
    invalid_size_field[124..136].fill(b'x');
    write_tar_checksum(&mut invalid_size_field);

    let mut invalid_utf8_size_field = tar_header("pax_global_header", 0, b'g');
    invalid_utf8_size_field[124] = 0xff;
    write_tar_checksum(&mut invalid_utf8_size_field);

    let mut empty_name = tar_header("file", 0, b'0');
    empty_name[..100].fill(0);
    write_tar_checksum(&mut empty_name);

    let mut bytes_after_name_terminator = tar_header("a", 0, b'0');
    bytes_after_name_terminator[2] = b'x';
    write_tar_checksum(&mut bytes_after_name_terminator);

    let mut invalid_utf8_name = tar_header("a", 0, b'0');
    invalid_utf8_name[0] = 0xff;
    write_tar_checksum(&mut invalid_utf8_name);

    let mut bytes_after_prefix_terminator = tar_header("file", 0, b'0');
    bytes_after_prefix_terminator[345] = b'a';
    bytes_after_prefix_terminator[347] = b'x';
    write_tar_checksum(&mut bytes_after_prefix_terminator);

    let mut invalid_utf8_prefix = tar_header("file", 0, b'0');
    invalid_utf8_prefix[345] = 0xff;
    write_tar_checksum(&mut invalid_utf8_prefix);

    Ok(vec![
        gzip_bytes(&[])?,
        gzip_bytes(&[0; 1024])?,
        source_archive_with_entry(&corrupted_checksum, &[], true)?,
        source_archive_with_entry(&invalid_checksum_field, &[], true)?,
        source_archive_with_entry(&invalid_size_field, &[], true)?,
        source_archive_with_entry(&invalid_utf8_size_field, &[], true)?,
        source_archive_with_entry(&empty_name, &[], true)?,
        source_archive_with_entry(&bytes_after_name_terminator, &[], true)?,
        source_archive_with_entry(&invalid_utf8_name, &[], true)?,
        source_archive_with_entry(&bytes_after_prefix_terminator, &[], true)?,
        source_archive_with_entry(&invalid_utf8_prefix, &[], true)?,
        source_archive_with_entry(&tar_header("pax", 4_097, b'g'), &[], false)?,
        source_archive_with_entry(&tar_header("pax", 52, b'g'), b"short", false)?,
        source_archive_with_entry(&tar_header("file", 10, b'0'), b"x", false)?,
        source_archive_with_entry(&tar_header("file", 1, b'0'), b"x", false)?,
        source_archive_with_entry(&tar_header("file", 0, b'0'), &[], true)?,
    ])
}

#[cfg(unix)]
fn malformed_pax_archives() -> TestResult<Vec<Vec<u8>>> {
    let no_space = b"record-without-space";
    let non_numeric_length = b"x comment=1111111111111111111111111111111111111111\n";
    let overflowing_length = b"999999999999999999999999999999999999999999999999 comment=x\n";
    let missing_newline = b"20 comment=missing";
    let unrelated_record = pax_record("path", b"source");
    let mut invalid_utf8_commit = [b'1'; 40];
    invalid_utf8_commit[20] = 0xff;
    let invalid_utf8_record = pax_record("comment", &invalid_utf8_commit);
    let short_commit_record = pax_record("comment", b"111111111111111111111111111111111111111");
    let empty_commit_record = pax_record("comment", b"");
    let duplicate_commit_record = [
        pax_record("comment", b"1111111111111111111111111111111111111111"),
        pax_record("comment", b"2222222222222222222222222222222222222222"),
    ]
    .concat();
    let invalid_utf8_length = b"\xff comment=1111111111111111111111111111111111111111\n";
    let first_record = pax_record("path", b"source");
    let overflow_record = format!("{} comment=x\n", usize::MAX);
    let checked_add_overflow = [first_record.as_slice(), overflow_record.as_bytes()].concat();

    Ok(vec![
        source_archive_with_entry(
            &tar_header("pax", unrelated_record.len(), b'g'),
            &unrelated_record,
            false,
        )?,
        source_archive_with_entry(&tar_header("pax", no_space.len(), b'g'), no_space, true)?,
        source_archive_with_entry(
            &tar_header("pax", non_numeric_length.len(), b'g'),
            non_numeric_length,
            true,
        )?,
        source_archive_with_entry(
            &tar_header("pax", overflowing_length.len(), b'g'),
            overflowing_length,
            true,
        )?,
        source_archive_with_entry(
            &tar_header("pax", missing_newline.len(), b'g'),
            missing_newline,
            true,
        )?,
        source_archive_with_entry(
            &tar_header("pax", unrelated_record.len(), b'g'),
            &unrelated_record,
            true,
        )?,
        source_archive_with_entry(
            &tar_header("pax", invalid_utf8_record.len(), b'g'),
            &invalid_utf8_record,
            true,
        )?,
        source_archive_with_entry(
            &tar_header("pax", short_commit_record.len(), b'g'),
            &short_commit_record,
            true,
        )?,
        source_archive_with_entry(
            &tar_header("pax", empty_commit_record.len(), b'g'),
            &empty_commit_record,
            true,
        )?,
        source_archive_with_entry(
            &tar_header("pax", duplicate_commit_record.len(), b'g'),
            &duplicate_commit_record,
            true,
        )?,
        source_archive_with_entry(
            &tar_header("pax", invalid_utf8_length.len(), b'g'),
            invalid_utf8_length,
            true,
        )?,
        source_archive_with_entry(
            &tar_header("pax", checked_add_overflow.len(), b'g'),
            &checked_add_overflow,
            true,
        )?,
    ])
}

#[cfg(unix)]
#[test]
fn command_rejects_malformed_embedded_source_identity_records() -> TestResult {
    for source in malformed_tar_archives()?
        .into_iter()
        .chain(malformed_pax_archives()?)
    {
        let directory = tempfile::tempdir()?;
        let mut command = complete_command(directory.path())?;
        rebind_source_archive(directory.path(), &source)?;
        assert!(!command.output()?.status.success());
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn command_rejects_incomplete_or_ambiguous_source_archives() -> TestResult {
    let commit = "1".repeat(40);
    let valid = source_tar(&commit);

    let mut duplicate_commit = valid.clone();
    duplicate_commit.splice(1024..1024, valid[..1024].iter().copied());

    let mut interrupted_termination = valid.clone();
    let final_header = interrupted_termination.len() - 512;
    interrupted_termination[final_header..].copy_from_slice(&tar_header("late", 0, b'0'));

    let mut trailing_nonzero = valid.clone();
    trailing_nonzero.push(1);

    let mut unsupported_type = valid.clone();
    let first_source_header = 1024;
    unsupported_type[first_source_header + 156] = b'x';
    let mut header =
        <[u8; 512]>::try_from(&unsupported_type[first_source_header..first_source_header + 512])?;
    write_tar_checksum(&mut header);
    unsupported_type[first_source_header..first_source_header + 512].copy_from_slice(&header);

    let mut missing_source_entry = valid;
    missing_source_entry.drain(1024..1536);

    let valid = source_tar(&commit);
    let mut duplicate_required_entry = valid.clone();
    duplicate_required_entry.splice(1536..1536, valid[1024..1536].iter().copied());

    let mut required_directory = valid.clone();
    set_tar_entry_kind(&mut required_directory, 1024, b'5')?;

    let mut required_symlink = valid;
    set_tar_entry_kind(&mut required_symlink, 1024, b'2')?;

    for tar in [
        duplicate_commit,
        interrupted_termination,
        trailing_nonzero,
        unsupported_type,
        missing_source_entry,
        duplicate_required_entry,
        required_directory,
        required_symlink,
    ] {
        let directory = tempfile::tempdir()?;
        let mut command = complete_command(directory.path())?;
        rebind_source_archive(directory.path(), &gzip_bytes(&tar)?)?;
        assert!(!command.output()?.status.success());
    }
    Ok(())
}

fn set_tar_entry_kind(tar: &mut [u8], offset: usize, kind: u8) -> TestResult {
    let end = offset + 512;
    let mut header = <[u8; 512]>::try_from(&tar[offset..end])?;
    header[156] = kind;
    write_tar_checksum(&mut header);
    tar[offset..end].copy_from_slice(&header);
    Ok(())
}

fn replace_provenance_field(directory: &Path, field: &str, value: serde_json::Value) -> TestResult {
    let path = directory.join("provenance.json");
    let mut provenance: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
    provenance
        .as_object_mut()
        .ok_or("provenance is not an object")?
        .insert(field.to_owned(), value);
    let mut bytes = serde_json::to_vec(&provenance)?;
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    Ok(())
}
