pub mod support;

use std::error::Error;
#[cfg(unix)]
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::io::{Cursor, Write};
use std::path::Path;
use std::process::{Command, Stdio};

#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;

use flate2::write::GzEncoder;
use flate2::Compression;
use pos_reference::evaluator_protocol::{CaseStatus, ConformanceReport, EvaluationRequest};
use pos_reference::profile::Profile;
use pos_reference::signed_bundle::{preflight_signed_bundle, SelectedBundleCaps};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

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
    let request = directory.join("request.cbor");
    let bundle = directory.join("bundle.cfb1");
    let policy = directory.join("policy.tps1");
    let source = directory.join("source/pigloros-source.tar.gz");
    let provenance = directory.join("provenance.json");
    fs::write(&request, corpus.request)?;
    fs::write(&bundle, corpus.archive)?;
    fs::write(&policy, corpus.trust_policy)?;
    write_evaluator_package(directory)?;
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
    preflight.enforce_selected_caps(SelectedBundleCaps {
        max_profile_bytes: caps.max_profile_bytes,
        max_bundle_members: caps.max_bundle_members,
        max_member_path_bytes: caps.max_member_path_bytes,
        max_member_bytes: caps.max_member_bytes,
        max_total_bundle_bytes: caps.max_total_bundle_bytes,
    })?;
    Ok(())
}

fn write_evaluator_provenance(path: &Path, source: &[u8]) -> TestResult {
    let root = path.parent().ok_or("provenance path has no parent")?;
    let binary = fs::read(root.join("bin/pos-reference-evaluator"))?;
    let lock = fs::read(root.join("Cargo.lock"))?;
    let sbom = fs::read(root.join("sbom.cdx.json"))?;
    let licences = fs::read(root.join("licences.json"))?;
    let provenance = serde_json::json!({
        "build_target": "public-test-target",
        "cargo_locked": true,
        "dependency_lock_blake3": blake3::hash(&lock).to_hex().to_string(),
        "evaluator_binary_blake3": blake3::hash(&binary).to_hex().to_string(),
        "evaluator_source_blake3": blake3::hash(source).to_hex().to_string(),
        "licences_blake3": blake3::hash(&licences).to_hex().to_string(),
        "rust_toolchain": "rustc public-test-toolchain",
        "sbom_blake3": blake3::hash(&sbom).to_hex().to_string(),
        "schema": "PiglorOS.EvaluatorBuildProvenance.v1",
        "source_commit": "1111111111111111111111111111111111111111",
    });
    let mut bytes = serde_json::to_vec(&provenance)?;
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    Ok(())
}

fn write_evaluator_package(directory: &Path) -> TestResult {
    fs::create_dir_all(directory.join("source"))?;
    fs::create_dir_all(directory.join("bin"))?;
    let source = source_archive("1111111111111111111111111111111111111111")?;
    fs::write(directory.join("source/pigloros-source.tar.gz"), &source)?;
    fs::copy(
        env!("CARGO_BIN_EXE_pos-reference-evaluator"),
        directory.join("bin/pos-reference-evaluator"),
    )?;
    fs::write(
        directory.join("Cargo.lock"),
        b"public test dependency lock\n",
    )?;
    fs::write(directory.join("sbom.cdx.json"), b"{}\n")?;
    fs::write(directory.join("licences.json"), b"{}\n")?;
    write_evaluator_provenance(&directory.join("provenance.json"), &source)?;
    write_checksum_inventory(directory)?;
    Ok(())
}

fn write_checksum_inventory(directory: &Path) -> TestResult {
    let paths = [
        "Cargo.lock",
        "bin/pos-reference-evaluator",
        "licences.json",
        "provenance.json",
        "sbom.cdx.json",
        "source/pigloros-source.tar.gz",
    ];
    let mut inventory = String::new();
    for path in paths {
        let digest = blake3::hash(&fs::read(directory.join(path))?);
        writeln!(inventory, "{}  {path}", digest.to_hex())?;
    }
    fs::write(directory.join("BLAKE3SUMS"), inventory)?;
    Ok(())
}

fn source_archive(commit: &str) -> TestResult<Vec<u8>> {
    let record = format!("52 comment={commit}\n");
    let mut tar = Vec::new();
    tar.extend_from_slice(&tar_header("pax_global_header", record.len(), b'g'));
    tar.extend_from_slice(record.as_bytes());
    tar.resize(tar.len().div_ceil(512) * 512, 0);
    tar.extend_from_slice(&[0; 1024]);
    gzip_bytes(&tar)
}

fn gzip_bytes(bytes: &[u8]) -> TestResult<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes)?;
    Ok(encoder.finish()?)
}

fn tar_header(name: &str, size: usize, kind: u8) -> [u8; 512] {
    let mut header = [0_u8; 512];
    header[..name.len()].copy_from_slice(name.as_bytes());
    write_octal(&mut header[100..108], 0o644);
    write_octal(&mut header[108..116], 0);
    write_octal(&mut header[116..124], 0);
    write_octal(&mut header[124..136], size as u64);
    write_octal(&mut header[136..148], 0);
    header[148..156].fill(b' ');
    header[156] = kind;
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    write_tar_checksum(&mut header);
    header
}

fn write_tar_checksum(header: &mut [u8; 512]) {
    header[148..156].fill(b' ');
    let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
    let encoded = format!("{checksum:06o}\0 ");
    header[148..156].copy_from_slice(encoded.as_bytes());
}

fn write_octal(field: &mut [u8], value: u64) {
    let encoded = format!("{:0width$o}\0", value, width = field.len() - 1);
    field.copy_from_slice(encoded.as_bytes());
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

fn pax_record(key: &str, value: &[u8]) -> Vec<u8> {
    let mut body = Vec::from(key.as_bytes());
    body.push(b'=');
    body.extend_from_slice(value);
    body.push(b'\n');
    let mut length = body.len() + 2;
    loop {
        let prefix = format!("{length} ");
        let encoded_length = prefix.len() + body.len();
        if encoded_length == length {
            let mut record = Vec::from(prefix.as_bytes());
            record.extend_from_slice(&body);
            return record;
        }
        length = encoded_length;
    }
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
    write_evaluator_provenance(&directory.path().join("provenance.json"), &source)?;
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

#[cfg(unix)]
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
    write_evaluator_provenance(&directory.path().join("provenance.json"), &source)?;
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
#[test]
fn command_rejects_malformed_embedded_source_identity_records() -> TestResult {
    let mut corrupted_checksum = tar_header("pax_global_header", 0, b'g');
    corrupted_checksum[0] ^= 1;

    let mut invalid_checksum_field = tar_header("pax_global_header", 0, b'g');
    invalid_checksum_field[148..156].fill(b'x');

    let mut invalid_size_field = tar_header("pax_global_header", 0, b'g');
    invalid_size_field[124..136].fill(b'x');
    write_tar_checksum(&mut invalid_size_field);

    let no_space = b"record-without-space";
    let non_numeric_length = b"x comment=1111111111111111111111111111111111111111\n";
    let overflowing_length = b"999999999999999999999999999999999999999999999999 comment=x\n";
    let missing_newline = b"20 comment=missing";
    let unrelated_record = pax_record("path", b"source");
    let mut invalid_utf8_commit = [b'1'; 40];
    invalid_utf8_commit[20] = 0xff;
    let invalid_utf8_record = pax_record("comment", &invalid_utf8_commit);
    let short_commit_record = pax_record("comment", b"111111111111111111111111111111111111111");

    let archives = vec![
        gzip_bytes(&[])?,
        gzip_bytes(&[0; 1024])?,
        source_archive_with_entry(&corrupted_checksum, &[], true)?,
        source_archive_with_entry(&invalid_checksum_field, &[], true)?,
        source_archive_with_entry(&invalid_size_field, &[], true)?,
        source_archive_with_entry(&tar_header("pax", 4_097, b'g'), &[], false)?,
        source_archive_with_entry(&tar_header("pax", 52, b'g'), b"short", false)?,
        source_archive_with_entry(&tar_header("file", 10, b'0'), b"x", false)?,
        source_archive_with_entry(&tar_header("file", 0, b'0'), &[], true)?,
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
    ];

    for source in archives {
        let directory = tempfile::tempdir()?;
        let mut command = complete_command(directory.path())?;
        rebind_source_archive(directory.path(), &source)?;
        assert!(!command.output()?.status.success());
    }
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
