pub mod support;

use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::Command;

use pos_reference::evaluator_protocol::ConformanceReport;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn evaluator() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pos-reference-evaluator"))
}

fn complete_command(directory: &Path) -> TestResult<Command> {
    complete_command_with_adapter(directory, "/bin/cat")
}

fn complete_command_with_adapter(directory: &Path, adapter: &str) -> TestResult<Command> {
    let corpus = support::corpus()?;
    let request = directory.join("request.cbor");
    let bundle = directory.join("bundle.cfb1");
    let policy = directory.join("policy.tps1");
    fs::write(&request, corpus.request)?;
    fs::write(&bundle, corpus.archive)?;
    fs::write(&policy, corpus.trust_policy)?;
    let digest = "01".repeat(32);
    let mut command = evaluator();
    command.args([
        "--request",
        request.to_str().ok_or("request path is not UTF-8")?,
        "--bundle",
        bundle.to_str().ok_or("bundle path is not UTF-8")?,
        "--trust-policy",
        policy.to_str().ok_or("policy path is not UTF-8")?,
        "--source-digest",
        digest.as_str(),
        "--declaration-digest",
        digest.as_str(),
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

#[test]
fn command_rejects_incomplete_duplicate_and_noncanonical_identity_arguments() -> TestResult {
    assert!(!evaluator().output()?.status.success());

    let duplicated = evaluator()
        .args(["--request", "one", "--request", "two"])
        .output()?;
    assert!(!duplicated.status.success());

    let uppercase_digest = "A".repeat(64);
    let invalid_digest = evaluator()
        .args(["--source-digest", uppercase_digest.as_str()])
        .output()?;
    assert!(!invalid_digest.status.success());

    let zero_digest = "0".repeat(64);
    let zero_identity = evaluator()
        .args(["--source-digest", zero_digest.as_str()])
        .output()?;
    assert!(!zero_identity.status.success());

    let unknown = evaluator().arg("--legacy-protocol").output()?;
    assert!(!unknown.status.success());

    let wrong_length = evaluator().args(["--source-digest", "01"]).output()?;
    assert!(!wrong_length.status.success());

    let invalid_low_nibble = "0g".repeat(32);
    let invalid_digest = evaluator()
        .args(["--source-digest", invalid_low_nibble.as_str()])
        .output()?;
    assert!(!invalid_digest.status.success());

    for option in [
        "--request",
        "--bundle",
        "--trust-policy",
        "--source-digest",
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
            "--source-digest",
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
            "--source-digest",
            digest.as_str(),
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
            "--source-digest",
            digest.as_str(),
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
            "--source-digest",
            digest.as_str(),
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
            "--source-digest",
            digest.as_str(),
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
    let directory = tempfile::tempdir()?;
    let output = complete_command(directory.path())?
        .args(["--adapter-arg", "--ignored-by-cat"])
        .output()?;
    assert!(output.status.success());
    let report = ConformanceReport::from_canonical_cbor(&output.stdout)?;
    assert_eq!(report.cases.len(), 7);
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
    let directory = tempfile::tempdir()?;
    let mut missing_input = complete_command(directory.path())?;
    fs::remove_file(directory.path().join("request.cbor"))?;
    assert!(!missing_input.output()?.status.success());

    let directory = tempfile::tempdir()?;
    assert!(
        !complete_command_with_adapter(directory.path(), "relative-adapter")?
            .output()?
            .status
            .success()
    );

    let directory = tempfile::tempdir()?;
    assert!(
        !complete_command_with_adapter(directory.path(), "/bin/false")?
            .output()?
            .status
            .success()
    );

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
        [
            "--source-digest",
            "0101010101010101010101010101010101010101010101010101010101010101",
        ],
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
