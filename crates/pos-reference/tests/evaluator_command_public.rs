use std::error::Error;
use std::fs;
use std::process::Command;

type TestResult = Result<(), Box<dyn Error>>;

fn evaluator() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pos-reference-evaluator"))
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
