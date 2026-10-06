//! Public end-to-end check of the evidence package written by
//! `scripts/package-reference-evaluator.sh`.
//!
//! The release packaging job exports the package directory it produced through
//! `POS_REFERENCE_EVALUATOR_PACKAGE`. When the variable is unset there is no
//! packaged output to consume, so the test returns without checking anything;
//! the release job verifies the directory exists before running it.

pub mod support;

use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use pos_reference::evaluator_build_identity::PACKAGE_EVIDENCE_FILES;
use pos_reference::evaluator_protocol::ConformanceReport;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const PACKAGE_VARIABLE: &str = "POS_REFERENCE_EVALUATOR_PACKAGE";

#[test]
fn packaged_evaluator_verifies_its_own_script_output_and_emits_a_report() -> TestResult {
    let Some(package) = std::env::var_os(PACKAGE_VARIABLE).map(PathBuf::from) else {
        return Ok(());
    };
    let inventory = fs::read_to_string(package.join("BLAKE3SUMS"))?;
    let listed: Vec<&str> = inventory
        .lines()
        .filter_map(|line| line.split_once("  ").map(|(_, path)| path))
        .collect();
    assert_eq!(listed, PACKAGE_EVIDENCE_FILES.ordered());

    let corpus = support::corpus()?;
    let directory = tempfile::tempdir()?;
    let request = directory.path().join("request.cbor");
    let bundle = directory.path().join("bundle.cfb1");
    let policy = directory.path().join("policy.tps1");
    fs::write(&request, &corpus.request)?;
    fs::write(&bundle, &corpus.archive)?;
    fs::write(&policy, &corpus.trust_policy)?;
    let declaration_digest = "2f".repeat(32);
    let audit_digest = "01".repeat(32);
    let output = Command::new(package.join(PACKAGE_EVIDENCE_FILES.binary))
        .arg("--request")
        .arg(&request)
        .arg("--bundle")
        .arg(&bundle)
        .arg("--trust-policy")
        .arg(&policy)
        .arg("--evaluator-source")
        .arg(package.join(PACKAGE_EVIDENCE_FILES.source))
        .arg("--evaluator-provenance")
        .arg(package.join(PACKAGE_EVIDENCE_FILES.provenance))
        .args(["--declaration-digest", declaration_digest.as_str()])
        .args(["--shared-code-audit-digest", audit_digest.as_str()])
        .args(["--reviewer", "reviewer-one"])
        .args(["--authorship-independent", "--organizational-independent"])
        .output()?;
    assert!(
        output.status.success(),
        "packaged evaluator stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = ConformanceReport::from_canonical_cbor(&output.stdout)?;
    let source = fs::read(package.join(PACKAGE_EVIDENCE_FILES.source))?;
    assert_eq!(
        report.evaluator_source_digest,
        *blake3::hash(&source).as_bytes()
    );
    Ok(())
}
