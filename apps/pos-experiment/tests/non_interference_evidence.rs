#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! The checked-in non-interference evidence (ADR-062 Revision 8 slices
//! N1-N4; owner notes `ADR-062_R8_NonInterference_Executions`, decision 5,
//! and `ADR-062_R8_NonInterference_Fork`, decision 1).
//!
//! Every NIA1 under `fixtures/conformance/non-interference/executions/` must
//! be accepted by the independent pos-reference verifier under the repository
//! test-fixture-only executor key, at its content address, and the executed
//! cases of `execution-matrix.json` must be exactly those NIA1: every L, R
//! and F case of the rows declared in
//! `scripts/non_interference_executed_rows.json`, and nothing else.
//! `executed: true` never implies a pass.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use pos_conformance::{
    ExecutionModeV1, NonInterferenceExecutionArtifactV1, NonInterferenceVariantV1,
};
use pos_experiment::non_interference_harness::fixture_evidence::{
    non_interference_fixture_executor_key_v1, NON_INTERFERENCE_FIXTURE_EXECUTOR_KEY_ID_V1,
};
use pos_experiment::non_interference_harness::{
    non_interference_publication_path_v1, NON_INTERFERENCE_PUBLICATION_DIRECTORY_V1,
};
use pos_reference::verify_non_interference_execution_artifact_v1;
use serde_json::{json, Value};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const VARIANTS: [&str; 4] = ["S", "D", "W", "C"];

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        text.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        text.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
        text
    })
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

fn json_file(path: PathBuf) -> TestResult<Value> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

/// The declared executed rows and modes.
fn declared() -> TestResult<(Vec<String>, Vec<String>)> {
    let declaration =
        json_file(repository_root().join("scripts/non_interference_executed_rows.json"))?;
    let strings = |key: &str| -> TestResult<Vec<String>> {
        declaration[key]
            .as_array()
            .ok_or_else(|| format!("no {key} list"))?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("a non-text {key} entry").into())
            })
            .collect()
    };
    Ok((strings("rows")?, strings("modes")?))
}

#[test]
fn the_checked_in_evidence_is_verifier_accepted_and_flips_exactly_its_cases() -> TestResult {
    let root = repository_root().join("fixtures/conformance");
    let public = non_interference_fixture_executor_key_v1().public_key();
    let executor = json_file(root.join("non-interference/executor.json"))?;
    assert_eq!(executor["public_key_hex"], json!(hex(&public)));
    assert_eq!(
        executor["key_id"],
        json!(NON_INTERFERENCE_FIXTURE_EXECUTOR_KEY_ID_V1)
    );
    assert_eq!(
        executor["authority_kind"],
        json!("repository-test-fixture-only")
    );
    assert_eq!(executor["algorithm"], json!("Ed25519"));

    let mut accepted = BTreeMap::new();
    for entry in fs::read_dir(root.join(NON_INTERFERENCE_PUBLICATION_DIRECTORY_V1))? {
        let path = entry?.path();
        let bytes = fs::read(&path)?;
        let address = verify_non_interference_execution_artifact_v1(&bytes, &[public])?;
        assert_eq!(path, non_interference_publication_path_v1(&root, &address));
        let artifact = NonInterferenceExecutionArtifactV1::from_canonical_cbor(&bytes)?;
        assert!(artifact.equal);
        let id = format!(
            "{}-{}-{}",
            artifact.fixture_id,
            variant_letter(artifact.variant),
            mode_letter(artifact.mode)
        );
        accepted.insert(id, (hex(&address), artifact.result_digest));
    }
    let (rows, modes) = declared()?;
    assert_eq!(modes, ["L", "R", "F"]);
    let mut expected = BTreeSet::new();
    for row in &rows {
        for variant in VARIANTS {
            for mode in &modes {
                expected.insert(format!("{row}-{variant}-{mode}"));
            }
        }
    }
    assert_eq!(accepted.keys().cloned().collect::<BTreeSet<_>>(), expected);

    let matrix = json_file(root.join("matrix/execution-matrix.json"))?;
    let cases = matrix["cases"].as_array().ok_or("no cases")?;
    assert_eq!(cases.len(), 192);
    for case in cases {
        let id = case["case_id"].as_str().ok_or("no case id")?;
        if let Some((address, result_digest)) = accepted.get(id) {
            assert_eq!(case["executed"], json!(true), "{id}");
            assert_eq!(
                case["expected_result"],
                json!({"equal": true, "first_divergence": null, "nia1_content_digest": address}),
                "{id}"
            );
            assert_eq!(
                case["expected_result_digest"],
                json!(hex(result_digest)),
                "{id}"
            );
        } else {
            assert_eq!(case["executed"], json!(false), "{id}");
            assert_eq!(case["expected_result"], Value::Null, "{id}");
            assert_eq!(case["expected_result_digest"], Value::Null, "{id}");
        }
        assert_eq!(case["authority_fixture_id"], Value::Null, "{id}");
        assert_eq!(case["authority_result_digest"], Value::Null, "{id}");
    }
    assert_eq!(matrix["executed_case_count"], json!(expected.len()));
    for row in matrix["rows"].as_array().ok_or("no rows")? {
        let id = row["fixture_id"].as_str().unwrap_or_default();
        let executed = if rows.iter().any(|declared| declared == id) {
            VARIANTS.len() * modes.len()
        } else {
            0
        };
        assert_eq!(row["executed_case_count"], json!(executed), "{row}");
    }
    Ok(())
}
