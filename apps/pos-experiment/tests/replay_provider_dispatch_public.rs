//! ADR-068 exact provider dispatch of the checked-in `replay-conformance` fixtures through the
//! independent evaluator, and the flip of `expected/replay-conformance/deletion-redaction.json`
//! (ERA-001, degraded Replay; ADR-062 Revision 8, #1296) for a verifier-accepted execution only.
//!
//! The composition root of this test builds a signed in-memory CFB1 corpus from the checked-in
//! fixture files of every family (`pos-reference`'s public corpus builder), hands the evaluator
//! the adapter's exact `FixtureExecutorV1` declaration, and executes each dispatched case
//! through the EAI1/EAO1 byte codec: every attempt launches a fresh `pos-experiment` process.
//! The evaluator's CNR1 report is the verifier verdict. Local and Air-Gapped are both
//! `ExecutionProfile` runs and Local-relaxation engineering evidence; kernel-audited Air-Gapped
//! is slice N7 (#1235).
//!
//! The record shape and fixed-point rule are those of slice N6 (#1234, the ADR-062 R8
//! provider-dispatch note): an executed family's evidence-status record is `executed` only when
//! its case passes in both runs, names each run's outcome and actual output digest, and carries
//! no time. Its content does not depend on its own bytes, so re-execution with the flipped record
//! reaches the same record. Only `deletion-redaction` is an executed family; every other record
//! stays `pending`.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use pos_experiment::replay_conformance::executor_declaration;
use pos_reference::adapter_transport::{read_observation, write_attempt};
use pos_reference::evaluator::{
    evaluate, AdapterError, CaseAttempt, FixtureExecutorV1, SubjectAdapter, SubjectObservation,
};
use pos_reference::evaluator_build_identity::VerifiedEvaluatorBuildIdentity;
use pos_reference::evaluator_protocol::{
    CaseOutcome, CaseStatus, ConformanceReport, SubjectAdapterKind,
};
use pos_reference::selector_test_support::{
    real_replay_corpus, trust_policy_operator, verified_evaluator_identity, Corpus,
    RealFamilyMembers, RealProviderFixtures,
};
use serde_json::{json, Value};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const BINARY: &str = env!("CARGO_BIN_EXE_pos-experiment");
const LAYER: &str = "replay-conformance";
const OUTPUT_LIMIT: u64 = 1_048_576;
const FAMILIES: [&str; 7] = [
    "positive",
    "denied",
    "malformed",
    "resource-exhaustion",
    "deletion-redaction",
    "downgrade",
    "independent-evaluation",
];
/// The families whose evidence-status record is `executed` (#1296).
const EXECUTED_FAMILIES: [&str; 1] = ["deletion-redaction"];
const BUDGET_COUNTERS: [&str; 8] = [
    "memory_bytes",
    "cpu_fuel",
    "host_calls",
    "event_count",
    "output_bytes",
    "storage_bytes",
    "execution_steps",
    "simulation_time_ns",
];
/// The two `ExecutionProfile` runs: the CFB1 mode code and its record name.
const MODES: [(u64, &str); 2] = [(0, "local"), (1, "air-gapped")];

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/conformance")
}

fn read(relative: &str) -> TestResult<Vec<u8>> {
    Ok(fs::read(fixture_root().join(relative))?)
}

fn json_file(relative: &str) -> TestResult<Value> {
    Ok(serde_json::from_slice(&read(relative)?)?)
}

fn text(value: &Value, field: &str) -> TestResult<String> {
    Ok(value[field]
        .as_str()
        .ok_or("a field is not text")?
        .to_owned())
}

fn number(value: &Value, field: &str) -> TestResult<u64> {
    Ok(value[field].as_u64().ok_or("a field is not a number")?)
}

fn family_members(provider: &Value, name: &str) -> TestResult<RealFamilyMembers> {
    let contract = &provider["fixture_contracts"][name];
    let mut budget = [0; 8];
    for (slot, counter) in budget.iter_mut().zip(BUDGET_COUNTERS) {
        *slot = number(&contract["deterministic_budget"], counter)?;
    }
    let oracle = read(&format!("oracles/{LAYER}/{name}.json"))?;
    let kind: Value = serde_json::from_slice(&oracle)?;
    let failure_code = kind["oracle"]["code_id"].as_str().map(str::to_owned);
    let mut capability_ids = Vec::new();
    for id in contract["minimum_capability_ids"]
        .as_array()
        .ok_or("no capabilities")?
    {
        capability_ids.push(id.as_str().ok_or("a capability is not text")?.to_owned());
    }
    Ok(RealFamilyMembers {
        case_id: format!("{LAYER}-{name}"),
        schema: read(&text(&provider["schemas"], name)?)?,
        payload: read(&format!("inputs/{LAYER}/{name}.json"))?,
        evidence: read(&format!("expected/{LAYER}/{name}.json"))?,
        oracle,
        failure_code,
        auxiliary_input: read(&text(&provider["auxiliary"][name][0], "path")?)?,
        budget,
        watchdog_ms: number(contract, "watchdog_ms")?,
        capability_ids,
    })
}

fn real_fixtures() -> TestResult<RealProviderFixtures> {
    let provider = json_file("providers/replay-conformance/provider.json")?;
    let mut families = Vec::new();
    for name in FAMILIES {
        families.push(family_members(&provider, name)?);
    }
    Ok(RealProviderFixtures {
        provider_id: text(&provider, "provider_id")?,
        contract_version: text(&provider, "contract_version")?,
        abi_major: number(&provider, "abi_major")?,
        abi_minor: number(&provider, "abi_minor")?,
        families,
    })
}

/// The replay subject reached through its EAI1/EAO1 process boundary: one fresh
/// `pos-experiment` process per attempt.
struct ProcessSubject {
    subject_digest: [u8; 32],
    executed: usize,
}

impl ProcessSubject {
    fn spawn(stream: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut child = Command::new(BINARY)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        child
            .stdin
            .take()
            .ok_or(std::io::ErrorKind::BrokenPipe)?
            .write_all(stream)?;
        Ok(child.wait_with_output()?.stdout)
    }
}

impl SubjectAdapter for ProcessSubject {
    fn kind(&self) -> SubjectAdapterKind {
        SubjectAdapterKind::ExportedArtifact
    }

    fn subject_artifact_digest(&self) -> [u8; 32] {
        self.subject_digest
    }

    fn execute(&mut self, attempt: &CaseAttempt) -> Result<SubjectObservation, AdapterError> {
        self.executed += 1;
        let mut stream = Vec::new();
        write_attempt(&mut stream, attempt).or(Err(AdapterError::ProtocolFailure))?;
        let out = Self::spawn(&stream).or(Err(AdapterError::Unavailable))?;
        read_observation(out.as_slice(), OUTPUT_LIMIT).or(Err(AdapterError::ProtocolFailure))
    }
}

/// The verified evaluator identity, built once per test process.
fn evaluator_identity() -> TestResult<VerifiedEvaluatorBuildIdentity> {
    static IDENTITY: OnceLock<Result<VerifiedEvaluatorBuildIdentity, String>> = OnceLock::new();
    Ok(IDENTITY
        .get_or_init(|| verified_evaluator_identity().map_err(|error| error.to_string()))
        .clone()?)
}

fn evaluate_corpus(
    corpus: &Corpus,
    executors: &[FixtureExecutorV1],
) -> TestResult<(ConformanceReport, usize)> {
    let mut subject = ProcessSubject {
        subject_digest: corpus.subject_digest,
        executed: 0,
    };
    let report = evaluate(
        &corpus.request,
        &corpus.archive,
        &corpus.trust_policy,
        &trust_policy_operator()?,
        &evaluator_identity()?,
        executors,
        &mut subject,
    )?
    .report;
    Ok((report, subject.executed))
}

fn outcome<'a>(report: &'a ConformanceReport, name: &str) -> TestResult<&'a CaseOutcome> {
    let id = format!("{LAYER}-{name}");
    Ok(report
        .cases
        .iter()
        .find(|case| case.case_id == id)
        .ok_or("a case is absent from the report")?)
}

/// The evidence-status record the flip rule gives `family` for its two runs: `executed` only for
/// an executed family whose case passes in both, else `pending`.
fn wanted_record(family: &RealFamilyMembers, name: &str, runs: &[(&str, &CaseOutcome)]) -> Value {
    let accepted = EXECUTED_FAMILIES.contains(&name)
        && runs
            .iter()
            .all(|(_, case)| case.outcome == CaseStatus::Pass);
    let (status, execution_result) = if accepted {
        let modes: Vec<Value> = runs
            .iter()
            .map(|(mode, case)| {
                let digest = case
                    .actual_digest
                    .map(|digest| blake3::Hash::from_bytes(digest).to_hex().to_string());
                json!({"mode": mode, "outcome": "pass", "actual_digest": digest})
            })
            .collect();
        (
            "executed",
            json!({"evidence": "local-relaxation", "modes": modes}),
        )
    } else {
        ("pending", Value::Null)
    };
    json!({
        "claim_layer": LAYER,
        "case_id": family.case_id,
        "family": name,
        "input_blake3_digest": blake3::hash(&family.payload).to_hex().to_string(),
        "status": status,
        "execution_result": execution_result,
        "executed_at": null,
    })
}

/// Every family dispatches through the adapter's exact declaration and passes in the Local and
/// the Air-Gapped run; each checked-in record is the one the flip rule gives for those runs, so
/// only `deletion-redaction` is `executed`.
#[test]
fn every_replay_family_dispatches_exactly_and_flips_only_when_verified() -> TestResult {
    let fixtures = real_fixtures()?;
    let mut reports = Vec::new();
    for (mode, label) in MODES {
        let corpus = real_replay_corpus(&fixtures, mode)?;
        let declaration = executor_declaration(corpus.subject_digest);
        let (report, executed) = evaluate_corpus(&corpus, &[declaration])?;
        assert_eq!(executed, FAMILIES.len(), "{label}");
        assert_eq!(report.cases.len(), FAMILIES.len(), "{label}");
        reports.push((label, report));
    }
    for (family, name) in fixtures.families.iter().zip(FAMILIES) {
        let mut runs = Vec::new();
        for (label, report) in &reports {
            runs.push((*label, outcome(report, name)?));
        }
        for (label, case) in &runs {
            assert_eq!(case.outcome, CaseStatus::Pass, "{name} {label}");
            assert_eq!(
                case.actual_digest.is_some(),
                family.failure_code.is_none(),
                "{name} {label}"
            );
        }
        assert_eq!(
            json_file(&format!("expected/{LAYER}/{name}.json"))?,
            wanted_record(family, name, &runs),
            "{name}: the record follows the flip rule"
        );
    }
    Ok(())
}

/// A missing declaration, or one that differs from the provider key in its contract or ABI
/// minor, dispatches nothing: every case is non-executed and no process is launched.
#[test]
fn a_missing_or_mismatched_replay_executor_launches_no_process() -> TestResult {
    let fixtures = real_fixtures()?;
    let corpus = real_replay_corpus(&fixtures, 0)?;
    let exact = executor_declaration(corpus.subject_digest);
    let mut newer_minor = exact.clone();
    newer_minor.provider.abi_minor += 1;
    let mut other_contract = exact;
    other_contract.provider.contract_version = "1.0.0".to_owned();
    for (label, executors) in [
        ("no executor", Vec::new()),
        ("newer abi minor", vec![newer_minor]),
        ("other contract", vec![other_contract]),
    ] {
        let (report, executed) = evaluate_corpus(&corpus, &executors)?;
        assert_eq!(executed, 0, "{label}");
        assert_eq!(report.cases.len(), FAMILIES.len(), "{label}");
        for case in &report.cases {
            assert_eq!(case.outcome, CaseStatus::Unavailable, "{label}");
            assert_eq!(case.actual_digest, None, "{label}");
            assert_eq!(case.actual_error, None, "{label}");
        }
    }
    Ok(())
}
