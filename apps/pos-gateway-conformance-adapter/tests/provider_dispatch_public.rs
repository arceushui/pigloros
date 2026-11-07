#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! ADR-068 exact provider dispatch of the checked-in `gateway-client-conformance` fixtures
//! through the independent evaluator (the ADR-062 R8 N6 seam, #1234), and the flip of
//! `expected/gateway-client-conformance/*` for verifier-accepted executions only (#1295).
//!
//! The composition root of this test builds a signed in-memory CFB1 corpus from the checked-in
//! fixture files of every family (`pos-reference`'s public corpus builder), hands the evaluator
//! the adapter's exact `FixtureExecutorV1` declaration, and executes each dispatched case
//! through the adapter's EAI1/EAO1 byte codec on fresh in-process Gateways. The evaluator's
//! CNR1 report is the verifier verdict. Local and Air-Gapped are both `ExecutionProfile` runs
//! and Local-relaxation engineering evidence; kernel-audited Air-Gapped is slice N7.
//!
//! A family's evidence-status record is `executed` exactly when its case passes in both runs;
//! the record then names each run's outcome and its actual output digest or failure code, and
//! carries no time. Its content does not depend on its own bytes, so re-execution with the
//! flipped record reaches the same record (the fixed point of the ADR-062 R8 provider-dispatch
//! note).

use std::fs;
use std::path::PathBuf;

use pos_gateway_conformance_adapter::{executor_declaration, run};
use pos_reference::adapter_transport::{read_observation, write_attempt};
use pos_reference::evaluator::{
    evaluate, AdapterError, CaseAttempt, FixtureExecutorV1, SubjectAdapter, SubjectObservation,
};
use pos_reference::evaluator_protocol::{
    CaseOutcome, CaseStatus, ConformanceReport, SubjectAdapterKind,
};
use pos_reference::selector_test_support::{
    real_provider_corpus, verified_evaluator_identity, Corpus, RealFamilyMembers,
    RealProviderFixtures,
};
use serde_json::{json, Value};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const LAYER: &str = "gateway-client-conformance";
/// The CPF1 wire code of claim layer `GatewayClientConformance`.
const LAYER_CODE: u64 = 3;
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

#[cfg_attr(coverage_nightly, coverage(off))]
fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/conformance")
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn read(relative: &str) -> TestResult<Vec<u8>> {
    Ok(fs::read(fixture_root().join(relative))?)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn json_file(relative: &str) -> TestResult<Value> {
    Ok(serde_json::from_slice(&read(relative)?)?)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn text(value: &Value, field: &str) -> TestResult<String> {
    value[field]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("{field} is not text").into())
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn number(value: &Value, field: &str) -> TestResult<u64> {
    value[field]
        .as_u64()
        .ok_or_else(|| format!("{field} is not a number").into())
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn family_members(provider: &Value, name: &str) -> TestResult<RealFamilyMembers> {
    let contract = &provider["fixture_contracts"][name];
    let mut budget = [0; 8];
    for (slot, counter) in budget.iter_mut().zip(BUDGET_COUNTERS) {
        *slot = number(&contract["deterministic_budget"], counter)?;
    }
    let oracle = read(&format!("oracles/{LAYER}/{name}.json"))?;
    let kind: Value = serde_json::from_slice(&oracle)?;
    let failure_code = kind["oracle"]["code_id"].as_str().map(str::to_owned);
    let capability_ids = contract["minimum_capability_ids"]
        .as_array()
        .ok_or("no capabilities")?
        .iter()
        .map(|id| {
            id.as_str()
                .map(str::to_owned)
                .ok_or("a capability is not text")
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        provider["auxiliary"][name],
        json!([]),
        "{name}: no auxiliary member"
    );
    Ok(RealFamilyMembers {
        case_id: format!("{LAYER}-{name}"),
        schema: read(&text(&provider["schemas"], name)?)?,
        payload: read(&format!("inputs/{LAYER}/{name}.json"))?,
        evidence: read(&format!("expected/{LAYER}/{name}.json"))?,
        oracle,
        failure_code,
        auxiliary_input: None,
        budget,
        watchdog_ms: number(contract, "watchdog_ms")?,
        capability_ids,
    })
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn real_fixtures() -> TestResult<RealProviderFixtures> {
    let provider = json_file(&format!("providers/{LAYER}/provider.json"))?;
    Ok(RealProviderFixtures {
        provider_id: text(&provider, "provider_id")?,
        contract_version: text(&provider, "contract_version")?,
        abi_major: number(&provider, "abi_major")?,
        abi_minor: number(&provider, "abi_minor")?,
        families: FAMILIES
            .iter()
            .map(|name| family_members(&provider, name))
            .collect::<TestResult<Vec<_>>>()?,
    })
}

/// The Gateway subject reached through the adapter's EAI1/EAO1 codec.
struct GatewaySubject {
    subject_digest: [u8; 32],
    executed: usize,
}

impl SubjectAdapter for GatewaySubject {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn kind(&self) -> SubjectAdapterKind {
        SubjectAdapterKind::PublicGatewayProtocol
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn subject_artifact_digest(&self) -> [u8; 32] {
        self.subject_digest
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn execute(&mut self, attempt: &CaseAttempt) -> Result<SubjectObservation, AdapterError> {
        self.executed += 1;
        let mut stream = Vec::new();
        write_attempt(&mut stream, attempt).map_err(|_| AdapterError::ProtocolFailure)?;
        let mut out = Vec::new();
        run(stream.as_slice(), &mut out).map_err(|_| AdapterError::Unavailable)?;
        read_observation(out.as_slice(), OUTPUT_LIMIT).map_err(|_| AdapterError::ProtocolFailure)
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn evaluate_corpus(
    corpus: &Corpus,
    executors: &[FixtureExecutorV1],
) -> TestResult<(ConformanceReport, usize)> {
    let mut subject = GatewaySubject {
        subject_digest: corpus.subject_digest,
        executed: 0,
    };
    let report = evaluate(
        &corpus.request,
        &corpus.archive,
        &corpus.trust_policy,
        &verified_evaluator_identity()?,
        executors,
        &mut subject,
    )?
    .report;
    Ok((report, subject.executed))
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn corpus(fixtures: &RealProviderFixtures, mode: u64) -> TestResult<Corpus> {
    real_provider_corpus(
        fixtures,
        LAYER_CODE,
        SubjectAdapterKind::PublicGatewayProtocol,
        mode,
    )
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn outcome<'a>(report: &'a ConformanceReport, name: &str) -> TestResult<&'a CaseOutcome> {
    let id = format!("{LAYER}-{name}");
    report
        .cases
        .iter()
        .find(|case| case.case_id == id)
        .ok_or_else(|| format!("{id} is absent from the report").into())
}

/// The evidence-status record the flip rule gives `family` for its two runs.
#[cfg_attr(coverage_nightly, coverage(off))]
fn wanted_record(family: &RealFamilyMembers, name: &str, runs: &[(&str, &CaseOutcome)]) -> Value {
    let input = blake3::hash(&family.payload).to_hex().to_string();
    let accepted = runs
        .iter()
        .all(|(_, case)| case.outcome == CaseStatus::Pass);
    let base = |status: &str, execution_result: Value| {
        json!({
            "claim_layer": LAYER,
            "case_id": family.case_id,
            "family": name,
            "input_blake3_digest": input,
            "status": status,
            "execution_result": execution_result,
            "executed_at": null,
        })
    };
    if !accepted {
        return base("pending", Value::Null);
    }
    let modes: Vec<Value> = runs
        .iter()
        .map(|(mode, case)| {
            let (key, observed) = family.failure_code.as_ref().map_or_else(
                || {
                    let digest = case
                        .actual_digest
                        .map(|digest| blake3::Hash::from_bytes(digest).to_hex().to_string());
                    ("actual_digest", json!(digest))
                },
                |code| ("actual_error", json!(code)),
            );
            let mut run = json!({"mode": mode, "outcome": "pass"});
            run[key] = observed;
            run
        })
        .collect();
    base(
        "executed",
        json!({"evidence": "local-relaxation", "modes": modes}),
    )
}

#[test]
fn every_gateway_family_dispatches_exactly_and_flips_only_when_verified() -> TestResult {
    let fixtures = real_fixtures()?;
    let mut reports = Vec::new();
    for (mode, label) in MODES {
        let corpus = corpus(&fixtures, mode)?;
        let declaration = executor_declaration(corpus.subject_digest);
        let (report, executed) = evaluate_corpus(&corpus, &[declaration])?;
        assert_eq!(executed, FAMILIES.len(), "{label}");
        assert_eq!(report.cases.len(), FAMILIES.len(), "{label}");
        reports.push((label, report));
    }
    for (family, name) in fixtures.families.iter().zip(FAMILIES) {
        let runs = reports
            .iter()
            .map(|(label, report)| outcome(report, name).map(|case| (*label, case)))
            .collect::<TestResult<Vec<_>>>()?;
        for (label, case) in &runs {
            assert_eq!(case.outcome, CaseStatus::Pass, "{name} {label}");
            assert_eq!(
                case.actual_digest.is_some(),
                family.failure_code.is_none(),
                "{name} {label}"
            );
        }
        let checked_in = json_file(&format!("expected/{LAYER}/{name}.json"))?;
        assert_eq!(
            checked_in,
            wanted_record(family, name, &runs),
            "{name}: the record follows the flip rule"
        );
    }
    Ok(())
}

#[test]
fn a_missing_or_mismatched_gateway_executor_runs_no_exchange() -> TestResult {
    let fixtures = real_fixtures()?;
    let corpus = corpus(&fixtures, 0)?;
    let exact = executor_declaration(corpus.subject_digest);
    let mut newer_minor = exact.clone();
    newer_minor.provider.abi_minor += 1;
    let mut old_contract = exact.clone();
    old_contract.provider.contract_version = "1.0.0".to_owned();
    let mut plugin_protocol = exact;
    plugin_protocol.subject_adapter = SubjectAdapterKind::PublicPluginProtocol;
    for (label, executors) in [
        ("no executor", Vec::new()),
        ("newer abi minor", vec![newer_minor]),
        ("old contract", vec![old_contract]),
        ("another protocol", vec![plugin_protocol]),
    ] {
        let (report, executed) = evaluate_corpus(&corpus, &executors)?;
        assert_eq!(executed, 0, "{label}");
        assert!(
            report
                .cases
                .iter()
                .all(|case| case.outcome == CaseStatus::Unavailable
                    && case.actual_digest.is_none()
                    && case.actual_error.is_none()),
            "{label}"
        );
    }
    Ok(())
}
