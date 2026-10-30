#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Public-interface tests for the ADR-062 Revision 8 slice R4 replay-conformance
//! subject adapter (#1222).
//!
//! The attempts are built from the checked-in files of `fixtures/conformance`
//! the way the evaluator delivers them: the schema member, the payload, then
//! the auxiliary members (the evidence-status record, the namespaced-failure
//! oracle when the family has one, and the `RCS1` composite). The binary is
//! driven through its process boundary with the pos-reference EAI1/EAO1 codec
//! and judged against the oracle as the evaluator judges it: a
//! `canonical-output` family must output the exact oracle bytes, a
//! `namespaced-failure` family must return the oracle's failure. The oracles
//! and every expected stream are written by
//! `scripts/generate_replay_conformance_fixtures.py`, never by the adapter
//! (Q3).

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use pos_experiment::replay_conformance::{
    exit_code, run, run_with_store, AdapterRunErrorV1, CONTRACT_VERSION, PAYLOAD_INVALID,
    PROVIDER_ID, SCHEMA_ID, SUBCASE_MISMATCH,
};
use pos_reference::adapter_transport::{read_observation, write_attempt};
use pos_reference::evaluator::{
    AttemptArtifact, AttemptTransportCaps, CaseAttempt, ResourceUsage, SubjectObservation,
    SubjectResult,
};
use pos_reference::evaluator_domain::{ClaimLayer, ExecutionMode, FixtureFamily};
use pos_reference::profile::{DeterministicBudget, NamespacedFailure};
use pos_store::StoreConfig;
use serde_json::{json, Value};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const BINARY: &str = env!("CARGO_BIN_EXE_pos-experiment");
const OUTPUT_LIMIT: u64 = 1_048_576;
const FAMILIES: [FixtureFamily; 7] = [
    FixtureFamily::Positive,
    FixtureFamily::Denied,
    FixtureFamily::Malformed,
    FixtureFamily::ResourceExhaustion,
    FixtureFamily::DeletionRedaction,
    FixtureFamily::Downgrade,
    FixtureFamily::IndependentEvaluation,
];

/// The positive payload of provider contract 1.0.0 (before slice R4).
const PROVIDER_1_0_0_PAYLOAD: &[u8] = br#"{"case_id":"replay-conformance-positive","claim_layer":"replay-conformance","family":"positive","provider_contract":"pigloros.fixture.replay-conformance@1.0.0","subject_adapter":"exported-artifact","stimulus":{"operation":"verify-replay-determinism","recorded_events":[{"sequence":0,"event_type":"fixture-created"},{"sequence":1,"event_type":"fixture-verified"}]},"expected":{"replay":"deterministic","final_sequence":1}}
"#;
/// The positive schema member of provider contract 1.0.0.
const PROVIDER_1_0_0_SCHEMA: &[u8] = br#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","required":["case_id","claim_layer","family","provider_contract","subject_adapter","stimulus","expected"],"properties":{"case_id":{"type":"string","minLength":1},"claim_layer":{"type":"string","minLength":1},"family":{"const":"positive"},"provider_contract":{"type":"string","minLength":1},"subject_adapter":{"type":"string","minLength":1},"stimulus":{"const":{"operation":"verify-replay-determinism","recorded_events":[{"sequence":0,"event_type":"fixture-created"},{"sequence":1,"event_type":"fixture-verified"}]}},"expected":{"const":{"replay":"deterministic","final_sequence":1}}},"additionalProperties":false}
"#;

#[cfg_attr(coverage_nightly, coverage(off))]
fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/conformance")
}

#[cfg_attr(coverage_nightly, coverage(off))]
const fn family_name(family: FixtureFamily) -> &'static str {
    match family {
        FixtureFamily::Positive => "positive",
        FixtureFamily::Denied => "denied",
        FixtureFamily::Malformed => "malformed",
        FixtureFamily::ResourceExhaustion => "resource-exhaustion",
        FixtureFamily::DeletionRedaction => "deletion-redaction",
        FixtureFamily::Downgrade => "downgrade",
        FixtureFamily::IndependentEvaluation => "independent-evaluation",
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn read(relative: &str) -> TestResult<Vec<u8>> {
    Ok(fs::read(fixture_root().join(relative))?)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn artifact(bytes: Vec<u8>) -> AttemptArtifact {
    AttemptArtifact {
        digest: *blake3::hash(&bytes).as_bytes(),
        bytes,
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn oracle(family: FixtureFamily) -> TestResult<Vec<u8>> {
    read(&format!(
        "oracles/replay-conformance/{}.json",
        family_name(family)
    ))
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn family_contract(family: FixtureFamily) -> TestResult<Value> {
    let provider: Value =
        serde_json::from_slice(&read("providers/replay-conformance/provider.json")?)?;
    Ok(provider["fixture_contracts"][family_name(family)].clone())
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn counter(budget: &Value, key: &str) -> TestResult<u64> {
    Ok(budget[key].as_u64().ok_or("a budget counter is absent")?)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn family_budget(family: FixtureFamily) -> TestResult<DeterministicBudget> {
    let contract = family_contract(family)?;
    let budget = &contract["deterministic_budget"];
    Ok(DeterministicBudget {
        memory_bytes: counter(budget, "memory_bytes")?,
        cpu_fuel: counter(budget, "cpu_fuel")?,
        host_calls: counter(budget, "host_calls")?,
        event_count: counter(budget, "event_count")?,
        output_bytes: counter(budget, "output_bytes")?,
        storage_bytes: counter(budget, "storage_bytes")?,
        execution_steps: counter(budget, "execution_steps")?,
        simulation_time_ns: counter(budget, "simulation_time_ns")?,
    })
}

/// The attempt of `family` in `mode` from the checked-in fixture files.
#[cfg_attr(coverage_nightly, coverage(off))]
fn attempt(family: FixtureFamily, mode: ExecutionMode) -> TestResult<CaseAttempt> {
    let name = family_name(family);
    let payload = read(&format!("inputs/replay-conformance/{name}.json"))?;
    let schema = read(&format!(
        "providers/replay-conformance/schemas/{name}.schema.json"
    ))?;
    let evidence = read(&format!("expected/replay-conformance/{name}.json"))?;
    let composite = read(&format!("inputs/replay-conformance/{name}.rcs1"))?;
    let oracle = oracle(family)?;
    let kind = serde_json::from_slice::<Value>(&oracle)?["oracle"]["kind"].clone();
    let mut auxiliary = vec![artifact(evidence)];
    if kind == "namespaced-failure" {
        auxiliary.push(artifact(oracle));
    }
    auxiliary.push(artifact(composite));
    let contract = family_contract(family)?;
    Ok(CaseAttempt {
        case_id: format!("replay-conformance-{name}"),
        claim_layer: ClaimLayer::ReplayConformance,
        family,
        mode,
        fixture_digest: *blake3::hash(&payload).as_bytes(),
        schema: artifact(schema),
        payload: artifact(payload),
        auxiliary,
        budget: family_budget(family)?,
        watchdog_ms: contract["watchdog_ms"].as_u64().ok_or("no watchdog")?,
        network_allowed: false,
        capability_ids: Vec::new(),
        transport_caps: AttemptTransportCaps {
            max_member_bytes: 16_777_216,
            max_attempt_bytes: 67_108_864,
        },
    })
}

/// The attempt with its payload rewritten.
#[cfg_attr(coverage_nightly, coverage(off))]
fn with_payload(
    mut attempt: CaseAttempt,
    rewrite: impl FnOnce(&mut Value),
) -> TestResult<CaseAttempt> {
    let mut payload: Value = serde_json::from_slice(&attempt.payload.bytes)?;
    rewrite(&mut payload);
    let mut bytes = serde_json::to_vec(&payload)?;
    bytes.push(b'\n');
    attempt.fixture_digest = *blake3::hash(&bytes).as_bytes();
    attempt.payload = artifact(bytes);
    Ok(attempt)
}

/// `["RCS1", 1, [[digest, bytes], ...]]` over `members`.
#[cfg_attr(coverage_nightly, coverage(off))]
fn composite(
    magic: &str,
    members: &[&[u8]],
    digest_of: impl Fn(&[u8]) -> Vec<u8>,
) -> TestResult<Vec<u8>> {
    use ciborium::value::Value as Cbor;
    let entries = members
        .iter()
        .map(|bytes| {
            Cbor::Array(vec![
                Cbor::Bytes(digest_of(bytes)),
                Cbor::Bytes(bytes.to_vec()),
            ])
        })
        .collect();
    let value = Cbor::Array(vec![
        Cbor::Text(magic.to_owned()),
        Cbor::Integer(1_u8.into()),
        Cbor::Array(entries),
    ]);
    let mut bytes = Vec::new();
    ciborium::into_writer(&value, &mut bytes)?;
    Ok(bytes)
}

/// `members` in increasing digest order, as the `RCS1` grammar requires.
#[cfg_attr(coverage_nightly, coverage(off))]
fn sorted<'a>(members: &[&'a [u8]]) -> Vec<&'a [u8]> {
    let mut sorted = members.to_vec();
    sorted.sort_by_key(|member| blake3_of(member));
    sorted
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn blake3_of(bytes: &[u8]) -> Vec<u8> {
    blake3::hash(bytes).as_bytes().to_vec()
}

/// Run the library on `attempt` in this process.
#[cfg_attr(coverage_nightly, coverage(off))]
fn observe(attempt: &CaseAttempt) -> TestResult<SubjectObservation> {
    observe_with(&StoreConfig::Memory, attempt)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn observe_with(store: &StoreConfig, attempt: &CaseAttempt) -> TestResult<SubjectObservation> {
    let mut stream = Vec::new();
    write_attempt(&mut stream, attempt)?;
    let mut output = Vec::new();
    run_with_store(store, stream.as_slice(), &mut output)?;
    Ok(read_observation(output.as_slice(), OUTPUT_LIMIT)?)
}

/// Run the binary on `stream`: its exit code and standard output.
#[cfg_attr(coverage_nightly, coverage(off))]
fn spawn(stream: &[u8]) -> TestResult<(Option<i32>, Vec<u8>)> {
    let mut child = Command::new(BINARY)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child.stdin.take().ok_or("no stdin")?.write_all(stream)?;
    let output = child.wait_with_output()?;
    Ok((output.status.code(), output.stdout))
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn failure(code: &str) -> SubjectResult {
    SubjectResult::Failure(NamespacedFailure {
        owner_id: PROVIDER_ID.to_owned(),
        contract_version: CONTRACT_VERSION.to_owned(),
        code_id: code.to_owned(),
    })
}

/// The result the evaluator accepts for `family`: the oracle bytes, or the
/// oracle's failure.
#[cfg_attr(coverage_nightly, coverage(off))]
fn oracle_result(family: FixtureFamily) -> TestResult<SubjectResult> {
    let bytes = oracle(family)?;
    let record: Value = serde_json::from_slice(&bytes)?;
    let declared = &record["oracle"];
    Ok(if declared["kind"] == "canonical-output" {
        SubjectResult::Output(bytes)
    } else {
        SubjectResult::Failure(NamespacedFailure {
            owner_id: declared["owner_id"].as_str().ok_or("no owner")?.to_owned(),
            contract_version: declared["contract_version"]
                .as_str()
                .ok_or("no version")?
                .to_owned(),
            code_id: declared["code_id"].as_str().ok_or("no code")?.to_owned(),
        })
    })
}

/// The number of legs the oracle of `family` records.
#[cfg_attr(coverage_nightly, coverage(off))]
fn oracle_legs(family: FixtureFamily) -> TestResult<u64> {
    let record: Value = serde_json::from_slice(&oracle(family)?)?;
    let subcases = record["output"]["subcases"]
        .as_array()
        .or_else(|| record["subcases"].as_array())
        .ok_or("no sub-cases")?;
    let legs: usize = subcases
        .iter()
        .map(|subcase| subcase["legs"].as_array().map_or(0, Vec::len))
        .sum();
    Ok(u64::try_from(legs)?)
}

/// The evaluator's budget rule: no counter above the family budget.
#[cfg_attr(coverage_nightly, coverage(off))]
fn assert_within(usage: &ResourceUsage, budget: &DeterministicBudget) {
    assert!(usage.memory_bytes <= budget.memory_bytes);
    assert!(usage.cpu_fuel <= budget.cpu_fuel);
    assert!(usage.host_calls <= budget.host_calls);
    assert!(usage.event_count <= budget.event_count);
    assert!(usage.output_bytes <= budget.output_bytes);
    assert!(usage.storage_bytes <= budget.storage_bytes);
    assert!(usage.execution_steps <= budget.execution_steps);
    assert!(usage.simulation_time_ns <= budget.simulation_time_ns);
}

/// A standard output that is closed.
struct Unwritable;

impl Write for Unwritable {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("closed"))
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn every_family_meets_its_oracle_through_the_process_boundary() -> TestResult {
    for family in FAMILIES {
        for mode in [ExecutionMode::Local, ExecutionMode::AirGapped] {
            let attempt = attempt(family, mode)?;
            let mut stream = Vec::new();
            write_attempt(&mut stream, &attempt)?;
            let (code, stdout) = spawn(&stream)?;
            assert_eq!(code, Some(0), "{family:?} in {mode:?}");
            let observation = read_observation(stdout.as_slice(), OUTPUT_LIMIT)?;
            assert_eq!(
                observation.result,
                oracle_result(family)?,
                "{family:?} in {mode:?}"
            );
            assert_eq!(observation.usage.execution_steps, oracle_legs(family)?);
            assert_within(&observation.usage, &attempt.budget);
        }
    }
    Ok(())
}

#[test]
fn every_family_meets_its_oracle_through_the_library() -> TestResult {
    for family in FAMILIES {
        let attempt = attempt(family, ExecutionMode::Local)?;
        let observation = observe(&attempt)?;
        assert_eq!(observation.result, oracle_result(family)?, "{family:?}");
        // A second run of the same attempt gives the identical observation.
        assert_eq!(observe(&attempt)?, observation);
    }
    Ok(())
}

#[test]
fn every_w8h1_entry_is_materialized_with_bytes_and_an_independent_expected_result() -> TestResult {
    let inventory: Value = serde_json::from_slice(&read("expected-authority/inventory.json")?)?;
    let entries = inventory["entries"].as_array().ok_or("no entries")?;
    assert_eq!(entries.len(), 11);
    for entry in entries {
        let fixture_id = entry["fixture_id"].as_str().ok_or("no id")?;
        assert_eq!(entry["materialization_status"], "materialized");
        let payload = read(entry["fixture_bytes_path"].as_str().ok_or("no path")?)?;
        let expected = read(entry["expected_result_path"].as_str().ok_or("no path")?)?;
        assert_eq!(
            entry["fixture_bytes_digest"],
            json!(blake3::hash(&payload).to_hex().to_string())
        );
        assert_eq!(
            entry["expected_result_digest"],
            json!(blake3::hash(&expected).to_hex().to_string())
        );
        let payload: Value = serde_json::from_slice(&payload)?;
        let expected: Value = serde_json::from_slice(&expected)?;
        let subcases = expected["output"]["subcases"]
            .as_array()
            .or_else(|| expected["subcases"].as_array())
            .ok_or("no sub-cases")?;
        let carried = |subcases: &Vec<Value>| {
            subcases
                .iter()
                .any(|subcase| subcase["fixture_id"] == fixture_id)
        };
        assert!(carried(
            payload["subcases"].as_array().ok_or("no sub-cases")?
        ));
        assert!(carried(subcases), "{fixture_id}");
    }
    // Materialized is never executed: every evidence-status record is pending.
    for family in FAMILIES {
        let evidence: Value = serde_json::from_slice(&read(&format!(
            "expected/replay-conformance/{}.json",
            family_name(family)
        ))?)?;
        assert_eq!(evidence["status"], "pending");
        assert_eq!(evidence["execution_result"], Value::Null);
    }
    Ok(())
}

#[test]
fn provider_contract_1_0_0_has_no_reader() -> TestResult {
    let mut old = attempt(FixtureFamily::Positive, ExecutionMode::Local)?;
    old.schema = artifact(PROVIDER_1_0_0_SCHEMA.to_vec());
    old.payload = artifact(PROVIDER_1_0_0_PAYLOAD.to_vec());
    let mut stream = Vec::new();
    write_attempt(&mut stream, &old)?;
    assert_eq!(
        run(stream.as_slice(), Vec::new()),
        Err(AdapterRunErrorV1::NotExecuted)
    );
    let (code, stdout) = spawn(&stream)?;
    assert_eq!(code, Some(3), "not executed");
    assert!(stdout.is_empty(), "no EAO1 stream");

    // The 2.0.0 schema member with the 1.0.0 payload is outside the grammar.
    let mut old_payload = attempt(FixtureFamily::Positive, ExecutionMode::Local)?;
    old_payload.payload = artifact(PROVIDER_1_0_0_PAYLOAD.to_vec());
    assert_eq!(observe(&old_payload)?.result, failure(PAYLOAD_INVALID));
    assert_eq!(SCHEMA_ID, "pigloros.replay-conformance.case.v2");
    Ok(())
}

#[test]
fn a_wire_fault_or_an_unwritable_output_writes_no_observation() -> TestResult {
    let (code, stdout) = spawn(b"")?;
    assert_eq!(code, Some(2), "a wire fault");
    assert!(stdout.is_empty());
    assert_eq!(
        run(&b"not EAI1"[..], Vec::new()),
        Err(AdapterRunErrorV1::Wire)
    );

    let mut stream = Vec::new();
    write_attempt(
        &mut stream,
        &attempt(FixtureFamily::Malformed, ExecutionMode::Local)?,
    )?;
    assert_eq!(
        run(stream.as_slice(), Unwritable),
        Err(AdapterRunErrorV1::Output)
    );
    for (error, code) in [
        (AdapterRunErrorV1::Wire, 2),
        (AdapterRunErrorV1::NotExecuted, 3),
        (AdapterRunErrorV1::Output, 4),
    ] {
        assert_eq!(error.code(), code);
        assert_eq!(
            format!("{:?}", exit_code(Err(error))),
            format!("{:?}", std::process::ExitCode::from(code))
        );
    }
    assert_eq!(
        format!("{:?}", exit_code(Ok(()))),
        format!("{:?}", std::process::ExitCode::SUCCESS)
    );
    Ok(())
}

#[test]
fn another_claim_layer_or_mode_is_unavailable() -> TestResult {
    let mut foreign = attempt(FixtureFamily::Positive, ExecutionMode::Local)?;
    foreign.claim_layer = ClaimLayer::PluginConformance;
    let replay_mode = attempt(FixtureFamily::Positive, ExecutionMode::Replay)?;
    let fork_mode = attempt(FixtureFamily::Positive, ExecutionMode::Fork)?;
    for attempt in [foreign, replay_mode, fork_mode] {
        let observation = observe(&attempt)?;
        assert_eq!(observation.result, SubjectResult::Unavailable);
        assert_eq!(observation.usage, ResourceUsage::default());
    }
    Ok(())
}

#[test]
fn an_attempt_without_its_composite_is_not_executed() -> TestResult {
    let base = attempt(FixtureFamily::Positive, ExecutionMode::Local)?;
    let members = [b"SPDX-License-Identifier: MIT\n".as_slice()];
    // Two members out of digest order (and so not unique-sorted).
    let mut unsorted = [b"first".as_slice(), b"second".as_slice()];
    unsorted.sort_by_key(|member| std::cmp::Reverse(blake3_of(member)));
    let candidates = [
        Vec::new(),
        vec![artifact(b"{}".to_vec())],
        vec![artifact(composite("MCS1", &members, blake3_of)?)],
        vec![artifact(composite("RCS1", &members, |_| vec![0; 32])?)],
        vec![artifact(composite("RCS1", &members, |_| vec![0; 31])?)],
        vec![artifact(composite("RCS1", &unsorted, blake3_of)?)],
    ];
    for auxiliary in candidates {
        let mut attempt = base.clone();
        attempt.auxiliary = auxiliary;
        let mut stream = Vec::new();
        write_attempt(&mut stream, &attempt)?;
        assert_eq!(
            run(stream.as_slice(), Vec::new()),
            Err(AdapterRunErrorV1::NotExecuted)
        );
    }
    Ok(())
}

#[test]
fn a_payload_outside_the_grammar_is_payload_invalid() -> TestResult {
    let positive = attempt(FixtureFamily::Positive, ExecutionMode::Local)?;
    let denied = attempt(FixtureFamily::Denied, ExecutionMode::Local)?;
    let licence = blake3::hash(b"SPDX-License-Identifier: MIT\n")
        .to_hex()
        .to_string();
    let invalid: [fn(&mut Value); 14] = [
        |payload: &mut Value| payload["schema"] = json!("pigloros.replay-conformance.case.v1"),
        |payload: &mut Value| payload["family"] = json!("denied"),
        |payload: &mut Value| payload["subcases"] = json!([]),
        |payload: &mut Value| {
            let first = payload["subcases"][0].clone();
            payload["subcases"] = Value::Array(vec![first; 17]);
        },
        |payload: &mut Value| {
            payload["subcases"][2]["profiles"] = json!(["deterministic-local-v1"]);
        },
        |payload: &mut Value| payload["subcases"][0]["ticks"] = json!(3),
        |payload: &mut Value| {
            payload["subcases"][1]["export_evaluation"] =
                json!({"rule": "PreserveExact", "state": "Retained"});
        },
        |payload: &mut Value| payload["subcases"][0]["closure"]["primary"] = json!("00".repeat(32)),
        |payload: &mut Value| payload["subcases"][0]["closure"]["licence"] = json!("zz"),
        |payload: &mut Value| payload["subcases"][1]["manifest"]["input_digest"] = json!("0"),
        |payload: &mut Value| payload["subcases"][1]["expected_stream"]["timeline"] = json!("00"),
        |payload: &mut Value| {
            payload["subcases"][1]["expected_stream"]["events"][0]["identity"] = json!("");
        },
        |payload: &mut Value| {
            payload["subcases"][1]["expected_stream"]["checkpoint"]["digest"] = json!("AB");
        },
        |payload: &mut Value| payload["subcases"][1]["unknown"] = json!(true),
    ];
    for rewrite in invalid {
        let observation = observe(&with_payload(positive.clone(), rewrite)?)?;
        assert_eq!(observation.result, failure(PAYLOAD_INVALID));
        assert_eq!(observation.usage, ResourceUsage::default());
    }
    // A closure member of the wrong kind: the licence as the export or the
    // subject.
    let licence_as_export = with_payload(positive.clone(), |payload| {
        payload["subcases"][0]["closure"]["primary"] = json!(licence);
    })?;
    let licence_as_subject = with_payload(positive.clone(), |payload| {
        payload["subcases"][1]["closure"]["primary"] = json!(licence);
    })?;
    let bad_failure_bytes = with_payload(denied, |payload| {
        payload["subcases"][0]["expected_stream"]["failure"]["bytes"] = json!("0");
    })?;
    let not_json = CaseAttempt {
        payload: artifact(b"not JSON".to_vec()),
        ..positive
    };
    for attempt in [
        licence_as_export,
        licence_as_subject,
        bad_failure_bytes,
        not_json,
    ] {
        assert_eq!(observe(&attempt)?.result, failure(PAYLOAD_INVALID));
    }
    Ok(())
}

#[test]
fn a_subject_member_outside_its_grammar_is_payload_invalid() -> TestResult {
    let base = attempt(FixtureFamily::ResourceExhaustion, ExecutionMode::Local)?;
    let payload: Value = serde_json::from_slice(&base.payload.bytes)?;
    let subcase = &payload["subcases"][0];
    let licence = b"SPDX-License-Identifier: MIT\n";
    let subject = json!({
        "schema": "pigloros.replay-conformance.subject.v1",
        "entity": "000000000004HMASW9NF6YY7QF",
        "event_type": "replay.count",
        "drafts": [["01"], ["02"], ["03"]],
        "failure": null,
    });
    let mut variants = Vec::new();
    for (key, value) in [
        ("schema", json!("pigloros.replay-conformance.subject.v2")),
        ("entity", json!("not a ULID")),
        ("drafts", json!([["0g"]])),
    ] {
        let mut variant = subject.clone();
        variant[key] = value;
        variants.push(serde_json::to_vec(&variant)?);
    }
    for member in variants {
        let mut attempt = with_payload(base.clone(), |payload| {
            payload["subcases"][0]["closure"]["primary"] =
                json!(blake3::hash(&member).to_hex().to_string());
        })?;
        attempt.auxiliary = vec![artifact(composite(
            "RCS1",
            &sorted(&[member.as_slice(), licence.as_slice()]),
            blake3_of,
        )?)];
        assert_eq!(observe(&attempt)?.result, failure(PAYLOAD_INVALID));
    }
    // The well-formed member with the same composite layout runs.
    let member = serde_json::to_vec(&subject)?;
    let mut attempt = with_payload(base, |payload| {
        payload["subcases"][0]["closure"]["primary"] =
            json!(blake3::hash(&member).to_hex().to_string());
    })?;
    attempt.auxiliary = vec![artifact(composite(
        "RCS1",
        &sorted(&[member.as_slice(), licence.as_slice()]),
        blake3_of,
    )?)];
    // The request still binds the checked-in subject, so the closure is
    // refused at `artifact_closure`: a mismatch for this family.
    assert_eq!(subcase["id"], "res.1");
    assert_eq!(observe(&attempt)?.result, failure(SUBCASE_MISMATCH));
    Ok(())
}

#[test]
fn a_leg_that_is_not_as_expected_fails_its_oracle() -> TestResult {
    // A namespaced-failure family returns `subcase-mismatch`.
    let denied = with_payload(
        attempt(FixtureFamily::Denied, ExecutionMode::Local)?,
        |payload| payload["subcases"][2]["expect"][0]["replay_claim"] = json!("Exact"),
    )?;
    let observation = observe(&denied)?;
    assert_eq!(observation.result, failure(SUBCASE_MISMATCH));
    assert_eq!(observation.usage.execution_steps, 4);

    // A canonical-output family outputs what it observed, which is then not
    // its oracle: here a recorded Event payload the expected stream changes.
    let positive = with_payload(
        attempt(FixtureFamily::Positive, ExecutionMode::Local)?,
        |payload| payload["subcases"][0]["expected_stream"]["events"][1]["payload"] = json!("0a"),
    )?;
    let SubjectResult::Output(bytes) = observe(&positive)?.result else {
        return Err("a positive case outputs its record".into());
    };
    assert_ne!(bytes, oracle(FixtureFamily::Positive)?);
    let record: Value = serde_json::from_slice(&bytes)?;
    let leg = &record["output"]["subcases"][0]["legs"][0];
    assert_eq!(leg["outcome"], "Diverged");
    assert_eq!(leg["divergence"]["location"], "TimelineSeq");
    assert_eq!(leg["divergence"]["mismatch"], "CanonicalBytes");
    assert_eq!(leg["divergence"]["seq"], 2);
    Ok(())
}

#[test]
fn a_host_that_cannot_start_makes_the_attempt_unavailable() -> TestResult {
    let directory = tempfile::tempdir()?;
    let unreachable = StoreConfig::Sqlite {
        path: directory
            .path()
            .join("missing")
            .join("store.db")
            .to_string_lossy()
            .into_owned(),
    };
    let attempt = attempt(FixtureFamily::Positive, ExecutionMode::Local)?;
    let observation = observe_with(&unreachable, &attempt)?;
    assert_eq!(observation.result, SubjectResult::Unavailable);
    assert_eq!(observation.usage, ResourceUsage::default());
    Ok(())
}
