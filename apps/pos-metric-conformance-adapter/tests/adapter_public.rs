#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Public-interface tests for the ADR-062 Revision 7 slice 4 metric-conformance subject adapter
//! of plugins/eval (#1217).
//!
//! The attempts are built from the checked-in files of `fixtures/conformance` the way the
//! evaluator delivers them: the schema member, the payload, then the auxiliary members (the
//! evidence-status record, the namespaced-failure oracle when the family has one, and the
//! `MCS1` composite), with the provider's budget, watchdog and capabilities. The binary is driven
//! through its process boundary with the pos-reference EAI1/EAO1 codec and judged as the
//! evaluator judges a CNR1 case: a `canonical-output` family must output the exact oracle bytes,
//! a `namespaced-failure` family must return the oracle's failure, and no usage counter may
//! exceed the family budget. The oracles are written by the offline exact-fraction generator
//! (`scripts/generate_metric_conformance_fixtures.py`) and recomputed here by pos-reference;
//! plugins/eval is never asked for an expected result.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use ciborium::value::Value as Cbor;
use pos_metric_conformance_adapter::{
    exit_code, run, AdapterRunErrorV1, CAPABILITY_ID, CONTRACT_VERSION, PAYLOAD_INVALID,
    PROVIDER_ID, SCHEMA_ID, SUBCASE_MISMATCH,
};
use pos_reference::adapter_transport::{read_observation, write_attempt};
use pos_reference::evaluator::{
    AttemptArtifact, AttemptTransportCaps, CaseAttempt, ResourceUsage, SubjectObservation,
    SubjectResult,
};
use pos_reference::evaluator_domain::{ClaimLayer, ExecutionMode, FixtureFamily};
use pos_reference::metric_profile::{
    accept_result_v1, recompute_quantization_v1, recompute_result_v1,
};
use pos_reference::profile::{DeterministicBudget, NamespacedFailure};
use serde_json::{json, Value};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const BINARY: &str = env!("CARGO_BIN_EXE_pos-metric-conformance-adapter");
const OUTPUT_LIMIT: u64 = 1_048_576;
const MEMBER_CEILING: u64 = 64 * 1024 * 1024;
const FAMILIES: [FixtureFamily; 7] = [
    FixtureFamily::Positive,
    FixtureFamily::Denied,
    FixtureFamily::Malformed,
    FixtureFamily::ResourceExhaustion,
    FixtureFamily::DeletionRedaction,
    FixtureFamily::Downgrade,
    FixtureFamily::IndependentEvaluation,
];
const MODES: [ExecutionMode; 2] = [ExecutionMode::Local, ExecutionMode::AirGapped];

/// The positive payload of the Draft provider contract 1.0.0 (`fixture-ratio`).
const PROVIDER_1_0_0_PAYLOAD: &[u8] = br#"{"case_id":"metric-conformance-positive","claim_layer":"metric-conformance","family":"positive","provider_contract":"pigloros.fixture.metric-conformance@1.0.0","subject_adapter":"exported-artifact","stimulus":{"operation":"evaluate-metric-contract","metric":{"name":"fixture-ratio","numerator":9,"denominator":10}},"expected":{"value_micros":900000,"unit":"ratio"}}
"#;
/// The positive schema member of the Draft provider contract 1.0.0.
const PROVIDER_1_0_0_SCHEMA: &[u8] = br#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","required":["case_id","claim_layer","family","provider_contract","subject_adapter","stimulus","expected"],"properties":{"case_id":{"type":"string","minLength":1},"claim_layer":{"type":"string","minLength":1},"family":{"const":"positive"},"provider_contract":{"type":"string","minLength":1},"subject_adapter":{"type":"string","minLength":1},"stimulus":{"const":{"operation":"evaluate-metric-contract","metric":{"name":"fixture-ratio","numerator":9,"denominator":10}}},"expected":{"const":{"value_micros":900000,"unit":"ratio"}}},"additionalProperties":false}
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
        "oracles/metric-conformance/{}.json",
        family_name(family)
    ))
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn family_contract(family: FixtureFamily) -> TestResult<Value> {
    let provider: Value =
        serde_json::from_slice(&read("providers/metric-conformance/provider.json")?)?;
    Ok(provider["fixture_contracts"][family_name(family)].clone())
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn counter(budget: &Value, key: &str) -> TestResult<u64> {
    Ok(budget[key].as_u64().ok_or("a budget counter is absent")?)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn family_budget(contract: &Value) -> TestResult<DeterministicBudget> {
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
    let payload = read(&format!("inputs/metric-conformance/{name}.json"))?;
    let schema = read(&format!(
        "providers/metric-conformance/schemas/{name}.schema.json"
    ))?;
    let evidence = read(&format!("expected/metric-conformance/{name}.json"))?;
    let composite = read(&format!("inputs/metric-conformance/{name}.mcs1"))?;
    let oracle = oracle(family)?;
    let kind = serde_json::from_slice::<Value>(&oracle)?["oracle"]["kind"].clone();
    let mut auxiliary = vec![artifact(evidence)];
    if kind == "namespaced-failure" {
        auxiliary.push(artifact(oracle));
    }
    auxiliary.push(artifact(composite));
    let contract = family_contract(family)?;
    let capability_ids = contract["minimum_capability_ids"]
        .as_array()
        .ok_or("no capabilities")?
        .iter()
        .map(|capability| capability.as_str().map(str::to_owned))
        .collect::<Option<Vec<String>>>()
        .ok_or("a capability is not text")?;
    Ok(CaseAttempt {
        case_id: format!("metric-conformance-{name}"),
        claim_layer: ClaimLayer::MetricConformance,
        family,
        mode,
        fixture_digest: *blake3::hash(&payload).as_bytes(),
        schema: artifact(schema),
        payload: artifact(payload),
        auxiliary,
        budget: family_budget(&contract)?,
        watchdog_ms: contract["watchdog_ms"].as_u64().ok_or("no watchdog")?,
        network_allowed: contract["network_allowed"].as_bool().ok_or("no network")?,
        capability_ids,
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

#[cfg_attr(coverage_nightly, coverage(off))]
fn encode(value: &Cbor) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

/// `["MCS1", 1, [[digest, member], ...]]` over `members` in the given order.
#[cfg_attr(coverage_nightly, coverage(off))]
fn composite(magic: &str, version: u8, entries: Vec<Cbor>) -> TestResult<Vec<u8>> {
    encode(&Cbor::Array(vec![
        Cbor::Text(magic.to_owned()),
        Cbor::Integer(version.into()),
        Cbor::Array(entries),
    ]))
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn entry(member: &[u8]) -> Cbor {
    Cbor::Array(vec![
        Cbor::Bytes(blake3::hash(member).as_bytes().to_vec()),
        Cbor::Bytes(member.to_vec()),
    ])
}

/// `members` in increasing digest order, as the `MCS1` grammar requires.
#[cfg_attr(coverage_nightly, coverage(off))]
fn sorted_entries(members: &[&[u8]]) -> Vec<Cbor> {
    let mut sorted = members.to_vec();
    sorted.sort_by_key(|member| *blake3::hash(member).as_bytes());
    sorted.into_iter().map(entry).collect()
}

/// The members of the checked-in composite of `family`, by lowercase hexadecimal digest.
#[cfg_attr(coverage_nightly, coverage(off))]
fn members(family: FixtureFamily) -> TestResult<BTreeMap<String, Vec<u8>>> {
    let composite = read(&format!(
        "inputs/metric-conformance/{}.mcs1",
        family_name(family)
    ))?;
    let root: Cbor = ciborium::from_reader(composite.as_slice())?;
    let fields = root.as_array().ok_or("no MCS1 array")?;
    let entries = fields
        .get(2)
        .and_then(Cbor::as_array)
        .ok_or("no MCS1 entries")?;
    let mut members = BTreeMap::new();
    for entry in entries {
        let pair = entry.as_array().ok_or("no MCS1 pair")?;
        let member = pair.get(1).and_then(Cbor::as_bytes).ok_or("no member")?;
        members.insert(blake3::hash(member).to_hex().to_string(), member.clone());
    }
    Ok(members)
}

/// The sub-case `id` of the checked-in payload of `family`.
#[cfg_attr(coverage_nightly, coverage(off))]
fn subcase(family: FixtureFamily, id: &str) -> TestResult<Value> {
    let payload: Value = serde_json::from_slice(&read(&format!(
        "inputs/metric-conformance/{}.json",
        family_name(family)
    ))?)?;
    Ok(payload["subcases"]
        .as_array()
        .ok_or("no sub-cases")?
        .iter()
        .find(|subcase| subcase["id"] == id)
        .ok_or("no such sub-case")?
        .clone())
}

/// The member bytes of sub-case `id` of `family`.
#[cfg_attr(coverage_nightly, coverage(off))]
fn member_of(family: FixtureFamily, id: &str) -> TestResult<Vec<u8>> {
    let subcase = subcase(family, id)?;
    let digest = subcase["member"]["blake3"]
        .as_str()
        .ok_or("no member digest")?;
    Ok(members(family)?
        .remove(digest)
        .ok_or("the composite lacks the member")?)
}

/// The oracle entry of sub-case `id` of a `family`.
#[cfg_attr(coverage_nightly, coverage(off))]
fn oracle_entry(family: FixtureFamily, id: &str) -> TestResult<Value> {
    let record: Value = serde_json::from_slice(&oracle(family)?)?;
    Ok(record["output"]["subcases"]
        .as_array()
        .or_else(|| record["subcases"].as_array())
        .ok_or("no sub-cases")?
        .iter()
        .find(|entry| entry["id"] == id)
        .ok_or("no such oracle entry")?
        .clone())
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn unhex(text: &str) -> TestResult<Vec<u8>> {
    (0..text.len())
        .step_by(2)
        .map(|index| {
            text.get(index..index + 2)
                .ok_or_else(|| "odd hex".into())
                .and_then(|pair| u8::from_str_radix(pair, 16).map_err(Into::into))
        })
        .collect()
}

/// Run the library on `attempt` in this process.
#[cfg_attr(coverage_nightly, coverage(off))]
fn observe(attempt: &CaseAttempt) -> TestResult<SubjectObservation> {
    let mut stream = Vec::new();
    write_attempt(&mut stream, attempt)?;
    let mut output = Vec::new();
    run(stream.as_slice(), &mut output)?;
    Ok(read_observation(output.as_slice(), OUTPUT_LIMIT)?)
}

/// Run the library on `attempt`: its result, or the reason it wrote nothing.
#[cfg_attr(coverage_nightly, coverage(off))]
fn run_attempt(attempt: &CaseAttempt) -> TestResult<Result<(), AdapterRunErrorV1>> {
    let mut stream = Vec::new();
    write_attempt(&mut stream, attempt)?;
    Ok(run(stream.as_slice(), Vec::new()))
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

/// The output of a `canonical-output` observation as JSON.
#[cfg_attr(coverage_nightly, coverage(off))]
fn output_json(observation: &SubjectObservation) -> TestResult<Value> {
    match &observation.result {
        SubjectResult::Output(bytes) => Ok(serde_json::from_slice(bytes)?),
        other => Err(format!("not an output: {other:?}").into()),
    }
}

/// The CNR1 case status the evaluator records.
#[derive(Debug, PartialEq)]
enum CaseStatus {
    Pass,
    Fail,
}

/// The fields of a CNR1 case outcome the subject's observation decides.
#[derive(Debug, PartialEq)]
struct CaseOutcome {
    status: CaseStatus,
    expected_digest: Option<[u8; 32]>,
    actual_digest: Option<[u8; 32]>,
    actual_failure: Option<NamespacedFailure>,
}

/// Judge `observation` of `family` as the evaluator judges a case (`pos_reference::evaluator`):
/// usage above the budget fails; an output passes when its length and BLAKE3 equal the oracle
/// member's; a failure passes when it equals the oracle's namespaced failure.
#[cfg_attr(coverage_nightly, coverage(off))]
fn judge(
    family: FixtureFamily,
    observation: &SubjectObservation,
    budget: &DeterministicBudget,
) -> TestResult<CaseOutcome> {
    let oracle_bytes = oracle(family)?;
    let record: Value = serde_json::from_slice(&oracle_bytes)?;
    let declared = &record["oracle"];
    let usage = observation.usage;
    let within = usage.memory_bytes <= budget.memory_bytes
        && usage.cpu_fuel <= budget.cpu_fuel
        && usage.host_calls <= budget.host_calls
        && usage.event_count <= budget.event_count
        && usage.output_bytes <= budget.output_bytes
        && usage.storage_bytes <= budget.storage_bytes
        && usage.execution_steps <= budget.execution_steps
        && usage.simulation_time_ns <= budget.simulation_time_ns;
    let canonical = declared["kind"] == "canonical-output";
    let expected_digest = canonical.then(|| *blake3::hash(&oracle_bytes).as_bytes());
    let expected_failure = NamespacedFailure {
        owner_id: declared["owner_id"].as_str().unwrap_or_default().to_owned(),
        contract_version: declared["contract_version"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        code_id: declared["code_id"].as_str().unwrap_or_default().to_owned(),
    };
    let (status, actual_digest, actual_failure) = match &observation.result {
        SubjectResult::Output(bytes) => {
            let digest = *blake3::hash(bytes).as_bytes();
            let pass =
                canonical && bytes.len() == oracle_bytes.len() && Some(digest) == expected_digest;
            (pass, Some(digest), None)
        }
        SubjectResult::Failure(actual) => (
            !canonical && *actual == expected_failure,
            None,
            Some(actual.clone()),
        ),
        SubjectResult::Divergence { .. } | SubjectResult::Unavailable => (false, None, None),
    };
    Ok(CaseOutcome {
        status: if status && within {
            CaseStatus::Pass
        } else {
            CaseStatus::Fail
        },
        expected_digest,
        actual_digest,
        actual_failure,
    })
}

#[test]
fn every_metric_conformance_case_passes_in_local_and_air_gapped_through_the_process_boundary(
) -> TestResult {
    for family in FAMILIES {
        let mut outcomes = Vec::new();
        for mode in MODES {
            let attempt = attempt(family, mode)?;
            let mut stream = Vec::new();
            write_attempt(&mut stream, &attempt)?;
            let (code, stdout) = spawn(&stream)?;
            assert_eq!(code, Some(0), "{family:?} in {mode:?}");
            let observation = read_observation(stdout.as_slice(), OUTPUT_LIMIT)?;
            let outcome = judge(family, &observation, &attempt.budget)?;
            assert_eq!(outcome.status, CaseStatus::Pass, "{family:?} in {mode:?}");
            outcomes.push((outcome, observation));
        }
        // The CNR1 case outcome and the observation are identical in both modes: the same
        // MTR1/MQR1 bytes, or the same failure.
        assert_eq!(outcomes[0], outcomes[1], "{family:?}");
    }
    Ok(())
}

#[test]
fn every_family_gives_the_identical_observation_through_the_library() -> TestResult {
    for family in FAMILIES {
        let local = observe(&attempt(family, ExecutionMode::Local)?)?;
        let air_gapped = observe(&attempt(family, ExecutionMode::AirGapped)?)?;
        assert_eq!(local, air_gapped, "{family:?}");
        // A second run of the same attempt gives the identical observation.
        assert_eq!(observe(&attempt(family, ExecutionMode::Local)?)?, local);
    }
    Ok(())
}

#[test]
fn one_execution_step_is_metered_per_member_plugins_eval_decodes() -> TestResult {
    // positive 15 and deletion-redaction 4 members; independent-evaluation decodes ind.1 and
    // ind.3 but not the generator check ind.2.
    for (family, steps) in [
        (FixtureFamily::Positive, 15),
        (FixtureFamily::DeletionRedaction, 4),
        (FixtureFamily::IndependentEvaluation, 2),
        // den.1 and den.2 are refused before their member is read.
        (FixtureFamily::Denied, 0),
        // res.1 is decoded; res.2 is rejected by the transport and res.3 by the step budget.
        (FixtureFamily::ResourceExhaustion, 1),
        // dgr.1 is decoded; dgr.2 is refused and dgr.3 is the evaluator's.
        (FixtureFamily::Downgrade, 1),
    ] {
        let usage = observe(&attempt(family, ExecutionMode::Local)?)?.usage;
        assert_eq!(
            usage,
            ResourceUsage {
                execution_steps: steps,
                ..ResourceUsage::default()
            },
            "{family:?}"
        );
    }
    let malformed = attempt(FixtureFamily::Malformed, ExecutionMode::AirGapped)?;
    let payload: Value = serde_json::from_slice(&malformed.payload.bytes)?;
    let subcases = payload["subcases"].as_array().ok_or("no sub-cases")?;
    assert_eq!(
        observe(&malformed)?.usage.execution_steps,
        u64::try_from(subcases.len())?
    );
    Ok(())
}

#[test]
fn independent_evaluation_is_decided_by_pos_reference_and_the_generator_not_by_eval() -> TestResult
{
    let family = FixtureFamily::IndependentEvaluation;
    // ind.1: pos-reference recomputes the mixed MTI1 to the oracle bytes.
    let ind1 = oracle_entry(family, "ind.1")?;
    let recomputed =
        recompute_result_v1(&member_of(family, "ind.1")?).map_err(|failure| failure.to_string())?;
    assert_eq!(recomputed, unhex(ind1["hex"].as_str().ok_or("no hex")?)?);
    // ind.3: pos-reference recomputes the MTQ1 bit patterns to the oracle bytes.
    let ind3 = oracle_entry(family, "ind.3")?;
    let quantized = recompute_quantization_v1(&member_of(family, "ind.3")?)
        .map_err(|failure| failure.to_string())?;
    assert_eq!(quantized, unhex(ind3["hex"].as_str().ok_or("no hex")?)?);
    // ind.2: the generator's --check is not a subject output.
    assert_eq!(
        oracle_entry(family, "ind.2")?,
        json!({"id": "ind.2", "kind": "generator-check"})
    );
    // The adapter outputs the oracle bytes, which equal what pos-reference recomputed.
    let output = output_json(&observe(&attempt(family, ExecutionMode::AirGapped)?)?)?;
    assert_eq!(output["output"]["subcases"][0]["hex"], ind1["hex"]);
    assert_eq!(output["output"]["subcases"][2]["hex"], ind3["hex"]);
    Ok(())
}

#[test]
fn dgr3_a_foreign_mtr1_is_refused_by_the_evaluator_and_not_read_by_the_subject() -> TestResult {
    let family = FixtureFamily::Downgrade;
    let expected = oracle_entry(family, "dgr.3")?;
    let refused = accept_result_v1(&member_of(family, "dgr.3")?)
        .err()
        .ok_or("pos-reference accepted a foreign MTR1")?;
    assert_eq!(refused.error.to_string(), expected["error"]);
    assert_eq!(refused.first_coordinate, expected["first_coordinate"]);
    // An MTR1 member is never an input of the subject.
    let as_input = with_payload(attempt(family, ExecutionMode::Local)?, |payload| {
        payload["subcases"][2]["expect"] = json!({"kind": "metric-error", "code": 2,
               "error": "UnsupportedAlgorithm", "first_coordinate": "algorithm_major"});
    })?;
    assert_eq!(observe(&as_input)?.result, failure(PAYLOAD_INVALID));
    Ok(())
}

#[test]
fn deletion_redaction_results_never_carry_the_canary_identifier() -> TestResult {
    let marker = subcase(FixtureFamily::DeletionRedaction, "del.3")?["expect"]["absent_marker"]
        .as_str()
        .ok_or("no marker")?
        .to_owned();
    let observation = observe(&attempt(
        FixtureFamily::DeletionRedaction,
        ExecutionMode::AirGapped,
    )?)?;
    let SubjectResult::Output(bytes) = &observation.result else {
        return Err("no output".into());
    };
    assert!(!bytes
        .windows(marker.len())
        .any(|window| window == marker.as_bytes()));
    Ok(())
}

#[test]
fn a_failure_family_with_a_subcase_that_is_not_as_expected_is_subcase_mismatch() -> TestResult {
    let mismatch = failure(SUBCASE_MISMATCH);
    let malformed = attempt(FixtureFamily::Malformed, ExecutionMode::Local)?;
    let rewrites: [fn(&mut Value); 3] = [
        // Another first coordinate, another code, another name.
        |payload: &mut Value| {
            payload["subcases"][0]["expect"]["first_coordinate"] = json!("records/0/1");
        },
        |payload: &mut Value| payload["subcases"][0]["expect"]["code"] = json!(5),
        |payload: &mut Value| {
            payload["subcases"][0]["expect"]["error"] = json!("InvalidProbability");
        },
    ];
    for rewrite in rewrites {
        assert_eq!(
            observe(&with_payload(malformed.clone(), rewrite)?)?.result,
            mismatch
        );
    }
    // den.1 asking for the one capability the subject holds is granted, and computes.
    let granted = with_payload(
        attempt(FixtureFamily::Denied, ExecutionMode::AirGapped)?,
        |payload| {
            payload["subcases"][0]["stimulus"]["capability"] = json!(CAPABILITY_ID);
        },
    )?;
    let observation = observe(&granted)?;
    assert_eq!(observation.result, mismatch);
    assert_eq!(observation.usage.execution_steps, 1);
    let resource = attempt(FixtureFamily::ResourceExhaustion, ExecutionMode::Local)?;
    // The fixture's step budget, which res.3 exceeds by one.
    assert_eq!(resource.budget.execution_steps, 10_000_000);
    let rewrites: [fn(&mut Value); 2] = [
        // res.2 at exactly the 64 MiB ceiling is accepted by the transport.
        |payload: &mut Value| payload["subcases"][1]["stimulus"]["bytes"] = json!(MEMBER_CEILING),
        // res.3 at exactly the step budget is granted.
        |payload: &mut Value| payload["subcases"][2]["stimulus"]["requested"] = json!(10_000_000),
    ];
    for rewrite in rewrites {
        assert_eq!(
            observe(&with_payload(resource.clone(), rewrite)?)?.result,
            mismatch
        );
    }
    // dgr.2 presented with the subject's own contract is not refused.
    let own = with_payload(
        attempt(FixtureFamily::Downgrade, ExecutionMode::Local)?,
        |payload| {
            payload["subcases"][1]["stimulus"]["presented"]["contract_version"] =
                json!(CONTRACT_VERSION);
        },
    )?;
    assert_eq!(observe(&own)?.result, mismatch);
    Ok(())
}

#[test]
fn every_evidence_status_record_stays_pending() -> TestResult {
    // The run is Local-relaxation engineering evidence of a Draft profile, not a verified
    // Candidate execution, so no expected record is flipped from pending.
    for family in FAMILIES {
        let name = family_name(family);
        let evidence: Value =
            serde_json::from_slice(&read(&format!("expected/metric-conformance/{name}.json"))?)?;
        let payload = read(&format!("inputs/metric-conformance/{name}.json"))?;
        assert_eq!(evidence["status"], "pending", "{name}");
        assert_eq!(evidence["execution_result"], Value::Null, "{name}");
        assert_eq!(evidence["executed_at"], Value::Null, "{name}");
        assert_eq!(
            evidence["input_blake3_digest"],
            json!(blake3::hash(&payload).to_hex().to_string())
        );
    }
    Ok(())
}

#[test]
fn provider_contract_1_0_0_has_no_reader() -> TestResult {
    let mut old = attempt(FixtureFamily::Positive, ExecutionMode::Local)?;
    old.schema = artifact(PROVIDER_1_0_0_SCHEMA.to_vec());
    old.payload = artifact(PROVIDER_1_0_0_PAYLOAD.to_vec());
    assert_eq!(run_attempt(&old)?, Err(AdapterRunErrorV1::NotExecuted));
    let mut stream = Vec::new();
    write_attempt(&mut stream, &old)?;
    let (code, stdout) = spawn(&stream)?;
    assert_eq!(code, Some(3), "not executed");
    assert!(stdout.is_empty(), "no EAO1 stream");

    // The 2.0.0 schema member with the 1.0.0 payload is outside the grammar.
    let mut old_payload = attempt(FixtureFamily::Positive, ExecutionMode::Local)?;
    old_payload.payload = artifact(PROVIDER_1_0_0_PAYLOAD.to_vec());
    let observation = observe(&old_payload)?;
    assert_eq!(observation.result, failure(PAYLOAD_INVALID));
    assert_eq!(observation.usage, ResourceUsage::default());
    assert_eq!(SCHEMA_ID, "pigloros.metric-conformance.case.v2");
    Ok(())
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
    foreign.claim_layer = ClaimLayer::ReplayConformance;
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
fn an_attempt_without_its_composite_or_schema_member_is_not_executed() -> TestResult {
    let base = attempt(FixtureFamily::Positive, ExecutionMode::Local)?;
    let first = b"first".as_slice();
    let second = b"second".as_slice();
    let mut descending = [first, second];
    descending.sort_by_key(|member| std::cmp::Reverse(*blake3::hash(member).as_bytes()));
    let candidates = [
        Vec::new(),
        vec![artifact(b"{}".to_vec())],
        vec![artifact(vec![0xff])],
        vec![artifact(encode(&Cbor::Array(vec![
            Cbor::Text("MCS1".to_owned()),
            Cbor::Integer(1_u8.into()),
        ]))?)],
        vec![artifact(composite("MCS2", 1, sorted_entries(&[first]))?)],
        vec![artifact(composite("MCS1", 2, sorted_entries(&[first]))?)],
        vec![artifact(composite(
            "MCS1",
            1,
            vec![Cbor::Bytes(first.to_vec())],
        )?)],
        vec![artifact(composite(
            "MCS1",
            1,
            vec![Cbor::Array(vec![
                Cbor::Text("digest".to_owned()),
                Cbor::Bytes(first.to_vec()),
            ])],
        )?)],
        vec![artifact(composite(
            "MCS1",
            1,
            vec![Cbor::Array(vec![
                Cbor::Bytes(vec![0; 32]),
                Cbor::Bytes(first.to_vec()),
            ])],
        )?)],
        vec![artifact(composite(
            "MCS1",
            1,
            descending.into_iter().map(entry).collect(),
        )?)],
        vec![artifact(composite(
            "MCS1",
            1,
            vec![entry(first), entry(first)],
        )?)],
    ];
    for auxiliary in candidates {
        let mut attempt = base.clone();
        attempt.auxiliary = auxiliary;
        assert_eq!(run_attempt(&attempt)?, Err(AdapterRunErrorV1::NotExecuted));
    }
    // The schema member of another family is not the pinned one.
    let mut foreign_schema = base;
    foreign_schema.schema = artifact(read(
        "providers/metric-conformance/schemas/denied.schema.json",
    )?);
    assert_eq!(
        run_attempt(&foreign_schema)?,
        Err(AdapterRunErrorV1::NotExecuted)
    );
    Ok(())
}

#[test]
fn a_payload_outside_the_grammar_is_payload_invalid() -> TestResult {
    let positive = attempt(FixtureFamily::Positive, ExecutionMode::Local)?;
    let invalid: [fn(&mut Value); 13] = [
        |payload: &mut Value| payload["schema"] = json!("pigloros.metric-conformance.case.v1"),
        |payload: &mut Value| payload["family"] = json!("denied"),
        |payload: &mut Value| payload["algorithm"]["id"] = json!("pigloros.metric.other"),
        |payload: &mut Value| payload["algorithm"]["major"] = json!(2),
        |payload: &mut Value| payload["subcases"] = json!([]),
        |payload: &mut Value| {
            let first = payload["subcases"][0].clone();
            payload["subcases"] = Value::Array(vec![first; 65]);
        },
        |payload: &mut Value| payload["unknown"] = json!(true),
        |payload: &mut Value| payload["subcases"][0]["unknown"] = json!(true),
        |payload: &mut Value| payload["subcases"][0]["member"]["blake3"] = json!("zz".repeat(32)),
        |payload: &mut Value| payload["subcases"][0]["member"]["blake3"] = json!("00".repeat(32)),
        |payload: &mut Value| payload["subcases"][0]["member"]["bytes"] = json!(129),
        |payload: &mut Value| payload["subcases"][0]["expect"]["kind"] = json!("unknown"),
        |payload: &mut Value| payload["subcases"][0]["stimulus"] = json!({"kind": "unknown"}),
    ];
    let mut attempts = invalid
        .into_iter()
        .map(|rewrite| with_payload(positive.clone(), rewrite))
        .collect::<TestResult<Vec<CaseAttempt>>>()?;
    let downgrade = attempt(FixtureFamily::Downgrade, ExecutionMode::Local)?;
    let contracts: [fn(&mut Value); 3] = [
        |payload: &mut Value| {
            payload["subcases"][1]["stimulus"]["required"]["contract_version"] = json!("1.0.0");
        },
        |payload: &mut Value| {
            payload["subcases"][1]["stimulus"]["required"]["provider_id"] = json!("other");
        },
        |payload: &mut Value| payload["subcases"][1]["stimulus"]["allow_fallback"] = json!(true),
    ];
    for rewrite in contracts {
        attempts.push(with_payload(downgrade.clone(), rewrite)?);
    }
    attempts.push(with_payload(
        attempt(FixtureFamily::ResourceExhaustion, ExecutionMode::Local)?,
        |payload| payload["subcases"][1]["stimulus"]["ceiling_bytes"] = json!(MEMBER_CEILING + 1),
    )?);
    attempts.push(CaseAttempt {
        payload: artifact(b"not JSON".to_vec()),
        ..positive
    });
    for attempt in attempts {
        let observation = observe(&attempt)?;
        assert_eq!(observation.result, failure(PAYLOAD_INVALID));
        assert_eq!(observation.usage, ResourceUsage::default());
    }
    Ok(())
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn member_json(record: &str, member: &[u8]) -> Value {
    json!({
        "record": record,
        "blake3": blake3::hash(member).to_hex().to_string(),
        "bytes": member.len(),
    })
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn gate_subcase(id: &str, member: &Value, stimulus: &Value) -> Value {
    json!({
        "id": id,
        "title": "a gate",
        "member": member,
        "expect": {"kind": "denied", "code_id": "capability-denied", "output": null},
        "stimulus": stimulus,
    })
}

/// One sub-case per outcome the subject can observe: the gates (`g.1` to `g.9`), the
/// sub-cases it does not decide (`g.10`, `g.11`), results and a refused `MTQ1` (`g.12`).
#[cfg_attr(coverage_nightly, coverage(off))]
fn outcome_subcases(budget: u64, pos1: &[u8], empty_patterns: &[u8]) -> TestResult<Vec<Value>> {
    let input = member_json("MTI1", pos1);
    let contract = |version: &str| {
        json!({
            "kind": "provider-contract",
            "presented": {"provider_id": PROVIDER_ID, "contract_version": version},
            "required": {"provider_id": PROVIDER_ID, "contract_version": CONTRACT_VERSION},
            "allow_fallback": false,
        })
    };
    let oversized = |bytes: u64| {
        json!({"kind": "oversized-member", "record": "MTI1", "bytes": bytes,
               "ceiling_bytes": MEMBER_CEILING, "fill": "zero"})
    };
    let steps = |requested: u64| {
        json!({"kind": "execution-steps",
                                  "maximum": budget, "requested": requested})
    };
    Ok(vec![
        subcase(FixtureFamily::Positive, "pos.1")?,
        gate_subcase(
            "g.1",
            &input,
            &json!({"kind": "capability-request", "capability": "mutate-subject"}),
        ),
        gate_subcase(
            "g.2",
            &input,
            &json!({"kind": "capability-request", "capability": CAPABILITY_ID}),
        ),
        gate_subcase(
            "g.3",
            &input,
            &json!({"kind": "network-request", "execution_profile": "deterministic-air-gapped-v1"}),
        ),
        gate_subcase("g.4", &input, &steps(budget + 1)),
        gate_subcase("g.5", &input, &steps(budget)),
        gate_subcase("g.6", &Value::Null, &contract("1.0.0")),
        gate_subcase("g.7", &Value::Null, &contract(CONTRACT_VERSION)),
        gate_subcase("g.8", &Value::Null, &oversized(1)),
        gate_subcase("g.9", &Value::Null, &oversized(MEMBER_CEILING + 1)),
        json!({"id": "g.10", "title": "a check", "member": null,
               "expect": {"kind": "generator-check"}}),
        json!({"id": "g.11", "title": "a foreign result", "member": input,
               "expect": {"kind": "result-rejected", "code": 2, "error": "UnsupportedAlgorithm",
                          "first_coordinate": "algorithm_major"}}),
        subcase(FixtureFamily::Positive, "pos.7")?,
        gate_subcase(
            "g.12",
            &member_json("MTQ1", empty_patterns),
            &json!({"kind": "recompute", "families": ["positive"]}),
        ),
    ])
}

#[test]
fn a_canonical_output_records_every_outcome_the_subject_observes() -> TestResult {
    let base = attempt(FixtureFamily::Positive, ExecutionMode::Local)?;
    let budget = base.budget.execution_steps;
    let pos1 = member_of(FixtureFamily::Positive, "pos.1")?;
    let pos7 = member_of(FixtureFamily::Positive, "pos.7")?;
    let empty_patterns = encode(&Cbor::Array(vec![
        Cbor::Text("MTQ1".to_owned()),
        Cbor::Integer(1_u8.into()),
        Cbor::Array(Vec::new()),
    ]))?;
    let subcases = outcome_subcases(budget, &pos1, &empty_patterns)?;
    let mut attempt = with_payload(base, |payload| payload["subcases"] = Value::Array(subcases))?;
    attempt.auxiliary = vec![artifact(composite(
        "MCS1",
        1,
        sorted_entries(&[pos1.as_slice(), pos7.as_slice(), empty_patterns.as_slice()]),
    )?)];
    let observation = observe(&attempt)?;
    // pos.1, g.2, g.5, g.8 (accepted by the transport), pos.7 and g.12 are decoded.
    assert_eq!(observation.usage.execution_steps, 6);
    let output = output_json(&observation)?;
    let entries = output["output"]["subcases"]
        .as_array()
        .ok_or("no entries")?;
    let kinds: Vec<&str> = entries
        .iter()
        .map(|entry| {
            entry["kind"]
                .as_str()
                .or_else(|| entry["record"].as_str())
                .unwrap_or_default()
        })
        .collect();
    assert_eq!(
        kinds,
        [
            "MTR1",
            "denied",
            "MTR1",
            "denied",
            "resource-limit",
            "MTR1",
            "incompatible-contract",
            "no-input",
            "metric-error",
            "transport-rejection",
            "generator-check",
            "result-rejected",
            "MQR1",
            "metric-error",
        ]
    );
    assert_eq!(entries[0], oracle_entry(FixtureFamily::Positive, "pos.1")?);
    assert_eq!(entries[12], oracle_entry(FixtureFamily::Positive, "pos.7")?);
    assert_eq!(entries[8]["error"], "InvalidEncoding");
    assert_eq!(entries[9]["error"], "FieldOutOfBounds");
    assert_eq!(
        entries[13],
        json!({"code": 0, "error": "InvalidEncoding", "first_coordinate": "patterns",
               "id": "g.12", "kind": "metric-error"})
    );
    Ok(())
}
