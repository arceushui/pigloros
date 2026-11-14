#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Public-interface tests of the gateway-client-conformance subject adapter (provider contract
//! 2.0.0, #1295).
//!
//! The attempts are built from the checked-in files of `fixtures/conformance` the way the
//! evaluator delivers them (the schema member, the payload, then the evidence-status record and
//! the namespaced-failure oracle when the family has one), with the provider's budget, watchdog
//! and capabilities, and are crossed through the pos-reference EAI1/EAO1 codec. A
//! `canonical-output` family must output the exact oracle bytes and a `namespaced-failure`
//! family must return the oracle's failure. The oracles are written by the offline generator
//! (`scripts/generate_gateway_conformance_fixtures.py`) from the documented route table; the
//! Gateway is never asked for an expected result.

use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use pos_gateway_conformance_adapter::{
    executor_declaration, exit_code, normalize_response_v1, observation_v1, run, AdapterRunErrorV1,
    ABI_MAJOR, ABI_MINOR, CAPABILITY_IDS, CONTRACT_VERSION, PAYLOAD_INVALID, PROVIDER_ID,
    SCHEMA_ID, SUBCASE_MISMATCH,
};
use pos_reference::adapter_transport::{read_observation, write_attempt};
use pos_reference::evaluator::{
    AttemptArtifact, AttemptTransportCaps, CaseAttempt, ResourceUsage, SubjectObservation,
    SubjectResult,
};
use pos_reference::evaluator_domain::{ClaimLayer, ExecutionMode, FixtureFamily};
use pos_reference::evaluator_protocol::SubjectAdapterKind;
use pos_reference::profile::{DeterministicBudget, NamespacedFailure};
use serde_json::{json, Value};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const BINARY: &str = env!("CARGO_BIN_EXE_pos-gateway-conformance-adapter");
const LAYER: &str = "gateway-client-conformance";
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
const MODES: [ExecutionMode; 2] = [ExecutionMode::Local, ExecutionMode::AirGapped];

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
    read(&format!("oracles/{LAYER}/{}.json", family_name(family)))
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn family_contract(family: FixtureFamily) -> TestResult<Value> {
    let provider: Value =
        serde_json::from_slice(&read(&format!("providers/{LAYER}/provider.json"))?)?;
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
    let payload = read(&format!("inputs/{LAYER}/{name}.json"))?;
    let schema = read(&format!("providers/{LAYER}/schemas/{name}.schema.json"))?;
    let evidence = read(&format!("expected/{LAYER}/{name}.json"))?;
    let oracle = oracle(family)?;
    let kind = serde_json::from_slice::<Value>(&oracle)?["oracle"]["kind"].clone();
    let mut auxiliary = vec![artifact(evidence)];
    if kind == "namespaced-failure" {
        auxiliary.push(artifact(oracle));
    }
    let contract = family_contract(family)?;
    let capability_ids = contract["minimum_capability_ids"]
        .as_array()
        .ok_or("no capabilities")?
        .iter()
        .map(|capability| capability.as_str().map(str::to_owned))
        .collect::<Option<Vec<String>>>()
        .ok_or("a capability is not text")?;
    Ok(CaseAttempt {
        case_id: format!("{LAYER}-{name}"),
        claim_layer: ClaimLayer::GatewayClientConformance,
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

/// One attempt through the library and the EAI1/EAO1 codec.
#[cfg_attr(coverage_nightly, coverage(off))]
fn observe(attempt: &CaseAttempt) -> TestResult<Result<SubjectObservation, AdapterRunErrorV1>> {
    let mut stream = Vec::new();
    write_attempt(&mut stream, attempt)?;
    let mut out = Vec::new();
    Ok(match run(stream.as_slice(), &mut out) {
        Ok(()) => Ok(read_observation(out.as_slice(), OUTPUT_LIMIT)?),
        Err(error) => Err(error),
    })
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn observation(attempt: &CaseAttempt) -> TestResult<SubjectObservation> {
    Ok(observe(attempt)?.map_err(|error| format!("not executed: {error}"))?)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn failure(code: &str) -> SubjectResult {
    SubjectResult::Failure(NamespacedFailure {
        owner_id: PROVIDER_ID.to_owned(),
        contract_version: CONTRACT_VERSION.to_owned(),
        code_id: code.to_owned(),
    })
}

/// The sent exchanges and committed Events the requirements text meters for `attempt`.
#[cfg_attr(coverage_nightly, coverage(off))]
fn wanted_steps_and_events(attempt: &CaseAttempt) -> TestResult<(u64, u64)> {
    let payload: Value = serde_json::from_slice(&attempt.payload.bytes)?;
    let (mut steps, mut events) = (0, 0);
    for subcase in payload["subcases"].as_array().ok_or("no sub-cases")? {
        for exchange in subcase["exchanges"].as_array().ok_or("no exchanges")? {
            if exchange["expect"].get("refused").is_some() {
                continue;
            }
            steps += 1;
            let path = exchange["path"].as_str().ok_or("no path")?;
            let commits = path.ends_with("/signals") || path.ends_with("/actions");
            if commits && exchange["expect"]["status"] == json!(201) {
                events += 1;
            }
        }
    }
    Ok((steps, events))
}

#[test]
fn every_family_meets_its_oracle_identically_in_local_and_air_gapped() -> TestResult {
    for family in FAMILIES {
        let mut observed = Vec::new();
        for mode in MODES {
            let attempt = attempt(family, mode)?;
            let result = observation(&attempt)?;
            let oracle_bytes = oracle(family)?;
            let oracle: Value = serde_json::from_slice(&oracle_bytes)?;
            let wanted = oracle["oracle"]["code_id"]
                .as_str()
                .map_or(SubjectResult::Output(oracle_bytes), failure);
            assert_eq!(result.result, wanted, "{family:?} {mode:?}");
            let (steps, events) = wanted_steps_and_events(&attempt)?;
            let usage = result.usage;
            assert_eq!(usage.execution_steps, steps, "{family:?} steps");
            assert_eq!(usage.event_count, events, "{family:?} events");
            assert!(usage.output_bytes > 0, "{family:?} output bytes");
            assert!(
                usage.output_bytes <= attempt.budget.output_bytes,
                "{family:?}"
            );
            assert!(
                usage.execution_steps <= attempt.budget.execution_steps,
                "{family:?}"
            );
            assert!(
                usage.event_count <= attempt.budget.event_count,
                "{family:?}"
            );
            assert_eq!(
                ResourceUsage {
                    execution_steps: 0,
                    output_bytes: 0,
                    event_count: 0,
                    ..usage
                },
                ResourceUsage::default(),
                "{family:?}: the other counters are 0"
            );
            observed.push(result);
        }
        assert_eq!(observed[0], observed[1], "{family:?}: Local = Air-Gapped");
    }
    Ok(())
}

#[test]
fn other_claim_layers_and_replay_or_fork_modes_are_unavailable() -> TestResult {
    let mut other_layer = attempt(FixtureFamily::Positive, ExecutionMode::Local)?;
    other_layer.claim_layer = ClaimLayer::PluginConformance;
    let unavailable = SubjectObservation {
        result: SubjectResult::Unavailable,
        usage: ResourceUsage::default(),
    };
    assert_eq!(observation(&other_layer)?, unavailable);
    for mode in [ExecutionMode::Replay, ExecutionMode::Fork] {
        let attempt = attempt(FixtureFamily::Positive, mode)?;
        assert_eq!(observation(&attempt)?, unavailable, "{mode:?}");
    }
    Ok(())
}

#[test]
fn a_schema_member_other_than_the_pinned_one_is_not_executed() -> TestResult {
    let mut foreign = attempt(FixtureFamily::Positive, ExecutionMode::Local)?;
    foreign.schema = artifact(read(&format!(
        "providers/{LAYER}/schemas/denied.schema.json"
    ))?);
    assert_eq!(observe(&foreign)?, Err(AdapterRunErrorV1::NotExecuted));
    Ok(())
}

/// Rewrite the first exchange of the first sub-case.
#[cfg_attr(coverage_nightly, coverage(off))]
fn first_exchange(payload: &mut Value) -> &mut Value {
    &mut payload["subcases"][0]["exchanges"][0]
}

/// One payload rewrite that leaves the grammar.
type Rewrite = (&'static str, fn(&mut Value));

#[cfg_attr(coverage_nightly, coverage(off))]
const fn case(label: &'static str, rewrite: fn(&mut Value)) -> Rewrite {
    (label, rewrite)
}

/// The payload rewrites that leave the grammar, one bound or rule each.
#[cfg_attr(coverage_nightly, coverage(off))]
fn grammar_violations() -> Vec<Rewrite> {
    vec![
        case("not an object", |p| *p = json!([])),
        case("unknown member", |p| p["extra"] = json!(1)),
        case("schema", |p| {
            p["schema"] = json!("pigloros.gateway-client-conformance.case.v1");
        }),
        case("family", |p| p["family"] = json!("denied")),
        case("no sub-case", |p| p["subcases"] = json!([])),
        case("65 sub-cases", |p| {
            let one = p["subcases"][0].clone();
            p["subcases"] = Value::Array(vec![one; 65]);
        }),
        case("foreign prefix", |p| {
            p["subcases"][0]["id"] = json!("den.1");
        }),
        case("no number", |p| p["subcases"][0]["id"] = json!("pos.")),
        case("letter number", |p| {
            p["subcases"][0]["id"] = json!("pos.1a");
        }),
        case("no separator", |p| p["subcases"][0]["id"] = json!("pos1")),
        case("empty title", |p| p["subcases"][0]["title"] = json!("")),
        case("control title", |p| {
            p["subcases"][0]["title"] = json!("a\tb");
        }),
        case("long title", |p| {
            p["subcases"][0]["title"] = json!("t".repeat(161));
        }),
        case("empty canary", |p| p["subcases"][0]["canary"] = json!("")),
        case("spaced canary", |p| {
            p["subcases"][0]["canary"] = json!("a b");
        }),
        case("long canary", |p| {
            p["subcases"][0]["canary"] = json!("c".repeat(65));
        }),
        case("composition", |p| {
            p["subcases"][0]["composition"] = json!("sandboxed");
        }),
        case("no exchange", |p| p["subcases"][0]["exchanges"] = json!([])),
        case("129 exchanges", |p| {
            let one = first_exchange(p).clone();
            p["subcases"][0]["exchanges"] = Value::Array(vec![one; 129]);
        }),
        case("router", |p| first_exchange(p)["router"] = json!("public")),
        case("method", |p| first_exchange(p)["method"] = json!("PUT")),
        case("capture", |p| first_exchange(p)["capture"] = json!("event")),
        case("actor false", |p| first_exchange(p)["actor"] = json!(false)),
        case("exchange member", |p| {
            first_exchange(p)["headers"] = json!({});
        }),
        case("unknown route", |p| {
            first_exchange(p)["path"] = json!("/v2/health");
        }),
        case("relative path", |p| {
            first_exchange(p)["path"] = json!("health");
        }),
        case("no Timeline", |p| {
            first_exchange(p)["path"] = json!("/v1/timelines//events");
        }),
        case("no tail", |p| {
            first_exchange(p)["path"] = json!("/v1/timelines/t");
        }),
        case("unknown tail", |p| {
            first_exchange(p)["path"] = json!("/v1/timelines/t/forks");
        }),
        case("spaced path", |p| {
            first_exchange(p)["path"] = json!("/v1/timelines/a b/events");
        }),
        case("long path", |p| {
            first_exchange(p)["path"] = json!(format!("/v1/timelines/{}/events", "a".repeat(250)));
        }),
        case("slot before capture", |p| {
            first_exchange(p)["path"] = json!("/v1/timelines/{timeline}/events");
        }),
    ]
}

#[test]
fn payloads_outside_the_grammar_are_payload_invalid() -> TestResult {
    let base = attempt(FixtureFamily::Positive, ExecutionMode::Local)?;
    let invalid = SubjectObservation {
        result: failure(PAYLOAD_INVALID),
        usage: ResourceUsage::default(),
    };
    let mut not_json = base.clone();
    not_json.payload = artifact(b"{".to_vec());
    assert_eq!(observation(&not_json)?, invalid, "not JSON");
    for (label, rewrite) in grammar_violations() {
        let attempt = with_payload(base.clone(), rewrite)?;
        assert_eq!(observation(&attempt)?, invalid, "{label}");
    }
    Ok(())
}

#[test]
fn payloads_at_the_grammar_bounds_are_executed() -> TestResult {
    let base = attempt(FixtureFamily::Positive, ExecutionMode::Local)?;
    let at_bounds = with_payload(base, |p| {
        let exchange = json!({
            "router": "loopback", "method": "GET", "path": "/health", "actor": true,
            "expect": {"status": 200, "body": {"json": {"ok": true}}},
        });
        let subcase = json!({
            "id": "pos.70",
            "title": "t".repeat(160),
            "composition": "open",
            "canary": "c".repeat(64),
            "exchanges": vec![exchange; 128],
        });
        p["subcases"] = Value::Array(vec![subcase; 2]);
    })?;
    let executed = observation(&at_bounds)?;
    assert_eq!(executed.usage.execution_steps, 256);
    let SubjectResult::Output(bytes) = executed.result else {
        return Err("no output".into());
    };
    let record: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(
        record["output"]["subcases"][1]["prohibited_data_present"],
        json!(false)
    );
    Ok(())
}

#[test]
fn a_mismatched_exchange_or_a_present_canary_is_a_subcase_mismatch() -> TestResult {
    let base = attempt(FixtureFamily::Denied, ExecutionMode::Local)?;
    let mismatch = with_payload(base.clone(), |p| {
        p["subcases"][0]["exchanges"][1]["expect"]["status"] = json!(402);
    })?;
    assert_eq!(observation(&mismatch)?.result, failure(SUBCASE_MISMATCH));
    // A refused route is a mismatch when the exchange expected a response.
    let mut refused = base.clone();
    refused.capability_ids.retain(|id| id != "timeline.create");
    assert_eq!(observation(&refused)?.result, failure(SUBCASE_MISMATCH));
    // Every exchange matches, but the canary occurs in a spectator response.
    let mut canary = with_payload(base, |p| {
        p["subcases"] = json!([{
            "id": "den.9",
            "title": "a spectator response that carries the canary",
            "composition": "open",
            "canary": "piglor.com",
            "exchanges": [{
                "router": "spectator", "method": "GET", "path": "/v1/ledger",
                "expect": {"status": 200, "body": {"json": {
                    "domain": "piglor.com", "ledger": [], "path": "/ledger",
                }}},
            }],
        }]);
    })?;
    canary.capability_ids.push("gateway.ledger.read".to_owned());
    canary.capability_ids.sort();
    assert_eq!(observation(&canary)?.result, failure(SUBCASE_MISMATCH));
    Ok(())
}

#[test]
fn a_canonical_record_reports_a_present_canary_and_differs_from_the_oracle() -> TestResult {
    let base = attempt(FixtureFamily::DeletionRedaction, ExecutionMode::Local)?;
    let canary = with_payload(base, |p| p["subcases"][0]["canary"] = json!("piglor.com"))?;
    let SubjectResult::Output(bytes) = observation(&canary)?.result else {
        return Err("no output".into());
    };
    let record: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(
        record["output"]["subcases"][0]["prohibited_data_present"],
        json!(true)
    );
    assert_ne!(bytes, oracle(FixtureFamily::DeletionRedaction)?);
    Ok(())
}

#[test]
fn normalization_replaces_only_well_formed_ids_cursors_and_messages() {
    let ulid = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    let generation = "0123456789abcdef".repeat(4);
    let cursor = |timeline: &str, position: &str| format!("v1.{generation}.{timeline}.{position}");
    let kept = [
        "01ARZ3NDEKTSV4RRFFQ69G5FA",
        "01ARZ3NDEKTSV4RRFFQ69G5FAVX",
        "81ARZ3NDEKTSV4RRFFQ69G5FAV",
        "01ARZ3NDEKTSV4RRFFQ69G5FAI",
        "01arz3ndektsv4rrffq69g5fav",
    ];
    for id in kept {
        let value = json!({"id": id});
        assert_eq!(normalize_response_v1(value.clone()), value, "{id}");
    }
    assert_eq!(
        normalize_response_v1(json!({"id": "7ZZZZZZZZZZZZZZZZZZZZZZZZZ"})),
        json!({"id": "<ulid>"})
    );
    let short = format!("v1.{}.{ulid}.1", &generation[1..]);
    let upper = format!("v1.{}.{ulid}.1", generation.to_uppercase());
    let foreign = format!("v2.{generation}.{ulid}.1");
    let extra = format!("{}.1", cursor(ulid, "1"));
    for text in [
        cursor(ulid, "0"),
        cursor(ulid, "01"),
        cursor(ulid, ""),
        cursor(ulid, "1x"),
        cursor("not-a-ulid", "1"),
        short,
        upper,
        foreign,
        extra,
    ] {
        let value = json!({"next_cursor": text});
        assert_eq!(normalize_response_v1(value.clone()), value, "{text}");
    }
    assert_eq!(
        normalize_response_v1(json!({
            "events": [{"id": ulid, "entity": ulid, "seq": 1, "ok": true, "none": null}],
            "next_cursor": cursor(ulid, "10"),
            "detail": "anything",
            "instance": format!("/v1/timelines/{ulid}/not-a-ulid/events"),
            "error": "kept",
            "name": ulid,
        })),
        json!({
            "events": [{"id": "<ulid>", "entity": ulid, "seq": 1, "ok": true, "none": null}],
            "next_cursor": "<cursor>",
            "detail": "<message>",
            "instance": "/v1/timelines/<ulid>/not-a-ulid/events",
            "error": "kept",
            "name": ulid,
        })
    );
}

#[test]
fn the_executor_declaration_names_the_exact_provider_and_every_route_capability() {
    let declaration = executor_declaration([7; 32]);
    assert_eq!(declaration.provider.provider_id, PROVIDER_ID);
    assert_eq!(declaration.provider.contract_version, "2.0.0");
    assert_eq!(
        (
            declaration.provider.abi_major,
            declaration.provider.abi_minor
        ),
        (ABI_MAJOR, ABI_MINOR)
    );
    assert_eq!((ABI_MAJOR, ABI_MINOR), (1, 0));
    assert_eq!(
        declaration.subject_adapter,
        SubjectAdapterKind::PublicGatewayProtocol
    );
    assert_eq!(declaration.implementation_digest, [7; 32]);
    assert_eq!(
        declaration.capability_ids,
        CAPABILITY_IDS.map(str::to_owned).to_vec()
    );
    for family in FAMILIES {
        let schema = read(&format!(
            "providers/{LAYER}/schemas/{}.schema.json",
            family_name(family)
        ))
        .unwrap_or_default();
        assert_eq!(
            declaration.schema_digests[usize::from(family.code())],
            *blake3::hash(&schema).as_bytes(),
            "{family:?}"
        );
        assert!(String::from_utf8_lossy(&schema).contains(SCHEMA_ID));
    }
}

/// A writer whose every write fails.
struct Closed;

impl Write for Closed {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("closed"))
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("closed"))
    }
}

#[test]
fn wire_and_output_faults_have_their_exit_codes() -> TestResult {
    assert_eq!(
        run(b"not EAI1".as_slice(), Vec::new()),
        Err(AdapterRunErrorV1::Wire)
    );
    let mut stream = Vec::new();
    write_attempt(
        &mut stream,
        &attempt(FixtureFamily::Positive, ExecutionMode::Local)?,
    )?;
    assert_eq!(
        run(stream.as_slice(), Closed),
        Err(AdapterRunErrorV1::Output)
    );
    let codes = [
        AdapterRunErrorV1::Wire,
        AdapterRunErrorV1::NotExecuted,
        AdapterRunErrorV1::Output,
    ]
    .map(AdapterRunErrorV1::code);
    assert_eq!(codes, [2, 3, 4]);
    assert_eq!(
        format!("{:?}", exit_code(Ok(()))),
        format!("{:?}", std::process::ExitCode::SUCCESS)
    );
    assert_eq!(
        format!("{:?}", exit_code(Err(AdapterRunErrorV1::Output))),
        format!("{:?}", std::process::ExitCode::from(4))
    );
    Ok(())
}

/// Run the binary with `input` on its standard input.
#[cfg_attr(coverage_nightly, coverage(off))]
fn spawn(input: &[u8]) -> TestResult<std::process::Output> {
    let mut child = Command::new(BINARY)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    child.stdin.take().ok_or("no stdin")?.write_all(input)?;
    Ok(child.wait_with_output()?)
}

#[test]
fn the_binary_runs_one_attempt_through_its_process_boundary() -> TestResult {
    let mut stream = Vec::new();
    write_attempt(
        &mut stream,
        &attempt(FixtureFamily::Positive, ExecutionMode::AirGapped)?,
    )?;
    let output = spawn(&stream)?;
    assert!(output.status.success());
    let observed = read_observation(output.stdout.as_slice(), OUTPUT_LIMIT)?;
    assert_eq!(
        observed.result,
        SubjectResult::Output(oracle(FixtureFamily::Positive)?)
    );
    let wire = spawn(b"not EAI1")?;
    assert_eq!(wire.status.code(), Some(2));
    assert!(wire.stdout.is_empty());
    let mut foreign = attempt(FixtureFamily::Positive, ExecutionMode::Local)?;
    foreign.schema = artifact(b"{}".to_vec());
    let mut stream = Vec::new();
    write_attempt(&mut stream, &foreign)?;
    assert_eq!(spawn(&stream)?.status.code(), Some(3));
    Ok(())
}

#[test]
fn an_observation_is_the_status_and_the_normalized_json_or_non_json_body() {
    assert_eq!(
        observation_v1(404, None),
        json!({"status": 404, "body": "non-json"})
    );
    assert_eq!(
        observation_v1(
            400,
            Some(json!({"detail": "bad", "code": "invalid-request"}))
        ),
        json!({"status": 400, "body": {"json": {"detail": "<message>", "code": "invalid-request"}}})
    );
}
