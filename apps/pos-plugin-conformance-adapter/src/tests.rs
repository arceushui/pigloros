//! R8-A1, R8-A8 and R8-A15: the case driver, with a fake sub-case runner.

use pos_reference::evaluator::{ResourceUsage, SubjectResult};
use pos_reference::evaluator_domain::{ClaimLayer, ExecutionMode, FixtureFamily};
use pos_reference::profile::NamespacedFailure;
use serde_json::json;

use crate::test_support::{
    anchor_bytes, artifact, attempt, blake3_subcase, composite, composite_of, digest, hex_of,
    matched, observation, payload, sorted, stream, FakeRunner, TestResult,
};
use super::*;
use crate::payload::family_text;

fn full(id: &str) -> SubCaseRecordV1 {
    SubCaseRecordV1 {
        committed: Some([1; 32]),
        computed: Some([2; 32]),
        scan: Some(ScanResultV1 {
            found: Vec::new(),
            retained_ok: true,
            observed_plugin_id: "p".to_owned(),
            observed_invocation_id_hex: "ab".to_owned(),
        }),
        ..matched(id)
    }
}

fn failure(code: &str) -> SubjectResult {
    SubjectResult::Failure(NamespacedFailure {
        owner_id: PROVIDER_ID.to_owned(),
        contract_version: CONTRACT_VERSION.to_owned(),
        code_id: code.to_owned(),
    })
}

fn two_subcases(family: FixtureFamily) -> Vec<u8> {
    let subcases = vec![blake3_subcase("ind.1", "a"), blake3_subcase("ind.2a", "b")];
    payload(family_text(family), subcases).to_string().into_bytes()
}

/// Run the EAI1 stream of `attempt` through a fake runner that matches every sub-case.
fn run_matching(
    attempt: &CaseAttempt,
) -> Result<(Result<(), AdapterRunErrorV1>, Vec<u8>, usize), Box<dyn std::error::Error>> {
    let runner = FakeRunner::new(|subcase| full(subcase.id.as_str()));
    let mut out = Vec::new();
    let result = run_with(&runner, stream(attempt)?.as_slice(), &mut out);
    Ok((result, out, runner.calls().len()))
}

#[test]
fn one_eai1_stream_gives_one_eao1_stream_for_each_family() -> TestResult {
    let expected_failure = [
        (FixtureFamily::Denied, "capability-denied"),
        (FixtureFamily::Malformed, "malformed-payload"),
        (FixtureFamily::ResourceExhaustion, "resource-limit"),
        (FixtureFamily::Downgrade, "incompatible-contract"),
    ];
    for family in FixtureFamily::ALL {
        let bytes = two_subcases(*family);
        let case = attempt(*family, ExecutionMode::Local, bytes, vec![composite(&[])?]);
        let (result, out, calls) = run_matching(&case)?;
        assert_eq!(result, Ok(()), "{family:?}");
        assert_eq!(calls, 2, "{family:?}");
        let seen = observation(&out)?;
        let code = expected_failure.iter().find(|(f, _)| f == family);
        let expected = match code {
            Some((_, code)) => failure(code),
            None => SubjectResult::Output(map::record_bytes(
                "case-1",
                *family,
                &[full("ind.1"), full("ind.2a")],
            )),
        };
        assert_eq!(seen.result, expected, "{family:?}");
        assert_eq!(seen.usage, ResourceUsage::default());
    }
    Ok(())
}

#[test]
fn a_wire_fault_gives_no_stream_and_a_non_zero_exit() -> TestResult {
    let case = attempt(
        FixtureFamily::Positive,
        ExecutionMode::Local,
        two_subcases(FixtureFamily::Positive),
        vec![composite(&[])?],
    );
    let whole = stream(&case)?;
    let runner = FakeRunner::new(|subcase| full(subcase.id.as_str()));
    for bytes in [&whole[..whole.len() - 1], &whole[..10], &[][..], b"garbage"] {
        let mut out = Vec::new();
        let result = run_with(&runner, bytes, &mut out);
        assert_eq!(result, Err(AdapterRunErrorV1::Wire));
        assert!(out.is_empty());
    }
    let mut trailing = whole;
    trailing.push(0);
    let result = run_with(&runner, trailing.as_slice(), Vec::new());
    assert_eq!(result, Err(AdapterRunErrorV1::Wire));
    assert!(runner.calls().is_empty());
    Ok(())
}

#[test]
fn a_foreign_layer_or_a_replay_or_fork_attempt_is_unavailable_with_zero_usage() -> TestResult {
    let mut attempts = Vec::new();
    for layer in [ClaimLayer::ArtifactIntegrity, ClaimLayer::GatewayClientConformance] {
        let mut case = attempt(
            FixtureFamily::Positive,
            ExecutionMode::Local,
            two_subcases(FixtureFamily::Positive),
            vec![composite(&[])?],
        );
        case.claim_layer = layer;
        attempts.push(case);
    }
    for mode in [ExecutionMode::Replay, ExecutionMode::Fork] {
        attempts.push(attempt(
            FixtureFamily::Positive,
            mode,
            two_subcases(FixtureFamily::Positive),
            vec![composite(&[])?],
        ));
    }
    for case in attempts {
        let (result, out, calls) = run_matching(&case)?;
        assert_eq!(result, Ok(()));
        assert_eq!(calls, 0, "no sub-case runs");
        let seen = observation(&out)?;
        assert_eq!(seen.result, SubjectResult::Unavailable);
        assert_eq!(seen.usage, ResourceUsage::default());
    }
    Ok(())
}

#[test]
fn a_wrong_schema_string_or_schema_member_is_not_executed() -> TestResult {
    let composite = composite(&[])?;
    let mut wrong_text = payload("positive", vec![blake3_subcase("ind.1", "a")]);
    wrong_text["schema"] = json!("pigloros.plugin-conformance.case.v1");
    let case = attempt(
        FixtureFamily::Positive,
        ExecutionMode::Local,
        wrong_text.to_string().into_bytes(),
        vec![composite.clone()],
    );
    let (result, out, calls) = run_matching(&case)?;
    assert_eq!(result, Err(AdapterRunErrorV1::NotExecuted));
    assert!(out.is_empty());
    assert_eq!(calls, 0);

    let mut wrong_member = attempt(
        FixtureFamily::Positive,
        ExecutionMode::Local,
        two_subcases(FixtureFamily::Positive),
        vec![composite.clone()],
    );
    wrong_member.schema = artifact(b"another schema".to_vec());
    let (result, out, _) = run_matching(&wrong_member)?;
    assert_eq!(result, Err(AdapterRunErrorV1::NotExecuted));
    assert!(out.is_empty());

    let mut other_family = attempt(
        FixtureFamily::Positive,
        ExecutionMode::Local,
        two_subcases(FixtureFamily::Positive),
        vec![composite],
    );
    let denied = schema_digests::placeholder_schema(FixtureFamily::Denied);
    other_family.schema = artifact(denied.to_vec());
    let (result, _, _) = run_matching(&other_family)?;
    assert_eq!(result, Err(AdapterRunErrorV1::NotExecuted));
    Ok(())
}

#[test]
fn a_pinned_schema_payload_that_is_not_json_or_invalid_is_payload_invalid() -> TestResult {
    let mut unknown_key = payload("positive", vec![blake3_subcase("ind.1", "a")]);
    unknown_key["extra"] = json!(1);
    let payloads = [
        b"not json".to_vec(),
        b"[]".to_vec(),
        b"{}".to_vec(),
        unknown_key.to_string().into_bytes(),
        payload("denied", vec![blake3_subcase("ind.1", "a")]).to_string().into_bytes(),
        json!({"schema": 5, "family": "positive", "subcases": []}).to_string().into_bytes(),
    ];
    for bytes in payloads {
        let auxiliary = vec![composite(&[])?];
        let case = attempt(FixtureFamily::Positive, ExecutionMode::Local, bytes, auxiliary);
        let (result, out, calls) = run_matching(&case)?;
        assert_eq!(result, Ok(()));
        assert_eq!(calls, 0, "no sub-case runs");
        let seen = observation(&out)?;
        assert_eq!(seen.result, failure("payload-invalid"));
        assert_eq!(seen.usage, ResourceUsage::default());
    }
    Ok(())
}

fn install_subcase(anchor: &[u8]) -> serde_json::Value {
    let release = json!({"manifest": hex_of(b"manifest"), "blobs": [hex_of(b"blob")]});
    let material = json!({
        "anchor": hex_of(anchor),
        "tps1": hex_of(b"tps1"),
        "ptr1": [hex_of(b"ptr1")],
        "prv1": [hex_of(b"prv1")],
    });
    json!({
        "id": "den.19",
        "steps": [{
            "step": "install", "release": release, "material": material,
            "instant_micros": 1, "tick": 1,
        }],
        "expect": {"kind": "failed", "error": "e", "class": "c"},
    })
}

#[test]
fn a_digest_that_names_no_piece_or_an_undecodable_anchor_is_payload_invalid() -> TestResult {
    let anchor = anchor_bytes();
    let blobs: [&[u8]; 5] = [b"manifest", b"blob", b"tps1", b"ptr1", b"prv1"];
    let with = |extra: &[&[u8]]| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        composite(&[&blobs[..], extra].concat())
    };
    // Control: every piece is there and the anchor decodes.
    let ok = payload("positive", vec![install_subcase(&anchor)]);
    let complete = attempt(
        FixtureFamily::Positive,
        ExecutionMode::Local,
        ok.to_string().into_bytes(),
        vec![with(&[&anchor])?],
    );
    let (result, out, calls) = run_matching(&complete)?;
    assert_eq!(result, Ok(()));
    assert_eq!(calls, 1, "the control runs");
    assert!(matches!(observation(&out)?.result, SubjectResult::Output(_)));

    // The anchor piece is missing, the anchor does not decode, a blob is missing.
    let cases = [
        with(&[])?,
        with(&[b"not a PCA1 anchor"])?,
        composite(&[b"manifest", b"tps1", b"ptr1", b"prv1", &anchor])?,
    ];
    for (index, aux) in cases.into_iter().enumerate() {
        let broken = if index == 1 {
            payload("positive", vec![install_subcase(b"not a PCA1 anchor")])
        } else {
            ok.clone()
        };
        let case = attempt(
            FixtureFamily::Positive,
            ExecutionMode::Local,
            broken.to_string().into_bytes(),
            vec![aux],
        );
        let (result, out, calls) = run_matching(&case)?;
        assert_eq!(result, Ok(()), "case {index}");
        assert_eq!(calls, 0, "case {index}: nothing runs");
        let seen = observation(&out)?;
        assert_eq!(seen.result, failure("payload-invalid"), "case {index}");
    }
    Ok(())
}

#[test]
fn composite_faults_are_non_executed_outcomes() -> TestResult {
    let good = composite(&[b"a", b"b"])?;
    let mut descending = sorted(&[b"a", b"b"]);
    descending.reverse();
    let mut trailing = good.clone();
    trailing.push(0);
    let faults: Vec<Vec<Vec<u8>>> = vec![
        // zero composites
        Vec::new(),
        vec![b"evidence".to_vec()],
        vec![vec![0x83, 0x64]],
        // two composites
        vec![good.clone(), composite(&[b"c"])?],
        // a duplicate piece digest
        vec![composite_of(&[(digest(b"a"), b"a"), (digest(b"a"), b"a")])?],
        // a piece whose digest differs from the BLAKE3 of its bytes
        vec![composite_of(&[(digest(b"a"), b"not a")])?],
        // pieces that are not sorted by digest
        vec![composite_of(&descending)?],
        // not canonical CBOR: a trailing byte, an indefinite-length array, a wide integer
        vec![trailing],
        vec![vec![0x83, 0x64, 0x50, 0x43, 0x57, 0x32, 0x01, 0x9f, 0xff]],
        vec![vec![0x83, 0x64, 0x50, 0x43, 0x57, 0x32, 0x18, 0x01, 0x80]],
    ];
    for (index, auxiliary) in faults.into_iter().enumerate() {
        let case = attempt(
            FixtureFamily::Positive,
            ExecutionMode::Local,
            two_subcases(FixtureFamily::Positive),
            auxiliary,
        );
        let (result, out, calls) = run_matching(&case)?;
        assert_eq!(result, Err(AdapterRunErrorV1::NotExecuted), "fault {index}");
        assert!(out.is_empty(), "fault {index}: no EAO1 stream");
        assert_eq!(calls, 0, "fault {index}");
    }
    Ok(())
}

#[test]
fn every_sub_case_runs_in_the_mode_of_the_attempt() -> TestResult {
    for (mode, expected) in [
        (ExecutionMode::Local, CommunityPluginModeV1::Local),
        (ExecutionMode::AirGapped, CommunityPluginModeV1::AirGapped),
    ] {
        let case = attempt(
            FixtureFamily::Positive,
            mode,
            two_subcases(FixtureFamily::Positive),
            vec![composite(&[])?],
        );
        let runner = FakeRunner::new(|subcase| full(subcase.id.as_str()));
        run_with(&runner, stream(&case)?.as_slice(), Vec::new())?;
        assert_eq!(
            runner.calls(),
            vec![("ind.1".to_owned(), expected), ("ind.2a".to_owned(), expected)]
        );
    }
    Ok(())
}

#[test]
fn a_write_failure_is_an_output_error() -> TestResult {
    struct Closed;
    impl Write for Closed {
        fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let case = attempt(
        FixtureFamily::Positive,
        ExecutionMode::Local,
        two_subcases(FixtureFamily::Positive),
        vec![composite(&[])?],
    );
    let runner = FakeRunner::new(|subcase| full(subcase.id.as_str()));
    let result = run_with(&runner, stream(&case)?.as_slice(), Closed);
    assert_eq!(result, Err(AdapterRunErrorV1::Output));
    Ok(())
}

#[test]
fn run_reads_the_stream_and_reports_a_wire_fault() {
    let result = run(std::io::empty(), std::io::sink());
    assert_eq!(result, Err(AdapterRunErrorV1::Wire));
}

#[test]
fn the_exit_code_names_the_error() {
    let codes = [
        (AdapterRunErrorV1::Wire, 2_u8),
        (AdapterRunErrorV1::NotExecuted, 3),
        (AdapterRunErrorV1::Worker, 4),
        (AdapterRunErrorV1::Output, 5),
    ];
    for (error, code) in codes {
        assert_eq!(error.code(), code);
        assert_eq!(format!("{:?}", exit_code(Err(error))), format!("{:?}", ExitCode::from(code)));
        assert!(!error.to_string().is_empty());
    }
    assert_eq!(format!("{:?}", exit_code(Ok(()))), format!("{:?}", ExitCode::SUCCESS));
}
