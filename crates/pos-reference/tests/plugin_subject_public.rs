//! Public black-box tests of the independent evaluator over `plugin-conformance` fixtures.
//!
//! A scripted `SubjectAdapter` stands in for the Plugin subject. The tests exercise only the
//! public `evaluate` operation and the CNR1 report it returns; they import no host crate.

pub mod support;

use std::error::Error;
use std::io;
use std::sync::OnceLock;

use pos_reference::evaluator::{
    evaluate, AdapterError, CaseAttempt, EvaluatorError, ResourceUsage, SubjectAdapter,
    SubjectObservation, SubjectResult,
};
use pos_reference::evaluator_build_identity::VerifiedEvaluatorBuildIdentity;
use pos_reference::evaluator_domain::{ClaimLayer, FixtureFamily, SafeErrorCode};
use pos_reference::evaluator_protocol::{
    CaseOutcome, CaseStatus, ConformanceReport, SubjectAdapterKind,
};
use pos_reference::profile::{DeterministicBudget, NamespacedFailure};
use support::{BundleMutation, Corpus};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// The public input of `ind.1`, exactly as ADR-061 revision 8 specifies it.
const IND1_INPUT: &[u8] = b"PiglorOS independent fixture plugin-conformance";

/// The checked-in BLAKE3 of `IND1_INPUT`, shared with the host-side `independent-evaluation` test.
const IND1_DIGEST: &str = "92adc8f0b327b091f85e847d3fa1f7cb46e16bdd74f389d79b2e61171c2715c3";

/// ADR-068 R4 test 8, evaluator half: the usage the real worker measures for the `positive`
/// case in Local and Air-Gapped. `apps/pos-plugin-worker/tests/conformance_adapter_public.rs`
/// asserts the same literal on the real worker (`POSITIVE_USAGE`); keep the two in step.
const MEASURED_POSITIVE_USAGE: ResourceUsage = ResourceUsage {
    memory_bytes: 1_179_648,
    cpu_fuel: 42_604,
    host_calls: 6,
    event_count: 2,
    output_bytes: 16,
    storage_bytes: 16,
    execution_steps: 2,
    simulation_time_ns: 1,
};

/// The Execution Modes of the evaluator corpus: 0 is Local and 1 is Air-Gapped.
const CORPUS_MODES: [u64; 2] = [0, 1];

const FAILURE_FAMILIES: [(u8, &str); 4] = [
    (1, "capability-denied"),
    (2, "malformed-payload"),
    (3, "resource-limit"),
    (5, "incompatible-contract"),
];

type ByteMutation = fn(&mut Vec<u8>);

type Mutation = (&'static str, ByteMutation);

const FAMILY_COUNT: u8 = 7;

type Counter = fn(&mut ResourceUsage) -> &mut u64;

const COUNTERS: [(&str, Counter); 8] = [
    ("memory_bytes", |usage| &mut usage.memory_bytes),
    ("cpu_fuel", |usage| &mut usage.cpu_fuel),
    ("host_calls", |usage| &mut usage.host_calls),
    ("event_count", |usage| &mut usage.event_count),
    ("output_bytes", |usage| &mut usage.output_bytes),
    ("storage_bytes", |usage| &mut usage.storage_bytes),
    ("execution_steps", |usage| &mut usage.execution_steps),
    ("simulation_time_ns", |usage| &mut usage.simulation_time_ns),
];

const OUTPUT_FAMILIES: [u8; 3] = [0, 4, 6];

const PROVIDER_CODES: [&str; 6] = [
    "capability-denied",
    "malformed-payload",
    "resource-limit",
    "incompatible-contract",
    "subcase-mismatch",
    "payload-invalid",
];

struct Scripted<F> {
    subject_digest: [u8; 32],
    script: F,
}

impl<F> SubjectAdapter for Scripted<F>
where
    F: FnMut(&CaseAttempt) -> Result<SubjectObservation, AdapterError>,
{
    fn kind(&self) -> SubjectAdapterKind {
        SubjectAdapterKind::PublicPluginProtocol
    }

    fn subject_artifact_digest(&self) -> [u8; 32] {
        self.subject_digest
    }

    fn execute(&mut self, attempt: &CaseAttempt) -> Result<SubjectObservation, AdapterError> {
        (self.script)(attempt)
    }
}

fn evaluator_identity() -> TestResult<VerifiedEvaluatorBuildIdentity> {
    static IDENTITY: OnceLock<Result<VerifiedEvaluatorBuildIdentity, String>> = OnceLock::new();
    match IDENTITY
        .get_or_init(|| support::verified_evaluator_identity().map_err(|error| error.to_string()))
    {
        Ok(identity) => Ok(identity.clone()),
        Err(error) => Err(io::Error::other(error.clone()).into()),
    }
}

/// Lowercase hexadecimal. Only the hex and record construction is independent of the crate;
/// `IND1_DIGEST` is the anchor that pins the expected value.
fn hexadecimal(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(char::from(DIGITS[usize::from(byte >> 4)]));
        value.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    value
}

fn independent_blake3(input: &[u8]) -> String {
    hexadecimal(blake3::hash(input).as_bytes())
}

/// One JCS oracle record of a canonical-output family: sorted keys, no whitespace, one LF.
fn oracle_record(case: u8, family: &str, subcase: &str) -> Vec<u8> {
    format!(
        "{{\"case_id\":\"case-{case}\",\"claim_layer\":\"plugin-conformance\",\
         \"family\":\"{family}\",\"oracle\":{{\"kind\":\"canonical-output\"}},\
         \"output\":{{\"subcases\":[{subcase}]}}}}\n"
    )
    .into_bytes()
}

fn digest_subcase(value: &str) -> String {
    format!("{{\"id\":\"ind.1\",\"kind\":\"digest\",\"value\":\"{value}\"}}")
}

fn independent_record(digest: &str) -> Vec<u8> {
    oracle_record(6, "independent-evaluation", &digest_subcase(digest))
}

/// The hand-written oracle members; the failure families carry typed failures instead.
///
/// The `pos.1` and `del.1` subcase shapes are illustrative; S5 (R8-S7) owns the real record
/// shape. The placeholder members at ordinals 1, 2, 3 and 5 are written into the bundle but no
/// oracle references them, and the corpus payload is one opaque byte per family: both are inert
/// by design.
fn oracle_records() -> Vec<Vec<u8>> {
    let positive = format!(
        "{{\"id\":\"pos.1\",\"kind\":\"committed\",\"output_digest\":\"{}\"}}",
        "11".repeat(32)
    );
    let deletion = format!(
        "{{\"id\":\"del.1\",\"kind\":\"absent\",\"prohibited_data_present\":false,\
         \"retained_metadata\":{{\"invocation_id_hex\":\"{}\",\"plugin_id\":\"fixture.plugin\"}}}}",
        "22".repeat(16)
    );
    (0..FAMILY_COUNT)
        .map(|case| match case {
            0 => oracle_record(case, "positive", &positive),
            4 => oracle_record(case, "deletion-redaction", &deletion),
            6 => independent_record(IND1_DIGEST),
            _ => b"typed failure oracle".to_vec(),
        })
        .collect()
}

fn failure(code: &str) -> SubjectResult {
    SubjectResult::Failure(NamespacedFailure {
        owner_id: "test-provider".to_owned(),
        contract_version: "1.0.0".to_owned(),
        code_id: code.to_owned(),
    })
}

fn observe(result: SubjectResult) -> SubjectObservation {
    SubjectObservation {
        result,
        usage: ResourceUsage::default(),
    }
}

/// What a correct Plugin subject returns; family 6 recomputes `ind.1` from the public input.
fn faithful(family: FixtureFamily, records: &[Vec<u8>]) -> SubjectResult {
    match family {
        FixtureFamily::Positive => SubjectResult::Output(records[0].clone()),
        FixtureFamily::Denied => failure("capability-denied"),
        FixtureFamily::Malformed => failure("malformed-payload"),
        FixtureFamily::ResourceExhaustion => failure("resource-limit"),
        FixtureFamily::DeletionRedaction => SubjectResult::Output(records[4].clone()),
        FixtureFamily::Downgrade => failure("incompatible-contract"),
        FixtureFamily::IndependentEvaluation => {
            SubjectResult::Output(independent_record(&independent_blake3(IND1_INPUT)))
        }
    }
}

fn plugin_fixtures() -> TestResult<(Corpus, Vec<Vec<u8>>)> {
    let records = oracle_records();
    let corpus = support::plugin_corpus(&records)?;
    Ok((corpus, records))
}

fn run<F>(corpus: &Corpus, script: F) -> TestResult<ConformanceReport>
where
    F: FnMut(&CaseAttempt) -> Result<SubjectObservation, AdapterError>,
{
    let mut adapter = Scripted {
        subject_digest: corpus.subject_digest,
        script,
    };
    let artifacts = evaluate(
        &corpus.request,
        &corpus.archive,
        &corpus.trust_policy,
        &evaluator_identity()?,
        &mut adapter,
    )?;
    Ok(artifacts.report)
}

fn case(report: &ConformanceReport, family: u8) -> TestResult<&CaseOutcome> {
    let id = format!("case-{family}");
    report
        .cases
        .iter()
        .find(|outcome| outcome.case_id == id)
        .ok_or_else(|| io::Error::other(format!("{id} is absent from the report")).into())
}

fn expect_status(report: &ConformanceReport, family: u8, expected: CaseStatus) -> TestResult {
    let actual = case(report, family)?.outcome;
    if actual == expected {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "case-{family}: expected {expected:?}, got {actual:?}"
    ))
    .into())
}

fn expect_all(report: &ConformanceReport, expected: CaseStatus) -> TestResult {
    (0..FAMILY_COUNT).try_for_each(|family| expect_status(report, family, expected))
}

/// Usage that sits exactly at the fixture budget, with `extra` added to one counter.
fn usage_at(budget: DeterministicBudget, counter: Counter, extra: u64) -> ResourceUsage {
    let mut usage = ResourceUsage {
        memory_bytes: budget.memory_bytes,
        cpu_fuel: budget.cpu_fuel,
        host_calls: budget.host_calls,
        event_count: budget.event_count,
        output_bytes: budget.output_bytes,
        storage_bytes: budget.storage_bytes,
        execution_steps: budget.execution_steps,
        simulation_time_ns: budget.simulation_time_ns,
    };
    *counter(&mut usage) += extra;
    usage
}

#[test]
fn plugin_attempts_carry_plugin_layer_and_no_network() -> TestResult {
    let (corpus, records) = plugin_fixtures()?;
    let mut attempts = Vec::new();
    let report = run(&corpus, |attempt| {
        attempts.push(attempt.clone());
        Ok(observe(faithful(attempt.family, &records)))
    })?;
    expect_all(&report, CaseStatus::Pass)?;
    assert_eq!(attempts.len(), usize::from(FAMILY_COUNT), "attempts");
    for attempt in &attempts {
        assert_eq!(attempt.claim_layer, ClaimLayer::PluginConformance);
        assert!(!attempt.network_allowed, "{}", attempt.case_id);
    }
    assert!(report
        .cases
        .iter()
        .all(|outcome| outcome.claim_layer == ClaimLayer::PluginConformance));
    Ok(())
}

#[test]
fn faithful_subject_passes_with_output_equal_to_the_oracle_member() -> TestResult {
    let (corpus, records) = plugin_fixtures()?;
    let report = run(&corpus, |attempt| {
        Ok(observe(faithful(attempt.family, &records)))
    })?;
    expect_all(&report, CaseStatus::Pass)?;
    for family in OUTPUT_FAMILIES {
        let outcome = case(&report, family)?;
        assert_eq!(
            outcome.actual_digest, outcome.expected_digest,
            "case-{family} digests"
        );
        assert!(outcome.actual_digest.is_some(), "case-{family} digest");
    }
    Ok(())
}

#[test]
fn output_that_differs_by_one_byte_fails_and_the_control_passes() -> TestResult {
    let (corpus, records) = plugin_fixtures()?;
    let mutations: [Mutation; 5] = [
        ("flipped first byte", |bytes| bytes[0] ^= 1),
        ("flipped middle byte", |bytes| {
            let middle = bytes.len() / 2;
            bytes[middle] ^= 1;
        }),
        ("flipped last byte", |bytes| {
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
        }),
        ("dropped last byte", |bytes| {
            bytes.pop();
        }),
        ("appended byte", |bytes| bytes.push(b'\n')),
    ];
    for (label, mutate) in mutations {
        let report = run(&corpus, |attempt| {
            let mut result = faithful(attempt.family, &records);
            if let SubjectResult::Output(bytes) = &mut result {
                mutate(bytes);
            }
            Ok(observe(result))
        })?;
        for family in OUTPUT_FAMILIES {
            expect_status(&report, family, CaseStatus::Fail)
                .map_err(|error| io::Error::other(format!("{label}: {error}")))?;
            let outcome = case(&report, family)?;
            assert_ne!(
                outcome.actual_digest, outcome.expected_digest,
                "{label}: case-{family} digests differ"
            );
        }
        for (family, _) in FAILURE_FAMILIES {
            expect_status(&report, family, CaseStatus::Pass)?;
        }
    }
    Ok(())
}

#[test]
fn failure_codes_fail_unless_they_equal_the_oracle() -> TestResult {
    let (corpus, records) = plugin_fixtures()?;
    for returned in PROVIDER_CODES {
        let report = run(&corpus, |attempt| {
            let result = match attempt.family {
                FixtureFamily::Denied
                | FixtureFamily::Malformed
                | FixtureFamily::ResourceExhaustion
                | FixtureFamily::Downgrade => failure(returned),
                family => faithful(family, &records),
            };
            Ok(observe(result))
        })?;
        for (family, oracle) in FAILURE_FAMILIES {
            let equal = oracle == returned;
            let status = if equal {
                CaseStatus::Pass
            } else {
                CaseStatus::Fail
            };
            expect_status(&report, family, status)
                .map_err(|error| io::Error::other(format!("returned {returned}: {error}")))?;
            let outcome = case(&report, family)?;
            if !equal {
                assert_eq!(
                    outcome.actual_error,
                    Some(SafeErrorCode::DigestMismatch),
                    "returned {returned} for case-{family}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn failure_with_a_foreign_owner_or_version_fails() -> TestResult {
    let (corpus, records) = plugin_fixtures()?;
    let foreign = [("other-provider", "1.0.0"), ("test-provider", "2.0.0")];
    for (owner_id, contract_version) in foreign {
        let report = run(&corpus, |attempt| {
            let result = match attempt.family {
                FixtureFamily::Denied => SubjectResult::Failure(NamespacedFailure {
                    owner_id: owner_id.to_owned(),
                    contract_version: contract_version.to_owned(),
                    code_id: "capability-denied".to_owned(),
                }),
                family => faithful(family, &records),
            };
            Ok(observe(result))
        })?;
        expect_status(&report, 1, CaseStatus::Fail)?;
        expect_status(&report, 2, CaseStatus::Pass)?;
    }
    Ok(())
}

#[test]
fn result_kind_that_differs_from_the_oracle_kind_fails() -> TestResult {
    let (corpus, records) = plugin_fixtures()?;
    let report = run(&corpus, |attempt| {
        let result = match attempt.family {
            FixtureFamily::Denied => SubjectResult::Output(records[0].clone()),
            FixtureFamily::Positive => failure("capability-denied"),
            family => faithful(family, &records),
        };
        Ok(observe(result))
    })?;
    expect_status(&report, 0, CaseStatus::Fail)?;
    expect_status(&report, 1, CaseStatus::Fail)?;
    expect_status(&report, 2, CaseStatus::Pass)?;
    Ok(())
}

/// R8-S8, evaluator path: a member whose bytes do not match the descriptor digest of the
/// signed bundle stops the evaluation with a bundle error before the adapter runs.
///
/// `MemberBytes` replaces the bytes of the first bundle member (index 0) and `DescriptorDigest`
/// changes a descriptor digest; neither targets the `PCW2` composite specifically, because this
/// corpus carries one opaque byte per family. The composite itself is checked by the adapter
/// (`conformance_adapter_public.rs`).
#[test]
fn a_member_that_fails_its_descriptor_digest_never_reaches_the_adapter() -> TestResult {
    let records = oracle_records();
    for mutation in [
        BundleMutation::MemberBytes,
        BundleMutation::DescriptorDigest,
    ] {
        let corpus = support::plugin_corpus_with_bundle_mutation(&records, mutation)?;
        let mut launched = 0_u32;
        let result = {
            let mut adapter = Scripted {
                subject_digest: corpus.subject_digest,
                script: |attempt: &CaseAttempt| {
                    launched += 1;
                    Ok(observe(faithful(attempt.family, &records)))
                },
            };
            evaluate(
                &corpus.request,
                &corpus.archive,
                &corpus.trust_policy,
                &evaluator_identity()?,
                &mut adapter,
            )
        };
        assert_eq!(result.err(), Some(EvaluatorError::Bundle));
        assert_eq!(launched, 0);
    }
    Ok(())
}

#[test]
fn unavailable_is_neither_pass_nor_fail() -> TestResult {
    let (corpus, records) = plugin_fixtures()?;
    let report = run(&corpus, |_| Ok(observe(SubjectResult::Unavailable)))?;
    expect_all(&report, CaseStatus::Unavailable)?;
    for family in 0..FAMILY_COUNT {
        let outcome = case(&report, family)?;
        assert_eq!(outcome.actual_digest, None, "case-{family} digest");
        assert_eq!(outcome.actual_error, None, "case-{family} error");
    }
    for error in [
        AdapterError::Unavailable,
        AdapterError::WatchdogExpired,
        AdapterError::ProtocolFailure,
    ] {
        let report = run(&corpus, |attempt| {
            if attempt.family == FixtureFamily::Denied {
                return Err(error);
            }
            Ok(observe(faithful(attempt.family, &records)))
        })?;
        expect_status(&report, 1, CaseStatus::Unavailable)?;
        expect_status(&report, 0, CaseStatus::Pass)?;
        expect_status(&report, 2, CaseStatus::Pass)?;
    }
    Ok(())
}

#[test]
fn lost_authenticated_evidence_is_an_evaluator_error_not_a_case_status() -> TestResult {
    let (corpus, _) = plugin_fixtures()?;
    let mut adapter = Scripted {
        subject_digest: corpus.subject_digest,
        script: |_: &CaseAttempt| Err(AdapterError::AuthenticatedEvidenceFailure),
    };
    let result = evaluate(
        &corpus.request,
        &corpus.archive,
        &corpus.trust_policy,
        &evaluator_identity()?,
        &mut adapter,
    );
    assert_eq!(result.err(), Some(EvaluatorError::AdapterIdentity));
    Ok(())
}

#[test]
fn usage_at_the_budget_passes_and_one_above_fails_for_every_counter() -> TestResult {
    let (corpus, records) = plugin_fixtures()?;
    for (name, counter) in COUNTERS {
        let at_budget = run(&corpus, |attempt| {
            Ok(SubjectObservation {
                result: faithful(attempt.family, &records),
                usage: usage_at(attempt.budget, counter, 0),
            })
        })?;
        expect_all(&at_budget, CaseStatus::Pass)
            .map_err(|error| io::Error::other(format!("counter {name} at budget: {error}")))?;
        let above = run(&corpus, |attempt| {
            Ok(SubjectObservation {
                result: faithful(attempt.family, &records),
                usage: usage_at(attempt.budget, counter, 1),
            })
        })?;
        expect_all(&above, CaseStatus::Fail)
            .map_err(|error| io::Error::other(format!("counter {name} above: {error}")))?;
        for family in 0..FAMILY_COUNT {
            assert_eq!(
                case(&above, family)?.actual_error,
                Some(SafeErrorCode::ResourceLimitExceeded),
                "counter {name}, case-{family}"
            );
        }
    }
    Ok(())
}

/// The eight counters of `usage` in `COUNTERS` order.
const fn counters(usage: ResourceUsage) -> [u64; 8] {
    [
        usage.memory_bytes,
        usage.cpu_fuel,
        usage.host_calls,
        usage.event_count,
        usage.output_bytes,
        usage.storage_bytes,
        usage.execution_steps,
        usage.simulation_time_ns,
    ]
}

/// The report of a subject that gives every case its faithful result and the `positive` case the
/// measured usage, over a corpus in `mode` whose every fixture budget is `budget`.
fn measured_report(
    records: &[Vec<u8>],
    mode: u64,
    budget: [u64; 8],
) -> TestResult<ConformanceReport> {
    let corpus = support::plugin_corpus_with_budget(records, mode, budget)?;
    run(&corpus, |attempt| {
        let usage = if attempt.family == FixtureFamily::Positive {
            MEASURED_POSITIVE_USAGE
        } else {
            ResourceUsage::default()
        };
        Ok(SubjectObservation {
            result: faithful(attempt.family, records),
            usage,
        })
    })
}

/// ADR-068 R4 test 8, evaluator half: a budget equal to the measured `positive` usage passes,
/// and a budget one below it in any counter fails `ResourceLimitExceeded`, in Local and
/// Air-Gapped. The measured Simulation Time is 1 ns, the lowest legal budget (a zero budget is
/// rejected), so one below it is not a budget and the last counter has no below case.
#[test]
fn measured_positive_usage_passes_at_an_equal_budget_and_fails_one_below() -> TestResult {
    let records = oracle_records();
    let measured = counters(MEASURED_POSITIVE_USAGE);
    // The one-below cases take the first seven counters: Simulation Time must be the last.
    assert_eq!(COUNTERS[7].0, "simulation_time_ns");
    for mode in CORPUS_MODES {
        let equal = measured_report(&records, mode, measured)?;
        expect_all(&equal, CaseStatus::Pass)
            .map_err(|error| io::Error::other(format!("mode {mode} at the budget: {error}")))?;
        for (index, (name, _)) in COUNTERS.iter().enumerate().take(7) {
            let mut below = measured;
            below[index] -= 1;
            let report = measured_report(&records, mode, below)?;
            let positive = case(&report, 0)?;
            assert_eq!(positive.outcome, CaseStatus::Fail, "{name} mode {mode}");
            assert_eq!(
                positive.actual_error,
                Some(SafeErrorCode::ResourceLimitExceeded),
                "{name} mode {mode}"
            );
            expect_status(&report, 6, CaseStatus::Pass)?;
        }
    }
    Ok(())
}

#[test]
fn ind1_is_reproduced_by_an_independent_blake3_of_the_public_input() -> TestResult {
    assert_eq!(independent_blake3(IND1_INPUT), IND1_DIGEST);
    let mut changed = IND1_INPUT.to_vec();
    changed[0] ^= 1;
    let changed_digest = independent_blake3(&changed);
    assert_ne!(changed_digest, IND1_DIGEST, "one-byte input change");
    let mut terminated = IND1_INPUT.to_vec();
    terminated.push(b'\n');
    let terminated_digest = independent_blake3(&terminated);
    assert_ne!(terminated_digest, IND1_DIGEST, "trailing LF");

    let (corpus, records) = plugin_fixtures()?;
    let report = run(&corpus, |attempt| {
        Ok(observe(faithful(attempt.family, &records)))
    })?;
    expect_status(&report, 6, CaseStatus::Pass)?;
    let wrong_digest = format!("0{}", &IND1_DIGEST[1..]);
    let wrong = run(&corpus, |attempt| {
        let result = if attempt.family == FixtureFamily::IndependentEvaluation {
            SubjectResult::Output(independent_record(&wrong_digest))
        } else {
            faithful(attempt.family, &records)
        };
        Ok(observe(result))
    })?;
    expect_status(&wrong, 6, CaseStatus::Fail)
}
