//! R8-A2 to R8-A5: the mapping, the case precedence, the usage and the failures.

use std::collections::BTreeSet;

use pos_plugin_release::ContentValidationV1;
use pos_runtime::community_plugin_host::{
    AtomicCommitFailureV1, CommunityPluginModeV1, ComponentTrapClassV1, RevocationBasisV1,
    TrapReproductionV1, TrustDenialBasisV1,
};

use super::*;
use crate::test_support::{matched, TestResult};
use crate::world::{ScanResultV1, ScanSource};

type E = CommunityPluginHostErrorV1;
type R = CommunityPluginSubjectResultV1;

/// Every closed error with every basis, class and reproduction.
fn every_error() -> Vec<E> {
    let mut all = vec![E::InvalidManifest];
    for basis in [
        TrustDenialBasisV1::Expired,
        TrustDenialBasisV1::NotActive,
        TrustDenialBasisV1::Untrusted,
        TrustDenialBasisV1::PolicyMismatch,
        TrustDenialBasisV1::TrustStateUnavailable,
    ] {
        all.push(E::ArtifactTrustDenied { basis });
    }
    for basis in [
        RevocationBasisV1::PublisherKey,
        RevocationBasisV1::Artifact,
        RevocationBasisV1::OperatorDenial,
    ] {
        all.push(E::ArtifactRevoked { basis });
    }
    all.extend([
        E::IncompatibleAbi,
        E::MissingFeature { index: 2 },
        E::CapabilityDenied { index: 1 },
        E::InvalidInvocation,
        E::InvalidGuestOutput,
        E::UnsupportedSchema,
        E::StateMigrationFailed,
        E::GuestDeclaredFailure,
    ]);
    for reproduction in [
        TrapReproductionV1::ReproducedByConformance,
        TrapReproductionV1::Unverified,
    ] {
        all.push(E::ComponentTrap {
            class: ComponentTrapClassV1::Unreachable,
            reproduction,
        });
    }
    all.extend([
        E::WorkerCrashed,
        E::FuelExhausted,
        E::MemoryLimitExceeded,
        E::HostCallLimitExceeded,
        E::OutputLimitExceeded,
        E::DeterministicDeadlineExceeded,
        E::OperationalWatchdogStop,
    ]);
    for failure in [
        AtomicCommitFailureV1::DeterministicTypedResult,
        AtomicCommitFailureV1::Operational,
    ] {
        all.push(E::AtomicCommitFailed { failure });
    }
    all
}

fn outcome(result: R) -> CommunityPluginSubjectOutcomeV1 {
    CommunityPluginSubjectOutcomeV1 {
        plugin_id: "p".to_owned(),
        pmf1_digest: None,
        release_digest: None,
        tps1_digest: None,
        execution_profile_digest: None,
        tick: 0,
        mode: CommunityPluginModeV1::Local,
        content_validation: ContentValidationV1::NotPerformed,
        result,
    }
}

const METERING: MeteringV1 = MeteringV1 {
    startup_fuel: 5,
    call_fuel: 7,
    memory_bytes: 1_114_112,
    host_calls: 3,
};

/// The outcome result the host assembles for a failure `error`: `Refused` for a pre-execution
/// rejection and `Failed` otherwise, as `CommunityPluginSubjectOutcomeV1::assemble` does.
const fn result_of_error(error: E) -> R {
    match error.class() {
        HostFailureClassV1::PreExecutionRejection => R::Refused {
            error: error.name(),
            basis: error.basis_name(),
            class: error.class().name(),
        },
        HostFailureClassV1::Authoritative | HostFailureClassV1::Operational => R::Failed {
            error: error.name(),
            class: error.class().name(),
        },
    }
}

#[test]
fn the_known_names_are_exactly_the_twenty_closed_errors() {
    let names: BTreeSet<&str> = every_error().iter().map(|error| error.name()).collect();
    let known: BTreeSet<&str> = KNOWN_ERRORS.into_iter().collect();
    assert_eq!(names, known);
    assert_eq!(known.len(), 20);
}

#[test]
fn every_closed_error_with_every_basis_maps_by_its_class() {
    for error in every_error() {
        let mapped = of_outcome(&outcome(result_of_error(error)));
        let setup = of_error(error);
        match error.class() {
            HostFailureClassV1::PreExecutionRejection => {
                let SubResultV1::Refused {
                    error: name,
                    basis,
                    class,
                    index,
                } = mapped
                else {
                    std::panic::resume_unwind(Box::new(format!("{error:?} is not refused")));
                };
                assert_eq!(name, error.name());
                assert_eq!(basis, error.basis_name());
                assert_eq!(class, "PreExecutionRejection");
                assert_eq!(index, None, "an outcome record carries no index");
                let expected_index = match error {
                    E::MissingFeature { index } | E::CapabilityDenied { index } => {
                        Some(u64::try_from(index).unwrap_or(0))
                    }
                    _ => None,
                };
                assert_eq!(
                    setup,
                    SubResultV1::Refused {
                        error: error.name(),
                        basis: error.basis_name(),
                        class: "PreExecutionRejection",
                        index: expected_index,
                    }
                );
            }
            HostFailureClassV1::Authoritative => {
                let expected = SubResultV1::Failed {
                    error: error.name(),
                    class: "Authoritative",
                };
                assert_eq!(mapped, expected, "{error:?}");
                assert_eq!(setup, expected, "{error:?}");
            }
            HostFailureClassV1::Operational => {
                assert_eq!(mapped, SubResultV1::Operational, "{error:?}");
                assert_eq!(setup, SubResultV1::Operational, "{error:?}");
            }
        }
    }
}

#[test]
fn every_result_variant_maps_and_an_incomplete_record_is_operational() {
    let digest = Some([4; 32]);
    let usage = ResourceUsage {
        memory_bytes: 1_114_112,
        cpu_fuel: 12,
        host_calls: 3,
        ..ResourceUsage::default()
    };
    let committed = R::Committed {
        output_digest: digest,
        metering: Some(METERING),
    };
    assert_eq!(
        of_outcome(&outcome(committed)),
        SubResultV1::Committed {
            output_digest: [4; 32],
            usage,
        }
    );
    let operational = [
        R::Committed {
            output_digest: None,
            metering: Some(METERING),
        },
        R::Committed {
            output_digest: digest,
            metering: None,
        },
        R::Committed {
            output_digest: None,
            metering: None,
        },
        R::Staged {
            output_digest: digest,
            metering: Some(METERING),
        },
        R::Staged {
            output_digest: None,
            metering: None,
        },
        R::NotRun,
        R::Discarded,
    ];
    for result in operational {
        assert_eq!(
            of_outcome(&outcome(result)),
            SubResultV1::Operational,
            "{result:?}"
        );
    }
}

#[test]
fn an_unknown_name_or_class_is_operational() {
    let unknown = [
        R::Refused {
            error: "Bogus",
            basis: None,
            class: "PreExecutionRejection",
        },
        R::Failed {
            error: "Bogus",
            class: "Authoritative",
        },
        R::Failed {
            error: "FuelExhausted",
            class: "Bogus",
        },
        R::Failed {
            error: "FuelExhausted",
            class: "Operational",
        },
        R::Failed {
            error: "FuelExhausted",
            class: "PreExecutionRejection",
        },
    ];
    for result in unknown {
        assert_eq!(
            of_outcome(&outcome(result)),
            SubResultV1::Operational,
            "{result:?}"
        );
    }
}

fn operational_record(id: &str) -> SubCaseRecordV1 {
    SubCaseRecordV1 {
        outcomes: vec![outcome(R::NotRun)],
        ..SubCaseRecordV1::empty(id)
    }
}

#[test]
fn the_record_result_is_the_setup_refusal_else_the_last_outcome_else_none() {
    let empty = SubCaseRecordV1::empty("x");
    assert_eq!(of_record(&empty), None);
    let committed = R::Committed {
        output_digest: Some([1; 32]),
        metering: Some(METERING),
    };
    let refused = R::Refused {
        error: "IncompatibleAbi",
        basis: None,
        class: "PreExecutionRejection",
    };
    let both = SubCaseRecordV1 {
        outcomes: vec![outcome(refused), outcome(committed)],
        ..empty.clone()
    };
    assert!(matches!(
        of_record(&both),
        Some(SubResultV1::Committed { .. })
    ));
    let refusal = SubCaseRecordV1 {
        setup_refusal: Some(E::IncompatibleAbi),
        ..both
    };
    assert!(matches!(
        of_record(&refusal),
        Some(SubResultV1::Refused { .. })
    ));
}

#[test]
fn an_operational_result_is_never_a_failure_or_an_output() {
    let operational = [
        R::Failed {
            error: "WorkerCrashed",
            class: "Operational",
        },
        R::Failed {
            error: "OperationalWatchdogStop",
            class: "Operational",
        },
        R::Failed {
            error: "ComponentTrap",
            class: "Operational",
        },
        R::Failed {
            error: "AtomicCommitFailed",
            class: "Operational",
        },
        R::NotRun,
        R::Discarded,
        R::Staged {
            output_digest: Some([1; 32]),
            metering: Some(METERING),
        },
        R::Committed {
            output_digest: None,
            metering: None,
        },
    ];
    for family in FixtureFamily::ALL {
        for result in operational {
            let record = SubCaseRecordV1 {
                outcomes: vec![outcome(result)],
                ..matched("x")
            };
            let decided = case_result("c", *family, &[record]);
            assert_eq!(
                decided.result,
                SubjectResult::Unavailable,
                "{family:?} {result:?}"
            );
            assert_eq!(decided.usage, ResourceUsage::default());
        }
    }
    let overflow = R::Committed {
        output_digest: Some([1; 32]),
        metering: Some(MeteringV1 {
            startup_fuel: u64::MAX,
            call_fuel: 1,
            ..METERING
        }),
    };
    let record = SubCaseRecordV1 {
        outcomes: vec![outcome(overflow)],
        ..matched("x")
    };
    let decided = case_result("c", FixtureFamily::Positive, &[record]);
    assert_eq!(decided.result, SubjectResult::Unavailable);
}

#[test]
fn one_operational_subresult_at_any_position_makes_the_case_unavailable() {
    for family in [FixtureFamily::Denied, FixtureFamily::Positive] {
        for position in 0..3 {
            let records: Vec<SubCaseRecordV1> = (0..3)
                .map(|index| {
                    if index == position {
                        operational_record("op")
                    } else {
                        matched("ok")
                    }
                })
                .collect();
            let decided = case_result("c", family, &records);
            assert_eq!(
                decided.result,
                SubjectResult::Unavailable,
                "{family:?} {position}"
            );
        }
    }
}

const fn failure_of(decided: &CaseResultV1) -> Option<&str> {
    match &decided.result {
        SubjectResult::Failure(failure) => Some(failure.code_id.as_str()),
        _ => None,
    }
}

#[test]
fn a_failure_family_is_its_fixed_code_when_every_subcase_matched_else_subcase_mismatch() {
    let codes = [
        (FixtureFamily::Denied, "capability-denied"),
        (FixtureFamily::Malformed, "malformed-payload"),
        (FixtureFamily::ResourceExhaustion, "resource-limit"),
        (FixtureFamily::Downgrade, "incompatible-contract"),
    ];
    for (family, code) in codes {
        let all = [matched("a"), matched("b"), matched("c")];
        assert_eq!(failure_of(&case_result("c", family, &all)), Some(code));
        for position in 0..3 {
            let mut records = all.clone();
            records[position].matched = false;
            let decided = case_result("c", family, &records);
            assert_eq!(
                failure_of(&decided),
                Some("subcase-mismatch"),
                "{family:?} {position}"
            );
        }
    }
}

fn committed_record(id: &str, digest: Option<[u8; 32]>, matches: bool) -> SubCaseRecordV1 {
    SubCaseRecordV1 {
        committed: digest,
        matched: matches,
        ..SubCaseRecordV1::empty(id)
    }
}

fn output_of(decided: &CaseResultV1) -> String {
    match &decided.result {
        SubjectResult::Output(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        _ => String::new(),
    }
}

/// The head of the canonical record of `family`, up to the opening of the entries.
fn head(family: &str) -> String {
    format!(
        concat!(
            "{{\"case_id\":\"c\",\"claim_layer\":\"plugin-conformance\",",
            "\"family\":\"{}\",\"oracle\":{{\"kind\":\"canonical-output\"}},",
            "\"output\":{{\"subcases\":["
        ),
        family
    )
}

fn committed_entry(id: &str, digit: &str) -> String {
    format!(
        "{{\"id\":\"{id}\",\"kind\":\"committed\",\"output_digest\":\"{}\"}}",
        digit.repeat(32)
    )
}

#[test]
fn the_canonical_record_equals_the_hand_written_golden_byte_for_byte() {
    let records = [
        committed_record("pos.1", Some([1; 32]), true),
        committed_record("pos.2", Some([2; 32]), true),
    ];
    let decided = case_result("c", FixtureFamily::Positive, &records);
    let golden = format!(
        "{}{},{}]}}}}\n",
        head("positive"),
        committed_entry("pos.1", "01"),
        committed_entry("pos.2", "02")
    );
    assert_eq!(output_of(&decided), golden);
    assert!(golden.ends_with("}\n") && !golden[..golden.len() - 1].contains('\n'));
}

const fn position_digit(position: usize) -> u8 {
    match position {
        0 => 1,
        1 => 2,
        _ => 3,
    }
}

#[test]
fn one_mismatch_changes_exactly_its_entry() {
    let matching = [
        committed_record("pos.1", Some([1; 32]), true),
        committed_record("pos.2", Some([2; 32]), true),
        committed_record("pos.3", Some([3; 32]), true),
    ];
    let golden = output_of(&case_result("c", FixtureFamily::Positive, &matching));
    for position in 0..3 {
        // An observed digest that differs, one equal to the golden, or none at all.
        for observed in [Some([9; 32]), Some([position_digit(position); 32]), None] {
            let mut records = matching.clone();
            records[position] = committed_record(&records[position].id, observed, false);
            let seen = output_of(&case_result("c", FixtureFamily::Positive, &records));
            let id = format!("pos.{}", position + 1);
            let original = committed_entry(&id, &format!("0{}", position + 1));
            let replacement = format!("{{\"id\":\"{id}\",\"kind\":\"mismatch\"}}");
            assert_eq!(
                seen,
                golden.replacen(&original, &replacement, 1),
                "{position}"
            );
            assert_ne!(seen, golden);
        }
    }
}

fn scan(found: Vec<ScanSource>, plugin: &str) -> ScanResultV1 {
    ScanResultV1 {
        found,
        retained_ok: true,
        observed_plugin_id: plugin.to_owned(),
        observed_invocation_id_hex: "ab".to_owned(),
    }
}

#[test]
fn the_deletion_and_independent_entries_have_their_shapes() {
    let absent = SubCaseRecordV1 {
        scan: Some(scan(Vec::new(), "p")),
        ..matched("del.1")
    };
    let present = SubCaseRecordV1 {
        scan: Some(scan(vec![ScanSource::State], "p")),
        matched: false,
        ..matched("del.2")
    };
    let skipped = SubCaseRecordV1 {
        matched: false,
        ..SubCaseRecordV1::empty("del.3")
    };
    let records = [absent, present, skipped];
    let seen = output_of(&case_result(
        "c",
        FixtureFamily::DeletionRedaction,
        &records,
    ));
    let entries = concat!(
        "{\"id\":\"del.1\",\"kind\":\"absent\",\"prohibited_data_present\":false,",
        "\"retained_metadata\":{\"invocation_id_hex\":\"ab\",\"plugin_id\":\"p\"}},",
        "{\"id\":\"del.2\",\"kind\":\"mismatch\"},",
        "{\"id\":\"del.3\",\"kind\":\"mismatch\"}"
    );
    let opening = head("deletion-redaction");
    assert_eq!(seen, format!("{opening}{entries}]}}}}\n"));

    let computed = SubCaseRecordV1 {
        computed: Some([5; 32]),
        ..matched("ind.1")
    };
    let missing = SubCaseRecordV1 {
        matched: false,
        ..SubCaseRecordV1::empty("ind.2a")
    };
    let records = [computed, missing];
    let seen = output_of(&case_result(
        "c",
        FixtureFamily::IndependentEvaluation,
        &records,
    ));
    let opening = head("independent-evaluation");
    let entries = format!(
        concat!(
            "{{\"id\":\"ind.1\",\"kind\":\"digest\",\"value\":\"{}\"}},",
            "{{\"id\":\"ind.2a\",\"kind\":\"mismatch\"}}"
        ),
        "05".repeat(32)
    );
    assert_eq!(seen, format!("{opening}{entries}]}}}}\n"));
}

#[test]
fn a_failure_family_has_no_entries() {
    let record = matched("x");
    for family in [
        FixtureFamily::Denied,
        FixtureFamily::Malformed,
        FixtureFamily::ResourceExhaustion,
        FixtureFamily::Downgrade,
    ] {
        let entry = entry(family, &record);
        assert_eq!(entry.canonical(), b"{\"id\":\"x\",\"kind\":\"mismatch\"}");
    }
}

#[test]
fn usage_is_the_checked_sum_of_the_two_fuel_counters_and_the_rest_is_direct() -> TestResult {
    let usage = usage_of(METERING).ok_or("no usage")?;
    assert_eq!(
        usage,
        ResourceUsage {
            memory_bytes: 1_114_112,
            cpu_fuel: 12,
            host_calls: 3,
            event_count: 0,
            output_bytes: 0,
            storage_bytes: 0,
            execution_steps: 0,
            simulation_time_ns: 0,
        }
    );
    let edge = |startup_fuel, call_fuel| {
        usage_of(MeteringV1 {
            startup_fuel,
            call_fuel,
            ..METERING
        })
    };
    assert_eq!(edge(u64::MAX, 0).map(|u| u.cpu_fuel), Some(u64::MAX));
    assert_eq!(edge(0, u64::MAX).map(|u| u.cpu_fuel), Some(u64::MAX));
    assert_eq!(edge(u64::MAX, 1), None);
    assert_eq!(edge(1, u64::MAX), None);
    assert_eq!(edge(u64::MAX, u64::MAX), None);
    Ok(())
}

fn usage_record(id: &str, usage: ResourceUsage) -> SubCaseRecordV1 {
    SubCaseRecordV1 {
        usage,
        ..matched(id)
    }
}

#[test]
fn the_case_usage_is_the_per_counter_maximum_wherever_the_maximum_is() {
    let counters: [fn(&mut ResourceUsage, u64); 8] = [
        |u, v| u.memory_bytes = v,
        |u, v| u.cpu_fuel = v,
        |u, v| u.host_calls = v,
        |u, v| u.event_count = v,
        |u, v| u.output_bytes = v,
        |u, v| u.storage_bytes = v,
        |u, v| u.execution_steps = v,
        |u, v| u.simulation_time_ns = v,
    ];
    for (index, set) in counters.iter().enumerate() {
        for position in 0_u8..3 {
            let mut records = Vec::new();
            let mut expected = ResourceUsage::default();
            for slot in 0_u8..3 {
                let mut usage = ResourceUsage::default();
                // Every sub-case reports a small value of this counter; one reports the maximum.
                set(
                    &mut usage,
                    if slot == position {
                        1_000
                    } else {
                        10 + u64::from(slot)
                    },
                );
                records.push(usage_record("pos", usage));
            }
            set(&mut expected, 1_000);
            let decided = case_result("c", FixtureFamily::Positive, &records);
            assert_eq!(decided.usage, expected, "counter {index} at {position}");
        }
    }
    let none = case_result("c", FixtureFamily::Positive, &[]);
    assert_eq!(none.usage, ResourceUsage::default());
}

#[test]
fn every_failure_has_the_provider_identity_and_a_code_within_the_grammar() {
    let codes = [
        "capability-denied",
        "malformed-payload",
        "resource-limit",
        "incompatible-contract",
        "subcase-mismatch",
        "payload-invalid",
    ];
    for code in codes {
        let SubjectResult::Failure(value) = failure(code) else {
            std::panic::resume_unwind(Box::new("not a failure"));
        };
        assert_eq!(value.owner_id, "pigloros.fixture.plugin-conformance");
        assert_eq!(value.contract_version, "2.0.0");
        assert_eq!(value.code_id, code);
        let mut chars = code.chars();
        let first = chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
        let rest = chars.all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '/' | '-')
        });
        assert!(first && rest, "{code}");
    }
    assert_eq!(payload_invalid(), failure("payload-invalid"));
}
