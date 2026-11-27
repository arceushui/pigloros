//! The adapter argument vector of every provider conformance case.

use pos_conformance::{
    ProviderConformanceCase, MEMORY_CEILING_BYTES, OUTPUT_CEILING_BYTES, OVERSHOOT, TASK_CEILING,
    WATCHDOG_CEILING_MS, WORK_CEILING_BYTES,
};

fn vector(case: ProviderConformanceCase) -> Vec<String> {
    case.adapter_plan().arguments()
}

fn words(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn every_case_has_exactly_this_argument_vector() {
    use ProviderConformanceCase as Case;
    let idle = (WATCHDOG_CEILING_MS * OVERSHOOT).to_string();
    let expected = [
        (Case::FilesystemEscape, words(&["filesystem-escape"])),
        (Case::ReadOnlyRootWrite, words(&["read-only-root-write"])),
        (
            Case::WorkAreaExhaustion,
            words(&["work-area-exhaustion", "33554432"]),
        ),
        (Case::NetworkEscape, words(&["network-escape"])),
        (Case::ForeignSignals, words(&["foreign-signals"])),
        (Case::OrphanedChild, words(&["orphaned-child"])),
        (Case::TaskExhaustion, words(&["task-exhaustion", "128"])),
        (
            Case::MemoryExhaustion,
            words(&["memory-exhaustion", "134217728"]),
        ),
        (Case::WatchdogExpiry, words(&["watchdog-expiry", "60000"])),
        (
            Case::OversizedOutput,
            words(&["oversized-output", "2097152"]),
        ),
        (Case::AdapterCrash, words(&["adapter-crash"])),
        (Case::MalformedOutput, words(&["malformed-output"])),
        (Case::CancelBeforeRelease, words(&["honest"])),
        (Case::CancelWhileRunning, words(&["idle", &idle])),
        (Case::BrokerCrashRecovery, words(&["idle", &idle])),
        (Case::RevokedBeforeAdmission, words(&["honest"])),
        (Case::RevokedWhileRunning, words(&["idle", &idle])),
        (Case::MissingHostFeature, words(&["honest"])),
        (Case::ConcurrentAttempts, words(&["honest"])),
    ];
    assert_eq!(expected.len(), Case::ALL.len());
    for (case, arguments) in expected {
        assert_eq!(vector(case), arguments, "{}", case.id());
    }
}

#[test]
fn every_bound_is_strictly_above_the_ceiling_it_probes() {
    for case in ProviderConformanceCase::ALL {
        let plan = case.adapter_plan();
        assert_eq!(
            plan.bound,
            case.probed_ceiling().map(|ceiling| ceiling * OVERSHOOT),
            "{}",
            case.id()
        );
        if let (Some(bound), Some(ceiling)) = (plan.bound, case.probed_ceiling()) {
            assert!(bound > ceiling, "{}", case.id());
        }
    }
}

#[test]
fn the_ceilings_are_fixed_and_the_overshoot_is_a_real_excess() {
    assert_eq!(OVERSHOOT, 2);
    assert_eq!(MEMORY_CEILING_BYTES, 64 << 20);
    assert_eq!(TASK_CEILING, 64);
    assert_eq!(WATCHDOG_CEILING_MS, 30_000);
    assert_eq!(OUTPUT_CEILING_BYTES, 1 << 20);
    assert_eq!(WORK_CEILING_BYTES, 16 << 20);
}

#[test]
fn a_mode_with_a_bound_is_named_by_the_case_or_is_the_idle_mode() {
    for case in ProviderConformanceCase::ALL {
        let plan = case.adapter_plan();
        if plan.bound.is_some() {
            assert!(
                plan.mode == case.id() || plan.mode == "idle",
                "{}",
                case.id()
            );
        } else {
            assert!(
                plan.mode == case.id() || plan.mode == "honest",
                "{}",
                case.id()
            );
        }
    }
}
