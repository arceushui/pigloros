use super::*;

type TestResult = Result<(), String>;

/// The profile digest of the constant runtime under the V1 ceilings, from the
/// generator-independent EPF1 computation (`b3sum` over the 1,636-byte body).
const CONSTANT_DIGEST: &str = "7d29c03a26e3c7121def90dabd9cb517ecf61600e75021d99999bbca244e52b9";

/// The ADR-061 revision 7 vector R7-D1 digest.
const R7_D1_DIGEST: &str = "9df81ceb0d029665c3317e72736385b21af951200babd30cbbfc7d0a8d11e100";

const R7_D1_FEATURES: [&str; 3] = ["runtime", "component-model", "cranelift"];

const R7_D1_CEILINGS: CeilingValuesV1 = CeilingValuesV1 {
    memory_bytes: 67_108_864,
    fuel: 1_000_000_000,
    host_calls: 1_000_000,
    event_bytes: 16_777_216,
    log_bytes: 16_384,
};

fn digest_bytes(hex: &str) -> Result<[u8; 32], String> {
    let bytes: Result<Vec<u8>, String> = (0..hex.len())
        .step_by(2)
        .map(|start| {
            hex.get(start..start + 2)
                .ok_or_else(|| "short hex".to_owned())
                .and_then(|pair| u8::from_str_radix(pair, 16).map_err(|e| e.to_string()))
        })
        .collect();
    bytes?
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("{} digest bytes", bytes.len()))
}

fn row(trap_code: &str, outcome_name: &str) -> Result<TrapTableEntryV1, String> {
    TrapTableEntryV1::from_adr_outcome(trap_code, outcome_name)
        .ok_or_else(|| format!("no row for {trap_code} and {outcome_name}"))
}

fn r7_d1_runtime() -> Result<PinnedComponentRuntimeV1, String> {
    let engine = PinnedEngineConfigV1 {
        max_wasm_stack: 524_288,
        consume_fuel: true,
        epoch_interruption: true,
    };
    let features = R7_D1_FEATURES.map(str::to_owned).to_vec();
    let rows = vec![
        row("OutOfFuel", "FuelExhausted")?,
        row("Interrupt", "OperationalWatchdogStop")?,
        row("UnreachableCodeReached", "unreachable")?,
    ];
    PinnedComponentRuntimeV1::new("fixture-1".to_owned(), features, engine, rows)
        .map_err(|error| format!("{error:?}"))
}

#[test]
fn the_constant_runtime_passes_the_validating_constructor() -> TestResult {
    let constant = pinned_runtime_v1();
    let rebuilt = PinnedComponentRuntimeV1::new(
        constant.wasmtime_version().to_owned(),
        constant.resolved_features().to_vec(),
        constant.engine(),
        constant.trap_table().to_vec(),
    )
    .map_err(|error| format!("{error:?}"))?;
    assert_eq!(constant, rebuilt, "the constant violates its own table");
    assert_eq!(constant.wasmtime_version(), "49.0.2");
    assert_eq!(constant.resolved_features().len(), 6);
    assert_eq!(constant.engine().max_wasm_stack, 524_288);
    assert_eq!(constant.trap_table().len(), 50, "one row per trap code");
    Ok(())
}

#[test]
fn every_constant_row_round_trips_through_its_outcome_name() -> TestResult {
    for entry in pinned_runtime_v1().trap_table() {
        let again = row(&entry.trap_code, entry.outcome.name())?;
        assert_eq!(&again, entry, "{}", entry.trap_code);
    }
    Ok(())
}

#[test]
fn the_constant_profile_digest_is_the_golden_value() -> TestResult {
    let digest = profile_digest_of(CommunityPluginCeilingsV1::V1.values(), pinned_runtime_v1());
    assert_eq!(digest, Some(digest_bytes(CONSTANT_DIGEST)?));
    Ok(())
}

#[test]
fn one_changed_trap_row_changes_the_digest() {
    let values = CommunityPluginCeilingsV1::V1.values();
    let golden = profile_digest_of(values, pinned_runtime_v1());
    let mut outcome = pinned_runtime_v1();
    outcome.trap_table[0].outcome = TrapOutcomeV1::Trap(ComponentTrapClassV1::Other);
    let mut code = pinned_runtime_v1();
    code.trap_table[49].trap_code.push('x');
    for changed in [outcome, code] {
        let digest = profile_digest_of(values, changed);
        assert!(digest.is_some(), "a changed row still has a digest");
        assert_ne!(digest, golden, "a changed row left the digest unchanged");
    }
}

#[test]
fn from_adr_outcome_accepts_every_closed_outcome_name() -> TestResult {
    let pairs = [
        ("UnreachableCodeReached", "unreachable"),
        ("MemoryOutOfBounds", "memory-out-of-bounds"),
        ("TableOutOfBounds", "table-out-of-bounds"),
        ("IndirectCallToNull", "indirect-call"),
        ("IntegerOverflow", "integer-arithmetic"),
        ("StackOverflow", "stack-exhausted"),
        ("NullReference", "other"),
        ("OutOfFuel", "FuelExhausted"),
        ("Interrupt", "OperationalWatchdogStop"),
    ];
    for (trap_code, name) in pairs {
        let entry = row(trap_code, name)?;
        assert_eq!(entry.trap_code, trap_code);
        assert_eq!(entry.outcome.name(), name);
    }
    Ok(())
}

#[test]
fn from_adr_outcome_rejects_a_misclassified_or_unknown_name() {
    let rejected = [
        ("StackOverflow", "other"),
        ("OutOfFuel", "other"),
        ("OutOfFuel", "OperationalWatchdogStop"),
        ("Interrupt", "FuelExhausted"),
        ("NullReference", "unreachable"),
        ("StackOverflow", "stack"),
        ("StackOverflow", "Stack-Exhausted"),
        ("StackOverflow", ""),
    ];
    for (trap_code, name) in rejected {
        assert_eq!(
            TrapTableEntryV1::from_adr_outcome(trap_code, name),
            None,
            "{trap_code} {name}"
        );
    }
}

#[test]
fn profile_digest_of_equals_the_r7_d1_vector() -> TestResult {
    let digest = profile_digest_of(R7_D1_CEILINGS, r7_d1_runtime()?);
    assert_eq!(digest, Some(digest_bytes(R7_D1_DIGEST)?));
    Ok(())
}

#[test]
fn profile_digest_of_refuses_out_of_range_ceilings() -> TestResult {
    let maxima = DeterministicBudgetV1::MAXIMA;
    let refused = [
        CeilingValuesV1 {
            memory_bytes: 1,
            ..R7_D1_CEILINGS
        },
        CeilingValuesV1 {
            memory_bytes: WASM_PAGE_BYTES_V1 + 1,
            ..R7_D1_CEILINGS
        },
        CeilingValuesV1 {
            fuel: 0,
            ..R7_D1_CEILINGS
        },
        CeilingValuesV1 {
            host_calls: maxima.host_calls + 1,
            ..R7_D1_CEILINGS
        },
        CeilingValuesV1 {
            event_bytes: maxima.event_bytes + 1,
            ..R7_D1_CEILINGS
        },
        CeilingValuesV1 {
            log_bytes: maxima.log_bytes + 1,
            ..R7_D1_CEILINGS
        },
    ];
    for ceilings in refused {
        assert_eq!(
            profile_digest_of(ceilings, r7_d1_runtime()?),
            None,
            "{ceilings:?}"
        );
    }
    Ok(())
}

#[test]
fn every_trap_class_is_a_closed_outcome() {
    let classes = [
        ComponentTrapClassV1::Unreachable,
        ComponentTrapClassV1::MemoryOutOfBounds,
        ComponentTrapClassV1::TableOutOfBounds,
        ComponentTrapClassV1::IndirectCall,
        ComponentTrapClassV1::IntegerArithmetic,
        ComponentTrapClassV1::StackExhausted,
        ComponentTrapClassV1::Other,
    ];
    for (index, class) in classes.into_iter().enumerate() {
        assert_eq!(class as usize, index, "{class:?} is out of order");
        assert_eq!(
            TrapOutcomeV1::from_name(class.name()),
            Some(TrapOutcomeV1::Trap(class)),
            "{class:?}"
        );
    }
    // `Other` is the last class, so a class added after it moves its position.
    assert_eq!(ComponentTrapClassV1::Other as usize + 1, classes.len());
    assert_eq!(pinned::CLOSED_OUTCOMES.len(), classes.len() + 2);
}
