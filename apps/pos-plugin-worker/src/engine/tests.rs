use pos_crypto::plugin_execution::DeterministicBudgetV1;
use pos_crypto::plugin_worker_ipc::WorkerNegotiationV1;

use super::*;

const RUST_GUEST: &[u8] = include_bytes!(
    "../../../../plugins/community/examples/compatibility-prototype/fixtures/rust-guest.wasm"
);
const C_GUEST: &[u8] = include_bytes!(
    "../../../../plugins/community/examples/compatibility-prototype/fixtures/c-guest.wasm"
);

fn request(
    component: &[u8],
    export: WorkerExportV1,
    limits: DeterministicBudgetV1,
) -> WorkerRequestV1 {
    WorkerRequestV1 {
        export,
        component: component.to_vec(),
        negotiation: WorkerNegotiationV1 {
            world: "pigloros:plugin/community-plugin@0.1.0".to_owned(),
            abi_major: 0,
            abi_minor: 0,
            required_features: Vec::new(),
            pmf1_digest: [1; 32],
            release_digest: [2; 32],
        },
        limits,
        simulation_time: 42,
        invocation: Vec::new(),
    }
}

const ROOMY: DeterministicBudgetV1 = DeterministicBudgetV1 {
    memory_bytes: 64 * 1_048_576,
    fuel: 100_000_000,
    ..DeterministicBudgetV1::MAXIMA
};

fn run_request(request: &WorkerRequestV1) -> Option<WorkerOutcomeV1> {
    invoke(request)
}

fn integer(value: u64) -> Value {
    Value::Integer(value.into())
}

fn bytes(value: &[u8]) -> Value {
    Value::Array(value.iter().map(|byte| integer(u64::from(*byte))).collect())
}

fn record(value: &[u8]) -> Value {
    Value::Array(vec![bytes(value)])
}

fn expected_descriptor() -> Vec<u8> {
    let descriptor = Value::Array(vec![
        record(b"pigloros.compatibility-prototype"),
        record(b"0.1.0"),
        record(b"pigloros:plugin/community-plugin@0.1.0"),
        integer(0),
        integer(1),
        integer(1),
        Value::Array(Vec::new()),
        Value::Array(vec![record(&[1; 32])]),
        record(&[2; 32]),
        Value::Array(Vec::new()),
        Value::Array(Vec::new()),
        Value::Array(Vec::new()),
        record(&[0; 32]),
        record(&[0; 32]),
    ]);
    let mut out = Vec::new();
    let encoded = ciborium::into_writer(&Value::Array(vec![integer(0), descriptor]), &mut out);
    assert!(encoded.is_ok());
    out
}

#[test]
fn both_guests_describe_the_same_plugin() {
    for guest in [RUST_GUEST, C_GUEST] {
        let outcome = run_request(&request(guest, WorkerExportV1::Describe, ROOMY));
        let Some(WorkerOutcomeV1::Completed(completion)) = outcome else {
            std::panic::resume_unwind(Box::new(format!("{outcome:?}")));
        };
        assert_eq!(completion.payload, expected_descriptor());
        assert!(completion.call_fuel > 0);
        assert!(completion.memory_bytes > 0);
    }
}

#[test]
fn inputs_the_prototype_engine_cannot_lower_are_invalid_invocations() {
    let invalid = Some(WorkerOutcomeV1::Failed(WorkerFailureV1::InvalidInvocation));
    for export in [WorkerExportV1::Reduce, WorkerExportV1::Drive] {
        assert_eq!(run_request(&request(RUST_GUEST, export, ROOMY)), invalid);
    }
    let mut with_input = request(RUST_GUEST, WorkerExportV1::Describe, ROOMY);
    with_input.invocation = b"input".to_vec();
    assert_eq!(run_request(&with_input), invalid);
}

#[test]
fn bytes_that_do_not_implement_the_world_are_incompatible() {
    let outcome = run_request(&request(
        b"not a component",
        WorkerExportV1::Describe,
        ROOMY,
    ));
    assert_eq!(
        outcome,
        Some(WorkerOutcomeV1::Failed(WorkerFailureV1::IncompatibleAbi))
    );
}

#[test]
fn budgets_bound_the_prototype_engine() {
    let starved = DeterministicBudgetV1 { fuel: 1, ..ROOMY };
    let small = DeterministicBudgetV1 {
        memory_bytes: 65_536,
        ..ROOMY
    };
    for (limits, failure) in [
        (starved, WorkerFailureV1::FuelExhausted),
        (small, WorkerFailureV1::MemoryLimitExceeded),
    ] {
        let outcome = run_request(&request(RUST_GUEST, WorkerExportV1::Describe, limits));
        assert_eq!(outcome, Some(WorkerOutcomeV1::Failed(failure)));
    }
}

#[test]
fn prototype_failures_map_to_closed_outcomes() {
    for (failure, expected) in [
        (
            InvocationFailure::FuelExhausted,
            WorkerFailureV1::FuelExhausted,
        ),
        (
            InvocationFailure::MemoryLimitExceeded,
            WorkerFailureV1::MemoryLimitExceeded,
        ),
        (
            InvocationFailure::OperationalWatchdogStop,
            WorkerFailureV1::OperationalWatchdogStop,
        ),
        (
            InvocationFailure::HostCallRejected,
            WorkerFailureV1::HostCallLimitExceeded,
        ),
        (
            InvocationFailure::Rejected,
            WorkerFailureV1::InvalidInvocation,
        ),
    ] {
        assert_eq!(failure_outcome(failure), WorkerOutcomeV1::Failed(expected));
    }
    assert_eq!(
        failure_outcome(InvocationFailure::ComponentTrap(Trap::StackOverflow)),
        WorkerOutcomeV1::Trapped(WorkerTrapClassV1::StackExhausted)
    );
}

#[test]
fn trap_codes_follow_the_revision_4_table() {
    for (trap, class) in [
        (Trap::UnreachableCodeReached, WorkerTrapClassV1::Unreachable),
        (
            Trap::MemoryOutOfBounds,
            WorkerTrapClassV1::MemoryOutOfBounds,
        ),
        (Trap::HeapMisaligned, WorkerTrapClassV1::MemoryOutOfBounds),
        (Trap::ArrayOutOfBounds, WorkerTrapClassV1::MemoryOutOfBounds),
        (Trap::TableOutOfBounds, WorkerTrapClassV1::TableOutOfBounds),
        (Trap::IndirectCallToNull, WorkerTrapClassV1::IndirectCall),
        (Trap::BadSignature, WorkerTrapClassV1::IndirectCall),
        (Trap::IntegerOverflow, WorkerTrapClassV1::IntegerArithmetic),
        (
            Trap::IntegerDivisionByZero,
            WorkerTrapClassV1::IntegerArithmetic,
        ),
        (
            Trap::BadConversionToInteger,
            WorkerTrapClassV1::IntegerArithmetic,
        ),
        (Trap::StackOverflow, WorkerTrapClassV1::StackExhausted),
        (Trap::NullReference, WorkerTrapClassV1::Other),
        (Trap::CannotEnterComponent, WorkerTrapClassV1::Other),
    ] {
        assert_eq!(trap_class(trap), class, "{trap:?}");
    }
}

fn encoded(value: &Value) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).ok().map(|()| out)
}

#[test]
fn lifted_values_encode_structurally() {
    let boxed = |value: Val| Some(Box::new(value));
    for (value, expected) in [
        (Val::Bool(true), Value::Bool(true)),
        (Val::U8(1), integer(1)),
        (Val::U16(300), integer(300)),
        (Val::U32(70_000), integer(70_000)),
        (Val::U64(u64::MAX), integer(u64::MAX)),
        (
            Val::Enum("reduce".to_owned()),
            Value::Text("reduce".to_owned()),
        ),
        (
            Val::Variant("case".to_owned(), boxed(Val::U8(2))),
            Value::Array(vec![Value::Text("case".to_owned()), integer(2)]),
        ),
        (
            Val::Variant("bare".to_owned(), None),
            Value::Array(vec![Value::Text("bare".to_owned())]),
        ),
        (Val::Option(None), Value::Null),
        (
            Val::Option(boxed(Val::U8(3))),
            Value::Array(vec![integer(3)]),
        ),
        (Val::Result(Ok(None)), Value::Array(vec![integer(0)])),
        (
            Val::Result(Err(boxed(Val::U8(4)))),
            Value::Array(vec![integer(1), integer(4)]),
        ),
        (
            Val::Record(vec![
                ("a".to_owned(), Val::U8(5)),
                ("b".to_owned(), Val::Bool(false)),
            ]),
            Value::Array(vec![integer(5), Value::Bool(false)]),
        ),
        (Val::List(vec![Val::U8(6)]), Value::Array(vec![integer(6)])),
    ] {
        assert_eq!(encode_value(&value), encoded(&expected), "{value:?}");
    }
}

#[test]
fn kinds_outside_the_world_are_not_encoded() {
    for value in [
        Val::String("text".to_owned()),
        Val::S32(-1),
        Val::List(vec![Val::U8(1), Val::Float64(1.0)]),
        Val::Record(vec![("a".to_owned(), Val::Char('x'))]),
        Val::Variant("case".to_owned(), Some(Box::new(Val::S8(1)))),
        Val::Option(Some(Box::new(Val::S16(1)))),
        Val::Result(Ok(Some(Box::new(Val::S64(1))))),
    ] {
        assert_eq!(encode_value(&value), None, "{value:?}");
    }
    let report = InvocationReport {
        value: Val::String("text".to_owned()),
        startup_fuel: 1,
        call_fuel: 2,
        memory_bytes: 3,
        operational_log: Vec::new(),
    };
    assert_eq!(
        completion(&report),
        WorkerOutcomeV1::Failed(WorkerFailureV1::InvalidGuestOutput)
    );
}
