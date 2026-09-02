use std::error::Error;
use std::ffi::OsString;

use ciborium::value::Value;
use pos_reference::adapter_transport::{
    decode_attempt, decode_observation, encode_attempt, encode_observation, TransportError,
};
use pos_reference::evaluator::{
    AdapterError, CaseAttempt, ResourceUsage, SubjectObservation, SubjectResult,
};
use pos_reference::evaluator_protocol::SubjectAdapterKind;
use pos_reference::process_adapter::ProcessAdapter;
use pos_reference::profile::{DeterministicBudget, NamespacedFailure};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn budget() -> DeterministicBudget {
    DeterministicBudget {
        memory_bytes: 1,
        cpu_fuel: 2,
        host_calls: 3,
        event_count: 4,
        output_bytes: 5,
        storage_bytes: 6,
        execution_steps: 7,
        simulation_time_ns: 8,
    }
}

fn usage() -> ResourceUsage {
    ResourceUsage {
        memory_bytes: 8,
        cpu_fuel: 7,
        host_calls: 6,
        event_count: 5,
        output_bytes: 4,
        storage_bytes: 3,
        execution_steps: 2,
        simulation_time_ns: 1,
    }
}

fn attempt() -> CaseAttempt {
    CaseAttempt {
        case_id: "case-1".to_owned(),
        claim_layer: 6,
        family: 5,
        mode: 1,
        fixture_digest: [7; 32],
        schema: vec![1, 2],
        payload: vec![3, 4],
        auxiliary: vec![vec![5], vec![6]],
        budget: budget(),
        watchdog_ms: 25,
        network_allowed: false,
        capability_ids: vec!["alpha".to_owned(), "beta".to_owned()],
    }
}

fn canonical(value: &Value) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn replace_field(value: &mut Value, index: usize, replacement: Value) -> TestResult {
    let Value::Array(fields) = value else {
        return Err("test value is not an array".into());
    };
    let field = fields
        .get_mut(index)
        .ok_or("test field index is out of bounds")?;
    *field = replacement;
    Ok(())
}

fn attempt_value() -> Value {
    Value::Array(vec![
        Value::Text("EAI1".to_owned()),
        Value::Integer(1_u64.into()),
        Value::Text("case-1".to_owned()),
        Value::Integer(6_u64.into()),
        Value::Integer(5_u64.into()),
        Value::Integer(1_u64.into()),
        Value::Bytes(vec![7; 32]),
        Value::Bytes(vec![1, 2]),
        Value::Bytes(vec![3, 4]),
        Value::Array(vec![Value::Bytes(vec![5]), Value::Bytes(vec![6])]),
        Value::Array(
            (1_u64..=8)
                .map(|value| Value::Integer(value.into()))
                .collect(),
        ),
        Value::Integer(25_u64.into()),
        Value::Bool(false),
        Value::Array(vec![
            Value::Text("alpha".to_owned()),
            Value::Text("beta".to_owned()),
        ]),
    ])
}

#[test]
fn attempt_transport_round_trips_the_exact_public_contract() -> TestResult {
    let expected = attempt();
    let bytes = encode_attempt(&expected)?;

    assert_eq!(bytes, canonical(&attempt_value())?);
    assert_eq!(decode_attempt(&bytes), Ok(expected));
    Ok(())
}

#[test]
fn attempt_transport_rejects_each_bounded_identity_failure() {
    let mut value = attempt();
    value.case_id.clear();
    assert_eq!(
        encode_attempt(&value),
        Err(TransportError::FieldOutOfBounds)
    );

    let mut value = attempt();
    value.fixture_digest = [0; 32];
    assert_eq!(
        encode_attempt(&value),
        Err(TransportError::FieldOutOfBounds)
    );

    let mut value = attempt();
    value.watchdog_ms = 0;
    assert_eq!(
        encode_attempt(&value),
        Err(TransportError::FieldOutOfBounds)
    );

    let mut value = attempt();
    value.capability_ids.swap(0, 1);
    assert_eq!(
        encode_attempt(&value),
        Err(TransportError::FieldOutOfBounds)
    );
}

#[test]
fn attempt_transport_rejects_wrong_versions_shapes_types_and_codes() -> TestResult {
    let mut value = attempt_value();
    replace_field(&mut value, 0, Value::Text("EAI0".to_owned()))?;
    assert_eq!(
        decode_attempt(&canonical(&value)?),
        Err(TransportError::UnsupportedVersion)
    );

    replace_field(&mut value, 0, Value::Text("EAI1".to_owned()))?;
    replace_field(&mut value, 3, Value::Integer(7_u64.into()))?;
    assert_eq!(
        decode_attempt(&canonical(&value)?),
        Err(TransportError::InvalidEncoding)
    );

    replace_field(&mut value, 3, Value::Integer(6_u64.into()))?;
    replace_field(
        &mut value,
        10,
        Value::Array(vec![Value::Integer(0_u64.into()); 8]),
    )?;
    assert_eq!(
        decode_attempt(&canonical(&value)?),
        Err(TransportError::FieldOutOfBounds)
    );

    replace_field(
        &mut value,
        10,
        Value::Array(
            (1_u64..=8)
                .map(|item| Value::Integer(item.into()))
                .collect(),
        ),
    )?;
    replace_field(&mut value, 12, Value::Null)?;
    assert_eq!(
        decode_attempt(&canonical(&value)?),
        Err(TransportError::InvalidEncoding)
    );

    assert_eq!(
        decode_attempt(&[0xff]),
        Err(TransportError::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn transport_preflights_untrusted_cbor_before_decoding() {
    let oversized_bytes = [0x5a, 0xff, 0xff, 0xff, 0xff];
    assert_eq!(
        decode_attempt(&oversized_bytes),
        Err(TransportError::FieldOutOfBounds)
    );

    let mut excessive_depth = vec![0x81; 66];
    excessive_depth.push(0x00);
    assert_eq!(
        decode_attempt(&excessive_depth),
        Err(TransportError::FieldOutOfBounds)
    );

    for malformed in [
        &[0x98][..],
        &[0x9f, 0xff][..],
        &[0xa0][..],
        &[0x80, 0x00][..],
        &[0x98, 0x00][..],
    ] {
        assert_eq!(
            decode_attempt(malformed),
            Err(TransportError::InvalidEncoding)
        );
    }
}

#[test]
fn observation_transport_round_trips_every_closed_result() -> TestResult {
    let results = [
        SubjectResult::Output(vec![1, 2, 3]),
        SubjectResult::Failure(NamespacedFailure {
            owner_id: "owner".to_owned(),
            contract_version: "1.2.3".to_owned(),
            code_id: "denied".to_owned(),
        }),
        SubjectResult::Divergence {
            classification: 6,
            first_coordinate: vec![4, 5],
        },
        SubjectResult::Unavailable,
    ];
    for result in results {
        let expected = SubjectObservation {
            result,
            usage: usage(),
        };
        let encoded = encode_observation(&expected)?;
        assert_eq!(decode_observation(&encoded), Ok(expected));
    }
    Ok(())
}

#[test]
fn observation_transport_rejects_nonexclusive_or_unbounded_results() -> TestResult {
    let invalid_union = Value::Array(vec![
        Value::Text("EAO1".to_owned()),
        Value::Integer(1_u64.into()),
        Value::Integer(0_u64.into()),
        Value::Bytes(vec![1]),
        Value::Array(vec![]),
        Value::Null,
        Value::Array(vec![Value::Integer(0_u64.into()); 8]),
    ]);
    assert_eq!(
        decode_observation(&canonical(&invalid_union)?),
        Err(TransportError::InvalidEncoding)
    );

    let empty_coordinate = SubjectObservation {
        result: SubjectResult::Divergence {
            classification: 0,
            first_coordinate: Vec::new(),
        },
        usage: usage(),
    };
    assert_eq!(
        encode_observation(&empty_coordinate),
        Err(TransportError::FieldOutOfBounds)
    );

    let invalid_failure = SubjectObservation {
        result: SubjectResult::Failure(NamespacedFailure {
            owner_id: String::new(),
            contract_version: "1.0.0".to_owned(),
            code_id: "failure".to_owned(),
        }),
        usage: usage(),
    };
    assert_eq!(
        encode_observation(&invalid_failure),
        Err(TransportError::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn process_adapter_requires_an_absolute_subject_executable() {
    assert_eq!(
        ProcessAdapter::new(
            SubjectAdapterKind::ExportedArtifact,
            [1; 32],
            "relative-adapter",
            Vec::<OsString>::new(),
        ),
        Err(AdapterError::ProtocolFailure)
    );
}
