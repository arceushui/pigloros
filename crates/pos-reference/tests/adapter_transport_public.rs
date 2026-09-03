use std::error::Error;
use std::ffi::OsString;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;

use ciborium::value::Value;
use pos_reference::adapter_transport::{
    decode_attempt, decode_observation, encode_attempt, encode_observation, TransportError,
};
use pos_reference::evaluator::{
    AdapterError, CaseAttempt, ResourceUsage, SubjectAdapter, SubjectObservation, SubjectResult,
};
use pos_reference::evaluator_protocol::{ProtocolError, SubjectAdapterKind};
use pos_reference::process_adapter::ProcessAdapter;
use pos_reference::profile::{DeterministicBudget, NamespacedFailure};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const fn budget() -> DeterministicBudget {
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

const fn usage() -> ResourceUsage {
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

fn observation_shapes() -> [SubjectObservation; 4] {
    [
        SubjectObservation {
            result: SubjectResult::Output(vec![1]),
            usage: usage(),
        },
        SubjectObservation {
            result: SubjectResult::Failure(NamespacedFailure {
                owner_id: "owner".to_owned(),
                contract_version: "1.0.0".to_owned(),
                code_id: "failure".to_owned(),
            }),
            usage: usage(),
        },
        SubjectObservation {
            result: SubjectResult::Divergence {
                classification: 1,
                first_coordinate: vec![1],
            },
            usage: usage(),
        },
        SubjectObservation {
            result: SubjectResult::Unavailable,
            usage: usage(),
        },
    ]
}

#[test]
fn transport_errors_preserve_public_protocol_failure_classes() {
    assert_eq!(
        TransportError::from(ProtocolError::UnsupportedVersion),
        TransportError::UnsupportedVersion
    );
    assert_eq!(
        TransportError::from(ProtocolError::FieldOutOfBounds),
        TransportError::FieldOutOfBounds
    );
    for error in [
        ProtocolError::InvalidEncoding,
        ProtocolError::NonCanonicalOrder,
        ProtocolError::DigestMismatch,
    ] {
        assert_eq!(TransportError::from(error), TransportError::InvalidEncoding);
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
fn attempt_transport_rejects_each_scalar_and_collection_boundary() {
    for mutation in 0..7 {
        let mut value = attempt();
        match mutation {
            0 => value.case_id = "a".repeat(129),
            1 => value.claim_layer = 7,
            2 => value.family = 7,
            3 => value.mode = 4,
            4 => value.auxiliary = vec![Vec::new(); 65_537],
            5 => value.capability_ids = vec!["capability".to_owned(); 65_537],
            _ => value.capability_ids = vec!["same".to_owned(), "same".to_owned()],
        }
        assert_eq!(
            encode_attempt(&value),
            Err(TransportError::FieldOutOfBounds)
        );
    }
}

#[test]
fn attempt_transport_rejects_wrong_types_at_each_required_field() -> TestResult {
    let valid = attempt_value();
    for index in 0..14 {
        let mut changed = valid.clone();
        replace_field(&mut changed, index, Value::Null)?;
        assert!(decode_attempt(&canonical(&changed)?).is_err());
    }
    let Value::Array(fields) = &valid else {
        return Err("attempt is not an array".into());
    };
    for (field_index, nested_count) in [(9, 2), (10, 8), (13, 2)] {
        for nested_index in 0..nested_count {
            let mut changed = valid.clone();
            let Value::Array(changed_fields) = &mut changed else {
                return Err("attempt is not an array".into());
            };
            let Value::Array(nested) = &mut changed_fields[field_index] else {
                return Err("attempt nested field is not an array".into());
            };
            nested[nested_index] = Value::Null;
            assert!(decode_attempt(&canonical(&changed)?).is_err());
        }
    }
    assert_eq!(fields.len(), 14);
    Ok(())
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

    let oversized_output = SubjectObservation {
        result: SubjectResult::Output(vec![0; 64 * 1024 * 1024 + 1]),
        usage: usage(),
    };
    assert_eq!(
        encode_observation(&oversized_output),
        Err(TransportError::FieldOutOfBounds)
    );

    let invalid_divergence = SubjectObservation {
        result: SubjectResult::Divergence {
            classification: 9,
            first_coordinate: vec![1],
        },
        usage: usage(),
    };
    assert_eq!(
        encode_observation(&invalid_divergence),
        Err(TransportError::FieldOutOfBounds)
    );

    let oversized_coordinate = SubjectObservation {
        result: SubjectResult::Divergence {
            classification: 1,
            first_coordinate: vec![1; 129],
        },
        usage: usage(),
    };
    assert_eq!(
        encode_observation(&oversized_coordinate),
        Err(TransportError::FieldOutOfBounds)
    );

    Ok(())
}

#[test]
fn observation_transport_rejects_each_failure_field_boundary() {
    for mutation in 0..6 {
        let invalid_failure = SubjectObservation {
            result: SubjectResult::Failure(NamespacedFailure {
                owner_id: match mutation {
                    0 => String::new(),
                    1 => "a".repeat(129),
                    _ => "owner".to_owned(),
                },
                contract_version: match mutation {
                    2 => String::new(),
                    3 => "a".repeat(129),
                    _ => "1.0.0".to_owned(),
                },
                code_id: match mutation {
                    4 => String::new(),
                    5 => "a".repeat(129),
                    _ => "failure".to_owned(),
                },
            }),
            usage: usage(),
        };
        assert_eq!(
            encode_observation(&invalid_failure),
            Err(TransportError::FieldOutOfBounds)
        );
    }
}

#[test]
fn observation_transport_rejects_versions_codes_and_field_types() -> TestResult {
    let encoded = encode_observation(&SubjectObservation {
        result: SubjectResult::Output(vec![1]),
        usage: usage(),
    })?;
    let mut value: Value = ciborium::from_reader(encoded.as_slice())?;

    replace_field(&mut value, 0, Value::Text("EAO0".to_owned()))?;
    assert_eq!(
        decode_observation(&canonical(&value)?),
        Err(TransportError::UnsupportedVersion)
    );

    replace_field(&mut value, 0, Value::Text("EAO1".to_owned()))?;
    replace_field(&mut value, 2, Value::Integer(9_u64.into()))?;
    assert_eq!(
        decode_observation(&canonical(&value)?),
        Err(TransportError::InvalidEncoding)
    );

    replace_field(&mut value, 2, Value::Integer(0_u64.into()))?;
    replace_field(&mut value, 3, Value::Null)?;
    assert_eq!(
        decode_observation(&canonical(&value)?),
        Err(TransportError::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn observation_transport_rejects_wrong_types_at_every_public_field() -> TestResult {
    for observation in observation_shapes() {
        let result_field = match &observation.result {
            SubjectResult::Output(_) => Some(3),
            SubjectResult::Failure(_) => Some(4),
            SubjectResult::Divergence { .. } => Some(5),
            SubjectResult::Unavailable => None,
        };
        let encoded = encode_observation(&observation)?;
        let valid: Value = ciborium::from_reader(encoded.as_slice())?;
        for index in [Some(0), Some(1), Some(2), result_field, Some(6)]
            .into_iter()
            .flatten()
        {
            let mut changed = valid.clone();
            replace_field(&mut changed, index, Value::Null)?;
            assert!(decode_observation(&canonical(&changed)?).is_err());
        }

        let Value::Array(fields) = &valid else {
            return Err("observation is not an array".into());
        };
        for usage_index in 0..8 {
            let mut changed = valid.clone();
            let Value::Array(changed_fields) = &mut changed else {
                return Err("observation is not an array".into());
            };
            let Value::Array(usage_fields) = &mut changed_fields[6] else {
                return Err("usage is not an array".into());
            };
            usage_fields[usage_index] = Value::Null;
            assert!(decode_observation(&canonical(&changed)?).is_err());
        }
        assert_eq!(fields.len(), 7);
    }

    let failure = encode_observation(&SubjectObservation {
        result: SubjectResult::Failure(NamespacedFailure {
            owner_id: "owner".to_owned(),
            contract_version: "1.0.0".to_owned(),
            code_id: "failure".to_owned(),
        }),
        usage: usage(),
    })?;
    for field_index in 0..3 {
        let mut changed: Value = ciborium::from_reader(failure.as_slice())?;
        let Value::Array(fields) = &mut changed else {
            return Err("observation is not an array".into());
        };
        let Value::Array(failure_fields) = &mut fields[4] else {
            return Err("failure is not an array".into());
        };
        failure_fields[field_index] = Value::Null;
        assert!(decode_observation(&canonical(&changed)?).is_err());
    }

    let divergence = encode_observation(&SubjectObservation {
        result: SubjectResult::Divergence {
            classification: 1,
            first_coordinate: vec![1],
        },
        usage: usage(),
    })?;
    for field_index in 0..2 {
        let mut changed: Value = ciborium::from_reader(divergence.as_slice())?;
        let Value::Array(fields) = &mut changed else {
            return Err("observation is not an array".into());
        };
        let Value::Array(divergence_fields) = &mut fields[5] else {
            return Err("divergence is not an array".into());
        };
        divergence_fields[field_index] = Value::Null;
        assert!(decode_observation(&canonical(&changed)?).is_err());
    }

    for malformed in [
        &[][..],
        &[0xff][..],
        &[0x80][..],
        &[0x87, 0x64, b'E', b'A', b'O'][..],
    ] {
        assert!(decode_observation(malformed).is_err());
    }
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

#[cfg(unix)]
#[test]
fn process_adapter_keeps_crashes_timeouts_and_bad_frames_operational() -> TestResult {
    let mut operational_attempt = attempt();
    operational_attempt.watchdog_ms = 1_000;
    let mut crashed = ProcessAdapter::new(
        SubjectAdapterKind::ExportedArtifact,
        [1; 32],
        "/bin/false",
        Vec::new(),
    )?;
    assert_eq!(
        crashed.execute(&operational_attempt),
        Err(AdapterError::Unavailable)
    );

    let mut timed_out = ProcessAdapter::new(
        SubjectAdapterKind::ExportedArtifact,
        [1; 32],
        "/bin/sleep",
        vec![OsString::from("1")],
    )?;
    assert_eq!(
        timed_out.execute(&attempt()),
        Err(AdapterError::WatchdogExpired)
    );

    let mut malformed = ProcessAdapter::new(
        SubjectAdapterKind::ExportedArtifact,
        [1; 32],
        "/bin/cat",
        Vec::new(),
    )?;
    assert_eq!(
        malformed.execute(&operational_attempt),
        Err(AdapterError::ProtocolFailure)
    );

    let mut missing = ProcessAdapter::new(
        SubjectAdapterKind::ExportedArtifact,
        [1; 32],
        "/definitely/not/a/subject-adapter",
        Vec::new(),
    )?;
    assert_eq!(
        missing.execute(&operational_attempt),
        Err(AdapterError::Unavailable)
    );

    let mut invalid_attempt = attempt();
    invalid_attempt.case_id.clear();
    assert_eq!(
        malformed.execute(&invalid_attempt),
        Err(AdapterError::ProtocolFailure)
    );

    let mut unrepresentable_response = attempt();
    unrepresentable_response.budget.output_bytes = u64::MAX;
    assert_eq!(
        malformed.execute(&unrepresentable_response),
        Err(AdapterError::ProtocolFailure)
    );

    let mut oversized = ProcessAdapter::new(
        SubjectAdapterKind::ExportedArtifact,
        [1; 32],
        "/usr/bin/head",
        ["-c", "70000", "/dev/zero"].map(OsString::from).to_vec(),
    )?;
    assert_eq!(
        oversized.execute(&operational_attempt),
        Err(AdapterError::ProtocolFailure)
    );

    let expected = SubjectObservation {
        result: SubjectResult::Unavailable,
        usage: usage(),
    };
    let response = encode_observation(&expected)?;
    if response.contains(&0) {
        return Err("test response cannot be represented as a process argument".into());
    }
    let mut successful = ProcessAdapter::new(
        SubjectAdapterKind::ExportedArtifact,
        [1; 32],
        "/bin/sh",
        vec![
            OsString::from("-c"),
            OsString::from("/bin/cat >/dev/null; printf %s \"$1\""),
            OsString::from("adapter"),
            OsString::from_vec(response),
        ],
    )?;
    assert_eq!(successful.execute(&operational_attempt), Ok(expected));
    Ok(())
}

#[cfg(unix)]
#[test]
fn process_adapter_watchdog_terminates_descendants_holding_transport_open() -> TestResult {
    let mut descendant = ProcessAdapter::new(
        SubjectAdapterKind::ExportedArtifact,
        [1; 32],
        "/bin/sh",
        vec![OsString::from("-c"), OsString::from("sleep 30 & exit 0")],
    )?;
    let started = std::time::Instant::now();
    assert_eq!(
        descendant.execute(&attempt()),
        Err(AdapterError::WatchdogExpired)
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn process_adapter_bounds_blocked_request_transport() -> TestResult {
    let mut blocked_request = attempt();
    blocked_request.watchdog_ms = 100;
    blocked_request.payload = vec![0; 1024 * 1024];
    let mut adapter = ProcessAdapter::new(
        SubjectAdapterKind::ExportedArtifact,
        [1; 32],
        "/usr/bin/python3",
        vec![
            OsString::from("-c"),
            OsString::from(
                "import os,time\nif os.fork(): os._exit(0)\nos.close(1)\nos.close(2)\ntime.sleep(30)",
            ),
        ],
    )?;
    assert_eq!(
        adapter.execute(&blocked_request),
        Err(AdapterError::WatchdogExpired)
    );
    Ok(())
}
