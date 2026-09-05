use std::error::Error;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::io;

use ciborium::value::Value;
use pos_reference::adapter_transport::{
    read_attempt, read_observation, write_attempt, write_observation, TransportError,
};
use pos_reference::evaluator::{
    AdapterError, AttemptArtifact, AttemptTransportCaps, CaseAttempt, ResourceUsage,
    SubjectAdapter, SubjectObservation, SubjectResult,
};
use pos_reference::evaluator_protocol::{ProtocolError, SubjectAdapterKind};
use pos_reference::process_adapter::ProcessAdapter;
use pos_reference::profile::{DeterministicBudget, NamespacedFailure};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const ATTEMPT_DOMAIN: &[u8] = b"PiglorOS.EvaluatorAttemptStream.v1\0";
const OBSERVATION_DOMAIN: &[u8] = b"PiglorOS.EvaluatorObservationStream.v1\0";
const CHUNK_BYTES: usize = 64 * 1024;

struct FailAfterWrites {
    successful_writes_remaining: usize,
}

impl io::Write for FailAfterWrites {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.successful_writes_remaining == 0 {
            return Err(io::Error::other("intentional writer failure"));
        }
        self.successful_writes_remaining -= 1;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

const fn budget() -> DeterministicBudget {
    DeterministicBudget {
        memory_bytes: 1,
        cpu_fuel: 2,
        host_calls: 3,
        event_count: 4,
        output_bytes: 128 * 1024,
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

fn artifact(bytes: Vec<u8>) -> AttemptArtifact {
    AttemptArtifact {
        digest: *blake3::hash(&bytes).as_bytes(),
        bytes,
    }
}

fn attempt() -> CaseAttempt {
    CaseAttempt {
        case_id: "case-1".to_owned(),
        claim_layer: 6,
        family: 5,
        mode: 1,
        fixture_digest: [7; 32],
        schema: artifact(vec![1, 2]),
        payload: artifact(vec![3, 4]),
        auxiliary: vec![artifact(vec![5]), artifact(vec![6])],
        budget: budget(),
        watchdog_ms: 250,
        network_allowed: false,
        capability_ids: vec!["alpha".to_owned(), "beta".to_owned()],
        transport_caps: AttemptTransportCaps {
            max_member_bytes: 128 * 1024,
            max_attempt_bytes: 512 * 1024,
        },
    }
}

const fn observation(result: SubjectResult) -> SubjectObservation {
    SubjectObservation {
        result,
        usage: usage(),
    }
}

fn encoded_attempt(value: &CaseAttempt) -> Result<Vec<u8>, TransportError> {
    let mut bytes = Vec::new();
    write_attempt(&mut bytes, value)?;
    Ok(bytes)
}

fn encoded_observation(value: &SubjectObservation) -> Result<Vec<u8>, TransportError> {
    let mut bytes = Vec::new();
    write_observation(&mut bytes, value)?;
    Ok(bytes)
}

fn encode_value(value: &Value) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn framed(value: &Value) -> TestResult<Vec<u8>> {
    let encoded = encode_value(value)?;
    let length = u32::try_from(encoded.len())?;
    let mut frame = length.to_be_bytes().to_vec();
    frame.extend(encoded);
    Ok(frame)
}

fn frame_values(mut bytes: &[u8]) -> TestResult<Vec<Value>> {
    let mut values = Vec::new();
    while !bytes.is_empty() {
        let prefix: [u8; 4] = bytes.get(..4).ok_or("missing frame prefix")?.try_into()?;
        let length = usize::try_from(u32::from_be_bytes(prefix))?;
        let framed = bytes.get(4..).ok_or("missing frame")?;
        let encoded = framed.get(..length).ok_or("truncated frame")?;
        values.push(ciborium::from_reader(encoded)?);
        bytes = &framed[length..];
    }
    Ok(values)
}

fn signed_frames(
    mut values: Vec<Value>,
    domain: &[u8],
    digest_field: usize,
) -> TestResult<Vec<u8>> {
    let terminal = values.pop().ok_or("missing terminal frame")?;
    let mut transcript = blake3::Hasher::new();
    transcript.update(domain);
    let mut bytes = Vec::new();
    for value in values {
        let frame = framed(&value)?;
        transcript.update(&frame);
        bytes.extend(frame);
    }
    let Value::Array(mut fields) = terminal else {
        return Err("terminal frame must be an array".into());
    };
    fields[digest_field] = Value::Bytes(transcript.finalize().as_bytes().to_vec());
    bytes.extend(framed(&Value::Array(fields))?);
    Ok(bytes)
}

fn replace_field(value: &mut Value, index: usize, replacement: Value) -> TestResult {
    let Value::Array(fields) = value else {
        return Err("frame must be an array".into());
    };
    *fields.get_mut(index).ok_or("field missing")? = replacement;
    Ok(())
}

#[test]
fn transport_errors_preserve_public_failure_classes() {
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

#[test]
fn attempt_stream_round_trips_authenticated_artifacts_and_selected_caps() -> TestResult {
    let mut expected = attempt();
    expected.payload = artifact(vec![9; CHUNK_BYTES + 1]);
    let bytes = encoded_attempt(&expected)?;
    let frames = frame_values(&bytes)?;

    assert_eq!(read_attempt(bytes.as_slice()), Ok(expected));
    let Value::Array(start) = &frames[0] else {
        return Err("start frame must be an array".into());
    };
    assert_eq!(start.len(), 14);
    assert_eq!(start[0], Value::Text("EAI1".to_owned()));
    assert_eq!(start[10], Value::Integer(2_u64.into()));
    assert_eq!(start[11], Value::Integer(4_u64.into()));
    assert_eq!(start[12], Value::Integer((128_u64 * 1024).into()));
    assert_eq!(start[13], Value::Integer((512_u64 * 1024).into()));
    assert_eq!(frames.len(), 13);
    Ok(())
}

#[test]
fn attempt_writer_rejects_invalid_public_values() {
    let invalid: [fn(&mut CaseAttempt); 12] = [
        |value: &mut CaseAttempt| value.case_id.clear(),
        |value: &mut CaseAttempt| value.case_id = "a".repeat(129),
        |value: &mut CaseAttempt| value.claim_layer = 7,
        |value: &mut CaseAttempt| value.family = 7,
        |value: &mut CaseAttempt| value.mode = 4,
        |value: &mut CaseAttempt| value.fixture_digest = [0; 32],
        |value: &mut CaseAttempt| value.watchdog_ms = 0,
        |value: &mut CaseAttempt| value.capability_ids.swap(0, 1),
        |value: &mut CaseAttempt| value.capability_ids[0].clear(),
        |value: &mut CaseAttempt| value.budget.memory_bytes = 0,
        |value: &mut CaseAttempt| value.transport_caps.max_member_bytes = 0,
        |value: &mut CaseAttempt| value.transport_caps.max_attempt_bytes = 0,
    ];
    for mutation in invalid {
        let mut value = attempt();
        mutation(&mut value);
        assert_eq!(
            encoded_attempt(&value),
            Err(TransportError::FieldOutOfBounds)
        );
    }

    let mut bad_digest = attempt();
    bad_digest.payload.digest = [8; 32];
    assert_eq!(
        encoded_attempt(&bad_digest),
        Err(TransportError::InvalidEncoding)
    );

    let mut oversized_member = attempt();
    oversized_member.transport_caps.max_member_bytes = 1;
    assert_eq!(
        encoded_attempt(&oversized_member),
        Err(TransportError::FieldOutOfBounds)
    );

    let mut oversized_total = attempt();
    oversized_total.transport_caps.max_attempt_bytes = 2;
    assert_eq!(
        encoded_attempt(&oversized_total),
        Err(TransportError::FieldOutOfBounds)
    );

    let mut oversized_output_authority = attempt();
    oversized_output_authority.budget.output_bytes = 64 * 1024 * 1024 + 1;
    assert_eq!(
        encoded_attempt(&oversized_output_authority),
        Err(TransportError::FieldOutOfBounds)
    );
}

#[test]
fn attempt_writer_reports_capability_frame_failures() {
    let writer = FailAfterWrites {
        successful_writes_remaining: 2,
    };
    assert_eq!(
        write_attempt(writer, &attempt()),
        Err(TransportError::InvalidEncoding)
    );
}

#[test]
fn attempt_reader_rejects_wrong_order_identity_digest_and_trailing_data() -> TestResult {
    let bytes = encoded_attempt(&attempt())?;
    let valid = frame_values(&bytes)?;

    let mut changed = valid.clone();
    replace_field(&mut changed[0], 0, Value::Text("EAI0".to_owned()))?;
    assert_eq!(
        read_attempt(signed_frames(changed, ATTEMPT_DOMAIN, 2)?.as_slice()),
        Err(TransportError::UnsupportedVersion)
    );

    for (field, replacement, expected) in [
        (
            2,
            Value::Text(String::new()),
            TransportError::FieldOutOfBounds,
        ),
        (
            2,
            Value::Text("a".repeat(129)),
            TransportError::FieldOutOfBounds,
        ),
        (
            3,
            Value::Integer(7_u64.into()),
            TransportError::InvalidEncoding,
        ),
        (
            3,
            Value::Integer(256_u64.into()),
            TransportError::InvalidEncoding,
        ),
    ] {
        let mut changed = valid.clone();
        replace_field(&mut changed[0], field, replacement)?;
        assert_eq!(
            read_attempt(signed_frames(changed, ATTEMPT_DOMAIN, 2)?.as_slice()),
            Err(expected)
        );
    }

    let mut changed = valid.clone();
    changed.swap(1, 2);
    assert_eq!(
        read_attempt(signed_frames(changed, ATTEMPT_DOMAIN, 2)?.as_slice()),
        Err(TransportError::InvalidEncoding)
    );

    let mut changed = valid.clone();
    replace_field(&mut changed[3], 2, Value::Integer(1_u64.into()))?;
    assert!(read_attempt(signed_frames(changed, ATTEMPT_DOMAIN, 2)?.as_slice()).is_err());

    let mut changed = valid;
    replace_field(&mut changed[4], 5, Value::Bytes(vec![8; 2]))?;
    assert_eq!(
        read_attempt(signed_frames(changed, ATTEMPT_DOMAIN, 2)?.as_slice()),
        Err(TransportError::InvalidEncoding)
    );

    let mut changed = frame_values(&bytes)?;
    replace_field(&mut changed[4], 5, Value::Text("not-bytes".to_owned()))?;
    assert_eq!(
        read_attempt(signed_frames(changed, ATTEMPT_DOMAIN, 2)?.as_slice()),
        Err(TransportError::InvalidEncoding)
    );

    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        read_attempt(trailing.as_slice()),
        Err(TransportError::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn attempt_reader_preflights_every_frame_before_allocation_or_decode() -> TestResult {
    for malformed in [
        Vec::new(),
        vec![0, 0, 0, 0],
        vec![0, 2, 0, 1],
        vec![0, 0, 0, 2, 0x81],
        vec![0, 0, 0, 1, 0xff],
    ] {
        assert!(read_attempt(malformed.as_slice()).is_err());
    }

    let deeply_nested = Value::Array(vec![Value::Array(vec![Value::Array(vec![Value::Array(
        vec![Value::Array(vec![Value::Integer(0_u64.into())])],
    )])])]);
    let deep_frame = framed(&deeply_nested)?;
    assert_eq!(
        read_attempt(deep_frame.as_slice()),
        Err(TransportError::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn observation_stream_round_trips_every_terminal_result() -> TestResult {
    let results = [
        SubjectResult::Output(vec![3; CHUNK_BYTES + 1]),
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
        let expected = observation(result);
        let encoded = encoded_observation(&expected)?;
        assert_eq!(
            read_observation(encoded.as_slice(), 128 * 1024),
            Ok(expected)
        );
    }
    Ok(())
}

#[test]
fn observation_reader_discards_provisional_output_for_non_output_terminal() -> TestResult {
    let output = observation(SubjectResult::Output(vec![1, 2, 3]));
    let mut values = frame_values(&encoded_observation(&output)?)?;
    let terminal = values.last_mut().ok_or("terminal missing")?;
    replace_field(terminal, 2, Value::Integer(3_u64.into()))?;
    replace_field(terminal, 3, Value::Null)?;
    replace_field(terminal, 4, Value::Null)?;
    let encoded = signed_frames(values, OBSERVATION_DOMAIN, 8)?;

    assert_eq!(
        read_observation(encoded.as_slice(), 10),
        Ok(observation(SubjectResult::Unavailable))
    );
    Ok(())
}

#[test]
fn observation_transport_rejects_selected_bounds_and_invalid_results() -> TestResult {
    let encoded = encoded_observation(&observation(SubjectResult::Output(vec![1, 2])))?;
    assert_eq!(
        read_observation(encoded.as_slice(), 1),
        Err(TransportError::FieldOutOfBounds)
    );
    assert_eq!(
        read_observation(encoded.as_slice(), 0),
        Err(TransportError::FieldOutOfBounds)
    );
    assert_eq!(
        read_observation(encoded.as_slice(), 64 * 1024 * 1024 + 1),
        Err(TransportError::FieldOutOfBounds)
    );

    for result in [
        SubjectResult::Divergence {
            classification: 9,
            first_coordinate: vec![1],
        },
        SubjectResult::Divergence {
            classification: 1,
            first_coordinate: Vec::new(),
        },
        SubjectResult::Divergence {
            classification: 1,
            first_coordinate: vec![1; 129],
        },
        SubjectResult::Failure(NamespacedFailure {
            owner_id: String::new(),
            contract_version: "1".to_owned(),
            code_id: "code".to_owned(),
        }),
    ] {
        assert_eq!(
            encoded_observation(&observation(result)),
            Err(TransportError::FieldOutOfBounds)
        );
    }
    Ok(())
}

#[test]
fn observation_reader_rejects_tampering_bad_offsets_and_nonexclusive_results() -> TestResult {
    let bytes = encoded_observation(&observation(SubjectResult::Output(vec![1, 2])))?;
    let valid = frame_values(&bytes)?;

    let mut changed = valid.clone();
    replace_field(&mut changed[0], 0, Value::Text("EAO0".to_owned()))?;
    assert_eq!(
        read_observation(
            signed_frames(changed, OBSERVATION_DOMAIN, 8)?.as_slice(),
            10
        ),
        Err(TransportError::UnsupportedVersion)
    );

    let mut changed = valid.clone();
    replace_field(&mut changed[1], 2, Value::Integer(1_u64.into()))?;
    assert_eq!(
        read_observation(
            signed_frames(changed, OBSERVATION_DOMAIN, 8)?.as_slice(),
            10
        ),
        Err(TransportError::InvalidEncoding)
    );

    let mut changed = valid;
    replace_field(&mut changed[2], 5, Value::Array(Vec::new()))?;
    assert_eq!(
        read_observation(
            signed_frames(changed, OBSERVATION_DOMAIN, 8)?.as_slice(),
            10
        ),
        Err(TransportError::InvalidEncoding)
    );

    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        read_observation(trailing.as_slice(), 10),
        Err(TransportError::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn process_adapter_requires_an_absolute_executable() {
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
fn process_adapter_preserves_lifecycle_failure_precedence() -> TestResult {
    let mut operational = attempt();
    operational.watchdog_ms = 1_000;
    let mut crashed = ProcessAdapter::new(
        SubjectAdapterKind::ExportedArtifact,
        [1; 32],
        "/bin/false",
        Vec::new(),
    )?;
    assert_eq!(
        crashed.execute(&operational),
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
        malformed.execute(&operational),
        Err(AdapterError::ProtocolFailure)
    );

    let mut missing = ProcessAdapter::new(
        SubjectAdapterKind::ExportedArtifact,
        [1; 32],
        "/definitely/not/an/adapter",
        Vec::new(),
    )?;
    assert_eq!(
        missing.execute(&operational),
        Err(AdapterError::Unavailable)
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn process_adapter_streams_a_successful_observation() -> TestResult {
    let mut operational = attempt();
    operational.watchdog_ms = 1_000;
    let expected = observation(SubjectResult::Unavailable);
    let response = encoded_observation(&expected)?;
    let mut escaped = String::with_capacity(response.len() * 4);
    for byte in response {
        write!(&mut escaped, "\\{byte:03o}")?;
    }
    let mut adapter = ProcessAdapter::new(
        SubjectAdapterKind::ExportedArtifact,
        [1; 32],
        "/bin/sh",
        vec![
            OsString::from("-c"),
            OsString::from("/bin/cat >/dev/null; /usr/bin/printf %b \"$1\""),
            OsString::from("adapter"),
            OsString::from(escaped),
        ],
    )?;

    assert_eq!(adapter.execute(&operational), Ok(expected));
    Ok(())
}

#[cfg(unix)]
#[test]
fn process_adapter_watchdog_terminates_descendants_holding_pipes_open() -> TestResult {
    let mut adapter = ProcessAdapter::new(
        SubjectAdapterKind::ExportedArtifact,
        [1; 32],
        "/bin/sh",
        vec![OsString::from("-c"), OsString::from("sleep 30 & exit 0")],
    )?;
    let started = std::time::Instant::now();
    assert_eq!(
        adapter.execute(&attempt()),
        Err(AdapterError::WatchdogExpired)
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn process_adapter_bounds_a_blocked_request_stream() -> TestResult {
    let mut blocked = attempt();
    blocked.watchdog_ms = 100;
    blocked.payload = artifact(vec![0; CHUNK_BYTES * 2]);
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
        adapter.execute(&blocked),
        Err(AdapterError::WatchdogExpired)
    );
    Ok(())
}
