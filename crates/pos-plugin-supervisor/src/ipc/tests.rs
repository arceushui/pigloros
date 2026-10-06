use pos_runtime::community_plugin_host::{
    FieldRefV1, GuestPluginErrorV1, MeteringV1, PluginErrorCodeV1,
};

use super::*;
use crate::fixtures::{descriptor, invocation, log, negotiated, ok, output, METERING};

type Error = CommunityPluginHostErrorV1;

fn request(call: WorkerCallV1) -> WorkerRequestV1 {
    WorkerRequestV1 {
        component: b"component".to_vec(),
        negotiation: negotiated().to_transport(),
        watchdog_millis: 60_000,
        host_inputs: HostInputs {
            simulation_time: 42,
        },
        call,
    }
}

fn round_trip_request(request: &WorkerRequestV1) -> Decoded<WorkerRequestV1> {
    encode_worker_request_v1(request).and_then(|bytes| decode_worker_request_v1(&bytes))
}

#[test]
fn requests_round_trip_every_call_and_mode() {
    for call in [
        WorkerCallV1::Describe,
        WorkerCallV1::Reduce(invocation()),
        WorkerCallV1::Drive(invocation()),
    ] {
        let original = request(call);
        assert_eq!(round_trip_request(&original).as_ref(), Ok(&original));
    }
    let mut air_gapped = request(WorkerCallV1::Describe);
    air_gapped.negotiation.mode = CommunityPluginModeV1::AirGapped;
    air_gapped.negotiation.required_features = vec!["alpha".to_owned(), "beta".to_owned()];
    air_gapped.negotiation.declared_minors = (3, 300);
    assert_eq!(round_trip_request(&air_gapped).as_ref(), Ok(&air_gapped));
}

#[test]
fn every_head_width_is_written_in_shortest_form() {
    for (value, length) in [
        (0, 1),
        (23, 1),
        (24, 2),
        (255, 2),
        (256, 3),
        (65_535, 3),
        (65_536, 5),
        (4_294_967_295, 5),
        (4_294_967_296, 9),
        (u64::MAX, 9),
    ] {
        let mut writer = Writer::default();
        writer.unsigned(value);
        assert_eq!(writer.bytes.len(), length, "{value}");
        let mut original = request(WorkerCallV1::Describe);
        original.watchdog_millis = value;
        assert_eq!(round_trip_request(&original).as_ref(), Ok(&original), "{value}");
    }
}

#[test]
fn the_describe_request_has_its_golden_prefix_and_suffix() {
    let bytes = ok(encode_worker_request_v1(&request(WorkerCallV1::Describe)));
    let mut prefix = vec![0x87, 0x64];
    prefix.extend_from_slice(b"PWQ1");
    prefix.extend_from_slice(&[0x01, 0x49]);
    prefix.extend_from_slice(b"component");
    prefix.extend_from_slice(&[0x8b, 0x78, 0x26]);
    prefix.extend_from_slice(b"pigloros:plugin/community-plugin@0.1.0");
    assert!(bytes.starts_with(&prefix));
    let suffix = [0x19, 0xea, 0x60, 0x18, 0x2a, 0x81, 0x00];
    assert!(bytes.ends_with(&suffix));
    let capability_and_mode = [
        0x81, 0x89, 0x64, b'r', b'e', b'a', b'd', 0x63, b'g', b'e', b't', 0x61, b'*', 0x64,
        b't', b'e', b's', b't', 0x65, b'l', b'o', b'c', b'a', b'l', 0xf4, 0x01, 0x02, 0x03,
        0x00, 0x88,
    ];
    assert!(bytes
        .windows(capability_and_mode.len())
        .any(|window| window == capability_and_mode));
}

#[test]
fn requests_beyond_the_decoder_bounds_are_not_encoded() {
    let mut largest = request(WorkerCallV1::Describe);
    largest.component = vec![0; MAX_WORKER_COMPONENT_BYTES_V1];
    assert!(round_trip_request(&largest).is_ok());
    let mut oversized = largest;
    oversized.component.push(0);
    assert_eq!(encode_worker_request_v1(&oversized), Err(WorkerEnvelopeErrorV1));
    let mut long_world = request(WorkerCallV1::Describe);
    long_world.negotiation.world = "w".repeat(MAX_TEXT_BYTES + 1);
    assert_eq!(encode_worker_request_v1(&long_world), Err(WorkerEnvelopeErrorV1));
    let mut long_pattern = request(WorkerCallV1::Describe);
    long_pattern.negotiation.not_granted_capabilities[0].resource_pattern =
        "p".repeat(MAX_PATTERN_BYTES);
    assert!(round_trip_request(&long_pattern).is_ok());
    long_pattern.negotiation.not_granted_capabilities[0]
        .resource_pattern
        .push('p');
    assert_eq!(encode_worker_request_v1(&long_pattern), Err(WorkerEnvelopeErrorV1));
    let mut long_observation = invocation();
    long_observation.observation_bytes = vec![0; 1_048_577];
    let observed = request(WorkerCallV1::Reduce(long_observation));
    assert_eq!(encode_worker_request_v1(&observed), Err(WorkerEnvelopeErrorV1));
}

/// The encoded request with the call replaced by `call`.
fn with_call(call: &[u8]) -> Vec<u8> {
    let bytes = ok(encode_worker_request_v1(&request(WorkerCallV1::Describe)));
    [&bytes[..bytes.len() - 2], call].concat()
}

#[test]
fn malformed_requests_are_envelope_faults() {
    assert!(decode_worker_request_v1(&with_call(&[0x81, 0x00])).is_ok());
    for (index, call) in [
        &[0x82, 0x00, 0x00][..],
        &[0x81, 0x01],
        &[0x81, 0x03],
        &[0x80],
    ]
    .iter()
    .enumerate()
    {
        assert_eq!(
            decode_worker_request_v1(&with_call(call)),
            Err(WorkerEnvelopeErrorV1),
            "call {index}"
        );
    }
    let valid = ok(encode_worker_request_v1(&request(WorkerCallV1::Describe)));
    let mut wrong_magic = valid.clone();
    wrong_magic[5] = b'R';
    let mut wrong_version = valid.clone();
    wrong_version[6] = 0x02;
    let mut wrong_count = valid.clone();
    wrong_count[0] = 0x86;
    // The mode is the only `0x00` directly before the eight-limit array.
    let mode_at = valid
        .windows(2)
        .position(|pair| pair == [0x00, 0x88])
        .unwrap_or_default();
    let mut unknown_mode = valid.clone();
    unknown_mode[mode_at] = 0x02;
    for (index, bytes) in [
        wrong_magic,
        wrong_version,
        wrong_count,
        unknown_mode,
        [valid.as_slice(), &[0]].concat(),
        valid[..valid.len() - 1].to_vec(),
    ]
    .iter()
    .enumerate()
    {
        assert_eq!(decode_worker_request_v1(bytes), Err(WorkerEnvelopeErrorV1), "case {index}");
    }
    let mut air_gapped = valid;
    air_gapped[mode_at] = 0x01;
    let decoded = decode_worker_request_v1(&air_gapped).map(|r| r.negotiation.mode);
    assert_eq!(decoded, Ok(CommunityPluginModeV1::AirGapped));
}

fn guest_errors() -> Vec<GuestPluginErrorV1> {
    let field = FieldRefV1 {
        schema_id: 70_000,
        field_ordinal: 300,
    };
    [
        PluginErrorCodeV1::InvalidInvocation(field),
        PluginErrorCodeV1::UnsupportedSchema(7),
        PluginErrorCodeV1::CapabilityRequired("net".to_owned()),
        PluginErrorCodeV1::DependencyMissing([3; 32]),
        PluginErrorCodeV1::DeterministicBudgetExhausted,
        PluginErrorCodeV1::InvalidState(field),
        PluginErrorCodeV1::MigrationRejected(field),
        PluginErrorCodeV1::GuestDeclaredFailure(65_535),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, code)| GuestPluginErrorV1 {
        code,
        canonical_coordinate: (index % 2 == 0).then(|| vec![1, 2]),
        related_digest: (index % 3 == 0).then_some([4; 32]),
    })
    .collect()
}

fn described(result: GuestReturnV1<PluginDescriptorV1>) -> WorkerOutcomeV1 {
    Ok(WorkerReturnV1::Described(InvocationReportV1 {
        result,
        metering: METERING,
        operational_log: log(),
    }))
}

fn produced(result: GuestReturnV1<PluginOutputV1>) -> WorkerOutcomeV1 {
    Ok(WorkerReturnV1::Produced(InvocationReportV1 {
        result,
        metering: METERING,
        operational_log: log(),
    }))
}

fn round_trip_response(outcome: &WorkerOutcomeV1) -> Decoded<WorkerOutcomeV1> {
    encode_worker_response_v1(outcome).and_then(|bytes| decode_worker_response_v1(&bytes))
}

#[test]
fn responses_round_trip_every_outcome() {
    let mut outcomes = vec![
        described(Ok(descriptor(&negotiated()))),
        produced(Ok(output(&invocation()))),
    ];
    for error in guest_errors() {
        outcomes.push(described(Err(error.clone())));
        outcomes.push(produced(Err(error)));
    }
    outcomes.extend(WORKER_FAILURES_V1.map(Err));
    outcomes.extend(WORKER_TRAP_CLASSES_V1.map(|class| {
        Err(Error::ComponentTrap {
            class,
            reproduction: TrapReproductionV1::Unverified,
        })
    }));
    for outcome in outcomes {
        assert_eq!(round_trip_response(&outcome), Ok(outcome.clone()), "{outcome:?}");
    }
}

#[test]
fn response_wire_codes_follow_their_lists() {
    let prefix = [0x83, 0x64, b'P', b'W', b'R', b'1', 0x01, 0x82];
    for (code, failure) in (0_u8..).zip(WORKER_FAILURES_V1) {
        let bytes = encode_worker_response_v1(&Err(failure));
        assert_eq!(bytes, Ok([&prefix[..], &[0x02, code]].concat()));
    }
    for (code, class) in (0_u8..).zip(WORKER_TRAP_CLASSES_V1) {
        let trap = Err(Error::ComponentTrap {
            class,
            reproduction: TrapReproductionV1::Unverified,
        });
        let bytes = encode_worker_response_v1(&trap);
        assert_eq!(bytes, Ok([&prefix[..], &[0x03, code]].concat()));
    }
    let metering = MeteringV1 {
        startup_fuel: 1,
        call_fuel: 2,
        memory_bytes: 3,
        host_calls: 4,
    };
    let budget = GuestPluginErrorV1 {
        code: PluginErrorCodeV1::DeterministicBudgetExhausted,
        canonical_coordinate: None,
        related_digest: None,
    };
    let declared = Ok(WorkerReturnV1::Described(InvocationReportV1 {
        result: Err(budget),
        metering,
        operational_log: Vec::new(),
    }));
    let expected = [
        0x83, 0x64, b'P', b'W', b'R', b'1', 0x01, 0x84, 0x00, 0x82, 0x01, 0x83, 0x81, 0x04, 0xf6,
        0xf6, 0x84, 0x01, 0x02, 0x03, 0x04, 0x80,
    ];
    assert_eq!(encode_worker_response_v1(&declared), Ok(expected.to_vec()));
}

#[test]
fn errors_the_wire_cannot_carry_are_not_encoded() {
    for error in [
        Error::WorkerCrashed,
        Error::CapabilityDenied { index: 0 },
        Error::ComponentTrap {
            class: ComponentTrapClassV1::Other,
            reproduction: TrapReproductionV1::ReproducedByConformance,
        },
    ] {
        assert_eq!(encode_worker_response_v1(&Err(error)), Err(WorkerEnvelopeErrorV1));
    }
    let mut long_log = log();
    long_log[0].message = "m".repeat(257);
    let logged = Ok(WorkerReturnV1::Produced(InvocationReportV1 {
        result: Ok(output(&invocation())),
        metering: METERING,
        operational_log: long_log,
    }));
    assert_eq!(encode_worker_response_v1(&logged), Err(WorkerEnvelopeErrorV1));
}

#[test]
fn malformed_responses_are_envelope_faults() {
    let header = [0x83, 0x64, b'P', b'W', b'R', b'1', 0x01];
    let response = |outcome: &[u8]| [&header[..], outcome].concat();
    assert!(decode_worker_response_v1(&response(&[0x82, 0x02, 0x00])).is_ok());
    let cases = [
        response(&[0x82, 0x02, 0x08]),
        response(&[0x82, 0x03, 0x07]),
        response(&[0x82, 0x04, 0x00]),
        response(&[0x82, 0x00, 0x00]),
        response(&[0x84, 0x02, 0x00, 0x00, 0x00]),
        response(&[0x85, 0x00, 0x00, 0x00, 0x00, 0x00]),
        response(&[0x84, 0x00, 0x82, 0x02, 0x00, 0x84, 0, 0, 0, 0, 0x80]),
        response(&[0x84, 0x00, 0x82, 0x01, 0x83, 0x82, 0x04, 0x00, 0xf6, 0xf6, 0x84, 0, 0, 0, 0, 0x80]),
        response(&[0x84, 0x00, 0x82, 0x01, 0x83, 0x81, 0x00, 0xf6, 0xf6, 0x84, 0, 0, 0, 0, 0x80]),
        response(&[0x84, 0x00, 0x82, 0x01, 0x83, 0x81, 0x08, 0xf6, 0xf6, 0x84, 0, 0, 0, 0, 0x80]),
        [&header[..6], &[0x02, 0x82, 0x02, 0x00]].concat(),
        [&[0x84], &header[1..], &[0x82, 0x02, 0x00]].concat(),
        [&response(&[0x82, 0x02, 0x00])[..], &[0x00]].concat(),
        response(&[0x82, 0x02]),
        Vec::new(),
    ];
    for (index, bytes) in cases.iter().enumerate() {
        assert_eq!(decode_worker_response_v1(bytes), Err(WorkerEnvelopeErrorV1), "case {index}");
    }
    let unit = response(&[0x84, 0x00, 0x82, 0x01, 0x83, 0x81, 0x04, 0xf6, 0xf6, 0x84, 0, 0, 0, 0, 0x80]);
    assert!(decode_worker_response_v1(&unit).is_ok());
}
