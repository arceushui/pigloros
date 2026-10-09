use pos_runtime::community_plugin_host::{
    FieldRefV1, GuestPluginErrorV1, MeteringV1, OperationalLogRecord, PluginErrorCodeV1,
};

use super::*;
use crate::test_support::{descriptor, invocation, log, negotiated, ok, output, METERING};

type Error = CommunityPluginHostErrorV1;

/// An invocation whose numbers need every CBOR head width.
fn wide_invocation() -> PluginInvocationV1 {
    let mut wide = invocation(b"observation");
    wide.timeline_position.seq = 70_000;
    wide.timeline_position.tick = u64::MAX;
    wide.timeline_position.scheduler_position = 24;
    wide.output_base_ordinal = 255;
    wide.principal_ref.schema_id = 300;
    wide.principal_ref.byte_length = 4_294_967_296;
    wide
}

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
        WorkerCallV1::Reduce(wide_invocation()),
        WorkerCallV1::Drive(invocation(b"observation")),
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
fn the_profile_digest_is_an_optional_thirty_two_byte_string() {
    let mut digested = request(WorkerCallV1::Describe);
    digested.negotiation.execution_profile_digest = Some([0x9d; 32]);
    assert_eq!(round_trip_request(&digested).as_ref(), Ok(&digested));
    let with = ok(encode_worker_request_v1(&digested));
    let without = ok(encode_worker_request_v1(&request(WorkerCallV1::Describe)));
    assert_eq!(with.len(), without.len() + 34);
    let marker = [0x81, 0x58, 0x20, 0x9d];
    assert!(with.windows(4).any(|window| window == marker));
    assert!(!without.windows(4).any(|window| window == marker));
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
        assert_eq!(
            round_trip_request(&original).as_ref(),
            Ok(&original),
            "{value}"
        );
    }
}

#[test]
fn the_describe_request_has_its_golden_prefix_and_suffix() {
    let bytes = ok(encode_worker_request_v1(&request(WorkerCallV1::Describe)));
    let mut prefix = vec![0x87, 0x64];
    prefix.extend_from_slice(b"PWQ1");
    prefix.extend_from_slice(&[0x01, 0x49]);
    prefix.extend_from_slice(b"component");
    prefix.extend_from_slice(&[0x8c, 0x78, 0x26]);
    prefix.extend_from_slice(b"pigloros:plugin/community-plugin@0.1.0");
    assert!(bytes.starts_with(&prefix));
    let suffix = [0x19, 0xea, 0x60, 0x18, 0x2a, 0x81, 0x00];
    assert!(bytes.ends_with(&suffix));
    let capability_and_mode = [
        0x81, 0x89, 0x64, b'r', b'e', b'a', b'd', 0x63, b'g', b'e', b't', 0x61, b'*', 0x64, b't',
        b'e', b's', b't', 0x65, b'l', b'o', b'c', b'a', b'l', 0xf4, 0x01, 0x02, 0x03, 0x00, 0x88,
    ];
    assert!(bytes
        .windows(capability_and_mode.len())
        .any(|window| window == capability_and_mode));
}

#[test]
fn only_an_oversize_component_stops_the_encoder() {
    let mut largest = request(WorkerCallV1::Describe);
    largest.component = vec![0; MAX_WORKER_COMPONENT_BYTES_V1];
    assert_eq!(round_trip_request(&largest).as_ref(), Ok(&largest));
    let mut oversized = largest;
    oversized.component.push(0);
    assert_eq!(
        encode_worker_request_v1(&oversized),
        Err(WorkerEnvelopeErrorV1)
    );
}

#[test]
fn the_decoder_enforces_the_bounds_the_encoder_leaves_to_validation() {
    let at_bound = |change: fn(&mut WorkerRequestV1)| {
        let mut request = request(WorkerCallV1::Describe);
        change(&mut request);
        round_trip_request(&request)
    };
    let over_bound = |change: fn(&mut WorkerRequestV1)| {
        let mut request = request(WorkerCallV1::Describe);
        change(&mut request);
        encode_worker_request_v1(&request).and_then(|bytes| decode_worker_request_v1(&bytes))
    };
    assert!(at_bound(|r| r.negotiation.world = "w".repeat(MAX_TEXT_BYTES)).is_ok());
    assert!(at_bound(
        |r| r.negotiation.not_granted_capabilities[0].resource_pattern =
            "p".repeat(MAX_PATTERN_BYTES)
    )
    .is_ok());
    assert!(at_bound(|r| r.negotiation.required_features = vec!["f".to_owned(); MAX_LIST]).is_ok());
    let bad = Err(WorkerEnvelopeErrorV1);
    assert_eq!(
        over_bound(|r| r.negotiation.world = "w".repeat(MAX_TEXT_BYTES + 1)),
        bad
    );
    assert_eq!(
        over_bound(
            |r| r.negotiation.not_granted_capabilities[0].resource_pattern =
                "p".repeat(MAX_PATTERN_BYTES + 1)
        ),
        bad
    );
    assert_eq!(
        over_bound(|r| r.negotiation.required_features = vec!["f".to_owned(); MAX_LIST + 1]),
        bad
    );
    let mut observed = invocation(b"observation");
    observed.observation_bytes = vec![0; 1_048_577];
    let request = request(WorkerCallV1::Reduce(observed));
    let decoded = encode_worker_request_v1(&request).and_then(|b| decode_worker_request_v1(&b));
    assert_eq!(decoded, bad);
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
        assert_eq!(
            decode_worker_request_v1(bytes),
            Err(WorkerEnvelopeErrorV1),
            "case {index}"
        );
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

fn described(result: GuestReturnV1<PluginDescriptorV1>) -> WorkerReturnV1 {
    WorkerReturnV1::Described(InvocationReportV1 {
        result,
        metering: METERING,
        operational_log: log(),
    })
}

fn produced(result: GuestReturnV1<PluginOutputV1>) -> WorkerReturnV1 {
    WorkerReturnV1::Produced(InvocationReportV1 {
        result,
        metering: METERING,
        operational_log: log(),
    })
}

fn round_trip_response(outcome: &WorkerOutcomeV1) -> Decoded<WorkerOutcomeV1> {
    encode_worker_response_v1(outcome).and_then(|bytes| decode_worker_response_v1(&bytes))
}

#[test]
fn responses_round_trip_every_outcome() {
    let mut outcomes: Vec<WorkerOutcomeV1> = vec![
        Ok(described(Ok(descriptor(&negotiated())))),
        Ok(produced(Ok(output(&invocation(b"observation"))))),
    ];
    for error in guest_errors() {
        outcomes.push(Ok(described(Err(error.clone()))));
        outcomes.push(Ok(produced(Err(error))));
    }
    outcomes.extend(WORKER_FAILURES_V1.map(Err));
    outcomes.extend(WORKER_TRAP_CLASSES_V1.map(|class| {
        Err(Error::ComponentTrap {
            class,
            reproduction: TrapReproductionV1::Unverified,
        })
    }));
    for outcome in outcomes {
        assert_eq!(
            round_trip_response(&outcome),
            Ok(outcome.clone()),
            "{outcome:?}"
        );
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
        assert_eq!(
            encode_worker_response_v1(&Err(error)),
            Err(WorkerEnvelopeErrorV1)
        );
    }
}

#[test]
fn the_response_decoder_enforces_the_log_bounds() {
    let logged = |records: Vec<OperationalLogRecord>| {
        let outcome = Ok(WorkerReturnV1::Produced(InvocationReportV1 {
            result: Ok(output(&invocation(b"observation"))),
            metering: METERING,
            operational_log: records,
        }));
        encode_worker_response_v1(&outcome).and_then(|bytes| decode_worker_response_v1(&bytes))
    };
    let record = |message: String| OperationalLogRecord {
        category: 1,
        message,
    };
    assert!(logged(vec![record("m".repeat(256)); 64]).is_ok());
    assert_eq!(
        logged(vec![record("m".repeat(257))]),
        Err(WorkerEnvelopeErrorV1)
    );
    assert_eq!(
        logged(vec![record(String::new()); 65]),
        Err(WorkerEnvelopeErrorV1)
    );
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
        response(&[
            0x84, 0x00, 0x82, 0x01, 0x83, 0x82, 0x04, 0x00, 0xf6, 0xf6, 0x84, 0, 0, 0, 0, 0x80,
        ]),
        response(&[
            0x84, 0x00, 0x82, 0x01, 0x83, 0x81, 0x00, 0xf6, 0xf6, 0x84, 0, 0, 0, 0, 0x80,
        ]),
        response(&[
            0x84, 0x00, 0x82, 0x01, 0x83, 0x81, 0x08, 0xf6, 0xf6, 0x84, 0, 0, 0, 0, 0x80,
        ]),
        [&header[..6], &[0x02, 0x82, 0x02, 0x00]].concat(),
        [&[0x84], &header[1..], &[0x82, 0x02, 0x00]].concat(),
        [&response(&[0x82, 0x02, 0x00])[..], &[0x00]].concat(),
        response(&[0x82, 0x02]),
        Vec::new(),
    ];
    for (index, bytes) in cases.iter().enumerate() {
        assert_eq!(
            decode_worker_response_v1(bytes),
            Err(WorkerEnvelopeErrorV1),
            "case {index}"
        );
    }
    let unit = response(&[
        0x84, 0x00, 0x82, 0x01, 0x83, 0x81, 0x04, 0xf6, 0xf6, 0x84, 0, 0, 0, 0, 0x80,
    ]);
    assert!(decode_worker_response_v1(&unit).is_ok());
}

/// Every request shape: each call, a required capability, features, Air-Gapped.
fn request_samples() -> Vec<WorkerRequestV1> {
    let mut rich = request(WorkerCallV1::Describe);
    rich.negotiation.mode = CommunityPluginModeV1::AirGapped;
    rich.negotiation.required_features = vec!["alpha".to_owned(), "beta".to_owned()];
    let mut required = rich.negotiation.not_granted_capabilities[0].clone();
    required.required = true;
    rich.negotiation.not_granted_capabilities.push(required);
    vec![
        rich,
        request(WorkerCallV1::Reduce(wide_invocation())),
        request(WorkerCallV1::Drive(invocation(b"observation"))),
    ]
}

#[test]
fn a_required_capability_round_trips_so_the_transport_can_refuse_it() {
    let samples = request_samples();
    assert_eq!(round_trip_request(&samples[0]).as_ref(), Ok(&samples[0]));
    let required = &samples[0].negotiation.not_granted_capabilities;
    assert!(!required[0].required && required[1].required);
}

#[test]
fn every_truncated_request_is_an_envelope_fault() {
    for sample in request_samples() {
        let bytes = ok(encode_worker_request_v1(&sample));
        for length in 0..bytes.len() {
            assert_eq!(
                decode_worker_request_v1(&bytes[..length]),
                Err(WorkerEnvelopeErrorV1),
                "{length} of {} bytes",
                bytes.len()
            );
        }
        assert_eq!(decode_worker_request_v1(&bytes), Ok(sample));
    }
}

fn response_samples() -> Vec<WorkerOutcomeV1> {
    let mut featured = descriptor(&negotiated());
    featured.required_features = vec!["alpha".to_owned(), "beta".to_owned()];
    let mut samples: Vec<WorkerOutcomeV1> = vec![
        Ok(described(Ok(descriptor(&negotiated())))),
        Ok(described(Ok(featured))),
        Ok(produced(Ok(output(&invocation(b"observation"))))),
    ];
    for error in guest_errors() {
        samples.push(Ok(described(Err(error.clone()))));
        samples.push(Ok(produced(Err(error))));
    }
    samples.push(Err(Error::FuelExhausted));
    samples.push(Err(Error::ComponentTrap {
        class: ComponentTrapClassV1::Other,
        reproduction: TrapReproductionV1::Unverified,
    }));
    samples
}

#[test]
fn every_truncated_response_is_an_envelope_fault() {
    for sample in response_samples() {
        let bytes = ok(encode_worker_response_v1(&sample));
        for length in 0..bytes.len() {
            assert_eq!(
                decode_worker_response_v1(&bytes[..length]),
                Err(WorkerEnvelopeErrorV1),
                "{length} of {} bytes",
                bytes.len()
            );
        }
        assert_eq!(decode_worker_response_v1(&bytes), Ok(sample));
    }
}

/// `bytes` with the first occurrence of `from` replaced by `to`.
fn spliced(bytes: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let at = bytes
        .windows(from.len())
        .position(|window| window == from)
        .unwrap_or_default();
    [&bytes[..at], to, &bytes[at + from.len()..]].concat()
}

#[test]
fn integers_beyond_their_field_width_are_envelope_faults() {
    // `abi_major` 65,535 as a `u16`, then as 65,536 (a `u32`-sized head).
    let mut abi = request(WorkerCallV1::Describe);
    abi.negotiation.abi_major = u16::MAX;
    let bytes = ok(encode_worker_request_v1(&abi));
    assert_eq!(decode_worker_request_v1(&bytes), Ok(abi));
    let wide = spliced(&bytes, &[0x19, 0xff, 0xff], &[0x1a, 0x00, 0x01, 0x00, 0x00]);
    assert_eq!(decode_worker_request_v1(&wide), Err(WorkerEnvelopeErrorV1));
    // `scheduler_position` 2^32 - 1 as a `u32`, then as 2^32.
    let mut position = invocation(b"observation");
    position.timeline_position.scheduler_position = u32::MAX;
    let bytes = ok(encode_worker_request_v1(&request(WorkerCallV1::Reduce(
        position,
    ))));
    assert!(decode_worker_request_v1(&bytes).is_ok());
    let wide = spliced(
        &bytes,
        &[0x1a, 0xff, 0xff, 0xff, 0xff],
        &[0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
    );
    assert_eq!(decode_worker_request_v1(&wide), Err(WorkerEnvelopeErrorV1));
}
