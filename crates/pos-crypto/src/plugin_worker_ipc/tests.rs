use super::*;

fn negotiation() -> WorkerNegotiationV1 {
    WorkerNegotiationV1 {
        world: "pigloros:plugin/community-plugin@0.1.0".to_owned(),
        abi_major: 0,
        abi_minor: 300,
        required_features: vec!["alpha".to_owned(), "beta".to_owned()],
        pmf1_digest: [1; 32],
        release_digest: [2; 32],
    }
}

fn request() -> WorkerRequestV1 {
    WorkerRequestV1 {
        export: WorkerExportV1::Reduce,
        component: b"component".to_vec(),
        negotiation: negotiation(),
        limits: DeterministicBudgetV1 {
            memory_bytes: 65_536,
            fuel: u64::MAX,
            host_calls: 1,
            event_count: 2,
            event_bytes: 3,
            state_bytes: 4,
            log_calls: 5,
            log_bytes: 6,
        },
        simulation_time: 42,
        invocation: b"invocation".to_vec(),
    }
}

fn encoded(request: &WorkerRequestV1) -> Vec<u8> {
    encode_worker_request_v1(request)
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("encode: {error:?}"))))
}

fn round_trip(request: &WorkerRequestV1) -> Result<WorkerRequestV1, WorkerEnvelopeErrorV1> {
    decode_worker_request_v1(&encoded(request))
}

#[test]
fn requests_round_trip_every_field() {
    let original = request();
    assert_eq!(round_trip(&original), Ok(original));
    for export in WorkerExportV1::ALL {
        let original = WorkerRequestV1 {
            export,
            ..request()
        };
        assert_eq!(round_trip(&original), Ok(original));
    }
}

#[test]
fn every_head_width_round_trips_in_shortest_form() {
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
        let mut out = Vec::new();
        unsigned(&mut out, value);
        assert_eq!(out.len(), length, "{value}");
        let original = WorkerRequestV1 {
            simulation_time: value,
            ..request()
        };
        assert_eq!(round_trip(&original), Ok(original), "{value}");
    }
}

#[test]
fn request_golden_bytes_are_canonical() {
    let small = WorkerRequestV1 {
        export: WorkerExportV1::Drive,
        component: vec![0xaa],
        negotiation: WorkerNegotiationV1 {
            world: "w".to_owned(),
            abi_major: 0,
            abi_minor: 1,
            required_features: Vec::new(),
            pmf1_digest: [0; 32],
            release_digest: [0; 32],
        },
        limits: DeterministicBudgetV1::MINIMA,
        simulation_time: 7,
        invocation: Vec::new(),
    };
    let mut expected = vec![0x88, 0x64];
    expected.extend_from_slice(b"PWQ1");
    expected.extend_from_slice(&[0x01, 0x02, 0x41, 0xaa, 0x86, 0x61, b'w', 0x00, 0x01, 0x80]);
    for _ in 0..2 {
        expected.extend_from_slice(&[0x58, 0x20]);
        expected.extend_from_slice(&[0; 32]);
    }
    expected.extend_from_slice(&[0x88, 0x1a, 0x00, 0x01, 0x00, 0x00, 0x01]);
    expected.extend_from_slice(&[0; 6]);
    expected.extend_from_slice(&[0x07, 0x40]);
    assert_eq!(encoded(&small), expected);
    assert_eq!(decode_worker_request_v1(&expected), Ok(small));
}

#[test]
fn request_bounds_are_enforced_on_both_sides() {
    let at_bound = WorkerRequestV1 {
        component: vec![0; MAX_WORKER_COMPONENT_BYTES_V1],
        invocation: vec![0; MAX_WORKER_INVOCATION_BYTES_V1],
        negotiation: WorkerNegotiationV1 {
            world: "w".repeat(MAX_TEXT_BYTES),
            required_features: vec!["f".repeat(MAX_TEXT_BYTES); MAX_FEATURES],
            ..negotiation()
        },
        ..request()
    };
    assert_eq!(round_trip(&at_bound).as_ref(), Ok(&at_bound));
    let oversized = [
        WorkerRequestV1 {
            component: vec![0; MAX_WORKER_COMPONENT_BYTES_V1 + 1],
            ..request()
        },
        WorkerRequestV1 {
            invocation: vec![0; MAX_WORKER_INVOCATION_BYTES_V1 + 1],
            ..request()
        },
        WorkerRequestV1 {
            negotiation: WorkerNegotiationV1 {
                world: "w".repeat(MAX_TEXT_BYTES + 1),
                ..negotiation()
            },
            ..request()
        },
        WorkerRequestV1 {
            negotiation: WorkerNegotiationV1 {
                required_features: vec!["f".to_owned(); MAX_FEATURES + 1],
                ..negotiation()
            },
            ..request()
        },
        WorkerRequestV1 {
            negotiation: WorkerNegotiationV1 {
                required_features: vec!["f".repeat(MAX_TEXT_BYTES + 1)],
                ..negotiation()
            },
            ..request()
        },
    ];
    for request in oversized {
        assert_eq!(
            encode_worker_request_v1(&request),
            Err(WorkerEnvelopeErrorV1)
        );
        let bytes = request_bytes(&request);
        assert_eq!(decode_worker_request_v1(&bytes), Err(WorkerEnvelopeErrorV1));
    }
}

fn bytes_of(write: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut out = Vec::new();
    write(&mut out);
    out
}

/// The eight request members of `request()` with every limit 1 and time 7.
fn members() -> [Vec<u8>; 8] {
    let negotiation = bytes_of(|out| {
        array(out, 6);
        text(out, "pigloros:plugin/community-plugin@0.1.0");
        unsigned(out, 0);
        unsigned(out, 300);
        array(out, 2);
        text(out, "alpha");
        text(out, "beta");
        byte_string(out, &[1; 32]);
        byte_string(out, &[2; 32]);
    });
    let limits = bytes_of(|out| {
        array(out, 8);
        for _ in 0..8 {
            unsigned(out, 1);
        }
    });
    [
        bytes_of(|out| text(out, WORKER_REQUEST_MAGIC_V1)),
        vec![0x01],
        vec![0x01],
        bytes_of(|out| byte_string(out, b"component")),
        negotiation,
        limits,
        vec![0x07],
        bytes_of(|out| byte_string(out, b"invocation")),
    ]
}

/// The request bytes with member `index` replaced by `member`.
fn with_member(index: usize, member: &[u8]) -> Vec<u8> {
    let mut out = vec![0x88];
    for (position, field) in members().iter().enumerate() {
        out.extend_from_slice(if position == index { member } else { field });
    }
    out
}

#[test]
fn the_member_splicer_reproduces_a_valid_request() {
    let bytes = with_member(usize::MAX, &[]);
    let decoded = decode_worker_request_v1(&bytes);
    let expected = WorkerRequestV1 {
        limits: DeterministicBudgetV1 {
            memory_bytes: 1,
            fuel: 1,
            host_calls: 1,
            event_count: 1,
            event_bytes: 1,
            state_bytes: 1,
            log_calls: 1,
            log_bytes: 1,
        },
        simulation_time: 7,
        ..request()
    };
    assert_eq!(decoded, Ok(expected));
}

#[test]
fn malformed_requests_are_envelope_faults() {
    let mut wrong_magic = Vec::new();
    text(&mut wrong_magic, WORKER_RESPONSE_MAGIC_V1);
    let cases = [
        with_member(0, &wrong_magic),
        with_member(0, &[0x63, b'P', b'W', b'Q']),
        with_member(1, &[0x02]),
        with_member(1, &[0x18, 0x01]),
        with_member(2, &[0x03]),
        with_member(3, &[0x60]),
        with_member(5, &[0x87, 1, 1, 1, 1, 1, 1, 1]),
        with_member(6, &[0x20]),
        with_member(7, &[0x60]),
    ];
    for (index, bytes) in cases.iter().enumerate() {
        assert_eq!(
            decode_worker_request_v1(bytes),
            Err(WorkerEnvelopeErrorV1),
            "case {index}"
        );
    }
    let valid = encoded(&request());
    let mut trailing = valid.clone();
    trailing.push(0);
    assert_eq!(
        decode_worker_request_v1(&trailing),
        Err(WorkerEnvelopeErrorV1)
    );
    assert_eq!(
        decode_worker_request_v1(&valid[..valid.len() - 1]),
        Err(WorkerEnvelopeErrorV1)
    );
    let mut wrong_count = valid;
    wrong_count[0] = 0x87;
    assert_eq!(
        decode_worker_request_v1(&wrong_count),
        Err(WorkerEnvelopeErrorV1)
    );
}

#[test]
fn malformed_negotiations_are_envelope_faults() {
    let mut digest = Vec::new();
    byte_string(&mut digest, &[0; 32]);
    let negotiation_with = |abi_major: &[u8], features: &[u8], last: &[u8]| {
        let mut out = vec![0x86, 0x61, b'w'];
        out.extend_from_slice(abi_major);
        out.push(0x00);
        out.extend_from_slice(features);
        out.extend_from_slice(&digest);
        out.extend_from_slice(last);
        out
    };
    let valid = negotiation_with(&[0x00], &[0x80], &digest);
    assert!(decode_worker_request_v1(&with_member(4, &valid)).is_ok());
    let cases = [
        negotiation_with(&[0x1a, 0x00, 0x01, 0x00, 0x00], &[0x80], &digest),
        negotiation_with(&[0x00], &[0x81, 0x40], &digest),
        negotiation_with(&[0x00], &[0x80], &[0x58, 0x1f]),
        [&[0x85][..], &valid[1..]].concat(),
    ];
    for (index, member) in cases.iter().enumerate() {
        assert_eq!(
            decode_worker_request_v1(&with_member(4, member)),
            Err(WorkerEnvelopeErrorV1),
            "case {index}"
        );
    }
    let largest = negotiation_with(&[0x19, 0xff, 0xff], &[0x80], &digest);
    let decoded = decode_worker_request_v1(&with_member(4, &largest));
    assert_eq!(
        decoded.map(|request| request.negotiation.abi_major),
        Ok(65_535)
    );
}

fn completion() -> WorkerCompletionV1 {
    WorkerCompletionV1 {
        payload: b"payload".to_vec(),
        startup_fuel: 1,
        call_fuel: 300,
        memory_bytes: 65_536,
    }
}

#[test]
fn responses_round_trip_every_outcome() {
    let mut outcomes = vec![WorkerOutcomeV1::Completed(completion())];
    outcomes.extend(WorkerFailureV1::ALL.map(WorkerOutcomeV1::Failed));
    outcomes.extend(WorkerTrapClassV1::ALL.map(WorkerOutcomeV1::Trapped));
    for outcome in outcomes {
        let bytes = encode_worker_response_v1(&outcome);
        assert_eq!(decode_worker_response_v1(&bytes), Ok(outcome));
    }
}

#[test]
fn response_wire_codes_follow_declaration_order() {
    let prefix = [0x83, 0x64, b'P', b'W', b'R', b'1', 0x01, 0x82];
    for (code, failure) in (0_u8..).zip(WorkerFailureV1::ALL) {
        let bytes = encode_worker_response_v1(&WorkerOutcomeV1::Failed(failure));
        assert_eq!(bytes, [&prefix[..], &[0x01, code]].concat());
    }
    for (code, class) in (0_u8..).zip(WorkerTrapClassV1::ALL) {
        let bytes = encode_worker_response_v1(&WorkerOutcomeV1::Trapped(class));
        assert_eq!(bytes, [&prefix[..], &[0x02, code]].concat());
    }
    let completed = encode_worker_response_v1(&WorkerOutcomeV1::Completed(completion()));
    let mut expected = vec![0x83, 0x64, b'P', b'W', b'R', b'1', 0x01, 0x85, 0x00, 0x47];
    expected.extend_from_slice(b"payload");
    expected.extend_from_slice(&[0x01, 0x19, 0x01, 0x2c, 0x1a, 0x00, 0x01, 0x00, 0x00]);
    assert_eq!(completed, expected);
}

#[test]
fn malformed_responses_are_envelope_faults() {
    let header = [0x83, 0x64, b'P', b'W', b'R', b'1', 0x01];
    let response = |outcome: &[u8]| [&header[..], outcome].concat();
    let failed = response(&[0x82, 0x01, 0x00]);
    assert!(decode_worker_response_v1(&failed).is_ok());
    let cases = [
        response(&[0x82, 0x01, 0x08]),
        response(&[0x82, 0x02, 0x07]),
        response(&[0x82, 0x03, 0x00]),
        response(&[0x82, 0x00, 0x00]),
        response(&[0x85, 0x01, 0x00, 0x00, 0x00, 0x00]),
        response(&[0x86, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00]),
        response(&[0x82, 0x01, 0x18, 0x00]),
        response(&[
            0x82, 0x01, 0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ]),
        response(&[0x85, 0x00, 0x60, 0x00, 0x00, 0x00]),
        [
            &[0x83, 0x64, b'P', b'W', b'Q', b'1', 0x01][..],
            &[0x82, 0x01, 0x00],
        ]
        .concat(),
        [&header[..6], &[0x02, 0x82, 0x01, 0x00]].concat(),
        [&[0x84], &header[1..], &[0x82, 0x01, 0x00]].concat(),
        [failed.as_slice(), &[0x00]].concat(),
        failed[..failed.len() - 1].to_vec(),
        Vec::new(),
    ];
    for (index, bytes) in cases.iter().enumerate() {
        assert_eq!(
            decode_worker_response_v1(bytes),
            Err(WorkerEnvelopeErrorV1),
            "case {index}"
        );
    }
}
