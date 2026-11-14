//! Independent CRI1/CPR1/CSH1 wire fixtures through the public data boundary.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    CommunityLifecycleErrorV1 as Error, CommunityMemberHeadV1 as Member,
    CommunityMemberHeadsV1 as Members, CommunityPassFrontierV1 as Frontier,
    CommunityPassKeyV1 as Pass, CommunityReservationInputV1 as ReservationInput,
    CommunityReservationRequestInputV1 as RequestInput, CommunityReservationRequestV1 as Request,
    CommunityReservationV1 as Reservation, CommunitySelectedHeadInputV1 as HeadInput,
    CommunitySelectedHeadV1 as Head, MAX_COMMUNITY_MEMBERS_V1,
};
use pos_core::{Hash, Seq, TimelineId};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

const fn timeline(byte: u8) -> TimelineId {
    TimelineId::from_ulid(ulid::Ulid::from_bytes([byte; 16]))
}

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

fn encode(value: &Value) -> Fallible<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)?;
    Ok(out)
}

fn pass_bytes(ordinal: u64) -> Fallible<Vec<u8>> {
    encode(&Value::Array(vec![
        bytes(b"CPK1"),
        uint(1),
        bytes(&[7; 16]),
        bytes(&[8; 16]),
        uint(ordinal),
    ]))
}

const fn request_input() -> RequestInput {
    RequestInput {
        timeline: timeline(7),
        generation: [8; 16],
        reservation_operation_id: [9; 16],
        expected_head_digest: hash(1),
        prepared_input_set_digest: hash(2),
        roster_digest: hash(3),
        profile_digest: hash(4),
        authority_request_digest: hash(5),
        source_closure_digest: hash(6),
        requested_evidence_horizon: 1,
    }
}

fn request_fields(input: RequestInput) -> Vec<Value> {
    vec![
        bytes(b"CRI1"),
        uint(1),
        bytes(&input.timeline.inner().to_bytes()),
        bytes(&input.generation),
        bytes(&input.reservation_operation_id),
        bytes(input.expected_head_digest.as_bytes()),
        bytes(input.prepared_input_set_digest.as_bytes()),
        bytes(input.roster_digest.as_bytes()),
        bytes(input.profile_digest.as_bytes()),
        bytes(input.authority_request_digest.as_bytes()),
        bytes(input.source_closure_digest.as_bytes()),
        uint(input.requested_evidence_horizon),
    ]
}

fn reservation_input(ordinal: u64) -> Result<ReservationInput, Error> {
    Ok(ReservationInput {
        pass_key: Pass::new(timeline(7), [8; 16], ordinal)?,
        request_digest: hash(10),
        native_producer_ordinal: 2,
        predecessor_head_digest: hash(1),
        roster_digest: hash(3),
        prepared_input_set_digest: hash(2),
        profile_digest: hash(4),
        evidence_not_after_micros: 1,
    })
}

fn reservation_fields(input: ReservationInput) -> Fallible<Vec<Value>> {
    Ok(vec![
        bytes(b"CPR1"),
        uint(1),
        bytes(&pass_bytes(input.pass_key.ordinal())?),
        bytes(input.request_digest.as_bytes()),
        uint(input.native_producer_ordinal),
        bytes(input.predecessor_head_digest.as_bytes()),
        bytes(input.roster_digest.as_bytes()),
        bytes(input.prepared_input_set_digest.as_bytes()),
        bytes(input.profile_digest.as_bytes()),
        uint(input.evidence_not_after_micros),
    ])
}

fn members(count: u8) -> Vec<Member> {
    (1..=count)
        .map(|byte| Member {
            member_binding_digest: hash(byte),
            member_progress_digest: hash(100),
        })
        .collect()
}

const fn head_input(frontier: Frontier, members: &[Member]) -> HeadInput<'_> {
    HeadInput {
        timeline: timeline(7),
        generation: [8; 16],
        frontier,
        member_heads: Members::from_members(members),
        event_logical_head: Seq::ZERO,
        profile_digest: hash(4),
        host_progress_digest: hash(5),
    }
}

fn head_fields(input: &HeadInput<'_>) -> Fallible<Vec<Value>> {
    let frontier = match input.frontier {
        Frontier::Initial => Value::Array(vec![uint(0)]),
        Frontier::Committed(key) => Value::Array(vec![uint(1), bytes(&pass_bytes(key.ordinal())?)]),
    };
    Ok(vec![
        bytes(b"CSH1"),
        uint(1),
        bytes(&input.timeline.inner().to_bytes()),
        bytes(&input.generation),
        frontier,
        Value::Array(
            input
                .member_heads
                .iter()
                .map(|member| {
                    Value::Array(vec![
                        bytes(member.member_binding_digest.as_bytes()),
                        bytes(member.member_progress_digest.as_bytes()),
                    ])
                })
                .collect(),
        ),
        uint(input.event_logical_head.as_u64()),
        bytes(input.profile_digest.as_bytes()),
        bytes(input.host_progress_digest.as_bytes()),
    ])
}

fn framing_refuses(encoded: &[u8], maximum: usize, decode: impl Fn(&[u8]) -> Result<(), Error>) {
    for end in 0..encoded.len() {
        assert!(decode(&encoded[..end]).is_err(), "accepted prefix {end}");
    }
    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert_eq!(decode(&trailing), Err(Error::InvalidEncoding));
    assert_eq!(decode(&vec![0; maximum + 1]), Err(Error::BoundsExceeded));
    let mut version = encoded.to_vec();
    version[6] = 2;
    assert_eq!(decode(&version), Err(Error::UnsupportedVersion));
    let mut nonpreferred = encoded.to_vec();
    nonpreferred.splice(6..7, [0x18, 1]);
    assert_eq!(decode(&nonpreferred), Err(Error::InvalidEncoding));
    let mut magic = encoded.to_vec();
    magic[2] = b'X';
    assert_eq!(decode(&magic), Err(Error::InvalidEncoding));
    let mut arity = encoded.to_vec();
    arity[0] -= 1;
    assert_eq!(decode(&arity), Err(Error::InvalidEncoding));
}

#[test]
fn pre_reserve_identity_has_exact_twelve_fields_without_a_future_pass() -> TestResult {
    for horizon in [1, 24, 65_536, u64::MAX / 2] {
        let input = RequestInput {
            requested_evidence_horizon: horizon,
            ..request_input()
        };
        let expected = encode(&Value::Array(request_fields(input)))?;
        let record = Request::new(input)?;
        assert!(record.as_input() == &input);
        assert_eq!(record.to_canonical_cbor().as_slice(), expected);
        assert!(Request::from_canonical_cbor(&expected)?.as_input() == &input);
        assert!(expected.len() <= 1024);
    }
    Ok(())
}

#[test]
fn reserve_discovery_identity_distinguishes_original_operation_and_inputs() -> TestResult {
    let original = request_input();
    let mut distinct = [original; 3];
    distinct[0].reservation_operation_id = [10; 16];
    distinct[1].prepared_input_set_digest = hash(20);
    distinct[2].expected_head_digest = hash(21);
    let encoded = Request::new(original)?.to_canonical_cbor();
    for input in distinct {
        assert_ne!(
            Request::new(input)?.to_canonical_cbor().as_slice(),
            encoded.as_slice()
        );
    }
    Ok(())
}

#[test]
fn request_refuses_zero_coordinates_operation_and_every_required_digest() -> TestResult {
    for field in 2..=10 {
        let mut fields = request_fields(request_input());
        fields[field] = bytes(&vec![0; if field <= 4 { 16 } else { 32 }]);
        let encoded = encode(&Value::Array(fields))?;
        assert_eq!(
            Request::from_canonical_cbor(&encoded).err(),
            Some(Error::InvalidBinding)
        );
    }
    let mut input = request_input();
    input.reservation_operation_id = [0; 16];
    assert_eq!(Request::new(input).err(), Some(Error::InvalidBinding));
    Ok(())
}

#[test]
fn request_horizon_is_fixed_positive_and_i64_bounded() -> TestResult {
    for horizon in [0, (u64::MAX / 2) + 1, u64::MAX] {
        let input = RequestInput {
            requested_evidence_horizon: horizon,
            ..request_input()
        };
        assert_eq!(Request::new(input).err(), Some(Error::BoundsExceeded));
        let encoded = encode(&Value::Array(request_fields(input)))?;
        assert_eq!(
            Request::from_canonical_cbor(&encoded).err(),
            Some(Error::BoundsExceeded)
        );
    }
    Ok(())
}

#[test]
fn request_refuses_all_truncations_and_nonpreferred_semantic_values() -> TestResult {
    let encoded = encode(&Value::Array(request_fields(request_input())))?;
    framing_refuses(&encoded, 1024, |bytes| {
        Request::from_canonical_cbor(bytes).map(|_| ())
    });
    let mut overlong_zero = encoded;
    let last = overlong_zero.len() - 1;
    overlong_zero.splice(last.., [0x18, 0]);
    assert_eq!(
        Request::from_canonical_cbor(&overlong_zero).err(),
        Some(Error::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn reservation_has_exact_ten_fields_and_independent_native_ordinal() -> TestResult {
    for pass_ordinal in [1, 24, u64::MAX] {
        for native_ordinal in [1, 65_536, u64::MAX] {
            let input = ReservationInput {
                native_producer_ordinal: native_ordinal,
                evidence_not_after_micros: u64::MAX / 2,
                ..reservation_input(pass_ordinal)?
            };
            let expected = encode(&Value::Array(reservation_fields(input)?))?;
            let record = Reservation::new(input)?;
            assert!(record.as_input() == &input);
            assert_eq!(record.to_canonical_cbor().as_slice(), expected);
            assert!(Reservation::from_canonical_cbor(&expected)?.as_input() == &input);
            assert!(expected.len() <= 512);
        }
    }
    Ok(())
}

#[test]
fn reservation_rejects_missing_links_zero_native_ordinal_and_bad_horizons() -> TestResult {
    for field in [3, 5, 6, 7, 8] {
        let mut fields = reservation_fields(reservation_input(1)?)?;
        fields[field] = bytes(&[0; 32]);
        assert_eq!(
            Reservation::from_canonical_cbor(&encode(&Value::Array(fields))?).err(),
            Some(Error::InvalidBinding)
        );
    }
    let input = ReservationInput {
        native_producer_ordinal: 0,
        ..reservation_input(1)?
    };
    assert_eq!(Reservation::new(input).err(), Some(Error::InvalidBinding));
    for horizon in [0, (u64::MAX / 2) + 1, u64::MAX] {
        let input = ReservationInput {
            evidence_not_after_micros: horizon,
            ..reservation_input(1)?
        };
        let encoded = encode(&Value::Array(reservation_fields(input)?))?;
        assert_eq!(
            Reservation::from_canonical_cbor(&encoded).err(),
            Some(Error::BoundsExceeded)
        );
    }
    Ok(())
}

#[test]
fn reservation_refuses_all_truncations_and_invalid_nested_keys() -> TestResult {
    let encoded = encode(&Value::Array(reservation_fields(reservation_input(1)?)?))?;
    framing_refuses(&encoded, 512, |bytes| {
        Reservation::from_canonical_cbor(bytes).map(|_| ())
    });
    for key in [pass_bytes(0)?, vec![0; 65], vec![]] {
        let mut fields = reservation_fields(reservation_input(1)?)?;
        fields[2] = bytes(&key);
        assert!(Reservation::from_canonical_cbor(&encode(&Value::Array(fields))?).is_err());
    }
    Ok(())
}

#[test]
fn complete_head_has_exact_nine_fields_and_retains_all_sixty_four_members() -> TestResult {
    assert_eq!(MAX_COMMUNITY_MEMBERS_V1, 64);
    for count in [1, 64] {
        for frontier in [
            Frontier::Initial,
            Frontier::Committed(Pass::new(timeline(7), [8; 16], u64::MAX)?),
        ] {
            let rows = members(count);
            let mut input = head_input(frontier, &rows);
            input.event_logical_head = Seq::from_u64(u64::MAX);
            let expected = encode(&Value::Array(head_fields(&input)?))?;
            let record = Head::new(input)?;
            assert_eq!(record.to_canonical_cbor().as_slice(), expected);
            let restored = Head::from_canonical_cbor(&expected)?;
            assert!(record.as_input() == restored.as_input());
            assert!(restored
                .as_input()
                .member_heads
                .eq(&Members::from_members(&rows)));
            assert!(!restored
                .as_input()
                .member_heads
                .eq(&Members::from_members(&[])));
            let mut changed_rows = rows.clone();
            changed_rows[0].member_progress_digest = hash(99);
            assert!(!restored
                .as_input()
                .member_heads
                .eq(&Members::from_members(&changed_rows)));
            assert_eq!(restored.as_input().member_heads.len(), usize::from(count));
            assert_eq!(
                restored.as_input().event_logical_head,
                Seq::from_u64(u64::MAX)
            );
            assert!(expected.len() <= 65_536);
        }
    }
    Ok(())
}

#[test]
fn committed_frontiers_encode_independently_of_the_event_logical_head() -> TestResult {
    let rows = members(1);
    let initial = Head::new(head_input(Frontier::Initial, &rows))?;
    let first = Head::new(head_input(
        Frontier::Committed(Pass::new(timeline(7), [8; 16], 1)?),
        &rows,
    ))?;
    let second = Head::new(head_input(
        Frontier::Committed(Pass::new(timeline(7), [8; 16], 2)?),
        &rows,
    ))?;
    for record in [&initial, &first, &second] {
        assert_eq!(record.as_input().event_logical_head, Seq::ZERO);
    }
    assert_ne!(
        initial.to_canonical_cbor().as_slice(),
        first.to_canonical_cbor().as_slice()
    );
    assert_ne!(
        first.to_canonical_cbor().as_slice(),
        second.to_canonical_cbor().as_slice()
    );
    Ok(())
}

#[test]
fn each_member_pair_framing_component_is_required_independently() -> TestResult {
    let rows = members(1);
    let original = Head::new(head_input(Frontier::Initial, &rows))?.to_canonical_cbor();
    let pair = encode(&Value::Array(vec![
        bytes(rows[0].member_binding_digest.as_bytes()),
        bytes(rows[0].member_progress_digest.as_bytes()),
    ]))?;
    assert_eq!(pair.len(), 69);
    let start = original
        .windows(pair.len())
        .position(|candidate| candidate == pair)
        .ok_or("missing member pair")?;
    for (offset, replacement) in [(0, 0x83), (2, 0x1f), (35, 0x59), (36, 0x1f)] {
        let mut changed = original.to_vec();
        changed[start + offset] = replacement;
        assert_eq!(
            Head::from_canonical_cbor(&changed).err(),
            Some(Error::InvalidEncoding)
        );
    }
    Ok(())
}

#[test]
fn head_frontier_must_belong_to_the_exact_timeline_and_generation() -> TestResult {
    let rows = members(1);
    for (timeline, generation) in [(timeline(9), [8; 16]), (timeline(7), [9; 16])] {
        let input = head_input(
            Frontier::Committed(Pass::new(timeline, generation, 1)?),
            &rows,
        );
        assert_eq!(Head::new(input).err(), Some(Error::InvalidBinding));
    }
    for (field, length) in [(2, 16), (3, 16), (7, 32), (8, 32)] {
        let mut fields = head_fields(&head_input(Frontier::Initial, &rows))?;
        fields[field] = bytes(&vec![0; length]);
        assert_eq!(
            Head::from_canonical_cbor(&encode(&Value::Array(fields))?).err(),
            Some(Error::InvalidBinding)
        );
    }
    Ok(())
}

#[test]
fn head_refuses_empty_oversized_duplicate_unordered_or_zero_member_rows() -> TestResult {
    for count in [0, 65] {
        let rows = members(count);
        let input = head_input(Frontier::Initial, &rows);
        let encoded = encode(&Value::Array(head_fields(&input)?))?;
        assert_eq!(Head::new(input).err(), Some(Error::BoundsExceeded));
        assert_eq!(
            Head::from_canonical_cbor(&encoded).err(),
            Some(Error::BoundsExceeded)
        );
    }
    let mut duplicate = members(2);
    duplicate[1] = duplicate[0];
    assert_eq!(
        Head::new(head_input(Frontier::Initial, &duplicate)).err(),
        Some(Error::InvalidBinding)
    );
    let mut unordered = members(2);
    unordered.reverse();
    assert_eq!(
        Head::new(head_input(Frontier::Initial, &unordered)).err(),
        Some(Error::InvalidBinding)
    );
    for zero_member in [true, false] {
        let mut rows = members(1);
        if zero_member {
            rows[0].member_binding_digest = Hash::zero();
        } else {
            rows[0].member_progress_digest = Hash::zero();
        }
        let input = head_input(Frontier::Initial, &rows);
        let encoded = encode(&Value::Array(head_fields(&input)?))?;
        assert_eq!(
            Head::from_canonical_cbor(&encoded).err(),
            Some(Error::InvalidBinding)
        );
    }
    Ok(())
}

#[test]
fn head_refuses_all_truncations_and_closed_frontier_or_member_shapes() -> TestResult {
    let rows = members(1);
    let input = head_input(
        Frontier::Committed(Pass::new(timeline(7), [8; 16], 1)?),
        &rows,
    );
    let encoded = encode(&Value::Array(head_fields(&input)?))?;
    framing_refuses(&encoded, 65_536, |bytes| {
        Head::from_canonical_cbor(bytes).map(|_| ())
    });
    for frontier in [
        Value::Array(vec![uint(2)]),
        Value::Array(vec![uint(0), Value::Null]),
        Value::Array(vec![uint(1)]),
        Value::Array(vec![uint(1), bytes(&pass_bytes(0)?)]),
        Value::Array(vec![uint(1), bytes(&[0; 65])]),
        Value::Null,
    ] {
        let mut fields = head_fields(&input)?;
        fields[4] = frontier;
        assert!(Head::from_canonical_cbor(&encode(&Value::Array(fields))?).is_err());
    }
    for member in [
        Value::Null,
        Value::Array(vec![bytes(&[1; 32])]),
        Value::Array(vec![bytes(&[1; 32]), bytes(&[2; 31])]),
    ] {
        let mut fields = head_fields(&input)?;
        fields[5] = Value::Array(vec![member]);
        assert!(Head::from_canonical_cbor(&encode(&Value::Array(fields))?).is_err());
    }
    Ok(())
}

#[test]
fn head_bounds_member_count_before_reading_or_allocating_rows() -> TestResult {
    let rows = members(1);
    let fields = head_fields(&head_input(Frontier::Initial, &rows))?;
    let mut encoded = encode(&Value::Array(fields[..5].to_vec()))?;
    encoded[0] = 0x89;
    encoded.extend_from_slice(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    assert_eq!(
        Head::from_canonical_cbor(&encoded).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn head_roster_decode_borrows_exact_original_wire_rows() -> TestResult {
    let rows = members(64);
    let original = Head::new(head_input(Frontier::Initial, &rows))?;
    assert!(original
        .as_input()
        .member_heads
        .as_canonical_rows()
        .is_none());
    let encoded = original.to_canonical_cbor();
    let restored = Head::from_canonical_cbor(&encoded)?;
    let borrowed = restored
        .as_input()
        .member_heads
        .as_canonical_rows()
        .ok_or("missing borrowed rows")?;
    assert_eq!(borrowed.len(), 64 * 69);
    let offset = 45;
    assert_eq!(borrowed.as_ptr(), encoded[offset..].as_ptr());
    assert_eq!(borrowed, &encoded[offset..offset + 64 * 69]);
    assert!(restored
        .as_input()
        .member_heads
        .iter()
        .eq(rows.iter().copied()));
    assert!(original.as_input() == restored.as_input());
    Ok(())
}
