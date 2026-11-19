//! ADR-129 §4 CBQ1 pre-Reserve budget quote at its public seam, with the
//! code-0 initialization quote of the owner decisions on #560 (notes 22722
//! G3 and 22729).
//!
//! Every expected wire is built independently with `ciborium` from the ADR
//! field list, and every digest with `blake3` from the `H(record)` rule.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    CommunityBudgetQuoteInputV1 as QuoteInput, CommunityBudgetQuoteV1 as Quote,
    CommunityDueMemberBudgetV1 as Due, CommunityLifecycleErrorV1 as Error,
    CommunitySharedCountsV1 as Counts, COMMUNITY_INITIALIZATION_MEMBER_BYTES_V1,
    COMMUNITY_SHARED_RECORD_LIMITS_V1, MAX_COMMUNITY_BUDGET_QUOTE_BYTES_V1,
};
use pos_core::{Hash, TimelineId};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const GENERATION: [u8; 16] = [2; 16];

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
fn record_digest(encoded: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.Community.CBQ1.v1\0");
    hasher.update(encoded);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

const fn due(member: u8, tuple: u8) -> Due {
    Due {
        member_binding_digest: hash(member),
        negotiated_tuple_digest: hash(tuple),
    }
}

fn input() -> QuoteInput {
    QuoteInput {
        timeline: timeline(4),
        generation: GENERATION,
        profile_digest: hash(9),
        prior_shared_counts: Counts {
            nodes: 1,
            edges: 2,
            declared_inputs: 3,
            encoded_record_bytes: 4,
        },
        due_members: vec![due(10, 11), due(12, 11)],
        maximum_required_nodes: 5,
        maximum_required_edges: 6,
        maximum_required_bytes: 7,
    }
}

/// The ADR-129 §4 field list, in order.
fn quote_value(input: &QuoteInput) -> Value {
    let counts = input.prior_shared_counts;
    Value::Array(vec![
        bytes(b"CBQ1"),
        uint(1),
        bytes(&input.timeline.inner().to_bytes()),
        bytes(&input.generation),
        bytes(input.profile_digest.as_bytes()),
        Value::Array(vec![
            uint(counts.nodes),
            uint(counts.edges),
            uint(counts.declared_inputs),
            uint(counts.encoded_record_bytes),
        ]),
        Value::Array(
            input
                .due_members
                .iter()
                .map(|row| {
                    Value::Array(vec![
                        bytes(row.member_binding_digest.as_bytes()),
                        bytes(row.negotiated_tuple_digest.as_bytes()),
                    ])
                })
                .collect(),
        ),
        uint(input.maximum_required_nodes),
        uint(input.maximum_required_edges),
        uint(input.maximum_required_bytes),
    ])
}

fn assert_round_trip(input: &QuoteInput) -> TestResult {
    let expected = encode(&quote_value(input))?;
    let quote = Quote::new(input.clone())?;
    assert_eq!(quote.to_canonical_cbor().as_slice(), expected.as_slice());
    assert_eq!(quote.digest(), record_digest(&expected));
    assert!(quote.as_input() == input);
    let decoded = Quote::from_canonical_cbor(&expected)?;
    assert!(decoded == quote);
    Ok(())
}

fn decode_error(value: &Value) -> Fallible<Option<Error>> {
    Ok(Quote::from_canonical_cbor(&encode(value)?).err())
}

#[test]
fn cbq1_round_trips_the_exact_ten_fields() -> TestResult {
    assert_round_trip(&input())?;
    // One due row, zero counts and wide heads everywhere.
    assert_round_trip(&QuoteInput {
        prior_shared_counts: Counts {
            nodes: u64::MAX,
            edges: 0,
            declared_inputs: u64::MAX,
            encoded_record_bytes: 0,
        },
        due_members: vec![due(10, 11)],
        maximum_required_nodes: u64::MAX,
        maximum_required_edges: 0,
        maximum_required_bytes: u64::MAX,
        ..input()
    })?;
    // Roster order, not digest order.
    assert_round_trip(&QuoteInput {
        due_members: vec![due(12, 11), due(10, 13)],
        ..input()
    })?;
    // The full 64-member roster.
    assert_round_trip(&QuoteInput {
        due_members: (1..=64).map(|member| due(member, 200)).collect(),
        ..input()
    })
}

/// G3 and note 22729: zero prior counts, `2n` nodes and edges, and `n`
/// per-member encoding bounds.
#[test]
fn initialization_quote_has_the_owner_decided_maxima() -> TestResult {
    let rows = vec![due(10, 11), due(12, 13), due(14, 11)];
    let quote = Quote::initialization(timeline(4), GENERATION, hash(9), rows.clone())?;
    assert!(
        *quote.as_input()
            == QuoteInput {
                timeline: timeline(4),
                generation: GENERATION,
                profile_digest: hash(9),
                prior_shared_counts: Counts {
                    nodes: 0,
                    edges: 0,
                    declared_inputs: 0,
                    encoded_record_bytes: 0,
                },
                due_members: rows,
                maximum_required_nodes: 6,
                maximum_required_edges: 6,
                maximum_required_bytes: 3 * 3_147_312,
            }
    );
    // CSC1 + CIS1 + CSR1 + two CPN1s.
    assert_eq!(
        COMMUNITY_INITIALIZATION_MEMBER_BYTES_V1,
        1_048_624 + 1_024 + 512 + 2 * 1_048_576
    );
    assert_eq!(
        Quote::initialization(timeline(4), GENERATION, hash(9), vec![]).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn cbq1_refuses_invalid_bindings() {
    let cases = [
        QuoteInput {
            timeline: timeline(0),
            ..input()
        },
        QuoteInput {
            generation: [0; 16],
            ..input()
        },
        QuoteInput {
            profile_digest: Hash::zero(),
            ..input()
        },
        QuoteInput {
            due_members: vec![due(10, 11), due(0, 11)],
            ..input()
        },
        QuoteInput {
            due_members: vec![due(10, 0), due(12, 11)],
            ..input()
        },
        // A repeated member digest, adjacent or not.
        QuoteInput {
            due_members: vec![due(10, 11), due(10, 12)],
            ..input()
        },
        QuoteInput {
            due_members: vec![due(10, 11), due(12, 11), due(10, 13)],
            ..input()
        },
    ];
    for case in cases {
        assert_eq!(Quote::new(case).err(), Some(Error::InvalidBinding));
    }
}

#[test]
fn cbq1_bounds_the_due_rows() -> TestResult {
    for count in [0, 65] {
        let rows: Vec<Due> = (1..=count).map(|member| due(member, 200)).collect();
        let case = QuoteInput {
            due_members: rows,
            ..input()
        };
        let value = quote_value(&case);
        assert_eq!(Quote::new(case).err(), Some(Error::BoundsExceeded));
        assert_eq!(decode_error(&value)?, Some(Error::BoundsExceeded));
    }
    Ok(())
}

#[test]
fn cbq1_decoding_rejects_noncanonical_and_foreign_records() -> TestResult {
    let valid = encode(&quote_value(&input()))?;
    let mut wide_version = valid.clone();
    wide_version.splice(6..7, [0x18, 0x01]);
    let mut indefinite = valid.clone();
    indefinite[0] = 0x9f;
    let mut trailing = valid.clone();
    trailing.push(0);
    let truncated = valid[..valid.len() - 1].to_vec();
    for bytes in [wide_version, indefinite, trailing, truncated] {
        assert_eq!(
            Quote::from_canonical_cbor(&bytes).err(),
            Some(Error::InvalidEncoding)
        );
    }
    let mut fields = quote_value(&input());
    let items = fields.as_array_mut().ok_or("array")?;
    items[1] = uint(2);
    assert_eq!(decode_error(&fields)?, Some(Error::UnsupportedVersion));
    let mut nine = quote_value(&input());
    nine.as_array_mut().ok_or("array")?.pop();
    assert_eq!(decode_error(&nine)?, Some(Error::InvalidEncoding));
    let mut magic = quote_value(&input());
    magic.as_array_mut().ok_or("array")?[0] = bytes(b"CPV1");
    assert_eq!(decode_error(&magic)?, Some(Error::InvalidEncoding));
    // Three counts, a three-field due row and a zero digest in a row.
    for (index, replacement) in [
        (5, Value::Array(vec![uint(1), uint(2), uint(3)])),
        (
            6,
            Value::Array(vec![Value::Array(vec![
                bytes(hash(10).as_bytes()),
                bytes(hash(11).as_bytes()),
                uint(0),
            ])]),
        ),
    ] {
        let mut value = quote_value(&input());
        value.as_array_mut().ok_or("array")?[index] = replacement;
        assert_eq!(decode_error(&value)?, Some(Error::InvalidEncoding));
    }
    let mut repeated = quote_value(&input());
    if let Some(Value::Array(rows)) = repeated.as_array_mut().ok_or("array")?.get_mut(6) {
        rows[1] = rows[0].clone();
    }
    assert_eq!(decode_error(&repeated)?, Some(Error::InvalidBinding));
    let oversized = vec![0; MAX_COMMUNITY_BUDGET_QUOTE_BYTES_V1 + 1];
    assert_eq!(
        Quote::from_canonical_cbor(&oversized).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

/// Owner decision 6 (2026-11-19): each maximum must fit its CDP1 shared
/// per-record limit, exactly at the limit and not one over.
#[test]
fn quotes_fit_the_shared_record_limits_exactly() -> TestResult {
    let [nodes, edges, bytes] = COMMUNITY_SHARED_RECORD_LIMITS_V1;
    assert_eq!(
        COMMUNITY_SHARED_RECORD_LIMITS_V1,
        [65_536, 262_144, 134_217_728]
    );
    let at = |nodes, edges, bytes| {
        Quote::new(QuoteInput {
            maximum_required_nodes: nodes,
            maximum_required_edges: edges,
            maximum_required_bytes: bytes,
            ..input()
        })
    };
    at(nodes, edges, bytes)?.require_within(COMMUNITY_SHARED_RECORD_LIMITS_V1)?;
    for (n, e, b) in [
        (nodes + 1, edges, bytes),
        (nodes, edges + 1, bytes),
        (nodes, edges, bytes + 1),
    ] {
        assert_eq!(
            at(n, e, b)?
                .require_within(COMMUNITY_SHARED_RECORD_LIMITS_V1)
                .err(),
            Some(Error::BoundsExceeded)
        );
    }
    Ok(())
}
