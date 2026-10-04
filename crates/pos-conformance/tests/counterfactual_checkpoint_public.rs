#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Public-interface tests for the ADR-064 RCP1 recompute-checkpoint contract.

use ciborium::value::Value;
use pos_conformance::counterfactual::checkpoint::{
    CheckpointDigestEntryV1, ExogenousCursorV1, RecomputeCheckpointContractErrorV1 as RcpError,
    RecomputeCheckpointV1, MAX_CHECKPOINT_DIGEST_ENTRIES_V1, MAX_CHECKPOINT_OWNER_ID_BYTES_V1,
    MAX_EXOGENOUS_CURSOR_POSITION_V1, MAX_RECOMPUTE_CHECKPOINT_BYTES_V1,
    RECOMPUTE_CHECKPOINT_MAGIC_V1,
};
use std::io::Cursor;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type ListSelector = fn(&mut RecomputeCheckpointV1) -> &mut Vec<CheckpointDigestEntryV1>;

const FIELD_PLAN: usize = 2;
const FIELD_TICK: usize = 3;
const FIELD_SCHEDULER_POSITION: usize = 5;
const FIELD_PLUGINS: usize = 6;
const FIELD_PROJECTIONS: usize = 7;
const FIELD_STATE: usize = 8;
const FIELD_CURSOR: usize = 9;
const FIELD_PROVENANCE: usize = 10;
const FIELD_DIGEST: usize = 11;

const LISTS: [(usize, ListSelector); 3] = [
    (FIELD_PLUGINS, plugin_state_digests),
    (FIELD_PROJECTIONS, projection_digests),
    (FIELD_STATE, state_digests),
];

const fn plugin_state_digests(
    checkpoint: &mut RecomputeCheckpointV1,
) -> &mut Vec<CheckpointDigestEntryV1> {
    &mut checkpoint.plugin_state_digests
}

const fn projection_digests(
    checkpoint: &mut RecomputeCheckpointV1,
) -> &mut Vec<CheckpointDigestEntryV1> {
    &mut checkpoint.projection_digests
}

const fn state_digests(
    checkpoint: &mut RecomputeCheckpointV1,
) -> &mut Vec<CheckpointDigestEntryV1> {
    &mut checkpoint.state_digests
}

fn entry(owner_id: &str, fill: u8) -> CheckpointDigestEntryV1 {
    CheckpointDigestEntryV1 {
        owner_id: owner_id.to_owned(),
        digest: [fill; 32],
    }
}

fn sealed(mut checkpoint: RecomputeCheckpointV1) -> TestResult<RecomputeCheckpointV1> {
    checkpoint.checkpoint_digest = checkpoint.digest()?;
    Ok(checkpoint)
}

fn sample() -> TestResult<RecomputeCheckpointV1> {
    sealed(RecomputeCheckpointV1 {
        plan_digest: [1; 32],
        tick: 7,
        seq: 42,
        scheduler_position: 3,
        plugin_state_digests: vec![entry("plugin.alpha", 2), entry("plugin.beta", 3)],
        projection_digests: vec![entry("projection.ledger", 4)],
        state_digests: vec![entry("state.world", 5)],
        exogenous_cursor: ExogenousCursorV1 {
            consumed_descriptors: 2,
            last_descriptor_digest: Some([6; 32]),
        },
        provenance_root: [8; 32],
        checkpoint_digest: [0; 32],
    })
}

fn encode(value: &Value) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn sample_fields() -> TestResult<Vec<Value>> {
    let bytes = sample()?.to_canonical_cbor()?;
    match ciborium::from_reader(Cursor::new(bytes))? {
        Value::Array(fields) => Ok(fields),
        _ => Err("RCP1 must be represented by a CBOR array".into()),
    }
}

fn replace_field(index: usize, replacement: Value) -> TestResult<Vec<u8>> {
    let mut fields = sample_fields()?;
    fields[index] = replacement;
    encode(&Value::Array(fields))
}

fn decode_error(bytes: &[u8]) -> Option<RcpError> {
    RecomputeCheckpointV1::from_canonical_cbor(bytes).err()
}

fn assert_structural_error(checkpoint: &RecomputeCheckpointV1, expected: RcpError) {
    assert_eq!(checkpoint.digest(), Err(expected));
    assert_eq!(checkpoint.validate(), Err(expected));
    assert_eq!(checkpoint.to_canonical_cbor(), Err(expected));
}

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

fn digest_value(fill: u8) -> Value {
    Value::Bytes(vec![fill; 32])
}

fn entry_value(owner_id: &str, fill: u8) -> Value {
    Value::Array(vec![Value::Text(owner_id.to_owned()), digest_value(fill)])
}

fn owner_ids(count: usize) -> Vec<CheckpointDigestEntryV1> {
    (0..count)
        .map(|index| entry(&format!("owner.{index:05}"), 9))
        .collect()
}

fn find(haystack: &[u8], needle: &[u8]) -> TestResult<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
        .ok_or_else(|| "needle is absent".into())
}

#[test]
fn canonical_checkpoint_roundtrips_with_exact_twelve_field_shape() -> TestResult {
    let checkpoint = sample()?;
    let bytes = checkpoint.to_canonical_cbor()?;
    let decoded = RecomputeCheckpointV1::from_canonical_cbor(&bytes)?;

    assert_eq!(decoded, checkpoint);
    assert_eq!(decoded.to_canonical_cbor()?, bytes);
    assert_eq!(decoded.validate(), Ok(()));
    assert_eq!(decoded.digest()?, checkpoint.checkpoint_digest);
    let fields = sample_fields()?;
    assert_eq!(fields.len(), 12);
    assert_eq!(
        fields[0],
        Value::Text(RECOMPUTE_CHECKPOINT_MAGIC_V1.to_owned())
    );
    assert_eq!(RECOMPUTE_CHECKPOINT_MAGIC_V1, "RCP1");
    assert_eq!(fields[1], uint(1));
    assert_eq!(fields[FIELD_TICK], uint(7));
    assert_eq!(fields[4], uint(42));
    assert_eq!(fields[FIELD_SCHEDULER_POSITION], uint(3));
    assert_eq!(
        fields[FIELD_CURSOR],
        Value::Array(vec![uint(2), digest_value(6)])
    );
    Ok(())
}

#[test]
fn digest_is_domain_separated_over_fields_zero_through_ten() -> TestResult {
    let checkpoint = sample()?;
    let mut fields = sample_fields()?;
    assert_eq!(
        fields.pop(),
        Some(Value::Bytes(checkpoint.checkpoint_digest.to_vec()))
    );
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.RecomputeCheckpoint.v1\0");
    hasher.update(&encode(&Value::Array(fields))?);
    assert_eq!(*hasher.finalize().as_bytes(), checkpoint.checkpoint_digest);
    Ok(())
}

#[test]
fn every_bound_field_is_digest_mutation_sensitive() -> TestResult {
    let original = sample()?;
    let mutations: [fn(&mut RecomputeCheckpointV1); 12] = [
        |checkpoint| checkpoint.plan_digest[0] ^= 1,
        |checkpoint| checkpoint.tick += 1,
        |checkpoint| checkpoint.seq += 1,
        |checkpoint| checkpoint.scheduler_position += 1,
        |checkpoint| checkpoint.plugin_state_digests[0].digest[31] ^= 1,
        |checkpoint| checkpoint.plugin_state_digests[1].owner_id.push('z'),
        |checkpoint| checkpoint.projection_digests[0].digest[0] ^= 1,
        |checkpoint| checkpoint.state_digests[0].digest[0] ^= 1,
        |checkpoint| checkpoint.state_digests[0].owner_id.push('z'),
        |checkpoint| checkpoint.exogenous_cursor.consumed_descriptors += 1,
        |checkpoint| {
            checkpoint.exogenous_cursor.last_descriptor_digest = Some([7; 32]);
        },
        |checkpoint| checkpoint.provenance_root[0] ^= 1,
    ];
    for mutate in mutations {
        let mut mutated = original.clone();
        mutate(&mut mutated);
        assert_eq!(mutated.validate(), Err(RcpError::DigestMismatch));
        assert_eq!(mutated.to_canonical_cbor(), Err(RcpError::DigestMismatch));
        let resealed = sealed(mutated)?;
        assert_ne!(resealed.checkpoint_digest, original.checkpoint_digest);
        let bytes = resealed.to_canonical_cbor()?;
        assert_eq!(
            RecomputeCheckpointV1::from_canonical_cbor(&bytes)?,
            resealed
        );
    }
    Ok(())
}

#[test]
fn declared_digest_mismatch_is_rejected_by_every_entry_point() -> TestResult {
    let mut checkpoint = sample()?;
    checkpoint.checkpoint_digest[0] ^= 1;
    assert_eq!(checkpoint.validate(), Err(RcpError::DigestMismatch));
    assert_eq!(
        checkpoint.to_canonical_cbor(),
        Err(RcpError::DigestMismatch)
    );
    assert_eq!(checkpoint.digest()?, sample()?.checkpoint_digest);
    assert_eq!(
        decode_error(&replace_field(FIELD_DIGEST, digest_value(9))?),
        Some(RcpError::DigestMismatch)
    );
    let mut bytes = sample()?.to_canonical_cbor()?;
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert_eq!(decode_error(&bytes), Some(RcpError::DigestMismatch));
    Ok(())
}

#[test]
fn errors_keep_distinct_public_messages() {
    for (error, message) in [
        (
            RcpError::InvalidEncoding,
            "invalid RCP1 recompute checkpoint encoding",
        ),
        (
            RcpError::UnsupportedVersion,
            "unsupported RCP1 recompute checkpoint version",
        ),
        (
            RcpError::FieldOutOfBounds,
            "RCP1 recompute checkpoint field is out of bounds",
        ),
        (
            RcpError::NonCanonicalOrder,
            "RCP1 recompute checkpoint lists are not canonical",
        ),
        (
            RcpError::DuplicateIdentity,
            "RCP1 recompute checkpoint owner is duplicated",
        ),
        (
            RcpError::DigestMismatch,
            "RCP1 recompute checkpoint digest does not match",
        ),
    ] {
        assert_eq!(error.to_string(), message);
        assert!(std::error::Error::source(&error).is_none());
    }
}

#[test]
fn encoded_size_limit_is_checked_before_decoding() {
    assert_eq!(MAX_RECOMPUTE_CHECKPOINT_BYTES_V1, 16 * 1024 * 1024);
    let at_limit = vec![0; MAX_RECOMPUTE_CHECKPOINT_BYTES_V1];
    assert_eq!(decode_error(&at_limit), Some(RcpError::InvalidEncoding));
    let over_limit = vec![0x8c; MAX_RECOMPUTE_CHECKPOINT_BYTES_V1 + 1];
    assert_eq!(decode_error(&over_limit), Some(RcpError::FieldOutOfBounds));
}

#[test]
fn decoder_rejects_unsupported_magic_and_version() -> TestResult {
    for (index, replacement, expected) in [
        (
            0,
            Value::Text("RCP2".to_owned()),
            RcpError::UnsupportedVersion,
        ),
        (0, Value::Bytes(b"RCP1".to_vec()), RcpError::InvalidEncoding),
        (1, uint(0), RcpError::UnsupportedVersion),
        (1, uint(2), RcpError::UnsupportedVersion),
        (1, Value::Text("1".to_owned()), RcpError::InvalidEncoding),
    ] {
        assert_eq!(
            decode_error(&replace_field(index, replacement)?),
            Some(expected)
        );
    }
    Ok(())
}

#[test]
fn decoder_checks_the_header_before_the_field_count() -> TestResult {
    let mut short = sample_fields()?;
    short.truncate(FIELD_CURSOR);
    for (index, replacement) in [(0, Value::Text("RCP2".to_owned())), (1, uint(2))] {
        let mut future = short.clone();
        future[index] = replacement;
        assert_eq!(
            decode_error(&encode(&Value::Array(future))?),
            Some(RcpError::UnsupportedVersion)
        );
    }
    assert_eq!(
        decode_error(&encode(&Value::Array(short))?),
        Some(RcpError::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn decoder_rejects_wrong_field_types_and_shapes() -> TestResult {
    let negative = Value::Integer((-1_i64).into());
    for (index, replacement) in [
        (FIELD_PLAN, Value::Bytes(vec![1; 31])),
        (FIELD_PLAN, Value::Text("plan".to_owned())),
        (FIELD_TICK, negative.clone()),
        (FIELD_TICK, Value::Null),
        (4, Value::Bool(true)),
        (FIELD_SCHEDULER_POSITION, negative.clone()),
        (FIELD_PLUGINS, Value::Null),
        (FIELD_PLUGINS, Value::Array(vec![digest_value(2)])),
        (
            FIELD_PLUGINS,
            Value::Array(vec![Value::Array(vec![Value::Text("p".to_owned())])]),
        ),
        (
            FIELD_PLUGINS,
            Value::Array(vec![Value::Array(vec![uint(1), digest_value(2)])]),
        ),
        (
            FIELD_PLUGINS,
            Value::Array(vec![Value::Array(vec![
                Value::Text("p".to_owned()),
                Value::Bytes(vec![2; 33]),
            ])]),
        ),
        (FIELD_CURSOR, Value::Null),
        (FIELD_CURSOR, Value::Array(vec![uint(0)])),
        (FIELD_CURSOR, Value::Array(vec![negative, Value::Null])),
        (
            FIELD_CURSOR,
            Value::Array(vec![uint(1), Value::Text("d".to_owned())]),
        ),
        (FIELD_PROVENANCE, Value::Null),
        (FIELD_DIGEST, Value::Bytes(vec![0; 16])),
    ] {
        assert_eq!(
            decode_error(&replace_field(index, replacement)?),
            Some(RcpError::InvalidEncoding),
            "field {index}"
        );
    }
    Ok(())
}

#[test]
fn decoder_rejects_missing_unknown_and_non_array_records() -> TestResult {
    let mut missing = sample_fields()?;
    missing.pop();
    assert_eq!(
        decode_error(&encode(&Value::Array(missing))?),
        Some(RcpError::InvalidEncoding)
    );
    let mut unknown = sample_fields()?;
    unknown.push(Value::Null);
    assert_eq!(
        decode_error(&encode(&Value::Array(unknown))?),
        Some(RcpError::InvalidEncoding)
    );
    assert_eq!(
        decode_error(&encode(&uint(1))?),
        Some(RcpError::InvalidEncoding)
    );
    let map = Value::Map(vec![(uint(0), uint(1))]);
    assert_eq!(
        decode_error(&encode(&map)?),
        Some(RcpError::InvalidEncoding)
    );
    let tagged = Value::Tag(24, Box::new(uint(1)));
    assert_eq!(
        decode_error(&encode(&tagged)?),
        Some(RcpError::InvalidEncoding)
    );
    let float = replace_field(FIELD_TICK, Value::Float(1.5))?;
    assert_eq!(decode_error(&float), Some(RcpError::InvalidEncoding));
    assert_eq!(decode_error(&[]), Some(RcpError::InvalidEncoding));
    Ok(())
}

#[test]
fn decoder_rejects_noncanonical_trailing_truncated_and_invalid_text_bytes() -> TestResult {
    let canonical = sample()?.to_canonical_cbor()?;
    assert_eq!(canonical[0], 0x8c);

    let mut long_header = vec![0x98, 0x0c];
    long_header.extend_from_slice(&canonical[1..]);
    assert_eq!(decode_error(&long_header), Some(RcpError::InvalidEncoding));

    let mut indefinite = vec![0x9f];
    indefinite.extend_from_slice(&canonical[1..]);
    indefinite.push(0xff);
    assert_eq!(decode_error(&indefinite), Some(RcpError::InvalidEncoding));

    let mut trailing = canonical.clone();
    trailing.push(0);
    assert_eq!(decode_error(&trailing), Some(RcpError::InvalidEncoding));

    let truncated = &canonical[..canonical.len() - 1];
    assert_eq!(decode_error(truncated), Some(RcpError::InvalidEncoding));

    let mut invalid_utf8 = canonical;
    let owner = find(&invalid_utf8, b"plugin.alpha")?;
    invalid_utf8[owner] = 0xff;
    assert_eq!(decode_error(&invalid_utf8), Some(RcpError::InvalidEncoding));
    Ok(())
}

#[test]
fn decoder_bounds_nesting_depth_and_list_items_before_allocation() -> TestResult {
    let depth_three = Value::Array(vec![Value::Array(vec![
        Value::Text("p".to_owned()),
        Value::Array(Vec::new()),
    ])]);
    assert_eq!(
        decode_error(&replace_field(FIELD_PLUGINS, depth_three)?),
        Some(RcpError::InvalidEncoding)
    );
    let depth_four = Value::Array(vec![Value::Array(vec![
        Value::Text("p".to_owned()),
        Value::Array(vec![Value::Array(Vec::new())]),
    ])]);
    assert_eq!(
        decode_error(&replace_field(FIELD_PLUGINS, depth_four)?),
        Some(RcpError::FieldOutOfBounds)
    );
    let over_limit = (0..=MAX_CHECKPOINT_DIGEST_ENTRIES_V1)
        .map(|index| entry_value(&format!("owner.{index:05}"), 9))
        .collect();
    assert_eq!(
        decode_error(&replace_field(FIELD_STATE, Value::Array(over_limit))?),
        Some(RcpError::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn scheduler_position_is_bounded_to_u32() -> TestResult {
    let mut checkpoint = sample()?;
    checkpoint.scheduler_position = u32::MAX;
    let checkpoint = sealed(checkpoint)?;
    let bytes = checkpoint.to_canonical_cbor()?;
    assert_eq!(
        RecomputeCheckpointV1::from_canonical_cbor(&bytes)?,
        checkpoint
    );
    assert_eq!(
        decode_error(&replace_field(
            FIELD_SCHEDULER_POSITION,
            uint(u64::from(u32::MAX) + 1)
        )?),
        Some(RcpError::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn plan_and_provenance_identities_must_be_nonzero() -> TestResult {
    let mut zero_plan = sample()?;
    zero_plan.plan_digest = [0; 32];
    assert_structural_error(&zero_plan, RcpError::FieldOutOfBounds);
    let mut zero_provenance = sample()?;
    zero_provenance.provenance_root = [0; 32];
    assert_structural_error(&zero_provenance, RcpError::FieldOutOfBounds);
    for field in [FIELD_PLAN, FIELD_PROVENANCE] {
        assert_eq!(
            decode_error(&replace_field(field, digest_value(0))?),
            Some(RcpError::FieldOutOfBounds)
        );
    }
    Ok(())
}

#[test]
fn digest_lists_enforce_entry_count_bounds() -> TestResult {
    let mut empty_optional = sample()?;
    empty_optional.plugin_state_digests.clear();
    empty_optional.projection_digests.clear();
    let empty_optional = sealed(empty_optional)?;
    let bytes = empty_optional.to_canonical_cbor()?;
    assert_eq!(
        RecomputeCheckpointV1::from_canonical_cbor(&bytes)?,
        empty_optional
    );

    let mut empty_state = sample()?;
    empty_state.state_digests.clear();
    assert_structural_error(&empty_state, RcpError::FieldOutOfBounds);
    assert_eq!(
        decode_error(&replace_field(FIELD_STATE, Value::Array(Vec::new()))?),
        Some(RcpError::FieldOutOfBounds)
    );

    for (_, select) in LISTS {
        let mut at_limit = sample()?;
        *select(&mut at_limit) = owner_ids(MAX_CHECKPOINT_DIGEST_ENTRIES_V1);
        let at_limit = sealed(at_limit)?;
        let bytes = at_limit.to_canonical_cbor()?;
        assert_eq!(
            RecomputeCheckpointV1::from_canonical_cbor(&bytes)?,
            at_limit
        );

        let mut over_limit = sample()?;
        *select(&mut over_limit) = owner_ids(MAX_CHECKPOINT_DIGEST_ENTRIES_V1 + 1);
        assert_structural_error(&over_limit, RcpError::FieldOutOfBounds);
    }
    Ok(())
}

#[test]
fn digest_entries_require_bounded_owner_ids_and_nonzero_digests() -> TestResult {
    let at_limit = "o".repeat(MAX_CHECKPOINT_OWNER_ID_BYTES_V1);
    let multibyte_at_limit = "\u{3a9}".repeat(MAX_CHECKPOINT_OWNER_ID_BYTES_V1 / 2);
    for owner_id in [at_limit.as_str(), multibyte_at_limit.as_str(), "B"] {
        for (_, select) in LISTS {
            let mut checkpoint = sample()?;
            *select(&mut checkpoint) = vec![entry(owner_id, 9)];
            let checkpoint = sealed(checkpoint)?;
            let bytes = checkpoint.to_canonical_cbor()?;
            assert_eq!(
                RecomputeCheckpointV1::from_canonical_cbor(&bytes)?,
                checkpoint
            );
        }
    }

    let over_limit = "o".repeat(MAX_CHECKPOINT_OWNER_ID_BYTES_V1 + 1);
    let multibyte_over_limit = "\u{3a9}".repeat(MAX_CHECKPOINT_OWNER_ID_BYTES_V1 / 2 + 1);
    for invalid in [
        entry("", 9),
        entry(&over_limit, 9),
        entry(&multibyte_over_limit, 9),
        entry("owner.zero", 0),
    ] {
        for (index, select) in LISTS {
            let mut checkpoint = sample()?;
            *select(&mut checkpoint) = vec![invalid.clone()];
            assert_structural_error(&checkpoint, RcpError::FieldOutOfBounds);
            let encoded = Value::Array(vec![Value::Array(vec![
                Value::Text(invalid.owner_id.clone()),
                Value::Bytes(invalid.digest.to_vec()),
            ])]);
            assert_eq!(
                decode_error(&replace_field(index, encoded)?),
                Some(RcpError::FieldOutOfBounds)
            );
        }
    }
    Ok(())
}

#[test]
fn digest_lists_are_strictly_ordered_by_owner_bytes() -> TestResult {
    for (index, select) in LISTS {
        let mut byte_ordered = sample()?;
        *select(&mut byte_ordered) = vec![entry("Zeta", 2), entry("alpha", 3), entry("beta", 4)];
        let byte_ordered = sealed(byte_ordered)?;
        let bytes = byte_ordered.to_canonical_cbor()?;
        assert_eq!(
            RecomputeCheckpointV1::from_canonical_cbor(&bytes)?,
            byte_ordered
        );

        let mut reversed = sample()?;
        *select(&mut reversed) = vec![entry("alpha", 2), entry("gamma", 3), entry("beta", 4)];
        assert_structural_error(&reversed, RcpError::NonCanonicalOrder);
        let encoded = Value::Array(vec![entry_value("beta", 2), entry_value("alpha", 3)]);
        assert_eq!(
            decode_error(&replace_field(index, encoded)?),
            Some(RcpError::NonCanonicalOrder)
        );

        let mut duplicated = sample()?;
        *select(&mut duplicated) = vec![entry("alpha", 2), entry("alpha", 3)];
        assert_structural_error(&duplicated, RcpError::DuplicateIdentity);
        let encoded = Value::Array(vec![entry_value("alpha", 2), entry_value("alpha", 2)]);
        assert_eq!(
            decode_error(&replace_field(index, encoded)?),
            Some(RcpError::DuplicateIdentity)
        );
    }
    Ok(())
}

#[test]
fn exogenous_cursor_binds_count_to_last_descriptor_digest() -> TestResult {
    let valid = [
        (0, None),
        (1, Some([6; 32])),
        (MAX_EXOGENOUS_CURSOR_POSITION_V1, Some([6; 32])),
    ];
    for (consumed_descriptors, last_descriptor_digest) in valid {
        let mut checkpoint = sample()?;
        checkpoint.exogenous_cursor = ExogenousCursorV1 {
            consumed_descriptors,
            last_descriptor_digest,
        };
        let checkpoint = sealed(checkpoint)?;
        let bytes = checkpoint.to_canonical_cbor()?;
        assert_eq!(
            RecomputeCheckpointV1::from_canonical_cbor(&bytes)?,
            checkpoint
        );
    }
    assert_eq!(MAX_EXOGENOUS_CURSOR_POSITION_V1, 65_536);

    let invalid = [
        (0, Some([6; 32])),
        (1, None),
        (3, Some([0; 32])),
        (MAX_EXOGENOUS_CURSOR_POSITION_V1 + 1, Some([6; 32])),
        (u64::MAX, Some([6; 32])),
    ];
    for (consumed_descriptors, last_descriptor_digest) in invalid {
        let mut checkpoint = sample()?;
        checkpoint.exogenous_cursor = ExogenousCursorV1 {
            consumed_descriptors,
            last_descriptor_digest,
        };
        assert_structural_error(&checkpoint, RcpError::FieldOutOfBounds);
        let encoded = Value::Array(vec![
            uint(consumed_descriptors),
            last_descriptor_digest.map_or(Value::Null, |digest| Value::Bytes(digest.to_vec())),
        ]);
        assert_eq!(
            decode_error(&replace_field(FIELD_CURSOR, encoded)?),
            Some(RcpError::FieldOutOfBounds)
        );
    }
    Ok(())
}
