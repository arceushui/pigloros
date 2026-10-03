//! Public-seam tests for the ADR-105 records nested in `FAE1`: `FAI1`,
//! `FIP1`, `IKR1`, `IKT1`, `FEE1`, and `FTI1`.

use ciborium::Value;
use pos_core::{
    CanonicalBytes, EntityId, ForkAttributionCodecErrorV1 as CodecError,
    ForkAttributionIssuerPolicyEntryV1, ForkAttributionIssuerPolicyInputV1,
    ForkAttributionIssuerPolicyV1, ForkAttributionIssuerStateV1, ForkAttributionIssuerV1,
    ForkEventEvidenceV1, ForkTimelineImportInputV1, ForkTimelineImportV1, Hash,
    ImportedKeyRecordV1, ImportedKeyTombstoneV1, KeyIdentityV1, KeyRecordV1, KeyRoleV1,
    KeyTombstoneV1, PublicKey, Seq, Signature, TimelineMode, MAX_FORK_ATTRIBUTION_ISSUER_BYTES_V1,
    MAX_FORK_ATTRIBUTION_ISSUER_POLICY_BYTES_V1, MAX_FORK_ATTRIBUTION_ISSUER_POLICY_ENTRIES_V1,
    MAX_FORK_EVENT_EVIDENCE_BYTES_V1, MAX_FORK_TIMELINE_IMPORT_BYTES_V1,
    MAX_FORK_TIMELINE_IMPORT_NAME_BYTES_V1, MAX_IMPORTED_KEY_RECORD_BYTES_V1,
    MAX_IMPORTED_KEY_TOMBSTONE_BYTES_V1, MAX_TIMELINE_EVENT_ENVELOPE_BYTES_V1,
    MAX_TIMELINE_EVENT_PAYLOAD_BYTES_V1,
};
use ulid::Ulid;

pub mod common;

use common::{
    attribution_identity, encode, envelope_at, evidence, evidence_from, hash, issuer, items,
    timeline_id, unhex, widened, Fallible, TestResult,
};

/// Independently computed canonical vectors (see the PR description).
const FAI1_HEX: &str = "85644641493101686973737565722d61015820\
    2222222222222222222222222222222222222222222222222222222222222222";
const IKR1_HEX: &str = "8764494b5231016963726561746f722d6101015820\
    4444444444444444444444444444444444444444444444444444444444444444\
    5820\
    5555555555555555555555555555555555555555555555555555555555555555";
const FTI1_HEX: &str = "8a6446544931015002020202020202020202020202020202\
    0064666f726bf6500101010101010101010101010101010104005820\
    6666666666666666666666666666666666666666666666666666666666666666";

/// Offset of the `FAI1` epoch: array head, marker, version, and the
/// nine-byte `"issuer-a"` text item.
const FAI1_EPOCH_AT: usize = 1 + 5 + 1 + 9;
/// Offset of the first `"issuer-a"` text byte.
const FAI1_ISSUER_TEXT_AT: usize = 1 + 5 + 1 + 1;

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn int(value: u64) -> Value {
    Value::Integer(value.into())
}

/// Every strict prefix of a canonical record fails closed as malformed.
fn truncations_fail<T>(bytes: &[u8], decode: impl Fn(&[u8]) -> Result<T, CodecError>) {
    for end in 0..bytes.len() {
        assert_eq!(
            decode(&bytes[..end]).err(),
            Some(CodecError::InvalidEncoding),
            "prefix of {end} bytes"
        );
    }
}

/// Replace one top-level field and return the decoder result's error.
fn mutated<T>(
    canonical: &[u8],
    at: usize,
    value: Value,
    decode: impl Fn(&[u8]) -> Result<T, CodecError>,
) -> Fallible<Option<CodecError>> {
    let mut fields = items(canonical)?;
    *fields.get_mut(at).ok_or("field index")? = value;
    Ok(decode(&encode(fields)?).err())
}

#[test]
fn fai1_matches_independent_vector_and_round_trips() -> TestResult {
    let issuer = issuer()?;
    let bytes = issuer.to_canonical_cbor();
    assert_eq!(bytes, unhex(FAI1_HEX)?);
    assert_eq!(
        ForkAttributionIssuerV1::from_canonical_cbor(&bytes)?,
        issuer
    );
    assert_eq!(issuer.issuer_id(), "issuer-a");
    assert_eq!(issuer.epoch(), 1);
    assert_eq!(issuer.public_key(), PublicKey::from_bytes([0x22; 32]));
    let widest = ForkAttributionIssuerV1::new("i".repeat(128), u64::MAX, issuer.public_key())?;
    assert_eq!(
        ForkAttributionIssuerV1::from_canonical_cbor(&widest.to_canonical_cbor())?,
        widest
    );
    truncations_fail(&bytes, ForkAttributionIssuerV1::from_canonical_cbor);
    Ok(())
}

#[test]
fn fai1_rejects_identity_bounds_versions_and_alternate_encodings() -> TestResult {
    let key = PublicKey::from_bytes([0x22; 32]);
    for (issuer_id, epoch) in [
        (String::new(), 1),
        ("i".repeat(129), 1),
        ("issuer-a".to_owned(), 0),
    ] {
        assert_eq!(
            ForkAttributionIssuerV1::new(issuer_id, epoch, key),
            Err(CodecError::FieldOutOfBounds)
        );
    }
    let bytes = issuer()?.to_canonical_cbor();
    let decode = ForkAttributionIssuerV1::from_canonical_cbor;
    for (at, value, expected) in [
        (0, text("FAI2"), CodecError::InvalidEncoding),
        (1, int(2), CodecError::UnsupportedVersion),
        (2, text(""), CodecError::FieldOutOfBounds),
        (2, text(&"i".repeat(129)), CodecError::FieldOutOfBounds),
        (
            2,
            Value::Bytes(b"issuer-a".to_vec()),
            CodecError::InvalidEncoding,
        ),
        (3, int(0), CodecError::FieldOutOfBounds),
        (4, Value::Bytes(vec![0x22; 31]), CodecError::InvalidEncoding),
    ] {
        assert_eq!(mutated(&bytes, at, value, decode)?, Some(expected));
    }
    let mut short = items(&bytes)?;
    short.pop();
    assert_eq!(decode(&encode(short)?), Err(CodecError::InvalidEncoding));
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(decode(&trailing), Err(CodecError::InvalidEncoding));
    let mut invalid_utf8 = bytes.clone();
    invalid_utf8[FAI1_ISSUER_TEXT_AT] = 0xff;
    assert_eq!(decode(&invalid_utf8), Err(CodecError::InvalidEncoding));
    let wide_epoch = widened(&bytes, FAI1_EPOCH_AT);
    assert_eq!(decode(&wide_epoch), Err(CodecError::NonCanonical));
    assert_eq!(
        decode(&vec![0; MAX_FORK_ATTRIBUTION_ISSUER_BYTES_V1 + 1]),
        Err(CodecError::FieldOutOfBounds)
    );
    Ok(())
}

fn entry(
    issuer_id: &str,
    epoch: u64,
    key: u8,
    state: ForkAttributionIssuerStateV1,
) -> Result<ForkAttributionIssuerPolicyEntryV1, CodecError> {
    Ok(ForkAttributionIssuerPolicyEntryV1 {
        issuer: ForkAttributionIssuerV1::new(issuer_id, epoch, PublicKey::from_bytes([key; 32]))?,
        state,
    })
}

fn genesis_input() -> Result<ForkAttributionIssuerPolicyInputV1, CodecError> {
    Ok(ForkAttributionIssuerPolicyInputV1 {
        scope: "scope-a".to_owned(),
        generation: 1,
        previous_policy_digest: None,
        entries: vec![
            entry("issuer-a", 1, 1, ForkAttributionIssuerStateV1::Retired)?,
            entry("issuer-a", 2, 2, ForkAttributionIssuerStateV1::Active)?,
            entry("issuer-b", 1, 3, ForkAttributionIssuerStateV1::Revoked)?,
        ],
    })
}

#[test]
fn fip1_round_trips_genesis_and_successor_with_domain_digest() -> TestResult {
    let genesis = ForkAttributionIssuerPolicyV1::new(genesis_input()?)?;
    let bytes = genesis.to_canonical_cbor();
    assert_eq!(&bytes[..6], &[0x86, 0x64, b'F', b'I', b'P', b'1']);
    assert_eq!(
        ForkAttributionIssuerPolicyV1::from_canonical_cbor(&bytes)?,
        genesis
    );
    let mut preimage = b"pigloros/fork-attribution-issuer-policy/v1".to_vec();
    preimage.extend_from_slice(&bytes);
    assert_eq!(
        genesis.digest().as_bytes(),
        blake3::hash(&preimage).as_bytes()
    );
    let entries = &genesis.input().entries;
    for entry in entries {
        assert_eq!(genesis.issuer_state(&entry.issuer), Some(entry.state));
    }
    assert_eq!(genesis.issuer_state(&issuer()?), None);
    let successor = ForkAttributionIssuerPolicyV1::new(ForkAttributionIssuerPolicyInputV1 {
        generation: 2,
        previous_policy_digest: Some(genesis.digest()),
        ..genesis_input()?
    })?;
    assert_eq!(
        ForkAttributionIssuerPolicyV1::from_canonical_cbor(&successor.to_canonical_cbor())?,
        successor
    );
    truncations_fail(&bytes, ForkAttributionIssuerPolicyV1::from_canonical_cbor);
    Ok(())
}

#[test]
fn fip1_states_are_closed() {
    for state in [
        ForkAttributionIssuerStateV1::Active,
        ForkAttributionIssuerStateV1::Retired,
        ForkAttributionIssuerStateV1::Revoked,
    ] {
        assert_eq!(
            ForkAttributionIssuerStateV1::from_code(state.code()),
            Ok(state)
        );
    }
    for code in [0, 4, u8::MAX] {
        assert_eq!(
            ForkAttributionIssuerStateV1::from_code(code),
            Err(CodecError::InvalidEncoding)
        );
    }
}

/// Policy inputs that each violate exactly one header or count bound.
fn invalid_policy_headers(
    base: &ForkAttributionIssuerPolicyInputV1,
    too_many: Vec<ForkAttributionIssuerPolicyEntryV1>,
) -> [ForkAttributionIssuerPolicyInputV1; 8] {
    [
        ForkAttributionIssuerPolicyInputV1 {
            scope: String::new(),
            ..base.clone()
        },
        ForkAttributionIssuerPolicyInputV1 {
            scope: "s".repeat(129),
            ..base.clone()
        },
        ForkAttributionIssuerPolicyInputV1 {
            generation: 0,
            ..base.clone()
        },
        ForkAttributionIssuerPolicyInputV1 {
            previous_policy_digest: Some(hash(9)),
            ..base.clone()
        },
        ForkAttributionIssuerPolicyInputV1 {
            generation: 2,
            ..base.clone()
        },
        ForkAttributionIssuerPolicyInputV1 {
            generation: 2,
            previous_policy_digest: Some(Hash::zero()),
            ..base.clone()
        },
        ForkAttributionIssuerPolicyInputV1 {
            entries: Vec::new(),
            ..base.clone()
        },
        ForkAttributionIssuerPolicyInputV1 {
            entries: too_many,
            ..base.clone()
        },
    ]
}

#[test]
fn fip1_constructor_rejects_header_entry_order_and_key_reuse() -> TestResult {
    let max_entries = (0..MAX_FORK_ATTRIBUTION_ISSUER_POLICY_ENTRIES_V1)
        .map(|index| {
            let key = u8::try_from(index).map_err(|_| CodecError::FieldOutOfBounds)?;
            entry(
                &format!("issuer-{index:02}"),
                1,
                key,
                ForkAttributionIssuerStateV1::Active,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let full = ForkAttributionIssuerPolicyV1::new(ForkAttributionIssuerPolicyInputV1 {
        entries: max_entries.clone(),
        ..genesis_input()?
    })?;
    assert_eq!(
        ForkAttributionIssuerPolicyV1::from_canonical_cbor(&full.to_canonical_cbor())?,
        full
    );
    let mut too_many = max_entries;
    too_many.push(entry(
        "issuer-zz",
        1,
        0xee,
        ForkAttributionIssuerStateV1::Active,
    )?);
    let base = genesis_input()?;
    let header_cases = invalid_policy_headers(&base, too_many);
    for input in header_cases {
        assert_eq!(
            ForkAttributionIssuerPolicyV1::new(input),
            Err(CodecError::FieldOutOfBounds)
        );
    }
    let mut unordered = base.clone();
    unordered.entries.swap(0, 1);
    let mut duplicate_identity = base.clone();
    duplicate_identity.entries[1] = entry("issuer-a", 1, 9, ForkAttributionIssuerStateV1::Active)?;
    for input in [unordered, duplicate_identity] {
        assert_eq!(
            ForkAttributionIssuerPolicyV1::new(input),
            Err(CodecError::NonCanonical)
        );
    }
    let mut reused_key = base;
    reused_key.entries[2] = entry("issuer-b", 1, 1, ForkAttributionIssuerStateV1::Revoked)?;
    assert_eq!(
        ForkAttributionIssuerPolicyV1::new(reused_key),
        Err(CodecError::FieldMismatch)
    );
    Ok(())
}

#[test]
fn fip1_decoder_rejects_versions_counts_states_and_carrier_bounds() -> TestResult {
    let bytes = ForkAttributionIssuerPolicyV1::new(genesis_input()?)?.to_canonical_cbor();
    let decode = ForkAttributionIssuerPolicyV1::from_canonical_cbor;
    let fai1 = Value::Bytes(issuer()?.to_canonical_cbor());
    let entry_with = |issuer: Value, state: Value| Value::Array(vec![issuer, state]);
    let many =
        vec![entry_with(fai1.clone(), int(1)); MAX_FORK_ATTRIBUTION_ISSUER_POLICY_ENTRIES_V1 + 1];
    for (at, value, expected) in [
        (1, int(2), CodecError::UnsupportedVersion),
        (2, text(&"s".repeat(129)), CodecError::FieldOutOfBounds),
        (4, Value::Bytes(vec![1; 31]), CodecError::InvalidEncoding),
        (5, Value::Array(many), CodecError::FieldOutOfBounds),
        (
            5,
            Value::Array(vec![entry_with(fai1.clone(), int(4))]),
            CodecError::InvalidEncoding,
        ),
        (
            5,
            Value::Array(vec![entry_with(fai1.clone(), int(300))]),
            CodecError::InvalidEncoding,
        ),
        (
            5,
            Value::Array(vec![Value::Array(vec![fai1, int(1), int(1)])]),
            CodecError::InvalidEncoding,
        ),
        (3, int(0), CodecError::FieldOutOfBounds),
        (
            5,
            Value::Array(vec![entry_with(Value::Bytes(Vec::new()), int(1))]),
            CodecError::FieldOutOfBounds,
        ),
        (
            5,
            Value::Array(vec![entry_with(Value::Bytes(b"x".to_vec()), int(1))]),
            CodecError::InvalidEncoding,
        ),
        (
            5,
            Value::Array(vec![entry_with(
                Value::Bytes(vec![0; MAX_FORK_ATTRIBUTION_ISSUER_BYTES_V1 + 1]),
                int(1),
            )]),
            CodecError::FieldOutOfBounds,
        ),
    ] {
        assert_eq!(mutated(&bytes, at, value, decode)?, Some(expected));
    }
    let generation_at = 1 + 5 + 1 + 8;
    assert_eq!(bytes[generation_at], 0x01);
    assert_eq!(
        decode(&widened(&bytes, generation_at)),
        Err(CodecError::NonCanonical)
    );
    assert_eq!(
        decode(&vec![0; MAX_FORK_ATTRIBUTION_ISSUER_POLICY_BYTES_V1 + 1]),
        Err(CodecError::FieldOutOfBounds)
    );
    Ok(())
}

fn live_key() -> Result<ImportedKeyRecordV1, CodecError> {
    ImportedKeyRecordV1::new(
        attribution_identity(1),
        Some(hash(0x44)),
        PublicKey::from_bytes([0x55; 32]),
    )
}

fn destroyed_key() -> Result<ImportedKeyRecordV1, CodecError> {
    ImportedKeyRecordV1::new(
        attribution_identity(1),
        None,
        PublicKey::from_bytes([0x55; 32]),
    )
}

fn tombstone(epoch: u64) -> Result<ImportedKeyTombstoneV1, CodecError> {
    ImportedKeyTombstoneV1::new(
        attribution_identity(epoch),
        hash(0x44),
        hash(0x45),
        hash(0x46),
    )
}

#[test]
fn ikr1_and_ikt1_round_trip_and_project_source_registry_values() -> TestResult {
    let live = live_key()?;
    assert_eq!(live.to_canonical_cbor(), unhex(IKR1_HEX)?);
    let destroyed = destroyed_key()?;
    let ended = tombstone(1)?;
    for key in [live, destroyed] {
        assert_eq!(
            ImportedKeyRecordV1::from_canonical_cbor(&key.to_canonical_cbor())?,
            key
        );
        truncations_fail(
            &key.to_canonical_cbor(),
            ImportedKeyRecordV1::from_canonical_cbor,
        );
    }
    let ended_bytes = ended.to_canonical_cbor();
    assert_eq!(&ended_bytes[..6], &[0x88, 0x64, b'I', b'K', b'T', b'1']);
    assert_eq!(
        ImportedKeyTombstoneV1::from_canonical_cbor(&ended_bytes)?,
        ended
    );
    truncations_fail(&ended_bytes, ImportedKeyTombstoneV1::from_canonical_cbor);
    assert_eq!(live.identity(), attribution_identity(1));
    assert_eq!(live.private_material_digest(), Some(hash(0x44)));
    assert_eq!(
        live.public_verification_key(),
        PublicKey::from_bytes([0x55; 32])
    );
    assert_eq!(
        (
            ended.identity(),
            ended.destroyed_material_digest(),
            ended.destruction_digest(),
            ended.deletion_receipt()
        ),
        (attribution_identity(1), hash(0x44), hash(0x45), hash(0x46))
    );
    let source = KeyRecordV1 {
        identity: attribution_identity(1),
        private_material_digest: Some(hash(0x44)),
        public_verification_key: Some(PublicKey::from_bytes([0x55; 32])),
    };
    assert_eq!(ImportedKeyRecordV1::from_key_record(&source)?, live);
    let source_destroyed = KeyRecordV1 {
        private_material_digest: None,
        ..source
    };
    assert_eq!(
        ImportedKeyRecordV1::from_key_record(&source_destroyed)?,
        destroyed
    );
    let without_key = KeyRecordV1 {
        public_verification_key: None,
        ..source
    };
    assert_eq!(
        ImportedKeyRecordV1::from_key_record(&without_key),
        Err(CodecError::FieldOutOfBounds)
    );
    let source_tombstone = KeyTombstoneV1 {
        identity: attribution_identity(1),
        destroyed_material_digest: hash(0x44),
        destruction_digest: hash(0x45),
        deletion_receipt: hash(0x46),
    };
    assert_eq!(
        ImportedKeyTombstoneV1::from_tombstone(&source_tombstone)?,
        ended
    );
    Ok(())
}

#[test]
fn imported_key_constructors_and_decoders_reject_foreign_roles_and_zero_values() -> TestResult {
    let key = PublicKey::from_bytes([0x55; 32]);
    let timeline_role = KeyIdentityV1::new("creator-a", KeyRoleV1::TimelineIntegritySigning, 1);
    for (identity, material) in [
        (timeline_role, Some(hash(1))),
        (attribution_identity(0), Some(hash(1))),
        (attribution_identity(1), Some(Hash::zero())),
    ] {
        assert_eq!(
            ImportedKeyRecordV1::new(identity, material, key),
            Err(CodecError::FieldOutOfBounds)
        );
    }
    for (identity, digests) in [
        (timeline_role, [hash(1), hash(2), hash(3)]),
        (attribution_identity(1), [Hash::zero(), hash(2), hash(3)]),
        (attribution_identity(1), [hash(1), Hash::zero(), hash(3)]),
        (attribution_identity(1), [hash(1), hash(2), Hash::zero()]),
    ] {
        assert_eq!(
            ImportedKeyTombstoneV1::new(identity, digests[0], digests[1], digests[2]),
            Err(CodecError::FieldOutOfBounds)
        );
    }
    let record = live_key()?.to_canonical_cbor();
    let decode_record = ImportedKeyRecordV1::from_canonical_cbor;
    for (at, value, expected) in [
        (0, text("IKR2"), CodecError::InvalidEncoding),
        (1, int(2), CodecError::UnsupportedVersion),
        (2, text(""), CodecError::FieldOutOfBounds),
        (3, int(2), CodecError::FieldOutOfBounds),
        (3, int(200), CodecError::InvalidEncoding),
        (3, int(300), CodecError::InvalidEncoding),
        (4, int(0), CodecError::FieldOutOfBounds),
        (5, Value::Bytes(vec![0; 32]), CodecError::FieldOutOfBounds),
        (6, Value::Bytes(vec![0x55; 33]), CodecError::InvalidEncoding),
    ] {
        assert_eq!(mutated(&record, at, value, decode_record)?, Some(expected));
    }
    assert_eq!(
        decode_record(&vec![0; MAX_IMPORTED_KEY_RECORD_BYTES_V1 + 1]),
        Err(CodecError::FieldOutOfBounds)
    );
    let ended = tombstone(1)?.to_canonical_cbor();
    let decode_tombstone = ImportedKeyTombstoneV1::from_canonical_cbor;
    for (at, value, expected) in [
        (1, int(2), CodecError::UnsupportedVersion),
        (3, int(2), CodecError::FieldOutOfBounds),
        (5, Value::Bytes(vec![0; 32]), CodecError::FieldOutOfBounds),
        (7, Value::Null, CodecError::InvalidEncoding),
    ] {
        assert_eq!(
            mutated(&ended, at, value, decode_tombstone)?,
            Some(expected)
        );
    }
    let mut trailing = ended;
    trailing.push(0);
    assert_eq!(
        decode_tombstone(&trailing),
        Err(CodecError::InvalidEncoding)
    );
    assert_eq!(
        decode_tombstone(&vec![0; MAX_IMPORTED_KEY_TOMBSTONE_BYTES_V1 + 1]),
        Err(CodecError::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn fee1_round_trips_and_binds_its_exact_payload() -> TestResult {
    let item = evidence(5, b"payload")?;
    let bytes = item.to_canonical_cbor();
    assert_eq!(&bytes[..6], &[0x85, 0x64, b'F', b'E', b'E', b'1']);
    assert_eq!(ForkEventEvidenceV1::from_canonical_cbor(&bytes)?, item);
    assert_eq!(item.payload().as_slice(), b"payload");
    assert_eq!(item.signature(), Signature::from_bytes([0x77; 64]));
    assert_eq!(item.envelope().input().origin_logical_seq, Seq::from_u64(5));
    truncations_fail(&bytes, ForkEventEvidenceV1::from_canonical_cbor);
    let empty = evidence(6, b"")?;
    assert_eq!(
        ForkEventEvidenceV1::from_canonical_cbor(&empty.to_canonical_cbor())?,
        empty
    );

    let signature = Signature::from_bytes([0x77; 64]);
    let payload = CanonicalBytes::from_vec(b"payload".to_vec());
    let envelope = envelope_at(timeline_id(2), 5, 1, &payload)?;
    assert_eq!(
        ForkEventEvidenceV1::new(
            envelope.clone(),
            CanonicalBytes::from_vec(b"other".to_vec()),
            signature
        ),
        Err(CodecError::FieldMismatch)
    );
    assert_eq!(
        ForkEventEvidenceV1::new(
            envelope,
            CanonicalBytes::from_vec(vec![0; MAX_TIMELINE_EVENT_PAYLOAD_BYTES_V1 + 1]),
            signature
        ),
        Err(CodecError::FieldOutOfBounds)
    );
    assert_eq!(
        ForkEventEvidenceV1::new(
            envelope_at(timeline_id(2), 5, 2, &payload)?,
            payload,
            signature
        ),
        Err(CodecError::FieldMismatch)
    );
    Ok(())
}

#[test]
fn fee1_decoder_rejects_envelope_signature_version_and_size_bounds() -> TestResult {
    let bytes = evidence(5, b"payload")?.to_canonical_cbor();
    let decode = ForkEventEvidenceV1::from_canonical_cbor;
    for (at, value, expected) in [
        (1, int(2), CodecError::UnsupportedVersion),
        (2, Value::Bytes(Vec::new()), CodecError::FieldOutOfBounds),
        (
            2,
            Value::Bytes(vec![0; MAX_TIMELINE_EVENT_ENVELOPE_BYTES_V1 + 1]),
            CodecError::FieldOutOfBounds,
        ),
        (
            2,
            Value::Bytes(b"not an envelope".to_vec()),
            CodecError::InvalidEncoding,
        ),
        (
            3,
            Value::Bytes(b"other".to_vec()),
            CodecError::FieldMismatch,
        ),
        (4, Value::Bytes(vec![0x77; 63]), CodecError::InvalidEncoding),
    ] {
        assert_eq!(mutated(&bytes, at, value, decode)?, Some(expected));
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(decode(&trailing), Err(CodecError::InvalidEncoding));
    assert_eq!(
        decode(&vec![0; MAX_FORK_EVENT_EVIDENCE_BYTES_V1 + 1]),
        Err(CodecError::FieldOutOfBounds)
    );
    Ok(())
}

fn fork_input(local_head: u64) -> ForkTimelineImportInputV1 {
    ForkTimelineImportInputV1 {
        child_timeline_id: timeline_id(2),
        name: Some("fork".to_owned()),
        owner: None,
        parent_timeline_id: timeline_id(1),
        parent_cut: 4,
        local_head,
        parent_chain_hash: hash(0x66),
    }
}

#[test]
fn fti1_matches_independent_vector_and_round_trips_optional_metadata() -> TestResult {
    let empty = ForkTimelineImportV1::new(fork_input(0))?;
    let bytes = empty.to_canonical_cbor();
    assert_eq!(bytes, unhex(FTI1_HEX)?);
    assert_eq!(ForkTimelineImportV1::from_canonical_cbor(&bytes)?, empty);
    assert_eq!(empty.final_logical_head(), 4);
    let owned = ForkTimelineImportV1::new(ForkTimelineImportInputV1 {
        name: None,
        owner: Some(EntityId::from_ulid(Ulid::from_parts(3, 4))),
        parent_cut: u64::MAX - 2,
        local_head: 2,
        ..fork_input(0)
    })?;
    let owned_bytes = owned.to_canonical_cbor();
    assert_eq!(
        ForkTimelineImportV1::from_canonical_cbor(&owned_bytes)?,
        owned
    );
    assert_eq!(owned.final_logical_head(), u64::MAX);
    assert_eq!(owned.input().local_head, 2);
    let longest = ForkTimelineImportV1::new(ForkTimelineImportInputV1 {
        name: Some("n".repeat(MAX_FORK_TIMELINE_IMPORT_NAME_BYTES_V1)),
        ..fork_input(0)
    })?;
    assert_eq!(
        ForkTimelineImportV1::from_canonical_cbor(&longest.to_canonical_cbor())?,
        longest
    );
    truncations_fail(&owned_bytes, ForkTimelineImportV1::from_canonical_cbor);
    truncations_fail(&bytes, ForkTimelineImportV1::from_canonical_cbor);
    Ok(())
}

#[test]
fn fti1_rejects_name_identity_overflow_mode_and_size_bounds() -> TestResult {
    for input in [
        ForkTimelineImportInputV1 {
            name: Some("n".repeat(MAX_FORK_TIMELINE_IMPORT_NAME_BYTES_V1 + 1)),
            ..fork_input(0)
        },
        ForkTimelineImportInputV1 {
            parent_timeline_id: timeline_id(2),
            ..fork_input(0)
        },
        ForkTimelineImportInputV1 {
            parent_cut: u64::MAX,
            ..fork_input(1)
        },
    ] {
        assert_eq!(
            ForkTimelineImportV1::new(input),
            Err(CodecError::FieldOutOfBounds)
        );
    }
    let bytes = ForkTimelineImportV1::new(fork_input(0))?.to_canonical_cbor();
    let decode = ForkTimelineImportV1::from_canonical_cbor;
    for (at, value, expected) in [
        (1, int(2), CodecError::UnsupportedVersion),
        (3, int(1), CodecError::InvalidEncoding),
        (
            4,
            text(&"n".repeat(MAX_FORK_TIMELINE_IMPORT_NAME_BYTES_V1 + 1)),
            CodecError::FieldOutOfBounds,
        ),
        (5, Value::Bytes(vec![1; 15]), CodecError::InvalidEncoding),
        (6, Value::Bytes(vec![2; 16]), CodecError::FieldOutOfBounds),
    ] {
        assert_eq!(mutated(&bytes, at, value, decode)?, Some(expected));
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(decode(&trailing), Err(CodecError::InvalidEncoding));
    assert_eq!(
        decode(&vec![0; MAX_FORK_TIMELINE_IMPORT_BYTES_V1 + 1]),
        Err(CodecError::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn fti1_and_fee1_project_and_reconstruct_the_exact_timeline_export() -> TestResult {
    let fork = ForkTimelineImportV1::new(fork_input(2))?;
    let segment = vec![evidence(5, b"first")?, evidence(6, b"")?];
    let export = fork.to_timeline_export(&segment)?;
    assert_eq!(export.timeline.meta.id, timeline_id(2));
    assert_eq!(export.timeline.meta.mode, TimelineMode::Historical);
    assert_eq!(
        export.timeline.meta.fork_point,
        Some((timeline_id(1), Seq::from_u64(4)))
    );
    assert_eq!(export.timeline.head, Seq::from_u64(2));
    assert_eq!(export.parent_fork_hash, Some(hash(0x66)));
    let sequences = export
        .events
        .iter()
        .map(|event| event.seq)
        .collect::<Vec<_>>();
    assert_eq!(sequences, [Seq::from_u64(1), Seq::from_u64(2)]);
    assert_eq!(
        ForkTimelineImportV1::from_export(&export)?,
        (fork, segment.clone())
    );
    assert_eq!(
        ForkEventEvidenceV1::from_event(&export.events[0])?,
        segment[0]
    );

    let empty = ForkTimelineImportV1::new(fork_input(0))?;
    let empty_export = empty.to_timeline_export(&[])?;
    assert_eq!(
        ForkTimelineImportV1::from_export(&empty_export)?,
        (empty, Vec::new())
    );
    Ok(())
}

#[test]
fn fti1_reconstruction_rejects_count_order_and_origin_mismatches() -> TestResult {
    let fork = ForkTimelineImportV1::new(fork_input(2))?;
    for segment in [
        vec![evidence(5, b"")?],
        vec![evidence(6, b"")?, evidence(5, b"")?],
        vec![evidence(5, b"")?, evidence(7, b"")?],
        vec![evidence(5, b"")?, evidence_from(timeline_id(3), 6, b"")?],
    ] {
        assert_eq!(
            fork.to_timeline_export(&segment).err(),
            Some(CodecError::FieldMismatch)
        );
    }
    Ok(())
}

#[test]
fn fti1_projection_rejects_exports_it_cannot_reproduce() -> TestResult {
    let fork = ForkTimelineImportV1::new(fork_input(2))?;
    let export = fork.to_timeline_export(&[evidence(5, b"a")?, evidence(6, b"b")?])?;
    let mut root = export.clone();
    root.timeline.meta.fork_point = None;
    let mut without_hash = export.clone();
    without_hash.parent_fork_hash = None;
    let mut live = export.clone();
    live.timeline.meta.mode = TimelineMode::Live;
    let mut stitched = export.clone();
    stitched.events[1].seq = Seq::from_u64(6);
    let mut unsigned = export.clone();
    unsigned.events[0].signature = None;
    let mut without_identity = export.clone();
    without_identity.events[0].signature_identity = None;
    for candidate in [
        root,
        without_hash,
        live,
        stitched,
        unsigned,
        without_identity,
    ] {
        assert_eq!(
            ForkTimelineImportV1::from_export(&candidate).err(),
            Some(CodecError::FieldMismatch)
        );
    }
    let mut self_parent = export;
    self_parent.timeline.meta.fork_point = Some((timeline_id(2), Seq::from_u64(4)));
    assert_eq!(
        ForkTimelineImportV1::from_export(&self_parent).err(),
        Some(CodecError::FieldOutOfBounds)
    );
    Ok(())
}

/// Offset of the version in every record: a one-byte array head and the
/// five-byte text marker.
const VERSION_AT: usize = 1 + 5;

/// A widened version head is noncanonical, and a trailing byte is malformed.
fn rejects_widened_and_trailing<T>(bytes: &[u8], decode: impl Fn(&[u8]) -> Result<T, CodecError>) {
    assert_eq!(bytes[VERSION_AT], 0x01);
    assert_eq!(
        decode(&widened(bytes, VERSION_AT)).err(),
        Some(CodecError::NonCanonical)
    );
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert_eq!(decode(&trailing).err(), Some(CodecError::InvalidEncoding));
}

#[test]
fn every_nested_record_rejects_widened_heads_and_trailing_bytes() -> TestResult {
    rejects_widened_and_trailing(
        &issuer()?.to_canonical_cbor(),
        ForkAttributionIssuerV1::from_canonical_cbor,
    );
    rejects_widened_and_trailing(
        &ForkAttributionIssuerPolicyV1::new(genesis_input()?)?.to_canonical_cbor(),
        ForkAttributionIssuerPolicyV1::from_canonical_cbor,
    );
    rejects_widened_and_trailing(
        &live_key()?.to_canonical_cbor(),
        ImportedKeyRecordV1::from_canonical_cbor,
    );
    rejects_widened_and_trailing(
        &tombstone(1)?.to_canonical_cbor(),
        ImportedKeyTombstoneV1::from_canonical_cbor,
    );
    rejects_widened_and_trailing(
        &evidence(5, b"payload")?.to_canonical_cbor(),
        ForkEventEvidenceV1::from_canonical_cbor,
    );
    rejects_widened_and_trailing(
        &ForkTimelineImportV1::new(fork_input(0))?.to_canonical_cbor(),
        ForkTimelineImportV1::from_canonical_cbor,
    );
    Ok(())
}
