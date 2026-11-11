//! Independent COH1/COE1 wire fixtures; parsing is not authenticated admission.

#[path = "support/community_nonce_properties.rs"]
pub mod nonce_properties;

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    CommunityArtifactHeaderInputV1 as Input, CommunityArtifactHeaderV1 as Header,
    CommunityArtifactKindV1 as Kind, CommunityArtifactOperationV1 as Operation,
    CommunityArtifactPurposeV1 as Purpose, CommunityEncryptedEnvelopeV1 as Envelope,
    CommunityLifecycleErrorV1 as Error, CommunityPassKeyV1 as Pass,
    MAX_COMMUNITY_ENVELOPE_PLAINTEXT_BYTES_V1 as MAX_PLAINTEXT,
};
use pos_core::{Hash, TimelineId};
use proptest::arbitrary::any;

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const fn timeline(byte: u8) -> TimelineId {
    TimelineId::from_ulid(ulid::Ulid::from_bytes([byte; 16]))
}

const fn input(operation: Operation, purpose: Purpose, record_kind: Kind) -> Input {
    Input {
        timeline: timeline(7),
        generation: [8; 16],
        purpose,
        operation,
        record_kind,
        scope_cover_digest: Hash::from_bytes([10; 32]),
        evidence_not_after_micros: 11,
    }
}

fn pass(ordinal: u64) -> Result<Operation, Error> {
    Pass::new(timeline(7), [8; 16], ordinal).map(Operation::Pass)
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

fn owner(purpose: u8, operation: Operation) -> String {
    let suffix = match operation {
        Operation::Pass(key) => format!("p:{:016x}", key.ordinal()),
        Operation::Initialization(_) => format!("i:{}", "ab".repeat(16)),
        Operation::Control(_) => format!("c:{}", "ab".repeat(16)),
    };
    format!(
        "community:{}:{}:{purpose}:{suffix}",
        "07".repeat(16),
        "08".repeat(16)
    )
}

fn header_fields(input: Input, purpose: u8, kind: u16) -> Fallible<Vec<Value>> {
    let (operation, identity) = match input.operation {
        Operation::Pass(key) => (
            0,
            encode(&Value::Array(vec![
                bytes(b"CPK1"),
                uint(1),
                bytes(&[7; 16]),
                bytes(&[8; 16]),
                uint(key.ordinal()),
            ]))?,
        ),
        Operation::Initialization(id) => (1, id.to_vec()),
        Operation::Control(id) => (2, id.to_vec()),
    };
    Ok(vec![
        bytes(b"COH1"),
        uint(1),
        bytes(&input.timeline.inner().to_bytes()),
        bytes(&input.generation),
        uint(u64::from(purpose)),
        uint(operation),
        bytes(&identity),
        uint(u64::from(kind)),
        Value::Text(owner(purpose, input.operation)),
        uint(7),
        uint(1),
        bytes(input.scope_cover_digest.as_bytes()),
        uint(input.evidence_not_after_micros),
    ])
}

fn execution_input() -> Result<Input, Error> {
    Ok(input(pass(1)?, Purpose::ExecutionState, Kind::StateContent))
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
    let mut wide = encoded.to_vec();
    wide.splice(6..7, [0x18, 1]);
    assert_eq!(decode(&wide), Err(Error::InvalidEncoding));
}

#[test]
fn exact_header_owner_key_and_context_digest_match_the_independent_wire() -> TestResult {
    for operation in [
        pass(1)?,
        pass(u64::MAX)?,
        Operation::Initialization([0xab; 16]),
        Operation::Control([0xab; 16]),
    ] {
        let mut value = input(operation, Purpose::ExecutionState, Kind::StateContent);
        value.evidence_not_after_micros = u64::MAX / 2;
        let expected = encode(&Value::Array(header_fields(value, 0, 0)?))?;
        let header = Header::new(value)?;
        assert!(header.as_input() == &value);
        assert_eq!(header.to_canonical_cbor().as_slice(), expected);
        let identity = header.key_identity();
        assert_eq!(identity.owner_id.as_str(), owner(0, operation));
        assert_eq!(identity.role.code(), 7);
        assert_eq!(identity.epoch, 1);
        let mut preimage = b"PiglorOS.Community.EnvelopeContext.v1\0".to_vec();
        preimage.extend_from_slice(&expected);
        assert_eq!(
            header.associated_data_digest(),
            Hash::from_bytes(*blake3::hash(&preimage).as_bytes())
        );
        assert!(Header::from_canonical_cbor(&expected)?.as_input() == &value);
        assert!(expected.len() <= 1024);
    }
    Ok(())
}

#[test]
fn all_thirty_six_purpose_kind_pairs_follow_the_closed_admission_table() -> TestResult {
    let purposes = [
        (0, Purpose::ExecutionState, vec![0, 1, 2, 3, 7, 8]),
        (1, Purpose::PresentationTrace, vec![4, 7, 8]),
        (2, Purpose::ReplayEvidence, vec![5, 7, 8]),
        (3, Purpose::LifecycleControl, vec![6, 7, 8]),
    ];
    let kinds = [
        (0, Kind::StateContent),
        (1, Kind::StateRevisionOrHead),
        (2, Kind::PreparedInvocation),
        (3, Kind::ExecutionProvenance),
        (4, Kind::TraceAnnotation),
        (5, Kind::ReplayReceiptOrRoot),
        (6, Kind::LifecycleControl),
        (7, Kind::BoundedRecordBundle),
        (8, Kind::ClassificationProof),
    ];
    for (purpose_code, purpose, admitted) in purposes {
        assert_eq!(purpose.code(), purpose_code);
        for (kind_code, kind) in kinds {
            assert_eq!(kind.code(), kind_code);
            let value = input(Operation::Control([0xab; 16]), purpose, kind);
            let encoded = encode(&Value::Array(header_fields(
                value,
                purpose_code,
                kind_code,
            )?))?;
            if admitted.contains(&kind_code) {
                assert_eq!(Header::new(value)?.to_canonical_cbor().as_slice(), encoded);
                assert!(Header::from_canonical_cbor(&encoded)?.as_input() == &value);
            } else {
                assert_eq!(Header::new(value).err(), Some(Error::InvalidBinding));
                assert_eq!(
                    Header::from_canonical_cbor(&encoded).err(),
                    Some(Error::InvalidBinding)
                );
            }
        }
    }
    Ok(())
}

#[test]
fn zero_foreign_coordinates_operation_ids_scope_and_bad_horizons_refuse() -> TestResult {
    for value in [
        Input {
            timeline: timeline(0),
            ..execution_input()?
        },
        Input {
            generation: [0; 16],
            ..execution_input()?
        },
        Input {
            timeline: timeline(9),
            ..execution_input()?
        },
        Input {
            generation: [9; 16],
            ..execution_input()?
        },
        Input {
            scope_cover_digest: Hash::zero(),
            ..execution_input()?
        },
        input(
            Operation::Initialization([0; 16]),
            Purpose::ExecutionState,
            Kind::StateContent,
        ),
        input(
            Operation::Control([0; 16]),
            Purpose::ExecutionState,
            Kind::StateContent,
        ),
    ] {
        let encoded = encode(&Value::Array(header_fields(value, 0, 0)?))?;
        assert_eq!(Header::new(value).err(), Some(Error::InvalidBinding));
        assert_eq!(
            Header::from_canonical_cbor(&encoded).err(),
            Some(Error::InvalidBinding)
        );
    }
    for horizon in [0, (u64::MAX / 2) + 1, u64::MAX] {
        let value = Input {
            evidence_not_after_micros: horizon,
            ..execution_input()?
        };
        let encoded = encode(&Value::Array(header_fields(value, 0, 0)?))?;
        assert_eq!(
            Header::from_canonical_cbor(&encoded).err(),
            Some(Error::BoundsExceeded)
        );
    }
    Ok(())
}

#[test]
fn header_rejects_owner_aliases_and_any_other_role_or_epoch() -> TestResult {
    let original = header_fields(execution_input()?, 0, 0)?;
    for (alias, error) in [
        (String::new(), Error::InvalidBinding),
        ("x".repeat(128), Error::InvalidBinding),
        ("x".repeat(129), Error::BoundsExceeded),
        (owner(0, pass(1)?).to_uppercase(), Error::InvalidBinding),
        (format!(" {}", owner(0, pass(1)?)), Error::InvalidBinding),
    ] {
        let mut fields = original.clone();
        fields[8] = Value::Text(alias.clone());
        assert_eq!(
            Header::from_canonical_cbor(&encode(&Value::Array(fields))?).err(),
            Some(error)
        );
    }
    for (field, value) in [(9, 0), (9, 8), (10, 0), (10, 2)] {
        let mut fields = original.clone();
        fields[field] = uint(value);
        assert_eq!(
            Header::from_canonical_cbor(&encode(&Value::Array(fields))?).err(),
            Some(Error::InvalidBinding)
        );
    }
    let mut invalid_utf8 = encode(&Value::Array(original))?;
    let at = invalid_utf8
        .windows(10)
        .position(|bytes| bytes == b"community:")
        .ok_or("missing owner")?;
    invalid_utf8[at] = 0xff;
    assert_eq!(
        Header::from_canonical_cbor(&invalid_utf8).err(),
        Some(Error::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn unknown_enum_tags_and_wrong_operation_payloads_are_closed() -> TestResult {
    let original = header_fields(execution_input()?, 0, 0)?;
    for (field, value) in [(4, 4), (5, 3), (7, 9)] {
        let mut fields = original.clone();
        fields[field] = uint(value);
        assert_eq!(
            Header::from_canonical_cbor(&encode(&Value::Array(fields))?).err(),
            Some(Error::InvalidEncoding)
        );
    }
    for operation in [1, 2] {
        for length in [15, 17, 65] {
            let mut fields = original.clone();
            fields[5] = uint(operation);
            fields[6] = bytes(&vec![1; length]);
            let expected = if length > 64 {
                Error::BoundsExceeded
            } else {
                Error::InvalidEncoding
            };
            assert_eq!(
                Header::from_canonical_cbor(&encode(&Value::Array(fields))?).err(),
                Some(expected)
            );
        }
    }
    let mut fields = original;
    fields[6] = bytes(&encode(&Value::Array(vec![
        bytes(b"CPK1"),
        uint(1),
        bytes(&[7; 16]),
        bytes(&[8; 16]),
        uint(0),
    ]))?);
    assert_eq!(
        Header::from_canonical_cbor(&encode(&Value::Array(fields))?).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

#[test]
fn header_rejects_every_truncation_trailing_and_nonpreferred_input() -> TestResult {
    for operation in [
        pass(1)?,
        Operation::Initialization([0xab; 16]),
        Operation::Control([0xab; 16]),
    ] {
        let encoded = encode(&Value::Array(header_fields(
            input(operation, Purpose::ExecutionState, Kind::StateContent),
            0,
            0,
        )?))?;
        framing_refuses(&encoded, 1024, |bytes| {
            Header::from_canonical_cbor(bytes).map(|_| ())
        });
    }
    let mut wide_purpose = encode(&Value::Array(header_fields(execution_input()?, 0, 0)?))?;
    wide_purpose.splice(41..42, [0x18, 0]);
    assert_eq!(
        Header::from_canonical_cbor(&wide_purpose).err(),
        Some(Error::InvalidEncoding)
    );
    Ok(())
}

fn envelope_wire(header: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Fallible<Vec<u8>> {
    encode(&Value::Array(vec![
        bytes(b"COE1"),
        uint(1),
        bytes(header),
        bytes(nonce),
        bytes(ciphertext),
    ]))
}

#[test]
fn envelope_has_exact_five_fields_and_borrows_its_cipher_range() -> TestResult {
    nonce_properties::check(any::<[u8; 12]>(), |nonce| {
        assert_eq!(MAX_PLAINTEXT, 3_145_728);
        let header_bytes = encode(&Value::Array(header_fields(execution_input()?, 0, 0)?))?;
        for length in [16, 17, 3_145_744] {
            let ciphertext = vec![0x42; length];
            let expected = envelope_wire(&header_bytes, &nonce, &ciphertext)?;
            let value = Envelope::new(Header::new(execution_input()?)?, nonce, &ciphertext)?;
            assert_eq!(value.to_canonical_cbor().as_slice(), expected);
            let mut preimage = b"PiglorOS.Community.Envelope.v1\0".to_vec();
            preimage.extend_from_slice(&expected);
            assert_eq!(
                value.address(),
                Hash::from_bytes(*blake3::hash(&preimage).as_bytes())
            );
            assert_eq!(value.ciphertext_and_tag().as_ptr(), ciphertext.as_ptr());
            let decoded = Envelope::from_canonical_cbor(&expected)?;
            assert_eq!(decoded.nonce(), &nonce);
            assert!(decoded.header().as_input() == &execution_input()?);
            assert_eq!(decoded.ciphertext_and_tag(), ciphertext);
            assert_eq!(
                decoded.ciphertext_and_tag().as_ptr(),
                expected[expected.len() - length..].as_ptr()
            );
            assert!(expected.len() <= 3_147_840);
        }
        Ok(())
    })
}

#[test]
fn envelope_refuses_missing_tags_bad_nonces_and_oversized_nested_records() -> TestResult {
    nonce_properties::check(
        (any::<[u8; 12]>(), any::<[u8; 13]>()),
        |(nonce, invalid_nonce)| {
            let header_bytes = encode(&Value::Array(header_fields(execution_input()?, 0, 0)?))?;
            for length in [0, 15, MAX_PLAINTEXT + 17] {
                let encoded = envelope_wire(&header_bytes, &nonce, &vec![0; length])?;
                assert_eq!(
                    Envelope::from_canonical_cbor(&encoded).err(),
                    Some(Error::BoundsExceeded)
                );
            }
            for length in [11, 13] {
                let encoded = envelope_wire(&header_bytes, &invalid_nonce[..length], &[0; 16])?;
                assert_eq!(
                    Envelope::from_canonical_cbor(&encoded).err(),
                    Some(Error::InvalidEncoding)
                );
            }
            let header_too_large = envelope_wire(&[0; 1025], &nonce, &[0; 16])?;
            assert_eq!(
                Envelope::from_canonical_cbor(&header_too_large).err(),
                Some(Error::BoundsExceeded)
            );
            let valid = envelope_wire(&header_bytes, &nonce, &[0; 16])?;
            framing_refuses(&valid, 3_147_840, |bytes| {
                Envelope::from_canonical_cbor(bytes).map(|_| ())
            });
            Ok(())
        },
    )
}
