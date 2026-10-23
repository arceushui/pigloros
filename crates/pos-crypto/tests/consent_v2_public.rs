//! CGV2 tests use literal ADR-097 vectors and independent ciborium encoding.

use ciborium::Value;
use pos_core::EntityId;
use pos_crypto::consent_v2::{
    ConsentGrantedV2, ConsentPolicyV2, ConsentV2Error, CONSENT_GRANTED_V2_EVENT_TYPE,
    MAX_CONSENT_V2_BYTES,
};
use pos_crypto::subject_ciphertext::{SubjectCiphertextErrorV1, SubjectCiphertextV1};
use ulid::Ulid;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

// Literal accepted ADR-097 section 6 consent-purpose SDC1 vector and header.
const CIPHERTEXT: &str = concat!(
    "9044534443310178287375626a6563743a3030303130323033303430353036303730",
    "38303930613062306330643065306650000102030405060708090a0b0c0d0e0f00",
    "010150202122232425262728292a2b2c2d2e2f0150303132333435363738393a3b",
    "3c3d3e3f72636f6e73656e742e6772616e7465642e76320167707572706f736558",
    "20513dd9edf3114e25d2d84b53ab30c0bb572d15ecd39d483b0aaed14fbf575612",
    "4c00000000000000000000000155ce7d381b6e54d7843023c0999e3b55b3f78a0a",
    "d82f",
);
const HEADER: &str = concat!(
    "8b44434756320250000102030405060708090a0b0c0d0e0f50101112131415161718",
    "191a1b1c1d1e1f0101f4f4000001",
);

fn hex(value: &str) -> TestResult<Vec<u8>> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}

fn encode(values: &[Value]) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(values, &mut bytes)?;
    Ok(bytes)
}

fn outer() -> TestResult<Vec<Value>> {
    // Insert ciphertext between the grantee and policy, independently of
    // the production encoder. No encryption or key is needed to read policy.
    let mut values: Vec<Value> = ciborium::de::from_reader(hex(HEADER)?.as_slice())?;
    values.insert(4, Value::Bytes(hex(CIPHERTEXT)?));
    Ok(values)
}

fn inner() -> TestResult<Vec<Value>> {
    Ok(ciborium::de::from_reader(hex(CIPHERTEXT)?.as_slice())?)
}

const fn policy() -> ConsentPolicyV2 {
    ConsentPolicyV2 {
        subject_id: EntityId::from_ulid(Ulid::from_bytes([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        ])),
        grantee_id: EntityId::from_ulid(Ulid::from_bytes([
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        ])),
        modalities: 1,
        min_geo_resolution: 1,
        fork_permitted: false,
        export_permitted: false,
        retention_days: 0,
        expiry_secs: 0,
        grant_seq: 1,
    }
}

#[test]
fn accepted_vector_preserves_all_clear_policy_without_keys() -> TestResult {
    let policy = policy();
    let ciphertext = SubjectCiphertextV1::from_bytes(&hex(CIPHERTEXT)?)?;
    let payload = ConsentGrantedV2::new(policy, ciphertext.clone())?;
    assert_eq!(payload.as_bytes(), encode(&outer()?)?);
    assert_eq!(payload.public_header(), hex(HEADER)?);
    assert_eq!(policy.public_header()?, hex(HEADER)?);
    assert_eq!(payload.policy(), &policy);
    assert_eq!(payload.encrypted_purpose(), &ciphertext);
    assert_eq!(ciphertext.event_type(), CONSENT_GRANTED_V2_EVENT_TYPE);
    assert_eq!(ConsentGrantedV2::from_bytes(payload.as_bytes())?, payload);
    assert_eq!(payload.clone(), payload);
    assert!(!format!("{payload:?}").is_empty());
    Ok(())
}

#[test]
fn permits_v1_policy_extremes_without_changing_session_or_expiry_semantics() -> TestResult {
    let mut values = outer()?;
    values[5] = Value::Integer(15.into());
    values[6] = Value::Integer(0.into());
    values[7] = Value::Bool(true);
    values[8] = Value::Bool(true);
    values[9] = Value::Integer(u16::MAX.into());
    values[10] = Value::Integer(u32::MAX.into());
    let payload = ConsentGrantedV2::from_bytes(&encode(&values)?)?;
    let expected = ConsentPolicyV2 {
        modalities: 15,
        min_geo_resolution: 0,
        fork_permitted: true,
        export_permitted: true,
        retention_days: u16::MAX,
        expiry_secs: u32::MAX,
        ..policy()
    };
    assert_eq!(payload.policy(), &expected);
    values.remove(4);
    assert_eq!(payload.public_header(), encode(&values)?);
    assert_eq!(expected.public_header()?, encode(&values)?);
    let mut no_modalities = outer()?;
    no_modalities[5] = Value::Integer(0.into());
    assert_eq!(
        ConsentGrantedV2::from_bytes(&encode(&no_modalities)?)?
            .policy()
            .modalities,
        0
    );
    Ok(())
}

#[test]
fn rejects_every_invalid_clear_policy_and_numeric_overflow() -> TestResult {
    let original = outer()?;
    for (index, value) in [
        (0, Value::Bytes(b"CGV1".to_vec())),
        (1, Value::Integer(1.into())),
        (2, Value::Bytes(vec![0; 16])),
        (3, Value::Bytes(vec![0; 16])),
        (5, Value::Integer(16.into())),
        (5, Value::Integer(256.into())),
        (6, Value::Integer(2.into())),
        (6, Value::Integer(256.into())),
        (9, Value::Integer(65_536.into())),
        (10, Value::Integer(0x1_0000_0000_u64.into())),
        (11, Value::Integer(0.into())),
        (11, Value::Integer(2.into())),
        (2, Value::Bytes(vec![1; 16])),
    ] {
        let mut values = original.clone();
        values[index] = value;
        assert!(
            ConsentGrantedV2::from_bytes(&encode(&values)?).is_err(),
            "field {index}"
        );
    }
    let nil = EntityId::from_ulid(Ulid::nil());
    for bad in [
        ConsentPolicyV2 {
            subject_id: nil,
            ..policy()
        },
        ConsentPolicyV2 {
            grantee_id: nil,
            ..policy()
        },
        ConsentPolicyV2 {
            modalities: 16,
            ..policy()
        },
        ConsentPolicyV2 {
            min_geo_resolution: 2,
            ..policy()
        },
        ConsentPolicyV2 {
            grant_seq: 0,
            ..policy()
        },
    ] {
        assert_eq!(bad.public_header(), Err(ConsentV2Error::InvalidPolicy));
        assert_eq!(
            ConsentGrantedV2::new(bad, SubjectCiphertextV1::from_bytes(&hex(CIPHERTEXT)?)?),
            Err(ConsentV2Error::InvalidPolicy)
        );
    }
    Ok(())
}

#[test]
fn rejects_nested_subject_sequence_use_type_schema_and_tag_substitution() -> TestResult {
    for (index, value) in [
        (6, Value::Integer(0.into())),
        (8, Value::Integer(2.into())),
        (10, Value::Text("subject.data.v1".into())),
        (11, Value::Integer(2.into())),
        (12, Value::Text("other".into())),
    ] {
        let mut values = inner()?;
        values[index] = value;
        let nested = SubjectCiphertextV1::from_bytes(&encode(&values)?)?;
        assert_eq!(
            ConsentGrantedV2::new(policy(), nested),
            Err(ConsentV2Error::InvalidPolicy)
        );
    }
    let bad_subject = ConsentPolicyV2 {
        subject_id: policy().grantee_id,
        ..policy()
    };
    assert_eq!(
        ConsentGrantedV2::new(
            bad_subject,
            SubjectCiphertextV1::from_bytes(&hex(CIPHERTEXT)?)?
        ),
        Err(ConsentV2Error::InvalidPolicy)
    );
    let mut values = outer()?;
    values[4] = Value::Bytes(vec![0]);
    assert!(ConsentGrantedV2::from_bytes(&encode(&values)?).is_err());
    Ok(())
}

#[test]
fn rejects_wrong_types_truncation_trailing_and_noncanonical_encodings() -> TestResult {
    let original = outer()?;
    let bytes = encode(&original)?;
    for end in 0..bytes.len() {
        assert!(
            ConsentGrantedV2::from_bytes(&bytes[..end]).is_err(),
            "prefix {end}"
        );
    }
    for index in 0..12 {
        let mut values = original.clone();
        values[index] = Value::Null;
        assert!(
            ConsentGrantedV2::from_bytes(&encode(&values)?).is_err(),
            "null field {index}"
        );
    }
    for head in [0x8b, 0x8d, 0x9f, 0xac, 0xc0] {
        let mut altered = bytes.clone();
        altered[0] = head;
        assert!(ConsentGrantedV2::from_bytes(&altered).is_err());
    }
    let mut overlong = vec![0x98, 12];
    overlong.extend_from_slice(&bytes[1..]);
    assert_eq!(
        ConsentGrantedV2::from_bytes(&overlong),
        Err(ConsentV2Error::InvalidEncoding)
    );
    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        ConsentGrantedV2::from_bytes(&trailing),
        Err(ConsentV2Error::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn bounds_purpose_and_complete_payload_before_consumer_access() -> TestResult {
    let mut values = inner()?;
    values[15] = Value::Bytes(vec![0; 128 + 2 + 16]);
    let accepted = SubjectCiphertextV1::from_bytes(&encode(&values)?)?;
    assert!(ConsentGrantedV2::new(policy(), accepted).is_ok());
    values[15] = Value::Bytes(vec![0; 128 + 2 + 16 + 1]);
    assert_eq!(
        ConsentGrantedV2::new(
            policy(),
            SubjectCiphertextV1::from_bytes(&encode(&values)?)?
        ),
        Err(ConsentV2Error::BoundsExceeded)
    );
    assert_eq!(
        ConsentGrantedV2::from_bytes(&vec![0; MAX_CONSENT_V2_BYTES + 1]),
        Err(ConsentV2Error::BoundsExceeded)
    );
    // An oversized declared byte-string length is refused before allocation.
    let mut bytes = encode(&outer()?)?;
    let purpose_offset = 1 + 5 + 1 + 17 + 17;
    bytes.truncate(purpose_offset);
    bytes.extend_from_slice(&[0x5a, 0, 4, 0, 1]);
    assert_eq!(
        ConsentGrantedV2::from_bytes(&bytes),
        Err(ConsentV2Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn errors_are_closed_and_disclose_no_purpose() {
    for error in [
        ConsentV2Error::InvalidEncoding,
        ConsentV2Error::InvalidPolicy,
        ConsentV2Error::BoundsExceeded,
        ConsentV2Error::Ciphertext(SubjectCiphertextErrorV1::InvalidEncoding { ordinal: 0 }),
    ] {
        assert!(!error.to_string().is_empty());
        assert!(!error.to_string().contains("demo"));
    }
}
