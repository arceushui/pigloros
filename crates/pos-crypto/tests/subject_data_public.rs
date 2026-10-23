//! Accepted ADR-097 revision 3 SDP1 format at the public crypto seam.
//! Test CBOR is produced independently with ciborium, not the SDP1 encoder.

use ciborium::Value;
use pos_core::EntityId;
use pos_crypto::subject_ciphertext::SubjectCiphertextV1;
use pos_crypto::subject_data::{
    subject_data_public_header, SubjectDataErrorV1, SubjectDataV1, MAX_SUBJECT_DATA_BYTES,
    SUBJECT_DATA_EVENT_TYPE,
};
use ulid::Ulid;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const SUBJECT: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
// Literal SDC1 bytes from ADR-097 section 6, subject-field vector.
const CIPHERTEXT: &str = concat!(
    "9044534443310178287375626a6563743a3030303130323033303430353036303730",
    "38303930613062306330643065306650000102030405060708090a0b0c0d0e0f00",
    "010050202122232425262728292a2b2c2d2e2f0250404142434445464748494a4b",
    "4c4d4e4f6f7375626a6563742e646174612e7631016576616c75655820e6bf4f8e",
    "52a32b8dde63271248768be2856d3419f22fbf0e8c9092ad6ed0434f4c00000000",
    "000000000000000153f44051b705eb62c2ab8bde18321611bf094f6d",
);
const HEADER: &str = "8444534450310150000102030405060708090a0b0c0d0e0f6576616c7565";

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

fn outer(ciphertext: Vec<u8>) -> Vec<Value> {
    vec![
        Value::Bytes(b"SDP1".to_vec()),
        Value::Integer(1.into()),
        Value::Bytes(SUBJECT.to_vec()),
        Value::Text("value".into()),
        Value::Bytes(ciphertext),
    ]
}

fn inner() -> TestResult<Vec<Value>> {
    Ok(ciborium::de::from_reader(hex(CIPHERTEXT)?.as_slice())?)
}

#[test]
fn accepted_vector_and_complete_public_header() -> TestResult {
    let nested = SubjectCiphertextV1::from_bytes(&hex(CIPHERTEXT)?)?;
    let payload = SubjectDataV1::new(nested.clone())?;
    let independent = encode(&outer(hex(CIPHERTEXT)?))?;
    assert_eq!(payload.as_bytes(), independent);
    assert_eq!(payload.public_header(), hex(HEADER)?);
    assert_eq!(payload.ciphertext(), &nested);
    assert_eq!(nested.event_type(), SUBJECT_DATA_EVENT_TYPE);
    assert_eq!(SubjectDataV1::from_bytes(&independent)?, payload);
    assert_eq!(payload.clone(), payload);
    assert!(!format!("{payload:?}").is_empty());
    assert_eq!(
        subject_data_public_header(EntityId::from_ulid(Ulid::from_bytes(SUBJECT)), "value")?,
        hex(HEADER)?
    );
    Ok(())
}

#[test]
fn header_validates_subject_and_tag_wire_grammar() -> TestResult {
    let subject = EntityId::from_ulid(Ulid::from_bytes(SUBJECT));
    assert_eq!(
        subject_data_public_header(EntityId::from_ulid(Ulid::nil()), "value"),
        Err(SubjectDataErrorV1::InvalidHeader)
    );
    for tag in ["", "é"] {
        assert_eq!(
            subject_data_public_header(subject, tag),
            Err(SubjectDataErrorV1::InvalidHeader)
        );
    }
    assert_eq!(
        subject_data_public_header(subject, &"x".repeat(129)),
        Err(SubjectDataErrorV1::BoundsExceeded)
    );
    let tag = "x".repeat(128);
    let expected = encode(&[
        Value::Bytes(b"SDP1".to_vec()),
        Value::Integer(1.into()),
        Value::Bytes(SUBJECT.to_vec()),
        Value::Text(tag.clone()),
    ])?;
    assert_eq!(subject_data_public_header(subject, &tag)?, expected);
    Ok(())
}

#[test]
fn rejects_truncation_trailing_bytes_and_noncanonical_framing() -> TestResult {
    let bytes = encode(&outer(hex(CIPHERTEXT)?))?;
    for end in 0..bytes.len() {
        assert!(
            SubjectDataV1::from_bytes(&bytes[..end]).is_err(),
            "prefix {end}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        SubjectDataV1::from_bytes(&trailing),
        Err(SubjectDataErrorV1::InvalidEncoding)
    );
    let mut overlong = vec![0x98, 5];
    overlong.extend_from_slice(&bytes[1..]);
    assert_eq!(
        SubjectDataV1::from_bytes(&overlong),
        Err(SubjectDataErrorV1::InvalidEncoding)
    );
    for head in [0x84, 0x86, 0x9f, 0xa5, 0xc0] {
        let mut altered = bytes.clone();
        altered[0] = head;
        assert!(SubjectDataV1::from_bytes(&altered).is_err());
    }
    Ok(())
}

#[test]
fn rejects_outer_header_substitution_and_wrong_types() -> TestResult {
    let original = outer(hex(CIPHERTEXT)?);
    let attacks = [
        (0, Value::Bytes(b"SDP2".to_vec())),
        (1, Value::Integer(2.into())),
        (2, Value::Bytes(vec![0; 16])),
        (2, Value::Bytes(vec![1; 16])),
        (2, Value::Bytes(vec![1; 15])),
        (3, Value::Text("other".into())),
        (3, Value::Text(String::new())),
        (3, Value::Text("é".into())),
        (3, Value::Text("x".repeat(129))),
        (4, Value::Bytes(vec![0])),
    ];
    for (index, value) in attacks {
        let mut values = original.clone();
        values[index] = value;
        assert!(
            SubjectDataV1::from_bytes(&encode(&values)?).is_err(),
            "field {index}"
        );
    }
    for index in 0..5 {
        let mut values = original.clone();
        values[index] = Value::Null;
        assert!(
            SubjectDataV1::from_bytes(&encode(&values)?).is_err(),
            "null field {index}"
        );
    }
    Ok(())
}

#[test]
fn rejects_wrong_nested_use_event_type_and_schema() -> TestResult {
    for (index, value) in [
        (6, Value::Integer(1.into())),
        (10, Value::Text("consent.granted.v2".into())),
        (11, Value::Integer(2.into())),
    ] {
        let mut values = inner()?;
        values[index] = value;
        let bytes = encode(&values)?;
        assert_eq!(
            SubjectDataV1::new(SubjectCiphertextV1::from_bytes(&bytes)?),
            Err(SubjectDataErrorV1::InvalidHeader)
        );
        assert_eq!(
            SubjectDataV1::from_bytes(&encode(&outer(bytes))?),
            Err(SubjectDataErrorV1::InvalidHeader)
        );
    }
    let mut values = inner()?;
    values[12] = Value::Text("other".into());
    assert_eq!(
        SubjectDataV1::from_bytes(&encode(&outer(encode(&values)?))?),
        Err(SubjectDataErrorV1::InvalidHeader)
    );
    Ok(())
}

#[test]
fn containing_payload_bound_includes_outer_and_byte_string_framing() -> TestResult {
    let mut values = inner()?;
    let mut sealed = vec![0; MAX_SUBJECT_DATA_BYTES - 300];
    values[15] = Value::Bytes(sealed.clone());
    let initial_len = encode(&outer(encode(&values)?))?.len();
    sealed.resize(sealed.len() + MAX_SUBJECT_DATA_BYTES - initial_len, 0);
    values[15] = Value::Bytes(sealed.clone());
    let bytes = encode(&outer(encode(&values)?))?;
    assert_eq!(bytes.len(), MAX_SUBJECT_DATA_BYTES);
    let decoded = SubjectDataV1::from_bytes(&bytes)?;
    assert_eq!(decoded.as_bytes(), bytes);
    sealed.push(0);
    values[15] = Value::Bytes(sealed);
    let nested = SubjectCiphertextV1::from_bytes(&encode(&values)?)?;
    assert_eq!(
        SubjectDataV1::new(nested),
        Err(SubjectDataErrorV1::BoundsExceeded)
    );
    assert_eq!(
        SubjectDataV1::from_bytes(&encode(&outer(encode(&values)?))?),
        Err(SubjectDataErrorV1::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn errors_disclose_no_record_or_key_bytes() {
    for error in [
        SubjectDataErrorV1::InvalidEncoding,
        SubjectDataErrorV1::BoundsExceeded,
        SubjectDataErrorV1::InvalidHeader,
    ] {
        assert!(!error.to_string().is_empty());
    }
}
