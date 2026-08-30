use ciborium::value::Value;
use pos_core::{
    ErasureCoordinatorRecordPartsV1, ErasureCoordinatorRecordV1, ErasureErrorV1,
    ErasureReferenceV1, ErasureRequestInputV1, ErasureRequestV1, ErasureScopeV1, ErasureStateV1,
};

const fn reference(value: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([value; 32])
}

fn submitted_record() -> Result<ErasureCoordinatorRecordV1, ErasureErrorV1> {
    let coordinator = reference(2);
    let request = ErasureRequestV1::new(ErasureRequestInputV1 {
        request: reference(1),
        subject: reference(3),
        scope: ErasureScopeV1::PrivateSubjectData,
        selectors: vec![reference(4)],
        requester: reference(5),
        authorization: reference(6),
        policy: reference(7),
        request_position: 9,
        horizon_position: 10,
        provenance: reference(8),
    })?;
    let state = ErasureStateV1::submitted(request.reference(), coordinator, reference(9))?;
    ErasureCoordinatorRecordV1::from_parts(
        ErasureCoordinatorRecordPartsV1 {
            request,
            state,
            targets: Vec::new(),
            acknowledgements: Vec::new(),
            receipt: None,
            receipt_input: None,
            authorize_provenance: None,
            freeze_provenance: None,
            dispatch_provenance: None,
            scope_extension_ledger: None,
            administrative_resolution_head: None,
            supporting_records: pos_core::ErasureSupportingRecordsV1::default(),
        },
        coordinator,
    )
}

fn submitted_record_bytes() -> Vec<u8> {
    let bytes = submitted_record().and_then(|record| record.to_canonical_cbor());
    assert!(bytes.is_ok());
    bytes.unwrap_or_default()
}

fn malformed_record_bytes() -> Vec<Vec<u8>> {
    let bytes = submitted_record_bytes();
    let Ok(Value::Array(fields)) = ciborium::from_reader(bytes.as_slice()) else {
        return Vec::new();
    };
    let bytes32 = || Value::Bytes(vec![0; 32]);
    let replacements = [
        (0, Value::Text("invalid".to_owned())),
        (2, Value::Null),
        (3, Value::Null),
        (4, Value::Null),
        (5, Value::Null),
        (6, Value::Null),
        (7, Value::Array(Vec::new())),
        (7, Value::Array(vec![Value::Null; 19])),
        (8, Value::Text("invalid".to_owned())),
        (9, Value::Text("invalid".to_owned())),
        (10, Value::Array(Vec::new())),
        (10, Value::Array(vec![Value::Null, bytes32(), bytes32()])),
        (
            10,
            Value::Array(vec![Value::Integer(0.into()), Value::Null, bytes32()]),
        ),
        (
            10,
            Value::Array(vec![Value::Integer(0.into()), bytes32(), Value::Null]),
        ),
        (11, Value::Text("invalid".to_owned())),
        (12, Value::Null),
        (12, Value::Array(Vec::new())),
    ];
    replacements
        .into_iter()
        .filter_map(|(index, replacement)| {
            let mut fields = fields.clone();
            fields[index] = replacement;
            let mut bytes = Vec::new();
            ciborium::into_writer(&Value::Array(fields), &mut bytes)
                .ok()
                .map(|()| bytes)
        })
        .collect()
}

#[test]
fn public_record_decoder_rejects_each_malformed_field() {
    let malformed = malformed_record_bytes();
    assert_eq!(malformed.len(), 17);
    for bytes in malformed {
        assert!(ErasureCoordinatorRecordV1::from_canonical_cbor(&bytes).is_err());
    }
}

#[test]
fn public_record_decoder_rejects_noncanonical_encoding() {
    assert_eq!(
        ErasureCoordinatorRecordV1::from_canonical_cbor(&[0x18, 0x01]),
        Err(ErasureErrorV1::InvalidEncoding)
    );
}

#[test]
fn public_record_decoder_rejects_oversized_input() {
    let oversized = vec![0; pos_core::erasure::ERASURE_COORDINATOR_RECORD_MAX_BYTES + 1];
    assert_eq!(
        ErasureCoordinatorRecordV1::from_canonical_cbor(&oversized),
        Err(ErasureErrorV1::ScopeInvalid)
    );
}
