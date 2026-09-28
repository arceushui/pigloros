use ciborium::value::Value;
use pos_core::{
    fork_authentication::{
        AuthenticatedPrincipalEvidenceV1, AuthenticatedPrincipalRecordV1,
        ForkAuthenticationAdapterPolicyV1, ForkAuthenticationCodecErrorV1,
        ForkAuthenticationPolicyV1, LocalAccountBindingV1, LocalAccountRegistryV1,
        MAX_AUTHENTICATED_PRINCIPAL_EVIDENCE_BYTES_V1, MAX_AUTHENTICATED_PRINCIPAL_RECORD_BYTES_V1,
        MAX_FORK_AUTH_CREDENTIAL_BYTES_V1, MAX_FORK_AUTH_POLICY_BYTES_V1,
    },
    Hash, OwnerIdV1, PrincipalRefV1,
};

fn principal(value: u8) -> Result<PrincipalRefV1, pos_core::AuthorityErrorV1> {
    PrincipalRefV1::try_new([value; 16], "local.test")
}

fn adapter() -> ForkAuthenticationAdapterPolicyV1 {
    ForkAuthenticationAdapterPolicyV1 {
        adapter_id: "local".to_owned(),
        verifying_key: [7; 32],
        minimum_assurance: 2,
        registry_bindings: vec![Hash::from_bytes([1; 32]), Hash::from_bytes([2; 32])],
    }
}

fn policy() -> Result<ForkAuthenticationPolicyV1, ForkAuthenticationCodecErrorV1> {
    ForkAuthenticationPolicyV1::new(vec![adapter()])
}

fn registry() -> Result<LocalAccountRegistryV1, ForkAuthenticationCodecErrorV1> {
    LocalAccountRegistryV1::new(
        "local".to_owned(),
        2,
        vec![LocalAccountBindingV1 {
            uid: 1001,
            principal: principal(1).map_err(|_| ForkAuthenticationCodecErrorV1::InvalidEncoding)?,
            owner: OwnerIdV1::from_static("alice"),
        }],
        1000,
    )
}

fn record() -> Result<AuthenticatedPrincipalRecordV1, ForkAuthenticationCodecErrorV1> {
    Ok(AuthenticatedPrincipalRecordV1 {
        principal: principal(1).map_err(|_| ForkAuthenticationCodecErrorV1::InvalidEncoding)?,
        adapter_id: "local".to_owned(),
        assurance: 2,
        issued_at: 100,
        expires_at: 200,
        registry_binding: Hash::from_bytes([1; 32]),
        operation_nonce: [3; 32],
    })
}

fn mutate(
    bytes: &[u8],
    change: impl FnOnce(&mut Value) -> std::io::Result<()>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut value = ciborium::from_reader(bytes)?;
    change(&mut value)?;
    let mut result = Vec::new();
    ciborium::into_writer(&value, &mut result)?;
    Ok(result)
}

fn fields(value: &mut Value) -> std::io::Result<&mut Vec<Value>> {
    value
        .as_array_mut()
        .ok_or_else(|| std::io::Error::other("fixture must be a CBOR array"))
}

#[test]
fn fap1_public_decoder_rejects_every_nested_field_shape() -> Result<(), Box<dyn std::error::Error>>
{
    let canonical = policy()?.to_canonical_cbor()?;
    let cases: Vec<(Vec<u8>, ForkAuthenticationCodecErrorV1)> = vec![
        (vec![0x80], ForkAuthenticationCodecErrorV1::InvalidEncoding),
        (
            mutate(&canonical, |value| {
                fields(value)?[0] = Value::Bytes(b"FAP1".to_vec());
                Ok(())
            })?,
            ForkAuthenticationCodecErrorV1::InvalidEncoding,
        ),
        (
            mutate(&canonical, |value| {
                fields(value)?[1] = Value::Integer(2_u8.into());
                Ok(())
            })?,
            ForkAuthenticationCodecErrorV1::UnsupportedVersion,
        ),
        (
            mutate(&canonical, |value| {
                fields(value)?[2] = Value::Integer(0_u8.into());
                Ok(())
            })?,
            ForkAuthenticationCodecErrorV1::FieldOutOfBounds,
        ),
        (
            mutate(&canonical, |value| {
                let adapters = fields(&mut fields(value)?[2])?;
                adapters[0] = Value::Integer(0_u8.into());
                Ok(())
            })?,
            ForkAuthenticationCodecErrorV1::InvalidEncoding,
        ),
    ];
    for (bytes, expected) in cases {
        assert_eq!(
            ForkAuthenticationPolicyV1::from_canonical_cbor(&bytes),
            Err(expected)
        );
    }

    let nested_cases: Vec<(usize, Value, ForkAuthenticationCodecErrorV1)> = vec![
        (
            0,
            Value::Bytes(b"local".to_vec()),
            ForkAuthenticationCodecErrorV1::InvalidEncoding,
        ),
        (
            1,
            Value::Integer(0_u8.into()),
            ForkAuthenticationCodecErrorV1::InvalidEncoding,
        ),
        (
            2,
            Value::Text("two".to_owned()),
            ForkAuthenticationCodecErrorV1::InvalidEncoding,
        ),
        (
            3,
            Value::Bytes(Vec::new()),
            ForkAuthenticationCodecErrorV1::FieldOutOfBounds,
        ),
    ];
    for (field, replacement, expected) in nested_cases {
        let bytes = mutate(&canonical, |value| {
            let adapters = fields(&mut fields(value)?[2])?;
            let adapter = fields(&mut adapters[0])?;
            adapter[field] = replacement;
            Ok(())
        })?;
        assert_eq!(
            ForkAuthenticationPolicyV1::from_canonical_cbor(&bytes),
            Err(expected)
        );
    }

    let zero_key = mutate(&canonical, |value| {
        let adapters = fields(&mut fields(value)?[2])?;
        fields(&mut adapters[0])?[1] = Value::Bytes(vec![0; 32]);
        Ok(())
    })?;
    assert_eq!(
        ForkAuthenticationPolicyV1::from_canonical_cbor(&zero_key),
        Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        ForkAuthenticationPolicyV1::from_canonical_cbor(&vec![
            0;
            MAX_FORK_AUTH_POLICY_BYTES_V1 + 1
        ]),
        Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn lar1_public_decoder_rejects_row_types_principals_and_registry_bounds(
) -> Result<(), Box<dyn std::error::Error>> {
    let canonical = registry()?.to_canonical_cbor()?;
    let cases: Vec<(Vec<u8>, ForkAuthenticationCodecErrorV1)> = vec![
        (vec![0x80], ForkAuthenticationCodecErrorV1::InvalidEncoding),
        (
            mutate(&canonical, |value| {
                fields(value)?[1] = Value::Integer(2_u8.into());
                Ok(())
            })?,
            ForkAuthenticationCodecErrorV1::UnsupportedVersion,
        ),
        (
            mutate(&canonical, |value| {
                fields(value)?[4] = Value::Bytes(Vec::new());
                Ok(())
            })?,
            ForkAuthenticationCodecErrorV1::FieldOutOfBounds,
        ),
        (
            mutate(&canonical, |value| {
                let rows = fields(&mut fields(value)?[4])?;
                rows[0] = Value::Integer(0_u8.into());
                Ok(())
            })?,
            ForkAuthenticationCodecErrorV1::InvalidEncoding,
        ),
    ];
    for (bytes, expected) in cases {
        assert_eq!(
            LocalAccountRegistryV1::from_canonical_cbor(&bytes, 1000),
            Err(expected)
        );
    }

    let row_cases: Vec<(usize, Value, ForkAuthenticationCodecErrorV1)> = vec![
        (
            0,
            Value::Text("1001".to_owned()),
            ForkAuthenticationCodecErrorV1::InvalidEncoding,
        ),
        (
            1,
            Value::Bytes(Vec::new()),
            ForkAuthenticationCodecErrorV1::FieldOutOfBounds,
        ),
        (
            2,
            Value::Bytes(b"alice".to_vec()),
            ForkAuthenticationCodecErrorV1::InvalidEncoding,
        ),
    ];
    for (field, replacement, expected) in row_cases {
        let bytes = mutate(&canonical, |value| {
            let rows = fields(&mut fields(value)?[4])?;
            fields(&mut rows[0])?[field] = replacement;
            Ok(())
        })?;
        assert_eq!(
            LocalAccountRegistryV1::from_canonical_cbor(&bytes, 1000),
            Err(expected)
        );
    }

    let forbidden_uid = mutate(&canonical, |value| {
        let rows = fields(&mut fields(value)?[4])?;
        fields(&mut rows[0])?[0] = Value::Integer(0_u8.into());
        Ok(())
    })?;
    assert_eq!(
        LocalAccountRegistryV1::from_canonical_cbor(&forbidden_uid, 1000),
        Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        LocalAccountRegistryV1::from_canonical_cbor(
            &vec![0; MAX_FORK_AUTH_CREDENTIAL_BYTES_V1 + 1],
            1000,
        ),
        Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn apr1_public_decoder_rejects_record_field_shapes() -> Result<(), Box<dyn std::error::Error>> {
    let record = record()?;
    let apr = record.to_canonical_cbor()?;
    let record_cases: Vec<(usize, Value, ForkAuthenticationCodecErrorV1)> = vec![
        (
            2,
            Value::Integer(0_u8.into()),
            ForkAuthenticationCodecErrorV1::FieldOutOfBounds,
        ),
        (
            3,
            Value::Bytes(b"local".to_vec()),
            ForkAuthenticationCodecErrorV1::InvalidEncoding,
        ),
        (
            4,
            Value::Text("two".to_owned()),
            ForkAuthenticationCodecErrorV1::InvalidEncoding,
        ),
        (
            5,
            Value::Text("100".to_owned()),
            ForkAuthenticationCodecErrorV1::InvalidEncoding,
        ),
        (
            6,
            Value::Text("200".to_owned()),
            ForkAuthenticationCodecErrorV1::InvalidEncoding,
        ),
        (
            7,
            Value::Integer(0_u8.into()),
            ForkAuthenticationCodecErrorV1::InvalidEncoding,
        ),
        (
            8,
            Value::Integer(0_u8.into()),
            ForkAuthenticationCodecErrorV1::InvalidEncoding,
        ),
    ];
    for (field, replacement, expected) in record_cases {
        let bytes = mutate(&apr, |value| {
            fields(value)?[field] = replacement;
            Ok(())
        })?;
        assert_eq!(
            AuthenticatedPrincipalRecordV1::from_canonical_cbor(&bytes),
            Err(expected)
        );
    }
    let invalid_interval = mutate(&apr, |value| {
        fields(value)?[6] = Value::Integer(100_u8.into());
        Ok(())
    })?;
    assert_eq!(
        AuthenticatedPrincipalRecordV1::from_canonical_cbor(&invalid_interval),
        Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        AuthenticatedPrincipalRecordV1::from_canonical_cbor(&vec![
            0;
            MAX_AUTHENTICATED_PRINCIPAL_RECORD_BYTES_V1
                + 1
        ],),
        Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn fae1_public_decoder_rejects_evidence_field_shapes() -> Result<(), Box<dyn std::error::Error>> {
    let record = record()?;
    let evidence = AuthenticatedPrincipalEvidenceV1::new(record, [9; 64])?;
    let fae = evidence.to_canonical_cbor()?;
    let cases: Vec<(Vec<u8>, ForkAuthenticationCodecErrorV1)> = vec![
        (vec![0x80], ForkAuthenticationCodecErrorV1::InvalidEncoding),
        (
            mutate(&fae, |value| {
                fields(value)?[1] = Value::Integer(2_u8.into());
                Ok(())
            })?,
            ForkAuthenticationCodecErrorV1::UnsupportedVersion,
        ),
        (
            mutate(&fae, |value| {
                fields(value)?[2] = Value::Integer(0_u8.into());
                Ok(())
            })?,
            ForkAuthenticationCodecErrorV1::FieldOutOfBounds,
        ),
        (
            mutate(&fae, |value| {
                fields(value)?[3] = Value::Integer(0_u8.into());
                Ok(())
            })?,
            ForkAuthenticationCodecErrorV1::InvalidEncoding,
        ),
        (
            mutate(&fae, |value| {
                fields(value)?[2] = Value::Bytes(vec![0xff]);
                Ok(())
            })?,
            ForkAuthenticationCodecErrorV1::InvalidEncoding,
        ),
    ];
    for (bytes, expected) in cases {
        assert_eq!(
            AuthenticatedPrincipalEvidenceV1::from_canonical_cbor(&bytes),
            Err(expected)
        );
    }
    assert_eq!(
        AuthenticatedPrincipalEvidenceV1::from_canonical_cbor(&vec![
            0;
            MAX_AUTHENTICATED_PRINCIPAL_EVIDENCE_BYTES_V1
                + 1
        ],),
        Err(ForkAuthenticationCodecErrorV1::FieldOutOfBounds)
    );
    Ok(())
}
