#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use ciborium::value::Value;
use pos_core::{
    ForkAdmissionAuthorityCodecErrorV1, ForkAdmissionErrorV1, ForkAdmissionHostRecordV1,
    ForkAdmissionInitializeChallengeV1, ForkAdmissionOpenChallengeV1, ForkAuthorityOriginV1, Hash,
    OwnerIdV1, PrincipalOwnerBindingInputV1, PrincipalOwnerBindingV1, PublicKey,
    MAX_PRINCIPAL_OWNER_BINDING_BYTES_V1,
};

const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

const fn key(value: u8) -> PublicKey {
    PublicKey::from_bytes([value; 32])
}

fn expect_out_of_bounds<T>(result: Result<T, ForkAdmissionAuthorityCodecErrorV1>) {
    assert_eq!(
        result.err(),
        Some(ForkAdmissionAuthorityCodecErrorV1::FieldOutOfBounds)
    );
}

#[test]
fn public_authority_codecs_reject_each_invalid_field_and_cbor_shape(
) -> Result<(), Box<dyn std::error::Error>> {
    let host = ForkAdmissionHostRecordV1::new(hash(1), key(2), hash(3))?;
    let initialize = ForkAdmissionInitializeChallengeV1::new(hash(1), hash(2), key(3), hash(4))?;
    let open = ForkAdmissionOpenChallengeV1::new(hash(1), hash(2), hash(3))?;

    assert_eq!(
        initialize.host_record(),
        ForkAdmissionHostRecordV1::new(hash(1), key(3), hash(4))?
    );

    for field in [9, 43, 77] {
        let mut bytes = host.to_canonical_cbor()?;
        bytes[field..field + 32].fill(0);
        expect_out_of_bounds(ForkAdmissionHostRecordV1::from_canonical_cbor(&bytes));
    }
    for field in [9, 43, 77, 111] {
        let mut bytes = initialize.to_canonical_cbor()?;
        bytes[field..field + 32].fill(0);
        expect_out_of_bounds(ForkAdmissionInitializeChallengeV1::from_canonical_cbor(
            &bytes,
        ));
    }
    for field in [9, 43, 77] {
        let mut bytes = open.to_canonical_cbor()?;
        bytes[field..field + 32].fill(0);
        expect_out_of_bounds(ForkAdmissionOpenChallengeV1::from_canonical_cbor(&bytes));
    }

    expect_out_of_bounds(ForkAdmissionHostRecordV1::new(
        Hash::zero(),
        key(2),
        hash(3),
    ));
    expect_out_of_bounds(ForkAdmissionHostRecordV1::new(hash(1), key(0), hash(3)));
    expect_out_of_bounds(ForkAdmissionHostRecordV1::new(
        hash(1),
        key(2),
        Hash::zero(),
    ));
    expect_out_of_bounds(ForkAdmissionInitializeChallengeV1::new(
        Hash::zero(),
        hash(2),
        key(3),
        hash(4),
    ));
    expect_out_of_bounds(ForkAdmissionInitializeChallengeV1::new(
        hash(1),
        Hash::zero(),
        key(3),
        hash(4),
    ));
    expect_out_of_bounds(ForkAdmissionInitializeChallengeV1::new(
        hash(1),
        hash(2),
        key(0),
        hash(4),
    ));
    expect_out_of_bounds(ForkAdmissionInitializeChallengeV1::new(
        hash(1),
        hash(2),
        key(3),
        Hash::zero(),
    ));
    expect_out_of_bounds(ForkAdmissionOpenChallengeV1::new(
        Hash::zero(),
        hash(2),
        hash(3),
    ));
    expect_out_of_bounds(ForkAdmissionOpenChallengeV1::new(
        hash(1),
        Hash::zero(),
        hash(3),
    ));
    expect_out_of_bounds(ForkAdmissionOpenChallengeV1::new(
        hash(1),
        hash(2),
        Hash::zero(),
    ));

    let mut trailing_field = host.to_canonical_cbor()?;
    trailing_field[0] = 0x84;
    assert_eq!(
        ForkAdmissionHostRecordV1::from_canonical_cbor(&trailing_field),
        Err(ForkAdmissionAuthorityCodecErrorV1::InvalidEncoding)
    );
    assert_eq!(
        ForkAdmissionHostRecordV1::from_canonical_cbor(&[0]),
        Err(ForkAdmissionAuthorityCodecErrorV1::InvalidEncoding)
    );
    let mut non_integer_version = host.to_canonical_cbor()?;
    non_integer_version[6] = 0xf5;
    assert_eq!(
        ForkAdmissionHostRecordV1::from_canonical_cbor(&non_integer_version),
        Err(ForkAdmissionAuthorityCodecErrorV1::InvalidEncoding)
    );
    let mut non_bytes_field = host.to_canonical_cbor()?;
    non_bytes_field.splice(7..41, [0xf6]);
    assert_eq!(
        ForkAdmissionHostRecordV1::from_canonical_cbor(&non_bytes_field),
        Err(ForkAdmissionAuthorityCodecErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn public_challenge_decoders_reject_wrong_field_types_and_widths(
) -> Result<(), Box<dyn std::error::Error>> {
    let initialize = ForkAdmissionInitializeChallengeV1::new(hash(1), hash(2), key(3), hash(4))?;
    let open = ForkAdmissionOpenChallengeV1::new(hash(1), hash(2), hash(3))?;
    let initialize_bytes = initialize.canonical_bytes();
    let open_bytes = open.canonical_bytes();
    assert_eq!(
        ForkAdmissionInitializeChallengeV1::from_canonical_cbor(&initialize_bytes)?,
        initialize
    );
    assert_eq!(
        ForkAdmissionOpenChallengeV1::from_canonical_cbor(&open_bytes)?,
        open
    );

    // Both replacements preserve valid CBOR and shorten the complete record,
    // so envelope parsing and the byte ceiling cannot mask field validation.
    // FAI1/FAO1 still use the shared field decoder after FAH1's fixed-shape path.
    let mut short_bytes = vec![0x58, 31];
    short_bytes.extend_from_slice(&[1; 31]);
    for replacement in [vec![0xf6], short_bytes] {
        for offset in [7, 41, 75, 109] {
            let mut bytes = initialize_bytes.clone();
            bytes.splice(offset..offset + 34, replacement.iter().copied());
            assert_eq!(
                ForkAdmissionInitializeChallengeV1::from_canonical_cbor(&bytes).err(),
                Some(ForkAdmissionAuthorityCodecErrorV1::FieldOutOfBounds),
                "FAI1 field at {offset}"
            );
        }
        for offset in [7, 41, 75] {
            let mut bytes = open_bytes.clone();
            bytes.splice(offset..offset + 34, replacement.iter().copied());
            assert_eq!(
                ForkAdmissionOpenChallengeV1::from_canonical_cbor(&bytes).err(),
                Some(ForkAdmissionAuthorityCodecErrorV1::FieldOutOfBounds),
                "FAO1 field at {offset}"
            );
        }
    }
    Ok(())
}

#[test]
fn public_authority_codecs_round_trip_valid_records() -> Result<(), Box<dyn std::error::Error>> {
    let host = ForkAdmissionHostRecordV1::new(hash(1), key(2), hash(3))?;
    let initialize = ForkAdmissionInitializeChallengeV1::new(hash(4), hash(5), key(6), hash(7))?;
    let open = ForkAdmissionOpenChallengeV1::new(hash(8), hash(9), hash(10))?;

    assert_eq!(initialize.store_id(), hash(4));
    assert_eq!(initialize.authentication_policy_digest(), hash(7));

    assert_eq!(
        ForkAdmissionHostRecordV1::from_canonical_cbor(&host.canonical_bytes())?,
        host
    );
    assert_eq!(
        ForkAdmissionInitializeChallengeV1::from_canonical_cbor(&initialize.canonical_bytes())?,
        initialize
    );
    assert_eq!(
        ForkAdmissionOpenChallengeV1::from_canonical_cbor(&open.canonical_bytes())?,
        open
    );
    Ok(())
}

// An independent copy of the pre-factor generic transport/error table. This
// exercises public decoding, not the fast-path's private shape predicate.
#[cfg_attr(coverage_nightly, coverage(off))]
mod fixed_fah1_parity {
    use super::*;
    use std::io::Cursor;

    type CodecResult = Result<ForkAdmissionHostRecordV1, ForkAdmissionAuthorityCodecErrorV1>;

    fn previous_decoder(bytes: &[u8]) -> CodecResult {
        use ForkAdmissionAuthorityCodecErrorV1::{
            FieldOutOfBounds, InvalidEncoding, UnsupportedVersion,
        };
        if bytes.len() > 109 {
            return Err(FieldOutOfBounds);
        }
        let mut cursor = Cursor::new(bytes);
        let value: Value = ciborium::from_reader(&mut cursor).map_err(|_| InvalidEncoding)?;
        if cursor.position() != bytes.len() as u64 {
            return Err(InvalidEncoding);
        }
        let Value::Array(fields) = value else {
            return Err(InvalidEncoding);
        };
        if fields.len() != 5
            || !matches!(fields.first(), Some(Value::Text(marker)) if marker == "FAH1")
        {
            return Err(InvalidEncoding);
        }
        match &fields[1] {
            Value::Integer(version) if *version == 1.into() => {}
            Value::Integer(_) => return Err(UnsupportedVersion),
            _ => return Err(InvalidEncoding),
        }
        let field = |value: &Value| -> Result<[u8; 32], ForkAdmissionAuthorityCodecErrorV1> {
            let Value::Bytes(bytes) = value else {
                return Err(FieldOutOfBounds);
            };
            let array = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| FieldOutOfBounds)?;
            if array == [0; 32] {
                return Err(FieldOutOfBounds);
            }
            Ok(array)
        };
        ForkAdmissionHostRecordV1::new(
            Hash::from_bytes(field(&fields[2])?),
            PublicKey::from_bytes(field(&fields[3])?),
            Hash::from_bytes(field(&fields[4])?),
        )
    }

    fn parity(bytes: &[u8]) {
        assert_eq!(
            ForkAdmissionHostRecordV1::from_canonical_cbor(bytes),
            previous_decoder(bytes),
            "FAH1 public codec parity for {bytes:?}"
        );
    }

    fn encode(value: &Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut bytes = Vec::new();
        ciborium::into_writer(value, &mut bytes)?;
        Ok(bytes)
    }

    fn fields() -> Vec<Value> {
        vec![
            Value::Text("FAH1".to_owned()),
            Value::Integer(1.into()),
            Value::Bytes(vec![1; 32]),
            Value::Bytes(vec![2; 32]),
            Value::Bytes(vec![3; 32]),
        ]
    }

    #[test]
    fn fixed_fah1_public_decoder_matches_independent_golden_and_previous_transport(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut golden = vec![0x85, 0x64, b'F', b'A', b'H', b'1', 1];
        for identity in [1, 2, 3] {
            golden.extend_from_slice(&[0x58, 32]);
            golden.extend_from_slice(&[identity; 32]);
        }
        assert_eq!(golden.len(), 109);
        assert_eq!(encode(&Value::Array(fields()))?, golden);
        let host = ForkAdmissionHostRecordV1::new(hash(1), key(2), hash(3))?;
        assert_eq!(host.canonical_bytes(), golden);
        assert_eq!(
            ForkAdmissionHostRecordV1::from_canonical_cbor(&golden)?,
            host
        );
        parity(&golden);
        for length in 0..golden.len() {
            parity(&golden[..length]);
        }
        let mut trailing = golden.clone();
        trailing.push(0);
        parity(&trailing);
        for offset in 0..golden.len() {
            for replacement in [0, 1, 0x17, 0x18, 0x20, 0x58, 0x60, 0x80, 0x9f, 0xf6, 0xff] {
                let mut mutated = golden.clone();
                mutated[offset] = replacement;
                parity(&mutated);
            }
        }
        for start in [9, 43, 77] {
            let mut zero = golden.clone();
            zero[start..start + 32].fill(0);
            parity(&zero);
            assert_eq!(
                ForkAdmissionHostRecordV1::from_canonical_cbor(&zero),
                Err(ForkAdmissionAuthorityCodecErrorV1::FieldOutOfBounds)
            );
        }
        // Correct fields in nonpreferred/indefinite transports exceed the cap.
        for (range, replacement) in [
            (0..1, vec![0x98, 5]),
            (1..2, vec![0x78, 4]),
            (6..7, vec![0x18, 1]),
            (7..9, vec![0x59, 0, 32]),
        ] {
            let mut nonpreferred = golden.clone();
            nonpreferred.splice(range, replacement);
            parity(&nonpreferred);
        }
        let mut indefinite = golden;
        indefinite[0] = 0x9f;
        indefinite.push(0xff);
        parity(&indefinite);
        Ok(())
    }

    #[test]
    fn fixed_fah1_public_decoder_rejects_compensated_nonfixed_shapes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for lengths in [[31, 33, 32], [32, 31, 33], [33, 32, 31]] {
            let mut values = fields();
            for (index, length) in lengths.into_iter().enumerate() {
                values[index + 2] = Value::Bytes(vec![1; length]);
            }
            let bytes = encode(&Value::Array(values))?;
            assert_eq!(bytes.len(), 109);
            parity(&bytes);
            assert_eq!(
                ForkAdmissionHostRecordV1::from_canonical_cbor(&bytes),
                Err(ForkAdmissionAuthorityCodecErrorV1::FieldOutOfBounds)
            );
        }

        let mut values = fields();
        values[2] = Value::Bytes(vec![1; 31]);
        let short = encode(&Value::Array(values))?;
        assert_eq!(short.len(), 108);
        // Each nonpreferred header consumes the byte saved by the short field.
        for (range, replacement) in [
            (0..1, vec![0x98, 5]),
            (1..2, vec![0x78, 4]),
            (6..7, vec![0x18, 1]),
            (7..9, vec![0x59, 0, 31]),
        ] {
            let mut bytes = short.clone();
            bytes.splice(range, replacement);
            assert_eq!(bytes.len(), 109);
            parity(&bytes);
            assert_eq!(
                ForkAdmissionHostRecordV1::from_canonical_cbor(&bytes),
                Err(ForkAdmissionAuthorityCodecErrorV1::FieldOutOfBounds)
            );
        }
        let mut indefinite = short;
        indefinite[0] = 0x9f;
        indefinite.push(0xff);
        assert_eq!(indefinite.len(), 109);
        parity(&indefinite);

        // A tagged outer value fails envelope decoding before field validation.
        let mut values = fields();
        values[2] = Value::Bytes(vec![1; 30]);
        let mut tagged = vec![0xd8, 24];
        tagged.extend(encode(&Value::Array(values))?);
        assert_eq!(tagged.len(), 109);
        parity(&tagged);
        assert_eq!(
            ForkAdmissionHostRecordV1::from_canonical_cbor(&tagged),
            Err(ForkAdmissionAuthorityCodecErrorV1::InvalidEncoding)
        );
        Ok(())
    }

    #[test]
    fn fixed_fah1_public_decoder_preserves_malformed_error_precedence(
    ) -> Result<(), Box<dyn std::error::Error>> {
        parity(&encode(&Value::Null)?);
        parity(&encode(&Value::Array(Vec::new()))?);
        for version in [
            Value::Integer(0.into()),
            Value::Integer(2.into()),
            Value::Integer((-1).into()),
            Value::Null,
            Value::Bool(true),
        ] {
            let mut values = fields();
            values[1] = version;
            parity(&encode(&Value::Array(values.clone()))?);
            values[2] = Value::Null;
            parity(&encode(&Value::Array(values.clone()))?);
            values[0] = Value::Text("FAO1".to_owned());
            parity(&encode(&Value::Array(values))?);
        }
        for index in 2..5 {
            for invalid in [
                Value::Null,
                Value::Integer(1.into()),
                Value::Bytes(Vec::new()),
                Value::Bytes(vec![1; 31]),
                Value::Bytes(vec![1; 33]),
                Value::Bytes(vec![0; 32]),
            ] {
                let mut values = fields();
                values[index] = invalid;
                parity(&encode(&Value::Array(values))?);
            }
        }
        for marker in [
            Value::Text("FAH2".to_owned()),
            Value::Bytes(b"FAH1".to_vec()),
            Value::Null,
        ] {
            let mut values = fields();
            values[0] = marker;
            parity(&encode(&Value::Array(values))?);
        }
        Ok(())
    }
}

#[test]
fn public_pob1_codec_is_canonical_bounded_and_closed() -> Result<(), Box<dyn std::error::Error>> {
    let binding = PrincipalOwnerBindingV1::new(PrincipalOwnerBindingInputV1 {
        operation_id: hash(1),
        principal_digest: hash(2),
        owner: OwnerIdV1::new("o".repeat(128))?,
        origin: ForkAuthorityOriginV1::Local,
    })?;
    let canonical = binding.to_canonical_cbor();
    assert_eq!(canonical.len(), MAX_PRINCIPAL_OWNER_BINDING_BYTES_V1);
    assert_eq!(
        PrincipalOwnerBindingV1::from_canonical_cbor(&canonical)?,
        binding
    );

    let mut wrong_marker = canonical.clone();
    wrong_marker[2] = b'X';
    assert_eq!(
        PrincipalOwnerBindingV1::from_canonical_cbor(&wrong_marker),
        Err(ForkAdmissionErrorV1::CorruptAuthority)
    );
    let mut trailing = canonical.clone();
    trailing.push(0);
    assert_eq!(
        PrincipalOwnerBindingV1::from_canonical_cbor(&trailing),
        Err(ForkAdmissionErrorV1::CorruptAuthority)
    );
    assert_eq!(
        PrincipalOwnerBindingV1::from_canonical_cbor(
            &[0; MAX_PRINCIPAL_OWNER_BINDING_BYTES_V1 + 1],
        ),
        Err(ForkAdmissionErrorV1::CorruptAuthority)
    );
    let mut zero_operation_id = canonical.clone();
    zero_operation_id[9..41].fill(0);
    assert_eq!(
        PrincipalOwnerBindingV1::from_canonical_cbor(&zero_operation_id),
        Err(ForkAdmissionErrorV1::CorruptAuthority)
    );
    let mut zero_principal_digest = canonical;
    zero_principal_digest[43..75].fill(0);
    assert_eq!(
        PrincipalOwnerBindingV1::from_canonical_cbor(&zero_principal_digest),
        Err(ForkAdmissionErrorV1::CorruptAuthority)
    );
    assert_eq!(
        PrincipalOwnerBindingV1::new(PrincipalOwnerBindingInputV1 {
            operation_id: Hash::zero(),
            principal_digest: hash(2),
            owner: OwnerIdV1::new("owner")?,
            origin: ForkAuthorityOriginV1::Local,
        }),
        Err(ForkAdmissionErrorV1::InvalidRequest)
    );
    Ok(())
}

#[test]
fn public_pob1_decoder_rejects_each_untrusted_record_shape(
) -> Result<(), Box<dyn std::error::Error>> {
    let binding = PrincipalOwnerBindingV1::new(PrincipalOwnerBindingInputV1 {
        operation_id: hash(1),
        principal_digest: hash(2),
        owner: OwnerIdV1::new("owner")?,
        origin: ForkAuthorityOriginV1::Local,
    })?;
    let canonical = binding.to_canonical_cbor();

    let mut trailing = canonical;
    trailing.push(0);
    assert_eq!(
        PrincipalOwnerBindingV1::from_canonical_cbor(&trailing),
        Err(ForkAdmissionErrorV1::CorruptAuthority)
    );

    for record in [
        Value::Null,
        Value::Array(vec![
            Value::Bytes(b"POB1".to_vec()),
            Value::Integer(1.into()),
            Value::Bytes(hash(1).as_bytes().to_vec()),
            Value::Bytes(hash(2).as_bytes().to_vec()),
            Value::Integer(1.into()),
            Value::Array(vec![Value::Integer(1.into())]),
        ]),
        Value::Array(vec![
            Value::Bytes(b"POB1".to_vec()),
            Value::Integer(1.into()),
            Value::Integer(1.into()),
            Value::Bytes(hash(2).as_bytes().to_vec()),
            Value::Text("owner".to_owned()),
            Value::Array(vec![Value::Integer(1.into())]),
        ]),
        Value::Array(vec![
            Value::Bytes(b"POB1".to_vec()),
            Value::Integer(1.into()),
            Value::Bytes(vec![1; 31]),
            Value::Bytes(hash(2).as_bytes().to_vec()),
            Value::Text("owner".to_owned()),
            Value::Array(vec![Value::Integer(1.into())]),
        ]),
        Value::Array(vec![
            Value::Bytes(b"POB1".to_vec()),
            Value::Integer(1.into()),
            Value::Bytes(hash(1).as_bytes().to_vec()),
            Value::Bytes(hash(2).as_bytes().to_vec()),
            Value::Text(String::new()),
            Value::Array(vec![Value::Integer(1.into())]),
        ]),
    ] {
        let mut bytes = Vec::new();
        ciborium::into_writer(&record, &mut bytes)?;
        assert_eq!(
            PrincipalOwnerBindingV1::from_canonical_cbor(&bytes),
            Err(ForkAdmissionErrorV1::CorruptAuthority)
        );
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod borrowed_pob1_parity {
    use super::*;
    use std::io::Cursor;

    type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

    /// Preserve the previous generic-tree transport as an independent test
    /// oracle. Production now uses borrowed native primitives instead.
    fn previous_decoder(bytes: &[u8]) -> Option<PrincipalOwnerBindingV1> {
        if bytes.len() > MAX_PRINCIPAL_OWNER_BINDING_BYTES_V1 {
            return None;
        }
        let mut cursor = Cursor::new(bytes);
        let value: Value = ciborium::from_reader(&mut cursor).ok()?;
        let mut canonical = Vec::new();
        ciborium::into_writer(&value, &mut canonical).ok()?;
        if usize::try_from(cursor.position()).ok()? != bytes.len() || canonical != bytes {
            return None;
        }
        let Value::Array(fields) = value else {
            return None;
        };
        if fields.len() != 6
            || !matches!(&fields[0], Value::Bytes(marker) if marker == b"POB1")
            || !matches!(&fields[1], Value::Integer(version) if *version == 1.into())
            || !matches!(&fields[5], Value::Array(origin) if origin.len() == 1 && origin[0] == Value::Integer(1.into()))
        {
            return None;
        }
        let digest = |value: &Value| -> Option<Hash> {
            let Value::Bytes(value) = value else {
                return None;
            };
            let bytes: [u8; 32] = value.as_slice().try_into().ok()?;
            (bytes != [0; 32]).then_some(Hash::from_bytes(bytes))
        };
        let Value::Text(owner) = &fields[4] else {
            return None;
        };
        let binding = PrincipalOwnerBindingV1::new(PrincipalOwnerBindingInputV1 {
            operation_id: digest(&fields[2])?,
            principal_digest: digest(&fields[3])?,
            owner: OwnerIdV1::new(owner).ok()?,
            origin: ForkAuthorityOriginV1::Local,
        })
        .ok()?;
        (binding.to_canonical_cbor() == bytes).then_some(binding)
    }

    fn parity(bytes: &[u8]) {
        match previous_decoder(bytes) {
            Some(expected) => assert_eq!(
                PrincipalOwnerBindingV1::from_canonical_cbor(bytes),
                Ok(expected)
            ),
            None => assert_eq!(
                PrincipalOwnerBindingV1::from_canonical_cbor(bytes),
                Err(ForkAdmissionErrorV1::CorruptAuthority)
            ),
        }
    }

    fn fields(owner: &str, origin: Value) -> Value {
        Value::Array(vec![
            Value::Bytes(b"POB1".to_vec()),
            Value::Integer(1.into()),
            Value::Bytes(hash(1).as_bytes().to_vec()),
            Value::Bytes(hash(2).as_bytes().to_vec()),
            Value::Text(owner.to_owned()),
            origin,
        ])
    }

    fn encode(value: &Value) -> Fallible<Vec<u8>> {
        let mut bytes = Vec::new();
        ciborium::into_writer(value, &mut bytes)?;
        Ok(bytes)
    }

    #[test]
    fn public_pob1_borrowed_decoder_matches_previous_transport_and_independent_bytes(
    ) -> Fallible<()> {
        for owner in [
            "o".to_owned(),
            "o".repeat(23),
            "o".repeat(24),
            "o".repeat(64),
            "o".repeat(128),
            "é".repeat(64),
        ] {
            let bytes = encode(&fields(
                &owner,
                Value::Array(vec![Value::Integer(1.into())]),
            ))?;
            let binding = PrincipalOwnerBindingV1::from_canonical_cbor(&bytes)?;
            assert_eq!(binding.input().owner.as_str(), owner);
            assert_eq!(binding.to_canonical_cbor(), bytes);
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"pigloros/principal-owner-binding/v1");
            hasher.update(&bytes);
            assert_eq!(
                binding.digest(),
                Hash::from_bytes(*hasher.finalize().as_bytes())
            );
            parity(&bytes);
            for end in 0..bytes.len() {
                parity(&bytes[..end]);
            }
            for index in 0..bytes.len() {
                for replacement in [0, 255] {
                    let mut changed = bytes.clone();
                    changed[index] = replacement;
                    parity(&changed);
                }
            }
            let mut trailing = bytes.clone();
            trailing.push(0);
            parity(&trailing);
            let mut nonpreferred = bytes;
            // POB1's BSTR4 marker occupies indices 1..6, version is index 6.
            assert_eq!(nonpreferred[6], 1);
            nonpreferred.splice(6..7, [0x18, 0x01]);
            parity(&nonpreferred);
        }
        Ok(())
    }

    #[test]
    fn public_pob1_borrowed_decoder_preserves_shapes_and_local_imported_origin_boundary(
    ) -> Fallible<()> {
        for owner in [String::new(), "o".repeat(129), "é".repeat(65)] {
            parity(&encode(&fields(
                &owner,
                Value::Array(vec![Value::Integer(1.into())]),
            ))?);
        }
        for origin in [
            Value::Array(vec![]),
            Value::Array(vec![Value::Integer(0.into())]),
            Value::Array(vec![
                Value::Integer(2.into()),
                Value::Bytes(hash(3).as_bytes().to_vec()),
            ]),
            Value::Null,
        ] {
            parity(&encode(&fields("owner", origin))?);
        }
        for marker in [
            Value::Text("POB1".to_owned()),
            Value::Bytes(b"POB2".to_vec()),
        ] {
            let Value::Array(mut value) =
                fields("owner", Value::Array(vec![Value::Integer(1.into())]))
            else {
                return Err("fixture shape".into());
            };
            value[0] = marker;
            parity(&encode(&Value::Array(value))?);
        }
        let local = PrincipalOwnerBindingV1::new(PrincipalOwnerBindingInputV1 {
            operation_id: hash(1),
            principal_digest: hash(2),
            owner: OwnerIdV1::new("é".repeat(64))?,
            origin: ForkAuthorityOriginV1::Local,
        })?;
        let imported =
            pos_core::ImportedPrincipalOwnerBindingV1::from_local(local.clone(), hash(3));
        let bytes = imported.to_canonical_cbor();
        assert_eq!(
            bytes.len(),
            pos_core::MAX_IMPORTED_PRINCIPAL_OWNER_BINDING_BYTES_V1
        );
        assert_eq!(
            pos_core::ImportedPrincipalOwnerBindingV1::from_canonical_cbor(&bytes)?,
            imported
        );
        parity(&bytes);
        assert_eq!(
            PrincipalOwnerBindingV1::from_canonical_cbor(&local.to_canonical_cbor())?,
            local
        );
        Ok(())
    }
}
