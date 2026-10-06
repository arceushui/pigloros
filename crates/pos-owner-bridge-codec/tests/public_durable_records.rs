use pos_owner_bridge_codec::{
    decode_cleanup_record, decode_subject_credential_binding, encode_cleanup_record,
    encode_subject_credential_binding, CleanupRecordV1, CoseEs256PublicKey, OwnerBridgeCodecError,
    SubjectCredentialBindingV1, TransportCodes, MAX_SUBJECT_CREDENTIAL_BINDING_BYTES,
};

const CEREMONY_ID: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const SUBJECT_ID: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const USER_HANDLE: [u8; 32] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
];
const IMAGE_PATH_SHA256: [u8; 32] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
];

#[test]
fn public_durable_codecs_match_adr_097_and_110_vectors() -> Result<(), OwnerBridgeCodecError> {
    let binding = fixture_binding()?;
    let expected_binding = hex::<187>(b"90445343423101656f776e657250101112131415161718191a1b1c1d1e1f0001696c6f63616c686f737476687474703a2f2f6c6f63616c686f73743a34393239314280815820404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f584da50102032620012158206b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2962258204fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f500f4f4078100");
    let mut binding_output = [0; 187];
    assert_eq!(
        encode_subject_credential_binding(&binding, &mut binding_output),
        Ok(expected_binding.len())
    );
    assert_eq!(binding_output, expected_binding);
    assert_eq!(
        decode_subject_credential_binding(&binding_output),
        Ok(binding)
    );

    let cleanup = CleanupRecordV1::new(
        CEREMONY_ID,
        "owner-bridge-1",
        7,
        0x0102_0304_0506_0708,
        IMAGE_PATH_SHA256,
    )?;
    let expected_cleanup = hex::<83>(b"8744504243520150000102030405060708090a0b0c0d0e0f6e6f776e65722d6272696467652d31071b01020304050607085820a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
    let mut cleanup_output = [0; 83];
    assert_eq!(
        encode_cleanup_record(&cleanup, &mut cleanup_output),
        Ok(expected_cleanup.len())
    );
    assert_eq!(cleanup_output, expected_cleanup);
    assert_eq!(decode_cleanup_record(&cleanup_output), Ok(cleanup));
    Ok(())
}

#[test]
fn public_durable_codecs_reject_closed_schema_violations() -> Result<(), OwnerBridgeCodecError> {
    assert_eq!(
        SubjectCredentialBindingV1::new(
            "owner",
            SUBJECT_ID,
            1,
            &[0x80, 0x81],
            USER_HANDLE,
            CoseEs256PublicKey::from_canonical_encoding(&cose_key())?,
            false,
            true,
            7,
            TransportCodes::new(&[0])?,
        ),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );

    let mut binding_output = [0; 187];
    let binding_length =
        encode_subject_credential_binding(&fixture_binding()?, &mut binding_output)?;
    binding_output[binding_length - 1] = 6;
    assert_eq!(
        decode_subject_credential_binding(&binding_output),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );
    assert_eq!(
        decode_subject_credential_binding(&[0; MAX_SUBJECT_CREDENTIAL_BINDING_BYTES + 1]),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );

    let mut invalid_point = cose_key();
    invalid_point[10..42].fill(0);
    assert_eq!(
        CoseEs256PublicKey::from_canonical_encoding(&invalid_point),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );

    let cleanup = CleanupRecordV1::new(CEREMONY_ID, "owner-bridge-1", 7, 0, IMAGE_PATH_SHA256)?;
    let mut cleanup_output = [0; 128];
    let cleanup_length = encode_cleanup_record(&cleanup, &mut cleanup_output)?;
    cleanup_output[cleanup_length] = 0;
    assert_eq!(
        decode_cleanup_record(&cleanup_output[..cleanup_length + 1]),
        Err(OwnerBridgeCodecError::TrailingBytes)
    );
    Ok(())
}

fn fixture_binding() -> Result<SubjectCredentialBindingV1<'static>, OwnerBridgeCodecError> {
    SubjectCredentialBindingV1::new(
        "owner",
        SUBJECT_ID,
        1,
        &[0x80, 0x81],
        USER_HANDLE,
        CoseEs256PublicKey::from_canonical_encoding(&cose_key())?,
        false,
        false,
        7,
        TransportCodes::new(&[0])?,
    )
}

fn cose_key() -> [u8; 77] {
    hex::<77>(b"a50102032620012158206b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2962258204fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
}

fn hex<const N: usize>(input: &[u8]) -> [u8; N] {
    assert_eq!(input.len(), N * 2);
    let mut output = [0; N];
    for (index, byte) in output.iter_mut().enumerate() {
        let high = hex_nibble(input[index * 2]);
        let low = hex_nibble(input[index * 2 + 1]);
        assert!(high < 16);
        assert!(low < 16);
        *byte = (high << 4) | low;
    }
    output
}

const fn hex_nibble(input: u8) -> u8 {
    match input {
        b'0'..=b'9' => input - b'0',
        b'a'..=b'f' => input - b'a' + 10,
        _ => u8::MAX,
    }
}
