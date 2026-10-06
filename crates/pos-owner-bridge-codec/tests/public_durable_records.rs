use pos_owner_bridge_codec::{
    decode_cleanup_record, decode_subject_credential_binding, encode_cleanup_record,
    encode_subject_credential_binding, CleanupRecordV1, CoseEs256PublicKey, OwnerBridgeCodecError,
    SubjectCredentialBindingInputV1, SubjectCredentialBindingV1, TransportCodes,
    MAX_CLEANUP_RECORD_BYTES, MAX_SUBJECT_CREDENTIAL_BINDING_BYTES,
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
        SubjectCredentialBindingV1::new(SubjectCredentialBindingInputV1 {
            owner_id: "owner",
            subject_id: SUBJECT_ID,
            epoch: 1,
            credential_id: &[0x80, 0x81],
            user_handle: USER_HANDLE,
            public_key: CoseEs256PublicKey::from_canonical_encoding(&cose_key())?,
            backup_eligible: false,
            backup_state: true,
            sign_count: 7,
            transports: TransportCodes::new(&[0])?,
        }),
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
        decode_cleanup_record(&cleanup_output[..=cleanup_length]),
        Err(OwnerBridgeCodecError::TrailingBytes)
    );
    let oversized_cleanup = vec![0; MAX_CLEANUP_RECORD_BYTES + 1];
    assert_eq!(
        decode_cleanup_record(&oversized_cleanup),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn public_durable_records_enforce_complete_size_and_output_boundaries(
) -> Result<(), OwnerBridgeCodecError> {
    let binding = fixture_binding()?;
    let mut binding_short_output = [0; 186];
    assert_eq!(
        encode_subject_credential_binding(&binding, &mut binding_short_output),
        Err(OwnerBridgeCodecError::BufferTooSmall)
    );
    assert_eq!(
        binding_with("owner", 1, &[]),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );

    let cleanup = CleanupRecordV1::new(CEREMONY_ID, "owner-bridge-1", 7, 0, IMAGE_PATH_SHA256)?;
    let mut cleanup_short_output = [0; 74];
    assert_eq!(
        encode_cleanup_record(&cleanup, &mut cleanup_short_output),
        Err(OwnerBridgeCodecError::BufferTooSmall)
    );

    let owner_at_field_limit = "o".repeat(MAX_SUBJECT_CREDENTIAL_BINDING_BYTES);
    assert_eq!(
        binding_with(&owner_at_field_limit, 1, &[0x80, 0x81]),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );
    let owner_over_field_limit = "o".repeat(MAX_SUBJECT_CREDENTIAL_BINDING_BYTES + 1);
    assert_eq!(
        binding_with(&owner_over_field_limit, 1, &[0x80, 0x81]),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );
    let folder_at_field_limit = "f".repeat(MAX_CLEANUP_RECORD_BYTES);
    assert_eq!(
        CleanupRecordV1::new(CEREMONY_ID, &folder_at_field_limit, 7, 0, IMAGE_PATH_SHA256),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );
    let folder_over_field_limit = "f".repeat(MAX_CLEANUP_RECORD_BYTES + 1);
    assert_eq!(
        CleanupRecordV1::new(
            CEREMONY_ID,
            &folder_over_field_limit,
            7,
            0,
            IMAGE_PATH_SHA256,
        ),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn public_durable_encoders_reject_every_short_output() -> Result<(), OwnerBridgeCodecError> {
    let binding = fixture_binding()?;
    for length in 0..187 {
        let mut output = vec![0; length];
        assert_eq!(
            encode_subject_credential_binding(&binding, &mut output),
            Err(OwnerBridgeCodecError::BufferTooSmall),
            "binding output length {length}"
        );
    }

    let cleanup = CleanupRecordV1::new(
        CEREMONY_ID,
        "owner-bridge-1",
        7,
        0x0102_0304_0506_0708,
        IMAGE_PATH_SHA256,
    )?;
    for length in 0..83 {
        let mut output = vec![0; length];
        assert_eq!(
            encode_cleanup_record(&cleanup, &mut output),
            Err(OwnerBridgeCodecError::BufferTooSmall),
            "cleanup output length {length}"
        );
    }
    Ok(())
}

#[test]
fn public_durable_decoders_reject_every_truncated_record() -> Result<(), OwnerBridgeCodecError> {
    let binding = fixture_binding()?;
    let mut binding_bytes = [0; 187];
    let binding_length = encode_subject_credential_binding(&binding, &mut binding_bytes)?;
    for length in 0..binding_length {
        assert!(
            decode_subject_credential_binding(&binding_bytes[..length]).is_err(),
            "binding prefix {length}"
        );
    }

    let cleanup = CleanupRecordV1::new(
        CEREMONY_ID,
        "owner-bridge-1",
        7,
        0x0102_0304_0506_0708,
        IMAGE_PATH_SHA256,
    )?;
    let mut cleanup_bytes = [0; 83];
    let cleanup_length = encode_cleanup_record(&cleanup, &mut cleanup_bytes)?;
    for length in 0..cleanup_length {
        assert!(
            decode_cleanup_record(&cleanup_bytes[..length]).is_err(),
            "cleanup prefix {length}"
        );
    }
    Ok(())
}

#[test]
fn public_binding_decoder_rejects_wrong_cbor_types() -> Result<(), OwnerBridgeCodecError> {
    let binding = fixture_binding()?;
    let mut binding_bytes = [0; 187];
    encode_subject_credential_binding(&binding, &mut binding_bytes)?;
    for (label, offset, value) in [
        ("outer array", 0, 0x40),
        ("magic", 1, 0x60),
        ("version", 6, 0x60),
        ("owner ID", 7, 0x40),
        ("subject ID", 13, 0x60),
        ("role", 30, 0x60),
        ("RP ID", 32, 0x40),
        ("owner origin", 42, 0x40),
        ("credential ID", 65, 0x60),
        ("user handle", 68, 0x60),
        ("COSE key", 102, 0x60),
        ("algorithm", 181, 0x60),
        ("backup eligibility", 182, 0x60),
        ("backup state", 183, 0x60),
        ("signature counter", 184, 0x60),
        ("transport list", 185, 0x40),
        ("transport code", 186, 0x60),
    ] {
        let mut malformed = binding_bytes;
        malformed[offset] = value;
        assert!(
            decode_subject_credential_binding(&malformed).is_err(),
            "binding {label}"
        );
    }

    let mut oversized_owner_length = binding_bytes;
    oversized_owner_length[7..10].copy_from_slice(&[0x79, 0x10, 0x01]);
    assert_eq!(
        decode_subject_credential_binding(&oversized_owner_length),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn public_cleanup_decoder_rejects_wrong_cbor_types() -> Result<(), OwnerBridgeCodecError> {
    let cleanup = CleanupRecordV1::new(
        CEREMONY_ID,
        "owner-bridge-1",
        7,
        0x0102_0304_0506_0708,
        IMAGE_PATH_SHA256,
    )?;
    let mut cleanup_bytes = [0; 83];
    encode_cleanup_record(&cleanup, &mut cleanup_bytes)?;
    for (label, offset, value) in [
        ("outer array", 0, 0x40),
        ("magic", 1, 0x60),
        ("version", 6, 0x60),
        ("ceremony ID", 7, 0x60),
        ("folder name", 24, 0x40),
        ("browser PID", 39, 0x60),
        ("creation time", 40, 0x60),
        ("image hash", 49, 0x60),
    ] {
        let mut malformed = cleanup_bytes;
        malformed[offset] = value;
        assert!(
            decode_cleanup_record(&malformed).is_err(),
            "cleanup {label}"
        );
    }

    let mut oversized_folder_length = cleanup_bytes;
    oversized_folder_length[24..27].copy_from_slice(&[0x79, 0x10, 0x01]);
    assert_eq!(
        decode_cleanup_record(&oversized_folder_length),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn public_durable_records_preserve_every_field_and_cbor_width_boundary(
) -> Result<(), OwnerBridgeCodecError> {
    let binding = fixture_binding()?;
    assert_eq!(binding.owner_id(), "owner");
    assert_eq!(binding.subject_id(), SUBJECT_ID);
    assert_eq!(binding.epoch(), 1);
    assert_eq!(binding.credential_id(), &[0x80, 0x81]);
    assert_eq!(binding.user_handle(), USER_HANDLE);
    assert_eq!(binding.public_key().canonical_encoding(), cose_key());
    assert!(!binding.backup_eligible());
    assert!(!binding.backup_state());
    assert_eq!(binding.sign_count(), 7);
    assert_eq!(binding.transports().as_slice(), &[0]);

    let cleanup = CleanupRecordV1::new(
        CEREMONY_ID,
        "owner-bridge-1",
        u32::MAX,
        u64::MAX,
        IMAGE_PATH_SHA256,
    )?;
    assert_eq!(cleanup.ceremony_id(), CEREMONY_ID);
    assert_eq!(cleanup.folder_name(), "owner-bridge-1");
    assert_eq!(cleanup.browser_pid(), u32::MAX);
    assert_eq!(cleanup.creation_filetime(), u64::MAX);
    assert_eq!(cleanup.image_path_sha256(), IMAGE_PATH_SHA256);

    let credential_id = [0x80, 0x81];
    for epoch in [24, 256, 65_536, u64::MAX] {
        let boundary = binding_with("owner", epoch, &credential_id)?;
        let mut output = vec![0; MAX_SUBJECT_CREDENTIAL_BINDING_BYTES];
        let length = encode_subject_credential_binding(&boundary, &mut output)?;
        assert_eq!(
            decode_subject_credential_binding(&output[..length])?.epoch(),
            epoch
        );
    }

    let owner_with_one_byte_length = "o".repeat(24);
    let owner_with_two_byte_length = "o".repeat(256);
    for owner_id in [
        owner_with_one_byte_length.as_str(),
        owner_with_two_byte_length.as_str(),
    ] {
        let boundary = binding_with(owner_id, 1, &credential_id)?;
        let mut output = vec![0; MAX_SUBJECT_CREDENTIAL_BINDING_BYTES];
        let length = encode_subject_credential_binding(&boundary, &mut output)?;
        assert_eq!(
            decode_subject_credential_binding(&output[..length])?.owner_id(),
            owner_id
        );
    }
    Ok(())
}

#[test]
fn public_durable_decoders_reject_every_closed_schema_variation(
) -> Result<(), OwnerBridgeCodecError> {
    let binding = fixture_binding()?;
    let mut binding_bytes = [0; 187];
    let binding_length = encode_subject_credential_binding(&binding, &mut binding_bytes)?;
    assert_eq!(binding_length, binding_bytes.len());

    let mut wrong_binding_array = binding_bytes;
    wrong_binding_array[0] = 0x8f;
    assert_binding_error(&wrong_binding_array, OwnerBridgeCodecError::InvalidCbor);
    let mut wrong_binding_magic = binding_bytes;
    wrong_binding_magic[2] = b'X';
    assert_binding_error(&wrong_binding_magic, OwnerBridgeCodecError::InvalidPayload);
    let mut wrong_binding_version = binding_bytes;
    wrong_binding_version[6] = 2;
    assert_binding_error(
        &wrong_binding_version,
        OwnerBridgeCodecError::InvalidPayload,
    );
    let mut noncanonical_binding_version = Vec::from(binding_bytes);
    noncanonical_binding_version.splice(6..7, [0x18, 1]);
    assert_binding_error(
        &noncanonical_binding_version,
        OwnerBridgeCodecError::NonCanonicalCbor,
    );
    let mut wrong_subject_width = binding_bytes;
    wrong_subject_width[13] = 0x51;
    assert_binding_error(&wrong_subject_width, OwnerBridgeCodecError::InvalidCbor);
    let mut wrong_role = binding_bytes;
    wrong_role[30] = 1;
    assert_binding_error(&wrong_role, OwnerBridgeCodecError::InvalidPayload);
    let mut wrong_rp_id = binding_bytes;
    wrong_rp_id[33] = b'X';
    assert_binding_error(&wrong_rp_id, OwnerBridgeCodecError::InvalidPayload);
    let mut wrong_origin = binding_bytes;
    wrong_origin[43] = b'X';
    assert_binding_error(&wrong_origin, OwnerBridgeCodecError::InvalidPayload);
    let mut empty_credential = binding_bytes;
    empty_credential[65] = 0x40;
    assert_binding_error(&empty_credential, OwnerBridgeCodecError::BoundsExceeded);
    let mut wrong_user_handle_width = binding_bytes;
    wrong_user_handle_width[68] = 0x41;
    assert_binding_error(&wrong_user_handle_width, OwnerBridgeCodecError::InvalidCbor);
    let mut wrong_algorithm = binding_bytes;
    wrong_algorithm[181] = 1;
    assert_binding_error(&wrong_algorithm, OwnerBridgeCodecError::InvalidPayload);
    let mut invalid_cose_point = binding_bytes;
    invalid_cose_point[114..146].fill(0);
    assert_binding_error(&invalid_cose_point, OwnerBridgeCodecError::InvalidPayload);
    let mut wrong_backup_flag = binding_bytes;
    wrong_backup_flag[182] = 0xf6;
    assert_binding_error(&wrong_backup_flag, OwnerBridgeCodecError::InvalidCbor);
    let mut oversized_sign_count = Vec::from(binding_bytes);
    oversized_sign_count.splice(184..185, [0x1b, 0, 0, 0, 1, 0, 0, 0, 0]);
    assert_binding_error(&oversized_sign_count, OwnerBridgeCodecError::InvalidPayload);
    let mut too_many_transports = binding_bytes;
    too_many_transports[185] = 0x87;
    assert_binding_error(&too_many_transports, OwnerBridgeCodecError::BoundsExceeded);
    let mut unknown_transport = binding_bytes;
    unknown_transport[186] = 6;
    assert_binding_error(&unknown_transport, OwnerBridgeCodecError::InvalidPayload);
    let mut oversized_transport_code = Vec::from(binding_bytes);
    oversized_transport_code.splice(186..187, [0x19, 1, 0]);
    assert_binding_error(
        &oversized_transport_code,
        OwnerBridgeCodecError::InvalidPayload,
    );
    let mut binding_trailing = Vec::from(binding_bytes);
    binding_trailing.push(0);
    assert_binding_error(&binding_trailing, OwnerBridgeCodecError::TrailingBytes);

    let cleanup = CleanupRecordV1::new(
        CEREMONY_ID,
        "owner-bridge-1",
        7,
        0x0102_0304_0506_0708,
        IMAGE_PATH_SHA256,
    )?;
    let mut cleanup_bytes = [0; 83];
    let cleanup_length = encode_cleanup_record(&cleanup, &mut cleanup_bytes)?;
    assert_eq!(cleanup_length, cleanup_bytes.len());

    let mut wrong_cleanup_array = cleanup_bytes;
    wrong_cleanup_array[0] = 0x86;
    assert_cleanup_error(&wrong_cleanup_array, OwnerBridgeCodecError::InvalidCbor);
    let mut wrong_cleanup_magic = cleanup_bytes;
    wrong_cleanup_magic[2] = b'X';
    assert_cleanup_error(&wrong_cleanup_magic, OwnerBridgeCodecError::InvalidPayload);
    let mut wrong_cleanup_version = cleanup_bytes;
    wrong_cleanup_version[6] = 2;
    assert_cleanup_error(
        &wrong_cleanup_version,
        OwnerBridgeCodecError::InvalidPayload,
    );
    let mut wrong_ceremony_width = cleanup_bytes;
    wrong_ceremony_width[7] = 0x51;
    assert_cleanup_error(&wrong_ceremony_width, OwnerBridgeCodecError::InvalidCbor);
    let mut oversized_browser_pid = Vec::from(cleanup_bytes);
    oversized_browser_pid.splice(39..40, [0x1b, 0, 0, 0, 1, 0, 0, 0, 0]);
    assert_cleanup_error(
        &oversized_browser_pid,
        OwnerBridgeCodecError::InvalidPayload,
    );
    let mut wrong_image_hash_width = cleanup_bytes;
    wrong_image_hash_width[49] = 0x41;
    assert_cleanup_error(&wrong_image_hash_width, OwnerBridgeCodecError::InvalidCbor);
    let mut cleanup_trailing = Vec::from(cleanup_bytes);
    cleanup_trailing.push(0);
    assert_cleanup_error(&cleanup_trailing, OwnerBridgeCodecError::TrailingBytes);
    Ok(())
}

fn fixture_binding() -> Result<SubjectCredentialBindingV1<'static>, OwnerBridgeCodecError> {
    binding_with("owner", 1, &[0x80, 0x81])
}

fn binding_with<'a>(
    owner_id: &'a str,
    epoch: u64,
    credential_id: &'a [u8],
) -> Result<SubjectCredentialBindingV1<'a>, OwnerBridgeCodecError> {
    SubjectCredentialBindingV1::new(SubjectCredentialBindingInputV1 {
        owner_id,
        subject_id: SUBJECT_ID,
        epoch,
        credential_id,
        user_handle: USER_HANDLE,
        public_key: CoseEs256PublicKey::from_canonical_encoding(&cose_key())?,
        backup_eligible: false,
        backup_state: false,
        sign_count: 7,
        transports: TransportCodes::new(&[0])?,
    })
}

fn assert_binding_error(input: &[u8], expected: OwnerBridgeCodecError) {
    assert_eq!(decode_subject_credential_binding(input), Err(expected));
}

fn assert_cleanup_error(input: &[u8], expected: OwnerBridgeCodecError) {
    assert_eq!(decode_cleanup_record(input), Err(expected));
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
