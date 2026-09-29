use ciborium::value::Value;
use pos_core::{
    fork_authentication::{
        AuthenticatedPrincipalEvidenceV1, MAX_AUTHENTICATED_PRINCIPAL_EVIDENCE_BYTES_V1,
    },
    ForkAdmissionCommandCodecErrorV1, ForkAdmissionHostCommandV1, ForkAdmissionRecoveryCommandV1,
    ForkAdmissionRecoveryProofV1, ForkCreateCommandV1, PrincipalOwnerCommandV1,
    MAX_FORK_ADMISSION_HOST_COMMAND_BYTES_V1, MAX_FORK_ADMISSION_RECOVERY_COMMAND_BYTES_V1,
    MAX_FORK_ADMISSION_RECOVERY_PROOF_BYTES_V1, MAX_FORK_CREATE_COMMAND_BYTES_V1,
    MAX_PRINCIPAL_OWNER_COMMAND_BYTES_V1,
};
use sha2::{Digest, Sha256};

fn encode(value: &Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(&value, &mut bytes)?;
    Ok(bytes)
}

fn bytes(value: u8, length: usize) -> Value {
    Value::Bytes(vec![value; length])
}

fn maximum_poc1() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    encode(&Value::Array(vec![
        Value::Text("POC1".to_owned()),
        Value::Integer(1.into()),
        bytes(1, 32),
        bytes(2, 32),
        bytes(3, 32),
        bytes(4, 32),
        bytes(5, 32),
        Value::Text("o".repeat(128)),
    ]))
}

fn maximum_fcc1() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    encode(&Value::Array(vec![
        Value::Text("FCC1".to_owned()),
        Value::Integer(1.into()),
        bytes(0xff, 32),
        bytes(0xfe, 32),
        bytes(0xfd, 32),
        bytes(0xfc, 32),
        bytes(0xfb, 32),
        bytes(0xff, 16),
        Value::Integer(u64::MAX.into()),
        Value::Integer(u64::MAX.into()),
        bytes(0xfa, 32),
        bytes(0xf9, 32),
        Value::Integer(1.into()),
        Value::Text("c".repeat(128)),
    ]))
}

fn maximum_fae1() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    fae1(128, 255)
}

fn fae1(text_length: usize, assurance: u8) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let principal = encode(&Value::Array(vec![
        Value::Bytes(b"PRN1".to_vec()),
        Value::Integer(1.into()),
        bytes(0xff, 16),
        Value::Text("a".repeat(text_length)),
    ]))?;
    let record = encode(&Value::Array(vec![
        Value::Text("APR1".to_owned()),
        Value::Integer(1.into()),
        Value::Bytes(principal),
        Value::Text("b".repeat(text_length)),
        Value::Integer(assurance.into()),
        Value::Integer((u64::MAX - 1).into()),
        Value::Integer(u64::MAX.into()),
        bytes(0xff, 32),
        bytes(0xff, 32),
    ]))?;
    encode(&Value::Array(vec![
        Value::Text("FAE1".to_owned()),
        Value::Integer(1.into()),
        Value::Bytes(record),
        bytes(0xaa, 64),
    ]))
}

fn maximum_frc1() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    encode(&Value::Array(vec![
        Value::Text("FRC1".to_owned()),
        Value::Integer(1.into()),
        bytes(0xff, 32),
        bytes(0xfe, 32),
        Value::Integer(1.into()),
        bytes(0xfd, 32),
    ]))
}

fn small_poc1() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    encode(&Value::Array(vec![
        Value::Text("POC1".to_owned()),
        Value::Integer(1.into()),
        bytes(1, 32),
        bytes(2, 32),
        bytes(3, 32),
        bytes(4, 32),
        bytes(5, 32),
        Value::Text("owner".to_owned()),
    ]))
}

fn host_command(
    command: Vec<u8>,
    evidence: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    encode(&Value::Array(vec![
        Value::Text("FAC1".to_owned()),
        Value::Integer(1.into()),
        Value::Bytes(command),
        Value::Bytes(evidence),
        bytes(0xaa, 64),
    ]))
}

fn recovery_proof(
    command: Vec<u8>,
    signature: Value,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    encode(&Value::Array(vec![
        Value::Text("FRP1".to_owned()),
        Value::Integer(1.into()),
        Value::Bytes(command),
        signature,
    ]))
}

/// Replace one top-level field and re-encode canonically.
fn with_field(
    bytes: &[u8],
    index: usize,
    replacement: Value,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let value: Value = ciborium::from_reader(bytes)?;
    let Value::Array(mut fields) = value else {
        return Err("expected CBOR array".into());
    };
    fields[index] = replacement;
    encode(&Value::Array(fields))
}

/// Re-encode the version integer (byte 6 after a four-byte marker) in a
/// non-shortest form.
fn noncanonical_version(bytes: &[u8]) -> Vec<u8> {
    let mut noncanonical = bytes.to_vec();
    noncanonical.splice(6..7, [0x18, 1]);
    noncanonical
}

fn assert_one_byte_over<T>(
    bytes: Vec<u8>,
    decode: impl FnOnce(&[u8]) -> Result<T, ForkAdmissionCommandCodecErrorV1>,
) {
    let mut oversized = bytes;
    oversized.push(0);
    assert_eq!(
        decode(&oversized).err(),
        Some(ForkAdmissionCommandCodecErrorV1::FieldOutOfBounds)
    );
}

#[test]
fn principal_owner_command_maximum_literal_matches_adr_106_r2(
) -> Result<(), Box<dyn std::error::Error>> {
    let poc1 = maximum_poc1()?;
    assert_eq!(poc1.len(), MAX_PRINCIPAL_OWNER_COMMAND_BYTES_V1);
    assert_eq!(
        PrincipalOwnerCommandV1::from_canonical_cbor(&poc1)?.to_canonical_cbor(),
        poc1
    );
    assert_one_byte_over(poc1, PrincipalOwnerCommandV1::from_canonical_cbor);
    Ok(())
}

#[test]
fn fork_create_command_maximum_literal_matches_adr_106_r2() -> Result<(), Box<dyn std::error::Error>>
{
    let fcc1 = maximum_fcc1()?;
    assert_eq!(fcc1.len(), MAX_FORK_CREATE_COMMAND_BYTES_V1);
    assert_eq!(
        &fcc1[..8],
        &[0x8e, 0x64, b'F', b'C', b'C', b'1', 0x01, 0x58]
    );
    assert_eq!(
        &Sha256::digest(&fcc1)[..],
        &[
            0xa0, 0xad, 0x88, 0x22, 0x2b, 0x2a, 0x47, 0x45, 0x27, 0x10, 0x74, 0xbf, 0xfb, 0x47,
            0xb1, 0x80, 0x3c, 0x20, 0xda, 0xc9, 0x76, 0x75, 0x79, 0x91, 0x28, 0xb8, 0x33, 0x37,
            0xba, 0xdf, 0xa8, 0x6d,
        ]
    );
    assert_eq!(
        ForkCreateCommandV1::from_canonical_cbor(&fcc1)?.to_canonical_cbor(),
        fcc1
    );
    assert_one_byte_over(fcc1, ForkCreateCommandV1::from_canonical_cbor);
    Ok(())
}

#[test]
fn fork_admission_host_command_maximum_literal_matches_adr_106_r2(
) -> Result<(), Box<dyn std::error::Error>> {
    let fae1 = maximum_fae1()?;
    assert_eq!(fae1.len(), MAX_AUTHENTICATED_PRINCIPAL_EVIDENCE_BYTES_V1);
    assert_eq!(
        &fae1[..8],
        &[0x84, 0x64, b'F', b'A', b'E', b'1', 0x01, 0x59]
    );
    assert_eq!(
        &Sha256::digest(&fae1)[..],
        &[
            0x03, 0x81, 0x59, 0x78, 0xb5, 0xa2, 0xcd, 0xf7, 0x9f, 0x7f, 0xf9, 0x80, 0x91, 0x04,
            0xc8, 0x0a, 0x8f, 0x02, 0xbc, 0x90, 0x05, 0xdd, 0xba, 0xd8, 0x9e, 0x8c, 0x9e, 0xab,
            0xe0, 0x99, 0x65, 0xdc,
        ]
    );
    assert!(AuthenticatedPrincipalEvidenceV1::from_canonical_cbor(&fae1).is_ok());
    let expected_fae1 = fae1.clone();
    let expected_fcc1 = maximum_fcc1()?;
    let host_command = encode(&Value::Array(vec![
        Value::Text("FAC1".to_owned()),
        Value::Integer(1.into()),
        Value::Bytes(expected_fcc1.clone()),
        Value::Bytes(fae1),
        bytes(0xaa, 64),
    ]))?;
    assert_eq!(host_command.len(), MAX_FORK_ADMISSION_HOST_COMMAND_BYTES_V1);
    assert_eq!(
        &host_command[..8],
        &[0x85, 0x64, b'F', b'A', b'C', b'1', 0x01, 0x59]
    );
    assert_eq!(
        &Sha256::digest(&host_command)[..],
        &[
            0x80, 0xb6, 0xf8, 0xa8, 0xa4, 0xb4, 0xdc, 0xcf, 0xca, 0x03, 0x42, 0x61, 0x8e, 0x7c,
            0xb4, 0xa3, 0xaf, 0xd6, 0xa5, 0xf8, 0x5b, 0x09, 0xaa, 0x75, 0x35, 0x50, 0xb2, 0xb0,
            0x53, 0x36, 0x75, 0x09,
        ]
    );
    let parsed = ForkAdmissionHostCommandV1::from_canonical_cbor(&host_command)?;
    assert_eq!(parsed.to_canonical_cbor(), host_command);
    assert_eq!(parsed.command_bytes(), expected_fcc1);
    assert_eq!(parsed.evidence_bytes(), expected_fae1);
    assert_eq!(parsed.signature().as_bytes(), &[0xaa; 64]);
    assert_one_byte_over(
        host_command,
        ForkAdmissionHostCommandV1::from_canonical_cbor,
    );
    Ok(())
}

#[test]
fn fork_admission_recovery_command_maximum_literal_matches_adr_106_r2(
) -> Result<(), Box<dyn std::error::Error>> {
    let recovery_command = maximum_frc1()?;
    assert_eq!(
        recovery_command.len(),
        MAX_FORK_ADMISSION_RECOVERY_COMMAND_BYTES_V1
    );
    assert_eq!(
        &recovery_command[..8],
        &[0x86, 0x64, b'F', b'R', b'C', b'1', 0x01, 0x58]
    );
    assert_eq!(
        ForkAdmissionRecoveryCommandV1::from_canonical_cbor(&recovery_command)?.to_canonical_cbor(),
        recovery_command
    );
    assert_one_byte_over(
        recovery_command,
        ForkAdmissionRecoveryCommandV1::from_canonical_cbor,
    );
    Ok(())
}

#[test]
fn fork_admission_recovery_proof_maximum_literal_matches_adr_106_r2(
) -> Result<(), Box<dyn std::error::Error>> {
    let recovery_proof = encode(&Value::Array(vec![
        Value::Text("FRP1".to_owned()),
        Value::Integer(1.into()),
        Value::Bytes(maximum_frc1()?),
        bytes(0xaa, 64),
    ]))?;
    assert_eq!(
        recovery_proof.len(),
        MAX_FORK_ADMISSION_RECOVERY_PROOF_BYTES_V1
    );
    assert_eq!(
        &recovery_proof[..8],
        &[0x84, 0x64, b'F', b'R', b'P', b'1', 0x01, 0x58]
    );
    let parsed = ForkAdmissionRecoveryProofV1::from_canonical_cbor(&recovery_proof)?;
    assert_eq!(parsed.to_canonical_cbor(), recovery_proof);
    assert_eq!(parsed.command_bytes(), maximum_frc1()?);
    assert_eq!(parsed.signature().as_bytes(), &[0xaa; 64]);
    assert_one_byte_over(
        recovery_proof,
        ForkAdmissionRecoveryProofV1::from_canonical_cbor,
    );
    Ok(())
}

#[test]
fn command_codecs_fail_closed_for_malformed_public_fields() -> Result<(), Box<dyn std::error::Error>>
{
    let owner_command_with_zero_digest = encode(&Value::Array(vec![
        Value::Text("POC1".to_owned()),
        Value::Integer(1.into()),
        bytes(0, 32),
        bytes(2, 32),
        bytes(3, 32),
        bytes(4, 32),
        bytes(5, 32),
        Value::Text("owner".to_owned()),
    ]))?;
    assert_eq!(
        PrincipalOwnerCommandV1::from_canonical_cbor(&owner_command_with_zero_digest).err(),
        Some(ForkAdmissionCommandCodecErrorV1::FieldOutOfBounds)
    );

    let fork_command_with_mismatched_tick = encode(&Value::Array(vec![
        Value::Text("FCC1".to_owned()),
        Value::Integer(1.into()),
        bytes(1, 32),
        bytes(2, 32),
        bytes(3, 32),
        bytes(4, 32),
        bytes(5, 32),
        bytes(6, 16),
        Value::Integer(7.into()),
        Value::Integer(8.into()),
        bytes(9, 32),
        bytes(10, 32),
        Value::Integer(1.into()),
        Value::Text("child".to_owned()),
    ]))?;
    assert_eq!(
        ForkCreateCommandV1::from_canonical_cbor(&fork_command_with_mismatched_tick).err(),
        Some(ForkAdmissionCommandCodecErrorV1::FieldOutOfBounds)
    );

    let recovery_command_with_unknown_kind = encode(&Value::Array(vec![
        Value::Text("FRC1".to_owned()),
        Value::Integer(1.into()),
        bytes(1, 32),
        bytes(2, 32),
        Value::Integer(3.into()),
        bytes(3, 32),
    ]))?;
    assert_eq!(
        ForkAdmissionRecoveryCommandV1::from_canonical_cbor(&recovery_command_with_unknown_kind)
            .err(),
        Some(ForkAdmissionCommandCodecErrorV1::FieldOutOfBounds)
    );

    let unsupported_poc1 = encode(&Value::Array(vec![
        Value::Text("POC1".to_owned()),
        Value::Integer(2.into()),
        bytes(1, 32),
        bytes(2, 32),
        bytes(3, 32),
        bytes(4, 32),
        bytes(5, 32),
        Value::Text("owner".to_owned()),
    ]))?;
    assert_eq!(
        PrincipalOwnerCommandV1::from_canonical_cbor(&unsupported_poc1).err(),
        Some(ForkAdmissionCommandCodecErrorV1::UnsupportedVersion)
    );
    assert_eq!(
        ForkCreateCommandV1::from_canonical_cbor(&encode(&Value::Text("FCC1".to_owned()))?).err(),
        Some(ForkAdmissionCommandCodecErrorV1::InvalidEncoding)
    );

    let invalid_host_command = encode(&Value::Array(vec![
        Value::Text("FAC1".to_owned()),
        Value::Integer(1.into()),
        Value::Bytes(encode(&Value::Text("not-a-command".to_owned()))?),
        Value::Bytes(maximum_fae1()?),
        bytes(0xaa, 64),
    ]))?;
    assert_eq!(
        ForkAdmissionHostCommandV1::from_canonical_cbor(&invalid_host_command).err(),
        Some(ForkAdmissionCommandCodecErrorV1::InvalidEncoding)
    );

    let mut invalid_recovery_command = maximum_frc1()?;
    invalid_recovery_command[2] = b'X';
    let invalid_recovery_proof = encode(&Value::Array(vec![
        Value::Text("FRP1".to_owned()),
        Value::Integer(1.into()),
        Value::Bytes(invalid_recovery_command),
        bytes(0xaa, 64),
    ]))?;
    assert_eq!(
        ForkAdmissionRecoveryProofV1::from_canonical_cbor(&invalid_recovery_proof).err(),
        Some(ForkAdmissionCommandCodecErrorV1::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn signed_command_envelopes_reject_malformed_public_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let valid_command = maximum_fcc1()?;
    let valid_evidence = maximum_fae1()?;
    let valid_recovery = maximum_frc1()?;

    for envelope in [
        encode(&Value::Array(vec![
            Value::Text("FAC1".to_owned()),
            Value::Integer(1.into()),
            Value::Text("not-a-command".to_owned()),
            Value::Bytes(valid_evidence.clone()),
            bytes(0xaa, 64),
        ]))?,
        encode(&Value::Array(vec![
            Value::Text("FAC1".to_owned()),
            Value::Integer(1.into()),
            Value::Bytes(valid_command.clone()),
            Value::Text("not-evidence".to_owned()),
            bytes(0xaa, 64),
        ]))?,
        encode(&Value::Array(vec![
            Value::Text("FAC1".to_owned()),
            Value::Integer(1.into()),
            Value::Bytes(valid_command.clone()),
            Value::Bytes(valid_evidence.clone()),
            Value::Integer(1.into()),
        ]))?,
        encode(&Value::Array(vec![
            Value::Text("FAC1".to_owned()),
            Value::Integer(1.into()),
            Value::Bytes(valid_command),
            Value::Bytes(valid_evidence),
            bytes(0xaa, 63),
        ]))?,
    ] {
        assert_eq!(
            ForkAdmissionHostCommandV1::from_canonical_cbor(&envelope).err(),
            Some(ForkAdmissionCommandCodecErrorV1::FieldOutOfBounds)
        );
    }

    for envelope in [
        encode(&Value::Array(vec![
            Value::Text("FRP1".to_owned()),
            Value::Integer(1.into()),
            Value::Text("not-a-recovery-command".to_owned()),
            bytes(0xaa, 64),
        ]))?,
        recovery_proof(valid_recovery.clone(), Value::Integer(1.into()))?,
        recovery_proof(valid_recovery, bytes(0xaa, 63))?,
    ] {
        assert_eq!(
            ForkAdmissionRecoveryProofV1::from_canonical_cbor(&envelope).err(),
            Some(ForkAdmissionCommandCodecErrorV1::FieldOutOfBounds)
        );
    }
    Ok(())
}

#[test]
fn command_codecs_reject_noninteger_versions_and_invalid_cbor(
) -> Result<(), Box<dyn std::error::Error>> {
    let unexpected_version = encode(&Value::Array(vec![
        Value::Text("POC1".to_owned()),
        Value::Text("one".to_owned()),
        bytes(1, 32),
        bytes(2, 32),
        bytes(3, 32),
        bytes(4, 32),
        bytes(5, 32),
        Value::Text("owner".to_owned()),
    ]))?;
    assert_eq!(
        PrincipalOwnerCommandV1::from_canonical_cbor(&unexpected_version).err(),
        Some(ForkAdmissionCommandCodecErrorV1::InvalidEncoding)
    );
    assert_eq!(
        PrincipalOwnerCommandV1::from_canonical_cbor(&[0xff]).err(),
        Some(ForkAdmissionCommandCodecErrorV1::InvalidEncoding)
    );

    let mut command_with_trailing_data = encode(&Value::Array(vec![
        Value::Text("POC1".to_owned()),
        Value::Integer(1.into()),
        bytes(1, 32),
        bytes(2, 32),
        bytes(3, 32),
        bytes(4, 32),
        bytes(5, 32),
        Value::Text("owner".to_owned()),
    ]))?;
    command_with_trailing_data.push(0);
    assert_eq!(
        PrincipalOwnerCommandV1::from_canonical_cbor(&command_with_trailing_data).err(),
        Some(ForkAdmissionCommandCodecErrorV1::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn command_codecs_reject_noncanonical_version_encodings() -> Result<(), Box<dyn std::error::Error>>
{
    assert_eq!(
        PrincipalOwnerCommandV1::from_canonical_cbor(&noncanonical_version(&small_poc1()?)).err(),
        Some(ForkAdmissionCommandCodecErrorV1::NonCanonical)
    );
    let valid_host_command = host_command(small_poc1()?, fae1(1, 255)?)?;
    assert!(ForkAdmissionHostCommandV1::from_canonical_cbor(&valid_host_command).is_ok());
    assert_eq!(
        ForkAdmissionHostCommandV1::from_canonical_cbor(&noncanonical_version(&valid_host_command))
            .err(),
        Some(ForkAdmissionCommandCodecErrorV1::NonCanonical)
    );
    // Every valid FRP1 is exactly the maximum, so the noncanonical form uses a
    // short signature to stay within bounds; canonical form is checked first.
    let short_proof = recovery_proof(maximum_frc1()?, bytes(0xaa, 63))?;
    assert_eq!(
        ForkAdmissionRecoveryProofV1::from_canonical_cbor(&noncanonical_version(&short_proof))
            .err(),
        Some(ForkAdmissionCommandCodecErrorV1::NonCanonical)
    );
    Ok(())
}

#[test]
fn recovery_command_garbage_matches_other_command_codecs() {
    for garbage in [&[0xff][..], &[][..], &[0x80][..]] {
        assert_eq!(
            ForkAdmissionRecoveryCommandV1::from_canonical_cbor(garbage).err(),
            PrincipalOwnerCommandV1::from_canonical_cbor(garbage).err()
        );
        assert_eq!(
            ForkAdmissionRecoveryCommandV1::from_canonical_cbor(garbage).err(),
            Some(ForkAdmissionCommandCodecErrorV1::InvalidEncoding)
        );
    }
}

#[test]
fn signed_envelopes_propagate_enclosed_command_errors() -> Result<(), Box<dyn std::error::Error>> {
    let evidence = fae1(1, 255)?;
    let poc1 = small_poc1()?;
    for (command, expected) in [
        (
            with_field(&poc1, 2, bytes(0, 32))?,
            ForkAdmissionCommandCodecErrorV1::FieldOutOfBounds,
        ),
        (
            with_field(&poc1, 1, Value::Integer(2.into()))?,
            ForkAdmissionCommandCodecErrorV1::UnsupportedVersion,
        ),
        (
            noncanonical_version(&poc1),
            ForkAdmissionCommandCodecErrorV1::NonCanonical,
        ),
        (
            with_field(&maximum_fcc1()?, 9, Value::Integer(7.into()))?,
            ForkAdmissionCommandCodecErrorV1::FieldOutOfBounds,
        ),
        (
            with_field(&maximum_fcc1()?, 1, Value::Integer(2.into()))?,
            ForkAdmissionCommandCodecErrorV1::UnsupportedVersion,
        ),
        (
            vec![0xff],
            ForkAdmissionCommandCodecErrorV1::InvalidEncoding,
        ),
    ] {
        assert_eq!(
            ForkAdmissionHostCommandV1::from_canonical_cbor(&host_command(
                command,
                evidence.clone()
            )?)
            .err(),
            Some(expected)
        );
    }

    let frc1 = maximum_frc1()?;
    for (command, expected) in [
        (
            with_field(&frc1, 4, Value::Integer(3.into()))?,
            ForkAdmissionCommandCodecErrorV1::FieldOutOfBounds,
        ),
        (
            with_field(&frc1, 1, Value::Integer(2.into()))?,
            ForkAdmissionCommandCodecErrorV1::UnsupportedVersion,
        ),
        (
            vec![0xff],
            ForkAdmissionCommandCodecErrorV1::InvalidEncoding,
        ),
    ] {
        assert_eq!(
            ForkAdmissionRecoveryProofV1::from_canonical_cbor(&recovery_proof(
                command,
                bytes(0xaa, 64)
            )?)
            .err(),
            Some(expected)
        );
    }
    Ok(())
}

#[test]
fn host_command_propagates_enclosed_evidence_errors() -> Result<(), Box<dyn std::error::Error>> {
    let evidence = fae1(1, 255)?;
    for (evidence, expected) in [
        (
            vec![0xff],
            ForkAdmissionCommandCodecErrorV1::InvalidEncoding,
        ),
        (
            noncanonical_version(&evidence),
            ForkAdmissionCommandCodecErrorV1::NonCanonical,
        ),
        (
            with_field(&evidence, 1, Value::Integer(2.into()))?,
            ForkAdmissionCommandCodecErrorV1::UnsupportedVersion,
        ),
        (
            fae1(1, 0)?,
            ForkAdmissionCommandCodecErrorV1::FieldOutOfBounds,
        ),
    ] {
        assert_eq!(
            ForkAdmissionHostCommandV1::from_canonical_cbor(&host_command(
                small_poc1()?,
                evidence
            )?)
            .err(),
            Some(expected)
        );
    }
    Ok(())
}
