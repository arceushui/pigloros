//! Exact ephemeral ADR-106 Fork-admission command envelopes.
//!
//! Decoding proves deterministic-CBOR structure only. The trusted host proof
//! must be verified under the pinned host key before a store uses a value.

use std::io::Cursor;

use ciborium::value::Value;

use crate::{
    fork_authentication::{
        AuthenticatedPrincipalEvidenceV1, ForkAuthenticationCodecErrorV1,
        MAX_AUTHENTICATED_PRINCIPAL_EVIDENCE_BYTES_V1,
    },
    OwnerIdV1, Signature,
};

/// Largest complete canonical POC1 size.
pub const MAX_PRINCIPAL_OWNER_COMMAND_BYTES_V1: usize = 307;
/// Largest complete canonical FCC1 size.
pub const MAX_FORK_CREATE_COMMAND_BYTES_V1: usize = 411;
/// Largest complete canonical FAC1 size.
pub const MAX_FORK_ADMISSION_HOST_COMMAND_BYTES_V1: usize = 947;
/// Exact complete canonical FRC1 size.
pub const MAX_FORK_ADMISSION_RECOVERY_COMMAND_BYTES_V1: usize = 110;
/// Exact complete canonical FRP1 size.
pub const MAX_FORK_ADMISSION_RECOVERY_PROOF_BYTES_V1: usize = 185;

/// Closed decode failures for POC1, FCC1, FAC1, FRC1, and FRP1 envelopes.
///
/// Signed envelopes propagate the failure of their enclosed command or
/// evidence instead of collapsing it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ForkAdmissionCommandCodecErrorV1 {
    #[error("invalid Fork admission command encoding")]
    InvalidEncoding,
    #[error("noncanonical Fork admission command encoding")]
    NonCanonical,
    #[error("unsupported Fork admission command version")]
    UnsupportedVersion,
    #[error("Fork admission command field is out of bounds")]
    FieldOutOfBounds,
}

/// Opaque canonical POC1 principal-to-Owner command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalOwnerCommandV1(Vec<u8>);

impl PrincipalOwnerCommandV1 {
    /// # Errors
    ///
    /// Returns a closed codec error when the envelope is malformed,
    /// noncanonical, or contains an out-of-bounds field.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ForkAdmissionCommandCodecErrorV1> {
        validate_poc1(bytes)?;
        Ok(Self(bytes.to_vec()))
    }

    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        self.0.clone()
    }
}

/// Opaque canonical FCC1 Fork-creation command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkCreateCommandV1(Vec<u8>);

impl ForkCreateCommandV1 {
    /// # Errors
    ///
    /// Returns a closed codec error when the envelope is malformed,
    /// noncanonical, or contains an out-of-bounds field.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ForkAdmissionCommandCodecErrorV1> {
        validate_fcc1(bytes)?;
        Ok(Self(bytes.to_vec()))
    }

    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        self.0.clone()
    }
}

/// Opaque canonical FRC1 lookup-only recovery command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkAdmissionRecoveryCommandV1(Vec<u8>);

impl ForkAdmissionRecoveryCommandV1 {
    /// # Errors
    ///
    /// Returns a closed codec error when the envelope is malformed,
    /// noncanonical, or contains an out-of-bounds field.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ForkAdmissionCommandCodecErrorV1> {
        validate_frc1(bytes)?;
        Ok(Self(bytes.to_vec()))
    }

    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        self.0.clone()
    }
}

/// Opaque signed FAC1. A decoded value remains unauthorised until its host
/// signature is verified with the durable FAH1 host key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkAdmissionHostCommandV1 {
    canonical: Vec<u8>,
    command: Vec<u8>,
    evidence: Vec<u8>,
    signature: Signature,
}

impl ForkAdmissionHostCommandV1 {
    /// # Errors
    ///
    /// Returns a closed codec error when the envelope is malformed,
    /// noncanonical, or contains an out-of-bounds field.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ForkAdmissionCommandCodecErrorV1> {
        let fields = decode_envelope(bytes, MAX_FORK_ADMISSION_HOST_COMMAND_BYTES_V1, "FAC1", 5)?;
        let command = bounded_bytes(&fields[2], MAX_FORK_CREATE_COMMAND_BYTES_V1)?;
        validate_host_command(command)?;
        let evidence = bounded_bytes(&fields[3], MAX_AUTHENTICATED_PRINCIPAL_EVIDENCE_BYTES_V1)?;
        AuthenticatedPrincipalEvidenceV1::from_canonical_cbor(evidence).map_err(evidence_error)?;
        let signature = Signature::from_bytes(fixed::<64>(&fields[4])?);
        Ok(Self {
            canonical: bytes.to_vec(),
            command: command.to_vec(),
            evidence: evidence.to_vec(),
            signature,
        })
    }

    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        self.canonical.clone()
    }

    /// Return the validated enclosed POC1 or FCC1 bytes.
    #[must_use]
    pub fn command_bytes(&self) -> Vec<u8> {
        self.command.clone()
    }

    /// Return the validated enclosed FAE1 bytes.
    #[must_use]
    pub fn evidence_bytes(&self) -> Vec<u8> {
        self.evidence.clone()
    }

    /// Return the validated FAC1 signature.
    #[must_use]
    pub const fn signature(&self) -> Signature {
        self.signature
    }
}

/// Opaque signed FRP1 lookup-only recovery proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkAdmissionRecoveryProofV1 {
    canonical: Vec<u8>,
    command: Vec<u8>,
    signature: Signature,
}

impl ForkAdmissionRecoveryProofV1 {
    /// # Errors
    ///
    /// Returns a closed codec error when the envelope is malformed,
    /// noncanonical, or contains an out-of-bounds field.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ForkAdmissionCommandCodecErrorV1> {
        let fields = decode_envelope(bytes, MAX_FORK_ADMISSION_RECOVERY_PROOF_BYTES_V1, "FRP1", 4)?;
        let command = bounded_bytes(&fields[2], MAX_FORK_ADMISSION_RECOVERY_COMMAND_BYTES_V1)?;
        ForkAdmissionRecoveryCommandV1::from_canonical_cbor(command)?;
        let signature = Signature::from_bytes(fixed::<64>(&fields[3])?);
        Ok(Self {
            canonical: bytes.to_vec(),
            command: command.to_vec(),
            signature,
        })
    }

    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        self.canonical.clone()
    }

    /// Return the validated enclosed FRC1 bytes.
    #[must_use]
    pub fn command_bytes(&self) -> Vec<u8> {
        self.command.clone()
    }

    /// Return the validated FRP1 signature.
    #[must_use]
    pub const fn signature(&self) -> Signature {
        self.signature
    }
}

/// Accept exactly one enclosed POC1 or FCC1, reporting the failure of the
/// command whose marker matched.
fn validate_host_command(bytes: &[u8]) -> Result<(), ForkAdmissionCommandCodecErrorV1> {
    validate_poc1(bytes).or_else(|principal_owner| {
        validate_fcc1(bytes).map_err(|fork_create| {
            if fork_create == ForkAdmissionCommandCodecErrorV1::InvalidEncoding {
                principal_owner
            } else {
                fork_create
            }
        })
    })
}

const fn evidence_error(error: ForkAuthenticationCodecErrorV1) -> ForkAdmissionCommandCodecErrorV1 {
    match error {
        ForkAuthenticationCodecErrorV1::InvalidEncoding => {
            ForkAdmissionCommandCodecErrorV1::InvalidEncoding
        }
        ForkAuthenticationCodecErrorV1::NonCanonical => {
            ForkAdmissionCommandCodecErrorV1::NonCanonical
        }
        ForkAuthenticationCodecErrorV1::UnsupportedVersion => {
            ForkAdmissionCommandCodecErrorV1::UnsupportedVersion
        }
        ForkAuthenticationCodecErrorV1::FieldOutOfBounds
        | ForkAuthenticationCodecErrorV1::FieldMismatch => {
            ForkAdmissionCommandCodecErrorV1::FieldOutOfBounds
        }
    }
}

fn validate_poc1(bytes: &[u8]) -> Result<(), ForkAdmissionCommandCodecErrorV1> {
    let fields = decode_envelope(bytes, MAX_PRINCIPAL_OWNER_COMMAND_BYTES_V1, "POC1", 8)?;
    if fields[2..7].iter().all(nonzero_32)
        && matches!(&fields[7], Value::Text(owner) if OwnerIdV1::new(owner).is_ok())
    {
        Ok(())
    } else {
        Err(ForkAdmissionCommandCodecErrorV1::FieldOutOfBounds)
    }
}

fn validate_fcc1(bytes: &[u8]) -> Result<(), ForkAdmissionCommandCodecErrorV1> {
    let fields = decode_envelope(bytes, MAX_FORK_CREATE_COMMAND_BYTES_V1, "FCC1", 14)?;
    if fields[2..7].iter().all(nonzero_32)
        && matches!(&fields[7], Value::Bytes(value) if value.len() == 16)
        && matches!((&fields[8], &fields[9]), (Value::Integer(fold), Value::Integer(tick)) if fold == tick && u64::try_from(*fold).is_ok())
        && nonzero_32(&fields[10])
        && nonzero_32(&fields[11])
        && matches!(&fields[12], Value::Integer(value) if *value == 0.into() || *value == 1.into())
        && matches!(&fields[13], Value::Text(name) if valid_text(name))
    {
        Ok(())
    } else {
        Err(ForkAdmissionCommandCodecErrorV1::FieldOutOfBounds)
    }
}

/// Canonical encoding plus the fixed-width field checks imply the exact FRC1
/// size, so no separate length check is needed.
fn validate_frc1(bytes: &[u8]) -> Result<(), ForkAdmissionCommandCodecErrorV1> {
    let fields = decode_envelope(
        bytes,
        MAX_FORK_ADMISSION_RECOVERY_COMMAND_BYTES_V1,
        "FRC1",
        6,
    )?;
    if fields[2..4].iter().all(nonzero_32)
        && matches!(&fields[4], Value::Integer(kind) if *kind == 1.into() || *kind == 2.into())
        && nonzero_32(&fields[5])
    {
        Ok(())
    } else {
        Err(ForkAdmissionCommandCodecErrorV1::FieldOutOfBounds)
    }
}

fn decode_envelope(
    bytes: &[u8],
    maximum: usize,
    marker: &str,
    count: usize,
) -> Result<Vec<Value>, ForkAdmissionCommandCodecErrorV1> {
    let value = decode(bytes, maximum)?;
    let Value::Array(fields) = value else {
        return Err(ForkAdmissionCommandCodecErrorV1::InvalidEncoding);
    };
    if fields.len() != count
        || !matches!(fields.first(), Some(Value::Text(value)) if value == marker)
    {
        return Err(ForkAdmissionCommandCodecErrorV1::InvalidEncoding);
    }
    match fields.get(1) {
        Some(Value::Integer(version)) if *version == 1.into() => Ok(fields),
        Some(Value::Integer(_)) => Err(ForkAdmissionCommandCodecErrorV1::UnsupportedVersion),
        _ => Err(ForkAdmissionCommandCodecErrorV1::InvalidEncoding),
    }
}

fn decode(bytes: &[u8], maximum: usize) -> Result<Value, ForkAdmissionCommandCodecErrorV1> {
    if bytes.len() > maximum {
        return Err(ForkAdmissionCommandCodecErrorV1::FieldOutOfBounds);
    }
    let mut cursor = Cursor::new(bytes);
    let value: Value = ciborium::from_reader(&mut cursor)
        .map_err(|_| ForkAdmissionCommandCodecErrorV1::InvalidEncoding)?;
    if cursor.position() != bytes.len() as u64 {
        return Err(ForkAdmissionCommandCodecErrorV1::InvalidEncoding);
    }
    let mut canonical = Vec::new();
    if ciborium::into_writer(&value, &mut canonical).is_ok_and(|()| canonical == bytes) {
        Ok(value)
    } else {
        Err(ForkAdmissionCommandCodecErrorV1::NonCanonical)
    }
}

fn bounded_bytes(value: &Value, maximum: usize) -> Result<&[u8], ForkAdmissionCommandCodecErrorV1> {
    match value {
        Value::Bytes(value) if !value.is_empty() && value.len() <= maximum => Ok(value),
        _ => Err(ForkAdmissionCommandCodecErrorV1::FieldOutOfBounds),
    }
}

fn fixed<const N: usize>(value: &Value) -> Result<[u8; N], ForkAdmissionCommandCodecErrorV1> {
    match value {
        Value::Bytes(value) => value
            .as_slice()
            .try_into()
            .map_err(|_| ForkAdmissionCommandCodecErrorV1::FieldOutOfBounds),
        _ => Err(ForkAdmissionCommandCodecErrorV1::FieldOutOfBounds),
    }
}

fn nonzero_32(value: &Value) -> bool {
    matches!(value, Value::Bytes(value) if value.len() == 32 && value.iter().any(|byte| *byte != 0))
}
fn valid_text(value: &str) -> bool {
    (1..=128).contains(&value.len()) && !value.contains('\0')
}
