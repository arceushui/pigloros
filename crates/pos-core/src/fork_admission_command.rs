//! Exact ephemeral ADR-106 Fork-admission command envelopes.
//!
//! Decoding proves deterministic-CBOR structure only. The trusted host proof
//! must be verified under the pinned host key before a store uses a value.

use std::io::Cursor;

use ciborium::value::Value;

use crate::{
    fork_admission::{digest, ForkAdmissionOperationKindV1},
    fork_authentication::{
        AuthenticatedPrincipalEvidenceV1, ForkAuthenticationCodecErrorV1,
        MAX_AUTHENTICATED_PRINCIPAL_EVIDENCE_BYTES_V1,
    },
    Hash, OwnerIdV1, Signature, TimelineId,
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

const PRINCIPAL_OWNER_COMMITMENT_DOMAIN: &[u8] = b"pigloros/principal-owner-command/v1";
const FORK_CREATE_COMMITMENT_DOMAIN: &[u8] = b"pigloros/fork-create-command/v1";

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

/// Immutable facts carried by a canonical POC1 or FCC1 payload.
///
/// This is plain public data: any caller can construct a value, and a value
/// is never authority on its own. Facts returned by
/// [`ForkAdmissionHostCommandV1::validated_command_facts`] have passed the
/// strict codec, while FAC1 host-signature and FAE1 evidence verification
/// remain the authority boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ForkAdmissionCommandFactsV1 {
    /// Facts from a POC1 principal-to-Owner command.
    PrincipalOwner {
        store_id: Hash,
        session_identity: Hash,
        operation_id: Hash,
        evidence_digest: Hash,
        principal_digest: Hash,
        owner: OwnerIdV1,
    },
    /// Facts from an FCC1 Fork-creation command.
    Fork {
        store_id: Hash,
        session_identity: Hash,
        operation_id: Hash,
        evidence_digest: Hash,
        principal_digest: Hash,
        parent_id: TimelineId,
        cut: u64,
        descriptor_hash: Hash,
        composition_hash: Hash,
        attribution_required: bool,
        child_name: String,
    },
}

impl ForkAdmissionCommandFactsV1 {
    /// Return the FCC1 operation ID and parent, or `None` for a POC1.
    #[must_use]
    pub const fn fork_target(&self) -> Option<(Hash, TimelineId)> {
        match self {
            Self::PrincipalOwner { .. } => None,
            Self::Fork {
                operation_id,
                parent_id,
                ..
            } => Some((*operation_id, *parent_id)),
        }
    }

    /// Return the durable ADR-106 operation commitment for these facts.
    ///
    /// The session identity is excluded, so the value survives reopen.
    #[must_use]
    pub fn commitment(&self) -> Hash {
        match self {
            Self::PrincipalOwner {
                store_id,
                operation_id,
                evidence_digest,
                principal_digest,
                owner,
                ..
            } => PrincipalOwnerCommitmentInputV1 {
                store_id: *store_id,
                operation_id: *operation_id,
                evidence_digest: *evidence_digest,
                principal_digest: *principal_digest,
                owner: *owner,
            }
            .commitment(),
            Self::Fork {
                store_id,
                operation_id,
                evidence_digest,
                principal_digest,
                parent_id,
                cut,
                descriptor_hash,
                composition_hash,
                attribution_required,
                child_name,
                ..
            } => ForkCreateCommitmentInputV1 {
                store_id: *store_id,
                operation_id: *operation_id,
                evidence_digest: *evidence_digest,
                principal_digest: *principal_digest,
                parent_id: *parent_id,
                cut: *cut,
                descriptor_hash: *descriptor_hash,
                composition_hash: *composition_hash,
                attribution_required: *attribution_required,
                child_name,
            }
            .commitment(),
        }
    }
}

/// Durable POC1 fields bound by the ADR-106 POB1 operation commitment.
///
/// These are POC1 field 2 and fields 4 through 7. Both the command path and
/// durable recovery derive the commitment through this one encoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrincipalOwnerCommitmentInputV1 {
    /// FAH1 store identity (field 2).
    pub store_id: Hash,
    /// POB1 operation identity (field 4).
    pub operation_id: Hash,
    /// FAE1 evidence digest (field 5).
    pub evidence_digest: Hash,
    /// `PrincipalRefV1` digest (field 6).
    pub principal_digest: Hash,
    /// Trusted resolver Owner (field 7).
    pub owner: OwnerIdV1,
}

impl PrincipalOwnerCommitmentInputV1 {
    /// Return `BLAKE3("pigloros/principal-owner-command/v1" || canonical array)`.
    #[must_use]
    pub fn commitment(&self) -> Hash {
        digest(
            PRINCIPAL_OWNER_COMMITMENT_DOMAIN,
            &canonical_bytes(&Value::Array(vec![
                hash_value(self.store_id),
                hash_value(self.operation_id),
                hash_value(self.evidence_digest),
                hash_value(self.principal_digest),
                Value::Text(self.owner.as_str().to_owned()),
            ])),
        )
    }
}

/// Durable FCC1 fields bound by the ADR-106 FAR1 operation commitment.
///
/// These are FCC1 field 2 and fields 4 through 13. The expected completed
/// Fold Cursor and post-fold Tick Boundary are both `cut`. Both the command
/// path and durable recovery derive the commitment through this one encoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkCreateCommitmentInputV1<'a> {
    /// FAH1 store identity (field 2).
    pub store_id: Hash,
    /// FAR1 operation identity (field 4).
    pub operation_id: Hash,
    /// FAE1 evidence digest (field 5).
    pub evidence_digest: Hash,
    /// `PrincipalRefV1` digest (field 6).
    pub principal_digest: Hash,
    /// Parent Timeline (field 7).
    pub parent_id: TimelineId,
    /// Completed Fold Cursor and post-fold Tick Boundary (fields 8 and 9).
    pub cut: u64,
    /// Room revision descriptor hash (field 10).
    pub descriptor_hash: Hash,
    /// Plugin composition hash (field 11).
    pub composition_hash: Hash,
    /// Attribution requirement (field 12).
    pub attribution_required: bool,
    /// Child Fork name (field 13).
    pub child_name: &'a str,
}

impl ForkCreateCommitmentInputV1<'_> {
    /// Return `BLAKE3("pigloros/fork-create-command/v1" || canonical array)`.
    #[must_use]
    pub fn commitment(&self) -> Hash {
        digest(
            FORK_CREATE_COMMITMENT_DOMAIN,
            &canonical_bytes(&Value::Array(vec![
                hash_value(self.store_id),
                hash_value(self.operation_id),
                hash_value(self.evidence_digest),
                hash_value(self.principal_digest),
                Value::Bytes(self.parent_id.inner().to_bytes().to_vec()),
                Value::Integer(self.cut.into()),
                Value::Integer(self.cut.into()),
                hash_value(self.descriptor_hash),
                hash_value(self.composition_hash),
                Value::Integer(u8::from(self.attribution_required).into()),
                Value::Text(self.child_name.to_owned()),
            ])),
        )
    }
}

/// Immutable facts decoded from a canonical FRC1 lookup command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkAdmissionRecoveryCommandFactsV1 {
    /// FAH1 store identity (field 2).
    pub store_id: Hash,
    /// Current authority session identity (field 3).
    pub session_identity: Hash,
    /// Operation kind (field 4).
    pub kind: ForkAdmissionOperationKindV1,
    /// Exact operation identity (field 5).
    pub operation_id: Hash,
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
        validate_poc1(bytes).map(|_| Self(bytes.to_vec()))
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
        validate_fcc1(bytes).map(|_| Self(bytes.to_vec()))
    }

    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        self.0.clone()
    }
}

/// Opaque canonical FRC1 lookup-only recovery command.
#[derive(Clone, Debug)]
pub struct ForkAdmissionRecoveryCommandV1(Vec<u8>, ForkAdmissionRecoveryCommandFactsV1);

impl PartialEq for ForkAdmissionRecoveryCommandV1 {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for ForkAdmissionRecoveryCommandV1 {}

impl ForkAdmissionRecoveryCommandV1 {
    /// # Errors
    ///
    /// Returns a closed codec error when the envelope is malformed,
    /// noncanonical, or contains an out-of-bounds field.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ForkAdmissionCommandCodecErrorV1> {
        let facts = validate_frc1(bytes)?;
        Ok(Self(bytes.to_vec(), facts))
    }

    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        self.0.clone()
    }

    const fn facts(&self) -> ForkAdmissionRecoveryCommandFactsV1 {
        self.1
    }
}

/// Opaque signed FAC1. A decoded value remains unauthorised until its host
/// signature is verified with the durable FAH1 host key.
#[derive(Clone, Debug)]
pub struct ForkAdmissionHostCommandV1 {
    canonical: Vec<u8>,
    command: Vec<u8>,
    evidence: Vec<u8>,
    signature: Signature,
    validated_command_facts: ForkAdmissionCommandFactsV1,
}

impl PartialEq for ForkAdmissionHostCommandV1 {
    fn eq(&self, other: &Self) -> bool {
        self.canonical == other.canonical
    }
}

impl Eq for ForkAdmissionHostCommandV1 {}

impl ForkAdmissionHostCommandV1 {
    /// # Errors
    ///
    /// Returns a closed codec error when the envelope is malformed,
    /// noncanonical, or contains an out-of-bounds field.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ForkAdmissionCommandCodecErrorV1> {
        let fields = decode_envelope(bytes, MAX_FORK_ADMISSION_HOST_COMMAND_BYTES_V1, "FAC1", 5)?;
        let command = bounded_bytes(&fields[2], MAX_FORK_CREATE_COMMAND_BYTES_V1)?;
        let validated_command_facts = validate_host_command(command)?;
        let evidence = bounded_bytes(&fields[3], MAX_AUTHENTICATED_PRINCIPAL_EVIDENCE_BYTES_V1)?;
        AuthenticatedPrincipalEvidenceV1::from_canonical_cbor(evidence).map_err(evidence_error)?;
        let signature = Signature::from_bytes(fixed::<64>(&fields[4])?);
        Ok(Self {
            canonical: bytes.to_vec(),
            command: command.to_vec(),
            evidence: evidence.to_vec(),
            signature,
            validated_command_facts,
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

    /// Return the codec-validated POC1 or FCC1 facts.
    #[must_use]
    pub const fn validated_command_facts(&self) -> &ForkAdmissionCommandFactsV1 {
        &self.validated_command_facts
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
#[derive(Clone, Debug)]
pub struct ForkAdmissionRecoveryProofV1 {
    canonical: Vec<u8>,
    command: Vec<u8>,
    signature: Signature,
    validated_command_facts: ForkAdmissionRecoveryCommandFactsV1,
}

impl PartialEq for ForkAdmissionRecoveryProofV1 {
    fn eq(&self, other: &Self) -> bool {
        self.canonical == other.canonical
    }
}

impl Eq for ForkAdmissionRecoveryProofV1 {}

impl ForkAdmissionRecoveryProofV1 {
    /// # Errors
    ///
    /// Returns a closed codec error when the envelope is malformed,
    /// noncanonical, or contains an out-of-bounds field.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ForkAdmissionCommandCodecErrorV1> {
        let fields = decode_envelope(bytes, MAX_FORK_ADMISSION_RECOVERY_PROOF_BYTES_V1, "FRP1", 4)?;
        let command = bounded_bytes(&fields[2], MAX_FORK_ADMISSION_RECOVERY_COMMAND_BYTES_V1)?;
        let validated_command_facts =
            ForkAdmissionRecoveryCommandV1::from_canonical_cbor(command)?.facts();
        let signature = Signature::from_bytes(fixed::<64>(&fields[3])?);
        Ok(Self {
            canonical: bytes.to_vec(),
            command: command.to_vec(),
            signature,
            validated_command_facts,
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

    /// Return the codec-validated FRC1 facts.
    #[must_use]
    pub const fn validated_command_facts(&self) -> ForkAdmissionRecoveryCommandFactsV1 {
        self.validated_command_facts
    }

    /// Return the validated FRP1 signature.
    #[must_use]
    pub const fn signature(&self) -> Signature {
        self.signature
    }
}

/// Accept exactly one enclosed POC1 or FCC1, reporting the failure of the
/// command whose marker matched.
fn validate_host_command(
    bytes: &[u8],
) -> Result<ForkAdmissionCommandFactsV1, ForkAdmissionCommandCodecErrorV1> {
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

fn validate_poc1(
    bytes: &[u8],
) -> Result<ForkAdmissionCommandFactsV1, ForkAdmissionCommandCodecErrorV1> {
    let fields = decode_envelope(bytes, MAX_PRINCIPAL_OWNER_COMMAND_BYTES_V1, "POC1", 8)?;
    Ok(ForkAdmissionCommandFactsV1::PrincipalOwner {
        store_id: nonzero_hash(&fields[2])?,
        session_identity: nonzero_hash(&fields[3])?,
        operation_id: nonzero_hash(&fields[4])?,
        evidence_digest: nonzero_hash(&fields[5])?,
        principal_digest: nonzero_hash(&fields[6])?,
        owner: owner_id(&fields[7])?,
    })
}

fn validate_fcc1(
    bytes: &[u8],
) -> Result<ForkAdmissionCommandFactsV1, ForkAdmissionCommandCodecErrorV1> {
    let fields = decode_envelope(bytes, MAX_FORK_CREATE_COMMAND_BYTES_V1, "FCC1", 14)?;
    let store_id = nonzero_hash(&fields[2])?;
    let session_identity = nonzero_hash(&fields[3])?;
    let operation_id = nonzero_hash(&fields[4])?;
    let evidence_digest = nonzero_hash(&fields[5])?;
    let principal_digest = nonzero_hash(&fields[6])?;
    let parent_id = timeline_id(&fields[7])?;
    let cut = unsigned(&fields[8])?;
    if unsigned(&fields[9])? != cut {
        return Err(ForkAdmissionCommandCodecErrorV1::FieldOutOfBounds);
    }
    Ok(ForkAdmissionCommandFactsV1::Fork {
        store_id,
        session_identity,
        operation_id,
        evidence_digest,
        principal_digest,
        parent_id,
        cut,
        descriptor_hash: nonzero_hash(&fields[10])?,
        composition_hash: nonzero_hash(&fields[11])?,
        attribution_required: boolean(&fields[12])?,
        child_name: text(&fields[13])?,
    })
}

/// Canonical encoding plus the fixed-width field checks imply the exact FRC1
/// size, so no separate length check is needed.
fn validate_frc1(
    bytes: &[u8],
) -> Result<ForkAdmissionRecoveryCommandFactsV1, ForkAdmissionCommandCodecErrorV1> {
    let fields = decode_envelope(
        bytes,
        MAX_FORK_ADMISSION_RECOVERY_COMMAND_BYTES_V1,
        "FRC1",
        6,
    )?;
    let store_id = nonzero_hash(&fields[2])?;
    let session_identity = nonzero_hash(&fields[3])?;
    let kind = match unsigned(&fields[4])? {
        1 => ForkAdmissionOperationKindV1::PrincipalOwner,
        2 => ForkAdmissionOperationKindV1::Fork,
        _ => return Err(ForkAdmissionCommandCodecErrorV1::FieldOutOfBounds),
    };
    let operation_id = nonzero_hash(&fields[5])?;
    Ok(ForkAdmissionRecoveryCommandFactsV1 {
        store_id,
        session_identity,
        kind,
        operation_id,
    })
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

/// Strictly decode one bounded deterministic-CBOR item.
///
/// Trailing bytes are `InvalidEncoding`; bytes that differ from their own
/// canonical re-encoding are `NonCanonical`.
pub(crate) fn decode(
    bytes: &[u8],
    maximum: usize,
) -> Result<Value, ForkAdmissionCommandCodecErrorV1> {
    if bytes.len() > maximum {
        return Err(ForkAdmissionCommandCodecErrorV1::FieldOutOfBounds);
    }
    let mut cursor = Cursor::new(bytes);
    let value: Value = ciborium::from_reader(&mut cursor)
        .map_err(|_| ForkAdmissionCommandCodecErrorV1::InvalidEncoding)?;
    if cursor.position() != bytes.len() as u64 {
        return Err(ForkAdmissionCommandCodecErrorV1::InvalidEncoding);
    }
    if canonical_bytes(&value) == bytes {
        Ok(value)
    } else {
        Err(ForkAdmissionCommandCodecErrorV1::NonCanonical)
    }
}

/// Encode one value with the crate's single deterministic-CBOR writer.
///
/// `ciborium` reports only writer I/O failures, which a `Vec` never
/// produces, so no length is ever truncated. An empty result could never
/// equal a canonical Fork-admission record.
pub(crate) fn canonical_bytes(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map(|()| bytes)
        .unwrap_or_default()
}

fn hash_value(hash: Hash) -> Value {
    Value::Bytes(hash.as_bytes().to_vec())
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

/// Decode one nonzero 32-byte digest field.
pub(crate) fn nonzero_hash(value: &Value) -> Result<Hash, ForkAdmissionCommandCodecErrorV1> {
    fixed::<32>(value).and_then(|bytes| {
        if bytes == [0; 32] {
            Err(ForkAdmissionCommandCodecErrorV1::FieldOutOfBounds)
        } else {
            Ok(Hash::from_bytes(bytes))
        }
    })
}

fn owner_id(value: &Value) -> Result<OwnerIdV1, ForkAdmissionCommandCodecErrorV1> {
    let Value::Text(owner) = value else {
        return Err(ForkAdmissionCommandCodecErrorV1::FieldOutOfBounds);
    };
    OwnerIdV1::new(owner).map_err(|_| ForkAdmissionCommandCodecErrorV1::FieldOutOfBounds)
}

fn timeline_id(value: &Value) -> Result<TimelineId, ForkAdmissionCommandCodecErrorV1> {
    fixed::<16>(value).map(|bytes| TimelineId::from_ulid(ulid::Ulid::from_bytes(bytes)))
}

fn unsigned(value: &Value) -> Result<u64, ForkAdmissionCommandCodecErrorV1> {
    value
        .as_integer()
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(ForkAdmissionCommandCodecErrorV1::FieldOutOfBounds)
}

fn boolean(value: &Value) -> Result<bool, ForkAdmissionCommandCodecErrorV1> {
    match unsigned(value)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ForkAdmissionCommandCodecErrorV1::FieldOutOfBounds),
    }
}

fn text(value: &Value) -> Result<String, ForkAdmissionCommandCodecErrorV1> {
    let Value::Text(value) = value else {
        return Err(ForkAdmissionCommandCodecErrorV1::FieldOutOfBounds);
    };
    if (1..=128).contains(&value.len()) && !value.contains('\0') {
        Ok(value.clone())
    } else {
        Err(ForkAdmissionCommandCodecErrorV1::FieldOutOfBounds)
    }
}
