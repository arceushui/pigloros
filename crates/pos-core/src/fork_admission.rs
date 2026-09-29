//! Durable Fork-admission result values.

use ciborium::value::Value;

use crate::{
    fork_admission_command::{canonical_bytes, decode, nonzero_hash},
    Hash, OwnerIdV1, TimelineId,
};

/// Maximum accepted canonical `POB1` bytes.
///
/// The largest record contains two 32-byte digests and a 128-byte owner
/// identifier: 1 + 5 + 1 + 34 + 34 + 130 + 2.
pub const MAX_PRINCIPAL_OWNER_BINDING_BYTES_V1: usize = 207;

/// Trust anchor of a durable POB1 or FAR1 record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForkAuthorityOriginV1 {
    /// Locally admitted authority, encoded as `[1]`.
    Local,
}

/// Closed failures at the Fork-admission store boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ForkAdmissionErrorV1 {
    /// A request field or precondition is invalid.
    #[error("invalid Fork admission request")]
    InvalidRequest,
    /// FAE1 provenance, policy membership, or first-use freshness failed.
    #[error("authentication evidence is not trusted")]
    Unauthenticated,
    /// The immutable Principal-to-Owner mapping disagrees.
    #[error("Principal-to-Owner binding conflicts")]
    PrincipalOwnerConflict,
    /// The expected completed Fold Cursor is not the parent head.
    #[error("the completed fold boundary is stale")]
    StaleFoldBoundary,
    /// The parent Timeline is absent or its cut cannot be read.
    #[error("the parent Timeline changed")]
    ParentChanged,
    /// The same operation ID is committed with unequal intent.
    #[error("Fork admission conflicts with a committed operation")]
    Conflict,
    /// Durable authority is malformed, partial, orphaned, or unequal.
    #[error("Fork admission authority is corrupt")]
    CorruptAuthority,
    /// The storage outcome cannot be determined.
    #[error("Fork admission storage outcome is indeterminate")]
    StorageIndeterminate,
    /// Host proof, policy, store, or session binding differs.
    #[error("Fork admission host authority does not match")]
    HostAuthorityMismatch,
    /// The production authority wall source is unavailable.
    #[error("Fork admission authority clock is unavailable")]
    AuthorityClockUnavailable,
    /// The wall source is below the durable authority fence.
    #[error("Fork admission authority clock rolled back")]
    ClockRollback,
    /// Lookup-only recovery found no operation of that kind and ID.
    #[error("Fork admission operation is missing")]
    OperationMissing,
    /// No canonical FAH1 has been provisioned.
    #[error("Fork admission authority is uninitialized")]
    AuthorityUninitialized,
    /// Provisioning found an existing FAH1.
    #[error("Fork admission authority is already initialized")]
    AuthorityAlreadyInitialized,
    /// Operating-system entropy was unavailable.
    #[error("Fork admission entropy is unavailable")]
    EntropyUnavailable,
}

/// One durable operation graph root.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ForkAdmissionOperationKindV1 {
    /// A POB1 Principal-to-Owner binding operation (wire kind 1).
    PrincipalOwner,
    /// An atomic child/FAR1 Fork-creation operation (wire kind 2).
    Fork,
}

impl ForkAdmissionOperationKindV1 {
    /// Return the FRC1 field-4 and durable operation-row kind code.
    #[must_use]
    pub const fn wire(self) -> u8 {
        match self {
            Self::PrincipalOwner => 1,
            Self::Fork => 2,
        }
    }
}

/// Fields of one POB1 Principal-to-Owner binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalOwnerBindingInputV1 {
    /// Stable nonzero operation identity that committed the binding.
    pub operation_id: Hash,
    /// Nonzero `PrincipalRefV1` canonical-byte digest.
    pub principal_digest: Hash,
    /// Owner resolved by the trusted host for this Principal.
    pub owner: OwnerIdV1,
    /// Trust anchor of the binding.
    pub origin: ForkAuthorityOriginV1,
}

/// Canonical local POB1 record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalOwnerBindingV1(PrincipalOwnerBindingInputV1);

impl PrincipalOwnerBindingV1 {
    /// # Errors
    /// Returns `InvalidRequest` when a required identity is zero.
    pub fn new(input: PrincipalOwnerBindingInputV1) -> Result<Self, ForkAdmissionErrorV1> {
        if input.operation_id == Hash::zero() || input.principal_digest == Hash::zero() {
            return Err(ForkAdmissionErrorV1::InvalidRequest);
        }
        Ok(Self(input))
    }

    /// # Errors
    /// Returns `CorruptAuthority` for malformed or noncanonical durable bytes.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, ForkAdmissionErrorV1> {
        let Value::Array(fields) = decode(bytes_in, MAX_PRINCIPAL_OWNER_BINDING_BYTES_V1)
            .map_err(|_| ForkAdmissionErrorV1::CorruptAuthority)?
        else {
            return Err(ForkAdmissionErrorV1::CorruptAuthority);
        };
        if fields.len() != 6
            || !matches!(&fields[0], Value::Bytes(marker) if marker == b"POB1")
            || !matches!(&fields[1], Value::Integer(version) if *version == 1.into())
            || !matches!(&fields[5], Value::Array(origin) if origin.len() == 1 && origin[0] == Value::Integer(1.into()))
        {
            return Err(ForkAdmissionErrorV1::CorruptAuthority);
        }
        let Value::Text(owner) = &fields[4] else {
            return Err(ForkAdmissionErrorV1::CorruptAuthority);
        };
        // `nonzero_hash` rejects zero digests and `OwnerIdV1::new` validates
        // the owner, so this decoded input already satisfies `Self::new`.
        let result = Self(PrincipalOwnerBindingInputV1 {
            operation_id: durable_hash(&fields[2])?,
            principal_digest: durable_hash(&fields[3])?,
            owner: OwnerIdV1::new(owner).map_err(|_| ForkAdmissionErrorV1::CorruptAuthority)?,
            origin: ForkAuthorityOriginV1::Local,
        });
        (result.to_canonical_cbor() == bytes_in)
            .then_some(result)
            .ok_or(ForkAdmissionErrorV1::CorruptAuthority)
    }

    /// Return the binding fields.
    #[must_use]
    pub const fn input(&self) -> &PrincipalOwnerBindingInputV1 {
        &self.0
    }

    /// Return the complete canonical POB1 bytes.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let input = self.input();
        canonical_bytes(&Value::Array(vec![
            Value::Bytes(b"POB1".to_vec()),
            Value::Integer(1.into()),
            Value::Bytes(input.operation_id.as_bytes().to_vec()),
            Value::Bytes(input.principal_digest.as_bytes().to_vec()),
            Value::Text(input.owner.as_str().to_owned()),
            Value::Array(vec![Value::Integer(1.into())]),
        ]))
    }

    /// Return `BLAKE3("pigloros/principal-owner-binding/v1" || POB1 bytes)`.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(
            b"pigloros/principal-owner-binding/v1",
            &self.to_canonical_cbor(),
        )
    }
}

/// Committed result of one atomic child/FAR1 creation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkAdmissionReceiptV1 {
    /// Newly created child Fork Timeline.
    pub child_id: TimelineId,
    /// Digest of the committed FAR1 record.
    pub admission_digest: Hash,
}

/// Committed result of one FAC1 execution or FRP1 recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ForkAdmissionOperationResultV1 {
    /// The immutable POB1 binding for the authenticated Principal.
    PrincipalOwner(PrincipalOwnerBindingV1),
    /// The committed child/FAR1 receipt.
    Fork(ForkAdmissionReceiptV1),
}

fn durable_hash(value: &Value) -> Result<Hash, ForkAdmissionErrorV1> {
    nonzero_hash(value).map_err(|_| ForkAdmissionErrorV1::CorruptAuthority)
}

/// Return `BLAKE3(domain || bytes)` for one Fork-admission digest domain.
pub(crate) fn digest(domain: &[u8], bytes_in: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes_in);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}
