//! ADR-105 import-only decoding of the three ADR-099 code-2 records.
//!
//! `POB1`, `FAR1`, and `FPO1` end with `authority-origin-v1`. Inside `FAE1`
//! that field is exactly `[2, authority_origin_digest]`, which every shared
//! ADR-099 decoder still rejects until #519 activates code-2 trusted reads.
//! These wrappers accept that code-2 form and nothing else, and only on the
//! import path: each one validates the record's local projection (the same
//! bytes with `[1]` in place of `[2, digest]`) with the unchanged strict local
//! decoder, so every other field keeps exactly its accepted rules and
//! canonical form. The projection never leaves this module, and every digest
//! is computed over the exact code-2 bytes.

use ciborium::value::Value;

use super::{
    authority_envelope::MAX_IMPORTED_PRINCIPAL_OWNER_BINDING_BYTES_V1, domain_digest,
    ForkAdmissionRecordInputV1, ForkAdmissionRecordV1, ForkAttributionCodecErrorV1 as Error,
    ForkPublicationOperationInputV1, ForkPublicationOperationV1, ADMISSION_DOMAIN,
    MAX_FORK_ADMISSION_RECORD_BYTES_V1, MAX_FORK_PUBLICATION_OPERATION_BYTES_V1,
};

use crate::{
    fork_admission::PRINCIPAL_OWNER_BINDING_DOMAIN, Hash, OwnerIdV1, PrincipalOwnerBindingV1,
};

/// The local `authority-origin-v1 = [1]`.
const LOCAL_ORIGIN: [u8; 2] = [0x81, 0x01];
/// The head of the code-2 `[2, bstr .size 32]` origin before its digest.
const IMPORTED_ORIGIN_HEAD: [u8; 4] = [0x82, 0x02, 0x58, 0x20];
/// The complete code-2 origin: its head plus the 32-byte digest.
const IMPORTED_ORIGIN_BYTES: usize = IMPORTED_ORIGIN_HEAD.len() + 32;

/// Split bounded code-2 record bytes into their local projection and the
/// carried authority-origin digest.
///
/// # Errors
/// Returns `FieldOutOfBounds` above `maximum`, `FieldMismatch` for a local
/// code-1 origin, which ADR-105 forbids inside `FAE1`, and `InvalidEncoding`
/// for any other final field.
fn local_projection(bytes_in: &[u8], maximum: usize) -> Result<(Vec<u8>, Hash), Error> {
    if bytes_in.len() > maximum {
        return Err(Error::FieldOutOfBounds);
    }
    let rejection = if bytes_in.ends_with(&LOCAL_ORIGIN) {
        Error::FieldMismatch
    } else {
        Error::InvalidEncoding
    };
    let (prefix, origin) = bytes_in.split_at(bytes_in.len().saturating_sub(IMPORTED_ORIGIN_BYTES));
    origin
        .strip_prefix(&IMPORTED_ORIGIN_HEAD)
        .and_then(|digest| <[u8; 32]>::try_from(digest).ok())
        .map(|digest| {
            let mut local = prefix.to_vec();
            local.extend_from_slice(&LOCAL_ORIGIN);
            (local, Hash::from_bytes(digest))
        })
        .ok_or(rejection)
}

/// Append the code-2 `[2, digest]` origin to one local record body.
fn with_imported_origin(mut body: Vec<u8>, authority_origin_digest: Hash) -> Vec<u8> {
    body.extend_from_slice(&IMPORTED_ORIGIN_HEAD);
    body.extend_from_slice(authority_origin_digest.as_bytes());
    body
}

/// One strict code-2 `POB1` carried by `FAE1` field 7.
///
/// This value is not admission authority: only a committed `FAE1` import can
/// make it visible.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedPrincipalOwnerBindingV1 {
    binding: PrincipalOwnerBindingV1,
    authority_origin_digest: Hash,
}

impl ImportedPrincipalOwnerBindingV1 {
    /// Give one source binding the code-2 origin, as the `FAE1` producer does
    /// after deriving the `FAO1` digest.
    #[must_use]
    pub const fn from_local(
        binding: PrincipalOwnerBindingV1,
        authority_origin_digest: Hash,
    ) -> Self {
        Self {
            binding,
            authority_origin_digest,
        }
    }

    /// Decode exact canonical code-2 `POB1` bytes.
    ///
    /// # Errors
    /// Returns `FieldOutOfBounds` above 241 bytes, `FieldMismatch` for a
    /// local origin, and `InvalidEncoding` for any other malformed,
    /// noncanonical, or zero-identity binding.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, Error> {
        let (local, digest) =
            local_projection(bytes_in, MAX_IMPORTED_PRINCIPAL_OWNER_BINDING_BYTES_V1)?;
        PrincipalOwnerBindingV1::from_canonical_cbor(&local)
            .map(|binding| Self::from_local(binding, digest))
            .map_err(|_| Error::InvalidEncoding)
    }

    /// Encode the exact canonical code-2 `POB1` bytes.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        self.binding.canonical_cbor_with_origin(Value::Array(vec![
            Value::Integer(2.into()),
            Value::Bytes(self.authority_origin_digest.as_bytes().to_vec()),
        ]))
    }

    /// Return the ADR-099 `POB1` digest over the exact code-2 bytes.
    #[must_use]
    pub fn digest(&self) -> Hash {
        domain_digest(PRINCIPAL_OWNER_BINDING_DOMAIN, &self.to_canonical_cbor())
    }

    /// The carried code-2 authority-origin digest.
    #[must_use]
    pub const fn authority_origin_digest(&self) -> Hash {
        self.authority_origin_digest
    }

    /// `POB1` field 4: the bound Owner.
    #[must_use]
    pub(super) const fn owner(&self) -> OwnerIdV1 {
        self.binding.input().owner
    }
}

/// One strict code-2 `FAR1` carried by `FAE1` field 8.
///
/// This value is not admission authority: only a committed `FAE1` import can
/// make it visible.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedForkAdmissionRecordV1 {
    record: ForkAdmissionRecordV1,
    authority_origin_digest: Hash,
}

impl ImportedForkAdmissionRecordV1 {
    /// Give one source admission the code-2 origin, as the `FAE1` producer
    /// does after deriving the `FAO1` digest.
    #[must_use]
    pub const fn from_local(record: ForkAdmissionRecordV1, authority_origin_digest: Hash) -> Self {
        Self {
            record,
            authority_origin_digest,
        }
    }

    /// Decode exact canonical code-2 `FAR1` bytes.
    ///
    /// # Errors
    /// Returns `FieldMismatch` for a local origin, and otherwise every error
    /// of the strict local `FAR1` decoder.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, Error> {
        let (local, digest) = local_projection(bytes_in, MAX_FORK_ADMISSION_RECORD_BYTES_V1)?;
        ForkAdmissionRecordV1::from_canonical_cbor(&local)
            .map(|record| Self::from_local(record, digest))
    }

    /// Encode the exact canonical code-2 `FAR1` bytes.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        with_imported_origin(self.record.canonical_body(), self.authority_origin_digest)
    }

    /// Return the ADR-099 `FAR1` digest over the exact code-2 bytes.
    #[must_use]
    pub fn digest(&self) -> Hash {
        domain_digest(ADMISSION_DOMAIN, &self.to_canonical_cbor())
    }

    /// The carried code-2 authority-origin digest.
    #[must_use]
    pub const fn authority_origin_digest(&self) -> Hash {
        self.authority_origin_digest
    }

    /// `FAR1` fields 2–13. The projected origin member is not field 14.
    #[must_use]
    pub(super) const fn fields(&self) -> &ForkAdmissionRecordInputV1 {
        self.record.input()
    }
}

/// One strict code-2 `FPO1` carried by `FAE1` field 11.
///
/// This value is not publication authority: only a committed `FAE1` import
/// can make it visible.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedForkPublicationOperationV1 {
    operation: ForkPublicationOperationV1,
    authority_origin_digest: Hash,
}

impl ImportedForkPublicationOperationV1 {
    /// Give one source publication operation the code-2 origin, as the
    /// `FAE1` producer does after deriving the `FAO1` digest.
    #[must_use]
    pub const fn from_local(
        operation: ForkPublicationOperationV1,
        authority_origin_digest: Hash,
    ) -> Self {
        Self {
            operation,
            authority_origin_digest,
        }
    }

    /// Decode exact canonical code-2 `FPO1` bytes.
    ///
    /// # Errors
    /// Returns `FieldMismatch` for a local origin, and otherwise every error
    /// of the strict local `FPO1` decoder.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, Error> {
        let (local, digest) = local_projection(bytes_in, MAX_FORK_PUBLICATION_OPERATION_BYTES_V1)?;
        ForkPublicationOperationV1::from_canonical_cbor(&local)
            .map(|operation| Self::from_local(operation, digest))
    }

    /// Encode the exact canonical code-2 `FPO1` bytes.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        with_imported_origin(
            self.operation.canonical_body(),
            self.authority_origin_digest,
        )
    }

    /// The carried code-2 authority-origin digest.
    #[must_use]
    pub const fn authority_origin_digest(&self) -> Hash {
        self.authority_origin_digest
    }

    /// `FPO1` fields 2–12. The projected origin member is not field 13.
    #[must_use]
    pub(super) const fn fields(&self) -> &ForkPublicationOperationInputV1 {
        self.operation.input()
    }
}
