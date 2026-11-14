//! The sealed input of the runtime-attestation signer (ADR-069 R9 §5).
//!
//! A [`SelfDigested`] record exists only after a complete record of a
//! runtime-signed kind was validated, canonically encoded and self-digested
//! under `PiglorOS.<M>.v1\0` by this crate's encoder. The signer derives its
//! message, `PiglorOS.<M>.Signature.v1\0 || self_digest`, from that record
//! alone: it accepts no bytes, digest or kind from a caller, so it is not a
//! signing oracle.
//!
//! [`RuntimeSigned`] is sealed. Its kinds are a subset of the R9 §5 set, and
//! a kind joins only when its encoder does: RLS1 now, SAU1, SPR1 and SPY1
//! with their emission. RQE1, KOE1, TME1 and RDY1 never do.

use ed25519_dalek::{Signature, VerifyingKey};

use super::codec::signature_message;
use super::{ExecutionReleaseFields, SandboxProviderProtocolError};

mod runtime_signed_sealed {
    /// Only this crate names the record kinds the runtime key signs.
    pub trait Sealed {}
}

/// A record kind that the runtime-attestation key signs.
pub trait RuntimeSigned: runtime_signed_sealed::Sealed {
    /// The record magic, `M` of the R9 §5 domains.
    const MAGIC: &'static str;
    /// The validated unsigned fields of a record of this kind.
    type Body;
}

/// RLS1, `ReleaseV1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rls1 {}

impl runtime_signed_sealed::Sealed for Rls1 {}

impl RuntimeSigned for Rls1 {
    const MAGIC: &'static str = "RLS1";
    type Body = ExecutionReleaseFields;
}

/// One complete, validated record of kind `M` and its self-digest.
///
/// Only this crate's record encoders construct one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelfDigested<M: RuntimeSigned> {
    body: M::Body,
    digest: [u8; 32],
}

impl<M: RuntimeSigned> SelfDigested<M> {
    pub(super) const fn sealed(body: M::Body, digest: [u8; 32]) -> Self {
        Self { body, digest }
    }

    /// The validated unsigned fields.
    #[must_use]
    pub const fn body(&self) -> &M::Body {
        &self.body
    }

    /// The self-digest under `PiglorOS.<M>.v1\0`.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// The exact Ed25519 message: `PiglorOS.<M>.Signature.v1\0 || digest`.
    #[must_use]
    pub fn signature_message(&self) -> Vec<u8> {
        signature_message(M::MAGIC, &self.digest)
    }

    /// Verify `signature` over this record's message under `key`, strictly.
    ///
    /// # Errors
    /// `SignatureInvalid` when it does not verify.
    pub fn verify(
        &self,
        signature: &[u8; 64],
        key: &VerifyingKey,
    ) -> Result<(), SandboxProviderProtocolError> {
        key.verify_strict(&self.signature_message(), &Signature::from_bytes(signature))
            .map_err(|_| SandboxProviderProtocolError::SignatureInvalid)
    }

    pub(super) fn into_body(self) -> M::Body {
        self.body
    }
}
