//! Bounded ADR-128 AES-256-GCM-SIV primitive, not a qualified artifact owner.
//!
//! The owner supplies already staged OS-random key material, admits its exact
//! operation/purpose identity and budget, and validates COH1/schema/current
//! authority before any use or release. This module authenticates bytes; it
//! cannot establish those facts, install a key vault or issue a guest permit.
//! The qualified owner must also enforce the accepted CPU/native profile and
//! inventory actual primitive copies. Zeroizing owned buffers is not proof of
//! physical memory sanitization or completed owner qualification.

use aes_gcm_siv::{AeadInOut, Aes256GcmSiv, KeyInit};
use pos_core::Hash;
use thiserror::Error;
use zeroize::Zeroizing;

pub use pos_core::community_lifecycle::MAX_COMMUNITY_ENVELOPE_PLAINTEXT_BYTES_V1;
/// Maximum primitive encryptions per staged operation/purpose key.
pub const MAX_COMMUNITY_KEY_ENCRYPTIONS_V1: u32 = 65_536;
const TAG_BYTES: usize = 16;

type Result<T> = std::result::Result<T, CommunityCipherErrorV1>;
type Entropy = fn(&mut [u8]) -> std::result::Result<(), getrandom::Error>;
type SealPrimitive = fn(
    &[u8; 32],
    &[u8; 12],
    &[u8],
    &mut [u8],
) -> std::result::Result<[u8; TAG_BYTES], aes_gcm_siv::Error>;

/// Closed primitive errors; none contains key, identity or guest bytes.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CommunityCipherErrorV1 {
    /// A staged key must admit 1..65536 encryptions under its owner's policy.
    #[error("invalid community encryption budget")]
    InvalidBudget,
    /// Input exceeds 3 MiB or ciphertext omits its 16-byte tag.
    #[error("community envelope bounds exceeded")]
    BoundsExceeded,
    /// Retained, sealed, exhausted or faulted keys cannot encrypt again.
    #[error("community encryption is closed")]
    EncryptionClosed,
    /// Fresh OS entropy was unavailable; further encryption is closed.
    #[error("community encryption entropy unavailable")]
    EntropyUnavailable,
    /// The primitive refused encryption; further encryption is closed.
    #[error("community encryption failed")]
    EncryptionFailed,
    /// No staged plaintext is returned after authentication failure.
    #[error("community envelope authentication failed")]
    AuthenticationFailed,
}

/// Unqualified AEAD parts, to be framed in the owner's exact COE1 record.
///
/// Deliberately has no `Debug`, `Clone`, Serde or plaintext representation.
pub struct CommunityCiphertextV1 {
    nonce: [u8; 12],
    ciphertext_and_tag: Zeroizing<Vec<u8>>,
}

impl CommunityCiphertextV1 {
    /// Borrow the fresh OS-selected nonce.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }

    /// Borrow encrypted bytes followed by the exact 16-byte authentication tag.
    #[must_use]
    pub fn ciphertext_and_tag(&self) -> &[u8] {
        &self.ciphertext_and_tag
    }
}

/// Non-cloneable primitive material, with no private-byte getter or reset API.
///
/// This is not the qualified material handle. Constructing it proves neither
/// native custody nor current permission. A qualified owner only admits staged
/// material for its original creation intent; retained material is decryption
/// only, including after restarting that owner. Lower limits require the
/// owner's identity-bound admitted policy, never a guest-selected override.
pub struct CommunityArtifactCipherV1 {
    material: Box<Zeroizing<[u8; 32]>>,
    material_digest: Hash,
    remaining_encryptions: u32,
}

impl CommunityArtifactCipherV1 {
    /// Move staged material into a bounded, unqualified encryption primitive.
    ///
    /// The actual owner creates and persists fresh material under its native
    /// intent/custody protocol before constructing an executable context.
    ///
    /// # Errors
    /// Rejects a zero budget or one above the accepted 65536-call ceiling.
    pub fn from_staged_material(
        material: Box<Zeroizing<[u8; 32]>>,
        maximum_encryptions: u32,
    ) -> Result<Self> {
        if maximum_encryptions == 0 || maximum_encryptions > MAX_COMMUNITY_KEY_ENCRYPTIONS_V1 {
            return Err(CommunityCipherErrorV1::InvalidBudget);
        }
        let mut cipher = Self::from_retained_material(material);
        cipher.remaining_encryptions = maximum_encryptions;
        Ok(cipher)
    }

    /// Move retained material into a permanently decryption-only primitive.
    #[must_use]
    pub fn from_retained_material(material: Box<Zeroizing<[u8; 32]>>) -> Self {
        let material_digest = crate::key_roles::key_material_digest(&material);
        Self {
            material,
            material_digest,
            remaining_encryptions: 0,
        }
    }

    /// Return the unchanged cross-role/epoch reuse fingerprint.
    #[must_use]
    pub const fn material_digest(&self) -> Hash {
        self.material_digest
    }

    /// Return remaining primitive calls, not an authorization grant.
    #[must_use]
    pub const fn remaining_encryptions(&self) -> u32 {
        self.remaining_encryptions
    }

    /// Irreversibly close new encryption when the owner seals/terminates.
    pub const fn close_encryption(&mut self) {
        self.remaining_encryptions = 0;
    }

    /// Encrypt a bounded record using a fresh OS nonce and 32-byte context AAD.
    ///
    /// The owner computes AAD from exact canonical COH1. This primitive does
    /// not authenticate a caller-supplied header, schema, role or authority.
    ///
    /// # Errors
    /// Rejects closed keys and oversized input before copying plaintext.
    /// Entropy/primitive failure closes further encryption and returns no
    /// candidate. Every primitive call burns its credit, even on failure.
    pub fn seal(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8; 32],
    ) -> Result<CommunityCiphertextV1> {
        self.seal_with(plaintext, associated_data, getrandom::fill, aes_seal)
    }

    /// Authenticate into private zeroizing staging, including for retained keys.
    ///
    /// The owner must still validate its exact record/schema/current authority
    /// before publishing or delivering this staging to any consumer.
    ///
    /// # Errors
    /// Rejects short/oversized ciphertext or authentication failure. No bytes
    /// from a failed decryption escape its zeroizing allocation.
    pub fn open(
        &self,
        nonce: &[u8; 12],
        ciphertext_and_tag: &[u8],
        associated_data: &[u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>> {
        if !(TAG_BYTES..=MAX_COMMUNITY_ENVELOPE_PLAINTEXT_BYTES_V1 + TAG_BYTES)
            .contains(&ciphertext_and_tag.len())
        {
            return Err(CommunityCipherErrorV1::BoundsExceeded);
        }
        let (ciphertext, tag_bytes) =
            ciphertext_and_tag.split_at(ciphertext_and_tag.len() - TAG_BYTES);
        let mut buffer = Zeroizing::new(Vec::with_capacity(ciphertext.len()));
        buffer.extend_from_slice(ciphertext);
        let mut tag = [0; TAG_BYTES];
        tag.copy_from_slice(tag_bytes);
        let key: &[u8; 32] = &self.material;
        if Aes256GcmSiv::new(key.into())
            .decrypt_inout_detached(
                nonce.into(),
                associated_data,
                buffer.as_mut_slice().into(),
                (&tag).into(),
            )
            .is_ok()
        {
            Ok(buffer)
        } else {
            Err(CommunityCipherErrorV1::AuthenticationFailed)
        }
    }

    // Private function pointers provide narrow nonce/primitive fault injection;
    // no public constructor accepts a caller RNG, cipher or authority verifier.
    fn seal_with(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8; 32],
        entropy: Entropy,
        primitive: SealPrimitive,
    ) -> Result<CommunityCiphertextV1> {
        if self.remaining_encryptions == 0 {
            return Err(CommunityCipherErrorV1::EncryptionClosed);
        }
        if plaintext.len() > MAX_COMMUNITY_ENVELOPE_PLAINTEXT_BYTES_V1 {
            return Err(CommunityCipherErrorV1::BoundsExceeded);
        }
        let mut nonce = [0; 12];
        if entropy(&mut nonce).is_err() {
            self.close_encryption();
            return Err(CommunityCipherErrorV1::EntropyUnavailable);
        }
        let mut buffer = Zeroizing::new(Vec::with_capacity(plaintext.len() + TAG_BYTES));
        buffer.extend_from_slice(plaintext);
        self.remaining_encryptions -= 1;
        primitive(&self.material, &nonce, associated_data, &mut buffer).map_or_else(
            |_| {
                self.close_encryption();
                Err(CommunityCipherErrorV1::EncryptionFailed)
            },
            |tag| {
                buffer.extend_from_slice(&tag);
                Ok(CommunityCiphertextV1 {
                    nonce,
                    ciphertext_and_tag: buffer,
                })
            },
        )
    }
}

fn aes_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buffer: &mut [u8],
) -> std::result::Result<[u8; TAG_BYTES], aes_gcm_siv::Error> {
    Aes256GcmSiv::new(key.into())
        .encrypt_inout_detached(nonce.into(), aad, buffer.into())
        .map(Into::into)
}

#[cfg(test)]
mod tests;
