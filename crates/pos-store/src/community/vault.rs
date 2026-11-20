//! Retained-Memory key vault entry: clear CKP1 intent, CKU1 credits and the
//! owned operation material behind its bounded cipher.
//!
//! Material is generated once, before its intent, and its fingerprint is
//! bound into that intent. Nothing here regenerates material for an existing
//! identity: a caller that finds an intent resolves it instead.

use pos_core::community_lifecycle::{
    CommunityArtifactHeaderV1, CommunityEncryptedEnvelopeV1, CommunityKeyIntentInputV1,
    CommunityKeyIntentV1, CommunityKeyUseV1, CommunityLifecycleErrorV1 as Error,
    CommunityMetadataSchemaV1, CommunityMetadataScopeV1,
};
use pos_crypto::community_cipher::{CommunityArtifactCipherV1, MAX_COMMUNITY_KEY_ENCRYPTIONS_V1};
use rand::{rngs::SysRng, TryRng};
use zeroize::Zeroizing;

use super::sealer::{open_metadata, seal_metadata, SealedMetadataV1};

/// One retained operation key; it has no material getter.
pub(super) struct VaultKeyV1 {
    intent: CommunityKeyIntentV1,
    credits: CommunityKeyUseV1,
    cipher: CommunityArtifactCipherV1,
}

impl VaultKeyV1 {
    /// Generate fresh OS material once and bind its fingerprint into `input`.
    pub(super) fn provision(mut input: CommunityKeyIntentInputV1) -> Result<Self, Error> {
        fresh_material()
            .and_then(|material| {
                CommunityArtifactCipherV1::from_staged_material(
                    material,
                    MAX_COMMUNITY_KEY_ENCRYPTIONS_V1,
                )
                .ok()
                .ok_or(Error::CapacityExhausted)
            })
            .and_then(|cipher| {
                input.material_fingerprint = cipher.material_digest();
                CommunityKeyIntentV1::new(input).and_then(|intent| {
                    CommunityKeyUseV1::new(&intent, 0).map(|credits| Self {
                        intent,
                        credits,
                        cipher,
                    })
                })
            })
    }

    /// Commit the next credit, then seal one metadata record.
    pub(super) fn seal(
        &mut self,
        scope: &CommunityMetadataScopeV1<'_>,
        schema: CommunityMetadataSchemaV1,
        plaintext: &[u8],
    ) -> Result<SealedMetadataV1, Error> {
        self.credits.next_credit().and_then(|credits| {
            self.credits = credits;
            seal_metadata(&mut self.cipher, scope, schema, plaintext)
        })
    }

    /// Commit the next credit, then encrypt `plaintext` under `header` into
    /// one canonical COE1. The caller derives the header from this key's
    /// own intent.
    pub(super) fn seal_envelope(
        &mut self,
        header: CommunityArtifactHeaderV1,
        plaintext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.credits.next_credit().and_then(|credits| {
            self.credits = credits;
            self.cipher
                .seal(plaintext, header.associated_data_digest().as_bytes())
                .ok()
                .ok_or(Error::CapacityExhausted)
                .and_then(|sealed| {
                    CommunityEncryptedEnvelopeV1::new(
                        header,
                        *sealed.nonce(),
                        sealed.ciphertext_and_tag(),
                    )
                    .map(|envelope| envelope.to_canonical_cbor())
                })
        })
    }

    /// Authenticate one canonical COE1 under this key, as the community
    /// extractor does before it validates a protected record (#560 A3c-2b′-2).
    pub(super) fn open_envelope(&self, envelope: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        CommunityEncryptedEnvelopeV1::from_canonical_cbor(envelope).and_then(|envelope| {
            self.cipher
                .open(
                    envelope.nonce(),
                    envelope.ciphertext_and_tag(),
                    envelope.header().associated_data_digest().as_bytes(),
                )
                .ok()
                .ok_or(Error::EvidenceUnavailable)
        })
    }

    /// Make this operation key permanently decryption-only.
    pub(super) const fn close(&mut self) {
        self.cipher.close_encryption();
    }

    /// Authenticate one sealed record under this key.
    pub(super) fn open(&self, sealed: &SealedMetadataV1) -> Result<Zeroizing<Vec<u8>>, Error> {
        open_metadata(&self.cipher, sealed)
    }

    /// Borrow the clear original intent.
    pub(super) const fn intent(&self) -> &CommunityKeyIntentV1 {
        &self.intent
    }

    /// Whether the retained material is the material named by the intent.
    pub(super) fn material_matches_intent(&self) -> bool {
        self.cipher.material_digest() == self.intent.as_input().material_fingerprint
    }

    /// Replace the intent while keeping this exact material, so tests can
    /// prove a mismatched intent is refused even when AEAD would succeed.
    #[cfg(test)]
    pub(super) fn with_intent(self, input: CommunityKeyIntentInputV1) -> Result<Self, Error> {
        CommunityKeyIntentV1::new(input).and_then(|intent| {
            CommunityKeyUseV1::new(&intent, 0).map(|credits| Self {
                intent,
                credits,
                cipher: self.cipher,
            })
        })
    }

    /// Highest committed encryption ordinal.
    #[cfg(test)]
    pub(super) const fn burned_credits(&self) -> u32 {
        self.credits.highest_encryption_ordinal()
    }
}

/// Fresh 16-byte identity from the OS CSPRNG.
///
/// An all-zero draw is not special-cased here: every record that carries
/// the identity (CKP1, CSM1, CCI1) refuses a zero identity, so the bootstrap
/// fails closed with `InvalidBinding` instead of using it.
pub(super) fn fresh_identity() -> Result<[u8; 16], Error> {
    let mut identity = [0_u8; 16];
    SysRng
        .try_fill_bytes(&mut identity)
        .ok()
        .map(|()| identity)
        .ok_or(Error::StorageUnavailable)
}

fn fresh_material() -> Result<Box<Zeroizing<[u8; 32]>>, Error> {
    let mut material = Box::new(Zeroizing::new([0_u8; 32]));
    SysRng
        .try_fill_bytes(material.as_mut_slice())
        .ok()
        .map(|()| material)
        .ok_or(Error::StorageUnavailable)
}
