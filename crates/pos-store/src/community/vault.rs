//! Retained-Memory key vault entry: clear CKP1 intent, CKU1 credits and the
//! owned operation material behind its bounded cipher.
//!
//! Material is generated once, before its intent, and its fingerprint is
//! bound into that intent. Nothing here regenerates material for an existing
//! identity: a caller that finds an intent resolves it instead.

use pos_core::community_lifecycle::{
    CommunityKeyIntentInputV1, CommunityKeyIntentV1, CommunityKeyUseV1,
    CommunityLifecycleErrorV1 as Error, CommunityMetadataSchemaV1, CommunityMetadataScopeV1,
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
        self.credits.next().and_then(|credits| {
            self.credits = credits;
            seal_metadata(&mut self.cipher, scope, schema, plaintext)
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

    /// Highest committed encryption ordinal.
    #[cfg(test)]
    pub(super) const fn burned_credits(&self) -> u32 {
        self.credits.highest_encryption_ordinal()
    }
}

/// Fresh nonzero 16-byte identity from the OS CSPRNG.
pub(super) fn fresh_identity() -> Result<[u8; 16], Error> {
    let mut identity = [0_u8; 16];
    SysRng
        .try_fill_bytes(&mut identity)
        .ok()
        .filter(|&()| identity != [0; 16])
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
