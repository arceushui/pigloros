//! Authenticated revocation snapshots and role-separated key resolution.

use ed25519_dalek::VerifyingKey;

use super::codec::{
    bounded_array, decode_document, digest32, key_id, require_canonical_order, signed, uint,
    verify_digest, verify_signature,
};
use super::{SandboxProviderProtocolError, SandboxTrustRole, SandboxTrustSnapshot};

/// Failures while resolving authority from authenticated trust records.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SandboxTrustError {
    /// The signed record violates its canonical protocol.
    #[error(transparent)]
    Protocol(#[from] SandboxProviderProtocolError),
    /// A named key is absent from the root-authenticated registry.
    #[error("sandbox signer is not trusted")]
    UnknownKey,
    /// The key is trusted for a different signing responsibility.
    #[error("sandbox signer has the wrong trust role")]
    WrongRole,
    /// The current revocation snapshot explicitly revokes this identity.
    #[error("sandbox signing key is revoked")]
    Revoked,
    /// Authority records refer to different snapshots.
    #[error("sandbox authority snapshots do not agree")]
    AuthorityMismatch,
    /// A successor snapshot skips or repeats the current epoch.
    #[error("sandbox revocation epoch is not the immediate successor")]
    EpochDiscontinuity,
}

/// Immutable RVS1 authenticated by a TRS1 administrator policy key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxRevocationSnapshot {
    trust_digest: [u8; 32],
    revocation_epoch: u64,
    revoked_keys: Vec<String>,
    revoked_providers: Vec<[u8; 32]>,
    revoked_images: Vec<[u8; 32]>,
    snapshot_digest: [u8; 32],
}

impl SandboxRevocationSnapshot {
    /// Authenticate RVS1 against the named root-authenticated registry.
    ///
    /// This validates a snapshot, not whether it is the latest installed one.
    /// The selector must bind it to APT1 and retain update continuity.
    ///
    /// # Errors
    /// Rejects invalid encoding, signatures, registry binding or signer role.
    pub fn authenticate(
        bytes: &[u8],
        trust: &SandboxTrustSnapshot,
    ) -> Result<Self, SandboxTrustError> {
        let document = decode_document(bytes)?;
        let (fields, snapshot_digest, signature) = signed::<8>(&document, "RVS1")?;
        let trust_digest = digest32(&fields[2])?;
        let revocation_epoch = uint(&fields[3])?;
        let keys = bounded_array(&fields[4], 0)?;
        let providers = bounded_array(&fields[5], 0)?;
        let images = bounded_array(&fields[6], 0)?;
        let signer = key_id(&fields[7])?;
        let revoked_keys = keys.iter().map(key_id).collect::<Result<Vec<_>, _>>()?;
        let revoked_providers = providers
            .iter()
            .map(digest32)
            .collect::<Result<Vec<_>, _>>()?;
        let revoked_images = images.iter().map(digest32).collect::<Result<Vec<_>, _>>()?;
        require_canonical_order(keys)?;
        require_canonical_order(providers)?;
        require_canonical_order(images)?;
        verify_digest("RVS1", fields, snapshot_digest)?;
        let key = resolve_key(trust, &signer, SandboxTrustRole::AdministratorPolicy)?;
        verify_signature("RVS1", &snapshot_digest, &signature, &key)?;
        if trust_digest != trust.snapshot_digest() {
            return Err(SandboxTrustError::AuthorityMismatch);
        }
        Ok(Self {
            trust_digest,
            revocation_epoch,
            revoked_keys,
            revoked_providers,
            revoked_images,
            snapshot_digest,
        })
    }

    /// Resolve an unrevoked key with the required role in the bound registry.
    ///
    /// # Errors
    /// Rejects a foreign registry, revoked key, absent key or incorrect role.
    pub fn active_key(
        &self,
        trust: &SandboxTrustSnapshot,
        id: &str,
        role: SandboxTrustRole,
    ) -> Result<VerifyingKey, SandboxTrustError> {
        if self.trust_digest != trust.snapshot_digest() {
            return Err(SandboxTrustError::AuthorityMismatch);
        }
        if self.revoked_keys.iter().any(|revoked| revoked == id) {
            return Err(SandboxTrustError::Revoked);
        }
        resolve_key(trust, id, role)
    }

    /// Check only immediate epoch continuity for snapshots from one registry.
    ///
    /// This is not full RCU1/RCA1 update validation: the stateful selector must
    /// additionally authenticate the request, previous digest, nonce, replay
    /// identity and provider acknowledgement before accepting an update.
    ///
    /// # Errors
    /// Rejects a different registry, skipped epoch, replay or epoch overflow.
    pub fn validate_immediate_epoch_for_same_registry(
        &self,
        next: &Self,
    ) -> Result<(), SandboxTrustError> {
        if self.trust_digest != next.trust_digest {
            return Err(SandboxTrustError::AuthorityMismatch);
        }
        if self.revocation_epoch.checked_add(1) != Some(next.revocation_epoch) {
            return Err(SandboxTrustError::EpochDiscontinuity);
        }
        Ok(())
    }

    /// Epoch authenticated by the administrator policy signer.
    #[must_use]
    pub const fn revocation_epoch(&self) -> u64 {
        self.revocation_epoch
    }

    /// Exact RVS1 self-digest for APT1 and receipt binding.
    #[must_use]
    pub const fn snapshot_digest(&self) -> [u8; 32] {
        self.snapshot_digest
    }

    /// Whether the administrator revoked an exact provider digest.
    #[must_use]
    pub fn provider_revoked(&self, digest: &[u8; 32]) -> bool {
        self.revoked_providers.binary_search(digest).is_ok()
    }

    /// Whether the administrator revoked an exact image digest.
    #[must_use]
    pub fn image_revoked(&self, digest: &[u8; 32]) -> bool {
        self.revoked_images.binary_search(digest).is_ok()
    }
}

fn resolve_key(
    trust: &SandboxTrustSnapshot,
    id: &str,
    role: SandboxTrustRole,
) -> Result<VerifyingKey, SandboxTrustError> {
    let key = trust
        .keys()
        .iter()
        .find(|key| key.key_id == id)
        .ok_or(SandboxTrustError::UnknownKey)?;
    if key.role != role {
        return Err(SandboxTrustError::WrongRole);
    }
    VerifyingKey::from_bytes(&key.public_key)
        .map_err(|_| SandboxProviderProtocolError::SignatureInvalid.into())
}
