//! Administrator-root authentication for provider trust snapshots.

use ciborium::value::Value;
use ed25519_dalek::VerifyingKey;

use super::codec::{
    array, bounded_array, decode_document, fixed_bytes, key_id, require_canonical_order, signed,
    uint, verify_digest, verify_signature,
};
use super::SandboxProviderProtocolError;

/// Closed signing-key responsibilities in ADR-069.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxTrustRole {
    /// Administrator-pinned offline trust root.
    OfflineTrustRoot,
    /// Administrator policy and revocation signer.
    AdministratorPolicy,
    /// Provider release manifest signer.
    ProviderRelease,
    /// Live provider response and receipt signer.
    ProviderRuntimeAttestation,
    /// Independent provider-conformance reviewer.
    IndependentConformanceReviewer,
    /// Image project manifest signer.
    ImageProject,
}

impl SandboxTrustRole {
    fn decode(value: &Value) -> Result<Self, SandboxProviderProtocolError> {
        match uint(value)? {
            0 => Ok(Self::OfflineTrustRoot),
            1 => Ok(Self::AdministratorPolicy),
            2 => Ok(Self::ProviderRelease),
            3 => Ok(Self::ProviderRuntimeAttestation),
            4 => Ok(Self::IndependentConformanceReviewer),
            5 => Ok(Self::ImageProject),
            _ => Err(SandboxProviderProtocolError::FieldOutOfBounds),
        }
    }
}

/// One key record authenticated by the offline root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxTrustKey {
    /// Registry identity, distinct from key bytes.
    pub key_id: String,
    /// Sole authorized signing role.
    pub role: SandboxTrustRole,
    /// Ed25519 public-key bytes.
    pub public_key: [u8; 32],
    /// Epoch carried by this key record.
    pub epoch: u64,
}

impl SandboxTrustKey {
    fn decode(value: &Value) -> Result<Self, SandboxProviderProtocolError> {
        let fields = array::<4>(value)?;
        Ok(Self {
            key_id: key_id(&fields[0])?,
            role: SandboxTrustRole::decode(&fields[1])?,
            public_key: fixed_bytes(&fields[2])?,
            epoch: uint(&fields[3])?,
        })
    }
}

/// Root-authenticated mapping for an image verification certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxTrustCertificate {
    /// SHA-256 fingerprint of the certificate.
    pub fingerprint: [u8; 32],
    /// Administrator-installed kernel keyring serial.
    pub keyring_serial: u64,
    /// Epoch carried by this certificate record.
    pub epoch: u64,
}

impl SandboxTrustCertificate {
    fn decode(value: &Value) -> Result<Self, SandboxProviderProtocolError> {
        let fields = array::<3>(value)?;
        Ok(Self {
            fingerprint: fixed_bytes(&fields[0])?,
            keyring_serial: uint(&fields[1])?,
            epoch: uint(&fields[2])?,
        })
    }
}

/// An immutable TRS1 snapshot verified against an external offline root pin.
///
/// Authentication establishes the snapshot's signer, not admission or freshness.
/// The selector must also apply its policy and current revocation snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxTrustSnapshot {
    trust_epoch: u64,
    keys: Vec<SandboxTrustKey>,
    certificates: Vec<SandboxTrustCertificate>,
    snapshot_digest: [u8; 32],
}

impl SandboxTrustSnapshot {
    /// Authenticate canonical TRS1 bytes against an administrator-supplied root.
    ///
    /// The root key is never discovered from the untrusted snapshot itself.
    ///
    /// # Errors
    /// Rejects malformed records, ambiguous identities, incorrect digests,
    /// a different named root, or an invalid signature.
    pub fn authenticate(
        bytes: &[u8],
        root_key_id: &str,
        root_key: &VerifyingKey,
    ) -> Result<Self, SandboxProviderProtocolError> {
        let document = decode_document(bytes)?;
        let (fields, snapshot_digest, signature) = signed::<6>(&document, "TRS1")?;
        let trust_epoch = uint(&fields[2])?;
        let key_values = bounded_array(&fields[3], 0)?;
        let certificate_values = bounded_array(&fields[4], 0)?;
        let signer = key_id(&fields[5])?;
        let keys = key_values
            .iter()
            .map(SandboxTrustKey::decode)
            .collect::<Result<Vec<_>, _>>()?;
        let certificates = certificate_values
            .iter()
            .map(SandboxTrustCertificate::decode)
            .collect::<Result<Vec<_>, _>>()?;
        require_canonical_order(key_values)?;
        require_canonical_order(certificate_values)?;
        reject_duplicate_identities(&keys, &certificates)?;
        verify_digest("TRS1", fields, snapshot_digest)?;
        if signer != root_key_id {
            return Err(SandboxProviderProtocolError::SignatureInvalid);
        }
        verify_signature("TRS1", &snapshot_digest, &signature, root_key)?;
        Ok(Self {
            trust_epoch,
            keys,
            certificates,
            snapshot_digest,
        })
    }

    /// Exact epoch authenticated by the root.
    #[must_use]
    pub const fn trust_epoch(&self) -> u64 {
        self.trust_epoch
    }

    /// Exact canonical TRS1 self-digest.
    #[must_use]
    pub const fn snapshot_digest(&self) -> [u8; 32] {
        self.snapshot_digest
    }

    /// Authenticated keys; revocation and role checks still apply at admission.
    #[must_use]
    pub fn keys(&self) -> &[SandboxTrustKey] {
        &self.keys
    }

    /// Authenticated certificate mappings.
    #[must_use]
    pub fn certificates(&self) -> &[SandboxTrustCertificate] {
        &self.certificates
    }
}

fn reject_duplicate_identities(
    keys: &[SandboxTrustKey],
    certificates: &[SandboxTrustCertificate],
) -> Result<(), SandboxProviderProtocolError> {
    let mut key_ids = std::collections::BTreeSet::new();
    let mut fingerprints = std::collections::BTreeSet::new();
    if keys.iter().any(|key| !key_ids.insert(&key.key_id))
        || certificates
            .iter()
            .any(|certificate| !fingerprints.insert(certificate.fingerprint))
    {
        return Err(SandboxProviderProtocolError::NonCanonicalOrder);
    }
    Ok(())
}
