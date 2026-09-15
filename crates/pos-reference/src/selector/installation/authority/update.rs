//! Single-use administrator challenges and revocation-only SIC1 validation.

mod durability;

pub use durability::CommittedInstallationUpdate;

use std::fs::File;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::time::{Duration, Instant};

use super::{fresh_selector_id, AuthenticatedSelectorBootstrap};
use crate::evaluator_protocol::{array, decode_canonical, encode, fixed_bytes, text, uint};
use crate::sandbox_provider_protocol::{
    RevocationUpdateRequest, SandboxAdministratorPolicy, SandboxRevocationSnapshot,
};
use crate::selector::installation::{
    digest_complete_file, hex_name, open_directory_chain, open_immutable_file,
    HeldInstallationArtifact, InstallationManifest, InstallationObjectKind, MANIFEST_LIMIT,
};
use crate::selector::SelectorBoundaryError;
use ciborium::value::Value;

const CHALLENGE_LIFETIME: Duration = Duration::from_secs(30);

/// One fresh selector-issued challenge owned by one administrative connection.
///
/// The value cannot be cloned. Validation consumes it, which prevents replay
/// across requests even before the connection owner closes the stream.
#[derive(Debug)]
pub struct InstallationChallenge {
    installation: [u8; 32],
    nonce: [u8; 16],
    expires_at: Instant,
}

impl InstallationChallenge {
    /// Encode the exact fresh-mode SICN1 challenge.
    ///
    /// # Errors
    /// Returns a closed boundary error after expiry or on local encoding failure.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SelectorBoundaryError> {
        self.require_live()?;
        encode(&Value::Array(vec![
            Value::Text("SICN1".to_owned()),
            Value::Integer(1_u64.into()),
            Value::Bytes(self.installation.to_vec()),
            Value::Bytes(self.nonce.to_vec()),
            Value::Integer(0_u64.into()),
        ]))
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)
    }

    fn require_live(&self) -> Result<(), SelectorBoundaryError> {
        (Instant::now() < self.expires_at)
            .then_some(())
            .ok_or(SelectorBoundaryError::ArtifactInvalid)
    }

    fn consume(self) -> Result<([u8; 32], [u8; 16], Instant), SelectorBoundaryError> {
        self.require_live()?;
        Ok((self.installation, self.nonce, self.expires_at))
    }

    #[cfg(test)]
    pub(crate) fn expire_for_test(&mut self) {
        self.expires_at = Instant::now();
    }

    #[cfg(test)]
    pub(crate) const fn replace_installation_for_test(&mut self, installation: [u8; 32]) {
        self.installation = installation;
    }
}

/// Fully authenticated SIU1 content awaiting an atomic attempt snapshot and SIR1 commit.
///
/// The next APT1 and RVS1 descriptors stay open so the durability boundary can
/// synchronize the exact bytes that validation authenticated.
#[derive(Debug)]
pub struct ValidatedInstallationUpdate {
    previous_manifest: Vec<u8>,
    next_manifest_bytes: Vec<u8>,
    next_manifest: InstallationManifest,
    revocation_update_bytes: Vec<u8>,
    revocation_update: RevocationUpdateRequest,
    next_policy: HeldInstallationArtifact,
    next_revocation: HeldInstallationArtifact,
}

impl AuthenticatedSelectorBootstrap {
    /// Issue a cryptographically random fresh-mode challenge.
    ///
    /// # Errors
    /// Returns a closed boundary error if randomness or deadline creation fails.
    pub fn issue_update_challenge(&self) -> Result<InstallationChallenge, SelectorBoundaryError> {
        let expires_at = Instant::now()
            .checked_add(CHALLENGE_LIFETIME)
            .ok_or(SelectorBoundaryError::SelectorUnavailable)?;
        Ok(InstallationChallenge {
            installation: self.installed.manifest().digest(),
            nonce: fresh_selector_id()?,
            expires_at,
        })
    }

    /// Consume one connection-owned challenge and authenticate one exact SIU1.
    ///
    /// This operation performs no durable write and grants no execution. Its
    /// caller must already have closed admission and serialized updates.
    ///
    /// # Errors
    /// Rejects expired, stale, malformed, substituted, non-successor, or
    /// incorrectly authorized installation updates.
    pub fn validate_update(
        &self,
        challenge: InstallationChallenge,
        bytes: &[u8],
    ) -> Result<ValidatedInstallationUpdate, SelectorBoundaryError> {
        let (installation, nonce, expires_at) = challenge.consume()?;
        if installation != self.installed.manifest().digest() {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        let (next_manifest_bytes, revocation_update_bytes) = decode_update(bytes, installation)?;
        let next_manifest = InstallationManifest::from_canonical_cbor(&next_manifest_bytes)
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        self.installed
            .manifest()
            .validate_revocation_successor(&next_manifest)
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        let next_revocation =
            self.open_updated_record(&next_manifest, InstallationObjectKind::REVOCATION_SNAPSHOT)?;
        let next_policy =
            self.open_updated_record(&next_manifest, InstallationObjectKind::ADMINISTRATOR_POLICY)?;
        let next_revocation_bytes = next_revocation.read_control(MANIFEST_LIMIT)?;
        let next_policy_bytes = next_policy.read_control(MANIFEST_LIMIT)?;
        let revocation_update = self.authenticate_update_records(
            &next_manifest,
            &next_policy_bytes,
            &next_revocation_bytes,
            &revocation_update_bytes,
        )?;
        if revocation_update.selector_nonce != nonce || Instant::now() >= expires_at {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        Ok(ValidatedInstallationUpdate {
            previous_manifest: self.installed.manifest_bytes().to_vec(),
            next_manifest_bytes,
            next_manifest,
            revocation_update_bytes,
            revocation_update,
            next_policy,
            next_revocation,
        })
    }

    fn authenticate_update_records(
        &self,
        next_manifest: &InstallationManifest,
        next_policy_bytes: &[u8],
        next_revocation_bytes: &[u8],
        revocation_update_bytes: &[u8],
    ) -> Result<RevocationUpdateRequest, SelectorBoundaryError> {
        let next_revocation =
            SandboxRevocationSnapshot::authenticate(next_revocation_bytes, &self.trust)
                .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        SandboxAdministratorPolicy::validate_revocation_successor(
            &self.installed.control_record(
                InstallationObjectKind::ADMINISTRATOR_POLICY,
                self.policy.policy_digest(),
            )?,
            next_policy_bytes,
            &self.trust,
            &self.revocation,
            &next_revocation,
        )
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        let update = RevocationUpdateRequest::authenticate(
            revocation_update_bytes,
            &self.trust,
            &self.revocation,
        )
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        let [_, expected_revocation, expected_policy] = next_manifest.authority_digests();
        if next_revocation.snapshot_digest() != expected_revocation
            || update.next_revocation != next_revocation
            || signed_digest(next_policy_bytes)? != expected_policy
            || embedded_revocation(revocation_update_bytes)? != next_revocation_bytes
        {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        Ok(update)
    }

    fn open_updated_record(
        &self,
        manifest: &InstallationManifest,
        kind: InstallationObjectKind,
    ) -> Result<HeldInstallationArtifact, SelectorBoundaryError> {
        let identity = manifest.authority_digests()[usize::from(kind.code())];
        let object = manifest
            .object(kind, identity)
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?
            .clone();
        if object.byte_length() > MANIFEST_LIMIT {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        let owner = self
            .installed
            .root
            .metadata()
            .map_err(|_| SelectorBoundaryError::Io)?
            .uid();
        let directory = open_directory_chain(
            self.installed
                .root
                .try_clone()
                .map_err(|_| SelectorBoundaryError::Io)?,
            Path::new(kind.directory()),
            owner,
        )?;
        let file = open_immutable_file(
            &directory,
            &hex_name(object.content_digest()),
            kind.required_mode(),
            object.byte_length(),
            owner,
        )?;
        if digest_complete_file(&file, object.byte_length())? != object.content_digest() {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        Ok(HeldInstallationArtifact { file, object })
    }
}

impl ValidatedInstallationUpdate {
    /// Exact current SIC1 retained before validation.
    #[must_use]
    pub fn previous_manifest_bytes(&self) -> &[u8] {
        &self.previous_manifest
    }

    /// Exact canonical successor SIC1.
    #[must_use]
    pub fn next_manifest_bytes(&self) -> &[u8] {
        &self.next_manifest_bytes
    }

    /// Parsed successor installation metadata.
    #[must_use]
    pub const fn next_manifest(&self) -> &InstallationManifest {
        &self.next_manifest
    }

    /// Exact administrator-signed RCU1 bytes.
    #[must_use]
    pub fn revocation_update_bytes(&self) -> &[u8] {
        &self.revocation_update_bytes
    }

    /// Authenticated RCU1 authority and successor RVS1.
    #[must_use]
    pub const fn revocation_update(&self) -> &RevocationUpdateRequest {
        &self.revocation_update
    }

    /// Retained successor APT1 and RVS1 descriptors.
    #[must_use]
    pub const fn record_files(&self) -> [&File; 2] {
        [self.next_policy.file(), self.next_revocation.file()]
    }

    #[cfg(test)]
    pub(crate) fn replace_previous_manifest_for_test(&mut self, manifest: Vec<u8>) {
        self.previous_manifest = manifest;
    }

    #[cfg(test)]
    pub(crate) fn clear_revocation_update_for_test(&mut self) {
        self.revocation_update_bytes.clear();
    }
}

fn decode_update(
    bytes: &[u8],
    expected_installation: [u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), SelectorBoundaryError> {
    let document = decode_canonical(bytes).map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    let fields = array(&document, 5).map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    if text(&fields[0]).map_err(|_| SelectorBoundaryError::ArtifactInvalid)? != "SIU1"
        || uint(&fields[1]).map_err(|_| SelectorBoundaryError::ArtifactInvalid)? != 1
        || fixed_bytes::<32>(&fields[2]).map_err(|_| SelectorBoundaryError::ArtifactInvalid)?
            != expected_installation
    {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    let (Value::Bytes(next), Value::Bytes(update)) = (&fields[3], &fields[4]) else {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    };
    if next.is_empty()
        || next.len() as u64 > MANIFEST_LIMIT
        || update.is_empty()
        || update.len() as u64 > MANIFEST_LIMIT
    {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    Ok((next.clone(), update.clone()))
}

fn signed_digest(bytes: &[u8]) -> Result<[u8; 32], SelectorBoundaryError> {
    let document = decode_canonical(bytes).map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    fixed_bytes(&array(&document, 3).map_err(|_| SelectorBoundaryError::ArtifactInvalid)?[1])
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)
}

fn embedded_revocation(bytes: &[u8]) -> Result<Vec<u8>, SelectorBoundaryError> {
    let document = decode_canonical(bytes).map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    let wrapper = array(&document, 3).map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    let fields = array(&wrapper[0], 8).map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    match &fields[4] {
        Value::Bytes(bytes) => Ok(bytes.clone()),
        _ => Err(SelectorBoundaryError::ArtifactInvalid),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn signed_record_extractors_reject_malformed_nested_values(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let malformed = encode(&Value::Array(vec![
            Value::Array(vec![
                Value::Text("RCU1".to_owned()),
                Value::Integer(1_u64.into()),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
            ]),
            Value::Bytes(vec![0; 32]),
            Value::Bytes(vec![0; 64]),
        ]))?;
        assert_eq!(
            embedded_revocation(&malformed),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        assert_eq!(
            signed_digest(&[0xff]),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        for value in [
            Value::Null,
            Value::Array(Vec::new()),
            Value::Array(vec![Value::Null, Value::Null, Value::Null]),
        ] {
            let bytes = encode(&value)?;
            assert_eq!(
                signed_digest(&bytes),
                Err(SelectorBoundaryError::ArtifactInvalid)
            );
            assert_eq!(
                embedded_revocation(&bytes),
                Err(SelectorBoundaryError::ArtifactInvalid)
            );
        }
        let malformed_unsigned = encode(&Value::Array(vec![
            Value::Array(Vec::new()),
            Value::Bytes(vec![0; 32]),
            Value::Bytes(vec![0; 64]),
        ]))?;
        assert_eq!(
            embedded_revocation(&malformed_unsigned),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        Ok(())
    }
}
