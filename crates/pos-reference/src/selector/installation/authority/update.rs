//! Single-use administrator challenges and signed revocation-only validation.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant};

use ciborium::value::Value;

use super::super::{
    open_directory_chain, open_file, InstallationManifest, InstallationObjectKind, MANIFEST_LIMIT,
};
use super::InstalledSelectorAuthority;
use crate::evaluator_protocol::{array, decode_canonical, encode, fixed_bytes, text, uint};
use crate::sandbox_provider_protocol::{
    RevocationUpdateRequest, SandboxAdministratorPolicy, SandboxRevocationSnapshot,
};
use crate::selector::{digest_name, ImmutableSandboxArtifact, SelectorBoundaryError};

/// One fresh selector-issued challenge, consumed by validation or connection closure.
///
/// The administrative connection owns this value; it is deliberately not cloneable.
#[derive(Debug)]
pub struct InstallationChallenge {
    installation: [u8; 32],
    nonce: [u8; 16],
    expires_at: Instant,
}

impl InstallationChallenge {
    /// Exact SICN1 bytes for this connection's fresh challenge.
    ///
    /// # Errors
    /// Rejects an expired challenge or a local encoding failure.
    pub fn to_cbor(&self) -> Result<Vec<u8>, SelectorBoundaryError> {
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
        if Instant::now() >= self.expires_at {
            Err(SelectorBoundaryError::ArtifactInvalid)
        } else {
            Ok(())
        }
    }

    fn into_parts(self) -> Result<([u8; 32], [u8; 16], Instant), SelectorBoundaryError> {
        self.require_live()?;
        Ok((self.installation, self.nonce, self.expires_at))
    }
}

/// A signed, validated update awaiting durable SIR1 commit and provider cancellation.
///
/// Constructing this value neither installs it nor opens admission. The exact
/// new policy/revocation descriptors remain held until the transaction completes.
#[derive(Debug)]
pub struct ValidatedInstallationUpdate {
    previous_manifest: Vec<u8>,
    next_manifest_bytes: Vec<u8>,
    next_manifest: InstallationManifest,
    revocation_update_bytes: Vec<u8>,
    revocation_update: RevocationUpdateRequest,
    next_policy_file: ImmutableSandboxArtifact,
    next_revocation_file: ImmutableSandboxArtifact,
}

impl InstalledSelectorAuthority {
    /// Issue a fresh challenge after the administrative peer has been authenticated.
    ///
    /// # Errors
    /// Rejects pending recovery or inability to establish the challenge deadline.
    pub fn issue_update_challenge(&self) -> Result<InstallationChallenge, SelectorBoundaryError> {
        self.installed.require_no_pending_recovery()?;
        let expires_at = Instant::now()
            .checked_add(Duration::from_secs(30))
            .ok_or(SelectorBoundaryError::ArtifactInvalid)?;
        let nonce = loop {
            let candidate = rand::random();
            if candidate != [0; 16] {
                break candidate;
            }
        };
        Ok(InstallationChallenge {
            installation: self.installed.manifest().digest(),
            nonce,
            expires_at,
        })
    }

    /// Consume a challenge and authenticate one exact SIU1 revocation-only update.
    ///
    /// The caller must serialize administrative transactions and close admission
    /// before invoking this method. Success is not durable completion or RCA1.
    ///
    /// # Errors
    /// Rejects stale/expired challenges, pending recovery, malformed frames,
    /// changed installation authority, invalid signatures, or mismatched RCU1.
    pub fn validate_update(
        &self,
        challenge: InstallationChallenge,
        bytes: &[u8],
    ) -> Result<ValidatedInstallationUpdate, SelectorBoundaryError> {
        let (installation, nonce, expires_at) = challenge.into_parts()?;
        self.installed.require_no_pending_recovery()?;
        if installation != self.installed.manifest().digest() {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        let (next_bytes, update_bytes) = decode_update(bytes, installation)?;
        let next_manifest = InstallationManifest::from_cbor(&next_bytes)
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        self.installed
            .manifest()
            .validate_revocation_successor(&next_manifest)
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        let next_revocation_file = self.open_updated_record(&next_manifest, 1)?;
        let next_policy_file = self.open_updated_record(&next_manifest, 2)?;
        let next_revocation_bytes = next_revocation_file.read_bytes()?;
        let next_policy_bytes = next_policy_file.read_bytes()?;
        let update = self.authenticate_update_records(
            &next_manifest,
            &next_policy_bytes,
            &next_revocation_bytes,
            &update_bytes,
        )?;
        if update.selector_nonce != nonce || Instant::now() >= expires_at {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        Ok(ValidatedInstallationUpdate {
            previous_manifest: self.installed.manifest_bytes().to_vec(),
            next_manifest_bytes: next_bytes,
            next_manifest,
            revocation_update_bytes: update_bytes,
            revocation_update: update,
            next_policy_file,
            next_revocation_file,
        })
    }

    fn authenticate_update_records(
        &self,
        next_manifest: &InstallationManifest,
        next_policy_bytes: &[u8],
        next_revocation_bytes: &[u8],
        update_bytes: &[u8],
    ) -> Result<RevocationUpdateRequest, SelectorBoundaryError> {
        let next_revocation =
            SandboxRevocationSnapshot::authenticate(next_revocation_bytes, &self.trust)
                .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        SandboxAdministratorPolicy::validate_revocation_successor(
            &self
                .installed
                .control_bytes(2, self.policy.policy_digest())?,
            next_policy_bytes,
            &self.trust,
            &self.revocation,
            &next_revocation,
        )
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        let update =
            RevocationUpdateRequest::authenticate(update_bytes, &self.trust, &self.revocation)
                .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        let [_, expected_revocation, expected_policy] = next_manifest.authority_digests();
        if next_revocation.snapshot_digest() != expected_revocation
            || update.next_revocation != next_revocation
            || signed_digest(next_policy_bytes)? != expected_policy
            || embedded_revocation(update_bytes)? != next_revocation_bytes
        {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        Ok(update)
    }

    fn open_updated_record(
        &self,
        manifest: &InstallationManifest,
        code: u8,
    ) -> Result<ImmutableSandboxArtifact, SelectorBoundaryError> {
        let identity = manifest.authority_digests()[usize::from(code)];
        let kind = InstallationObjectKind::from_code(code)
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        let entry = manifest
            .object(kind, identity)
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        if entry.length() > MANIFEST_LIMIT {
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
            Path::new("authority"),
            owner,
        )?;
        let mut file = open_file(
            &directory,
            &digest_name(entry.content_digest()),
            owner,
            0o400,
            MANIFEST_LIMIT,
        )?;
        let mut hasher = blake3::Hasher::new();
        let observed = std::io::copy(&mut (&mut file).take(entry.length() + 1), &mut hasher)
            .map_err(|_| SelectorBoundaryError::Io)?;
        if observed != entry.length() || hasher.finalize().as_bytes() != &entry.content_digest() {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|_| SelectorBoundaryError::Io)?;
        Ok(ImmutableSandboxArtifact {
            file,
            digest: entry.content_digest(),
            length: observed,
        })
    }
}

impl ValidatedInstallationUpdate {
    /// Previous root-installed SIC1, held before validation began.
    #[must_use]
    pub fn previous_manifest_bytes(&self) -> &[u8] {
        &self.previous_manifest
    }

    /// Exact successor SIC1 to install only after durable cancellation completion.
    #[must_use]
    pub fn next_manifest_bytes(&self) -> &[u8] {
        &self.next_manifest_bytes
    }

    /// Parsed successor metadata; this does not authorize execution.
    #[must_use]
    pub const fn next_manifest(&self) -> &InstallationManifest {
        &self.next_manifest
    }

    /// Exact signed RCU1 for provider replay and the durable recovery record.
    #[must_use]
    pub fn revocation_update_bytes(&self) -> &[u8] {
        &self.revocation_update_bytes
    }

    /// Authenticated RCU1 identities and successor revocation state.
    #[must_use]
    pub const fn revocation_update(&self) -> &RevocationUpdateRequest {
        &self.revocation_update
    }

    /// Held new APT1 and RVS1 descriptors for the pre-commit durability barrier.
    #[must_use]
    pub const fn record_files(&self) -> [&File; 2] {
        [&self.next_policy_file.file, &self.next_revocation_file.file]
    }
}

fn decode_update(
    bytes: &[u8],
    expected: [u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), SelectorBoundaryError> {
    let decode = || {
        let document = decode_canonical(bytes)?;
        let fields = array(&document, 5)?;
        if text(&fields[0])? != "SIU1"
            || uint(&fields[1])? != 1
            || fixed_bytes::<32>(&fields[2])? != expected
        {
            return Err(crate::evaluator_protocol::ProtocolError::InvalidEncoding);
        }
        let (Value::Bytes(next), Value::Bytes(update)) = (&fields[3], &fields[4]) else {
            return Err(crate::evaluator_protocol::ProtocolError::InvalidEncoding);
        };
        Ok((next.clone(), update.clone()))
    };
    decode().map_err(|_| SelectorBoundaryError::ArtifactInvalid)
}

fn signed_digest(bytes: &[u8]) -> Result<[u8; 32], SelectorBoundaryError> {
    let decode = || {
        let document = decode_canonical(bytes)?;
        fixed_bytes(&array(&document, 3)?[1])
    };
    decode().map_err(|_| SelectorBoundaryError::ArtifactInvalid)
}

fn embedded_revocation(bytes: &[u8]) -> Result<Vec<u8>, SelectorBoundaryError> {
    let decode = || {
        let document = decode_canonical(bytes)?;
        let fields = array(&array(&document, 3)?[0], 8)?;
        if let Value::Bytes(bytes) = &fields[4] {
            Ok(bytes.clone())
        } else {
            Err(crate::evaluator_protocol::ProtocolError::InvalidEncoding)
        }
    };
    decode().map_err(|_| SelectorBoundaryError::ArtifactInvalid)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn expired_challenge_cannot_be_sent_or_consumed() {
        let challenge = InstallationChallenge {
            installation: [1; 32],
            nonce: [2; 16],
            expires_at: Instant::now(),
        };
        assert_eq!(
            challenge.to_cbor(),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        assert!(challenge.into_parts().is_err());
    }
}
