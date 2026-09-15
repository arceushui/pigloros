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

fn invalid<T>(_: T) -> SelectorBoundaryError {
    SelectorBoundaryError::ArtifactInvalid
}

fn io<T>(_: T) -> SelectorBoundaryError {
    SelectorBoundaryError::Io
}

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

struct DecodedInstallationUpdate {
    nonce: [u8; 16],
    expires_at: Instant,
    next_manifest_bytes: Vec<u8>,
    revocation_update_bytes: Vec<u8>,
}

struct OpenedInstallationUpdate {
    decoded: DecodedInstallationUpdate,
    next_manifest: InstallationManifest,
    next_policy: HeldInstallationArtifact,
    next_revocation: HeldInstallationArtifact,
}

impl AuthenticatedSelectorBootstrap {
    /// Issue a cryptographically random fresh-mode challenge.
    ///
    /// # Errors
    /// Returns a closed boundary error if secure randomness is unavailable.
    pub fn issue_update_challenge(&self) -> Result<InstallationChallenge, SelectorBoundaryError> {
        fresh_selector_id().map(|nonce| InstallationChallenge {
            installation: self.installed.manifest().digest(),
            nonce,
            expires_at: Instant::now() + CHALLENGE_LIFETIME,
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
        challenge
            .consume()
            .and_then(|parts| self.decode_challenged_update(parts, bytes))
            .and_then(|decoded| self.open_challenged_update(decoded))
            .and_then(|opened| self.authenticate_challenged_update(opened))
    }

    fn decode_challenged_update(
        &self,
        (installation, nonce, expires_at): ([u8; 32], [u8; 16], Instant),
        bytes: &[u8],
    ) -> Result<DecodedInstallationUpdate, SelectorBoundaryError> {
        if installation != self.installed.manifest().digest() {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        decode_update(bytes, installation).map(|(next_manifest_bytes, revocation_update_bytes)| {
            DecodedInstallationUpdate {
                nonce,
                expires_at,
                next_manifest_bytes,
                revocation_update_bytes,
            }
        })
    }

    fn open_challenged_update(
        &self,
        decoded: DecodedInstallationUpdate,
    ) -> Result<OpenedInstallationUpdate, SelectorBoundaryError> {
        InstallationManifest::from_canonical_cbor(&decoded.next_manifest_bytes)
            .map_err(invalid)
            .and_then(|next_manifest| {
                self.installed
                    .manifest()
                    .validate_revocation_successor(&next_manifest)
                    .map_err(invalid)
                    .map(|()| next_manifest)
            })
            .and_then(|next_manifest| {
                self.open_updated_record(
                    &next_manifest,
                    InstallationObjectKind::REVOCATION_SNAPSHOT,
                )
                .map(|next_revocation| (next_manifest, next_revocation))
            })
            .and_then(|(next_manifest, next_revocation)| {
                self.open_updated_record(
                    &next_manifest,
                    InstallationObjectKind::ADMINISTRATOR_POLICY,
                )
                .map(|next_policy| OpenedInstallationUpdate {
                    decoded,
                    next_manifest,
                    next_policy,
                    next_revocation,
                })
            })
    }

    fn authenticate_challenged_update(
        &self,
        opened: OpenedInstallationUpdate,
    ) -> Result<ValidatedInstallationUpdate, SelectorBoundaryError> {
        opened
            .next_revocation
            .read_control(MANIFEST_LIMIT)
            .and_then(|next_revocation_bytes| {
                opened
                    .next_policy
                    .read_control(MANIFEST_LIMIT)
                    .map(|next_policy_bytes| (next_policy_bytes, next_revocation_bytes))
            })
            .and_then(|(next_policy_bytes, next_revocation_bytes)| {
                self.authenticate_update_records(
                    &opened.next_manifest,
                    &next_policy_bytes,
                    &next_revocation_bytes,
                    &opened.decoded.revocation_update_bytes,
                )
            })
            .and_then(|revocation_update| {
                if revocation_update.selector_nonce == opened.decoded.nonce
                    && Instant::now() < opened.decoded.expires_at
                {
                    Ok(ValidatedInstallationUpdate {
                        previous_manifest: self.installed.manifest_bytes().to_vec(),
                        next_manifest_bytes: opened.decoded.next_manifest_bytes,
                        next_manifest: opened.next_manifest,
                        revocation_update_bytes: opened.decoded.revocation_update_bytes,
                        revocation_update,
                        next_policy: opened.next_policy,
                        next_revocation: opened.next_revocation,
                    })
                } else {
                    Err(SelectorBoundaryError::ArtifactInvalid)
                }
            })
    }

    fn authenticate_update_records(
        &self,
        next_manifest: &InstallationManifest,
        next_policy_bytes: &[u8],
        next_revocation_bytes: &[u8],
        revocation_update_bytes: &[u8],
    ) -> Result<RevocationUpdateRequest, SelectorBoundaryError> {
        SandboxRevocationSnapshot::authenticate(next_revocation_bytes, &self.trust)
            .map_err(invalid)
            .and_then(|next_revocation| {
                self.installed
                    .control_record(
                        InstallationObjectKind::ADMINISTRATOR_POLICY,
                        self.policy.policy_digest(),
                    )
                    .and_then(|current_policy| {
                        SandboxAdministratorPolicy::validate_revocation_successor(
                            &current_policy,
                            next_policy_bytes,
                            &self.trust,
                            &self.revocation,
                            &next_revocation,
                        )
                        .map_err(invalid)
                    })
                    .map(|next_policy| (next_revocation, next_policy))
            })
            .and_then(|(next_revocation, next_policy)| {
                RevocationUpdateRequest::authenticate(
                    revocation_update_bytes,
                    &self.trust,
                    &self.revocation,
                )
                .map_err(invalid)
                .map(|update| (next_revocation, next_policy, update))
            })
            .and_then(|(next_revocation, next_policy, update)| {
                let [_, expected_revocation, expected_policy] = next_manifest.authority_digests();
                if next_revocation.snapshot_digest() == expected_revocation
                    && update.next_revocation == next_revocation
                    && next_policy.policy_digest() == expected_policy
                {
                    Ok(update)
                } else {
                    Err(SelectorBoundaryError::ArtifactInvalid)
                }
            })
    }

    fn open_updated_record(
        &self,
        manifest: &InstallationManifest,
        kind: InstallationObjectKind,
    ) -> Result<HeldInstallationArtifact, SelectorBoundaryError> {
        let identity = manifest.authority_digests()[usize::from(kind.code())];
        manifest
            .object(kind, identity)
            .map_err(invalid)
            .cloned()
            .and_then(|object| {
                if object.byte_length() <= MANIFEST_LIMIT {
                    Ok(object)
                } else {
                    Err(SelectorBoundaryError::ArtifactInvalid)
                }
            })
            .and_then(|object| {
                self.installed
                    .root
                    .metadata()
                    .map_err(io)
                    .map(|metadata| (object, metadata.uid()))
            })
            .and_then(|(object, owner)| {
                self.installed
                    .root
                    .try_clone()
                    .map_err(io)
                    .and_then(|root| open_directory_chain(root, Path::new(kind.directory()), owner))
                    .map(|directory| (object, owner, directory))
            })
            .and_then(|(object, owner, directory)| {
                open_immutable_file(
                    &directory,
                    &hex_name(object.content_digest()),
                    kind.required_mode(),
                    object.byte_length(),
                    owner,
                )
                .map(|file| (object, file))
            })
            .and_then(|(object, file)| {
                digest_complete_file(&file, object.byte_length()).and_then(|digest| {
                    if digest == object.content_digest() {
                        Ok(HeldInstallationArtifact { file, object })
                    } else {
                        Err(SelectorBoundaryError::ArtifactInvalid)
                    }
                })
            })
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

    #[cfg(test)]
    pub(crate) fn replace_next_manifest_for_test(&mut self, manifest: Vec<u8>) {
        self.next_manifest_bytes = manifest;
    }

    #[cfg(test)]
    pub(crate) fn replace_revocation_update_for_test(&mut self, update: Vec<u8>) {
        self.revocation_update_bytes = update;
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
