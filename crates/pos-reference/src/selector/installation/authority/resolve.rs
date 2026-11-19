//! The installed authority that verifies an RCU1 (ADR-069 R11 §8.2, D10).
//!
//! [`InstalledAuthorityObjects::resolve`] reads SIC1 under the SIC1 file
//! rules, but without the pending-SIR1 refusal, so the provider's revocation
//! responder can verify an RCU1 while SIR1 is pending. It exposes only the
//! verified TRS1 and the previous RVS1: it can produce no
//! [`super::super::InstalledSelectorState`], no admitted provider and no
//! admission. No authority byte comes from the channel; the RCU1 bytes only
//! name which installed RVS1 is its previous one.
//!
//! Exactly one of these must hold, so that a historically indexed RVS1
//! cannot yield an acknowledgement for a stale transition:
//! - (a) RCU1's previous RVS1 is the installed SIC1's current RVS1;
//! - (b) RCU1's next RVS1 is the installed SIC1's current RVS1 (the next
//!   SIC1 is already published: #349 crash row 7).
//!
//! The live mode allows only (a), and the previous RVS1 must also be the one
//! retained at startup. The TRS1 is the installed SIC1's current one: an
//! update keeps TRS1 unchanged, so an RVS1 that refines another TRS1 fails
//! authentication.
use std::fs::File;
use std::path::Path;

use ed25519_dalek::VerifyingKey;

use super::super::{
    digest_complete_file, hex_name, open_directory_chain, open_immutable_file, read_complete_file,
    validate_directory, HeldInstallationArtifact, InstallationManifest, InstallationObjectKind,
    MANIFEST_LIMIT, MANIFEST_NAME, SANDBOX_ARTIFACT_ROOT,
};
use crate::sandbox_provider_protocol::{
    RevocationUpdateRequest, SandboxRevocationSnapshot, SandboxTrustSnapshot,
};
use crate::selector::SelectorBoundaryError;

/// Which installed RVS1 may verify an RCU1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityResolution {
    /// The live provider runtime: only case (a), with the previous RVS1 the
    /// one it retained at startup.
    Live {
        /// The self-digest of the RVS1 retained at startup.
        retained_revocation_digest: [u8; 32],
    },
    /// The recovery peer: case (a) or case (b).
    Recovery,
}

/// The verified TRS1 and previous RVS1 that authenticate one RCU1. It
/// yields no admission: it neither converts into an admitted provider nor
/// coerces to the installation state.
// Stable rustdoc checks only that these examples fail to compile; nightly
// rustdoc, as the mutation baseline runs it, also checks their error codes.
#[cfg_attr(
    target_os = "linux",
    doc = r"
```compile_fail,E0277
use pos_reference::selector::installation::authority::{
    AdmittedSelectorProvider, InstalledAuthorityObjects,
};
fn admit(resolved: InstalledAuthorityObjects) -> AdmittedSelectorProvider {
    resolved.into()
}
```

```compile_fail,E0308
use pos_reference::selector::installation::authority::InstalledAuthorityObjects;
use pos_reference::selector::installation::InstalledSelectorState;
fn installed(resolved: &InstalledAuthorityObjects) -> &InstalledSelectorState {
    resolved
}
```
"
)]
#[derive(Debug)]
pub struct InstalledAuthorityObjects {
    trust: SandboxTrustSnapshot,
    previous_revocation: SandboxRevocationSnapshot,
}

impl InstalledAuthorityObjects {
    /// Resolve the installed authority for the RCU1 `rcu1` from the fixed
    /// installation.
    ///
    /// # Errors
    /// `ArtifactInvalid` for unsafe ancestry or files, an invalid SIC1, an
    /// RCU1 wrapper that names no installed RVS1, a transition that is
    /// neither allowed case, and a TRS1 or RVS1 that does not verify.
    pub fn resolve(
        rcu1: &[u8],
        resolution: AuthorityResolution,
    ) -> Result<Self, SelectorBoundaryError> {
        File::open("/")
            .map_err(|_| SelectorBoundaryError::Io)
            .and_then(|filesystem_root| {
                Path::new(SANDBOX_ARTIFACT_ROOT)
                    .strip_prefix("/")
                    .map_err(|_| SelectorBoundaryError::ArtifactInvalid)
                    .and_then(|relative| open_directory_chain(filesystem_root, relative, 0))
            })
            .and_then(|root| Self::resolve_at(&root, 0, rcu1, resolution))
    }

    fn resolve_at(
        root: &File,
        owner: u32,
        rcu1: &[u8],
        resolution: AuthorityResolution,
    ) -> Result<Self, SelectorBoundaryError> {
        validate_directory(root, owner)
            .and_then(|()| open_immutable_file(root, MANIFEST_NAME, 0o400, MANIFEST_LIMIT, owner))
            .and_then(|file| read_complete_file(&file, MANIFEST_LIMIT))
            .and_then(|bytes| {
                InstallationManifest::from_canonical_cbor(&bytes)
                    .map_err(|_| SelectorBoundaryError::ArtifactInvalid)
            })
            .and_then(|manifest| {
                RevocationUpdateRequest::claimed_revocation_digests(rcu1)
                    .map_err(|_| SelectorBoundaryError::ArtifactInvalid)
                    .and_then(|[previous, next]| {
                        let [trust, current, _] = manifest.authority_digests();
                        let allowed = match resolution {
                            AuthorityResolution::Live {
                                retained_revocation_digest,
                            } => previous == current && previous == retained_revocation_digest,
                            AuthorityResolution::Recovery => {
                                (previous == current) != (next == current)
                            }
                        };
                        allowed
                            .then_some((trust, previous))
                            .ok_or(SelectorBoundaryError::ArtifactInvalid)
                    })
                    .and_then(|(trust, previous)| {
                        Self::authenticate(root, owner, &manifest, trust, previous)
                    })
            })
    }

    /// Verify the installed TRS1 `trust` under the SIC1 offline root, then
    /// the installed RVS1 `previous` under it.
    fn authenticate(
        root: &File,
        owner: u32,
        manifest: &InstallationManifest,
        trust: [u8; 32],
        previous: [u8; 32],
    ) -> Result<Self, SelectorBoundaryError> {
        let (root_key_id, root_key) = manifest.offline_root();
        VerifyingKey::from_bytes(&root_key)
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)
            .and_then(|root_key| {
                installed_record(root, owner, manifest, InstallationObjectKind(0), trust).and_then(
                    |bytes| {
                        SandboxTrustSnapshot::authenticate(&bytes, root_key_id, &root_key)
                            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)
                    },
                )
            })
            .and_then(|trust| {
                installed_record(
                    root,
                    owner,
                    manifest,
                    InstallationObjectKind::REVOCATION_SNAPSHOT,
                    previous,
                )
                .and_then(|bytes| {
                    SandboxRevocationSnapshot::authenticate(&bytes, &trust)
                        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)
                })
                .map(|previous_revocation| Self {
                    trust,
                    previous_revocation,
                })
            })
    }

    /// The verified TRS1.
    #[must_use]
    pub const fn trust(&self) -> &SandboxTrustSnapshot {
        &self.trust
    }

    /// The verified previous RVS1 the RCU1 names.
    #[must_use]
    pub const fn previous_revocation(&self) -> &SandboxRevocationSnapshot {
        &self.previous_revocation
    }
}

/// The bytes of the SIC1-indexed object `kind`/`identity`, opened by its
/// content digest under the SIC1 file rules and checked against it.
fn installed_record(
    root: &File,
    owner: u32,
    manifest: &InstallationManifest,
    kind: InstallationObjectKind,
    identity: [u8; 32],
) -> Result<Vec<u8>, SelectorBoundaryError> {
    manifest
        .object(kind, identity)
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)
        .and_then(|object| {
            root.try_clone()
                .map_err(|_| SelectorBoundaryError::Io)
                .and_then(|root| open_directory_chain(root, Path::new(kind.directory()), owner))
                .and_then(|directory| {
                    open_immutable_file(
                        &directory,
                        &hex_name(object.content_digest),
                        kind.required_mode(),
                        object.byte_length,
                        owner,
                    )
                })
                .and_then(|file| {
                    digest_complete_file(&file, object.byte_length).and_then(|digest| {
                        (digest == object.content_digest)
                            .then(|| HeldInstallationArtifact {
                                file,
                                object: object.clone(),
                            })
                            .ok_or(SelectorBoundaryError::ArtifactInvalid)
                    })
                })
        })
        .and_then(|held| held.read_control(MANIFEST_LIMIT))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
