//! Offline-pinned bootstrap authority, separate from provider admission.

pub mod update;

use super::{InstallationObjectKind, InstalledSelectorObjects, MANIFEST_LIMIT};
use crate::sandbox_provider_protocol::{
    SandboxAdministratorPolicy, SandboxRevocationSnapshot, SandboxTrustSnapshot,
};
use crate::selector::SelectorBoundaryError;

/// Authenticated installed TRS1/RVS1/APT1 and their retained installation files.
///
/// This is not an execution permit: provider, image, host and case admission
/// still have to succeed before an evaluator socket is exposed.
#[derive(Debug)]
pub struct InstalledSelectorAuthority {
    installed: InstalledSelectorObjects,
    trust: SandboxTrustSnapshot,
    revocation: SandboxRevocationSnapshot,
    policy: SandboxAdministratorPolicy,
}

impl InstalledSelectorObjects {
    /// Authenticate bootstrap authority from the held root-owned installation.
    ///
    /// A pending SIR1 forbids this normal-startup path. Recovery must establish
    /// the next authority floor before normal admission can be attempted.
    ///
    /// # Errors
    /// Rejects pending recovery, oversized control records, incorrect semantic
    /// identities, forged signatures, mismatched epochs and revoked selection.
    pub fn authenticate_authority(
        self,
    ) -> Result<InstalledSelectorAuthority, SelectorBoundaryError> {
        self.require_no_pending_recovery()?;
        let (root_id, root_bytes) = self.manifest.offline_root();
        let root_key = ed25519_dalek::VerifyingKey::from_bytes(&root_bytes)
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        let [trust_digest, revocation_digest, policy_digest] = self.manifest.authority_digests();
        let trust = SandboxTrustSnapshot::authenticate(
            &self.control_bytes(0, trust_digest)?,
            root_id,
            &root_key,
        )
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        let revocation = SandboxRevocationSnapshot::authenticate(
            &self.control_bytes(1, revocation_digest)?,
            &trust,
        )
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        let policy = SandboxAdministratorPolicy::authenticate(
            &self.control_bytes(2, policy_digest)?,
            &trust,
            &revocation,
        )
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        if [
            trust.snapshot_digest(),
            revocation.snapshot_digest(),
            policy.policy_digest(),
        ] != [trust_digest, revocation_digest, policy_digest]
        {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        let selection = policy.selection();
        for (code, identity) in [
            (3, selection.provider_manifest),
            (11, selection.provider_binary),
            (10, selection.broker_hard_caps),
            (5, selection.conformance_profile),
            (4, selection.conformance_report),
            (7, selection.syscall_set),
        ] {
            self.artifact(InstallationObjectKind(code), identity)?;
        }
        Ok(InstalledSelectorAuthority {
            installed: self,
            trust,
            revocation,
            policy,
        })
    }

    fn control_bytes(
        &self,
        code: u8,
        identity: [u8; 32],
    ) -> Result<Vec<u8>, SelectorBoundaryError> {
        let artifact = self.artifact(InstallationObjectKind(code), identity)?;
        if artifact.length() > MANIFEST_LIMIT {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        artifact.read_bytes()
    }

    fn require_no_pending_recovery(&self) -> Result<(), SelectorBoundaryError> {
        use rustix::fs::{statat, AtFlags};
        match statat(
            &self.root,
            "installation-update.cbor",
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Err(rustix::io::Errno::NOENT) => Ok(()),
            // Any existing entry, including a broken link or invalid record,
            // requires recovery. Permission/I/O errors never mean absent.
            _ => Err(SelectorBoundaryError::ArtifactInvalid),
        }
    }
}

impl InstalledSelectorAuthority {
    /// Retained immutable installation and its typed object lookup.
    #[must_use]
    pub const fn installed(&self) -> &InstalledSelectorObjects {
        &self.installed
    }

    /// TRS1 authenticated only against SIC1's offline root pin.
    #[must_use]
    pub const fn trust(&self) -> &SandboxTrustSnapshot {
        &self.trust
    }

    /// RVS1 authenticated against the pinned registry.
    #[must_use]
    pub const fn revocation(&self) -> &SandboxRevocationSnapshot {
        &self.revocation
    }

    /// APT1 authenticated against both selected snapshots and their epochs.
    #[must_use]
    pub const fn policy(&self) -> &SandboxAdministratorPolicy {
        &self.policy
    }
}
