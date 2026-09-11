//! Authentication of SIC1's pinned bootstrap authority.

use ed25519_dalek::VerifyingKey;

use super::{InstallationObjectKind, InstalledSelectorState, MANIFEST_LIMIT};
use crate::sandbox_provider_protocol::{
    SandboxAdministratorPolicy, SandboxRevocationSnapshot, SandboxTrustSnapshot,
};
use crate::selector::SelectorBoundaryError;

/// Root-authenticated installation state ready for provider admission.
///
/// This is deliberately not an execution permit. The caller must still perform
/// full provider, image, request, and terminal-evidence authentication before
/// binding the evaluator selector socket.
#[derive(Debug)]
pub struct AuthenticatedSelectorBootstrap {
    installed: InstalledSelectorState,
    trust: SandboxTrustSnapshot,
    revocation: SandboxRevocationSnapshot,
    policy: SandboxAdministratorPolicy,
}

impl InstalledSelectorState {
    /// Authenticates the pinned TRS1, RVS1, and APT1 bootstrap chain.
    ///
    /// # Errors
    /// Returns an error for forged or inconsistent authority, revoked selected
    /// artifacts, or any APT1-selected provider artifact absent from SIC1.
    pub fn authenticate_bootstrap(
        self,
    ) -> Result<AuthenticatedSelectorBootstrap, SelectorBoundaryError> {
        let (root_key_id, root_bytes) = self.manifest.offline_root();
        let root_key = VerifyingKey::from_bytes(&root_bytes)
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        let [trust_digest, revocation_digest, policy_digest] = self.manifest.authority_digests();
        let trust = SandboxTrustSnapshot::authenticate(
            &self.control_record(InstallationObjectKind(0), trust_digest)?,
            root_key_id,
            &root_key,
        )
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        let revocation = SandboxRevocationSnapshot::authenticate(
            &self.control_record(InstallationObjectKind(1), revocation_digest)?,
            &trust,
        )
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        let policy = SandboxAdministratorPolicy::authenticate(
            &self.control_record(InstallationObjectKind(2), policy_digest)?,
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
        for (kind, identity) in [
            (InstallationObjectKind(3), selection.provider_manifest),
            (InstallationObjectKind(11), selection.provider_binary),
            (InstallationObjectKind(10), selection.broker_hard_caps),
            (InstallationObjectKind(5), selection.conformance_profile),
            (InstallationObjectKind(4), selection.conformance_report),
            (InstallationObjectKind(7), selection.syscall_set),
        ] {
            self.artifact(kind, identity)?;
        }
        Ok(AuthenticatedSelectorBootstrap {
            installed: self,
            trust,
            revocation,
            policy,
        })
    }

    fn control_record(
        &self,
        kind: InstallationObjectKind,
        identity: [u8; 32],
    ) -> Result<Vec<u8>, SelectorBoundaryError> {
        self.artifact(kind, identity)?.read_control(MANIFEST_LIMIT)
    }
}

impl AuthenticatedSelectorBootstrap {
    /// Returns the descriptor-retaining installed state.
    #[must_use]
    pub const fn installed(&self) -> &InstalledSelectorState {
        &self.installed
    }

    /// Returns the offline-root-authenticated TRS1 snapshot.
    #[must_use]
    pub const fn trust(&self) -> &SandboxTrustSnapshot {
        &self.trust
    }

    /// Returns the authenticated current RVS1 snapshot.
    #[must_use]
    pub const fn revocation(&self) -> &SandboxRevocationSnapshot {
        &self.revocation
    }

    /// Returns the authenticated selected APT1 policy.
    #[must_use]
    pub const fn policy(&self) -> &SandboxAdministratorPolicy {
        &self.policy
    }
}
