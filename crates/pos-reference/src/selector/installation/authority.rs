//! Authentication of SIC1's pinned bootstrap authority.

use ed25519_dalek::VerifyingKey;

use super::{InstallationObjectKind, InstalledSelectorState, MANIFEST_LIMIT};
use crate::sandbox_provider_protocol::{
    AdmittedSandboxProvider, ProviderConformanceReport, SandboxAdministratorPolicy,
    SandboxProviderAdmissionInputs, SandboxRevocationSnapshot, SandboxTrustSnapshot,
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

/// Root-selected provider released after full provider admission.
#[derive(Debug)]
pub struct AdmittedSelectorProvider {
    bootstrap: AuthenticatedSelectorBootstrap,
    provider: AdmittedSandboxProvider,
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
    /// Performs complete provider admission from retained SIC1 artifacts.
    ///
    /// # Errors
    /// Returns an error when the selected provider, conformance report, host
    /// profile, capability evidence, or immutable artifact bindings fail
    /// admission. This does not expose an evaluator socket.
    pub fn admit_provider(self) -> Result<AdmittedSelectorProvider, SelectorBoundaryError> {
        let selection = self.policy.selection().clone();
        let conformance_report = self
            .installed
            .control_record(InstallationObjectKind(4), selection.conformance_report)?;
        let host_profile_digest =
            ProviderConformanceReport::from_canonical_cbor(&conformance_report)
                .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?
                .tested_hcp1_digest;
        let provider_manifest = self
            .installed
            .control_record(InstallationObjectKind(3), selection.provider_manifest)?;
        let broker_hard_caps = self
            .installed
            .control_record(InstallationObjectKind(10), selection.broker_hard_caps)?;
        let host_profile = self
            .installed
            .control_record(InstallationObjectKind(6), host_profile_digest)?;
        let syscall_set = self
            .installed
            .control_record(InstallationObjectKind(7), selection.syscall_set)?;
        let provider_binary_digest = self
            .installed
            .artifact(InstallationObjectKind(11), selection.provider_binary)?
            .object()
            .content_digest();
        let provider = AdmittedSandboxProvider::admit(
            &self.policy,
            &self.trust,
            &self.revocation,
            SandboxProviderAdmissionInputs {
                provider_manifest: &provider_manifest,
                provider_binary_digest,
                broker_hard_caps: &broker_hard_caps,
                conformance_report: &conformance_report,
                host_profile: &host_profile,
                syscall_set: &syscall_set,
                required_features: self.installed.manifest.required_features(),
            },
        )
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        Ok(AdmittedSelectorProvider {
            bootstrap: self,
            provider,
        })
    }

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

impl AdmittedSelectorProvider {
    /// Returns the retained bootstrap authority and descriptors.
    #[must_use]
    pub const fn bootstrap(&self) -> &AuthenticatedSelectorBootstrap {
        &self.bootstrap
    }

    /// Returns the fully admitted selected provider.
    #[must_use]
    pub const fn provider(&self) -> &AdmittedSandboxProvider {
        &self.provider
    }
}
