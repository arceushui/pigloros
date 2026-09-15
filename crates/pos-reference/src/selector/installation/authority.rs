//! Authentication of SIC1's pinned bootstrap authority.

mod recovery_identity;
mod update;

pub use recovery_identity::{
    AdmittedProviderRuntime, InstallationRecoverySnapshot, ProviderRuntimeSlot,
};
pub use update::{CommittedInstallationUpdate, InstallationChallenge, ValidatedInstallationUpdate};

use ed25519_dalek::VerifyingKey;
use rustix::rand::{getrandom, GetRandomFlags};
use std::path::Path;

use super::{InstallationObjectKind, InstalledSelectorState, MANIFEST_LIMIT};
use crate::sandbox_provider_protocol::{
    AdmittedSandboxProvider, ProviderConformanceReport, SandboxAdministratorPolicy,
    SandboxProviderAdmissionInputs, SandboxRevocationSnapshot, SandboxTrustKey, SandboxTrustRole,
    SandboxTrustSnapshot,
};
use crate::selector::SelectorBoundaryError;

#[derive(Debug, thiserror::Error)]
pub(crate) enum InstallationUpdateCommitError {
    #[error(transparent)]
    BeforeRecovery(SelectorBoundaryError),
    #[error(transparent)]
    RecoveryPending(SelectorBoundaryError),
}

pub(crate) fn fresh_selector_id() -> Result<[u8; 16], SelectorBoundaryError> {
    fill_nonzero_id(|remaining| {
        getrandom(remaining, GetRandomFlags::empty())
            .map_err(|_| SelectorBoundaryError::SelectorUnavailable)
    })
}

fn fresh_distinct_selector_id(excluded: &[[u8; 16]]) -> Result<[u8; 16], SelectorBoundaryError> {
    fresh_distinct_selector_id_with(excluded, fresh_selector_id)
}

fn fresh_distinct_selector_id_with(
    excluded: &[[u8; 16]],
    mut generate: impl FnMut() -> Result<[u8; 16], SelectorBoundaryError>,
) -> Result<[u8; 16], SelectorBoundaryError> {
    loop {
        let candidate = generate()?;
        if !excluded.contains(&candidate) {
            return Ok(candidate);
        }
    }
}

fn fill_nonzero_id(
    mut fill: impl FnMut(&mut [u8]) -> Result<usize, SelectorBoundaryError>,
) -> Result<[u8; 16], SelectorBoundaryError> {
    let mut id = <[u8; 16]>::default();
    let mut remaining = id.as_mut_slice();
    while !remaining.is_empty() {
        let read = fill(&mut *remaining)?;
        if read == 0 || read > remaining.len() {
            return Err(SelectorBoundaryError::SelectorUnavailable);
        }
        remaining = &mut remaining[read..];
    }
    id.iter()
        .any(|byte| *byte != u8::default())
        .then_some(id)
        .ok_or(SelectorBoundaryError::SelectorUnavailable)
}

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
        let [trust_digest, revocation_digest, policy_digest] = self.manifest.authority_digests();
        VerifyingKey::from_bytes(&root_bytes)
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)
            .and_then(|root_key| {
                self.control_record(InstallationObjectKind(0), trust_digest)
                    .and_then(|trust_record| {
                        SandboxTrustSnapshot::authenticate(&trust_record, root_key_id, &root_key)
                            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)
                    })
            })
            .and_then(|trust| {
                self.control_record(InstallationObjectKind(1), revocation_digest)
                    .and_then(|revocation_record| {
                        SandboxRevocationSnapshot::authenticate(&revocation_record, &trust)
                            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)
                            .map(|revocation| (trust, revocation))
                    })
            })
            .and_then(|(trust, revocation)| {
                self.control_record(InstallationObjectKind(2), policy_digest)
                    .and_then(|policy_record| {
                        SandboxAdministratorPolicy::authenticate(
                            &policy_record,
                            &trust,
                            &revocation,
                        )
                        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)
                        .map(|policy| (trust, revocation, policy))
                    })
            })
            .and_then(|(trust, revocation, policy)| {
                authenticate_selected_artifacts(
                    &self,
                    &trust,
                    &revocation,
                    &policy,
                    [trust_digest, revocation_digest, policy_digest],
                )
                .map(|()| AuthenticatedSelectorBootstrap {
                    installed: self,
                    trust,
                    revocation,
                    policy,
                })
            })
    }

    pub(super) fn control_record(
        &self,
        kind: InstallationObjectKind,
        identity: [u8; 32],
    ) -> Result<Vec<u8>, SelectorBoundaryError> {
        self.artifact(kind, identity)
            .and_then(|artifact| artifact.read_control(MANIFEST_LIMIT))
    }
}

fn authenticate_selected_artifacts(
    installed: &InstalledSelectorState,
    trust: &SandboxTrustSnapshot,
    revocation: &SandboxRevocationSnapshot,
    policy: &SandboxAdministratorPolicy,
    expected_digests: [[u8; 32]; 3],
) -> Result<(), SelectorBoundaryError> {
    if [
        trust.snapshot_digest(),
        revocation.snapshot_digest(),
        policy.policy_digest(),
    ] != expected_digests
    {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    let selection = policy.selection();
    [
        (InstallationObjectKind(3), selection.provider_manifest),
        (InstallationObjectKind(11), selection.provider_binary),
        (InstallationObjectKind(10), selection.broker_hard_caps),
        (InstallationObjectKind(5), selection.conformance_profile),
        (InstallationObjectKind(4), selection.conformance_report),
        (InstallationObjectKind(7), selection.syscall_set),
    ]
    .into_iter()
    .try_for_each(|(kind, identity)| installed.artifact(kind, identity).map(|_| ()))
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
        AdmittedSandboxProvider::admit(
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
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)
        .map(|provider| AdmittedSelectorProvider {
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

    pub(crate) fn selected_provider_sockets(&self) -> (&Path, &Path) {
        self.bootstrap.installed.manifest().provider_sockets()
    }

    pub(crate) fn runtime_attestation_key(
        &self,
    ) -> Result<&SandboxTrustKey, SelectorBoundaryError> {
        let key_id = &self.provider.manifest().runtime_attestation_key_id;
        self.bootstrap
            .trust
            .keys()
            .iter()
            .find(|key| {
                key.key_id == *key_id && key.role == SandboxTrustRole::ProviderRuntimeAttestation
            })
            .ok_or(SelectorBoundaryError::ArtifactInvalid)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::selector::installation::tests::{admitted_state, corrupt_artifact, remove_artifact};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn bootstrap() -> Result<AuthenticatedSelectorBootstrap, Box<dyn std::error::Error>> {
        Ok(admitted_state()?.authenticate_bootstrap()?)
    }

    #[test]
    fn selector_ids_reject_failed_short_and_zero_entropy() {
        assert_eq!(
            fill_nonzero_id(|_| Err(SelectorBoundaryError::Io)),
            Err(SelectorBoundaryError::Io)
        );
        assert_eq!(
            fill_nonzero_id(|_| Ok(0)),
            Err(SelectorBoundaryError::SelectorUnavailable)
        );
        assert_eq!(
            fill_nonzero_id(|remaining| Ok(remaining.len() + 1)),
            Err(SelectorBoundaryError::SelectorUnavailable)
        );
        assert_eq!(
            fill_nonzero_id(|remaining| {
                remaining.fill(0);
                Ok(remaining.len())
            }),
            Err(SelectorBoundaryError::SelectorUnavailable)
        );
    }

    #[test]
    fn selector_ids_accept_partial_nonzero_entropy() -> TestResult {
        let mut value = 0_u8;
        let id = fill_nonzero_id(|remaining| {
            value = value.saturating_add(1);
            let written = remaining.len().min(3);
            remaining[..written].fill(value);
            Ok(written)
        })?;
        assert_ne!(id, [0; 16]);
        assert_eq!(&id[..3], &[1; 3]);
        assert_eq!(&id[15..], &[6]);
        Ok(())
    }

    #[test]
    fn distinct_selector_ids_retry_collisions_and_propagate_entropy_failure() {
        assert_eq!(
            fresh_distinct_selector_id_with(&[], || Err(SelectorBoundaryError::Io)),
            Err(SelectorBoundaryError::Io)
        );
        let mut candidates = [[7; 16], [8; 16]].into_iter();
        assert_eq!(
            fresh_distinct_selector_id_with(&[[7; 16]], || {
                candidates
                    .next()
                    .ok_or(SelectorBoundaryError::SelectorUnavailable)
            }),
            Ok([8; 16])
        );
    }

    #[test]
    fn admission_rejects_lost_retained_provider_artifacts() -> TestResult {
        let mut missing_report = bootstrap()?;
        let report = missing_report.policy.selection().conformance_report;
        remove_artifact(
            &mut missing_report.installed,
            InstallationObjectKind(4),
            report,
        );
        assert!(missing_report.admit_provider().is_err());

        let mut missing_manifest = bootstrap()?;
        let manifest = missing_manifest.policy.selection().provider_manifest;
        remove_artifact(
            &mut missing_manifest.installed,
            InstallationObjectKind(3),
            manifest,
        );
        assert!(missing_manifest.admit_provider().is_err());

        let mut missing_caps = bootstrap()?;
        let caps = missing_caps.policy.selection().broker_hard_caps;
        remove_artifact(
            &mut missing_caps.installed,
            InstallationObjectKind(10),
            caps,
        );
        assert!(missing_caps.admit_provider().is_err());

        let mut missing_syscalls = bootstrap()?;
        let syscalls = missing_syscalls.policy.selection().syscall_set;
        remove_artifact(
            &mut missing_syscalls.installed,
            InstallationObjectKind(7),
            syscalls,
        );
        assert!(missing_syscalls.admit_provider().is_err());

        let mut missing_binary = bootstrap()?;
        let binary = missing_binary.policy.selection().provider_binary;
        remove_artifact(
            &mut missing_binary.installed,
            InstallationObjectKind(11),
            binary,
        );
        assert!(missing_binary.admit_provider().is_err());
        Ok(())
    }

    #[test]
    fn admission_rejects_corrupt_report_and_lost_selected_host_profile() -> TestResult {
        let mut corrupt_report = bootstrap()?;
        let report = corrupt_report.policy.selection().conformance_report;
        corrupt_artifact(
            &mut corrupt_report.installed,
            InstallationObjectKind(4),
            report,
        )?;
        assert!(corrupt_report.admit_provider().is_err());

        let mut missing_host = bootstrap()?;
        let report = missing_host.policy.selection().conformance_report;
        let report = missing_host
            .installed
            .control_record(InstallationObjectKind(4), report)?;
        let host = ProviderConformanceReport::from_canonical_cbor(&report)?.tested_hcp1_digest;
        remove_artifact(&mut missing_host.installed, InstallationObjectKind(6), host);
        assert!(missing_host.admit_provider().is_err());
        Ok(())
    }
}
