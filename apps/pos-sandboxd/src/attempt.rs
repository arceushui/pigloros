//! The admitted and the active attempt records of the execute path (#441).
//!
//! [`AdmittedAttempt`] copies the facts of one reserved, admitted entry and
//! the directory prepared for it. [`ActiveAttempt`] is the record of a unit
//! that was started for it and not yet released; the Local binding token is
//! minted only from it.

use std::time::Instant;

use pos_reference::{
    provider_admission::AdmittedAuthority,
    sandbox_provider_protocol::{
        AdmissionAuthority, ExecuteAuthority, NetworkCapability, SandboxExecuteRequest,
        SandboxExecutionMode,
    },
};

use crate::{
    AdmittedEntry, ExecuteError, LauncherFacts, PreparedAttemptDirectory, TransientServiceUnitName,
};

/// The launch-policy view of an admitted attempt: everything a Local grant
/// must agree with (request, authority block, launch policy digest and the
/// network capabilities the policy allows).
#[derive(Clone, Debug, Eq, PartialEq)]
struct LaunchPolicyView {
    request_id: [u8; 16],
    authority: AdmissionAuthority,
    policy_digest: [u8; 32],
    network_capabilities: Vec<NetworkCapability>,
}

impl LaunchPolicyView {
    fn of(
        request: &SandboxExecuteRequest,
        policy_digest: [u8; 32],
        capabilities: &[NetworkCapability],
    ) -> Self {
        Self {
            request_id: request.request.request_id,
            authority: admission_authority(&request.authority),
            policy_digest,
            network_capabilities: capabilities.to_vec(),
        }
    }
}

/// The thirteen digests a grant carries, out of the fifteen of the request.
const fn admission_authority(authority: &ExecuteAuthority) -> AdmissionAuthority {
    AdmissionAuthority {
        evr1_digest: authority.evr1_digest,
        fixture_contract_digest: authority.fixture_contract_digest,
        fixture_digest: authority.fixture_digest,
        execution_profile_digest: authority.execution_profile_digest,
        lps1_digest: authority.lps1_digest,
        sim1_digest: authority.sim1_digest,
        apt1_digest: authority.apt1_digest,
        trs1_digest: authority.trs1_digest,
        rvs1_digest: authority.rvs1_digest,
        spm1_digest: authority.spm1_digest,
        pcf1_digest: authority.pcf1_digest,
        pcr1_digest: authority.pcr1_digest,
        hcp1_digest: authority.hcp1_digest,
    }
}

/// The facts of one reserved, admitted attempt that the execute path binds.
///
/// Only [`Self::from_entry`] creates one, from an entry whose reservation is
/// held and a directory prepared for that same attempt, so no caller can
/// present facts the admission did not produce.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedAttempt {
    attempt_id: [u8; 16],
    unit_name: TransientServiceUnitName,
    sim1_digest: [u8; 32],
    authority: AdmittedAuthority,
    mode: SandboxExecutionMode,
    executable_path: String,
    arguments: Vec<String>,
    executable_digest: [u8; 32],
    launch: LaunchPolicyView,
    launcher: LauncherFacts,
    runtime_key_id: String,
    runtime_key: ed25519_dalek::VerifyingKey,
}

impl AdmittedAttempt {
    /// Take the facts of `entry` and require `directory` to be its own.
    ///
    /// # Errors
    /// [`ExecuteError::DirectoryIdentity`] when the directory was prepared for
    /// another attempt or another SIM1.
    pub fn from_entry(
        entry: &AdmittedEntry<'_>,
        directory: &PreparedAttemptDirectory,
    ) -> Result<Self, ExecuteError> {
        let admission = entry.admission();
        let request = admission.snapshot().request();
        let intent = directory.intent();
        if intent.attempt_id() != request.attempt_id
            || intent.sim1_digest() != request.authority.sim1_digest
        {
            return Err(ExecuteError::DirectoryIdentity);
        }
        let manifest = admission.snapshot().image().manifest();
        let binary = admission.snapshot().provider_binary();
        Ok(Self {
            attempt_id: request.attempt_id,
            unit_name: intent.unit_name().clone(),
            sim1_digest: request.authority.sim1_digest,
            authority: admission.authority(),
            mode: admission.snapshot().launch_policy().execution_mode,
            executable_path: manifest.executable_path.clone(),
            arguments: manifest.arguments.clone(),
            executable_digest: manifest.executable_blake3_digest,
            launch: LaunchPolicyView::of(
                request,
                admission.snapshot().launch_policy().policy_digest,
                &admission.snapshot().launch_policy().network_capabilities,
            ),
            launcher: LauncherFacts {
                path: binary.path().to_owned(),
                digest: binary.digest(),
                length: binary.length(),
                identity: binary.identity(),
            },
            runtime_key_id: admission.snapshot().runtime_attestation_key_id().to_owned(),
            runtime_key: *admission.snapshot().runtime_attestation_key(),
        })
    }

    /// The attempt identity.
    #[must_use]
    pub const fn attempt_id(&self) -> [u8; 16] {
        self.attempt_id
    }

    /// The deterministic transient unit name of the attempt.
    #[must_use]
    pub const fn unit_name(&self) -> &TransientServiceUnitName {
        &self.unit_name
    }

    /// The execution mode of the admitted launch policy.
    #[must_use]
    pub const fn mode(&self) -> SandboxExecutionMode {
        self.mode
    }

    /// The SIM1 identity the attempt was admitted for.
    #[must_use]
    pub const fn sim1_digest(&self) -> [u8; 32] {
        self.sim1_digest
    }

    /// The authority heads and epochs the attempt was admitted with.
    #[must_use]
    pub const fn authority(&self) -> AdmittedAuthority {
        self.authority
    }

    /// The SIM1 adapter executable path.
    #[must_use]
    pub fn executable_path(&self) -> &str {
        &self.executable_path
    }

    /// The SIM1 fixed adapter argument vector.
    #[must_use]
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    /// The admitted BLAKE3 digest of the adapter executable.
    #[must_use]
    pub const fn executable_digest(&self) -> [u8; 32] {
        self.executable_digest
    }

    /// The launcher source derived solely from this admitted SIC1 context.
    #[must_use]
    pub fn launcher_source(&self) -> crate::LauncherSource {
        crate::LauncherSource::admitted(self.launcher.path.clone())
    }

    pub(crate) const fn launcher(&self) -> &LauncherFacts {
        &self.launcher
    }

    pub(crate) fn runtime_key_id(&self) -> &str {
        &self.runtime_key_id
    }

    pub(crate) const fn runtime_key(&self) -> &ed25519_dalek::VerifyingKey {
        &self.runtime_key
    }

    /// The request the admission was granted for.
    pub(crate) const fn request_id(&self) -> [u8; 16] {
        self.launch.request_id
    }

    /// The authority block a grant for this attempt must carry.
    pub(crate) const fn admission_authority(&self) -> &AdmissionAuthority {
        &self.launch.authority
    }

    /// The digest of the admitted launch policy (LPS1).
    pub(crate) const fn launch_policy_digest(&self) -> [u8; 32] {
        self.launch.policy_digest
    }

    /// The network capabilities the admitted launch policy allows.
    pub(crate) fn network_capabilities(&self) -> &[NetworkCapability] {
        &self.launch.network_capabilities
    }

    /// Facts for tests that have no privileged installation to admit from.
    #[cfg(all(test, unix))]
    pub(crate) fn for_test(
        attempt_id: [u8; 16],
        authority: AdmittedAuthority,
        mode: SandboxExecutionMode,
    ) -> crate::test_fixtures::TestResult<Self> {
        let unit_name = TransientServiceUnitName::from_attempt_id(attempt_id)?;
        Ok(Self {
            attempt_id,
            unit_name,
            sim1_digest: [0x51; 32],
            authority,
            mode,
            executable_path: "/usr/bin/adapter".to_owned(),
            arguments: vec!["--check".to_owned()],
            executable_digest: [0x61; 32],
            launch: LaunchPolicyView {
                request_id: crate::test_fixtures::REQUEST_ID,
                authority: crate::test_fixtures::grant_authority(),
                policy_digest: crate::test_fixtures::grant_authority().lps1_digest,
                network_capabilities: Vec::new(),
            },
            launcher: crate::test_fixtures::launcher_facts()?,
            runtime_key_id: crate::test_fixtures::RUNTIME_KEY_ID.to_owned(),
            runtime_key: ed25519_dalek::SigningKey::from_bytes(&crate::test_fixtures::RUNTIME_SEED)
                .verifying_key(),
        })
    }

    /// The same attempt, with a launch policy that allows `capabilities`.
    #[cfg(all(test, unix))]
    pub(crate) fn allowing(mut self, capabilities: Vec<NetworkCapability>) -> Self {
        self.launch.network_capabilities = capabilities;
        self
    }

    /// The same attempt running another adapter path.
    #[cfg(all(test, unix))]
    pub(crate) fn running(mut self, executable_path: String) -> Self {
        self.executable_path = executable_path;
        self
    }

    /// A deliberately inconsistent admitted digest for substitution tests.
    #[cfg(all(test, unix))]
    pub(crate) fn with_launcher_digest(mut self, digest: [u8; 32]) -> Self {
        self.launcher.digest = digest;
        self
    }
}

/// The record of a started, not yet released attempt.
///
/// It exists once the transient unit was started and its requested state
/// verified. It records the admitted attempt, whose authority heads the
/// successful last-moment recheck confirmed, and the broker watchdog deadline;
/// everything that must belong to this attempt is bound to it. It has no
/// public constructor.
#[derive(Clone, Debug)]
pub struct ActiveAttempt {
    admitted: AdmittedAttempt,
    deadline: Instant,
}

impl ActiveAttempt {
    pub(crate) const fn admitted(&self) -> &AdmittedAttempt {
        &self.admitted
    }
    pub(crate) const fn record(admitted: AdmittedAttempt, deadline: Instant) -> Self {
        Self { admitted, deadline }
    }

    /// The attempt identity.
    #[must_use]
    pub const fn attempt_id(&self) -> [u8; 16] {
        self.admitted.attempt_id
    }

    /// The deterministic transient unit name of the attempt.
    #[must_use]
    pub const fn unit_name(&self) -> &TransientServiceUnitName {
        &self.admitted.unit_name
    }

    /// The broker's monotonic watchdog deadline for the whole attempt.
    #[must_use]
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }
}
