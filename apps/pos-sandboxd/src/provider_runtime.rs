//! The authority a provider runtime binds at startup, before any socket
//! exists (ADR-069 R11 §5.1 steps 2 to 6, #1358).
//!
//! [`ProviderRuntimeAuthority::start`] runs these steps in their normative
//! order, and the first failure wins:
//!
//! 2. **SIC1.** The provider's own installation is opened (refused while
//!    SIR1 is pending), its bootstrap authority authenticated and the
//!    selected provider admitted.
//! 3. **Self-binding.** `/proc/self/exe`, followed through its magic link,
//!    must be the very file the held SIC1 kind-11 descriptor names: the same
//!    device and inode.
//! 4. **SPI1.** The provider installation is read and validated
//!    ([`ProviderInstallation::open`]).
//! 5. **Slot count.** The SPI1 attempt range must hold at least
//!    `min(BHC1 limit 13, 256)` slots.
//! 6. **Key.** The SPI1 key file's public key must be the TRS1
//!    runtime-attestation key that the SPM1 key ID names and the current
//!    RVS1 does not revoke. It becomes the one R9 runtime-attestation
//!    signer.
//!
//! The authority never changes afterwards (R11 D9): no step is repeated.

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use ed25519_dalek::VerifyingKey;
use pos_reference::sandbox_provider_protocol::SandboxTrustRole;
use pos_reference::selector::installation::authority::{
    AdmittedSelectorProvider, AuthenticatedSelectorBootstrap,
};
use pos_reference::selector::installation::{InstallationObjectKind, InstalledSelectorState};
use pos_reference::selector::SelectorBoundaryError;

use crate::{KeyFileReleaseSigner, ProviderInstallation, ProviderInstallationError, RuntimeKey};

/// The process's own executable, followed through its magic link.
const SELF_EXECUTABLE: &str = "/proc/self/exe";
/// The BHC1 limit that bounds how many attempts admission can use.
const ATTEMPT_LIMIT_ID: usize = 13;
/// The most attempts one runtime holds (ADR-069 §4.1, RCC1).
const MAX_SLOTS: u64 = 256;

/// Why a provider runtime refused to start. Each refusal comes before any
/// socket is bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProviderStartupError {
    /// Step 2: SIC1 is missing, invalid, pending recovery or not admitted.
    #[error(transparent)]
    Installation(#[from] SelectorBoundaryError),
    /// Step 3: `/proc/self/exe` is not the held SIC1 provider executable.
    #[error("the running executable is not the admitted provider binary")]
    SelfBinding,
    /// Steps 4 and 6: SPI1 or its key file was refused.
    #[error(transparent)]
    ProviderInstallation(#[from] ProviderInstallationError),
    /// Step 5: the attempt range holds fewer slots than admission can use.
    #[error("the attempt range holds fewer slots than admission can use")]
    SlotCount,
    /// Step 6: SPM1 names no runtime-attestation key that TRS1 holds and
    /// RVS1 leaves active.
    #[error("the runtime-attestation key is not admitted")]
    RuntimeKeyNotAdmitted,
}

/// The admitted provider, its SPI1 values and its runtime-attestation
/// signer, bound once at startup.
#[derive(Debug)]
pub struct ProviderRuntimeAuthority {
    admitted: AdmittedSelectorProvider,
    installation: ProviderInstallation,
    runtime_key: VerifyingKey,
    signer: KeyFileReleaseSigner,
}

impl ProviderRuntimeAuthority {
    /// Run R11 §5.1 steps 2 to 6 against the fixed installation and this
    /// process's own executable.
    ///
    /// # Errors
    /// The first step that fails, in order.
    pub fn start() -> Result<Self, ProviderStartupError> {
        InstalledSelectorState::open()
            .and_then(InstalledSelectorState::authenticate_bootstrap)
            .and_then(AuthenticatedSelectorBootstrap::admit_provider)
            .map_err(ProviderStartupError::from)
            .and_then(|admitted| {
                Self::bind(
                    admitted,
                    Path::new(SELF_EXECUTABLE),
                    ProviderInstallation::open,
                )
            })
    }

    /// Steps 3 to 6 for `admitted`, with `executable` as the running image
    /// and `open_installation` reading SPI1.
    fn bind(
        admitted: AdmittedSelectorProvider,
        executable: &Path,
        open_installation: impl FnOnce() -> Result<ProviderInstallation, ProviderInstallationError>,
    ) -> Result<Self, ProviderStartupError> {
        if !runs_admitted_binary(&admitted, executable) {
            return Err(ProviderStartupError::SelfBinding);
        }
        let installation = open_installation()?;
        if installation.attempt_range().slots() < u128::from(required_slots(&admitted)) {
            return Err(ProviderStartupError::SlotCount);
        }
        let key_id = admitted
            .provider()
            .manifest()
            .runtime_attestation_key_id
            .clone();
        let (runtime_key, signer) = admitted_runtime_key(&admitted).and_then(|runtime_key| {
            RuntimeKey::open(&installation)
                .and_then(|key| key.require_admitted(&runtime_key))
                .map(|key| (runtime_key, key.into_signer(key_id)))
                .map_err(ProviderStartupError::from)
        })?;
        Ok(Self {
            admitted,
            installation,
            runtime_key,
            signer,
        })
    }

    /// The admitted provider and its retained SIC1 authority.
    #[must_use]
    pub const fn admitted(&self) -> &AdmittedSelectorProvider {
        &self.admitted
    }

    /// The validated SPI1 values.
    #[must_use]
    pub const fn installation(&self) -> &ProviderInstallation {
        &self.installation
    }

    /// The admitted runtime-attestation public key.
    #[must_use]
    pub const fn runtime_key(&self) -> &VerifyingKey {
        &self.runtime_key
    }

    /// The one R9 runtime-attestation signer.
    #[must_use]
    pub const fn signer(&self) -> &KeyFileReleaseSigner {
        &self.signer
    }
}

/// Whether `executable`, followed through any link, is the file the held
/// SIC1 kind-11 descriptor of the selected provider binary names.
fn runs_admitted_binary(admitted: &AdmittedSelectorProvider, executable: &Path) -> bool {
    let bootstrap = admitted.bootstrap();
    bootstrap
        .installed()
        .artifact(
            InstallationObjectKind::PROVIDER_EXECUTABLE,
            bootstrap.policy().selection().provider_binary,
        )
        .ok()
        .and_then(|held| held.file().metadata().ok())
        .zip(std::fs::metadata(executable).ok())
        .is_some_and(|(held, running)| held.dev() == running.dev() && held.ino() == running.ino())
}

/// `min(BHC1 limit 13, 256)`. BHC1 holds every limit in ID order, so a
/// missing limit can only require the most.
fn required_slots(admitted: &AdmittedSelectorProvider) -> u64 {
    admitted
        .provider()
        .broker_hard_caps()
        .get(ATTEMPT_LIMIT_ID)
        .map_or(MAX_SLOTS, |limit| limit.value)
        .min(MAX_SLOTS)
}

/// The TRS1 role-3 key that the SPM1 key ID names, unrevoked by RVS1.
fn admitted_runtime_key(
    admitted: &AdmittedSelectorProvider,
) -> Result<VerifyingKey, ProviderStartupError> {
    let bootstrap = admitted.bootstrap();
    bootstrap
        .revocation()
        .active_key(
            bootstrap.trust(),
            &admitted.provider().manifest().runtime_attestation_key_id,
            SandboxTrustRole::ProviderRuntimeAttestation,
        )
        .ok()
        .ok_or(ProviderStartupError::RuntimeKeyNotAdmitted)
}
