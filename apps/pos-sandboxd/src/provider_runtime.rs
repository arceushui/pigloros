//! The authority a provider runtime binds at startup, before any socket
//! exists (ADR-069 R11 §5.1 steps 2 to 6, #1358).
//!
//! [`start_runtime_authority`] runs these steps in their normative order,
//! and the first failure wins:
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
//!    RVS1 does not revoke, as admission resolved it. It becomes the one
//!    R9 runtime-attestation signer.
//!
//! The authority never changes afterwards (R11 D9): no step is repeated.
//!
//! The `provider-runtime` mode, [`serve_provider_runtime`], runs these
//! steps before any socket exists. The selector started this process as its
//! runtime unit (#1399, R11 §5.0), so the mode then binds both SIC1
//! endpoints, execute then control (`endpoint`, R11 §6), sends `READY=1`
//! (`notify`) and serves both in state `Starting` (`serving`, R11 §7).
//! Restart reconciliation, which opens admission, is not composed yet
//! (R11 §15 slice 4): until it is, the runtime stays `Starting`.

mod endpoint;
mod notify;
mod serving;
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;

use std::ffi::OsStr;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use pos_reference::sandbox_provider_protocol::SandboxLimit;
use pos_reference::selector::installation::authority::{
    AdmittedSelectorProvider, AuthenticatedSelectorBootstrap,
};
use pos_reference::selector::installation::{InstallationObjectKind, InstalledSelectorState};
use pos_reference::selector::SelectorBoundaryError;

use crate::{KeyFileRuntimeSigner, ProviderInstallation, ProviderInstallationError, RuntimeKey};

/// The process's own executable, followed through its magic link.
const SELF_EXECUTABLE: &str = "/proc/self/exe";
/// The BHC1 limit that bounds how many attempts admission can use.
const ATTEMPT_LIMIT_ID: u8 = 13;
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
}

/// Why the `provider-runtime` mode stopped. No variant names a secret.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ProviderRuntimeError {
    /// R11 §5.1 steps 2 to 6 refused, before any socket existed.
    #[error(transparent)]
    Startup(#[from] ProviderStartupError),
    /// An endpoint lies at or under `/run/pigloros/sandbox` (R11 §6 M4).
    #[error("a provider endpoint lies under the provider state directory")]
    ReservedEndpoint,
    /// An endpoint, its parent or a directory above it fails the §6 rules,
    /// or a bound leaf lost its identity.
    #[error("a provider endpoint or its parent is unsafe")]
    UnsafeEndpoint,
    /// A listener could not be bound or polled.
    #[error("a provider endpoint is unavailable")]
    EndpointUnavailable,
}

fn unsafe_endpoint<T>(_: T) -> ProviderRuntimeError {
    ProviderRuntimeError::UnsafeEndpoint
}

fn unavailable<T>(_: T) -> ProviderRuntimeError {
    ProviderRuntimeError::EndpointUnavailable
}

/// The `provider-runtime` mode (R11 §5.1): bind this process's startup
/// authority, then bind, notify and serve until a listener invariant fails.
///
/// It reads `NOTIFY_SOCKET` and no other environment variable.
pub(crate) fn serve_provider_runtime() -> ProviderRuntimeError {
    serve_with(
        start_runtime_authority,
        std::env::var_os("NOTIFY_SOCKET").as_deref(),
    )
}

/// The mode against the startup authority that `start` binds, notifying
/// `notify_socket`.
fn serve_with(
    start: impl FnOnce() -> Result<RuntimeAuthority, ProviderStartupError>,
    notify_socket: Option<&OsStr>,
) -> ProviderRuntimeError {
    start().map_or_else(ProviderRuntimeError::from, |(admitted, _, signer)| {
        let (execute, control) = admitted
            .bootstrap()
            .installed()
            .manifest()
            .provider_sockets();
        endpoint::bind_endpoints(execute, control).map_or_else(
            |error| error,
            |(execute, control)| {
                notify::notify_ready(notify_socket);
                let pool = usize::try_from(required_slots(admitted.provider().broker_hard_caps()))
                    .unwrap_or(1);
                serving::Responder::new(&admitted, &signer).serve(&execute, &control, pool)
            },
        )
    })
}

/// The admitted provider, its SPI1 values and its runtime-attestation
/// signer, bound once at startup. Each part can only be built by its own
/// checked constructor.
type RuntimeAuthority = (
    AdmittedSelectorProvider,
    ProviderInstallation,
    KeyFileRuntimeSigner,
);

/// Run R11 §5.1 steps 2 to 6 against the fixed installation and this
/// process's own executable.
///
/// # Errors
/// The first step that fails, in order.
pub fn start_runtime_authority() -> Result<RuntimeAuthority, ProviderStartupError> {
    InstalledSelectorState::open()
        .and_then(InstalledSelectorState::authenticate_bootstrap)
        .and_then(AuthenticatedSelectorBootstrap::admit_provider)
        .map_err(ProviderStartupError::from)
        .and_then(|admitted| {
            bind(
                admitted,
                Path::new(SELF_EXECUTABLE),
                ProviderInstallation::open,
            )
        })
}

/// Steps 3 to 6 for `admitted`, with `executable` as the running image and
/// `open_installation` reading SPI1.
fn bind(
    admitted: AdmittedSelectorProvider,
    executable: &Path,
    open_installation: impl FnOnce() -> Result<ProviderInstallation, ProviderInstallationError>,
) -> Result<RuntimeAuthority, ProviderStartupError> {
    if !runs_admitted_binary(&admitted, executable) {
        return Err(ProviderStartupError::SelfBinding);
    }
    let installation = open_installation()?;
    if installation.attempt_range().slots()
        < u128::from(required_slots(admitted.provider().broker_hard_caps()))
    {
        return Err(ProviderStartupError::SlotCount);
    }
    let key_id = admitted
        .provider()
        .manifest()
        .runtime_attestation_key_id
        .clone();
    // Admission already resolved the TRS1 role-3 key that the SPM1 key ID
    // names and RVS1 leaves active.
    let signer = RuntimeKey::open(&installation)
        .and_then(|key| key.require_admitted(admitted.provider().runtime_attestation_key()))?
        .into_signer(key_id);
    Ok((admitted, installation, signer))
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

/// `min(BHC1 limit 13, 256)`.
fn required_slots(broker_hard_caps: &[SandboxLimit]) -> u64 {
    broker_hard_caps
        .iter()
        .filter(|limit| limit.limit_id == ATTEMPT_LIMIT_ID)
        .map(|limit| limit.value)
        .fold(MAX_SLOTS, u64::min)
}
