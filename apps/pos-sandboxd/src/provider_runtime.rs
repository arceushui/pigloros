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
//! The `provider-runtime` mode, `serve_provider_runtime`, runs these
//! steps and step 7 (`reconcile`: the system bus, the exclusive attempt
//! recovery, the staging directory and the network capture store) before any
//! socket exists. The
//! selector started this runtime as its runtime unit (#1399, R11 §5.0), so
//! the mode then binds both SIC1 endpoints, execute then control
//! (`endpoint`, R11 §6), sends `READY=1` (`notify`) and serves both in state
//! `Starting` (`serving`, R11 §7). Restart reconciliation runs on its own
//! thread meanwhile (steps 9 to 11): its success opens admission (`Open`)
//! through the execute port it hands over (`port`, R11 §7.3),
//! and its failure leaves `ReconcileFailed` for the life of the process,
//! with no retry. If that thread cannot be spawned, the runtime stays
//! `Starting` for the life of the process, which answers exactly as
//! `ReconcileFailed` does: admission never opens.
//!
//! The `recovery-peer` mode (`recovery_peer`, ADR-069 R12 §5) answers one
//! RCC1/RCU1 exchange of a pending SIR1 with the same revocation responder,
//! and then exits.

mod endpoint;
mod notify;
mod port;
mod reconcile;
// `pub` only so its `pub(crate)` items pass Clippy's `redundant_pub_crate`;
// nothing in it is public.
pub mod recovery_peer;
mod refusal_pool;
mod revocation;
mod serving;
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;

use std::ffi::OsStr;
use std::future::Future;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use pos_reference::sandbox_provider_protocol::SandboxLimit;
use pos_reference::selector::installation::authority::{
    AdmittedSelectorProvider, AuthenticatedSelectorBootstrap,
};
use pos_reference::selector::installation::{InstallationObjectKind, InstalledSelectorState};
use pos_reference::selector::SelectorBoundaryError;

use crate::{
    AttemptLifecycle, KeyFileRuntimeSigner, ProviderInstallation, ProviderInstallationError,
    RuntimeKey,
};
use reconcile::Reconcile;
pub use revocation::{
    AttemptCleanupState, AttemptStateSource, ExchangeObserver, ExchangeOutcome,
    RevocationUpdateResponder,
};

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
    /// R11 §5.1 step 7: the system bus, the exclusive attempt recovery, the
    /// staging directory or the network capture store is unavailable, before
    /// any socket existed.
    #[error(
        "the system bus, the attempt registry, the staging directory or the capture store is unavailable"
    )]
    HostUnavailable,
}

/// The execute socket's admission state once restart reconciliation ended
/// (R11 §7.1). Before it is set, the runtime is `Starting`.
enum AdmissionState {
    /// Reconciliation succeeded. The execute port's lifecycle holds the
    /// registry lock and the ledger for the life of the process; the
    /// revocation responder fences it.
    Open(Box<port::ExecutePort>),
    /// Reconciliation failed: admission stays closed for the life of the
    /// process, with no retry (R11 §5.1 step 11).
    ReconcileFailed,
}

/// The live runtime's attempt state for the revocation responder (R11
/// §8.1): once `Open`, the lifecycle's permanent fence and snapshot, read
/// through [`crate::LiveAttemptIdentity::cleanup_proved`]. Before that no
/// attempt can exist in this runtime, so the view is empty.
struct LiveAttempts<'a>(&'a OnceLock<AdmissionState>);

impl AttemptStateSource for LiveAttempts<'_> {
    fn attempt_states(&self) -> impl Future<Output = Option<Vec<AttemptCleanupState>>> + Send {
        let lifecycle = match self.0.get() {
            Some(AdmissionState::Open(port)) => Some(&port.lifecycle),
            _ => None,
        };
        async move {
            let Some(lifecycle) = lifecycle else {
                return Some(Vec::new());
            };
            fenced_attempt_states(lifecycle).await
        }
    }
}

/// Fence `lifecycle` for good and read each live attempt of its one
/// snapshot as the responder does; `None` once it was fenced before or a
/// live attempt's record is unreadable.
pub(crate) async fn fenced_attempt_states<I>(
    lifecycle: &AttemptLifecycle<I>,
) -> Option<Vec<AttemptCleanupState>> {
    lifecycle.fence_and_snapshot().await.ok().map(|snapshot| {
        snapshot
            .attempts()
            .iter()
            .map(|attempt| AttemptCleanupState {
                attempt_id: attempt.attempt_id(),
                cleanup_proved: attempt.cleanup_proved(),
            })
            .collect()
    })
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
        reconcile::prepare_host,
        notify_socket().as_deref(),
    )
}

/// The service manager's notification socket, the one environment variable
/// a provider mode reads (R11 §9).
fn notify_socket() -> Option<std::ffi::OsString> {
    std::env::var_os("NOTIFY_SOCKET")
}

/// The mode against the startup authority that `start` binds, with the
/// restart reconciliation `prepare` binds before any socket exists,
/// notifying `notify_socket`.
fn serve_with<R: Reconcile>(
    start: impl FnOnce() -> Result<RuntimeAuthority, ProviderStartupError>,
    prepare: impl FnOnce(&RuntimeAuthority) -> Result<R, ProviderRuntimeError>,
    notify_socket: Option<&OsStr>,
) -> ProviderRuntimeError {
    start()
        .map_err(ProviderRuntimeError::from)
        .and_then(|authority| prepare(&authority).map(|reconcile| (authority, reconcile)))
        .and_then(|((admitted, _, signer), reconcile)| {
            let (execute, control) = admitted
                .bootstrap()
                .installed()
                .manifest()
                .provider_sockets();
            endpoint::bind_endpoints(execute, control)
                .map(|endpoints| (admitted, signer, reconcile, endpoints))
        })
        .map_or_else(
            |error| error,
            |(admitted, signer, reconcile, (execute, control))| {
                notify::notify_ready(notify_socket);
                let admission = Arc::new(OnceLock::new());
                reconcile_in_background(reconcile, Arc::clone(&admission));
                let pool = usize::try_from(required_slots(admitted.provider().broker_hard_caps()))
                    .unwrap_or(1);
                // The port's attempts share the startup admission and the
                // one runtime key with serving.
                let (admitted, signer) = (Arc::new(admitted), Arc::new(signer));
                serving::Responder::new(&admitted, &signer, &admission, pool)
                    .serve(&execute, &control)
            },
        )
}

/// Run restart reconciliation on its own thread and record the admission
/// state it ends in (R11 §5.1 steps 9 to 11).
fn reconcile_in_background(
    reconciliation: impl Reconcile,
    admission: Arc<OnceLock<AdmissionState>>,
) {
    start_reconciliation(reconciliation, admission, |job| {
        std::thread::Builder::new()
            .name("reconcile".to_owned())
            .spawn(job)
            .map(drop)
    });
}

/// Start `reconciliation` through `spawn`, recording the state it ends in.
/// A failure is reported in one line on standard error.
///
/// If `spawn` fails, `admission` is never set: the runtime stays
/// `Starting` for the life of the process, which answers exactly as
/// `ReconcileFailed` does, and admission never opens. That is reported in
/// one line on standard error too.
fn start_reconciliation(
    reconciliation: impl Reconcile,
    admission: Arc<OnceLock<AdmissionState>>,
    spawn: impl FnOnce(Box<dyn FnOnce() + Send>) -> std::io::Result<()>,
) {
    spawn(Box::new(move || {
        let state = reconciliation.reconcile().map_or_else(
            |error| {
                writeln!(
                    std::io::stderr(),
                    "pos-sandboxd: restart reconciliation failed: {error}"
                )
                .ok();
                AdmissionState::ReconcileFailed
            },
            |port| AdmissionState::Open(Box::new(port)),
        );
        admission.set(state).ok();
    }))
    .unwrap_or_else(|error| {
        writeln!(
            std::io::stderr(),
            "pos-sandboxd: restart reconciliation could not start: {error}"
        )
        .ok();
    });
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
