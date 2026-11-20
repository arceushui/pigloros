#![cfg(all(target_os = "linux", any(test, feature = "test-support")))]
//! The Gateway offline store installation command (ADR-123 §3a, Redmine
//! #1467).
//!
//! It takes the ADR-134 §8 sibling mode lock exclusively and nonblocking,
//! holds it through the step, and runs the pos-store quiescent installation.
//! A Gateway composed without the profile, or another installer, holds that
//! lock, so contention refuses before anything is created. In Wave 9 the
//! command stays test-support gated with no CLI or deployable wiring (ADR-123
//! G13): no deployable build can install a store that no ungated participant
//! could open.

use pos_core::CoreError;
use pos_store::owner_store_installation::install_owner_store_namespace_v1;
pub use pos_store::owner_store_installation::OwnerStoreInstallationV1;

use crate::mode_profile::{GatewayModeErrorV1, GatewayModeStoreLockV1};

/// Closed failures of the Gateway store installation command.
#[derive(Debug, thiserror::Error)]
pub enum GatewayStoreInstallationErrorV1 {
    /// The sibling mode lock is held by another process or cannot be taken.
    #[error(transparent)]
    ModeLock(#[from] GatewayModeErrorV1),
    /// The quiescent installation refused; nothing was replaced.
    #[error(transparent)]
    Store(#[from] CoreError),
}

/// Install the store at `sqlite_path` for profile composition (ADR-123 §3a).
///
/// The operator asserts that no participant or ordinary process has the store
/// open. `sqlite_path` names the main file directly, in an absolute private
/// database directory; the installation refuses a symlinked main file and a
/// path without an absolute directory. The sibling mode lock is released when
/// the call returns; its lock file, which `GatewayModeStoreLockV1` creates,
/// stays beside the store whether or not the installation succeeds.
///
/// # Errors
/// Returns [`GatewayStoreInstallationErrorV1::ModeLock`] while any other
/// holder has the sibling mode lock or when it cannot be taken, and
/// [`GatewayStoreInstallationErrorV1::Store`] with the fixed pos-store
/// refusal for any failed installation precondition or step.
pub fn install_gateway_store_v1(
    sqlite_path: &str,
) -> Result<OwnerStoreInstallationV1, GatewayStoreInstallationErrorV1> {
    let _installing = GatewayModeStoreLockV1::exclusive(sqlite_path)?;
    // A path without a directory gives an empty one, which the installation
    // refuses as not absolute.
    let (directory, main) = sqlite_path.rsplit_once('/').unwrap_or(("", sqlite_path));
    Ok(install_owner_store_namespace_v1(
        std::path::Path::new(directory),
        main,
    )?)
}
