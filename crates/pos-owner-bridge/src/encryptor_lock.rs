//! Accepted ADR-110 E16 admission for the OS-user-global subject encryptor lock.
//!
//! The pure platform policy is available in normal builds. Linux filesystem
//! primitives require test-support; lock admission takes an explicit test directory (E15).
//! The Windows profile accepted by ADR-132 lives in `pos-owner-bridge-windows`
//! under the same test-support gate. Fixed per-user paths and owner activation
//! remain unavailable on every platform.

use crate::{BridgeError, UnavailableCode};

#[cfg(all(target_os = "linux", any(test, feature = "test-support")))]
pub mod linux;

/// The platform distinction selected by ADR-110 E16.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetOs {
    /// The selected descriptor/lock implementation.
    Linux,
    /// The named-mutex and NTFS ledger profile accepted by ADR-132.
    Windows,
    /// Every other operating system.
    Other,
}

/// The actual build target, rather than a caller's platform assertion.
pub const HOST_TARGET_OS: TargetOs = if cfg!(target_os = "linux") {
    TargetOs::Linux
} else if cfg!(windows) {
    TargetOs::Windows
} else {
    TargetOs::Other
};

/// Check the platform profile before any owner operation or ceremony.
///
/// # Errors
/// Returns `Unavailable(PlatformUnsupported)` for every target other than
/// Linux and Windows. Success selects a platform profile only; it neither
/// admits a ledger nor activates subject encryption.
pub const fn nonce_ledger_support(target: TargetOs) -> Result<(), BridgeError> {
    match target {
        TargetOs::Linux | TargetOs::Windows => Ok(()),
        TargetOs::Other => Err(BridgeError::Unavailable(
            UnavailableCode::PlatformUnsupported,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{nonce_ledger_support, TargetOs, HOST_TARGET_OS};
    use crate::{BridgeError, UnavailableCode};

    #[test]
    fn linux_and_windows_support_the_nonce_ledger_and_encryptor_lock() {
        assert_eq!(nonce_ledger_support(TargetOs::Linux), Ok(()));
        assert_eq!(nonce_ledger_support(TargetOs::Windows), Ok(()));
        assert_eq!(
            nonce_ledger_support(TargetOs::Other),
            Err(BridgeError::Unavailable(
                UnavailableCode::PlatformUnsupported
            ))
        );
        #[cfg(target_os = "linux")]
        assert_eq!(HOST_TARGET_OS, TargetOs::Linux);
        #[cfg(windows)]
        assert_eq!(HOST_TARGET_OS, TargetOs::Windows);
        #[cfg(not(any(target_os = "linux", windows)))]
        assert_eq!(HOST_TARGET_OS, TargetOs::Other);
    }
}
