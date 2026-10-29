//! Accepted ADR-110 E16 admission for the OS-user-global subject encryptor lock.
//!
//! The future owner adapter must acquire this lock before starting a ceremony
//! and retain it for its process lifetime. The lock alone grants no registry,
//! store, nonce or encryption authority; those checks remain owner obligations.
//! Only Linux has filesystem primitives. Other targets remain unavailable.

use crate::{BridgeError, UnavailableCode};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::SubjectEncryptorLock;

/// The platform distinction selected by ADR-110 E16.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetOs {
    /// The selected descriptor/lock implementation.
    Linux,
    /// Every other operating system, including Windows until #741.
    Other,
}

/// The actual build target, rather than a caller's platform assertion.
pub const HOST_TARGET_OS: TargetOs = if cfg!(target_os = "linux") {
    TargetOs::Linux
} else {
    TargetOs::Other
};

/// Check the platform profile before any owner operation or ceremony.
///
/// # Errors
/// Returns `Unavailable(PlatformUnsupported)` for every non-Linux target.
pub const fn nonce_ledger_support(target: TargetOs) -> Result<(), BridgeError> {
    match target {
        TargetOs::Linux => Ok(()),
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
    fn only_linux_supports_the_nonce_ledger_and_encryptor_lock() {
        assert_eq!(nonce_ledger_support(TargetOs::Linux), Ok(()));
        assert_eq!(
            nonce_ledger_support(TargetOs::Other),
            Err(BridgeError::Unavailable(
                UnavailableCode::PlatformUnsupported
            ))
        );
        #[cfg(target_os = "linux")]
        assert_eq!(HOST_TARGET_OS, TargetOs::Linux);
        #[cfg(not(target_os = "linux"))]
        assert_eq!(HOST_TARGET_OS, TargetOs::Other);
    }
}
