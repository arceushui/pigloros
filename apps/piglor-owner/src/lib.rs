//! Minimal owner entry point selected by ADR-110 §1a.
//!
//! #399 extends this executable with the real owner adapter. The accepted E16
//! gate keeps Windows owner operations unavailable until #741 supplies their
//! nonce-ledger profile; no ceremony starts before that gate succeeds.

#[cfg(windows)]
pub use pos_owner_bridge_windows::owner_startup as run;

/// Refuse targets without the selected native owner surface.
///
/// # Errors
///
/// Always returns `Unavailable(PlatformUnsupported)` on non-Windows targets.
#[cfg(not(windows))]
pub const fn run() -> Result<(), pos_owner_bridge::BridgeError> {
    Err(pos_owner_bridge::BridgeError::Unavailable(
        pos_owner_bridge::UnavailableCode::PlatformUnsupported,
    ))
}
