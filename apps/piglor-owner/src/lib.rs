//! Owner application entry point.

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
