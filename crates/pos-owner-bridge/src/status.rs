//! Bridge status and the checks that admit a new ceremony.

use crate::{BridgeError, QuarantineCode, UnavailableCode};

/// What the bridge can do right now.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeStatus {
    /// A ceremony may start.
    Ready,
    /// A ceremony is running.
    Busy,
    /// Cleanup is pending; every ceremony and owner operation is refused.
    Quarantined(QuarantineCode),
    /// The surface cannot run ceremonies until configuration changes or the process restarts.
    Unavailable(UnavailableCode),
}

impl BridgeStatus {
    /// Admit a new ceremony only from `Ready`.
    ///
    /// # Errors
    ///
    /// Returns the quarantine or unavailability that refuses the ceremony; a running ceremony
    /// refuses with `Unavailable(InterfaceUnavailable)`.
    pub const fn admission(self) -> Result<(), BridgeError> {
        match self {
            Self::Ready => Ok(()),
            Self::Busy => Err(BridgeError::Unavailable(
                UnavailableCode::InterfaceUnavailable,
            )),
            Self::Quarantined(code) => Err(BridgeError::Quarantine(code)),
            Self::Unavailable(code) => Err(BridgeError::Unavailable(code)),
        }
    }

    /// The status after a finished operation that failed with `error`.
    #[must_use]
    pub const fn after(error: Option<BridgeError>) -> Self {
        match error {
            Some(BridgeError::Unavailable(
                code @ (UnavailableCode::LoopbackChanged
                | UnavailableCode::AssetIntegrity
                | UnavailableCode::GenerationExhausted),
            )) => Self::Unavailable(code),
            Some(BridgeError::Quarantine(code)) => Self::Quarantined(code),
            _ => Self::Ready,
        }
    }
}
