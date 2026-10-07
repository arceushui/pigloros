//! The bounded release CAS loop and its legal-successor rule (ADR-110 §5.7).

use pos_owner_bridge_codec::ControlState;

use crate::{BridgeError, OwnerWebSurface, ProtocolCode, SurfaceError};

/// The hard bound on release attempts: twice the protocol maximum of four.
pub const MAX_RELEASE_ATTEMPTS: u8 = 8;

/// Which failures may be void because the page has already advanced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseMode {
    /// A timing failure: a state past `EMPTY` voids the failure instead of being overwritten.
    Timing,
    /// Every other failure and every end of ceremony: always continue to `RELEASE_REQUESTED`.
    Terminal,
}

const UNEXPECTED_STATE: BridgeError = BridgeError::Protocol(ProtocolCode::UnexpectedState);

/// Whether an honest page can move from `from` to `to` in one or more transitions.
#[must_use]
pub const fn reachable(from: ControlState, to: ControlState) -> bool {
    use ControlState::{Empty, Failed, Ready, Received, Writing};
    match from {
        Empty => matches!(to, Received | Writing | Ready | Failed),
        Received => matches!(to, Writing | Ready | Failed),
        Writing => matches!(to, Ready | Failed),
        _ => false,
    }
}

/// Load and decode the reply state word. An undecodable value is `UnexpectedState`.
///
/// # Errors
///
/// Returns the surface's classified failure, or `Protocol(UnexpectedState)` for a value
/// outside `0..=7`.
pub fn read_state(surface: &dyn OwnerWebSurface) -> Result<ControlState, BridgeError> {
    let word = surface.reply_load_state().map_err(SurfaceError::error)?;
    ControlState::try_from(word).or(Err(UNEXPECTED_STATE))
}

/// One attempt of the release loop: `None` means the CAS lost and the loop continues.
fn attempt(
    surface: &dyn OwnerWebSurface,
    previous: &mut ControlState,
    first: bool,
    mode: ReleaseMode,
) -> Option<Result<Option<ControlState>, BridgeError>> {
    let observed = match read_state(surface) {
        Ok(observed) => observed,
        Err(error) => return Some(Err(error)),
    };
    let legal = if first {
        observed == *previous || reachable(*previous, observed)
    } else {
        reachable(*previous, observed)
    };
    if !legal {
        return Some(Err(UNEXPECTED_STATE));
    }
    if mode == ReleaseMode::Timing && observed != ControlState::Empty {
        return Some(Ok(Some(observed)));
    }
    match surface.reply_compare_exchange(observed as u32, ControlState::ReleaseRequested as u32) {
        Ok(true) => Some(Ok(None)),
        Ok(false) => {
            *previous = observed;
            None
        }
        Err(error) => Some(Err(error.error())),
    }
}

/// Move the reply state to `RELEASE_REQUESTED` with a bounded strong-CAS loop.
///
/// `known` is the freshest state the host has observed. Returns `Ok(None)` once the CAS won,
/// and `Ok(Some(state))` in [`ReleaseMode::Timing`] when the page had already advanced to
/// `state`. The first read must equal or be reachable from `known`; every re-read after a failed
/// CAS must be strictly reachable from the previous observation. The legal-successor rule is
/// acyclic, so a legal sequence of reads ends within four attempts; the hard bound of eight is
/// the ADR's margin for a renderer that stores arbitrary values.
///
/// # Errors
///
/// Returns `Protocol(UnexpectedState)` after eight attempts or on an illegal observation, or
/// the surface's classified failure. The caller must then stop using the state word.
pub fn release_loop(
    surface: &dyn OwnerWebSurface,
    known: ControlState,
    mode: ReleaseMode,
) -> Result<Option<ControlState>, BridgeError> {
    let mut previous = known;
    (0..MAX_RELEASE_ATTEMPTS)
        .find_map(|index| attempt(surface, &mut previous, index == 0, mode))
        .unwrap_or(Err(UNEXPECTED_STATE))
}
