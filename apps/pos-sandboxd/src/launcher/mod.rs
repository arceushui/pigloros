//! The closed launch-barrier mode of the provider binary (ADR-069 "Trusted
//! launcher and trust binding", #441).
//!
//! The provider starts this binary as the transient unit's main process with
//! the single mode argument `launch-barrier <lpv1-hex>`. The launcher performs
//! no admission, policy interpretation or cleanup. It:
//!
//! 1. decodes the exact LPV1 launch parameters;
//! 2. adopts the descriptors systemd passes at fixed numbers and validates
//!    their names, types, count, order and the absence of any higher
//!    descriptor against the expected layout;
//! 3. accepts the release channel only if `SO_PEERCRED` identifies the root
//!    provider;
//! 4. opens, checks and hashes the adapter beneath the activated root and its
//!    own executable;
//! 5. sends exactly one `ReadyV1` with `SCM_CREDENTIALS`;
//! 6. waits for exactly one `ReleaseV1` and checks its attempt, nonce,
//!    `ReadyV1` digest and monotonic deadline; and
//! 7. closes the release channel and replaces its process image with the held
//!    adapter descriptor and an empty environment.
//!
//! Any other outcome, including EOF, ends the process without running adapter
//! bytes. This module is linked into the same binary as the provider but its
//! code path never calls the admission or verifier modules (owner decision
//! Q9.11, enforced by a hosted source test). Everything environmental sits
//! behind a crate-private host port; only the process host
//! reads the real process.

mod adapter;
mod barrier;
mod descriptors;
mod environment;
mod error;
mod exec;
mod host;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;

pub use error::{LauncherError, ReleaseDefect};

use std::convert::Infallible;

use pos_reference::sandbox_provider_protocol::LaunchParameters;

use self::{environment::LaunchEnvironment, host::ProcessHost};

/// The one launcher-mode argument.
pub const LAUNCH_BARRIER_MODE: &str = "launch-barrier";

/// Run the launcher against the real process. It never returns on success:
/// the process image is replaced by the released adapter. The returned error
/// is the reason the adapter was not executed.
#[must_use]
pub fn run_launch_barrier(lpv1_hex: &str) -> LauncherError {
    let Err(error) = launch(lpv1_hex);
    error
}

fn launch(lpv1_hex: &str) -> Result<Infallible, LauncherError> {
    let parameters = decode_parameters(lpv1_hex)?;
    let (environment, inherited) = LaunchEnvironment::from_process().and_then(|environment| {
        descriptors::adopt(&environment).map(|inherited| (environment, inherited))
    })?;
    barrier::run(&ProcessHost::root(), &environment, &parameters, inherited)
}

/// Decode the lowercase-hexadecimal LPV1 argument.
fn decode_parameters(lpv1_hex: &str) -> Result<LaunchParameters, LauncherError> {
    decode_hex(lpv1_hex)
        .and_then(|bytes| LaunchParameters::from_canonical_cbor(&bytes).ok())
        .ok_or(LauncherError::Parameters)
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let digits = text.as_bytes();
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    digits
        .chunks_exact(2)
        .map(|pair| Some((nibble(pair[0])? << 4) + nibble(pair[1])?))
        .collect()
}

const fn nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}
