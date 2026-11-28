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
//! 3. accepts the release channel only if the pidfs identity of its
//!    `SO_PEERPIDFD` is the provider's, which LPV1 records;
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
// Public so that its crate-visible reader is reachable from the rest of the
// provider without Clippy's `redundant_pub_crate` lint; it exports nothing.
#[doc(hidden)]
pub mod clock;
mod descriptors;
mod environment;
mod error;
mod exec;
mod host;
// Public for the same reason as `clock`; the provider's barrier reads its own pidfd identity here.
#[doc(hidden)]
pub mod process_identity;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;

pub use error::{AdapterFault, LauncherError, ReleaseDefect};

use std::convert::Infallible;

use pos_reference::sandbox_provider_protocol::LaunchParameters;

use self::{environment::LaunchEnvironment, host::ProcessHost};

/// The one launcher-mode argument.
pub const LAUNCH_BARRIER_MODE: &str = "launch-barrier";

/// The exit status of a launcher that did not run the adapter: one status from 64 per closed
/// failure.
///
/// The launcher's standard error is `/dev/null` (ADR-069 R10 section 4.2), so a failure leaves no
/// diagnostic in the unit. The status is the only trace of the reason, and the unit's
/// `ExecMainStatus` shows it. The set is closed and carries no path, descriptor or record byte:
///
/// | Status | Failure |
/// |---|---|
/// | 64 | the launch parameters are not a valid LPV1 |
/// | 65 | the launch environment is invalid |
/// | 66 | the inherited descriptor layout is invalid |
/// | 67 | the release channel peer is not the provider |
/// | 68 | the adapter is not a regular file |
/// | 69 | the launcher or adapter identity could not be read |
/// | 70 | `ReadyV1` could not be sent |
/// | 71 | `ReleaseV1` was not received |
/// | 72 | `ReleaseV1` was rejected |
/// | 73 | the adapter exec failed |
/// | 74 | the adapter's ELF header could not be read |
/// | 75 | the adapter is not a 64-bit little-endian ELF executable for this architecture |
/// | 100 + n | the adapter could not be opened beneath the root, with OS error number n (at most 27) |
#[must_use]
pub fn failure_status(error: &LauncherError) -> u8 {
    match error {
        LauncherError::Parameters => 64,
        LauncherError::Environment => 65,
        LauncherError::Layout => 66,
        LauncherError::Peer => 67,
        LauncherError::Adapter(fault) => adapter_status(*fault),
        LauncherError::Identity => 69,
        LauncherError::Ready => 70,
        LauncherError::ReleaseUnavailable => 71,
        LauncherError::Release(_) => 72,
        LauncherError::Exec(_) => 73,
    }
}

/// The exit status of an adapter that could not be held (see [`failure_status`]).
fn adapter_status(fault: AdapterFault) -> u8 {
    match fault {
        AdapterFault::NotRegular => 68,
        AdapterFault::Unreadable => 74,
        AdapterFault::NotNative => 75,
        // The mask keeps the sum below 256 for any error number (Linux's are at most 133).
        AdapterFault::Open(number) => 100 + u8::try_from(number & 0x7f).unwrap_or_default(),
    }
}

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
    barrier::run(&ProcessHost, &environment, &parameters, inherited)
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
