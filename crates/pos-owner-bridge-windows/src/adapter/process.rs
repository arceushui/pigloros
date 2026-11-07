#![cfg(windows)]
#![forbid(unsafe_code)]

use pos_owner_bridge::{BridgeError, ProbeResult, ProcessIdentity, ProcessProbe, UnavailableCode};
use pos_owner_bridge_codec::ImagePathSha256;

/// Query a complete process identity without exposing native diagnostics.
///
/// The image digest covers the query's exact UTF-16LE path. Only a successful
/// observation can supply an identity for a new cleanup record.
///
/// # Errors
///
/// Returns `Unavailable(InterfaceUnavailable)` on absence or incomplete inspection.
pub fn process_identity(pid: u32) -> Result<ProcessIdentity, BridgeError> {
    crate::Native::inspect_process(pid)
        .ok()
        .flatten()
        .ok_or(BridgeError::Unavailable(
            UnavailableCode::InterfaceUnavailable,
        ))
}

/// ADR-125 restart probe using only limited-information process queries.
#[derive(Debug, Default)]
pub struct WindowsProcessProbe;

impl ProcessProbe for WindowsProcessProbe {
    fn probe(&mut self, pid: u32, created: u64, image: &ImagePathSha256) -> ProbeResult {
        match crate::Native::inspect_process(pid) {
            Ok(Some(identity)) => {
                if identity.creation_filetime == created && identity.image_path_sha256 == *image {
                    ProbeResult::Present
                } else {
                    ProbeResult::Absent
                }
            }
            Ok(None) => ProbeResult::Absent,
            Err(()) => ProbeResult::Indeterminate,
        }
    }
}
