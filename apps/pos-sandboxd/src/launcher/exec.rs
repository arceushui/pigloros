//! The launcher's final step: replacing the process image with the held,
//! admitted adapter descriptor (ADR-069 "Trusted launcher and trust binding").
//!
//! This is the only production file allowed to name the kernel's
//! descriptor-exec call (owner decision Q9.9). It has exactly one call, on a
//! held descriptor, with `AT_EMPTY_PATH`, an explicit argument vector and an
//! empty environment. ADR-087 A.3 governs the daemon mode; this call creates no
//! process and the launcher holds no mountfsd or system-bus descriptor. A
//! hosted source test (`provider_process_creation_public`) enforces all of
//! this.

use std::{ffi::CString, fs::File, io};

use nix::{fcntl::AtFlags, unistd::execveat};

/// Replace this process image with the adapter held open as `adapter`.
///
/// The call returns only on failure, with the operating-system error.
pub(super) fn replace_process_image(adapter: &File, argv: &[CString]) -> io::Error {
    let environment: [CString; 0] = [];
    let Err(errno) = execveat(adapter, c"", argv, &environment, AtFlags::AT_EMPTY_PATH);
    io::Error::from_raw_os_error(errno as i32)
}
