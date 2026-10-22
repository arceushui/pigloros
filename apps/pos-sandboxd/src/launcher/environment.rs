//! The systemd launch environment the launcher reads before it trusts any
//! inherited descriptor.

use rustix::process::getpid;

use super::error::LauncherError;

/// Most descriptors any layout carries (Local: proxy plus release).
const MAX_DESCRIPTORS: u32 = 2;

/// Values taken from the process environment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LaunchEnvironment {
    /// The 16 bytes decoded from systemd's `INVOCATION_ID`.
    pub(crate) launch_instance_id: [u8; 16],
    /// Validated `LISTEN_FDS`, so descriptor adoption is bounded.
    pub(crate) descriptor_count: u32,
}

impl LaunchEnvironment {
    /// Read the real process environment.
    pub(crate) fn from_process() -> Result<Self, LauncherError> {
        Self::read(
            |name| std::env::var(name).ok(),
            u32::try_from(getpid().as_raw_nonzero().get()).unwrap_or(0),
        )
    }

    /// Validate `LISTEN_PID`, `LISTEN_FDS` and `INVOCATION_ID`.
    ///
    /// `LISTEN_PID` must be this process; `LISTEN_FDS` must be 1 or 2, so the
    /// adoption below can never allocate for an attacker-sized count.
    pub(crate) fn read(
        variable: impl Fn(&str) -> Option<String>,
        own_pid: u32,
    ) -> Result<Self, LauncherError> {
        let number = |name: &str| variable(name).and_then(|text| text.parse::<u32>().ok());
        let listen_pid = number("LISTEN_PID");
        let descriptor_count = number("LISTEN_FDS");
        let launch_instance_id = variable("INVOCATION_ID").and_then(|text| invocation_id(&text));
        match (listen_pid, descriptor_count, launch_instance_id) {
            (Some(pid), Some(count), Some(launch_instance_id))
                if pid == own_pid && (1..=MAX_DESCRIPTORS).contains(&count) =>
            {
                Ok(Self {
                    launch_instance_id,
                    descriptor_count: count,
                })
            }
            _ => Err(LauncherError::Environment),
        }
    }
}

/// The nonzero 16 bytes of a 32-character lowercase hexadecimal ID.
fn invocation_id(text: &str) -> Option<[u8; 16]> {
    let digits = text.as_bytes();
    if digits.len() != 32 {
        return None;
    }
    let mut id = [0_u8; 16];
    for (byte, pair) in id.iter_mut().zip(digits.chunks_exact(2)) {
        *byte = (super::nibble(pair[0])? << 4) | super::nibble(pair[1])?;
    }
    (id != [0; 16]).then_some(id)
}
