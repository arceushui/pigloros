//! Owner process hardening (ADR-110 E20 LP5, LT3): non-dumpable, and no core files.
//!
//! A non-dumpable process refuses `ptrace` and `/proc/<pid>/mem` access from other processes of
//! the same user that lack `CAP_SYS_PTRACE`, and `RLIMIT_CORE` of 0 means a crash leaves no core
//! file that holds a PIN or a PRF output. `mlock` is not used: swap and hibernation stay the
//! ADR-110 T8 residual.

use rustix::process::{set_dumpable_behavior, setrlimit, DumpableBehavior, Resource, Rlimit};

/// The process could not be hardened. It carries no detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HardeningError;

/// Make the calling process non-dumpable and set both `RLIMIT_CORE` limits to 0.
///
/// The hard limit is lowered as well, so nothing in this process can raise the soft limit again.
///
/// # Errors
///
/// Returns [`HardeningError`] when the kernel refuses either setting.
pub fn harden_process() -> Result<(), HardeningError> {
    set_dumpable_behavior(DumpableBehavior::NotDumpable)
        .and_then(|()| {
            setrlimit(
                Resource::Core,
                Rlimit {
                    current: Some(0),
                    maximum: Some(0),
                },
            )
        })
        .or(Err(HardeningError))
}
