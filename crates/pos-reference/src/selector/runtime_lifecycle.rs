//! The provider-neutral port through which the root selector owns the
//! provider runtime's lifecycle (ADR-069 R11 §5.0, R12 §4.2).
//!
//! The selector allocates a `ProviderRuntimeSlot` before any provider
//! process exists and asks the port to start exactly one runtime for it. The
//! port reports typed observations. An observation is never a proof: the
//! selector checks each one against its own request and against the kernel
//! (`/proc`) before it trusts the process.
//!
//! This module defines no systemd, bus or async runtime type. `pos-sandboxd`
//! implements the port as `SystemdProviderLifecycle`, and only the
//! `apps/pos-root-selector` package composes it (R12 §3).

use std::fs::File;
use std::io::{self, Read};
use std::num::NonZeroU64;
use std::path::Path;
use std::time::Instant;

use rustix::net::{connect, socket_with, AddressFamily, SocketAddrUnix, SocketFlags, SocketType};

use crate::provider_admission::AdmittedProviderBinary;
use crate::selector::installation::authority::{fresh_selector_id, ProviderRuntimeSlot};
use crate::selector::recovery::{
    PreviousRuntimeObservation, PreviousRuntimeTarget, RecoveryPeerLaunch, RecoveryPeerObservation,
    RecoverySlotObservation, RecoverySlotTarget,
};
use crate::selector::SelectorBoundaryError;

const MAX_CGROUP_PATH_BYTES: usize = 4096;

/// A fresh per-call value that binds one observation to one port call.
///
/// Only the selector draws one. Outside this crate it can only be echoed back:
/// the tuple field is private, so it cannot be constructed.
///
/// ```compile_fail,E0423
/// use pos_reference::selector::runtime_lifecycle::ObservationChallenge;
///
/// let _ = ObservationChallenge([7; 16]);
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservationChallenge([u8; 16]);

impl ObservationChallenge {
    /// Draw one fresh nonzero challenge from the selector's entropy source.
    pub(crate) fn fresh() -> Result<Self, SelectorBoundaryError> {
        fresh_selector_id().map(Self)
    }

    /// A fixed challenge for adapter tests in other crates.
    #[cfg(any(test, feature = "test-support"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[doc(hidden)]
    #[must_use]
    pub const fn for_test(value: [u8; 16]) -> Self {
        Self(value)
    }
}

/// A cgroup2 path relative to the cgroup2 mount root.
///
/// It is absolute and normalized: it starts with `/`, has no empty, `.` or
/// `..` component, no trailing `/` (except the root itself) and no NUL byte.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CgroupPath(String);

impl CgroupPath {
    /// Validate one manager- or kernel-reported cgroup path.
    ///
    /// # Errors
    /// Returns [`ProviderLifecycleError::Contradiction`] for a path that is not
    /// absolute and normalized, or that is longer than the kernel path bound.
    pub fn new(path: &str) -> Result<Self, ProviderLifecycleError> {
        let normalized = path == "/"
            || (path.starts_with('/')
                && path
                    .split('/')
                    .skip(1)
                    .all(|part| !part.is_empty() && part != "." && part != ".."));
        if normalized && path.len() < MAX_CGROUP_PATH_BYTES && !path.contains('\0') {
            Ok(Self(path.to_owned()))
        } else {
            Err(ProviderLifecycleError::Contradiction)
        }
    }

    /// The validated path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One selector-allocated runtime slot that the port must start.
///
/// Only the selector builds a target, from the slot it allocated before any
/// provider process exists and from the SIC1 kind-11 provider binary it
/// authenticated.
#[derive(Debug)]
pub struct RuntimeSlotTarget<'a> {
    challenge: ObservationChallenge,
    runtime_instance_id: [u8; 16],
    lifecycle_scope_id: [u8; 16],
    provider_binary_path: &'a str,
    provider_binary_digest: [u8; 32],
}

impl<'a> RuntimeSlotTarget<'a> {
    pub(crate) fn new(
        challenge: ObservationChallenge,
        slot: &ProviderRuntimeSlot,
        binary: &'a AdmittedProviderBinary,
    ) -> Self {
        Self {
            challenge,
            runtime_instance_id: slot.runtime_instance_id(),
            lifecycle_scope_id: slot.lifecycle_scope_id(),
            provider_binary_path: binary.path(),
            provider_binary_digest: binary.digest(),
        }
    }

    /// A target for adapter tests in other crates.
    #[cfg(any(test, feature = "test-support"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[doc(hidden)]
    #[must_use]
    pub const fn for_test(
        challenge: ObservationChallenge,
        runtime_instance_id: [u8; 16],
        lifecycle_scope_id: [u8; 16],
        provider_binary_path: &'a str,
        provider_binary_digest: [u8; 32],
    ) -> Self {
        Self {
            challenge,
            runtime_instance_id,
            lifecycle_scope_id,
            provider_binary_path,
            provider_binary_digest,
        }
    }

    /// The challenge the observation must echo.
    #[must_use]
    pub const fn challenge(&self) -> ObservationChallenge {
        self.challenge
    }

    /// The selector-allocated runtime-instance ID. ADR-069 R12 §4.2 fixes
    /// this field of the target; the slot binds it into SIR1.
    #[must_use]
    pub const fn runtime_instance_id(&self) -> [u8; 16] {
        self.runtime_instance_id
    }

    /// The selector-allocated lifecycle-scope ID, which names the unit.
    #[must_use]
    pub const fn lifecycle_scope_id(&self) -> [u8; 16] {
        self.lifecycle_scope_id
    }

    /// The SIC1 kind-11 object path, `/var/lib/pigloros/sandbox/providers/<hex digest>`.
    #[must_use]
    pub const fn provider_binary_path(&self) -> &'a str {
        self.provider_binary_path
    }

    /// The BLAKE3 content digest of the SIC1 kind-11 provider binary.
    #[must_use]
    pub const fn provider_binary_digest(&self) -> [u8; 32] {
        self.provider_binary_digest
    }
}

/// What the port reports after it started one runtime and saw it ready.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartedRuntimeObservation {
    challenge: ObservationChallenge,
    lifecycle_scope_id: [u8; 16],
    main_pid: NonZeroU64,
    main_start_time_ticks: u64,
    control_group: CgroupPath,
}

impl StartedRuntimeObservation {
    /// Record one started runtime as the adapter observed it.
    #[must_use]
    pub const fn new(
        challenge: ObservationChallenge,
        lifecycle_scope_id: [u8; 16],
        main_pid: NonZeroU64,
        main_start_time_ticks: u64,
        control_group: CgroupPath,
    ) -> Self {
        Self {
            challenge,
            lifecycle_scope_id,
            main_pid,
            main_start_time_ticks,
            control_group,
        }
    }

    /// The echoed challenge.
    #[must_use]
    pub const fn challenge(&self) -> ObservationChallenge {
        self.challenge
    }

    /// The lifecycle-scope ID of the started unit.
    #[must_use]
    pub const fn lifecycle_scope_id(&self) -> [u8; 16] {
        self.lifecycle_scope_id
    }

    /// The unit's reported `MainPID`.
    #[must_use]
    pub const fn main_pid(&self) -> NonZeroU64 {
        self.main_pid
    }

    /// The main process's `/proc/<pid>/stat` start-time ticks.
    #[must_use]
    pub const fn main_start_time_ticks(&self) -> u64 {
        self.main_start_time_ticks
    }

    /// The unit's reported `ControlGroup`.
    #[must_use]
    pub const fn control_group(&self) -> &CgroupPath {
        &self.control_group
    }
}

/// What the port reports after it stopped every stale runtime and recovery unit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaleUnitsObservation {
    challenge: ObservationChallenge,
    stopped_unit_count: usize,
}

impl StaleUnitsObservation {
    /// Record one completed stale-unit termination.
    #[must_use]
    pub const fn new(challenge: ObservationChallenge, stopped_unit_count: usize) -> Self {
        Self {
            challenge,
            stopped_unit_count,
        }
    }

    /// The echoed challenge.
    #[must_use]
    pub const fn challenge(&self) -> ObservationChallenge {
        self.challenge
    }

    /// How many loaded units were stopped and proven unloaded. ADR-069 R12
    /// §4.2 fixes this field of the observation.
    #[must_use]
    pub const fn stopped_unit_count(&self) -> usize {
        self.stopped_unit_count
    }
}

/// Closed port failures. Every one keeps admission closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProviderLifecycleError {
    /// The lifecycle manager could not be reached or refused the operation.
    #[error("provider lifecycle manager unavailable")]
    Unavailable,
    /// A provider-owned unit, process or cgroup remains.
    #[error("a provider-owned resource remains")]
    ResidualResource,
    /// A resource that the target does not own was found.
    ///
    /// Part of the normative error set of ADR-069 R12 §4.2; #349's
    /// `terminate_previous_runtime` returns it for a foreign unit or intent
    /// (R12 §7.1 steps 2 and 6).
    #[error("a resource not owned by the target was found")]
    ForeignResource,
    /// The manager's or the kernel's evidence contradicts itself or the target.
    #[error("contradictory lifecycle evidence")]
    Contradiction,
    /// The operation did not finish before its deadline.
    #[error("lifecycle deadline exceeded")]
    DeadlineExceeded,
}

/// The selector-owned provider-runtime lifecycle (ADR-069 R11 §5.0).
///
/// Every call is synchronous and bounded by an absolute deadline. An `Ok`
/// result is an observation the selector still checks; an `Err` keeps
/// admission closed. The first two operations serve normal open (#1399);
/// the last three serve root-owned recovery (#349, R12 §6).
pub trait ProviderLifecyclePort {
    /// Stop every loaded `pigloros-provider-runtime-*` and
    /// `pigloros-provider-recovery-*` unit, and prove each unloaded and its
    /// cgroup absent (R11 §5.0 step 2, R12 O11).
    ///
    /// The selector calls it only while no SIR1 is pending, before it
    /// allocates a slot.
    ///
    /// # Errors
    /// Fails closed if any unit cannot be stopped, a unit or cgroup remains,
    /// the manager is unavailable or the deadline passes.
    fn terminate_stale_runtimes(
        &self,
        challenge: ObservationChallenge,
        deadline: Instant,
    ) -> Result<StaleUnitsObservation, ProviderLifecycleError>;

    /// Start the runtime unit of `slot` and wait until it is ready (R11 §5.0
    /// steps 5 to 7, §5.2).
    ///
    /// # Errors
    /// Fails closed if the start is refused, the start job does not end
    /// `done`, the manager's evidence is inconsistent or the deadline passes.
    fn start_provider_runtime(
        &self,
        slot: &RuntimeSlotTarget<'_>,
        deadline: Instant,
    ) -> Result<StartedRuntimeObservation, ProviderLifecycleError>;

    /// Terminate the previous runtime unit of one pending SIR1, prove no
    /// foreign provider unit loaded, and run the cleanup part of restart
    /// reconciliation over its attempts (R12 §7.1). The registry lock is
    /// released before it returns.
    ///
    /// # Errors
    /// Fails closed for a foreign unit or intent, any residue, an
    /// unavailable manager or registry, and a missed deadline.
    fn terminate_previous_runtime(
        &self,
        target: &PreviousRuntimeTarget<'_>,
        deadline: Instant,
    ) -> Result<PreviousRuntimeObservation, ProviderLifecycleError>;

    /// Stop the recovery-peer unit of `target`, if loaded, prove it unloaded
    /// and report its control group (R12 §7.3). It is idempotent.
    ///
    /// # Errors
    /// Fails closed if the unit cannot be stopped or remains, the manager is
    /// unavailable or the deadline passes.
    fn reconcile_recovery_slot(
        &self,
        target: &RecoverySlotTarget<'_>,
        deadline: Instant,
    ) -> Result<RecoverySlotObservation, ProviderLifecycleError>;

    /// Start the one recovery-peer unit of `launch` and wait until it is
    /// ready (R12 §7.3 items 2 to 4).
    ///
    /// # Errors
    /// Fails closed if the start is refused, the start job does not end
    /// `done`, the manager's evidence is inconsistent or the deadline passes.
    fn start_recovery_peer(
        &self,
        launch: &RecoveryPeerLaunch<'_>,
        deadline: Instant,
    ) -> Result<RecoveryPeerObservation, ProviderLifecycleError>;
}

/// The `/proc/<pid>/stat` start-time ticks (field 22) of one live process.
///
/// # Errors
/// Returns [`ProviderLifecycleError::Contradiction`] when the PID is out of
/// range, no such process exists or its stat record is malformed.
pub fn process_start_time_ticks(pid: NonZeroU64) -> Result<u64, ProviderLifecycleError> {
    crate::provider_transport::process_start_time_ticks(pid)
        .map_err(|_| ProviderLifecycleError::Contradiction)
}

/// The unified cgroup2 path of one live process, from `/proc/<pid>/cgroup`.
///
/// # Errors
/// Returns [`SelectorBoundaryError::ArtifactInvalid`] when the record cannot
/// be read or is not one cgroup2 membership line.
pub(crate) fn process_control_group(pid: NonZeroU64) -> Result<String, SelectorBoundaryError> {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)
        .and_then(|text| unified_cgroup(&text).map(str::to_owned))
}

/// The one cgroup2 membership line `0::<path>` of a cgroup2-only host.
pub(crate) fn unified_cgroup(text: &str) -> Result<&str, SelectorBoundaryError> {
    text.strip_prefix("0::")
        .and_then(|rest| rest.strip_suffix('\n'))
        .filter(|path| !path.contains('\n'))
        .ok_or(SelectorBoundaryError::ArtifactInvalid)
}

/// The BLAKE3 digest of `/proc/<pid>/exe`, the process's own executable.
///
/// # Errors
/// Returns a closed error when the executable cannot be opened or read, or
/// its length is not `length`.
pub(crate) fn proc_executable_digest(
    pid: NonZeroU64,
    length: u64,
) -> Result<[u8; 32], SelectorBoundaryError> {
    File::open(format!("/proc/{pid}/exe"))
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)
        .and_then(|executable| bounded_digest(executable, length))
}

/// The BLAKE3 digest of exactly `length` bytes of `source`, read at most
/// `length + 1` bytes deep.
///
/// # Errors
/// Returns [`SelectorBoundaryError::Io`] for a read failure and
/// [`SelectorBoundaryError::ArtifactInvalid`] for another length.
pub(crate) fn bounded_digest(
    source: impl Read,
    length: u64,
) -> Result<[u8; 32], SelectorBoundaryError> {
    let mut hasher = blake3::Hasher::new();
    let mut bounded = source.take(length.saturating_add(1));
    let copied = io::copy(&mut bounded, &mut hasher);
    copied
        .map_err(|_| SelectorBoundaryError::Io)
        .and_then(|copied| {
            if copied == length {
                Ok(*hasher.finalize().as_bytes())
            } else {
                Err(SelectorBoundaryError::ArtifactInvalid)
            }
        })
}

/// A non-blocking `connect()` must fail with exactly `ECONNREFUSED`: no
/// process listens on the leaf any more.
///
/// # Errors
/// Returns [`SelectorBoundaryError::ArtifactInvalid`] for any other outcome
/// and [`SelectorBoundaryError::Io`] when no socket can be created.
pub(crate) fn require_refused(path: &Path) -> Result<(), SelectorBoundaryError> {
    SocketAddrUnix::new(path)
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)
        .and_then(|address| {
            socket_with(
                AddressFamily::UNIX,
                SocketType::STREAM,
                SocketFlags::CLOEXEC.union(SocketFlags::NONBLOCK),
                None,
            )
            .map_err(|_| SelectorBoundaryError::Io)
            .and_then(|socket| match connect(&socket, &address) {
                Err(rustix::io::Errno::CONNREFUSED) => Ok(()),
                _ => Err(SelectorBoundaryError::ArtifactInvalid),
            })
        })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn cgroup_paths_must_be_absolute_and_normalized() -> TestResult {
        for valid in ["/", "/system.slice", "/system.slice/a-b.service"] {
            assert_eq!(CgroupPath::new(valid)?.as_str(), valid);
        }
        let long = format!("/{}", "a".repeat(MAX_CGROUP_PATH_BYTES - 2));
        assert_eq!(
            CgroupPath::new(&long)?.as_str().len(),
            MAX_CGROUP_PATH_BYTES - 1
        );
        let too_long = format!("/{}", "a".repeat(MAX_CGROUP_PATH_BYTES - 1));
        for invalid in [
            "",
            "system.slice",
            "//",
            "/system.slice/",
            "/a//b",
            "/a/./b",
            "/a/../b",
            "/.",
            "/..",
            "/a\0b",
            too_long.as_str(),
        ] {
            assert_eq!(
                CgroupPath::new(invalid),
                Err(ProviderLifecycleError::Contradiction),
                "{invalid:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn challenges_are_fresh_and_nonzero() -> TestResult {
        let first = ObservationChallenge::fresh()?;
        let second = ObservationChallenge::fresh()?;
        assert_ne!(first, second);
        assert_ne!(first.0, [0; 16]);
        Ok(())
    }

    #[test]
    fn observations_report_exactly_what_the_adapter_recorded() -> TestResult {
        let challenge = ObservationChallenge::for_test([3; 16]);
        let pid = NonZeroU64::new(41).ok_or("zero pid")?;
        let started = StartedRuntimeObservation::new(
            challenge,
            [4; 16],
            pid,
            77,
            CgroupPath::new("/system.slice/x.service")?,
        );
        assert_eq!(started.challenge(), challenge);
        assert_eq!(started.lifecycle_scope_id(), [4; 16]);
        assert_eq!(started.main_pid(), pid);
        assert_eq!(started.main_start_time_ticks(), 77);
        assert_eq!(started.control_group().as_str(), "/system.slice/x.service");

        let stale = StaleUnitsObservation::new(challenge, 2);
        assert_eq!(stale.challenge(), challenge);
        assert_eq!(stale.stopped_unit_count(), 2);
        Ok(())
    }

    #[test]
    fn targets_carry_the_allocated_slot_and_the_admitted_binary() -> TestResult {
        let (_, admitted, _) = crate::selector::installation::tests::root_selector_fixture()?;
        let slot = ProviderRuntimeSlot::allocate(&admitted)?;
        let binary = crate::provider_admission::admitted_provider_binary(&admitted)?;
        let challenge = ObservationChallenge::for_test([5; 16]);
        let target = RuntimeSlotTarget::new(challenge, &slot, &binary);
        assert_eq!(target.challenge(), challenge);
        assert_eq!(target.runtime_instance_id(), slot.runtime_instance_id());
        assert_eq!(target.lifecycle_scope_id(), slot.lifecycle_scope_id());
        assert_eq!(target.provider_binary_path(), binary.path());
        assert_eq!(target.provider_binary_digest(), binary.digest());
        assert_ne!(target.runtime_instance_id(), target.lifecycle_scope_id());
        Ok(())
    }

    #[test]
    fn start_ticks_are_read_from_the_live_process() -> TestResult {
        let own = NonZeroU64::new(u64::from(std::process::id())).ok_or("zero pid")?;
        let ticks = process_start_time_ticks(own)?;
        assert_eq!(process_start_time_ticks(own)?, ticks);
        let out_of_range = NonZeroU64::new(u64::from(u32::MAX) + 1).ok_or("zero pid")?;
        assert_eq!(
            process_start_time_ticks(out_of_range),
            Err(ProviderLifecycleError::Contradiction)
        );
        Ok(())
    }
}
