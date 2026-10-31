//! Backend-specific components of the ADR-069 systemd Sandbox Provider Adapter.
//!
//! This library does not implement the provider daemon or grant admission. Its
//! binary currently runs only the closed launcher mode ([`launcher`]).
//! The existing signed admission boundary must supply the selected SCS1 digest
//! and architecture before these requested-state components are used.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

#[cfg(target_os = "linux")]
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[cfg(target_os = "linux")]
mod attempt;
#[cfg(target_os = "linux")]
mod attempt_registry;
#[cfg(target_os = "linux")]
mod execute;
mod hardening;
#[cfg(target_os = "linux")]
mod image_activator;
mod kernel_cgroup;
#[cfg(target_os = "linux")]
pub mod launcher;
#[cfg(target_os = "linux")]
mod local_network;
#[cfg(target_os = "linux")]
mod provider_barrier;
#[cfg(target_os = "linux")]
mod release_barrier;
#[cfg(target_os = "linux")]
mod release_signer;
#[cfg(target_os = "linux")]
mod root_attachment;
#[cfg(target_os = "linux")]
mod staging;
mod system_bus;
// Shared by the tests of several modules. Keeping it public, like the sibling
// crates' test support modules, avoids suppressing visibility lints.
#[cfg(all(test, unix))]
#[cfg_attr(coverage_nightly, coverage(off))]
#[doc(hidden)]
pub mod test_fixtures;
mod transient_unit;

#[derive(Debug)]
struct CgroupRoot(std::fs::File);

/// One irreversible execution claim, shared by the exact prepared directory.
#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Default)]
struct ExecutionOwnership(Arc<AtomicBool>);

#[cfg(target_os = "linux")]
impl PartialEq for ExecutionOwnership {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

#[cfg(target_os = "linux")]
impl Eq for ExecutionOwnership {}

#[cfg(target_os = "linux")]
impl ExecutionOwnership {
    /// Close this owner's start permission without releasing admission resources.
    fn close(&self) {
        self.0.store(true, Ordering::Release);
    }

    fn claim(&self) -> Result<(), ExecuteError> {
        self.0
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| ExecuteError::AttemptAlreadyClaimed)
    }
}

/// Facts copied only from the authenticated, retained SIC1 provider binary.
#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LauncherFacts {
    path: String,
    digest: [u8; 32],
    length: u64,
    identity: (u64, u64),
}

#[cfg(target_os = "linux")]
pub use attempt::{ActiveAttempt, AdmittedAttempt};
#[cfg(target_os = "linux")]
pub use execute::{
    execute, AttemptEnding, AttemptExecution, ExecuteError, ExecuteFailure, ExecuteJob,
    LaunchBarrier, ModePlan, NetworkEvidence, ReplayRequest, UnitCgroup, UnitHost, UnitKiller,
    UnitState,
};
#[cfg(target_os = "linux")]
pub use local_network::{
    BoundLocalProxy, CheckedLocal, EstablishedNetwork, FailClosedLocalNetwork, HostServiceChannel,
    HostServiceStream, LocalNetworkPort, LocalProxyBindError, RefusingConnector, ServeError,
    ServedProxy,
};

#[cfg(target_os = "linux")]
pub use attempt_registry::{
    CommittedPlannedAttempt, PlannedAttemptIntent, PreparedAttemptDirectory,
    RecoveredAttemptIntent, RecoveredUnmountedDirectory, RegistryRecoveryEntry,
    SystemdAttemptRecovery, SystemdAttemptRegistry, SystemdAttemptRegistryError,
    UnmountedDirectoryInventory,
};

#[cfg(target_os = "linux")]
pub use image_activator::{
    ActivationImage, ImageActivationError, ImageActivator, MountfsdImageActivator,
    QuarantinedRootMount,
};
#[cfg(target_os = "linux")]
pub use root_attachment::{activate_admitted_root, RootResourceIdentity, VerifiedRootMount};

#[cfg(target_os = "linux")]
pub use provider_barrier::{
    fresh_nonce, AuthorityCheck, BarrierError, BarrierEvidence, ObservedReadback,
    ObservedReadbackUnavailable, ProviderReleaseBarrier, RecheckRefusal, UnitIdentitySource,
};
#[cfg(target_os = "linux")]
pub use release_barrier::{
    release_after_ready, ExpectedLauncherReady, ReleaseBarrierError, ReleaseBinding, ReleaseRecheck,
};
#[cfg(target_os = "linux")]
pub use release_signer::{issue_release, KeyFileReleaseSigner, ReleaseSigner, ReleaseSignerError};
#[cfg(target_os = "linux")]
pub use staging::{
    AdmittedEntry, ControlFloor, StagedInput, StagingCharge, StagingDirectory, StagingError,
    StagingLedger, StagingLimits, StagingUsage, VerifiedStagedInput,
};

pub use hardening::{
    SystemdHardeningProperty, SystemdHardeningReadback, SystemdHardeningReadbackValue,
    SystemdHardeningValue, TransientUnitHardening, TransientUnitHardeningError,
};
pub use kernel_cgroup::{
    AttemptCgroupEmptyBasis, AttemptCgroupEmptyObservation, AttemptCgroupError,
    AttemptLimitEventCounter, AttemptLimitEventDelta, AttemptLimitEventSnapshot,
    AttemptLimitEventSource, BoundAttemptCgroup,
};
#[cfg(target_os = "linux")]
pub use kernel_cgroup::{AttemptShutdownDeadlines, AttemptShutdownError};
pub use system_bus::{
    SystemdAttemptUnitAbsenceObservation, SystemdAttemptUnitObservation, SystemdJobFailure,
    SystemdStartJob, SystemdStopJobCompleted, SystemdTransientUnitTransport,
    SystemdTransientUnitTransportError, SystemdVerifiedStart, TransientServiceUnitName,
    TransientServiceUnitNameError,
};
#[cfg(target_os = "linux")]
pub use system_bus::{SystemdAttemptUnitTeardownError, SystemdAttemptUnitTeardownObservation};
pub use transient_unit::{
    ActivatedRootDirectory, CheckedRoot, LaunchMode, LauncherInvocation, LauncherSource,
    SystemdManagerReadback, SystemdManagerReadbackOnlyProperty, SystemdServiceLimits,
    SystemdServiceLimitsError, SystemdTransientUnitNumericValue, SystemdTransientUnitProperty,
    SystemdTransientUnitReadback, SystemdTransientUnitReadbackValue, SystemdTransientUnitValue,
    TransientUnitLaunchInputs, TransientUnitRequest, TransientUnitRequestError,
};

/// The seven ELM1 limit IDs enforced by systemd service properties.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SystemdOperatingLimitProperty {
    MemoryMax,
    MemorySwapMax,
    TasksMax,
    CpuQuotaPerSecUSec,
    RuntimeMaxUSec,
    LimitNofile,
    LimitFsize,
}

impl SystemdOperatingLimitProperty {
    const ALL: [Self; 7] = [
        Self::MemoryMax,
        Self::MemorySwapMax,
        Self::TasksMax,
        Self::CpuQuotaPerSecUSec,
        Self::RuntimeMaxUSec,
        Self::LimitNofile,
        Self::LimitFsize,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::MemoryMax => "MemoryMax",
            Self::MemorySwapMax => "MemorySwapMax",
            Self::TasksMax => "TasksMax",
            Self::CpuQuotaPerSecUSec => "CPUQuotaPerSecUSec",
            Self::RuntimeMaxUSec => "RuntimeMaxUSec",
            Self::LimitNofile => "LimitNOFILE",
            Self::LimitFsize => "LimitFSIZE",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::MemoryMax => 0,
            Self::MemorySwapMax => 1,
            Self::TasksMax => 2,
            Self::CpuQuotaPerSecUSec => 3,
            Self::RuntimeMaxUSec => 4,
            Self::LimitNofile => 5,
            Self::LimitFsize => 6,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SystemdTransientUnitPropertyKind {
    Hardening(SystemdHardeningProperty),
    Dynamic(SystemdDynamicPropertyKind),
}

/// Per-attempt property identity, distinct from fixed hardening.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SystemdDynamicPropertyKind {
    RootDirectory,
    BindReadOnlyPaths,
    SystemCallFilter,
    RestrictAddressFamilies,
    OperatingLimit(SystemdOperatingLimitProperty),
    FileDescriptorStoreMax,
    ExtraFileDescriptors,
    TemporaryFileSystem,
    ExecStart,
}

impl SystemdTransientUnitPropertyKind {
    const fn name(self) -> &'static str {
        match self {
            Self::Hardening(property) => property.name(),
            Self::Dynamic(property) => property.name(),
        }
    }
}

impl SystemdDynamicPropertyKind {
    const fn name(self) -> &'static str {
        match self {
            Self::RootDirectory => "RootDirectory",
            Self::BindReadOnlyPaths => "BindReadOnlyPaths",
            Self::SystemCallFilter => "SystemCallFilter",
            Self::RestrictAddressFamilies => "RestrictAddressFamilies",
            Self::OperatingLimit(property) => property.name(),
            tail => tail.tail_name(),
        }
    }

    /// The last kinds; `TemporaryFileSystem` is the final one.
    const fn tail_name(self) -> &'static str {
        match self {
            Self::FileDescriptorStoreMax => "FileDescriptorStoreMax",
            Self::ExtraFileDescriptors => "ExtraFileDescriptors",
            Self::ExecStart => "ExecStart",
            _ => "TemporaryFileSystem",
        }
    }
}

trait SystemdTransientUnitPropertyAccess {
    fn kind(&self) -> SystemdTransientUnitPropertyKind;
    fn into_parts(self) -> (&'static str, SystemdTransientUnitValue);
}

use pos_reference::sandbox_provider_protocol::{
    SandboxArchitecture, SandboxProviderProtocolError, SandboxSyscallSet,
};

/// A validated systemd syscall-filter request and its distinct expected readback.
///
/// Fields are private so callers cannot replace validated names or invert the
/// allow-list mode after compiling a selected canonical record.
pub struct SystemCallFilter {
    record: SandboxSyscallSet,
}

/// Closed failures at the syscall-filter requested-state boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SystemCallFilterError {
    /// The selected bytes are not a valid canonical SCS1 record.
    #[error(transparent)]
    InvalidRecord(#[from] SandboxProviderProtocolError),
    /// The canonical record is not the exact selected SCS1 identity.
    #[error("systemd syscall-filter record differs from selected digest")]
    DigestMismatch,
    /// The canonical record is not for the selected admitted architecture.
    #[error("systemd syscall-filter architecture differs from selected architecture")]
    ArchitectureMismatch,
    /// Mode or exact ordered names differ from the prescribed property readback.
    #[error("systemd syscall-filter readback differs from selected authority")]
    ReadbackMismatch,
}

impl SystemCallFilter {
    /// Compile the exact canonical SCS1 selected by signed provider admission.
    ///
    /// `selected_digest` and `architecture` must come from the existing
    /// authenticated admission boundary, not evaluator-supplied claims. This
    /// method validates a request component; it does not grant admission or
    /// prove kernel enforcement.
    ///
    /// # Errors
    /// Rejects malformed bytes, an unequal SCS1 digest, or an unequal architecture.
    pub fn from_selected_record(
        bytes: &[u8],
        selected_digest: [u8; 32],
        architecture: SandboxArchitecture,
    ) -> Result<Self, SystemCallFilterError> {
        SandboxSyscallSet::from_canonical_cbor(bytes)
            .map_err(SystemCallFilterError::from)
            .and_then(|record| {
                if record.syscall_set_digest != selected_digest {
                    return Err(SystemCallFilterError::DigestMismatch);
                }
                if record.architecture != architecture {
                    return Err(SystemCallFilterError::ArchitectureMismatch);
                }
                Ok(Self { record })
            })
    }

    /// Return the exact `(bas)` value for systemd's `SystemCallFilter` property.
    ///
    /// Only requested names are sent; implicit backend additions belong solely
    /// in the expected readback. No groups, host lookups, or normalization occur.
    #[must_use]
    pub fn requested_property(&self) -> (bool, Vec<String>) {
        (true, self.record.requested_names.clone())
    }

    /// Compare typed D-Bus readback with the complete prescribed ordered array.
    ///
    /// The typed systemd proxy must deserialize `(bas)` before calling this
    /// method. Successful comparison is requested-state evidence only, not
    /// proof of native syscall rules or permission to release adapter bytes.
    ///
    /// # Errors
    /// Rejects inverted mode or any missing, extra, duplicated, or reordered name.
    pub fn verify_readback(
        &self,
        readback: &(bool, Vec<String>),
    ) -> Result<(), SystemCallFilterError> {
        if readback.0 && readback.1 == self.record.expected_effective_names {
            Ok(())
        } else {
            Err(SystemCallFilterError::ReadbackMismatch)
        }
    }
}

/// Run the binary for `arguments` (without the program name).
///
/// The only mode today is `launch-barrier <lpv1-hex>`, which never returns
/// success: a released adapter replaces the process image. Any other argument
/// vector, or any launcher failure, ends with a nonzero exit code and a fixed
/// diagnostic on standard error.
#[cfg(target_os = "linux")]
#[must_use]
pub fn run(arguments: impl IntoIterator<Item = std::ffi::OsString>) -> std::process::ExitCode {
    let arguments: Vec<_> = arguments.into_iter().collect();
    match arguments.as_slice() {
        [mode, lpv1] if mode == launcher::LAUNCH_BARRIER_MODE => {
            let error = lpv1
                .to_str()
                .map_or(launcher::LauncherError::Parameters, |hex| {
                    launcher::run_launch_barrier(hex)
                });
            report(&format!("pos-sandboxd: {error}"));
            std::process::ExitCode::FAILURE
        }
        _ => {
            report("usage: pos-sandboxd launch-barrier <lpv1-hex>");
            std::process::ExitCode::from(2)
        }
    }
}

/// One diagnostic line on standard error; a failed write changes nothing.
#[cfg(target_os = "linux")]
fn report(message: &str) {
    use std::io::Write;
    writeln!(std::io::stderr(), "{message}").ok();
}
