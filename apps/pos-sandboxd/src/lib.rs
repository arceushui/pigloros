//! Backend-specific components of the ADR-069 systemd Sandbox Provider Adapter.
//!
//! Its binary runs the closed launcher mode ([`launcher`]) and the
//! `provider-runtime` mode, which binds both SIC1 provider endpoints and
//! serves them before restart reconciliation (ADR-069 R11 §5.1 to §7). That
//! mode does not grant admission yet. The library also
//! holds the root selector's provider-runtime lifecycle adapter,
//! `SystemdProviderLifecycle` (ADR-069 R11 §5.0), which only the
//! `pos-root-selector` binary composes.
//! The existing signed admission boundary must supply the selected SCS1 digest
//! and architecture before these requested-state components are used.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

#[cfg(target_os = "linux")]
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc, OnceLock,
};

// Public module reachability keeps the channel, payload and capture items
// the execute path shares `pub(crate)` without Clippy's `redundant_pub_crate`
// lint, as for `provider_lifecycle` below.
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub mod adapter_stdio;
#[cfg(target_os = "linux")]
mod attempt;
#[cfg(target_os = "linux")]
mod attempt_classification;
#[cfg(target_os = "linux")]
mod attempt_evidence;
#[cfg(target_os = "linux")]
mod attempt_records;
#[cfg(target_os = "linux")]
mod attempt_registry;
#[cfg(target_os = "linux")]
mod execute;
mod hardening;
#[cfg(target_os = "linux")]
mod image_activator;
mod kernel_cgroup;
#[cfg(target_os = "linux")]
mod kernel_observation;
#[cfg(target_os = "linux")]
pub mod launcher;
#[cfg(target_os = "linux")]
mod lifecycle;
#[cfg(target_os = "linux")]
mod local_network;
#[cfg(target_os = "linux")]
mod namespace_network;
// Public module reachability keeps the removal report and the connector that
// owns it `pub(crate)` without Clippy's `redundant_pub_crate` lint, as for
// `provider_lifecycle` below; nothing in it is public.
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub mod network_removal;
// Public so that its crate-visible readers stay `pub(crate)` without Clippy's
// `redundant_pub_crate`; it exports nothing.
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub mod process_identity;
#[cfg(target_os = "linux")]
mod provider_barrier;
#[cfg(target_os = "linux")]
mod provider_installation;
// Public module reachability lets the provider-unit types that `system_bus`
// shares with the lifecycle adapter stay `pub(crate)` without Clippy's
// `redundant_pub_crate` lint.
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub mod provider_lifecycle;
// Public module reachability lets the `provider-runtime` mode's entry point
// and its error stay `pub(crate)` without Clippy's `redundant_pub_crate`
// lint, as for `provider_lifecycle`.
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub mod provider_runtime;
#[cfg(target_os = "linux")]
mod release_barrier;
#[cfg(target_os = "linux")]
mod restart;
// The #444 QEMU evidence guest's driver, compiled only with `test-support`
// and only for the two architectures the evidence guest runs on.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "test-support"
))]
pub mod packaged_conformance;
#[cfg(target_os = "linux")]
mod root_attachment;
#[cfg(target_os = "linux")]
mod runtime_signer;
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

/// A boot ID and a `CLOCK_MONOTONIC` time on that boot.
#[cfg(target_os = "linux")]
type BootInstant = ([u8; 16], std::time::Duration);

#[derive(Debug)]
struct CgroupRoot(std::fs::File);

/// One irreversible execution claim, shared by the exact prepared directory.
///
/// Its phase only moves forward: open, then claimed, then either submitted
/// (a unit start was requested) or fenced (no unit start can ever be
/// requested). The cgroup that the submitting execution bound is recorded
/// once, so terminal cleanup accepts stop evidence only for that cgroup.
#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Default)]
struct ExecutionOwnership(Arc<ExecutionState>);

#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
struct ExecutionState {
    phase: AtomicU8,
    cgroup: OnceLock<(u64, u64)>,
}

// Phase tags, not an order: FENCED (2) and SUBMITTED (3) are both terminal and
// neither follows the other. Compare phases only with compare-and-swap or
// `==`/`!=`, never with `<`/`>`.
#[cfg(target_os = "linux")]
const EXECUTION_OPEN: u8 = 0;
#[cfg(target_os = "linux")]
const EXECUTION_CLAIMED: u8 = 1;
#[cfg(target_os = "linux")]
const EXECUTION_FENCED: u8 = 2;
#[cfg(target_os = "linux")]
const EXECUTION_SUBMITTED: u8 = 3;

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
        self.advance(EXECUTION_OPEN, EXECUTION_FENCED).ok();
    }

    fn claim(&self) -> Result<(), ExecuteError> {
        self.advance(EXECUTION_OPEN, EXECUTION_CLAIMED)
    }

    /// Record, immediately before the unit start is requested, that the
    /// claimed execution may have created a unit. Refused once fenced.
    fn submit(&self) -> Result<(), ExecuteError> {
        self.advance(EXECUTION_CLAIMED, EXECUTION_SUBMITTED)
    }

    /// Record the exact cgroup the submitted execution bound to its unit.
    fn bind_cgroup(&self, identity: (u64, u64)) {
        self.0.cgroup.set(identity).ok();
    }

    /// Fence every future unit start; `false` when one was already requested.
    fn fence_unsubmitted(&self) -> bool {
        self.0
            .phase
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |phase| {
                (phase != EXECUTION_SUBMITTED).then_some(EXECUTION_FENCED)
            })
            .is_ok()
    }

    /// Whether `identity` is the cgroup this owner's execution bound.
    fn bound_cgroup_is(&self, identity: (u64, u64)) -> bool {
        self.bound_cgroup() == Some(identity)
    }

    /// The cgroup this owner's execution bound, if it bound one.
    fn bound_cgroup(&self) -> Option<(u64, u64)> {
        self.0.cgroup.get().copied()
    }

    fn advance(&self, from: u8, to: u8) -> Result<(), ExecuteError> {
        self.0
            .phase
            .compare_exchange(from, to, Ordering::AcqRel, Ordering::Acquire)
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
/// The root facts a PAI3 record retained at activation.
///
/// They are decoded for comparison with a fresh kernel readback: claims, not
/// evidence. The held image's identity is PAI2's, not repeated here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedRoot {
    /// The attached root's mount ID.
    pub(crate) mount_id: u64,
    /// The root inode on the mapper device.
    pub(crate) inode: u64,
    /// The mapper's device and disk sequence.
    pub(crate) mapper: ((u32, u32), u64),
    /// The mapper's UUID.
    pub(crate) mapper_uuid: String,
    /// The loop device's name.
    pub(crate) loop_name: String,
    /// The loop device's device and disk sequence.
    pub(crate) loop_device: ((u32, u32), u64),
}

#[cfg(target_os = "linux")]
impl RecordedRoot {
    /// The attached root's mount ID.
    #[must_use]
    pub const fn mount_id(&self) -> u64 {
        self.mount_id
    }

    /// The root inode on the mapper device.
    #[must_use]
    pub const fn inode(&self) -> u64 {
        self.inode
    }

    /// The mapper's device and disk sequence.
    #[must_use]
    pub const fn mapper(&self) -> ((u32, u32), u64) {
        self.mapper
    }

    /// The mapper's UUID.
    #[must_use]
    pub const fn mapper_uuid(&self) -> &str {
        self.mapper_uuid.as_str()
    }

    /// The loop device's name.
    #[must_use]
    pub const fn loop_name(&self) -> &str {
        self.loop_name.as_str()
    }

    /// The loop device's device and disk sequence.
    #[must_use]
    pub const fn loop_device(&self) -> ((u32, u32), u64) {
        self.loop_device
    }
}

/// The held image `(device, inode)` the test fixtures record and read back.
#[cfg(all(test, target_os = "linux"))]
pub(crate) const FIXTURE_IMAGE: (u64, u64) = (5, 6);
/// Other images than the fixture's, built without arithmetic from its
/// distinct device and inode: another inode on its device, and its inode on
/// another device.
#[cfg(all(test, target_os = "linux"))]
pub(crate) const OTHER_IMAGES: [(u64, u64); 2] = [
    (FIXTURE_IMAGE.0, FIXTURE_IMAGE.0),
    (FIXTURE_IMAGE.1, FIXTURE_IMAGE.1),
];
// `OTHER_IMAGES` differs from the fixture only while its device and inode do.
#[cfg(all(test, target_os = "linux"))]
const _: () = assert!(FIXTURE_IMAGE.0 != FIXTURE_IMAGE.1);

/// An attempt's `root` is opened only as a directory path, never through a
/// symlink: the root readback and the restart root inventory share this.
#[cfg(target_os = "linux")]
pub(crate) const ATTEMPT_ROOT_OPEN: rustix::fs::OFlags = rustix::fs::OFlags::PATH
    .union(rustix::fs::OFlags::DIRECTORY)
    .union(rustix::fs::OFlags::NOFOLLOW)
    .union(rustix::fs::OFlags::CLOEXEC);
/// It is resolved beneath the held attempt directory, across a mount but
/// never through a symlink.
#[cfg(target_os = "linux")]
pub(crate) const ATTEMPT_ROOT_RESOLVE: rustix::fs::ResolveFlags =
    rustix::fs::ResolveFlags::BENEATH.union(rustix::fs::ResolveFlags::NO_SYMLINKS);

#[cfg(target_os = "linux")]
/// One recorded attempt directory and its `root` entry, held by path only
/// and opened across a mount.
///
/// The root may still carry the previous runtime's root mount. Holding it
/// grants no detach authority: the mount must still be correlated with fresh
/// kernel readback, and the directory inventory must later find it unmounted.
#[derive(Debug)]
pub(crate) struct RecordedRootEntry {
    /// The committed intent, which recorded both directory identities.
    pub(crate) intent: RecoveredAttemptIntent,
    /// The held attempt directory, with its recorded identity.
    pub(crate) attempt: std::fs::File,
    /// `<attempt>/root`, opened as a path beneath the held attempt directory.
    pub(crate) root: std::os::fd::OwnedFd,
}

#[cfg(target_os = "linux")]
pub use adapter_stdio::{AdapterIo, FencedOutput, ReleasedOutput, StdioChannelError};
#[cfg(target_os = "linux")]
pub use attempt::{ActiveAttempt, AdmittedAttempt};
#[cfg(target_os = "linux")]
pub use attempt_evidence::{
    BoundUnit, ReleaseOutcome, ReleaseResources, ResourceEvidence, TerminalResources,
    TerminalServiceError,
};
#[cfg(target_os = "linux")]
pub use attempt_records::{
    AttemptAdmission, AttemptRecords, EvidenceFault, ResponseFault, RetainedResponse,
};
#[cfg(target_os = "linux")]
pub use execute::{
    execute, AttemptCancel, AttemptEnding, AttemptExecution, CancelSignal, ExecuteError,
    ExecuteFailure, ExecuteJob, LaunchBarrier, ModePlan, NetworkEvidence, ReplayRequest,
    StartFailure, UnitCgroup, UnitHost, UnitKiller, UnitState, UnverifiedStart,
};
#[cfg(target_os = "linux")]
pub use kernel_observation::{observation_evidence, MainProcess};
#[cfg(target_os = "linux")]
pub use kernel_observation::{
    BlockDevice, CgroupView, DeviceNumber, KernelIdentity, KernelObservation,
    KernelObservationError, KernelObservedReadback, NamespaceSet, ObservationContext, ObservedUnit,
    ProviderNamespaces, RootIdentity, WorkMount, WorkUsage,
};
#[cfg(target_os = "linux")]
pub use lifecycle::{
    finish_attempt, AttemptCleanup, AttemptCleanupDeadlines, AttemptCleanupError, AttemptLaunch,
    AttemptLifecycle, AttemptLifecycleError, AttemptProgress, AwaitedInput, BarrierFactory,
    CleanupBudget, EndedAttempt, ExchangeClaim, GrantWrite, InterruptedInput, LiveAttemptIdentity,
    LiveAttemptSnapshot, OwnedAttempt, ReconciledAttempt, RootRecheck, SystemdAttemptSteps,
};
#[cfg(target_os = "linux")]
pub use local_network::{
    BoundLocalProxy, CheckedLocal, EstablishedNetwork, FailClosedLocalNetwork, FailClosedSetup,
    HostServiceChannel, HostServiceStream, LocalNetworkPort, LocalProxyBindError, NetworkReadback,
    NetworkRemovalFailure, ReadbackError, RefusingConnector, RemoveNetwork, ServeError,
    ServedProxy, SetupClass, SetupError,
};
#[cfg(target_os = "linux")]
pub use namespace_network::netlink;
#[cfg(target_os = "linux")]
pub use namespace_network::{
    decode_firewall_rule, encode_firewall_rule, establish_namespace, AttemptEgress,
    AttemptNetworkError, EgressControl, EgressProbe, EgressProbeError, EgressSlice, EstablishError,
    EstablishFailure, ExpectedNamespace, FirewallBaseChain, FirewallChain, FirewallHook,
    FirewallRule, FirewallTableFamily, FirewallVerdict, ForwardingRecords, HostEgress,
    HostEgressError, InvalidEgressProbe, InvalidLinkName, IpPrefix, LinkKind, LinkName,
    LocalEgressProbe, NamespaceConnector, NamespaceControl, NamespaceName, NamespaceRoute,
    NamespacedLocalNetwork, NetlinkNamespaceControl, NetworkNamespaces, NetworkPlanError,
    NetworkRange, ObservedAddress, ObservedLink, ObservedNamespace, ObservedRoute, ObservedTable,
    OrphanSweepError, ReadbackMismatch, UndecodableRule, FORWARDING_RECORDS, HOST_TABLE,
    NAMESPACE_TABLE,
};
#[cfg(target_os = "linux")]
pub use namespace_network::{
    fb_tunnels_isolated, NetlinkUnitNetwork, UnitNetworkCheck, UnitNetworkError, FB_TUNNELS_SYSCTL,
};
#[cfg(target_os = "linux")]
pub use restart::{
    reconcile_cleanup, reconcile_restart, EgressPropertyProbe, OrphanNetworkCleanup,
    ReconciledRestart, RestartReconciliationError, RootsReleased,
};

#[cfg(target_os = "linux")]
pub use attempt_registry::{
    AttemptUnitTermination, CommittedPlannedAttempt, CompletedAttemptCleanup, PlannedAttemptIntent,
    PreparedAttemptDirectory, RecoveredAttemptIntent, RecoveredUnmountedDirectory,
    RegistryRecoveryEntry, SystemdAttemptRecovery, SystemdAttemptRegistry,
    SystemdAttemptRegistryError, UnmountedDirectoryInventory,
};

#[cfg(target_os = "linux")]
pub use image_activator::{
    ActivationImage, ImageActivationError, ImageActivator, MountfsdImageActivator,
    QuarantinedRootMount,
};
#[cfg(target_os = "linux")]
pub use root_attachment::{
    activate_admitted_root, ReleasedAttemptRoot, RootResourceIdentity, VerifiedRootMount,
};

#[cfg(target_os = "linux")]
pub use provider_barrier::{
    fresh_nonce, AuthorityCheck, BarrierError, ObservedReadback, ObservedReadbackUnavailable,
    ProviderReleaseBarrier, RecheckRefusal, UnitIdentitySource,
};
#[cfg(target_os = "linux")]
pub use provider_installation::{ProviderInstallation, ProviderInstallationError, RuntimeKey};
#[cfg(target_os = "linux")]
pub use provider_lifecycle::SystemdProviderLifecycle;
#[cfg(target_os = "linux")]
pub use provider_runtime::{start_runtime_authority, ProviderStartupError};
#[cfg(target_os = "linux")]
pub use release_barrier::{
    release_after_ready, ExpectedLauncherReady, ReleaseBarrierError, ReleaseBinding, ReleaseRecheck,
};
#[cfg(target_os = "linux")]
pub use runtime_signer::{
    issue_release, sign_verified, AdmittedRuntimeKey, KeyFileRuntimeSigner,
    RuntimeAttestationSigner, RuntimeSignerError,
};
#[cfg(target_os = "linux")]
pub use staging::{
    AdmittedEntry, ControlFloor, FailedInput, IssuedGrant, OutputReservationRefused, RecheckError,
    RecheckLedgerError, StagedInput, StagingCharge, StagingDirectory, StagingError, StagingLedger,
    StagingLimits, StagingUsage, VerifiedStagedInput,
};

pub use hardening::{
    SystemdHardeningProperty, SystemdHardeningReadback, SystemdHardeningReadbackValue,
    SystemdHardeningValue, TransientUnitHardening, TransientUnitHardeningError,
};
pub use kernel_cgroup::{
    AttemptCgroupEmptyBasis, AttemptCgroupEmptyObservation, AttemptCgroupError,
    AttemptLimitEventCounter, AttemptLimitEventDelta, AttemptLimitEventSnapshot,
    AttemptLimitEventSource, BoundAttemptCgroup, EffectiveCgroupLimits, EffectiveKernelLimit,
    EffectiveLimitError, EffectiveLimitMismatch, EffectiveLimitSource, EffectiveLimitVerdict,
    WorkCapacity,
};
#[cfg(target_os = "linux")]
pub use kernel_cgroup::{AttemptShutdownDeadlines, AttemptShutdownError};
pub use system_bus::{
    SystemdAttemptUnitAbsenceObservation, SystemdAttemptUnitObservation, SystemdJobFailure,
    SystemdMainExit, SystemdServiceResult, SystemdStartJob, SystemdStopJobCompleted,
    SystemdTransientUnitTransport, SystemdTransientUnitTransportError, SystemdUnitOutcome,
    SystemdUnitResultError, SystemdUnitResultObservation, SystemdVerifiedStart,
    TransientServiceUnitName, TransientServiceUnitNameError,
};
#[cfg(target_os = "linux")]
pub use system_bus::{SystemdAttemptUnitTeardownError, SystemdAttemptUnitTeardownObservation};
pub use transient_unit::{
    unverified_requested_configuration, verified_requested_configuration, RequestedConfiguration,
    RequestedConfigurationProperty, RequestedConfigurationValue,
};
pub use transient_unit::{
    ActivatedRootDirectory, CheckedRoot, LaunchMode, LauncherInvocation, LauncherSource,
    SystemdManagerReadback, SystemdManagerReadbackOnlyProperty, SystemdServiceLimits,
    SystemdServiceLimitsError, SystemdTransientUnitNumericValue, SystemdTransientUnitProperty,
    SystemdTransientUnitReadback, SystemdTransientUnitReadbackValue, SystemdTransientUnitValue,
    TransientUnitLaunchInputs, TransientUnitRequest, TransientUnitRequestError, UnitStdio,
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
    StandardInputFileDescriptor,
    StandardOutputFileDescriptor,
    StandardErrorFileDescriptor,
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

    /// The last kinds.
    const fn tail_name(self) -> &'static str {
        match self {
            Self::FileDescriptorStoreMax => "FileDescriptorStoreMax",
            Self::ExtraFileDescriptors => "ExtraFileDescriptors",
            Self::TemporaryFileSystem => "TemporaryFileSystem",
            last => last.last_name(),
        }
    }

    /// The command and the standard descriptors;
    /// `StandardErrorFileDescriptor` is the final kind.
    const fn last_name(self) -> &'static str {
        match self {
            Self::ExecStart => "ExecStart",
            Self::StandardInputFileDescriptor => "StandardInputFileDescriptor",
            Self::StandardOutputFileDescriptor => "StandardOutputFileDescriptor",
            _ => "StandardErrorFileDescriptor",
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
/// The modes are `launch-barrier <lpv1-hex>`, `provider-runtime` and
/// `recovery-peer <endpoint-id-hex>`. A released adapter replaces the
/// launcher's process image, and the provider runtime serves until a
/// listener invariant fails, so neither returns success. The recovery peer
/// exits with status 0 after it acknowledged its one exchange (ADR-069 R12
/// §5). Any other argument vector exits with status 2; a failure of any mode
/// ends with one fixed diagnostic on standard error and status 1, except for the launcher, whose
/// status says which closed failure it was (`launcher::failure_status`).
#[cfg(target_os = "linux")]
#[must_use]
pub fn run(arguments: impl IntoIterator<Item = std::ffi::OsString>) -> std::process::ExitCode {
    let arguments: Vec<_> = arguments.into_iter().collect();
    MODES
        .iter()
        .find_map(|mode| mode(&arguments))
        .unwrap_or(ModeOutcome::Usage)
        .exit()
}

/// How one run of the binary ended.
#[cfg(target_os = "linux")]
enum ModeOutcome {
    /// The arguments name no mode: exit status 2.
    Usage,
    /// The recovery peer acknowledged its one exchange: exit status 0.
    Succeeded,
    /// A mode failed with this diagnostic and exit status (1, except for the launcher, see
    /// `launcher::failure_status`).
    Failed(String, u8),
}

#[cfg(target_os = "linux")]
impl ModeOutcome {
    /// A failure of a mode, with its one fixed diagnostic.
    fn failed(error: impl std::fmt::Display) -> Self {
        Self::failed_with(error, 1)
    }

    /// A failure of a mode with its one fixed diagnostic and its own exit status.
    fn failed_with(error: impl std::fmt::Display, status: u8) -> Self {
        Self::Failed(format!("pos-sandboxd: {error}"), status)
    }

    /// Report the outcome on standard error and give the exit status.
    fn exit(self) -> std::process::ExitCode {
        match self {
            Self::Usage => {
                report(
                    "usage: pos-sandboxd launch-barrier <lpv1-hex> | provider-runtime \
                     | recovery-peer <endpoint-id-hex>",
                );
                std::process::ExitCode::from(2)
            }
            Self::Succeeded => std::process::ExitCode::SUCCESS,
            Self::Failed(diagnostic, status) => {
                report(&diagnostic);
                std::process::ExitCode::from(status)
            }
        }
    }
}

/// One mode: its outcome when `arguments` name it, or `None`.
#[cfg(target_os = "linux")]
type Mode = fn(&[std::ffi::OsString]) -> Option<ModeOutcome>;

/// Every mode the binary has, tried in order.
#[cfg(target_os = "linux")]
const MODES: [Mode; 3] = [
    provider_runtime_mode,
    recovery_peer_mode,
    launch_barrier_mode,
];

/// `provider-runtime`: serve until a listener invariant fails.
#[cfg(target_os = "linux")]
fn provider_runtime_mode(arguments: &[std::ffi::OsString]) -> Option<ModeOutcome> {
    match arguments {
        [mode] if mode == provider_lifecycle::PROVIDER_RUNTIME_ARGUMENT => Some(
            ModeOutcome::failed(provider_runtime::serve_provider_runtime()),
        ),
        _ => None,
    }
}

/// `recovery-peer <endpoint-id-hex>`: answer one exchange (ADR-069 R12 §5).
#[cfg(target_os = "linux")]
fn recovery_peer_mode(arguments: &[std::ffi::OsString]) -> Option<ModeOutcome> {
    match arguments {
        [mode, endpoint_id] if mode == provider_runtime::recovery_peer::RECOVERY_PEER_ARGUMENT => {
            Some(
                provider_runtime::recovery_peer::serve_recovery_peer(endpoint_id)
                    .map_or_else(ModeOutcome::failed, |()| ModeOutcome::Succeeded),
            )
        }
        _ => None,
    }
}

/// `launch-barrier <lpv1-hex>`: a released adapter replaces this process
/// image, so only a failure returns.
#[cfg(target_os = "linux")]
fn launch_barrier_mode(arguments: &[std::ffi::OsString]) -> Option<ModeOutcome> {
    match arguments {
        [mode, lpv1] if mode == launcher::LAUNCH_BARRIER_MODE => {
            let error = lpv1.to_str().map_or(
                launcher::LauncherError::Parameters,
                launcher::run_launch_barrier,
            );
            let status = launcher::failure_status(&error);
            Some(ModeOutcome::failed_with(error, status))
        }
        _ => None,
    }
}

/// One diagnostic line on standard error; a failed write changes nothing.
#[cfg(target_os = "linux")]
fn report(message: &str) {
    use std::io::Write;
    writeln!(std::io::stderr(), "{message}").ok();
}
