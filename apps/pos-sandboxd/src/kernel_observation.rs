//! The kernel observation of one released attempt unit (ADR-069 R9 §4.4).
//!
//! [`observe_unit`] derives the typed `kernel-observation` of KOE1 without
//! process creation and without `unsafe`: it anchors the manager's `MainPID`
//! with a pidfd and a `/proc/<MainPID>` directory descriptor proved to be
//! procfs, reads the identity again, and reads every per-process fact through
//! that descriptor while the pidfd shows the process alive. The `exe`, `ns/*`
//! and `root` entries are procfs magic links whose *targets* are the
//! evidence, so their final component is always followed. The release
//! recheck runs the same procedure again and requires an equal observation.
//!
//! This module collects typed evidence only. KOE1 encoding and its
//! self-digest belong to the record encoders.

use std::fs::File;
use std::io::Read;
use std::num::NonZeroU64;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use pos_reference::sandbox_provider_protocol::FdIdentity;
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::fs::{
    fstat, fstatfs, major, minor, open, openat, statx, AtFlags, Mode, OFlags, StatxFlags,
    PROC_SUPER_MAGIC,
};
use rustix::io::Errno;
use rustix::process::pidfd_open;
use rustix::process::Pid;
use rustix::process::PidfdFlags;

use crate::{EffectiveLimitError, ObservedReadback, ObservedReadbackUnavailable, WorkCapacity};

/// The six namespace types KOE1 records, in its order.
const NAMESPACES: [&str; 6] = ["mnt", "pid", "ipc", "uts", "user", "net"];
/// Where the procfs directories are, and the unit's `/work` beneath one,
/// reached through its `root` magic link.
const PROC_PATHS: ProcPaths<'static> = ProcPaths {
    proc: "/proc",
    work: "root/work",
};
/// The most `cgroup.procs` bytes read; `pids.max` keeps real lists far below.
const MAX_PROCS_BYTES: u64 = 1 << 20;
/// Kernel device-number bounds: 12 major bits and 20 minor bits.
const MAX_MAJOR: u32 = 4095;
const MAX_MINOR: u32 = 1_048_575;
const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC);
const READ: OFlags = OFlags::RDONLY.union(OFlags::CLOEXEC);

/// A kernel device number as `major:minor`, never a raw `st_dev`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceNumber {
    major: u32,
    minor: u32,
}

impl DeviceNumber {
    /// The pair, if it is within the kernel's 12-bit major and 20-bit minor.
    #[must_use]
    pub const fn new(major: u32, minor: u32) -> Option<Self> {
        if major <= MAX_MAJOR && minor <= MAX_MINOR {
            Some(Self { major, minor })
        } else {
            None
        }
    }

    /// Split a `st_dev` with the kernel's encoding.
    fn of(device: u64) -> Result<Self, KernelObservationError> {
        Self::new(major(device), minor(device)).ok_or(KernelObservationError::Device)
    }

    /// The major number.
    #[must_use]
    pub const fn major(self) -> u32 {
        self.major
    }

    /// The minor number.
    #[must_use]
    pub const fn minor(self) -> u32 {
        self.minor
    }
}

/// A device and inode: the identity of a cgroup directory or a namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelIdentity {
    device: DeviceNumber,
    inode: u64,
}

impl KernelIdentity {
    fn of(device: u64, inode: u64) -> Result<Self, KernelObservationError> {
        DeviceNumber::of(device).map(|device| Self { device, inode })
    }

    /// The device of the filesystem holding the inode.
    #[must_use]
    pub const fn device(self) -> DeviceNumber {
        self.device
    }

    /// The inode number.
    #[must_use]
    pub const fn inode(self) -> u64 {
        self.inode
    }
}

/// The six namespace identities of one process: mnt, pid, ipc, uts, user, net.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceSet([KernelIdentity; 6]);

impl NamespaceSet {
    /// The identities in KOE1 order.
    #[must_use]
    pub const fn identities(&self) -> &[KernelIdentity; 6] {
        &self.0
    }

    /// Read every namespace through `procdir`, following each magic link.
    fn read(procdir: BorrowedFd<'_>) -> Result<Self, KernelObservationError> {
        let mut identities = [KernelIdentity {
            device: DeviceNumber { major: 0, minor: 0 },
            inode: 0,
        }; 6];
        for (slot, name) in identities.iter_mut().zip(NAMESPACES) {
            *slot = namespace(procdir, name)?;
        }
        Ok(Self(identities))
    }

    /// Whether no namespace of `self` is the same-type namespace of `other`.
    fn isolated_from(&self, other: &Self) -> bool {
        self.0
            .iter()
            .zip(&other.0)
            .all(|(own, theirs)| own != theirs)
    }

    /// Namespaces that share no identity with `other`: every inode moved.
    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(crate) fn for_test_shifted(other: &Self) -> Self {
        Self(other.0.map(|identity| KernelIdentity {
            inode: identity.inode ^ 1,
            ..identity
        }))
    }
}

/// The provider's own namespaces, retained once at startup and the same for
/// every attempt of one runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderNamespaces(NamespaceSet);

impl ProviderNamespaces {
    /// Observe the provider's namespaces through `/proc/self`.
    ///
    /// # Errors
    /// Fails when `/proc/self` or one of its namespaces cannot be read.
    pub fn observe() -> Result<Self, KernelObservationError> {
        open("/proc/self", DIRECTORY, Mode::empty())
            .map_err(KernelObservationError::ProcDirectory)
            .and_then(|procdir| NamespaceSet::read(procdir.as_fd()))
            .map(Self)
    }

    /// The identities.
    #[must_use]
    pub const fn namespaces(&self) -> &NamespaceSet {
        &self.0
    }

    #[cfg(test)]
    pub(crate) const fn for_test(namespaces: NamespaceSet) -> Self {
        Self(namespaces)
    }
}

/// One block device generation: its number and disk sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockDevice {
    device: DeviceNumber,
    diskseq: NonZeroU64,
}

impl BlockDevice {
    pub(crate) fn of((major, minor): (u32, u32), diskseq: NonZeroU64) -> Option<Self> {
        DeviceNumber::new(major, minor).map(|device| Self { device, diskseq })
    }

    /// The device number.
    #[must_use]
    pub const fn device(self) -> DeviceNumber {
        self.device
    }

    /// The disk sequence.
    #[must_use]
    pub const fn diskseq(self) -> NonZeroU64 {
        self.diskseq
    }
}

/// The verified attached root: its mount, its mapper and its loop device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootIdentity {
    mount_id: u64,
    mapper: BlockDevice,
    loop_device: BlockDevice,
}

impl RootIdentity {
    pub(crate) const fn new(mount_id: u64, mapper: BlockDevice, loop_device: BlockDevice) -> Self {
        Self {
            mount_id,
            mapper,
            loop_device,
        }
    }

    /// The attached root's mount ID.
    #[must_use]
    pub const fn mount_id(self) -> u64 {
        self.mount_id
    }

    /// The device-mapper device; the root mount's device is the same.
    #[must_use]
    pub const fn mapper(self) -> BlockDevice {
        self.mapper
    }

    /// The loop device under the mapper.
    #[must_use]
    pub const fn loop_device(self) -> BlockDevice {
        self.loop_device
    }

    /// A root for tests, where no mount exists.
    #[cfg(test)]
    pub(crate) const FIXTURE: Self = Self {
        mount_id: 301,
        mapper: BlockDevice {
            device: DeviceNumber {
                major: 253,
                minor: 3,
            },
            diskseq: NonZeroU64::MIN,
        },
        loop_device: BlockDevice {
            device: DeviceNumber { major: 7, minor: 0 },
            diskseq: NonZeroU64::MAX,
        },
    };
}

/// The unit's `/work` mount and its capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkMount {
    mount_id: u64,
    capacity_bytes: u64,
}

impl WorkMount {
    /// The mount ID.
    #[must_use]
    pub const fn mount_id(self) -> u64 {
        self.mount_id
    }

    /// The capacity in bytes.
    #[must_use]
    pub const fn capacity_bytes(self) -> u64 {
        self.capacity_bytes
    }
}

/// `/work` after the payload exited: its mount, capacity and free space.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkUsage {
    mount: WorkMount,
    available_bytes: u64,
}

impl WorkUsage {
    /// Observe the retained `/work` handle again, before teardown.
    ///
    /// # Errors
    /// Fails when the handle is no longer a tmpfs mount root or cannot be read.
    pub fn observe(work: &File) -> Result<Self, KernelObservationError> {
        let mount = work_mount(work)?;
        fstatfs(work)
            .map_err(KernelObservationError::WorkRead)
            .and_then(|filesystem| {
                u64::try_from(filesystem.f_bsize)
                    .ok()
                    .and_then(|size| size.checked_mul(filesystem.f_bavail))
                    .ok_or(KernelObservationError::WorkCapacity)
            })
            .map(|available_bytes| Self {
                mount,
                available_bytes,
            })
    }

    /// The mount and its capacity.
    #[must_use]
    pub const fn mount(self) -> WorkMount {
        self.mount
    }

    /// The free bytes.
    #[must_use]
    pub const fn available_bytes(self) -> u64 {
        self.available_bytes
    }
}

/// The typed KOE1 `kernel-observation` of one released unit.
///
/// Two observations of the same unrestarted process are equal; the release
/// recheck relies on that equality.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelObservation {
    invocation_id: [u8; 16],
    main_pid: u32,
    launcher: FdIdentity,
    adapter: FdIdentity,
    root: RootIdentity,
    cgroup: KernelIdentity,
    namespaces: NamespaceSet,
    provider_namespaces: NamespaceSet,
    observed_fdl1_digest: [u8; 32],
    work: Option<WorkMount>,
}

impl KernelObservation {
    /// The unit's `InvocationID`.
    #[must_use]
    pub const fn invocation_id(&self) -> [u8; 16] {
        self.invocation_id
    }

    /// The unit's `MainPID`.
    #[must_use]
    pub const fn main_pid(&self) -> u32 {
        self.main_pid
    }

    /// The mount ID and inode of the target of `/proc/<MainPID>/exe`.
    #[must_use]
    pub const fn launcher(&self) -> FdIdentity {
        self.launcher
    }

    /// The adapter's mount ID and inode beneath the verified root.
    #[must_use]
    pub const fn adapter(&self) -> FdIdentity {
        self.adapter
    }

    /// The attached root.
    #[must_use]
    pub const fn root(&self) -> RootIdentity {
        self.root
    }

    /// The bound cgroup directory.
    #[must_use]
    pub const fn cgroup(&self) -> KernelIdentity {
        self.cgroup
    }

    /// The unit's namespaces.
    #[must_use]
    pub const fn namespaces(&self) -> &NamespaceSet {
        &self.namespaces
    }

    /// The provider's namespaces, each different from the unit's.
    #[must_use]
    pub const fn provider_namespaces(&self) -> &NamespaceSet {
        &self.provider_namespaces
    }

    /// The observed FDL1 digest that `ReadyV1` bound.
    #[must_use]
    pub const fn observed_fdl1_digest(&self) -> [u8; 32] {
        self.observed_fdl1_digest
    }

    /// The `/work` mount, when ELM1 limit 9 is nonzero.
    #[must_use]
    pub const fn work(&self) -> Option<WorkMount> {
        self.work
    }

    /// The same observation of another `MainPID`.
    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(crate) const fn with_main_pid_for_test(mut self, main_pid: u32) -> Self {
        self.main_pid = main_pid;
        self
    }
}

/// One observation and the `/work` handle it opened, retained for the
/// terminal `work-after` reading.
#[derive(Debug)]
pub struct ObservedUnit {
    observation: KernelObservation,
    work: Option<File>,
}

impl ObservedUnit {
    /// An observation that holds no `/work` handle.
    #[must_use]
    pub const fn new(observation: KernelObservation) -> Self {
        Self {
            observation,
            work: None,
        }
    }

    /// The observation.
    #[must_use]
    pub const fn observation(&self) -> &KernelObservation {
        &self.observation
    }

    /// The `/work` handle the observation opened, if a `/work` was requested.
    #[must_use]
    pub const fn work(&self) -> Option<&File> {
        self.work.as_ref()
    }
}

/// The bound attempt cgroup, as the observation reads it.
#[derive(Clone, Copy, Debug)]
pub struct CgroupView<'a> {
    directory: BorrowedFd<'a>,
    identity: (u64, u64),
}

impl<'a> CgroupView<'a> {
    /// The held cgroup directory and its `(st_dev, st_ino)`.
    #[must_use]
    pub const fn new(directory: BorrowedFd<'a>, identity: (u64, u64)) -> Self {
        Self {
            directory,
            identity,
        }
    }

    /// The `(st_dev, st_ino)` of the bound cgroup directory.
    #[must_use]
    pub const fn identity(&self) -> (u64, u64) {
        self.identity
    }
}

/// What the provider already holds for one observation of the unit.
#[derive(Clone, Copy, Debug)]
pub struct ObservationContext<'a> {
    cgroup: CgroupView<'a>,
    root: RootIdentity,
    adapter: FdIdentity,
    observed_fdl1_digest: [u8; 32],
    work: bool,
}

impl<'a> ObservationContext<'a> {
    /// The context of one attempt: its bound cgroup, rechecked root, adapter,
    /// FDL1 digest, and whether a `/work` mount was requested.
    #[must_use]
    pub const fn new(
        cgroup: CgroupView<'a>,
        root: RootIdentity,
        adapter: FdIdentity,
        observed_fdl1_digest: [u8; 32],
        work: bool,
    ) -> Self {
        Self {
            cgroup,
            root,
            adapter,
            observed_fdl1_digest,
            work,
        }
    }
}

/// Why no kernel observation could be made (KOE1 status 2).
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum KernelObservationError {
    /// The manager's `MainPID` or `InvocationID` could not be read.
    #[error("the unit identity could not be read")]
    Identity,
    /// The unit has no main process.
    #[error("the unit has no main process")]
    NoMainProcess,
    /// The manager's identity changed while the process was anchored.
    #[error("the unit identity changed during the observation")]
    IdentityChanged,
    /// `pidfd_open` or its liveness poll failed.
    #[error("the main process could not be anchored")]
    Pidfd(#[source] Errno),
    /// The pidfd reported that the main process exited.
    #[error("the main process exited during the observation")]
    Exited,
    /// `/proc/<MainPID>` could not be opened or identified.
    #[error("the process directory could not be opened")]
    ProcDirectory(#[source] Errno),
    /// The process directory is not on procfs.
    #[error("the process directory is not on procfs")]
    NotProcfs,
    /// A namespace could not be read.
    #[error("a namespace of the main process could not be read")]
    Namespace(#[source] Errno),
    /// The target of `exe` could not be identified.
    #[error("the launcher executable could not be observed")]
    Executable,
    /// `cgroup.procs` could not be read.
    #[error("the bound cgroup's process list could not be read")]
    CgroupProcs,
    /// The main process is not in the bound cgroup.
    #[error("the main process is not in the bound cgroup")]
    NotInCgroup,
    /// A unit namespace is the provider's namespace of the same type.
    #[error("the unit shares a namespace with the provider")]
    SharedNamespace,
    /// A device number is out of the kernel's bounds, or a size overflowed.
    #[error("a device number or size is out of bounds")]
    Device,
    /// The `/work` mount could not be opened or read.
    #[error("the /work mount could not be read")]
    WorkRead(#[source] Errno),
    /// The `/work` handle is not a tmpfs mount root of a known capacity.
    #[error("the /work mount is not a bounded tmpfs root")]
    WorkCapacity,
}

impl From<EffectiveLimitError> for KernelObservationError {
    fn from(_: EffectiveLimitError) -> Self {
        Self::WorkCapacity
    }
}

/// The procfs root and the `/work` path beneath a process directory.
#[derive(Clone, Copy)]
struct ProcPaths<'a> {
    proc: &'a str,
    work: &'a str,
}

/// The live main process: its pidfd and its procfs directory.
struct ProcessAnchor {
    pidfd: OwnedFd,
    procdir: OwnedFd,
}

impl ProcessAnchor {
    /// Steps 2 and 3: a pidfd, then `<proc>/<pid>` proved to be procfs.
    fn open(proc: &str, main_pid: u32) -> Result<Self, KernelObservationError> {
        let pid = i32::try_from(main_pid)
            .ok()
            .and_then(Pid::from_raw)
            .ok_or(KernelObservationError::NoMainProcess)?;
        let pidfd = pidfd_open(pid, PidfdFlags::empty()).map_err(KernelObservationError::Pidfd)?;
        let procdir = open(format!("{proc}/{main_pid}"), DIRECTORY, Mode::empty())
            .map_err(KernelObservationError::ProcDirectory)?;
        procfs(procdir.as_fd()).map(|()| Self { pidfd, procdir })
    }

    /// Steps 5 to 8: alive, then namespaces, launcher and `/work` through the
    /// procdir, then cgroup membership, then alive again.
    fn read(
        &self,
        context: &ObservationContext<'_>,
        main_pid: u32,
        work_path: &str,
    ) -> Result<ProcessFacts, KernelObservationError> {
        let procdir = self.procdir.as_fd();
        alive(self.pidfd.as_fd())
            .and_then(|()| NamespaceSet::read(procdir))
            .and_then(|namespaces| launcher(procdir).map(|launcher| (namespaces, launcher)))
            .and_then(|(namespaces, launcher)| {
                context
                    .work
                    .then(|| observe_work(procdir, work_path))
                    .transpose()
                    .map(|work| ProcessFacts {
                        namespaces,
                        launcher,
                        work,
                    })
            })
            .and_then(|facts| member(context.cgroup.directory, main_pid).map(|()| facts))
            .and_then(|facts| alive(self.pidfd.as_fd()).map(|()| facts))
    }
}

/// What the anchored procdir showed of the live main process.
struct ProcessFacts {
    namespaces: NamespaceSet,
    launcher: FdIdentity,
    work: Option<(WorkMount, File)>,
}

/// `procdir` is trusted only on procfs.
fn procfs(procdir: BorrowedFd<'_>) -> Result<(), KernelObservationError> {
    fstatfs(procdir)
        .map_err(KernelObservationError::ProcDirectory)
        .and_then(|filesystem| {
            (filesystem.f_type == PROC_SUPER_MAGIC)
                .then_some(())
                .ok_or(KernelObservationError::NotProcfs)
        })
}

/// The pidfd has not signalled exit.
fn alive(pidfd: BorrowedFd<'_>) -> Result<(), KernelObservationError> {
    let mut polled = [PollFd::from_borrowed_fd(pidfd, PollFlags::IN)];
    let now = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    poll(&mut polled, Some(&now))
        .map_err(KernelObservationError::Pidfd)
        .and_then(|ready| {
            (ready == 0)
                .then_some(())
                .ok_or(KernelObservationError::Exited)
        })
}

/// One namespace: open the magic link's target, then `fstat` it.
fn namespace(
    procdir: BorrowedFd<'_>,
    name: &str,
) -> Result<KernelIdentity, KernelObservationError> {
    openat(procdir, format!("ns/{name}"), READ, Mode::empty())
        .and_then(fstat)
        .map_err(KernelObservationError::Namespace)
        .and_then(|status| KernelIdentity::of(status.st_dev, status.st_ino))
}

/// The mount ID and inode of the target of `exe`, as `statx` follows it.
fn launcher(procdir: BorrowedFd<'_>) -> Result<FdIdentity, KernelObservationError> {
    statx(
        procdir,
        "exe",
        AtFlags::empty(),
        StatxFlags::INO.union(StatxFlags::MNT_ID),
    )
    .ok()
    .filter(|status| StatxFlags::from_bits_retain(status.stx_mask).contains(StatxFlags::MNT_ID))
    .map(|status| FdIdentity {
        mount_id: status.stx_mnt_id,
        inode: status.stx_ino,
    })
    .ok_or(KernelObservationError::Executable)
}

/// The mount ID and capacity of a held `/work` handle.
fn work_mount(work: &File) -> Result<WorkMount, KernelObservationError> {
    let capacity = WorkCapacity::observe(work)?;
    statx(work, "", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID)
        .ok()
        .filter(|status| StatxFlags::from_bits_retain(status.stx_mask).contains(StatxFlags::MNT_ID))
        .map(|status| WorkMount {
            mount_id: status.stx_mnt_id,
            capacity_bytes: capacity.bytes(),
        })
        .ok_or(KernelObservationError::WorkCapacity)
}

/// Open `path` beneath `base` as a directory and observe it as `/work`.
fn observe_work(
    base: BorrowedFd<'_>,
    path: &str,
) -> Result<(WorkMount, File), KernelObservationError> {
    let work = openat(base, path, DIRECTORY, Mode::empty())
        .map(File::from)
        .map_err(KernelObservationError::WorkRead)?;
    work_mount(&work).map(|mount| (mount, work))
}

/// Whether the held cgroup directory lists `main_pid` in `cgroup.procs`.
fn member(cgroup: BorrowedFd<'_>, main_pid: u32) -> Result<(), KernelObservationError> {
    let mut listed = String::new();
    openat(cgroup, "cgroup.procs", READ, Mode::empty())
        .map(File::from)
        .ok()
        .and_then(|procs| {
            procs
                .take(MAX_PROCS_BYTES + 1)
                .read_to_string(&mut listed)
                .ok()
        })
        .filter(|&read| read as u64 <= MAX_PROCS_BYTES)
        .ok_or(KernelObservationError::CgroupProcs)?;
    let main_pid = main_pid.to_string();
    listed
        .lines()
        .any(|line| line == main_pid)
        .then_some(())
        .ok_or(KernelObservationError::NotInCgroup)
}

/// Derive the kernel observation of the unit by the R9 §4.4 procedure.
///
/// `unit` reads the manager's `MainPID` and `InvocationID`; it is called
/// before the process is anchored and again after. Every per-process fact is
/// read through the anchored procfs directory while the pidfd shows the
/// process alive, so none can describe a later process with a reused PID.
///
/// # Errors
/// Any failed step; the observation is then unavailable.
pub fn observe_unit(
    unit: &dyn Fn() -> Result<(u32, [u8; 16]), KernelObservationError>,
    context: &ObservationContext<'_>,
    provider: &ProviderNamespaces,
) -> Result<ObservedUnit, KernelObservationError> {
    observe_unit_in(PROC_PATHS, unit, context, provider)
}

fn observe_unit_in(
    paths: ProcPaths<'_>,
    unit: &dyn Fn() -> Result<(u32, [u8; 16]), KernelObservationError>,
    context: &ObservationContext<'_>,
    provider: &ProviderNamespaces,
) -> Result<ObservedUnit, KernelObservationError> {
    let identity = unit()?;
    let (main_pid, invocation_id) = identity;
    let anchor = ProcessAnchor::open(paths.proc, main_pid)?;
    let again = unit()?;
    (again == identity)
        .then_some(())
        .ok_or(KernelObservationError::IdentityChanged)?;
    let facts = anchor.read(context, main_pid, paths.work)?;
    let provider_namespaces = *provider.namespaces();
    facts
        .namespaces
        .isolated_from(&provider_namespaces)
        .then_some(())
        .ok_or(KernelObservationError::SharedNamespace)?;
    let (device, inode) = context.cgroup.identity;
    let cgroup = KernelIdentity::of(device, inode)?;
    let (work, handle) = facts
        .work
        .map_or((None, None), |(mount, file)| (Some(mount), Some(file)));
    Ok(ObservedUnit {
        observation: KernelObservation {
            invocation_id,
            main_pid,
            launcher: facts.launcher,
            adapter: context.adapter,
            root: context.root,
            cgroup,
            namespaces: facts.namespaces,
            provider_namespaces,
            observed_fdl1_digest: context.observed_fdl1_digest,
            work,
        },
        work: handle,
    })
}

/// The production [`ObservedReadback`]: the R9 §4.4 procedure over procfs,
/// against the provider's namespaces retained at startup.
///
/// `digest` yields the KOE1 self-digest of a frozen observation, which the
/// KOE1 encoder supplies.
pub struct KernelObservedReadback<D> {
    provider: ProviderNamespaces,
    digest: D,
}

impl<D> KernelObservedReadback<D> {
    /// The readback for one runtime, whose namespaces are `provider`.
    #[must_use]
    pub const fn new(provider: ProviderNamespaces, digest: D) -> Self {
        Self { provider, digest }
    }
}

impl<D> ObservedReadback for KernelObservedReadback<D>
where
    D: Fn([u8; 32], &KernelObservation) -> [u8; 32],
{
    fn observe(
        &self,
        unit: &dyn Fn() -> Result<(u32, [u8; 16]), KernelObservationError>,
        context: &ObservationContext<'_>,
    ) -> Result<ObservedUnit, ObservedReadbackUnavailable> {
        observe_unit(unit, context, &self.provider).map_err(ObservedReadbackUnavailable)
    }

    fn digest(&self, ready1_digest: [u8; 32], observation: &KernelObservation) -> [u8; 32] {
        (self.digest)(ready1_digest, observation)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
