//! Bounded, descriptor-bound readback of effective kernel operating limits.
//!
//! This module reads what the kernel reports for ELM1 limit IDs 0 through 3
//! from the exact retained attempt cgroup and the `/work` capacity (ID 9) from
//! a retained directory handle, then compares both with the requested
//! [`SystemdServiceLimits`]. A match is readback evidence only: it does not by
//! itself prove that the kernel enforced a ceiling against a payload.

use std::fs::File;
use std::io::Read;

use rustix::fs::{fstatfs, openat2, Mode, OFlags};
use rustix::io::Errno;
use rustix::param::page_size;

use super::{
    AttemptCgroupError, BoundAttemptCgroup, BoundCgroupIdentity, BoundCgroupPath, RESOLVE_CHILD,
};
use crate::{SystemdOperatingLimitProperty, SystemdServiceLimits, TransientServiceUnitName};

const MAX_SOURCE_BYTES: u64 = 128;
const TMPFS_MAGIC: u64 = 0x0102_1994;
const MICROSECONDS_PER_SECOND: u64 = 1_000_000;
const MIN_CPU_PERIOD_MICROSECONDS: u64 = 1_000;
const CGROUP_SOURCE_COUNT: usize = 4;

/// One exact observation of an effective ELM1 operating limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum EffectiveLimitSource {
    /// The cgroup v2 `memory.max` file (ELM1 ID 0).
    MemoryMax,
    /// The cgroup v2 `memory.swap.max` file (ELM1 ID 1).
    MemorySwapMax,
    /// The cgroup v2 `pids.max` file (ELM1 ID 2).
    PidsMax,
    /// The cgroup v2 `cpu.max` quota at its reported period (ELM1 ID 3).
    CpuMax,
    /// The `/work` capacity observed before the payload ran (ELM1 ID 9).
    WorkCapacityBefore,
    /// The `/work` capacity observed after the payload exited (ELM1 ID 9).
    WorkCapacityAfter,
}

#[derive(Clone, Copy)]
struct SourceSpec {
    name: &'static str,
    limit_id: u8,
}

const SOURCE_SPECS: [SourceSpec; 6] = [
    SourceSpec {
        name: "memory.max",
        limit_id: 0,
    },
    SourceSpec {
        name: "memory.swap.max",
        limit_id: 1,
    },
    SourceSpec {
        name: "pids.max",
        limit_id: 2,
    },
    SourceSpec {
        name: "cpu.max",
        limit_id: 3,
    },
    SourceSpec {
        name: "/work statfs before",
        limit_id: 9,
    },
    SourceSpec {
        name: "/work statfs after",
        limit_id: 9,
    },
];

const CGROUP_SOURCES: [EffectiveLimitSource; CGROUP_SOURCE_COUNT] = [
    EffectiveLimitSource::MemoryMax,
    EffectiveLimitSource::MemorySwapMax,
    EffectiveLimitSource::PidsMax,
    EffectiveLimitSource::CpuMax,
];

impl EffectiveLimitSource {
    const fn index(self) -> usize {
        self as usize
    }

    /// Return the exact kernel filename or `/work` observation label.
    #[must_use]
    pub const fn name(self) -> &'static str {
        SOURCE_SPECS[self.index()].name
    }

    /// Return the closed ELM1 limit ID this observation reads back.
    #[must_use]
    pub const fn limit_id(self) -> u8 {
        SOURCE_SPECS[self.index()].limit_id
    }
}

/// One effective kernel value, compared exactly at kernel granularity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectiveKernelLimit {
    /// A finite byte, task, or CPU-microsecond ceiling.
    Bounded(u64),
    /// The kernel reports `max`, so it enforces no ceiling.
    Unlimited,
    /// No `/work` filesystem was observed or requested.
    Absent,
}

/// Failure to read one complete effective-limit observation.
#[derive(Debug, thiserror::Error)]
pub enum EffectiveLimitError {
    /// The exact bound cgroup could not be verified before or after reading.
    #[error(transparent)]
    Cgroup(#[from] AttemptCgroupError),
    /// A limit file could not be opened beneath the retained cgroup.
    #[error("failed to open effective limit source {property}")]
    Open {
        property: &'static str,
        #[source]
        error: Errno,
    },
    /// A limit file could not be read completely.
    #[error("failed to read effective limit source {property}")]
    Read {
        property: &'static str,
        #[source]
        error: std::io::Error,
    },
    /// A limit file exceeded its closed read bound.
    #[error("effective limit source {property} exceeded the read bound")]
    TooLong { property: &'static str },
    /// A limit file was not one canonical kernel value line.
    #[error("effective limit source {property} was malformed")]
    Malformed { property: &'static str },
    /// The retained `/work` directory could not be inspected.
    #[error("failed to statfs the retained /work directory")]
    WorkStatfs(#[source] Errno),
    /// The retained `/work` directory is not the requested tmpfs.
    #[error("the retained /work directory is not tmpfs")]
    WorkNotTmpfs,
    /// The `/work` block size or capacity is not representable.
    #[error("the retained /work capacity is not representable")]
    WorkCapacityMalformed,
}

/// Effective cgroup v2 limits read from one exact bound attempt cgroup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectiveCgroupLimits {
    identity: BoundCgroupIdentity,
    raw: [Vec<u8>; CGROUP_SOURCE_COUNT],
    values: [EffectiveKernelLimit; CGROUP_SOURCE_COUNT],
    cpu_period_microseconds: u64,
}

impl EffectiveCgroupLimits {
    /// Return the exact deterministic unit name.
    #[must_use]
    pub const fn unit_name(&self) -> &TransientServiceUnitName {
        &self.identity.unit_name
    }

    /// Return the verified systemd unit object path.
    #[must_use]
    pub fn unit_path(&self) -> &str {
        self.identity.unit_path.as_str()
    }

    /// Return the manager-reported cgroup path.
    #[must_use]
    pub fn control_group(&self) -> &str {
        &self.identity.control_group
    }

    /// Return the device and inode of the retained cgroup directory.
    #[must_use]
    pub const fn cgroup_identity(&self) -> (u64, u64) {
        (self.identity.device, self.identity.inode)
    }

    /// Return the exact bounded bytes of one cgroup source.
    ///
    /// The `/work` observations have no cgroup bytes and return `None`.
    #[must_use]
    pub fn raw(&self, source: EffectiveLimitSource) -> Option<&[u8]> {
        self.raw.get(source.index()).map(Vec::as_slice)
    }

    /// Return the parsed kernel value of one cgroup source.
    ///
    /// For `cpu.max` this is the quota in microseconds per reported period.
    /// The `/work` observations are not cgroup values and return `None`.
    #[must_use]
    pub fn value(&self, source: EffectiveLimitSource) -> Option<EffectiveKernelLimit> {
        self.values.get(source.index()).copied()
    }

    /// Return the `cpu.max` period in microseconds.
    #[must_use]
    pub const fn cpu_period_microseconds(&self) -> u64 {
        self.cpu_period_microseconds
    }

    /// Compare these kernel values and two `/work` observations with a request.
    ///
    /// Memory and swap ceilings match at page granularity, rounded down as
    /// the kernel stores them. The CPU quota must equal the requested
    /// per-million share of the reported period, rounded down; a larger
    /// kernel quota is a mismatch. `/work` must be absent when zero bytes are
    /// requested, or exactly the request rounded up to whole pages, both
    /// before and after the payload. `max` never matches a requested ceiling.
    #[must_use]
    pub fn compare(
        &self,
        requested: &SystemdServiceLimits,
        work_before: Option<WorkCapacity>,
        work_after: Option<WorkCapacity>,
    ) -> EffectiveLimitVerdict {
        let page = page_size() as u64;
        let work = expected_work(requested.work_bytes(), page);
        let rows = [
            (
                EffectiveLimitSource::MemoryMax,
                floor_to_page(
                    requested.value(SystemdOperatingLimitProperty::MemoryMax),
                    page,
                ),
            ),
            (
                EffectiveLimitSource::MemorySwapMax,
                floor_to_page(
                    requested.value(SystemdOperatingLimitProperty::MemorySwapMax),
                    page,
                ),
            ),
            (
                EffectiveLimitSource::PidsMax,
                EffectiveKernelLimit::Bounded(
                    requested.value(SystemdOperatingLimitProperty::TasksMax),
                ),
            ),
            (
                EffectiveLimitSource::CpuMax,
                EffectiveKernelLimit::Bounded(cpu_quota(
                    requested.value(SystemdOperatingLimitProperty::CpuQuotaPerSecUSec),
                    self.cpu_period_microseconds,
                )),
            ),
        ]
        .map(|(source, expected)| (source, expected, self.values[source.index()]));
        let work_rows = [
            (
                EffectiveLimitSource::WorkCapacityBefore,
                work,
                observed_work(work_before),
            ),
            (
                EffectiveLimitSource::WorkCapacityAfter,
                work,
                observed_work(work_after),
            ),
        ];
        EffectiveLimitVerdict::from_mismatches(
            rows.into_iter()
                .chain(work_rows)
                .filter(|(_, expected, observed)| expected != observed)
                .map(|(source, expected, observed)| EffectiveLimitMismatch {
                    source,
                    expected,
                    observed,
                })
                .collect(),
        )
    }
}

/// One `statfs` capacity observation of the retained `/work` directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkCapacity {
    bytes: u64,
}

type StatfsFields = (Option<u64>, Option<u64>, u64);

impl WorkCapacity {
    /// Observe the tmpfs capacity through a retained `/work` directory handle.
    ///
    /// The caller must open the handle inside the attempt's mount namespace
    /// and retain it; this method never resolves a path.
    ///
    /// # Errors
    /// Rejects a failed `statfs`, a non-tmpfs filesystem, or an
    /// unrepresentable block size or capacity.
    pub fn observe(directory: &File) -> Result<Self, EffectiveLimitError> {
        Self::from_statfs(fstatfs(directory).map(|filesystem| {
            (
                u64::try_from(filesystem.f_type).ok(),
                u64::try_from(filesystem.f_bsize).ok(),
                filesystem.f_blocks,
            )
        }))
    }

    fn from_statfs(observed: Result<StatfsFields, Errno>) -> Result<Self, EffectiveLimitError> {
        let (filesystem, block_size, blocks) = observed.map_err(EffectiveLimitError::WorkStatfs)?;
        if filesystem != Some(TMPFS_MAGIC) {
            return Err(EffectiveLimitError::WorkNotTmpfs);
        }
        block_size
            .and_then(|size| size.checked_mul(blocks))
            .map(|bytes| Self { bytes })
            .ok_or(EffectiveLimitError::WorkCapacityMalformed)
    }

    /// Return the total filesystem capacity in bytes.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.bytes
    }
}

/// The typed result of comparing effective kernel limits with a request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectiveLimitVerdict {
    /// Every observed value equals the requested ceiling.
    Matched,
    /// At least one observation differs, in source order.
    Mismatched(Vec<EffectiveLimitMismatch>),
}

impl EffectiveLimitVerdict {
    fn from_mismatches(mismatches: Vec<EffectiveLimitMismatch>) -> Self {
        if mismatches.is_empty() {
            Self::Matched
        } else {
            Self::Mismatched(mismatches)
        }
    }
}

/// One observation that differs from its requested ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectiveLimitMismatch {
    source: EffectiveLimitSource,
    expected: EffectiveKernelLimit,
    observed: EffectiveKernelLimit,
}

impl EffectiveLimitMismatch {
    /// Return the observation that differed.
    #[must_use]
    pub const fn source(&self) -> EffectiveLimitSource {
        self.source
    }

    /// Return the requested value at kernel granularity.
    #[must_use]
    pub const fn expected(&self) -> EffectiveKernelLimit {
        self.expected
    }

    /// Return the value the kernel reported.
    #[must_use]
    pub const fn observed(&self) -> EffectiveKernelLimit {
        self.observed
    }
}

impl BoundAttemptCgroup {
    /// Read the effective memory, swap, task, and CPU limits of this cgroup.
    ///
    /// Every file is opened beneath the retained directory descriptor, and the
    /// bound identity is verified before and after the reads. This never
    /// writes a controller or claims enforcement.
    ///
    /// # Errors
    /// Rejects identity replacement or any missing, unsafe, unreadable,
    /// oversized, or malformed source.
    pub fn read_effective_limits(&self) -> Result<EffectiveCgroupLimits, EffectiveLimitError> {
        self.read_effective_limits_with_verifier(Self::verify_effective_limit_identity)
    }

    fn read_effective_limits_with_verifier(
        &self,
        mut verify: impl FnMut(&Self) -> Result<(), AttemptCgroupError>,
    ) -> Result<EffectiveCgroupLimits, EffectiveLimitError> {
        verify(self)?;
        let mut raw: [Vec<u8>; CGROUP_SOURCE_COUNT] = Default::default();
        for (slot, source) in raw.iter_mut().zip(CGROUP_SOURCES) {
            *slot = self.read_effective_source(source)?;
        }
        let limits = parse_limits(self.identity.clone(), raw)?;
        verify(self)?;
        Ok(limits)
    }

    fn verify_effective_limit_identity(&self) -> Result<(), AttemptCgroupError> {
        match self.inspect_path_with_metadata(File::metadata)? {
            BoundCgroupPath::Present => Ok(()),
            BoundCgroupPath::Missing { .. } => Err(AttemptCgroupError::PathOpen(Errno::NOENT)),
        }
    }

    fn read_effective_source(
        &self,
        source: EffectiveLimitSource,
    ) -> Result<Vec<u8>, EffectiveLimitError> {
        let property = source.name();
        let mut file = openat2(
            &self.directory,
            property,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
            RESOLVE_CHILD,
        )
        .map(File::from)
        .map_err(|error| EffectiveLimitError::Open { property, error })?;
        let mut raw = Vec::new();
        (&mut file)
            .take(MAX_SOURCE_BYTES + 1)
            .read_to_end(&mut raw)
            .map_err(|error| EffectiveLimitError::Read { property, error })?;
        if raw.len() as u64 > MAX_SOURCE_BYTES {
            return Err(EffectiveLimitError::TooLong { property });
        }
        Ok(raw)
    }
}

fn parse_limits(
    identity: BoundCgroupIdentity,
    raw: [Vec<u8>; CGROUP_SOURCE_COUNT],
) -> Result<EffectiveCgroupLimits, EffectiveLimitError> {
    let memory = parse_single(&raw[0], EffectiveLimitSource::MemoryMax)?;
    let swap = parse_single(&raw[1], EffectiveLimitSource::MemorySwapMax)?;
    let pids = parse_single(&raw[2], EffectiveLimitSource::PidsMax)?;
    let (quota, period) = single_line(&raw[3])
        .and_then(|line| line.split_once(' '))
        .and_then(|(quota, period)| parse_limit(quota).zip(parse_period(period)))
        .ok_or_else(|| malformed(EffectiveLimitSource::CpuMax))?;
    Ok(EffectiveCgroupLimits {
        identity,
        raw,
        values: [memory, swap, pids, quota],
        cpu_period_microseconds: period,
    })
}

fn parse_single(
    raw: &[u8],
    source: EffectiveLimitSource,
) -> Result<EffectiveKernelLimit, EffectiveLimitError> {
    single_line(raw)
        .and_then(parse_limit)
        .ok_or_else(|| malformed(source))
}

const fn malformed(source: EffectiveLimitSource) -> EffectiveLimitError {
    EffectiveLimitError::Malformed {
        property: source.name(),
    }
}

fn single_line(raw: &[u8]) -> Option<&str> {
    std::str::from_utf8(raw)
        .ok()
        .and_then(|text| text.strip_suffix('\n'))
        .filter(|line| !line.contains('\n'))
}

fn parse_limit(field: &str) -> Option<EffectiveKernelLimit> {
    if field == "max" {
        Some(EffectiveKernelLimit::Unlimited)
    } else {
        parse_digits(field).map(EffectiveKernelLimit::Bounded)
    }
}

fn parse_period(field: &str) -> Option<u64> {
    parse_digits(field)
        .filter(|period| (MIN_CPU_PERIOD_MICROSECONDS..=MICROSECONDS_PER_SECOND).contains(period))
}

fn parse_digits(field: &str) -> Option<u64> {
    field
        .bytes()
        .all(|byte| byte.is_ascii_digit())
        .then(|| field.parse().ok())
        .flatten()
}

const fn floor_to_page(value: u64, page: u64) -> EffectiveKernelLimit {
    EffectiveKernelLimit::Bounded(value - value % page)
}

/// The `/work` capacity tmpfs reports for a request, rounded up to pages.
///
/// A request too large to round saturates, which no page-multiple capacity
/// can equal, so it fails closed as a mismatch.
const fn expected_work(work_bytes: u64, page: u64) -> EffectiveKernelLimit {
    if work_bytes == 0 {
        EffectiveKernelLimit::Absent
    } else {
        EffectiveKernelLimit::Bounded(work_bytes.div_ceil(page).saturating_mul(page))
    }
}

fn observed_work(observed: Option<WorkCapacity>) -> EffectiveKernelLimit {
    observed.map_or(EffectiveKernelLimit::Absent, |capacity| {
        EffectiveKernelLimit::Bounded(capacity.bytes)
    })
}

/// The kernel quota for a per-million CPU share, rounded down.
///
/// `period` is at most one second, so neither product can overflow.
const fn cpu_quota(per_million: u64, period: u64) -> u64 {
    per_million / MICROSECONDS_PER_SECOND * period
        + per_million % MICROSECONDS_PER_SECOND * period / MICROSECONDS_PER_SECOND
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::error::Error;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};

    use pos_reference::sandbox_provider_protocol::SandboxLimit;
    use zbus::OwnedObjectPath;

    use crate::CgroupRoot;

    use super::*;

    const PIDS: u64 = 16;
    const CPU_PER_MILLION: u64 = 500_000;
    const CPU_PERIOD: u64 = 100_000;
    const CPU_QUOTA: u64 = 50_000;

    fn page() -> u64 {
        page_size() as u64
    }

    fn sources() -> [EffectiveLimitSource; 6] {
        [
            EffectiveLimitSource::MemoryMax,
            EffectiveLimitSource::MemorySwapMax,
            EffectiveLimitSource::PidsMax,
            EffectiveLimitSource::CpuMax,
            EffectiveLimitSource::WorkCapacityBefore,
            EffectiveLimitSource::WorkCapacityAfter,
        ]
    }

    fn requested(
        memory: u64,
        swap: u64,
        cpu: u64,
        work: u64,
    ) -> Result<SystemdServiceLimits, Box<dyn Error>> {
        let limits: Vec<SandboxLimit> = (0..=16)
            .map(|limit_id| SandboxLimit {
                limit_id,
                value: match limit_id {
                    0 => memory,
                    1 => swap,
                    2 => PIDS,
                    3 => cpu,
                    4 => 5_000,
                    5 => 64,
                    6 => 4_096,
                    9 => work,
                    _ => 1_000,
                },
            })
            .collect();
        Ok(SystemdServiceLimits::from_effective_limits(&limits)?)
    }

    fn exact_request() -> Result<SystemdServiceLimits, Box<dyn Error>> {
        requested(32 * page(), 0, CPU_PER_MILLION, page())
    }

    fn exact_bytes(source: EffectiveLimitSource) -> Vec<u8> {
        match source {
            EffectiveLimitSource::MemoryMax => format!("{}\n", 32 * page()).into_bytes(),
            EffectiveLimitSource::MemorySwapMax => b"0\n".to_vec(),
            EffectiveLimitSource::PidsMax => format!("{PIDS}\n").into_bytes(),
            _ => format!("{CPU_QUOTA} {CPU_PERIOD}\n").into_bytes(),
        }
    }

    fn work(bytes: u64) -> Result<WorkCapacity, EffectiveLimitError> {
        WorkCapacity::from_statfs(Ok((Some(TMPFS_MAGIC), Some(page()), bytes / page())))
    }

    fn fixture(root: &Path) -> Result<(BoundAttemptCgroup, PathBuf), Box<dyn Error>> {
        let directory = root.join("system.slice/test.service");
        fs::create_dir_all(&directory)?;
        fs::write(directory.join("cgroup.events"), b"populated 1\n")?;
        for source in CGROUP_SOURCES {
            fs::write(directory.join(source.name()), exact_bytes(source))?;
        }
        let bound = BoundAttemptCgroup::open(
            CgroupRoot::for_test(File::open(root)?),
            TransientServiceUnitName::from_attempt_id([1; 16])?,
            OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/test")?,
            "/system.slice/test.service".to_owned(),
        )?;
        Ok((bound, directory))
    }

    fn mismatches(verdict: EffectiveLimitVerdict) -> Vec<EffectiveLimitMismatch> {
        match verdict {
            EffectiveLimitVerdict::Matched => Vec::new(),
            EffectiveLimitVerdict::Mismatched(mismatches) => mismatches,
        }
    }

    fn only_mismatch(
        verdict: EffectiveLimitVerdict,
    ) -> Result<EffectiveLimitMismatch, Box<dyn Error>> {
        match mismatches(verdict).as_slice() {
            [mismatch] => Ok(*mismatch),
            other => Err(format!("expected one mismatch, got {other:?}").into()),
        }
    }

    #[test]
    fn sources_name_their_kernel_files_and_closed_limit_ids() {
        assert_eq!(
            sources().map(EffectiveLimitSource::name),
            [
                "memory.max",
                "memory.swap.max",
                "pids.max",
                "cpu.max",
                "/work statfs before",
                "/work statfs after",
            ]
        );
        assert_eq!(
            sources().map(EffectiveLimitSource::limit_id),
            [0, 1, 2, 3, 9, 9]
        );
    }

    #[test]
    fn exact_kernel_values_and_work_capacity_match_the_request() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let (bound, _directory) = fixture(temporary.path())?;
        let limits = bound.read_effective_limits()?;
        assert_eq!(
            limits.unit_name(),
            &TransientServiceUnitName::from_attempt_id([1; 16])?
        );
        assert_eq!(limits.unit_path(), "/org/freedesktop/systemd1/unit/test");
        assert_eq!(limits.control_group(), "/system.slice/test.service");
        assert!(limits.cgroup_identity().1 > 0);
        assert_eq!(limits.cpu_period_microseconds(), CPU_PERIOD);
        for source in CGROUP_SOURCES {
            assert_eq!(limits.raw(source), Some(exact_bytes(source).as_slice()));
        }
        assert_eq!(
            limits.value(EffectiveLimitSource::MemoryMax),
            Some(EffectiveKernelLimit::Bounded(32 * page()))
        );
        assert_eq!(
            limits.value(EffectiveLimitSource::MemorySwapMax),
            Some(EffectiveKernelLimit::Bounded(0))
        );
        assert_eq!(
            limits.value(EffectiveLimitSource::PidsMax),
            Some(EffectiveKernelLimit::Bounded(PIDS))
        );
        assert_eq!(
            limits.value(EffectiveLimitSource::CpuMax),
            Some(EffectiveKernelLimit::Bounded(CPU_QUOTA))
        );
        for source in [
            EffectiveLimitSource::WorkCapacityBefore,
            EffectiveLimitSource::WorkCapacityAfter,
        ] {
            assert_eq!(limits.raw(source), None);
            assert_eq!(limits.value(source), None);
        }
        let capacity = work(page())?;
        assert_eq!(capacity.bytes(), page());
        assert_eq!(
            limits.compare(&exact_request()?, Some(capacity), Some(capacity)),
            EffectiveLimitVerdict::Matched
        );
        Ok(())
    }

    #[test]
    fn unaligned_requests_match_at_kernel_page_granularity() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let (bound, _directory) = fixture(temporary.path())?;
        let limits = bound.read_effective_limits()?;
        let capacity = work(page())?;
        let unaligned = requested(32 * page() + 1, page() - 1, CPU_PER_MILLION + 9, 1)?;
        assert_eq!(
            limits.compare(&unaligned, Some(capacity), Some(capacity)),
            EffectiveLimitVerdict::Matched
        );
        let below = requested(32 * page() - 1, 0, CPU_PER_MILLION, page())?;
        let mismatch = only_mismatch(limits.compare(&below, Some(capacity), Some(capacity)))?;
        assert_eq!(mismatch.source(), EffectiveLimitSource::MemoryMax);
        assert_eq!(
            mismatch.expected(),
            EffectiveKernelLimit::Bounded(31 * page())
        );
        assert_eq!(
            mismatch.observed(),
            EffectiveKernelLimit::Bounded(32 * page())
        );
        Ok(())
    }

    #[test]
    fn one_over_and_one_under_each_kernel_value_mismatch() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let (bound, directory) = fixture(temporary.path())?;
        let request = exact_request()?;
        let capacity = work(page())?;
        let cases: [(EffectiveLimitSource, [u64; 2], fn(u64) -> String); 4] = [
            (
                EffectiveLimitSource::MemoryMax,
                [31 * page(), 33 * page()],
                |value| format!("{value}\n"),
            ),
            (EffectiveLimitSource::MemorySwapMax, [page(), 1], |value| {
                format!("{value}\n")
            }),
            (
                EffectiveLimitSource::PidsMax,
                [PIDS - 1, PIDS + 1],
                |value| format!("{value}\n"),
            ),
            (
                EffectiveLimitSource::CpuMax,
                [CPU_QUOTA - 1, CPU_QUOTA + 1],
                |value| format!("{value} {CPU_PERIOD}\n"),
            ),
        ];
        for (source, values, render) in cases {
            let path = directory.join(source.name());
            for value in values {
                fs::write(&path, render(value))?;
                let limits = bound.read_effective_limits()?;
                let mismatch =
                    only_mismatch(limits.compare(&request, Some(capacity), Some(capacity)))?;
                assert_eq!(mismatch.source(), source);
                assert_eq!(mismatch.observed(), EffectiveKernelLimit::Bounded(value));
                assert_ne!(mismatch.expected(), mismatch.observed());
            }
            fs::write(&path, exact_bytes(source))?;
        }
        Ok(())
    }

    #[test]
    fn unlimited_kernel_values_never_match_a_requested_ceiling() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let (bound, directory) = fixture(temporary.path())?;
        let request = exact_request()?;
        let capacity = work(page())?;
        for source in CGROUP_SOURCES {
            let path = directory.join(source.name());
            let unlimited = if source == EffectiveLimitSource::CpuMax {
                format!("max {CPU_PERIOD}\n")
            } else {
                "max\n".to_owned()
            };
            fs::write(&path, unlimited)?;
            let limits = bound.read_effective_limits()?;
            assert_eq!(limits.value(source), Some(EffectiveKernelLimit::Unlimited));
            let mismatch = only_mismatch(limits.compare(&request, Some(capacity), Some(capacity)))?;
            assert_eq!(mismatch.source(), source);
            assert_eq!(mismatch.observed(), EffectiveKernelLimit::Unlimited);
            fs::write(&path, exact_bytes(source))?;
        }
        Ok(())
    }

    #[test]
    fn cpu_quota_tracks_the_reported_period() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let (bound, directory) = fixture(temporary.path())?;
        let capacity = work(page())?;
        let path = directory.join("cpu.max");
        for (per_million, line) in [
            (1_500_000, "1500000 1000000\n"),
            (500_000, "500 1000\n"),
            (999_999, "99999 100000\n"),
            (1, "0 1000\n"),
        ] {
            fs::write(&path, line)?;
            let limits = bound.read_effective_limits()?;
            let request = requested(32 * page(), 0, per_million, page())?;
            assert_eq!(
                limits.compare(&request, Some(capacity), Some(capacity)),
                EffectiveLimitVerdict::Matched,
                "{line}"
            );
        }
        let request = requested(32 * page(), 0, 5_000, page())?;
        fs::write(&path, "1000 100000\n")?;
        let limits = bound.read_effective_limits()?;
        let mismatch = only_mismatch(limits.compare(&request, Some(capacity), Some(capacity)))?;
        assert_eq!(mismatch.expected(), EffectiveKernelLimit::Bounded(500));
        assert_eq!(mismatch.observed(), EffectiveKernelLimit::Bounded(1_000));
        Ok(())
    }

    #[test]
    fn work_capacity_must_match_before_and_after() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let (bound, _directory) = fixture(temporary.path())?;
        let limits = bound.read_effective_limits()?;
        let request = exact_request()?;
        let exact = work(page())?;
        let over = work(2 * page())?;
        for (before, after, expected) in [
            (
                Some(over),
                Some(exact),
                vec![(EffectiveLimitSource::WorkCapacityBefore, over)],
            ),
            (
                Some(exact),
                Some(over),
                vec![(EffectiveLimitSource::WorkCapacityAfter, over)],
            ),
            (
                Some(over),
                Some(over),
                vec![
                    (EffectiveLimitSource::WorkCapacityBefore, over),
                    (EffectiveLimitSource::WorkCapacityAfter, over),
                ],
            ),
        ] {
            let found: Vec<_> = mismatches(limits.compare(&request, before, after))
                .into_iter()
                .map(|mismatch| (mismatch.source(), mismatch.observed()))
                .collect();
            let wanted: Vec<_> = expected
                .into_iter()
                .map(|(source, capacity)| (source, EffectiveKernelLimit::Bounded(capacity.bytes())))
                .collect();
            assert_eq!(found, wanted);
        }
        let missing = mismatches(limits.compare(&request, None, Some(exact)));
        assert_eq!(missing.len(), 1);
        assert_eq!(
            missing[0].source(),
            EffectiveLimitSource::WorkCapacityBefore
        );
        assert_eq!(missing[0].expected(), EffectiveKernelLimit::Bounded(page()));
        assert_eq!(missing[0].observed(), EffectiveKernelLimit::Absent);

        let no_work = requested(32 * page(), 0, CPU_PER_MILLION, 0)?;
        assert_eq!(
            limits.compare(&no_work, None, None),
            EffectiveLimitVerdict::Matched
        );
        let unexpected = only_mismatch(limits.compare(&no_work, None, Some(exact)))?;
        assert_eq!(unexpected.source(), EffectiveLimitSource::WorkCapacityAfter);
        assert_eq!(unexpected.expected(), EffectiveKernelLimit::Absent);

        let huge = requested(32 * page(), 0, CPU_PER_MILLION, u64::MAX - 1)?;
        let saturated = work(u64::MAX - u64::MAX % page())?;
        let verdict = mismatches(limits.compare(&huge, Some(saturated), Some(saturated)));
        assert_eq!(verdict.len(), 2);
        assert_eq!(
            verdict[0].expected(),
            EffectiveKernelLimit::Bounded(u64::MAX)
        );
        Ok(())
    }

    #[test]
    fn work_statfs_requires_a_representable_tmpfs() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let observed = WorkCapacity::observe(&File::open(temporary.path())?);
        assert!(matches!(
            observed,
            Ok(_) | Err(EffectiveLimitError::WorkNotTmpfs)
        ));
        assert!(matches!(
            WorkCapacity::from_statfs(Err(Errno::BADF)),
            Err(EffectiveLimitError::WorkStatfs(Errno::BADF))
        ));
        for filesystem in [None, Some(TMPFS_MAGIC + 1), Some(0x6367_7270)] {
            assert!(matches!(
                WorkCapacity::from_statfs(Ok((filesystem, Some(4096), 1))),
                Err(EffectiveLimitError::WorkNotTmpfs)
            ));
        }
        for (block_size, blocks) in [(None, 1), (Some(2), u64::MAX)] {
            assert!(matches!(
                WorkCapacity::from_statfs(Ok((Some(TMPFS_MAGIC), block_size, blocks))),
                Err(EffectiveLimitError::WorkCapacityMalformed)
            ));
        }
        assert_eq!(
            WorkCapacity::from_statfs(Ok((Some(TMPFS_MAGIC), Some(4096), 3)))?.bytes(),
            12_288
        );
        assert_eq!(
            WorkCapacity::from_statfs(Ok((Some(TMPFS_MAGIC), Some(4096), 0)))?.bytes(),
            0
        );
        Ok(())
    }

    #[test]
    fn malformed_values_fail_closed_for_every_source() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let (bound, directory) = fixture(temporary.path())?;
        let single: [&[u8]; 11] = [
            b"",
            b"\n",
            b"5",
            b"\xff\n",
            b"+5\n",
            b"-1\n",
            b" 5\n",
            b"5 \n",
            b"5\n6\n",
            b"MAX\n",
            b"18446744073709551616\n",
        ];
        let cpu: [&[u8]; 11] = [
            b"",
            b"max\n",
            b"50000\n",
            b"50000 100000",
            b"50000  100000\n",
            b"50000 100000 1\n",
            b"50000 max\n",
            b"x 100000\n",
            b"50000 999\n",
            b"50000 1000001\n",
            b"50000 100000\n1 1000\n",
        ];
        for source in CGROUP_SOURCES {
            let path = directory.join(source.name());
            let invalid: &[&[u8]] = if source == EffectiveLimitSource::CpuMax {
                &cpu
            } else {
                &single
            };
            for bytes in invalid {
                fs::write(&path, bytes)?;
                assert!(
                    matches!(
                        bound.read_effective_limits(),
                        Err(EffectiveLimitError::Malformed { property })
                            if property == source.name()
                    ),
                    "{source:?} {bytes:?}"
                );
            }
            fs::write(&path, exact_bytes(source))?;
        }
        for line in ["5 1000\n", "5 1000000\n"] {
            fs::write(directory.join("cpu.max"), line)?;
            assert_eq!(
                bound
                    .read_effective_limits()?
                    .value(EffectiveLimitSource::CpuMax),
                Some(EffectiveKernelLimit::Bounded(5))
            );
        }
        Ok(())
    }

    #[test]
    fn missing_unsafe_unreadable_and_oversized_sources_fail_closed() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let (bound, directory) = fixture(temporary.path())?;
        let outside = temporary.path().join("outside");
        fs::write(&outside, b"max\n")?;
        for source in CGROUP_SOURCES {
            let path = directory.join(source.name());
            fs::remove_file(&path)?;
            assert!(matches!(
                bound.read_effective_limits(),
                Err(EffectiveLimitError::Open { property, error: Errno::NOENT })
                    if property == source.name()
            ));
            symlink(&outside, &path)?;
            assert!(matches!(
                bound.read_effective_limits(),
                Err(EffectiveLimitError::Open { property, .. }) if property == source.name()
            ));
            fs::remove_file(&path)?;
            fs::create_dir(&path)?;
            assert!(matches!(
                bound.read_effective_limits(),
                Err(EffectiveLimitError::Read { property, .. }) if property == source.name()
            ));
            fs::remove_dir(&path)?;
            let bound_bytes = usize::try_from(MAX_SOURCE_BYTES)?;
            fs::write(&path, vec![b'1'; bound_bytes + 1])?;
            assert!(matches!(
                bound.read_effective_limits(),
                Err(EffectiveLimitError::TooLong { property }) if property == source.name()
            ));
            let mut exact = vec![b'1'; bound_bytes - 1];
            exact.push(b'\n');
            fs::write(&path, exact)?;
            assert!(!matches!(
                bound.read_effective_limits(),
                Err(EffectiveLimitError::TooLong { .. })
            ));
            fs::write(&path, exact_bytes(source))?;
        }
        Ok(())
    }

    #[test]
    fn identity_swap_or_removal_rejects_the_readback() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let (bound, directory) = fixture(temporary.path())?;
        let moved = directory.with_file_name("moved.service");
        fs::rename(&directory, &moved)?;
        fs::create_dir(&directory)?;
        for source in CGROUP_SOURCES {
            fs::write(directory.join(source.name()), exact_bytes(source))?;
        }
        assert!(matches!(
            bound.read_effective_limits(),
            Err(EffectiveLimitError::Cgroup(AttemptCgroupError::PathReused))
        ));
        for source in CGROUP_SOURCES {
            fs::remove_file(directory.join(source.name()))?;
        }
        fs::remove_dir(&directory)?;
        assert!(matches!(
            bound.read_effective_limits(),
            Err(EffectiveLimitError::Cgroup(AttemptCgroupError::PathOpen(
                Errno::NOENT
            )))
        ));
        Ok(())
    }

    #[test]
    fn identity_replacement_after_source_reads_rejects_the_readback() -> Result<(), Box<dyn Error>>
    {
        let temporary = tempfile::tempdir()?;
        let (bound, _directory) = fixture(temporary.path())?;
        let mut checks = 0;
        assert!(matches!(
            bound.read_effective_limits_with_verifier(|cgroup| {
                checks += 1;
                if checks == 2 {
                    Err(AttemptCgroupError::PathReused)
                } else {
                    cgroup.verify_effective_limit_identity()
                }
            }),
            Err(EffectiveLimitError::Cgroup(AttemptCgroupError::PathReused))
        ));
        assert_eq!(checks, 2);
        Ok(())
    }
}
