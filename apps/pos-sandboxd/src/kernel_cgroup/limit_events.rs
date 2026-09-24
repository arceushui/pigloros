//! Bounded, descriptor-bound operating-limit event observations.

use std::collections::BTreeMap;
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::unix::fs::MetadataExt;

use rustix::fs::{openat2, Mode, OFlags};
use rustix::time::{clock_gettime, ClockId};
use zbus::zvariant::OwnedObjectPath;

use crate::TransientServiceUnitName;

use super::{relative_cgroup_path, AttemptCgroupError, BoundAttemptCgroup, RESOLVE_CHILD};

const MAX_SOURCE_BYTES: u64 = 4096;

/// One exact cgroup v2 source of per-attempt operating-limit event evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptLimitEventSource {
    /// Non-hierarchical memory events for the bound cgroup.
    MemoryEventsLocal,
    /// Swap-limit events for the bound cgroup.
    MemorySwapEvents,
    /// Non-hierarchical task-limit events for the bound cgroup.
    PidsEventsLocal,
    /// CPU usage and throttling telemetry for the bound cgroup.
    CpuStat,
}

const SOURCES: [AttemptLimitEventSource; 4] = [
    AttemptLimitEventSource::MemoryEventsLocal,
    AttemptLimitEventSource::MemorySwapEvents,
    AttemptLimitEventSource::PidsEventsLocal,
    AttemptLimitEventSource::CpuStat,
];

impl AttemptLimitEventSource {
    const fn index(self) -> usize {
        match self {
            Self::MemoryEventsLocal => 0,
            Self::MemorySwapEvents => 1,
            Self::PidsEventsLocal => 2,
            Self::CpuStat => 3,
        }
    }

    const fn file_name(self) -> &'static str {
        match self {
            Self::MemoryEventsLocal => "memory.events.local",
            Self::MemorySwapEvents => "memory.swap.events",
            Self::PidsEventsLocal => "pids.events.local",
            Self::CpuStat => "cpu.stat",
        }
    }

    const fn required_counters(self) -> &'static [AttemptLimitEventCounter] {
        match self {
            Self::MemoryEventsLocal => &MEMORY_COUNTERS,
            Self::MemorySwapEvents => &SWAP_COUNTERS,
            Self::PidsEventsLocal => &PIDS_COUNTERS,
            Self::CpuStat => &CPU_COUNTERS,
        }
    }
}

/// A counter from the exact bound cgroup; CPU throttling is telemetry only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptLimitEventCounter {
    /// Processes killed by an out-of-memory killer.
    MemoryOomKill,
    /// Times memory use approached the configured maximum.
    MemoryMax,
    /// Times swap allocation failed at the maximum.
    SwapMax,
    /// Times task creation hit the process ceiling.
    PidsMax,
    /// CPU bandwidth periods in which throttling occurred.
    CpuNrThrottled,
    /// Total CPU bandwidth throttling time in microseconds.
    CpuThrottledUsec,
}

const MEMORY_COUNTERS: [AttemptLimitEventCounter; 2] = [
    AttemptLimitEventCounter::MemoryOomKill,
    AttemptLimitEventCounter::MemoryMax,
];
const SWAP_COUNTERS: [AttemptLimitEventCounter; 1] = [AttemptLimitEventCounter::SwapMax];
const PIDS_COUNTERS: [AttemptLimitEventCounter; 1] = [AttemptLimitEventCounter::PidsMax];
const CPU_COUNTERS: [AttemptLimitEventCounter; 2] = [
    AttemptLimitEventCounter::CpuNrThrottled,
    AttemptLimitEventCounter::CpuThrottledUsec,
];
const COUNTERS: [AttemptLimitEventCounter; 6] = [
    AttemptLimitEventCounter::MemoryOomKill,
    AttemptLimitEventCounter::MemoryMax,
    AttemptLimitEventCounter::SwapMax,
    AttemptLimitEventCounter::PidsMax,
    AttemptLimitEventCounter::CpuNrThrottled,
    AttemptLimitEventCounter::CpuThrottledUsec,
];

impl AttemptLimitEventCounter {
    const fn index(self) -> usize {
        match self {
            Self::MemoryOomKill => 0,
            Self::MemoryMax => 1,
            Self::SwapMax => 2,
            Self::PidsMax => 3,
            Self::CpuNrThrottled => 4,
            Self::CpuThrottledUsec => 5,
        }
    }

    const fn key(self) -> &'static str {
        match self {
            Self::MemoryOomKill => "oom_kill",
            Self::MemoryMax | Self::SwapMax | Self::PidsMax => "max",
            Self::CpuNrThrottled => "nr_throttled",
            Self::CpuThrottledUsec => "throttled_usec",
        }
    }
}

/// One complete bounded set of raw operating-limit event sources.
///
/// This is a read-only snapshot, not a claim of resource exhaustion or cleanup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptLimitEventSnapshot {
    unit_name: TransientServiceUnitName,
    unit_path: OwnedObjectPath,
    control_group: String,
    device: u64,
    inode: u64,
    raw: [Vec<u8>; 4],
    counters: [u64; 6],
    monotonic_seconds: i64,
    monotonic_nanoseconds: i64,
}

impl AttemptLimitEventSnapshot {
    /// Return the exact deterministic unit name.
    #[must_use]
    pub const fn unit_name(&self) -> &TransientServiceUnitName {
        &self.unit_name
    }

    /// Return the verified systemd unit object path.
    #[must_use]
    pub fn unit_path(&self) -> &str {
        self.unit_path.as_str()
    }

    /// Return the manager-reported cgroup path.
    #[must_use]
    pub fn control_group(&self) -> &str {
        &self.control_group
    }

    /// Return the device and inode of the retained cgroup directory.
    #[must_use]
    pub const fn cgroup_identity(&self) -> (u64, u64) {
        (self.device, self.inode)
    }

    /// Return the exact bounded source bytes for later signed evidence.
    #[must_use]
    pub fn raw(&self, source: AttemptLimitEventSource) -> &[u8] {
        &self.raw[source.index()]
    }

    /// Return one absolute kernel event counter without assigning an outcome.
    #[must_use]
    pub const fn counter(&self, counter: AttemptLimitEventCounter) -> u64 {
        self.counters[counter.index()]
    }

    /// Return the `CLOCK_MONOTONIC` capture time as seconds and nanoseconds.
    #[must_use]
    pub const fn observed_monotonic(&self) -> (i64, i64) {
        (self.monotonic_seconds, self.monotonic_nanoseconds)
    }

    /// Compare two snapshots of one bound cgroup using checked counter deltas.
    ///
    /// The caller must capture the baseline before releasing the launcher and
    /// the terminal snapshot after payload exit but before cgroup removal.
    /// This comparison does not classify a terminal outcome.
    ///
    /// # Errors
    /// Rejects changed identity, reversed observation time, or any decreased
    /// required counter.
    pub fn delta_to(self, terminal: Self) -> Result<AttemptLimitEventDelta, AttemptCgroupError> {
        if self.unit_name != terminal.unit_name
            || self.unit_path != terminal.unit_path
            || self.control_group != terminal.control_group
            || self.device != terminal.device
            || self.inode != terminal.inode
        {
            return Err(AttemptCgroupError::LimitEventIdentityMismatch);
        }
        if self.observed_monotonic() > terminal.observed_monotonic() {
            return Err(AttemptCgroupError::LimitEventTimeReversed);
        }
        let mut increases = [0; 6];
        for counter in COUNTERS {
            let index = counter.index();
            increases[index] = terminal.counters[index]
                .checked_sub(self.counters[index])
                .ok_or(AttemptCgroupError::LimitEventCounterDecreased { counter })?;
        }
        Ok(AttemptLimitEventDelta {
            baseline: self,
            terminal,
            increases,
        })
    }
}

/// Checked counter increases with both immutable raw-source snapshots.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptLimitEventDelta {
    baseline: AttemptLimitEventSnapshot,
    terminal: AttemptLimitEventSnapshot,
    increases: [u64; 6],
}

impl AttemptLimitEventDelta {
    /// Return the pre-release baseline and its raw evidence.
    #[must_use]
    pub const fn baseline(&self) -> &AttemptLimitEventSnapshot {
        &self.baseline
    }

    /// Return the post-exit terminal snapshot and its raw evidence.
    #[must_use]
    pub const fn terminal(&self) -> &AttemptLimitEventSnapshot {
        &self.terminal
    }

    /// Return a checked increase; CPU throttling alone is telemetry.
    #[must_use]
    pub const fn increase(&self, counter: AttemptLimitEventCounter) -> u64 {
        self.increases[counter.index()]
    }
}

impl BoundAttemptCgroup {
    /// Capture all required operating-limit event sources from the exact bound cgroup.
    ///
    /// This method never writes cgroup controllers or interprets event counters
    /// as a terminal result. The caller owns capture ordering around release
    /// and exit, and must keep the cgroup alive through the terminal capture.
    ///
    /// # Errors
    /// Rejects identity replacement or any missing, unsafe, unreadable,
    /// oversized, malformed, or incomplete source.
    pub fn capture_limit_events(&self) -> Result<AttemptLimitEventSnapshot, AttemptCgroupError> {
        self.capture_limit_events_with_verifier(Self::verify_limit_event_identity)
    }

    fn capture_limit_events_with_verifier(
        &self,
        mut verify: impl FnMut(&Self) -> Result<(), AttemptCgroupError>,
    ) -> Result<AttemptLimitEventSnapshot, AttemptCgroupError> {
        verify(self)?;
        let mut raw = std::array::from_fn(|_| Vec::new());
        let mut counters = [0; 6];
        for source in SOURCES {
            let bytes = self.read_limit_event_source(source)?;
            let parsed = parse_flat_counters(&bytes, source)?;
            for &counter in source.required_counters() {
                let Some(&value) = parsed.get(counter.key()) else {
                    return Err(AttemptCgroupError::MalformedLimitEvents {
                        property: source.file_name(),
                    });
                };
                counters[counter.index()] = value;
            }
            raw[source.index()] = bytes;
        }
        verify(self)?;
        let observed = clock_gettime(ClockId::Monotonic);
        Ok(AttemptLimitEventSnapshot {
            unit_name: self.unit_name.clone(),
            unit_path: self.unit_path.clone(),
            control_group: self.control_group.clone(),
            device: self.device,
            inode: self.inode,
            raw,
            counters,
            monotonic_seconds: observed.tv_sec,
            monotonic_nanoseconds: observed.tv_nsec,
        })
    }

    fn verify_limit_event_identity(&self) -> Result<(), AttemptCgroupError> {
        self.verify_limit_event_identity_with_metadata(File::metadata)
    }

    fn verify_limit_event_identity_with_metadata(
        &self,
        mut read_metadata: impl FnMut(&File) -> std::io::Result<Metadata>,
    ) -> Result<(), AttemptCgroupError> {
        let retained = read_metadata(&self.directory).map_err(AttemptCgroupError::Metadata)?;
        if retained.dev() != self.device || retained.ino() != self.inode {
            return Err(AttemptCgroupError::PathReused);
        }
        let relative = relative_cgroup_path(&self.control_group)?;
        let current = openat2(
            &self.root.0,
            relative,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            RESOLVE_CHILD,
        )
        .map(File::from)
        .map_err(AttemptCgroupError::PathOpen)?;
        let metadata = read_metadata(&current).map_err(AttemptCgroupError::Metadata)?;
        if metadata.dev() != self.device || metadata.ino() != self.inode {
            return Err(AttemptCgroupError::PathReused);
        }
        Ok(())
    }

    fn read_limit_event_source(
        &self,
        source: AttemptLimitEventSource,
    ) -> Result<Vec<u8>, AttemptCgroupError> {
        let property = source.file_name();
        let mut file = openat2(
            &self.directory,
            property,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
            RESOLVE_CHILD,
        )
        .map(File::from)
        .map_err(|error| AttemptCgroupError::LimitEventOpen { property, error })?;
        let mut raw = Vec::new();
        (&mut file)
            .take(MAX_SOURCE_BYTES + 1)
            .read_to_end(&mut raw)
            .map_err(|error| AttemptCgroupError::LimitEventRead { property, error })?;
        if raw.len() as u64 > MAX_SOURCE_BYTES {
            return Err(AttemptCgroupError::LimitEventTooLong { property });
        }
        Ok(raw)
    }
}

fn parse_flat_counters(
    raw: &[u8],
    source: AttemptLimitEventSource,
) -> Result<BTreeMap<&str, u64>, AttemptCgroupError> {
    let malformed = || AttemptCgroupError::MalformedLimitEvents {
        property: source.file_name(),
    };
    let text = std::str::from_utf8(raw).map_err(|_| malformed())?;
    if !raw.ends_with(b"\n") {
        return Err(malformed());
    }
    let mut counters = BTreeMap::new();
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let (Some(key), Some(value), None) = (fields.next(), fields.next(), fields.next()) else {
            return Err(malformed());
        };
        if !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(malformed());
        }
        let value = value.parse().map_err(|_| malformed())?;
        if counters.insert(key, value).is_some() {
            return Err(malformed());
        }
    }
    Ok(counters)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::error::Error;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};

    use crate::CgroupRoot;

    use super::*;

    fn source_bytes(source: AttemptLimitEventSource) -> &'static [u8] {
        match source {
            AttemptLimitEventSource::MemoryEventsLocal => {
                b"low 0\nmax 5\noom_kill 5\nfuture_counter 8\n"
            }
            AttemptLimitEventSource::MemorySwapEvents => b"max 5\nfail 0\n",
            AttemptLimitEventSource::PidsEventsLocal => b"max 5\n",
            AttemptLimitEventSource::CpuStat => b"usage_usec 9\nnr_throttled 5\nthrottled_usec 5\n",
        }
    }

    fn fixture(root: &Path) -> Result<(BoundAttemptCgroup, PathBuf), Box<dyn Error>> {
        let directory = root.join("system.slice/test.service");
        fs::create_dir_all(&directory)?;
        fs::write(directory.join("cgroup.events"), b"populated 1\n")?;
        for source in SOURCES {
            fs::write(directory.join(source.file_name()), source_bytes(source))?;
        }
        let bound = BoundAttemptCgroup::open(
            CgroupRoot::for_test(File::open(root)?),
            TransientServiceUnitName::from_attempt_id([1; 16])?,
            OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/test")?,
            "/system.slice/test.service".to_owned(),
        )?;
        Ok((bound, directory))
    }

    #[test]
    fn captures_exact_raw_sources_and_checked_terminal_increases() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let (bound, directory) = fixture(temporary.path())?;
        let baseline = bound.capture_limit_events()?;
        assert_eq!(
            baseline.unit_name(),
            &TransientServiceUnitName::from_attempt_id([1; 16])?
        );
        assert_eq!(baseline.unit_path(), "/org/freedesktop/systemd1/unit/test");
        assert_eq!(baseline.control_group(), "/system.slice/test.service");
        assert!(baseline.cgroup_identity().1 > 0);
        assert!(baseline.observed_monotonic().0 >= 0);
        for source in SOURCES {
            assert_eq!(baseline.raw(source), source_bytes(source));
        }
        for counter in COUNTERS {
            assert_eq!(baseline.counter(counter), 5);
        }

        fs::write(
            directory.join("memory.events.local"),
            b"low 0\nmax 6\noom_kill 7\nfuture_counter 9\n",
        )?;
        fs::write(directory.join("memory.swap.events"), b"max 8\nfail 0\n")?;
        fs::write(directory.join("pids.events.local"), b"max 9\n")?;
        fs::write(
            directory.join("cpu.stat"),
            b"usage_usec 30\nnr_throttled 10\nthrottled_usec 12\n",
        )?;
        let terminal = bound.capture_limit_events()?;
        assert!(baseline.observed_monotonic() <= terminal.observed_monotonic());
        let delta = baseline.delta_to(terminal)?;
        assert_eq!(delta.increase(AttemptLimitEventCounter::MemoryOomKill), 2);
        assert_eq!(delta.increase(AttemptLimitEventCounter::MemoryMax), 1);
        assert_eq!(delta.increase(AttemptLimitEventCounter::SwapMax), 3);
        assert_eq!(delta.increase(AttemptLimitEventCounter::PidsMax), 4);
        assert_eq!(delta.increase(AttemptLimitEventCounter::CpuNrThrottled), 5);
        assert_eq!(
            delta.increase(AttemptLimitEventCounter::CpuThrottledUsec),
            7
        );
        assert_eq!(
            delta
                .baseline()
                .counter(AttemptLimitEventCounter::MemoryOomKill),
            5
        );
        assert_eq!(
            delta
                .terminal()
                .counter(AttemptLimitEventCounter::MemoryOomKill),
            7
        );
        assert_eq!(
            delta
                .terminal()
                .raw(AttemptLimitEventSource::MemoryEventsLocal),
            b"low 0\nmax 6\noom_kill 7\nfuture_counter 9\n"
        );
        Ok(())
    }

    #[test]
    fn unchanged_and_cpu_throttling_only_snapshots_do_not_claim_exhaustion(
    ) -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let (bound, directory) = fixture(temporary.path())?;
        let baseline = bound.capture_limit_events()?;
        let unchanged = baseline.clone().delta_to(baseline.clone())?;
        for counter in COUNTERS {
            assert_eq!(unchanged.increase(counter), 0);
        }
        fs::write(
            directory.join("cpu.stat"),
            b"usage_usec 30\nnr_throttled 6\nthrottled_usec 15\n",
        )?;
        let delta = baseline.delta_to(bound.capture_limit_events()?)?;
        for counter in [
            AttemptLimitEventCounter::MemoryOomKill,
            AttemptLimitEventCounter::MemoryMax,
            AttemptLimitEventCounter::SwapMax,
            AttemptLimitEventCounter::PidsMax,
        ] {
            assert_eq!(delta.increase(counter), 0);
        }
        assert_eq!(delta.increase(AttemptLimitEventCounter::CpuNrThrottled), 1);
        assert_eq!(
            delta.increase(AttemptLimitEventCounter::CpuThrottledUsec),
            10
        );
        Ok(())
    }

    #[test]
    fn all_sources_reject_missing_duplicate_malformed_and_overflowing_values(
    ) -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let (bound, directory) = fixture(temporary.path())?;
        let invalid: [&[u8]; 9] = [
            b"",
            b"\xff\n",
            b"unknown 1\n",
            b"foo 1",
            b"foo\n",
            b"foo 1 extra\n",
            b"foo +1\n",
            b"foo 18446744073709551616\n",
            b"foo 1\nfoo 2\n",
        ];
        for source in SOURCES {
            let path = directory.join(source.file_name());
            for bytes in invalid {
                fs::write(&path, bytes)?;
                assert!(matches!(
                    bound.capture_limit_events(),
                    Err(AttemptCgroupError::MalformedLimitEvents { property })
                        if property == source.file_name()
                ));
            }
            fs::write(&path, source_bytes(source))?;
        }
        Ok(())
    }

    #[test]
    fn source_open_read_and_bound_errors_fail_closed() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let (bound, directory) = fixture(temporary.path())?;
        let outside = temporary.path().join("outside");
        fs::write(&outside, b"max 5\n")?;
        for source in SOURCES {
            let path = directory.join(source.file_name());
            fs::remove_file(&path)?;
            assert!(matches!(
                bound.capture_limit_events(),
                Err(AttemptCgroupError::LimitEventOpen { property, .. })
                    if property == source.file_name()
            ));
            symlink(&outside, &path)?;
            assert!(matches!(
                bound.capture_limit_events(),
                Err(AttemptCgroupError::LimitEventOpen { property, .. })
                    if property == source.file_name()
            ));
            fs::remove_file(&path)?;
            fs::write(&path, source_bytes(source))?;
        }

        let memory = directory.join("memory.events.local");
        fs::remove_file(&memory)?;
        fs::create_dir(&memory)?;
        assert!(matches!(
            bound.capture_limit_events(),
            Err(AttemptCgroupError::LimitEventRead {
                property: "memory.events.local",
                ..
            })
        ));
        fs::remove_dir(&memory)?;
        fs::write(&memory, vec![b'0'; usize::try_from(MAX_SOURCE_BYTES)? + 1])?;
        assert!(matches!(
            bound.capture_limit_events(),
            Err(AttemptCgroupError::LimitEventTooLong {
                property: "memory.events.local"
            })
        ));
        Ok(())
    }

    #[test]
    fn bound_path_replacement_and_invalid_identity_reject_capture() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let (mut bound, directory) = fixture(temporary.path())?;
        let original_device = bound.device;
        bound.device = original_device.wrapping_add(1);
        assert!(matches!(
            bound.capture_limit_events(),
            Err(AttemptCgroupError::PathReused)
        ));
        bound.device = original_device;
        bound.control_group = "/".to_owned();
        assert!(matches!(
            bound.capture_limit_events(),
            Err(AttemptCgroupError::InvalidPath)
        ));
        bound.control_group = "/system.slice/test.service".to_owned();
        let moved = directory.with_file_name("moved.service");
        fs::rename(&directory, &moved)?;
        fs::create_dir(&directory)?;
        assert!(matches!(
            bound.capture_limit_events(),
            Err(AttemptCgroupError::PathReused)
        ));
        fs::remove_dir(&directory)?;
        assert!(matches!(
            bound.capture_limit_events(),
            Err(AttemptCgroupError::PathOpen(_))
        ));
        Ok(())
    }

    #[test]
    fn identity_metadata_read_errors_fail_closed() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let (bound, _directory) = fixture(temporary.path())?;
        assert!(matches!(
            bound.verify_limit_event_identity_with_metadata(|_| Err(std::io::Error::other(
                "retained metadata read failed"
            ))),
            Err(AttemptCgroupError::Metadata(_))
        ));

        let mut reads = 0;
        assert!(matches!(
            bound.verify_limit_event_identity_with_metadata(|file| {
                reads += 1;
                if reads == 2 {
                    Err(std::io::Error::other("reopened metadata read failed"))
                } else {
                    file.metadata()
                }
            }),
            Err(AttemptCgroupError::Metadata(_))
        ));
        assert_eq!(reads, 2);
        Ok(())
    }

    #[test]
    fn identity_replacement_after_source_reads_rejects_capture() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let (bound, _directory) = fixture(temporary.path())?;
        let mut checks = 0;
        assert!(matches!(
            bound.capture_limit_events_with_verifier(|cgroup| {
                checks += 1;
                if checks == 2 {
                    Err(AttemptCgroupError::PathReused)
                } else {
                    cgroup.verify_limit_event_identity()
                }
            }),
            Err(AttemptCgroupError::PathReused)
        ));
        assert_eq!(checks, 2);
        Ok(())
    }

    #[test]
    fn snapshots_reject_foreign_identity_reversed_time_and_any_counter_decrease(
    ) -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let (bound, _directory) = fixture(temporary.path())?;
        let baseline = bound.capture_limit_events()?;
        let terminal = bound.capture_limit_events()?;
        let mut foreign = terminal.clone();
        foreign.unit_name = TransientServiceUnitName::from_attempt_id([2; 16])?;
        assert!(matches!(
            baseline.clone().delta_to(foreign),
            Err(AttemptCgroupError::LimitEventIdentityMismatch)
        ));
        let mut foreign = terminal.clone();
        foreign.unit_path = OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/other")?;
        assert!(matches!(
            baseline.clone().delta_to(foreign),
            Err(AttemptCgroupError::LimitEventIdentityMismatch)
        ));
        let mut foreign = terminal.clone();
        foreign.control_group = "/system.slice/other.service".to_owned();
        assert!(matches!(
            baseline.clone().delta_to(foreign),
            Err(AttemptCgroupError::LimitEventIdentityMismatch)
        ));
        let mut foreign = terminal.clone();
        foreign.device = foreign.device.wrapping_add(1);
        assert!(matches!(
            baseline.clone().delta_to(foreign),
            Err(AttemptCgroupError::LimitEventIdentityMismatch)
        ));
        let mut foreign = terminal.clone();
        foreign.inode = foreign.inode.wrapping_add(1);
        assert!(matches!(
            baseline.clone().delta_to(foreign),
            Err(AttemptCgroupError::LimitEventIdentityMismatch)
        ));
        let mut reversed = terminal.clone();
        reversed.monotonic_seconds = baseline.monotonic_seconds - 1;
        assert!(matches!(
            baseline.clone().delta_to(reversed),
            Err(AttemptCgroupError::LimitEventTimeReversed)
        ));
        for counter in COUNTERS {
            let mut decreased = terminal.clone();
            decreased.counters[counter.index()] = 4;
            assert!(matches!(
                baseline.clone().delta_to(decreased),
                Err(AttemptCgroupError::LimitEventCounterDecreased { .. })
            ));
        }
        Ok(())
    }
}
