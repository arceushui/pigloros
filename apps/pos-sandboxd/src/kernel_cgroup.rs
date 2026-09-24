//! Read-only kernel observations for one manager-bound attempt cgroup.

use std::fs::{File, Metadata};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;

use rustix::fs::{fstatfs, openat2, Mode, OFlags, ResolveFlags, CWD};
use rustix::io::Errno;
use rustix::time::{clock_gettime, ClockId};
use zbus::zvariant::OwnedObjectPath;

use crate::{CgroupRoot, TransientServiceUnitName};

mod limit_events;

pub use limit_events::{
    AttemptLimitEventCounter, AttemptLimitEventDelta, AttemptLimitEventSnapshot,
    AttemptLimitEventSource,
};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;
const MAX_CONTROL_GROUP_BYTES: usize = 4096;
const MAX_EVENTS_BYTES: u64 = 4096;
const RESOLVE_CHILD: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS)
    .union(ResolveFlags::NO_XDEV);

/// Failure to bind or independently observe the exact attempt cgroup.
#[derive(Debug, thiserror::Error)]
pub enum AttemptCgroupError {
    /// The manager returned no bounded normalized non-root cgroup path.
    #[error("systemd returned an invalid attempt cgroup path")]
    InvalidPath,
    /// The fixed unified hierarchy could not be opened without following links.
    #[error("failed to open the fixed cgroup v2 mount")]
    RootOpen(#[source] Errno),
    /// The fixed hierarchy could not be identified.
    #[error("failed to identify the fixed cgroup mount")]
    RootFilesystem(#[source] Errno),
    /// The fixed hierarchy is not cgroup v2.
    #[error("the fixed cgroup mount is not cgroup v2")]
    WrongFilesystem,
    /// The exact manager-reported cgroup directory could not be opened safely.
    #[error("failed to open the exact attempt cgroup")]
    PathOpen(#[source] Errno),
    /// The kernel events file could not be opened safely.
    #[error("failed to open attempt cgroup.events")]
    EventsOpen(#[source] Errno),
    /// The cgroup directory identity could not be read.
    #[error("failed to identify the exact attempt cgroup")]
    Metadata(#[source] std::io::Error),
    /// The retained kernel events file could not be read.
    #[error("failed to read attempt cgroup.events")]
    EventsRead(#[source] std::io::Error),
    /// The events file exceeded its closed read bound.
    #[error("attempt cgroup.events exceeded the read bound")]
    EventsTooLong,
    /// The events file lacks one unambiguous canonical populated value.
    #[error("attempt cgroup.events has no unambiguous populated value")]
    MalformedEvents,
    /// The exact original cgroup still contains a process in its subtree.
    #[error("the attempt cgroup remains populated")]
    StillPopulated,
    /// The manager-reported path was rebound to a different cgroup.
    #[error("the attempt cgroup path was replaced")]
    PathReused,
    /// A missing path did not prove that the retained cgroup itself was deleted.
    #[error("the attempt cgroup path disappeared without proven deletion")]
    DeletionUnproven,
    /// An exact limit-event source could not be opened beneath the retained cgroup.
    #[error("failed to open attempt cgroup limit-event source {property}")]
    LimitEventOpen {
        property: &'static str,
        #[source]
        error: Errno,
    },
    /// An exact limit-event source could not be read completely.
    #[error("failed to read attempt cgroup limit-event source {property}")]
    LimitEventRead {
        property: &'static str,
        #[source]
        error: std::io::Error,
    },
    /// An exact limit-event source exceeded the closed read bound.
    #[error("attempt cgroup limit-event source {property} exceeded the read bound")]
    LimitEventTooLong { property: &'static str },
    /// A source had malformed, duplicate, or missing required counters.
    #[error("attempt cgroup limit-event source {property} was malformed")]
    MalformedLimitEvents { property: &'static str },
    /// Two snapshots did not refer to the exact same bound attempt cgroup.
    #[error("attempt cgroup limit-event snapshots have different identities")]
    LimitEventIdentityMismatch,
    /// A later snapshot carried an earlier monotonic observation time.
    #[error("attempt cgroup limit-event observation time moved backwards")]
    LimitEventTimeReversed,
    /// A kernel event counter decreased between the two snapshots.
    #[error("attempt cgroup limit-event counter {counter:?} decreased")]
    LimitEventCounterDecreased { counter: AttemptLimitEventCounter },
}

impl CgroupRoot {
    pub(crate) fn system() -> Result<Self, AttemptCgroupError> {
        Self::open_path(CGROUP_ROOT)
    }

    fn open_path(path: &str) -> Result<Self, AttemptCgroupError> {
        let root = openat2(
            CWD,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map(File::from)
        .map_err(AttemptCgroupError::RootOpen)?;
        Self::verify(root)
    }

    fn verify(root: File) -> Result<Self, AttemptCgroupError> {
        Self::verify_with(root, |file| fstatfs(file))
    }

    fn verify_with(
        root: File,
        inspect: impl FnOnce(&File) -> Result<rustix::fs::StatFs, Errno>,
    ) -> Result<Self, AttemptCgroupError> {
        let filesystem = inspect(&root).map_err(AttemptCgroupError::RootFilesystem)?;
        if u64::try_from(filesystem.f_type).ok() != Some(CGROUP2_SUPER_MAGIC) {
            return Err(AttemptCgroupError::WrongFilesystem);
        }
        Ok(Self(root))
    }

    #[cfg(test)]
    pub(crate) const fn for_test(root: File) -> Self {
        Self(root)
    }
}

/// Why the exact bound cgroup is known to contain no live processes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptCgroupEmptyBasis {
    /// The retained kernel cgroup.events reported populated=0.
    Events,
    /// The exact bound cgroup directory was removed from the retained mount.
    Deleted,
}

/// Read-only process-emptiness evidence, never full attempt cleanup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptCgroupEmptyObservation {
    unit_name: TransientServiceUnitName,
    unit_path: OwnedObjectPath,
    control_group: String,
    device: u64,
    inode: u64,
    basis: AttemptCgroupEmptyBasis,
    raw_events: Option<Vec<u8>>,
    monotonic_seconds: i64,
    monotonic_nanoseconds: i64,
}

impl AttemptCgroupEmptyObservation {
    /// Return the exact deterministic unit name.
    #[must_use]
    pub const fn unit_name(&self) -> &TransientServiceUnitName {
        &self.unit_name
    }

    /// Return the exact systemd object path bound before termination.
    #[must_use]
    pub fn unit_path(&self) -> &str {
        self.unit_path.as_str()
    }

    /// Return the manager-reported cgroup path, not a locally inferred path.
    #[must_use]
    pub fn control_group(&self) -> &str {
        &self.control_group
    }

    /// Return the device and inode of the cgroup opened before termination.
    #[must_use]
    pub const fn cgroup_identity(&self) -> (u64, u64) {
        (self.device, self.inode)
    }

    /// Distinguish a kernel populated=0 read from deletion of the bound path.
    #[must_use]
    pub const fn basis(&self) -> AttemptCgroupEmptyBasis {
        self.basis
    }

    /// Return the exact retained cgroup.events bytes when that file proved emptiness.
    #[must_use]
    pub fn raw_events(&self) -> Option<&[u8]> {
        self.raw_events.as_deref()
    }

    /// Return the `CLOCK_MONOTONIC` observation time as seconds and nanoseconds.
    #[must_use]
    pub const fn observed_monotonic(&self) -> (i64, i64) {
        (self.monotonic_seconds, self.monotonic_nanoseconds)
    }
}

/// A retained descriptor-bound attempt cgroup, without termination authority.
#[derive(Debug)]
pub struct BoundAttemptCgroup {
    root: CgroupRoot,
    directory: File,
    events: File,
    unit_name: TransientServiceUnitName,
    unit_path: OwnedObjectPath,
    control_group: String,
    device: u64,
    inode: u64,
}

impl BoundAttemptCgroup {
    pub(crate) fn open(
        root: CgroupRoot,
        unit_name: TransientServiceUnitName,
        unit_path: OwnedObjectPath,
        control_group: String,
    ) -> Result<Self, AttemptCgroupError> {
        Self::open_with_metadata(root, unit_name, unit_path, control_group, File::metadata)
    }

    fn open_with_metadata(
        root: CgroupRoot,
        unit_name: TransientServiceUnitName,
        unit_path: OwnedObjectPath,
        control_group: String,
        read_metadata: impl FnOnce(&File) -> std::io::Result<Metadata>,
    ) -> Result<Self, AttemptCgroupError> {
        let relative = relative_cgroup_path(&control_group)?;
        let directory = openat2(
            &root.0,
            relative,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            RESOLVE_CHILD,
        )
        .map(File::from)
        .map_err(AttemptCgroupError::PathOpen)?;
        let metadata = read_metadata(&directory).map_err(AttemptCgroupError::Metadata)?;
        let events = openat2(
            &directory,
            "cgroup.events",
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
            RESOLVE_CHILD,
        )
        .map(File::from)
        .map_err(AttemptCgroupError::EventsOpen)?;
        let mut bound = Self {
            root,
            directory,
            events,
            unit_name,
            unit_path,
            control_group,
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        let initial = bound.read_events()?;
        parse_populated(&initial)?;
        Ok(bound)
    }

    /// Return the exact manager-reported cgroup path retained before termination.
    #[must_use]
    pub fn control_group(&self) -> &str {
        &self.control_group
    }

    /// Return a process-empty observation for only this bound cgroup.
    ///
    /// Success does not prove unit absence or cleanup of mounts, namespaces,
    /// network resources, image mappings, or temporary files.
    ///
    /// # Errors
    /// Rejects a populated, malformed, unreadable, or identity-replaced cgroup.
    pub fn observe_empty(&mut self) -> Result<AttemptCgroupEmptyObservation, AttemptCgroupError> {
        self.observe_empty_with_metadata(File::metadata)
    }

    fn observe_empty_with_metadata(
        &mut self,
        mut read_metadata: impl FnMut(&File) -> std::io::Result<Metadata>,
    ) -> Result<AttemptCgroupEmptyObservation, AttemptCgroupError> {
        let retained = read_metadata(&self.directory).map_err(AttemptCgroupError::Metadata)?;
        if retained.dev() != self.device || retained.ino() != self.inode {
            return Err(AttemptCgroupError::PathReused);
        }
        let relative = relative_cgroup_path(&self.control_group)?;
        let basis_and_raw = match openat2(
            &self.root.0,
            relative,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            RESOLVE_CHILD,
        ) {
            Err(Errno::NOENT) => {
                if retained.nlink() != 0 {
                    return Err(AttemptCgroupError::DeletionUnproven);
                }
                (AttemptCgroupEmptyBasis::Deleted, None)
            }
            Err(error) => return Err(AttemptCgroupError::PathOpen(error)),
            Ok(current) => {
                let metadata =
                    read_metadata(&File::from(current)).map_err(AttemptCgroupError::Metadata)?;
                if metadata.dev() != self.device || metadata.ino() != self.inode {
                    return Err(AttemptCgroupError::PathReused);
                }
                let raw = self.read_events()?;
                if parse_populated(&raw)? {
                    return Err(AttemptCgroupError::StillPopulated);
                }
                (AttemptCgroupEmptyBasis::Events, Some(raw))
            }
        };
        let observed = clock_gettime(ClockId::Monotonic);
        Ok(AttemptCgroupEmptyObservation {
            unit_name: self.unit_name.clone(),
            unit_path: self.unit_path.clone(),
            control_group: self.control_group.clone(),
            device: self.device,
            inode: self.inode,
            basis: basis_and_raw.0,
            raw_events: basis_and_raw.1,
            monotonic_seconds: observed.tv_sec,
            monotonic_nanoseconds: observed.tv_nsec,
        })
    }

    fn read_events(&mut self) -> Result<Vec<u8>, AttemptCgroupError> {
        self.events
            .seek(SeekFrom::Start(0))
            .map_err(AttemptCgroupError::EventsRead)?;
        let mut raw = Vec::new();
        (&mut self.events)
            .take(MAX_EVENTS_BYTES + 1)
            .read_to_end(&mut raw)
            .map_err(AttemptCgroupError::EventsRead)?;
        if raw.len() as u64 > MAX_EVENTS_BYTES {
            return Err(AttemptCgroupError::EventsTooLong);
        }
        Ok(raw)
    }
}

fn relative_cgroup_path(path: &str) -> Result<&str, AttemptCgroupError> {
    if path.len() < 2
        || path.len() >= MAX_CONTROL_GROUP_BYTES
        || !path.starts_with('/')
        || path.as_bytes().contains(&0)
        || path
            .split('/')
            .skip(1)
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(AttemptCgroupError::InvalidPath);
    }
    Ok(&path[1..])
}

fn parse_populated(raw: &[u8]) -> Result<bool, AttemptCgroupError> {
    let text = std::str::from_utf8(raw).map_err(|_| AttemptCgroupError::MalformedEvents)?;
    let mut populated = None;
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let key = fields.next().ok_or(AttemptCgroupError::MalformedEvents)?;
        let value = fields.next().ok_or(AttemptCgroupError::MalformedEvents)?;
        if fields.next().is_some() {
            return Err(AttemptCgroupError::MalformedEvents);
        }
        if key == "populated" {
            if populated.is_some() {
                return Err(AttemptCgroupError::MalformedEvents);
            }
            populated = Some(match value {
                "0" => false,
                "1" => true,
                _ => return Err(AttemptCgroupError::MalformedEvents),
            });
        }
    }
    populated.ok_or(AttemptCgroupError::MalformedEvents)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::error::Error;
    use std::fs;
    use std::os::fd::OwnedFd;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixStream;

    use super::*;

    #[test]
    fn populated_parser_requires_one_bounded_binary_value() {
        assert_eq!(
            parse_populated(b"populated 0\nfrozen 1\n").ok(),
            Some(false)
        );
        assert_eq!(parse_populated(b"frozen 0\npopulated 1\n").ok(), Some(true));
        for malformed in [
            b"".as_slice(),
            b"\n".as_slice(),
            b"frozen 0\n".as_slice(),
            b"populated 2\n".as_slice(),
            b"populated 0\npopulated 1\n".as_slice(),
            b"populated\n".as_slice(),
            b"populated 0 extra\n".as_slice(),
            b"\xff".as_slice(),
        ] {
            assert!(matches!(
                parse_populated(malformed),
                Err(AttemptCgroupError::MalformedEvents)
            ));
        }
    }

    #[test]
    fn manager_path_must_be_bounded_normalized_and_non_root() {
        assert_eq!(
            relative_cgroup_path("/system.slice/test.service").ok(),
            Some("system.slice/test.service")
        );
        for path in [
            "", "/", "relative", "/a//b", "/a/./b", "/a/../b", "/a/", "/a\0b",
        ] {
            assert!(matches!(
                relative_cgroup_path(path),
                Err(AttemptCgroupError::InvalidPath)
            ));
        }
        assert!(matches!(
            relative_cgroup_path(&format!("/{}", "x".repeat(MAX_CONTROL_GROUP_BYTES))),
            Err(AttemptCgroupError::InvalidPath)
        ));
    }

    #[test]
    fn wrong_mount_type_rejects_before_binding() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let error = CgroupRoot::verify(File::open(temporary.path())?).err();
        assert!(matches!(error, Some(AttemptCgroupError::WrongFilesystem)));
        let error =
            CgroupRoot::verify_with(File::open(temporary.path())?, |_| Err(Errno::BADF)).err();
        assert!(matches!(error, Some(AttemptCgroupError::RootFilesystem(_))));
        Ok(())
    }

    #[test]
    fn fixed_mount_opens_and_missing_root_fails_closed() -> Result<(), Box<dyn Error>> {
        CgroupRoot::system()?;
        let temporary = tempfile::tempdir()?;
        let missing = temporary.path().join("missing-cgroup-root");
        let error = CgroupRoot::open_path(missing.to_str().ok_or("non-UTF-8 path")?).err();
        assert!(matches!(error, Some(AttemptCgroupError::RootOpen(_))));
        Ok(())
    }

    #[test]
    fn retained_handle_distinguishes_populated_empty_and_deleted() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let relative = "system.slice/test.service";
        let directory = temporary.path().join(relative);
        fs::create_dir_all(&directory)?;
        let events = directory.join("cgroup.events");
        fs::write(&events, b"populated 1\nfrozen 0\n")?;
        let mut bound = BoundAttemptCgroup::open(
            CgroupRoot::for_test(File::open(temporary.path())?),
            TransientServiceUnitName::from_attempt_id([1; 16])?,
            OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/test")?,
            format!("/{relative}"),
        )?;
        assert_eq!(bound.control_group(), "/system.slice/test.service");
        assert!(matches!(
            bound.observe_empty(),
            Err(AttemptCgroupError::StillPopulated)
        ));
        fs::write(&events, b"populated 0\nfrozen 0\n")?;
        let empty = bound.observe_empty()?;
        assert_eq!(empty.basis(), AttemptCgroupEmptyBasis::Events);
        assert_eq!(
            empty.raw_events(),
            Some(b"populated 0\nfrozen 0\n".as_slice())
        );
        assert_eq!(empty.control_group(), "/system.slice/test.service");
        assert_eq!(empty.unit_path(), "/org/freedesktop/systemd1/unit/test");
        assert!(empty.observed_monotonic().0 >= 0);
        let original_identity = empty.cgroup_identity();
        // Fault injection models an I/O failure on the retained events handle.
        bound.events = File::open(&directory)?;
        assert!(matches!(
            bound.observe_empty(),
            Err(AttemptCgroupError::EventsRead(_))
        ));
        let (socket, _peer) = UnixStream::pair()?;
        bound.events = File::from(OwnedFd::from(socket));
        assert!(matches!(
            bound.observe_empty(),
            Err(AttemptCgroupError::EventsRead(_))
        ));
        fs::remove_file(events)?;
        fs::remove_dir(&directory)?;
        let deleted = bound.observe_empty()?;
        assert_eq!(deleted.basis(), AttemptCgroupEmptyBasis::Deleted);
        assert_eq!(deleted.raw_events(), None);
        assert_eq!(deleted.cgroup_identity(), original_identity);
        Ok(())
    }

    #[test]
    fn path_replacement_cannot_prove_original_cgroup_empty() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let parent = temporary.path().join("system.slice");
        let directory = parent.join("test.service");
        fs::create_dir_all(&directory)?;
        fs::write(directory.join("cgroup.events"), b"populated 1\n")?;
        let mut bound = BoundAttemptCgroup::open(
            CgroupRoot::for_test(File::open(temporary.path())?),
            TransientServiceUnitName::from_attempt_id([2; 16])?,
            OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/test")?,
            "/system.slice/test.service".to_owned(),
        )?;
        let original_device = bound.device;
        bound.device = original_device.wrapping_add(1);
        assert!(matches!(
            bound.observe_empty(),
            Err(AttemptCgroupError::PathReused)
        ));
        bound.device = original_device;
        bound.control_group = "/".to_owned();
        assert!(matches!(
            bound.observe_empty(),
            Err(AttemptCgroupError::InvalidPath)
        ));
        bound.control_group = "/system.slice/test.service".to_owned();
        fs::rename(&directory, parent.join("moved.service"))?;
        assert!(matches!(
            bound.observe_empty(),
            Err(AttemptCgroupError::DeletionUnproven)
        ));
        symlink(parent.join("moved.service"), &directory)?;
        assert!(matches!(
            bound.observe_empty(),
            Err(AttemptCgroupError::PathOpen(_))
        ));
        fs::remove_file(&directory)?;
        fs::create_dir(&directory)?;
        fs::write(directory.join("cgroup.events"), b"populated 0\n")?;
        assert!(matches!(
            bound.observe_empty(),
            Err(AttemptCgroupError::PathReused)
        ));
        Ok(())
    }

    #[test]
    fn symlinked_path_and_events_are_rejected() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let parent = temporary.path().join("system.slice");
        let actual = parent.join("actual.service");
        fs::create_dir_all(&actual)?;
        fs::write(actual.join("cgroup.events"), b"populated 0\n")?;
        symlink(&actual, parent.join("test.service"))?;
        let root = File::open(temporary.path())?;
        let rejected = BoundAttemptCgroup::open(
            CgroupRoot::for_test(root),
            TransientServiceUnitName::from_attempt_id([3; 16])?,
            OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/test")?,
            "/system.slice/test.service".to_owned(),
        );
        assert!(matches!(rejected, Err(AttemptCgroupError::PathOpen(_))));

        fs::remove_file(parent.join("test.service"))?;
        fs::create_dir(parent.join("test.service"))?;
        symlink(
            actual.join("cgroup.events"),
            parent.join("test.service/cgroup.events"),
        )?;
        let rejected = BoundAttemptCgroup::open(
            CgroupRoot::for_test(File::open(temporary.path())?),
            TransientServiceUnitName::from_attempt_id([4; 16])?,
            OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/test")?,
            "/system.slice/test.service".to_owned(),
        );
        assert!(matches!(rejected, Err(AttemptCgroupError::EventsOpen(_))));
        Ok(())
    }

    #[test]
    fn malformed_or_oversized_kernel_events_fail_closed() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let directory = temporary.path().join("system.slice/test.service");
        fs::create_dir_all(&directory)?;
        let events = directory.join("cgroup.events");
        fs::write(&events, b"frozen 0\n")?;
        let root = File::open(temporary.path())?;
        let unit_name = TransientServiceUnitName::from_attempt_id([5; 16])?;
        let unit_path = OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/test")?;
        let make_bound = || {
            BoundAttemptCgroup::open(
                CgroupRoot::for_test(root.try_clone().map_err(AttemptCgroupError::Metadata)?),
                unit_name.clone(),
                unit_path.clone(),
                "/system.slice/test.service".to_owned(),
            )
        };
        assert!(matches!(
            make_bound(),
            Err(AttemptCgroupError::MalformedEvents)
        ));
        fs::write(&events, b"populated 0\n")?;
        let mut bound = make_bound()?;
        fs::write(&events, b"populated 2\n")?;
        assert!(matches!(
            bound.observe_empty(),
            Err(AttemptCgroupError::MalformedEvents)
        ));
        fs::write(&events, vec![b'x'; usize::try_from(MAX_EVENTS_BYTES)? + 1])?;
        assert!(matches!(
            bound.observe_empty(),
            Err(AttemptCgroupError::EventsTooLong)
        ));
        Ok(())
    }

    #[test]
    fn unreadable_initial_events_fail_closed() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let directory = temporary.path().join("system.slice/test.service");
        fs::create_dir_all(directory.join("cgroup.events"))?;
        let error = BoundAttemptCgroup::open(
            CgroupRoot::for_test(File::open(temporary.path())?),
            TransientServiceUnitName::from_attempt_id([6; 16])?,
            OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/test")?,
            "/system.slice/test.service".to_owned(),
        )
        .err();
        assert!(matches!(error, Some(AttemptCgroupError::EventsRead(_))));
        let error = BoundAttemptCgroup::open_with_metadata(
            CgroupRoot::for_test(File::open(temporary.path())?),
            TransientServiceUnitName::from_attempt_id([7; 16])?,
            OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/test")?,
            "/system.slice/test.service".to_owned(),
            |_| Err(std::io::Error::other("injected metadata failure")),
        )
        .err();
        assert!(matches!(error, Some(AttemptCgroupError::Metadata(_))));
        Ok(())
    }

    #[test]
    fn identity_metadata_failures_do_not_prove_emptiness() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let directory = temporary.path().join("system.slice/test.service");
        fs::create_dir_all(&directory)?;
        fs::write(directory.join("cgroup.events"), b"populated 0\n")?;
        let mut bound = BoundAttemptCgroup::open(
            CgroupRoot::for_test(File::open(temporary.path())?),
            TransientServiceUnitName::from_attempt_id([8; 16])?,
            OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/test")?,
            "/system.slice/test.service".to_owned(),
        )?;
        let retained_error = bound
            .observe_empty_with_metadata(|_| {
                Err(std::io::Error::other("injected retained metadata failure"))
            })
            .err();
        assert!(matches!(
            retained_error,
            Some(AttemptCgroupError::Metadata(_))
        ));
        let mut reads = 0;
        let reopened_error = bound
            .observe_empty_with_metadata(|file| {
                reads += 1;
                if reads == 2 {
                    Err(std::io::Error::other("injected reopened metadata failure"))
                } else {
                    file.metadata()
                }
            })
            .err();
        assert!(matches!(
            reopened_error,
            Some(AttemptCgroupError::Metadata(_))
        ));
        assert_eq!(reads, 2);
        Ok(())
    }
}
