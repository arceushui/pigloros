//! The production attachment kernel: descriptor-bound operations and readback.
//!
//! Every observation is gathered as an `Option`: an unreadable or malformed
//! kernel fact is recorded as absent, and [`super::verify`] rejects any absent
//! or different fact. Nothing here decides acceptance.

use std::{
    fs::{self, File},
    os::fd::{AsFd, AsRawFd, BorrowedFd},
    path::{Path, PathBuf},
};

use rustix::{
    fs::{
        fstat, fstatfs, fstatvfs, open, openat2, statx, AtFlags, Mode, OFlags, ResolveFlags,
        StatVfsMountFlags, StatxFlags,
    },
    mount::{
        mount_change, move_mount, unmount, MountPropagationFlags, MoveMountFlags, UnmountFlags,
    },
};

use super::{cmdline, AttachmentKernel};
use crate::ImageActivationError;

/// One mount-visible inode: its mount ID, device and inode number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Node {
    pub(super) mount_id: u64,
    pub(super) device: (u32, u32),
    pub(super) inode: u64,
}

/// The single `/proc/self/mountinfo` entry of the attached mount.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct MountEntry {
    pub(super) mount_id: u64,
    pub(super) parent_id: u64,
    pub(super) device: (u32, u32),
    pub(super) root: String,
    pub(super) mount_point: String,
    pub(super) options: String,
    pub(super) optional: Vec<String>,
    pub(super) filesystem: String,
    pub(super) super_options: String,
}

/// The loop device backing one device-mapper slave partition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct LoopDevice {
    pub(super) backing: Option<(u64, u64)>,
    pub(super) offset: Option<u64>,
    pub(super) size_limit: Option<u64>,
    pub(super) autoclear: Option<u64>,
    pub(super) read_only: Option<u64>,
    /// Every `loop<N>p<K>` partition of the device, as 512-byte-sector
    /// `(start, size)` extents.
    pub(super) partitions: Option<Vec<Option<(u64, u64)>>>,
}

/// One device-mapper slave: a loop partition and its 512-byte-sector extent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Slave {
    pub(super) loop_name: Option<String>,
    pub(super) start: Option<u64>,
    pub(super) size: Option<u64>,
    pub(super) loop_device: Option<LoopDevice>,
}

/// The device-mapper device under the mount.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Mapper {
    pub(super) uuid: Option<String>,
    pub(super) read_only: Option<u64>,
    pub(super) slaves: Option<Vec<Slave>>,
}

/// Everything read back from the kernel about one attached mount.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Observations {
    /// The attached mount's root, read through the sealed mount descriptor.
    pub(super) mount: Option<Node>,
    /// `<attempt>/root` resolved again through the held attempt directory.
    pub(super) path: Option<Node>,
    /// The mount holding the held, now covered, root directory.
    pub(super) parent_mount_id: Option<u64>,
    pub(super) filesystem_magic: Option<u64>,
    pub(super) read_only: Option<bool>,
    pub(super) entry: Option<MountEntry>,
    pub(super) mapper: Option<Mapper>,
}

/// The host kernel, read through fixed procfs and sysfs roots.
#[derive(Debug)]
pub(super) struct HostKernel {
    proc: PathBuf,
    sys: PathBuf,
}

impl HostKernel {
    /// The only production host: `/proc` and `/sys`.
    pub(super) fn system() -> Self {
        Self::at(Path::new("/proc"), Path::new("/sys"))
    }

    /// A host whose procfs and sysfs files are read below other roots.
    pub(super) fn at(proc: &Path, sys: &Path) -> Self {
        Self {
            proc: proc.to_path_buf(),
            sys: sys.to_path_buf(),
        }
    }

    pub(super) fn descriptor_path(&self, descriptor: BorrowedFd<'_>) -> PathBuf {
        self.proc
            .join("self/fd")
            .join(descriptor.as_raw_fd().to_string())
    }

    fn mapper(&self, device: (u32, u32)) -> Mapper {
        let block = self
            .sys
            .join("dev/block")
            .join(format!("{}:{}", device.0, device.1));
        Mapper {
            uuid: read_text(&block.join("dm/uuid")),
            read_only: read_number(&block.join("ro")),
            slaves: fs::read_dir(block.join("slaves")).ok().map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .map(|entry| self.slave(&entry.file_name().to_string_lossy()))
                    .collect()
            }),
        }
    }

    fn slave(&self, name: &str) -> Slave {
        let partition = self.sys.join("class/block").join(name);
        let loop_name = loop_of(name);
        let loop_device = loop_name.as_deref().map(|name| self.loop_device(name));
        Slave {
            loop_name,
            start: read_number(&partition.join("start")),
            size: read_number(&partition.join("size")),
            loop_device,
        }
    }

    fn loop_device(&self, name: &str) -> LoopDevice {
        let device = self.sys.join("class/block").join(name);
        LoopDevice {
            backing: read_text(&device.join("loop/backing_file")).and_then(|path| {
                open(
                    path.as_str(),
                    OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .ok()
                .and_then(|file| fstat(file).ok())
                .map(|stat| (stat.st_dev, stat.st_ino))
            }),
            offset: read_number(&device.join("loop/offset")),
            size_limit: read_number(&device.join("loop/sizelimit")),
            autoclear: read_number(&device.join("loop/autoclear")),
            read_only: read_number(&device.join("ro")),
            partitions: fs::read_dir(&device).ok().map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .filter(|entry| loop_of(entry).as_deref() == Some(name))
                    .map(|partition| {
                        let partition = device.join(partition);
                        read_number(&partition.join("start"))
                            .zip(read_number(&partition.join("size")))
                    })
                    .collect()
            }),
        }
    }
}

impl AttachmentKernel for HostKernel {
    fn vetoes_userspace_verity(&self) -> bool {
        fs::read(self.proc.join("cmdline"))
            .is_ok_and(|cmdline| cmdline::vetoes_userspace_verity(&cmdline))
    }

    fn attach(&self, mount: BorrowedFd<'_>, root: &File) -> Result<(), ImageActivationError> {
        move_mount(
            mount,
            "",
            root,
            "",
            MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH | MoveMountFlags::MOVE_MOUNT_T_EMPTY_PATH,
        )
        .map_err(|_| ImageActivationError::AttachFailure)
    }

    fn make_private(&self, mount: BorrowedFd<'_>) -> Result<(), ImageActivationError> {
        mount_change(self.descriptor_path(mount), MountPropagationFlags::PRIVATE)
            .map_err(|_| ImageActivationError::AttachFailure)
    }

    fn observe(&self, mount: BorrowedFd<'_>, attempt: &File, root: &File) -> Observations {
        let attached = node(mount);
        Observations {
            mount: attached,
            path: openat2(
                attempt,
                "root",
                OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
            )
            .ok()
            .and_then(|path| node(path.as_fd())),
            parent_mount_id: node(root.as_fd()).map(|parent| parent.mount_id),
            filesystem_magic: fstatfs(mount)
                .ok()
                .and_then(|filesystem| u64::try_from(filesystem.f_type).ok()),
            read_only: fstatvfs(mount)
                .ok()
                .map(|filesystem| filesystem.f_flag.contains(StatVfsMountFlags::RDONLY)),
            entry: attached.and_then(|node| {
                read_text(&self.proc.join("self/mountinfo"))
                    .and_then(|mountinfo| mount_entry(&mountinfo, node.mount_id))
            }),
            mapper: attached.map(|node| self.mapper(node.device)),
        }
    }

    fn detach(&self, mount: BorrowedFd<'_>) -> Result<(), ImageActivationError> {
        unmount(self.descriptor_path(mount), UnmountFlags::DETACH)
            .map_err(|_| ImageActivationError::TeardownFailure)
    }
}

fn node(descriptor: BorrowedFd<'_>) -> Option<Node> {
    statx(
        descriptor,
        "",
        AtFlags::EMPTY_PATH,
        StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
    )
    .ok()
    .filter(|stat| has_mount_id(stat.stx_mask))
    .map(|stat| Node {
        mount_id: stat.stx_mnt_id,
        device: (stat.stx_dev_major, stat.stx_dev_minor),
        inode: stat.stx_ino,
    })
}

/// Whether a `statx` result mask reports a valid mount ID.
pub(super) const fn has_mount_id(mask: u32) -> bool {
    mask & StatxFlags::MNT_ID.bits() != 0
}

/// One sysfs or procfs text value without its trailing newline.
fn read_text(path: &Path) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|text| text.trim_end_matches('\n').to_owned())
}

fn read_number(path: &Path) -> Option<u64> {
    read_text(path).and_then(|text| text.parse().ok())
}

/// The loop device of a loop partition name, `loop<N>p<K>`.
pub(super) fn loop_of(partition: &str) -> Option<String> {
    partition
        .strip_prefix("loop")
        .and_then(|rest| rest.split_once('p'))
        .filter(|(device, number)| all_digits(device) && all_digits(number))
        .map(|(device, _)| format!("loop{device}"))
}

fn all_digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

/// The one mountinfo entry with `mount_id`; none or several reject.
pub(super) fn mount_entry(mountinfo: &str, mount_id: u64) -> Option<MountEntry> {
    let mut entries = mountinfo
        .lines()
        .filter_map(parse_entry)
        .filter(|entry| entry.mount_id == mount_id);
    match (entries.next(), entries.next()) {
        (Some(entry), None) => Some(entry),
        _ => None,
    }
}

fn parse_entry(line: &str) -> Option<MountEntry> {
    let (left, right) = line.split_once(" - ")?;
    let left: Vec<&str> = left.split(' ').collect();
    let right: Vec<&str> = right.split(' ').collect();
    match (left.as_slice(), right.as_slice()) {
        (
            [mount_id, parent_id, device, root, mount_point, options, optional @ ..],
            [filesystem, _source, super_options],
        ) => Some(MountEntry {
            mount_id: mount_id.parse().ok()?,
            parent_id: parent_id.parse().ok()?,
            device: device_numbers(device)?,
            root: (*root).to_owned(),
            mount_point: (*mount_point).to_owned(),
            options: (*options).to_owned(),
            optional: optional.iter().map(|field| (*field).to_owned()).collect(),
            filesystem: (*filesystem).to_owned(),
            super_options: (*super_options).to_owned(),
        }),
        _ => None,
    }
}

fn device_numbers(text: &str) -> Option<(u32, u32)> {
    text.split_once(':')
        .and_then(|(major, minor)| Some((major.parse().ok()?, minor.parse().ok()?)))
}
