use rustix::fs::{self, AtFlags, Dir, FileType, Mode, OFlags, RenameFlags, ResolveFlags, CWD};
#[cfg(target_os = "linux")]
use rustix::io::Errno;
#[cfg(target_os = "linux")]
use std::ffi::{CStr, CString};
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::Read as _;
#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "linux")]
use std::path::Component;
#[cfg(target_os = "linux")]
struct AtomicPublication {
    parent: OwnedFd,
    staging: OwnedFd,
    staging_name: CString,
    destination_name: CString,
    parent_identity: DirectoryIdentity,
    staging_identity: DirectoryIdentity,
    staging_present: bool,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

#[cfg(target_os = "linux")]
struct RelativeFilePath {
    directories: Vec<CString>,
    file_name: CString,
}

#[cfg(target_os = "linux")]
struct VerifiedPublication(AtomicPublication);

#[cfg(not(target_os = "linux"))]
struct AtomicPublication;

#[cfg(not(target_os = "linux"))]
impl AtomicPublication {
    const fn prepare(_destination: &Path) -> Result<Self, MaterializationError> {
        Err(MaterializationError::AtomicPublicationUnsupported)
    }
}

#[cfg(target_os = "linux")]
impl AtomicPublication {
    fn prepare(destination: &Path) -> Result<Self, MaterializationError> {
        output_parent_and_name(destination).and_then(|(parent_path, destination_name)| {
            let effective_uid = effective_uid();
            open_trusted_parent(parent_path, effective_uid).and_then(|(parent, parent_identity)| {
                create_private_staging(&parent, parent_identity, effective_uid).map(
                    |(staging_name, staging, staging_identity)| Self {
                        parent,
                        staging,
                        staging_name,
                        destination_name,
                        parent_identity,
                        staging_identity,
                        staging_present: true,
                    },
                )
            })
        })
    }

    fn write_file(&self, relative_path: &str, bytes: &[u8]) -> Result<(), MaterializationError> {
        relative_file_path(Path::new(relative_path)).and_then(|path| {
            self.write_parent(&path.directories).and_then(|directory| {
                let flags = OFlags::WRONLY
                    .union(OFlags::CREATE)
                    .union(OFlags::EXCL)
                    .union(OFlags::CLOEXEC)
                    .union(OFlags::NOFOLLOW);
                open_at2(
                    &directory,
                    &path.file_name,
                    flags,
                    Mode::from_raw_mode(0o600),
                    ResolveFlags::BENEATH.union(ResolveFlags::NO_SYMLINKS),
                )
                .and_then(|fd| {
                    let mut file: File = fd.into();
                    file.write_all(bytes)
                        .map_err(|_| MaterializationError::DurabilitySyncFailed)
                        .and_then(|()| sync_fd(&file))
                        .and_then(|()| sync_fd(&directory))
                })
            })
        })
    }

    fn write_parent(&self, directories: &[CString]) -> Result<OwnedFd, MaterializationError> {
        duplicate_fd(&self.staging).and_then(|directory| {
            directories.iter().try_fold(directory, |directory, name| {
                open_or_create_directory(&directory, name)
            })
        })
    }

    fn verify_and_sync(
        self,
        files: &[MaterializedFile],
    ) -> Result<VerifiedPublication, MaterializationError> {
        files
            .iter()
            .try_for_each(|file| {
                self.read_file(&file.relative_path).and_then(|bytes| {
                    if bytes != file.bytes {
                        return Err(MaterializationError::ArchiveDigestMismatch);
                    }
                    file.archive_release_filename
                        .as_deref()
                        .map_or(Ok(()), |release_filename| {
                            verify_public_archive(&bytes, release_filename)
                                .map_err(|_| MaterializationError::ArchiveDigestMismatch)
                        })
                })
            })
            .and_then(|()| sync_fd(&self.staging))
            .map(|()| VerifiedPublication(self))
    }

    fn read_file(&self, relative_path: &str) -> Result<Vec<u8>, MaterializationError> {
        relative_file_path(Path::new(relative_path)).and_then(|path| {
            self.read_parent(&path.directories).and_then(|directory| {
                open_at2(
                    &directory,
                    &path.file_name,
                    OFlags::RDONLY
                        .union(OFlags::CLOEXEC)
                        .union(OFlags::NOFOLLOW),
                    Mode::empty(),
                    ResolveFlags::BENEATH.union(ResolveFlags::NO_SYMLINKS),
                )
                .and_then(|fd| {
                    let mut file: File = fd.into();
                    let mut bytes = Vec::new();
                    file.read_to_end(&mut bytes)
                        .map_err(|_| MaterializationError::ArchiveDigestMismatch)
                        .map(|_| bytes)
                })
            })
        })
    }

    fn read_parent(&self, directories: &[CString]) -> Result<OwnedFd, MaterializationError> {
        duplicate_fd(&self.staging).and_then(|directory| {
            directories.iter().try_fold(directory, |directory, name| {
                open_directory(&directory, name)
            })
        })
    }
}

#[cfg(target_os = "linux")]
impl VerifiedPublication {
    fn publish(self) -> Result<(), MaterializationError> {
        let mut publication = self.0;
        publication.revalidate_for_publish().and_then(|()| {
            fs::renameat_with(
                &publication.parent,
                publication.staging_name.as_c_str(),
                &publication.parent,
                publication.destination_name.as_c_str(),
                RenameFlags::NOREPLACE,
            )
            .map_err(map_publish_error)
            .and_then(|()| {
                publication.staging_present = false;
                sync_fd(&publication.parent)
            })
        })
    }
}

#[cfg(target_os = "linux")]
impl Drop for AtomicPublication {
    fn drop(&mut self) {
        if self.staging_present {
            drop(remove_staging_tree(
                &self.parent,
                self.parent_identity,
                &self.staging_name,
                self.staging_identity,
                effective_uid(),
            ));
        }
    }
}

#[cfg(target_os = "linux")]
fn publish_materialized_tree(
    publication: AtomicPublication,
    files: &[MaterializedFile],
) -> Result<(), MaterializationError> {
    files
        .iter()
        .try_for_each(|file| publication.write_file(&file.relative_path, &file.bytes))
        .and_then(|()| publication.verify_and_sync(files))
        .and_then(VerifiedPublication::publish)
}

#[cfg(not(target_os = "linux"))]
fn publish_materialized_tree(
    _publication: AtomicPublication,
    _files: &[MaterializedFile],
) -> Result<(), MaterializationError> {
    Err(MaterializationError::AtomicPublicationUnsupported)
}

#[cfg(target_os = "linux")]
fn output_parent_and_name(destination: &Path) -> Result<(&Path, CString), MaterializationError> {
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = destination
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or(MaterializationError::UntrustedOutputDirectory)?;
    CString::new(file_name.as_bytes())
        .map_err(|_| MaterializationError::UntrustedOutputDirectory)
        .map(|name| (parent, name))
}

#[cfg(target_os = "linux")]
fn open_trusted_parent(
    parent: &Path,
    effective_uid: u32,
) -> Result<(OwnedFd, DirectoryIdentity), MaterializationError> {
    CString::new(parent.as_os_str().as_bytes())
        .map_err(|_| MaterializationError::UntrustedOutputDirectory)
        .and_then(|parent| {
            open_at2(
                CWD,
                &parent,
                OFlags::RDONLY
                    .union(OFlags::DIRECTORY)
                    .union(OFlags::CLOEXEC),
                Mode::empty(),
                ResolveFlags::NO_SYMLINKS,
            )
        })
        .and_then(|parent| {
            trusted_parent_identity(&parent, effective_uid).map(|identity| (parent, identity))
        })
}

#[cfg(target_os = "linux")]
fn create_private_staging(
    parent: &OwnedFd,
    parent_identity: DirectoryIdentity,
    effective_uid: u32,
) -> Result<(CString, OwnedFd, DirectoryIdentity), MaterializationError> {
    revalidate_parent(parent, parent_identity, effective_uid)?;
    for _ in 0..16 {
        let attempt = random_staging_name().and_then(|name| {
            match fs::mkdirat(parent, name.as_c_str(), Mode::from_raw_mode(0o700)) {
                Ok(()) => configure_private_staging(parent, &name, parent_identity, effective_uid)
                    .map(Some),
                Err(Errno::EXIST) => Ok(None),
                Err(error) => Err(map_open_error(error)),
            }
        });
        match attempt {
            Ok(Some(staging)) => return Ok(staging),
            Ok(None) => {}
            Err(error) => return Err(error),
        }
    }
    Err(MaterializationError::UntrustedOutputDirectory)
}

#[cfg(target_os = "linux")]
fn configure_private_staging(
    parent: &OwnedFd,
    staging_name: &CString,
    parent_identity: DirectoryIdentity,
    effective_uid: u32,
) -> Result<(CString, OwnedFd, DirectoryIdentity), MaterializationError> {
    let staging = match open_directory(parent, staging_name) {
        Ok(staging) => staging,
        Err(error) => {
            remove_empty_staging(parent, staging_name)?;
            return Err(error);
        }
    };
    let configured = fs::fchmod(&staging, Mode::from_raw_mode(0o700))
        .map_err(map_sync_error)
        .and_then(|()| sync_fd(&staging))
        .and_then(|()| {
            staging_identity(
                parent,
                staging_name,
                &staging,
                parent_identity,
                effective_uid,
            )
        });
    match configured {
        Ok(staging_identity) => Ok((staging_name.clone(), staging, staging_identity)),
        Err(error) => {
            drop(staging);
            remove_empty_staging(parent, staging_name)?;
            Err(error)
        }
    }
}

#[cfg(target_os = "linux")]
fn remove_empty_staging(parent: &OwnedFd, staging_name: &CStr) -> Result<(), MaterializationError> {
    fs::unlinkat(parent, staging_name, AtFlags::REMOVEDIR)
        .map_err(map_cleanup_error)
        .and_then(|()| sync_fd(parent))
}

#[cfg(target_os = "linux")]
fn random_staging_name() -> Result<CString, MaterializationError> {
    let mut random = [0_u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut random))
        .map_err(|_| MaterializationError::AtomicPublicationUnsupported)
        .and_then(|()| {
            let suffix = blake3::hash(&random).to_hex();
            CString::new(format!(".pigloros-conformance-staging-{suffix}"))
                .map_err(|_| MaterializationError::AtomicPublicationUnsupported)
        })
}

#[cfg(target_os = "linux")]
fn relative_file_path(path: &Path) -> Result<RelativeFilePath, MaterializationError> {
    path.components()
        .map(|component| match component {
            Component::Normal(name) => CString::new(name.as_bytes())
                .map_err(|_| MaterializationError::UntrustedOutputDirectory),
            _ => Err(MaterializationError::UntrustedOutputDirectory),
        })
        .collect::<Result<Vec<_>, _>>()
        .and_then(|mut components| {
            components
                .pop()
                .map(|file_name| RelativeFilePath {
                    directories: components,
                    file_name,
                })
                .ok_or(MaterializationError::UntrustedOutputDirectory)
        })
}

#[cfg(target_os = "linux")]
fn open_or_create_directory(
    parent: &OwnedFd,
    name: &CString,
) -> Result<OwnedFd, MaterializationError> {
    match fs::mkdirat(parent, name.as_c_str(), Mode::from_raw_mode(0o700)) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(error) => return Err(map_open_error(error)),
    }
    sync_fd(parent).and_then(|()| open_directory(parent, name))
}

#[cfg(target_os = "linux")]
fn open_directory(parent: &OwnedFd, name: &CStr) -> Result<OwnedFd, MaterializationError> {
    open_at2(
        parent,
        name,
        OFlags::RDONLY
            .union(OFlags::DIRECTORY)
            .union(OFlags::CLOEXEC),
        Mode::empty(),
        ResolveFlags::BENEATH.union(ResolveFlags::NO_SYMLINKS),
    )
}

#[cfg(target_os = "linux")]
fn duplicate_fd(fd: &OwnedFd) -> Result<OwnedFd, MaterializationError> {
    rustix::io::dup(fd).map_err(|_| MaterializationError::UntrustedOutputDirectory)
}

#[cfg(target_os = "linux")]
fn open_at2<Fd: std::os::fd::AsFd>(
    directory_fd: Fd,
    path: &CStr,
    flags: OFlags,
    mode: Mode,
    resolve: ResolveFlags,
) -> Result<OwnedFd, MaterializationError> {
    fs::openat2(directory_fd, path, flags, mode, resolve).map_err(map_open_error)
}

#[cfg(target_os = "linux")]
fn effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[cfg(target_os = "linux")]
fn trusted_parent_identity(
    parent: &OwnedFd,
    effective_uid: u32,
) -> Result<DirectoryIdentity, MaterializationError> {
    fs::fstat(parent)
        .map_err(map_open_error)
        .and_then(|metadata| validate_trusted_parent(metadata, effective_uid))
}

#[cfg(target_os = "linux")]
fn validate_trusted_parent(
    metadata: rustix::fs::Stat,
    effective_uid: u32,
) -> Result<DirectoryIdentity, MaterializationError> {
    let mode = Mode::from_raw_mode(metadata.st_mode);
    let writable_by_others = mode.intersects(Mode::WGRP.union(Mode::WOTH));
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != effective_uid
        || !mode.contains(Mode::WUSR.union(Mode::XUSR))
        || (writable_by_others && !mode.contains(Mode::SVTX))
    {
        return Err(MaterializationError::UntrustedOutputDirectory);
    }
    Ok(directory_identity(metadata))
}

#[cfg(target_os = "linux")]
const fn directory_identity(metadata: rustix::fs::Stat) -> DirectoryIdentity {
    DirectoryIdentity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
    }
}

#[cfg(target_os = "linux")]
fn revalidate_parent(
    parent: &OwnedFd,
    expected_identity: DirectoryIdentity,
    effective_uid: u32,
) -> Result<(), MaterializationError> {
    trusted_parent_identity(parent, effective_uid).and_then(|actual_identity| {
        if actual_identity == expected_identity {
            Ok(())
        } else {
            Err(MaterializationError::UntrustedOutputDirectory)
        }
    })
}

#[cfg(target_os = "linux")]
fn staging_identity(
    parent: &OwnedFd,
    staging_name: &CStr,
    staging: &OwnedFd,
    parent_identity: DirectoryIdentity,
    effective_uid: u32,
) -> Result<DirectoryIdentity, MaterializationError> {
    fs::statat(parent, staging_name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(map_open_error)
        .and_then(|named_metadata| {
            fs::fstat(staging)
                .map_err(map_open_error)
                .and_then(|retained_metadata| {
                    let named_identity =
                        validate_private_staging(named_metadata, parent_identity, effective_uid)?;
                    let retained_identity = validate_private_staging(
                        retained_metadata,
                        parent_identity,
                        effective_uid,
                    )?;
                    if named_identity == retained_identity {
                        Ok(named_identity)
                    } else {
                        Err(MaterializationError::UntrustedOutputDirectory)
                    }
                })
        })
}

#[cfg(target_os = "linux")]
fn validate_private_staging(
    metadata: rustix::fs::Stat,
    parent_identity: DirectoryIdentity,
    effective_uid: u32,
) -> Result<DirectoryIdentity, MaterializationError> {
    let mode = Mode::from_raw_mode(metadata.st_mode);
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != effective_uid
        || metadata.st_dev != parent_identity.device
        || mode != Mode::RWXU
    {
        return Err(MaterializationError::UntrustedOutputDirectory);
    }
    Ok(directory_identity(metadata))
}

#[cfg(target_os = "linux")]
impl AtomicPublication {
    fn revalidate_for_publish(&self) -> Result<(), MaterializationError> {
        revalidate_parent(&self.parent, self.parent_identity, effective_uid()).and_then(|()| {
            staging_identity(
                &self.parent,
                self.staging_name.as_c_str(),
                &self.staging,
                self.parent_identity,
                effective_uid(),
            )
            .and_then(|actual_identity| {
                if actual_identity == self.staging_identity {
                    Ok(())
                } else {
                    Err(MaterializationError::UntrustedOutputDirectory)
                }
            })
        })
    }
}

#[cfg(target_os = "linux")]
fn remove_staging_tree(
    parent: &OwnedFd,
    parent_identity: DirectoryIdentity,
    staging_name: &CStr,
    staging_identity_expected: DirectoryIdentity,
    effective_uid: u32,
) -> Result<(), MaterializationError> {
    revalidate_parent(parent, parent_identity, effective_uid).and_then(|()| {
        open_directory(parent, staging_name).and_then(|staging| {
            staging_identity(
                parent,
                staging_name,
                &staging,
                parent_identity,
                effective_uid,
            )
            .and_then(|actual_identity| {
                if actual_identity == staging_identity_expected {
                    remove_directory_contents(&staging)
                        .and_then(|()| {
                            fs::unlinkat(parent, staging_name, AtFlags::REMOVEDIR)
                                .map_err(map_cleanup_error)
                        })
                        .and_then(|()| sync_fd(parent))
                } else {
                    Err(MaterializationError::UntrustedOutputDirectory)
                }
            })
        })
    })
}

#[cfg(target_os = "linux")]
fn remove_directory_contents(directory: &OwnedFd) -> Result<(), MaterializationError> {
    Dir::read_from(directory)
        .map_err(map_cleanup_error)
        .and_then(|mut entries| {
            entries.try_for_each(|entry| {
                entry
                    .map_err(map_cleanup_error)
                    .and_then(|entry| remove_directory_entry(directory, entry.file_name()))
            })
        })
}

#[cfg(target_os = "linux")]
fn remove_directory_entry(directory: &OwnedFd, name: &CStr) -> Result<(), MaterializationError> {
    if name.to_bytes() == b"." || name.to_bytes() == b".." {
        return Ok(());
    }
    fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(map_cleanup_error)
        .and_then(|metadata| match FileType::from_raw_mode(metadata.st_mode) {
            FileType::Directory => open_directory(directory, name).and_then(|child| {
                remove_directory_contents(&child)
                    .and_then(|()| {
                        fs::unlinkat(directory, name, AtFlags::REMOVEDIR).map_err(map_cleanup_error)
                    })
                    .and_then(|()| sync_fd(directory))
            }),
            FileType::RegularFile => open_at2(
                directory,
                name,
                OFlags::RDONLY
                    .union(OFlags::CLOEXEC)
                    .union(OFlags::NOFOLLOW),
                Mode::empty(),
                ResolveFlags::BENEATH.union(ResolveFlags::NO_SYMLINKS),
            )
            .and_then(|file| {
                fs::fstat(&file)
                    .map_err(map_cleanup_error)
                    .and_then(|file_metadata| {
                        if FileType::from_raw_mode(file_metadata.st_mode) == FileType::RegularFile {
                            fs::unlinkat(directory, name, AtFlags::empty())
                                .map_err(map_cleanup_error)
                                .and_then(|()| sync_fd(directory))
                        } else {
                            Err(MaterializationError::UntrustedOutputDirectory)
                        }
                    })
            }),
            FileType::Symlink => Err(MaterializationError::SymlinkDetected),
            _ => Err(MaterializationError::UntrustedOutputDirectory),
        })
}

#[cfg(target_os = "linux")]
fn sync_fd<Fd: std::os::fd::AsFd>(fd: Fd) -> Result<(), MaterializationError> {
    fs::fsync(fd).map_err(map_sync_error)
}

#[cfg(target_os = "linux")]
const fn map_open_error(error: Errno) -> MaterializationError {
    match error {
        Errno::LOOP => MaterializationError::SymlinkDetected,
        Errno::NOSYS | Errno::INVAL | Errno::OPNOTSUPP | Errno::XDEV => {
            MaterializationError::AtomicPublicationUnsupported
        }
        _ => MaterializationError::UntrustedOutputDirectory,
    }
}

#[cfg(target_os = "linux")]
const fn map_publish_error(error: Errno) -> MaterializationError {
    match error {
        Errno::EXIST => MaterializationError::DestinationExists,
        Errno::NOSYS | Errno::INVAL | Errno::OPNOTSUPP | Errno::XDEV => {
            MaterializationError::AtomicPublicationUnsupported
        }
        _ => MaterializationError::UntrustedOutputDirectory,
    }
}

#[cfg(target_os = "linux")]
const fn map_sync_error(error: Errno) -> MaterializationError {
    match error {
        Errno::NOSYS | Errno::INVAL | Errno::OPNOTSUPP | Errno::XDEV => {
            MaterializationError::AtomicPublicationUnsupported
        }
        _ => MaterializationError::DurabilitySyncFailed,
    }
}

#[cfg(target_os = "linux")]
const fn map_cleanup_error(error: Errno) -> MaterializationError {
    match error {
        Errno::LOOP => MaterializationError::SymlinkDetected,
        Errno::NOSYS | Errno::INVAL | Errno::OPNOTSUPP | Errno::XDEV => {
            MaterializationError::AtomicPublicationUnsupported
        }
        _ => MaterializationError::UntrustedOutputDirectory,
    }
}

#[cfg(target_os = "linux")]
const _: () = {
    assert!(matches!(
        map_open_error(Errno::LOOP),
        MaterializationError::SymlinkDetected
    ));
    assert!(matches!(
        map_open_error(Errno::NOSYS),
        MaterializationError::AtomicPublicationUnsupported
    ));
    assert!(matches!(
        map_open_error(Errno::INVAL),
        MaterializationError::AtomicPublicationUnsupported
    ));
    assert!(matches!(
        map_publish_error(Errno::EXIST),
        MaterializationError::DestinationExists
    ));
    assert!(matches!(
        map_publish_error(Errno::NOSYS),
        MaterializationError::AtomicPublicationUnsupported
    ));
    assert!(matches!(
        map_publish_error(Errno::INVAL),
        MaterializationError::AtomicPublicationUnsupported
    ));
};
