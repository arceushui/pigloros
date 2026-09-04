use rustix::fs::{self, AtFlags, Dir, FileType, Mode, OFlags, RenameFlags, ResolveFlags, CWD};
#[cfg(target_os = "linux")]
use rustix::io::Errno;
#[cfg(target_os = "linux")]
use std::collections::{BTreeMap, BTreeSet};
#[cfg(target_os = "linux")]
use std::ffi::{CStr, CString, OsStr};
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::Read as _;
#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
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
#[derive(Clone, Copy, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(target_os = "linux")]
struct RelativeFilePath {
    components: Vec<OsString>,
}

#[cfg(target_os = "linux")]
impl RelativeFilePath {
    fn directories(&self) -> &[OsString] {
        &self.components[..self.components.len() - 1]
    }

    fn file_name(&self) -> &OsStr {
        &self.components[self.components.len() - 1]
    }
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct ExpectedDirectory<'a> {
    directories: BTreeMap<Vec<u8>, Self>,
    files: BTreeMap<Vec<u8>, &'a MaterializedFile>,
}

#[cfg(target_os = "linux")]
struct VerifiedPublication<'a> {
    publication: AtomicPublication,
    files: &'a [MaterializedFile],
}

#[cfg(target_os = "linux")]
impl AtomicPublication {
    fn prepare(
        destination: &Path,
        destination_name: CString,
    ) -> Result<Self, MaterializationError> {
        let parent_path = destination
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
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
    }

    fn write_file(&self, relative_path: &str, bytes: &[u8]) -> Result<(), MaterializationError> {
        let path = relative_file_path(Path::new(relative_path));
        self.write_parent(path.directories()).and_then(|directory| {
            let flags = OFlags::WRONLY
                .union(OFlags::CREATE)
                .union(OFlags::EXCL)
                .union(OFlags::CLOEXEC)
                .union(OFlags::NOFOLLOW);
            open_at2(
                &directory,
                path.file_name(),
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
    }

    fn write_parent(&self, directories: &[OsString]) -> Result<OwnedFd, MaterializationError> {
        duplicate_fd(&self.staging).and_then(|directory| {
            directories.iter().try_fold(directory, |directory, name| {
                open_or_create_directory(&directory, name)
            })
        })
    }

    fn verify_and_sync(&self, files: &[MaterializedFile]) -> Result<(), MaterializationError> {
        verify_directory_closure(&self.staging, &ExpectedDirectory::from_files(files))
            .and_then(|()| sync_fd(&self.staging))
    }

    fn abort(&mut self) -> Result<(), MaterializationError> {
        if !self.staging_present {
            return Ok(());
        }
        remove_staging_tree(
            &self.parent,
            self.parent_identity,
            &self.staging_name,
            self.staging_identity,
            effective_uid(),
        )?;
        self.staging_present = false;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl VerifiedPublication<'_> {
    fn publish(self) -> Result<(), MaterializationError> {
        let Self {
            mut publication,
            files,
        } = self;
        let result = publication
            .revalidate_for_publish()
            .and_then(|()| publication.verify_and_sync(files))
            .and_then(|()| publication.revalidate_for_publish())
            .and_then(|()| {
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
            });
        match result {
            Ok(()) => Ok(()),
            Err(error) => publication.abort().and(Err(error)),
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for AtomicPublication {
    fn drop(&mut self) {
        drop(self.abort());
    }
}

#[cfg(target_os = "linux")]
fn publish_materialized_tree(
    mut publication: AtomicPublication,
    files: &[MaterializedFile],
) -> Result<(), MaterializationError> {
    let result = files
        .iter()
        .try_for_each(|file| publication.write_file(&file.relative_path, &file.bytes));
    match result {
        Ok(()) => VerifiedPublication { publication, files }.publish(),
        Err(error) => publication.abort().and(Err(error)),
    }
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
    revalidate_parent(parent, effective_uid).and_then(|()| {
        random_staging_name().and_then(|name| {
            fs::mkdirat(parent, name.as_c_str(), Mode::from_raw_mode(0o700))
                .map_err(map_open_error)
                .and_then(|()| {
                    configure_private_staging(parent, &name, parent_identity, effective_uid)
                })
        })
    })
}

#[cfg(target_os = "linux")]
fn configure_private_staging(
    parent: &OwnedFd,
    staging_name: &CString,
    parent_identity: DirectoryIdentity,
    effective_uid: u32,
) -> Result<(CString, OwnedFd, DirectoryIdentity), MaterializationError> {
    configure_staging_descriptor(parent, staging_name, parent_identity, effective_uid)
        .map(|(staging, identity)| (staging_name.clone(), staging, identity))
        .inspect_err(|_| drop(unlink_empty_directory(parent, staging_name)))
}

#[cfg(target_os = "linux")]
fn configure_staging_descriptor(
    parent: &OwnedFd,
    staging_name: &CStr,
    parent_identity: DirectoryIdentity,
    effective_uid: u32,
) -> Result<(OwnedFd, DirectoryIdentity), MaterializationError> {
    open_directory(parent, staging_name).and_then(|staging| {
        fs::fchmod(&staging, Mode::from_raw_mode(0o700))
            .map_err(|_| MaterializationError::DurabilitySyncFailed)
            .and_then(|()| sync_fd(&staging))
            .and_then(|()| {
                staging_identity(
                    parent,
                    staging_name,
                    &staging,
                    parent_identity,
                    effective_uid,
                )
            })
            .map(|identity| (staging, identity))
    })
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
fn relative_file_path(path: &Path) -> RelativeFilePath {
    // MaterializedFile is private, and every constructor emits a non-empty
    // relative path from build-validated catalog identifiers or fixed names.
    RelativeFilePath {
        components: path.iter().map(OsStr::to_os_string).collect(),
    }
}

#[cfg(target_os = "linux")]
impl<'a> ExpectedDirectory<'a> {
    fn from_files(files: &'a [MaterializedFile]) -> Self {
        files.iter().fold(Self::default(), |mut expected, file| {
            expected.insert(&relative_file_path(Path::new(&file.relative_path)), file);
            expected
        })
    }

    fn insert(&mut self, path: &RelativeFilePath, file: &'a MaterializedFile) {
        self.insert_components(path.directories(), path.file_name(), file);
    }

    fn insert_components(
        &mut self,
        directories: &[OsString],
        file_name: &OsStr,
        file: &'a MaterializedFile,
    ) {
        let Some((directory, remaining)) = directories.split_first() else {
            self.files.insert(file_name.as_bytes().to_vec(), file);
            return;
        };
        self.directories
            .entry(directory.as_bytes().to_vec())
            .or_default()
            .insert_components(remaining, file_name, file);
    }
}

#[cfg(target_os = "linux")]
fn verify_directory_closure(
    directory: &OwnedFd,
    expected: &ExpectedDirectory<'_>,
) -> Result<(), MaterializationError> {
    Dir::read_from(directory)
        .map_err(map_open_error)
        .and_then(|mut entries| {
            let mut seen = BTreeSet::new();
            entries
                .try_for_each(|entry| {
                    entry.map_err(map_open_error).and_then(|entry| {
                        let name = entry.file_name();
                        if name.to_bytes() == b"." || name.to_bytes() == b".." {
                            return Ok(());
                        }
                        let name_bytes = name.to_bytes();
                        seen.insert(name_bytes.to_vec());
                        expected.directories.get(name_bytes).map_or_else(
                            || {
                                expected.files.get(name_bytes).map_or_else(
                                    || reject_unexpected_entry(directory, name),
                                    |file| verify_expected_file(directory, name, file),
                                )
                            },
                            |child| verify_expected_directory(directory, name, child),
                        )
                    })
                })
                .and_then(|()| verify_all_expected_entries_seen(expected, &seen))
        })
}

#[cfg(target_os = "linux")]
fn verify_all_expected_entries_seen(
    expected: &ExpectedDirectory<'_>,
    seen: &BTreeSet<Vec<u8>>,
) -> Result<(), MaterializationError> {
    let expected_count = expected.directories.len() + expected.files.len();
    let all_directories_seen = expected
        .directories
        .keys()
        .all(|name| seen.contains(name.as_slice()));
    let all_files_seen = expected
        .files
        .keys()
        .all(|name| seen.contains(name.as_slice()));
    if seen.len() == expected_count && all_directories_seen && all_files_seen {
        Ok(())
    } else {
        Err(MaterializationError::UntrustedOutputDirectory)
    }
}

#[cfg(target_os = "linux")]
fn reject_unexpected_entry(directory: &OwnedFd, name: &CStr) -> Result<(), MaterializationError> {
    fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(map_open_error)
        .and_then(|metadata| {
            if FileType::from_raw_mode(metadata.st_mode) == FileType::Symlink {
                Err(MaterializationError::SymlinkDetected)
            } else {
                Err(MaterializationError::UntrustedOutputDirectory)
            }
        })
}

#[cfg(target_os = "linux")]
fn verify_expected_directory(
    parent: &OwnedFd,
    name: &CStr,
    expected: &ExpectedDirectory<'_>,
) -> Result<(), MaterializationError> {
    named_directory_identity(parent, name).and_then(|named_identity| {
        open_directory(parent, name).and_then(|directory| {
            descriptor_directory_identity(&directory)
                .and_then(|opened_identity| {
                    require_unchanged_identity(&opened_identity, &named_identity)
                        .and_then(|()| verify_directory_closure(&directory, expected))
                })
                .and_then(|()| named_directory_identity(parent, name))
                .and_then(|current_named_identity| {
                    descriptor_directory_identity(&directory).and_then(|current_opened_identity| {
                        require_unchanged_identity(&current_named_identity, &named_identity)
                            .and_then(|()| {
                                require_unchanged_identity(
                                    &current_opened_identity,
                                    &named_identity,
                                )
                            })
                    })
                })
        })
    })
}

#[cfg(target_os = "linux")]
fn require_unchanged_identity<Identity: Eq>(
    actual: &Identity,
    expected: &Identity,
) -> Result<(), MaterializationError> {
    if actual == expected {
        Ok(())
    } else {
        Err(MaterializationError::UntrustedOutputDirectory)
    }
}

#[cfg(target_os = "linux")]
fn named_directory_identity(
    parent: &OwnedFd,
    name: &CStr,
) -> Result<DirectoryIdentity, MaterializationError> {
    fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(map_open_error)
        .and_then(directory_entry_identity)
}

#[cfg(target_os = "linux")]
fn descriptor_directory_identity(
    directory: &OwnedFd,
) -> Result<DirectoryIdentity, MaterializationError> {
    fs::fstat(directory)
        .map_err(map_open_error)
        .and_then(directory_entry_identity)
}

#[cfg(target_os = "linux")]
fn directory_entry_identity(
    metadata: rustix::fs::Stat,
) -> Result<DirectoryIdentity, MaterializationError> {
    let file_type = FileType::from_raw_mode(metadata.st_mode);
    if file_type == FileType::Directory {
        return Ok(directory_identity(metadata));
    }
    Err(non_directory_error(file_type))
}

#[cfg(target_os = "linux")]
#[inline(never)]
fn non_directory_error(file_type: FileType) -> MaterializationError {
    if file_type == FileType::Symlink {
        MaterializationError::SymlinkDetected
    } else {
        MaterializationError::UntrustedOutputDirectory
    }
}

#[cfg(target_os = "linux")]
fn verify_expected_file(
    parent: &OwnedFd,
    name: &CStr,
    expected: &MaterializedFile,
) -> Result<(), MaterializationError> {
    i64::try_from(expected.bytes.len())
        .map_err(|_| MaterializationError::ArchiveDigestMismatch)
        .and_then(|expected_size| {
            open_at2(
                parent,
                name,
                OFlags::RDONLY
                    .union(OFlags::CLOEXEC)
                    .union(OFlags::NOFOLLOW)
                    .union(OFlags::NONBLOCK),
                Mode::empty(),
                ResolveFlags::BENEATH.union(ResolveFlags::NO_SYMLINKS),
            )
            .and_then(|fd| {
                let mut file: File = fd.into();
                verified_file_identity(parent, name, &file, expected_size).and_then(|identity| {
                    let mut bytes = vec![0; expected.bytes.len()];
                    file.read_exact(&mut bytes)
                        .map_err(|_| MaterializationError::ArchiveDigestMismatch)
                        .and_then(|()| verified_file_identity(parent, name, &file, expected_size))
                        .and_then(|current_identity| {
                            require_unchanged_identity(&current_identity, &identity)
                                .and_then(|()| verify_materialized_bytes(expected, &bytes))
                        })
                })
            })
        })
}

#[cfg(target_os = "linux")]
fn verified_file_identity<Fd: std::os::fd::AsFd>(
    parent: &OwnedFd,
    name: &CStr,
    file: Fd,
    expected_size: i64,
) -> Result<FileIdentity, MaterializationError> {
    fs::fstat(file)
        .map_err(map_open_error)
        .and_then(|metadata| regular_file_identity(metadata, expected_size))
        .and_then(|descriptor_identity| {
            fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(map_open_error)
                .and_then(|metadata| regular_file_identity(metadata, expected_size))
                .and_then(|named_identity| {
                    require_unchanged_identity(&descriptor_identity, &named_identity)
                        .map(|()| descriptor_identity)
                })
        })
}

#[cfg(target_os = "linux")]
fn regular_file_identity(
    metadata: rustix::fs::Stat,
    expected_size: i64,
) -> Result<FileIdentity, MaterializationError> {
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile {
        return Err(MaterializationError::UntrustedOutputDirectory);
    }
    if metadata.st_size != expected_size {
        return Err(MaterializationError::ArchiveDigestMismatch);
    }
    Ok(FileIdentity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
    })
}

#[cfg(target_os = "linux")]
fn verify_materialized_bytes(
    expected: &MaterializedFile,
    bytes: &[u8],
) -> Result<(), MaterializationError> {
    if bytes != expected.bytes {
        return Err(MaterializationError::ArchiveDigestMismatch);
    }
    expected
        .archive_release_filename
        .as_deref()
        .map_or(Ok(()), |release_filename| {
            verify_public_archive(bytes, release_filename)
                .map_err(|_| MaterializationError::ArchiveDigestMismatch)
        })
}

#[cfg(target_os = "linux")]
fn open_or_create_directory(
    parent: &OwnedFd,
    name: &OsStr,
) -> Result<OwnedFd, MaterializationError> {
    match fs::mkdirat(parent, name, Mode::from_raw_mode(0o700)) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(error) => return Err(map_open_error(error)),
    }
    sync_fd(parent).and_then(|()| open_directory(parent, name))
}

#[cfg(target_os = "linux")]
fn open_directory<PathArg: rustix::path::Arg>(
    parent: &OwnedFd,
    name: PathArg,
) -> Result<OwnedFd, MaterializationError> {
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
fn open_at2<Fd: std::os::fd::AsFd, PathArg: rustix::path::Arg>(
    directory_fd: Fd,
    path: PathArg,
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
fn revalidate_parent(parent: &OwnedFd, effective_uid: u32) -> Result<(), MaterializationError> {
    trusted_parent_identity(parent, effective_uid).map(|_| ())
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
        revalidate_parent(&self.parent, effective_uid()).and_then(|()| {
            staging_identity(
                &self.parent,
                self.staging_name.as_c_str(),
                &self.staging,
                self.parent_identity,
                effective_uid(),
            )
            .map(|_| ())
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
    revalidate_parent(parent, effective_uid).and_then(|()| {
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
                        .and_then(|()| unlink_empty_directory(parent, staging_name))
                } else {
                    Err(MaterializationError::UntrustedOutputDirectory)
                }
            })
        })
    })
}

#[cfg(target_os = "linux")]
fn unlink_empty_directory(parent: &OwnedFd, name: &CStr) -> Result<(), MaterializationError> {
    fs::unlinkat(parent, name, AtFlags::REMOVEDIR)
        .map_err(map_open_error)
        .and_then(|()| sync_fd(parent))
}

#[cfg(target_os = "linux")]
fn remove_directory_contents(directory: &OwnedFd) -> Result<(), MaterializationError> {
    Dir::read_from(directory)
        .map_err(map_open_error)
        .and_then(|mut entries| {
            entries.try_for_each(|entry| {
                entry
                    .map_err(map_open_error)
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
        .map_err(map_open_error)
        .and_then(|metadata| match FileType::from_raw_mode(metadata.st_mode) {
            FileType::Directory => open_directory(directory, name).and_then(|child| {
                remove_directory_contents(&child)
                    .and_then(|()| {
                        fs::unlinkat(directory, name, AtFlags::REMOVEDIR).map_err(map_open_error)
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
                    .map_err(map_open_error)
                    .and_then(|file_metadata| {
                        if FileType::from_raw_mode(file_metadata.st_mode) == FileType::RegularFile {
                            fs::unlinkat(directory, name, AtFlags::empty())
                                .map_err(map_open_error)
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
    fs::fsync(fd).map_err(|_| MaterializationError::DurabilitySyncFailed)
}

#[cfg(target_os = "linux")]
const fn map_open_error(error: Errno) -> MaterializationError {
    map_atomic_error(AtomicOperation::Open, error)
}

#[cfg(target_os = "linux")]
const fn map_publish_error(error: Errno) -> MaterializationError {
    map_atomic_error(AtomicOperation::Publish, error)
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum AtomicOperation {
    Open,
    Publish,
}

#[cfg(target_os = "linux")]
const fn map_atomic_error(operation: AtomicOperation, error: Errno) -> MaterializationError {
    match (operation, error) {
        (AtomicOperation::Publish, Errno::EXIST) => MaterializationError::DestinationExists,
        (AtomicOperation::Open, Errno::LOOP) => MaterializationError::SymlinkDetected,
        (_, Errno::NOSYS | Errno::INVAL | Errno::OPNOTSUPP | Errno::XDEV) => {
            MaterializationError::AtomicPublicationUnsupported
        }
        (AtomicOperation::Open | AtomicOperation::Publish, _) => {
            MaterializationError::UntrustedOutputDirectory
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::fs::{self as standard_fs, File};
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn directory_identity_rejects_non_directories() -> Result<(), MaterializationError> {
        let directory =
            fs::statat(CWD, Path::new("."), AtFlags::empty()).map_err(map_open_error)?;
        assert!(directory_entry_identity(directory).is_ok());

        let regular_file =
            fs::statat(CWD, Path::new("/dev/null"), AtFlags::empty()).map_err(map_open_error)?;
        assert!(matches!(
            directory_entry_identity(regular_file),
            Err(MaterializationError::UntrustedOutputDirectory)
        ));
        assert!(matches!(
            non_directory_error(FileType::Symlink),
            MaterializationError::SymlinkDetected
        ));
        assert!(matches!(
            non_directory_error(FileType::RegularFile),
            MaterializationError::UntrustedOutputDirectory
        ));
        Ok(())
    }

    #[test]
    fn directory_entry_identity_classifies_filesystem_entries() -> Result<(), Box<dyn Error>> {
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!(
            "pigloros-directory-identity-{}-{suffix}",
            std::process::id()
        ));
        standard_fs::create_dir(&root)?;
        let directory = root.join("directory");
        let regular_file = root.join("regular-file");
        let symbolic_link = root.join("symbolic-link");
        standard_fs::create_dir(&directory)?;
        File::create(&regular_file)?;
        symlink(&directory, &symbolic_link)?;

        let classify = |path: &Path, flags| {
            fs::statat(CWD, path, flags)
                .map_err(map_open_error)
                .and_then(directory_entry_identity)
        };
        assert!(classify(&directory, AtFlags::empty()).is_ok());
        assert_eq!(
            classify(&regular_file, AtFlags::empty()),
            Err(MaterializationError::UntrustedOutputDirectory)
        );
        assert_eq!(
            classify(&symbolic_link, AtFlags::SYMLINK_NOFOLLOW),
            Err(MaterializationError::SymlinkDetected)
        );
        standard_fs::remove_dir_all(root)?;
        Ok(())
    }
}
