#![cfg(any(test, feature = "test-support"))]
//! ADR-137 P4 `subject-keys.v1` byte storage; no codec parsing or authority.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read as _};

use rustix::fd::OwnedFd;
use rustix::fs::{self, AtFlags, Dir, FileType, Mode, OFlags, Stat};

use super::commit::{CommitStage, StagedFile};
use super::{
    enforce, open_or_create_directory_component, same_file, validate_directory,
    SubjectEncryptorLock,
};
use crate::{BridgeError, UnavailableCode};

const DIRECTORY_NAME: &str = "subject-keys.v1";
const OWNER_PREFIX: &str = "subject:";
const OWNER_HEX_LENGTH: usize = 32;
const TEMPORARY_SUFFIX: &str = ".tmp";
const READ_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOCTTY);

/// The ADR-137 D2 step 4 bound on `subject-keys.v1` directory entries.
pub const MAX_SUBJECT_KEY_ARTIFACT_ENTRIES: usize = 4_096;

/// The byte bound on a stored artifact; inventory reads return one more byte.
pub const MAX_SUBJECT_KEY_ARTIFACT_BYTES: usize = 4_096;

/// The artifact kind fixed by an ADR-137 P4 reserved name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubjectKeyArtifactKind {
    /// `wrap.<owner_hex32>.<epoch_dec>.skw1`, holding `SubjectKeyWrapV1` bytes.
    Wrap,
    /// `binding.<owner_hex32>.<epoch_dec>.scb1`, holding
    /// `SubjectCredentialBindingV1` bytes.
    Binding,
}

impl SubjectKeyArtifactKind {
    const fn prefix(self) -> &'static str {
        match self {
            Self::Wrap => "wrap",
            Self::Binding => "binding",
        }
    }

    const fn extension(self) -> &'static str {
        match self {
            Self::Wrap => "skw1",
            Self::Binding => "scb1",
        }
    }
}

/// Whether a reserved name is the canonical name or its `.tmp` staging name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubjectKeyArtifactSlot {
    /// The committed name.
    Canonical,
    /// The canonical name with the suffix `.tmp`.
    Temporary,
}

/// One `(kind, owner, epoch)` reserved by ADR-137 P4.
///
/// Values exist only for an owner of `subject:` plus 32 lowercase hex digits
/// and an epoch of at least one. The rendered epoch is canonical decimal, so
/// parsing accepts exactly the names this type renders. A name is not proof
/// that a file holds that identity: the D2 inventory still parses every file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectKeyArtifactName {
    kind: SubjectKeyArtifactKind,
    owner_hex: String,
    epoch: u64,
}

impl SubjectKeyArtifactName {
    /// Build the reserved name for an owner id and a positive epoch.
    ///
    /// Returns `None` unless `owner_id` is `subject:` followed by exactly 32
    /// lowercase hex digits and `epoch` is not zero.
    #[must_use]
    pub fn new(kind: SubjectKeyArtifactKind, owner_id: &str, epoch: u64) -> Option<Self> {
        owner_id
            .strip_prefix(OWNER_PREFIX)
            .and_then(|owner_hex| Self::checked(kind, owner_hex, epoch))
    }

    /// Classify a directory entry name as a P4 reserved name.
    ///
    /// Returns `None` for every other name, including non-UTF-8 names and
    /// non-canonical spellings such as a leading zero in the epoch.
    #[must_use]
    pub fn parse(name: &[u8]) -> Option<(Self, SubjectKeyArtifactSlot)> {
        std::str::from_utf8(name).ok().and_then(|name| {
            let (base, slot) = name
                .strip_suffix(TEMPORARY_SUFFIX)
                .map_or((name, SubjectKeyArtifactSlot::Canonical), |base| {
                    (base, SubjectKeyArtifactSlot::Temporary)
                });
            [
                SubjectKeyArtifactKind::Wrap,
                SubjectKeyArtifactKind::Binding,
            ]
            .into_iter()
            .find_map(|kind| Self::parse_canonical(kind, base))
            .map(|parsed| (parsed, slot))
        })
    }

    fn parse_canonical(kind: SubjectKeyArtifactKind, base: &str) -> Option<Self> {
        base.strip_prefix(kind.prefix())
            .and_then(|rest| rest.strip_prefix('.'))
            .and_then(|rest| rest.strip_suffix(kind.extension()))
            .and_then(|rest| rest.strip_suffix('.'))
            .and_then(|middle| middle.split_once('.'))
            .and_then(|(owner_hex, epoch)| {
                epoch
                    .parse()
                    .ok()
                    .and_then(|epoch| Self::checked(kind, owner_hex, epoch))
            })
            .filter(|parsed| parsed.canonical() == base)
    }

    fn checked(kind: SubjectKeyArtifactKind, owner_hex: &str, epoch: u64) -> Option<Self> {
        (owner_hex.len() == OWNER_HEX_LENGTH
            && owner_hex
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            && epoch != 0)
            .then(|| Self {
                kind,
                owner_hex: owner_hex.to_owned(),
                epoch,
            })
    }

    /// The artifact kind.
    #[must_use]
    pub const fn kind(&self) -> SubjectKeyArtifactKind {
        self.kind
    }

    /// The owner id, `subject:` followed by the 32 lowercase hex digits.
    #[must_use]
    pub fn owner_id(&self) -> String {
        format!("{OWNER_PREFIX}{}", self.owner_hex)
    }

    /// The key epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The canonical name, for example `wrap.<owner_hex32>.<epoch_dec>.skw1`.
    #[must_use]
    pub fn canonical(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.kind.prefix(),
            self.owner_hex,
            self.epoch,
            self.kind.extension()
        )
    }

    /// The staging name: the canonical name with the suffix `.tmp`.
    #[must_use]
    pub fn temporary(&self) -> String {
        self.canonical() + TEMPORARY_SUFFIX
    }
}

/// What the inventory observed for one directory entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubjectKeyArtifactContent {
    /// A regular file, opened without following symlinks.
    Regular {
        /// The opened file's `[st_dev, st_ino]`.
        identity: [u64; 2],
        /// The first bytes, at most [`MAX_SUBJECT_KEY_ARTIFACT_BYTES`] + 1,
        /// so the caller can detect an oversized file.
        bytes: Vec<u8>,
    },
    /// Any entry that is not a regular file, such as a symlink, a directory
    /// or a FIFO. It is neither followed nor opened.
    NonRegular,
}

/// One entry of the `subject-keys.v1` inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectKeyArtifactEntry {
    /// The raw entry name, which need not be UTF-8 or reserved.
    pub name: Vec<u8>,
    /// What was observed for the entry.
    pub content: SubjectKeyArtifactContent,
}

impl SubjectEncryptorLock {
    /// Durably stage a new wrap or binding under its canonical P4 name.
    ///
    /// Admits `subject-keys.v1` in the held test directory: it is opened with
    /// `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`, created with mode 0700 when
    /// missing, and must be a directory owned by the effective UID with mode
    /// exactly 0700. The parent is synchronized so the directory entry is
    /// durable. The `.tmp` name is then created exclusively with mode 0600,
    /// written, synchronized and renamed to the canonical name without
    /// replacing any existing entry, and the directory is synchronized.
    ///
    /// The bytes are not parsed. The caller must have committed the ADR-137
    /// P3a staging record first. On failure before the rename, this owner's
    /// `.tmp` file is removed; an error after the rename leaves the canonical
    /// file with an unconfirmed outcome. Either state is what P5 recovers.
    ///
    /// # Errors
    /// Returns `Unavailable(InterfaceUnavailable)` for input above 4,096 bytes,
    /// an unsafe directory, an existing canonical or `.tmp` entry, or any I/O
    /// failure. No path or OS error escapes.
    pub fn stage_subject_key_artifact(
        &self,
        name: &SubjectKeyArtifactName,
        bytes: &[u8],
    ) -> Result<(), BridgeError> {
        self.stage_observing(name, bytes, |_| Ok(()))
    }

    fn stage_observing(
        &self,
        name: &SubjectKeyArtifactName,
        bytes: &[u8],
        after: impl FnMut(CommitStage) -> io::Result<()>,
    ) -> Result<(), BridgeError> {
        self.commit_artifact(name, bytes, false, after)
    }

    /// Durably replace an existing binding, as ADR-110 §9 allows for an
    /// active or retained identity.
    ///
    /// Admits `subject-keys.v1` as staging does. The existing canonical file
    /// must be a singly linked regular file owned by the effective UID with
    /// mode 0600 and not locked by another holder. The `.tmp` name is created
    /// exclusively, written and synchronized; both names are rechecked, then
    /// the rename and the directory sync complete the replacement. A missing
    /// binding is never created and a wrap is never replaced.
    ///
    /// # Errors
    /// Returns `Unavailable(InterfaceUnavailable)` for a wrap name, input above
    /// 4,096 bytes, a missing or unsafe binding, an existing `.tmp` entry,
    /// contention or any I/O failure. An error after the rename leaves an
    /// unconfirmed outcome.
    pub fn replace_subject_key_artifact(
        &self,
        name: &SubjectKeyArtifactName,
        bytes: &[u8],
    ) -> Result<(), BridgeError> {
        enforce(name.kind == SubjectKeyArtifactKind::Binding)
            .map_err(|_| BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable))
            .and_then(|()| self.commit_artifact(name, bytes, true, |_| Ok(())))
    }

    fn commit_artifact(
        &self,
        name: &SubjectKeyArtifactName,
        bytes: &[u8],
        replace_existing: bool,
        after: impl FnMut(CommitStage) -> io::Result<()>,
    ) -> Result<(), BridgeError> {
        let (target, temporary) = (name.canonical(), name.temporary());
        enforce(bytes.len() <= MAX_SUBJECT_KEY_ARTIFACT_BYTES)
            .and_then(|()| self.admit_artifact_directory())
            .map_err(io::Error::from)
            .and_then(|directory| {
                StagedFile::open(&directory, &target, &temporary, replace_existing)
                    .map_err(io::Error::from)
                    .and_then(|staged| staged.commit(bytes, after))
            })
            .map_err(|_| BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable))
    }

    /// List `subject-keys.v1` and read every regular file, as ADR-137 D2 step 4
    /// requires.
    ///
    /// Admits the directory as staging does. At most 4,096 entries other than
    /// `.` and `..` are accepted. Entries are returned sorted by name bytes.
    /// Each entry is inspected without following symlinks. A regular file of
    /// any name is opened with `O_NOFOLLOW`, its identity is rechecked, and
    /// at most 4,097 bytes are read. Every other entry is reported as
    /// [`SubjectKeyArtifactContent::NonRegular`], which D2 treats as
    /// unrecognized. Nothing is parsed, written, removed or repaired.
    ///
    /// # Errors
    /// Returns `Unavailable(InterfaceUnavailable)` for an unsafe directory,
    /// more than 4,096 entries, an entry that changes while being read, or any
    /// I/O failure. No partial listing escapes.
    pub fn list_and_read_subject_key_artifacts(
        &self,
    ) -> Result<Vec<SubjectKeyArtifactEntry>, BridgeError> {
        self.admit_artifact_directory()
            .and_then(|directory| entry_names(&directory).map(|names| (directory, names)))
            .map_err(io::Error::from)
            .and_then(|(directory, names)| {
                names
                    .into_iter()
                    .map(|name| read_entry(&directory, name))
                    .collect()
            })
            .map_err(|_| BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable))
    }

    fn admit_artifact_directory(&self) -> rustix::io::Result<OwnedFd> {
        open_or_create_directory_component(&self.directory, DIRECTORY_NAME)
            .and_then(|directory| validate_directory(&directory).map(|()| directory))
            .and_then(|directory| fs::fsync(&self.directory).map(|()| directory))
    }
}

const fn is_dot(name: &CStr) -> bool {
    matches!(name.to_bytes(), b"." | b"..")
}

fn entry_names(directory: &OwnedFd) -> rustix::io::Result<Vec<CString>> {
    Dir::read_from(directory)
        .and_then(|entries| {
            entries
                .filter(|entry| {
                    entry
                        .as_ref()
                        .map_or(true, |entry| !is_dot(entry.file_name()))
                })
                .take(MAX_SUBJECT_KEY_ARTIFACT_ENTRIES + 1)
                .map(|entry| entry.map(|entry| entry.file_name().to_owned()))
                .collect::<rustix::io::Result<Vec<_>>>()
        })
        .and_then(|mut names| {
            names.sort();
            enforce(names.len() <= MAX_SUBJECT_KEY_ARTIFACT_ENTRIES).map(|()| names)
        })
}

fn read_entry(directory: &OwnedFd, name: CString) -> io::Result<SubjectKeyArtifactEntry> {
    fs::statat(directory, &name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(io::Error::from)
        .and_then(|listed| {
            if FileType::from_raw_mode(listed.st_mode) == FileType::RegularFile {
                read_regular(directory, &name, &listed)
            } else {
                Ok(SubjectKeyArtifactContent::NonRegular)
            }
        })
        .map(|content| SubjectKeyArtifactEntry {
            name: name.into_bytes(),
            content,
        })
}

fn read_regular(
    directory: &OwnedFd,
    name: &CStr,
    listed: &Stat,
) -> io::Result<SubjectKeyArtifactContent> {
    fs::openat(directory, name, READ_FLAGS, Mode::empty())
        .and_then(|file| {
            fs::fstat(&file)
                .and_then(|opened| enforce(same_file(&opened, listed)))
                .map(|()| file)
        })
        .map_err(io::Error::from)
        .and_then(|file| {
            let mut bytes = Vec::new();
            let mut reader = File::from(file).take((MAX_SUBJECT_KEY_ARTIFACT_BYTES + 1) as u64);
            reader
                .read_to_end(&mut bytes)
                .map(|_| SubjectKeyArtifactContent::Regular {
                    identity: [listed.st_dev, listed.st_ino],
                    bytes,
                })
        })
}

#[cfg(test)]
mod tests;
