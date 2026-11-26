#![cfg(any(test, feature = "test-support"))]
//! ADR-123 §4–§6 qualified owner-store binding (Redmine #1547).
//!
//! [`QualifiedSqliteStoreV1::open`] is the owner's qualified constructor. Under
//! shared ADR-121 admission and the ADR-123 filesystem interlock it screens
//! every existing main/WAL/SHM entry, provisions missing companions as empty
//! private files, opens the installed main file read-write without following
//! symlinks on the `unix` VFS, checks WAL mode and, inside one setup
//! `BEGIN IMMEDIATE`, proves through the native `sqlite_filestat('main')`
//! diagnostic and `/proc/self/fd` metadata witnesses that `SQLite` holds
//! exactly the screened objects. It then validates the existing schema
//! without initializing it and attaches the persisted Gateway mode binding
//! (ADR-110 E20 LC3). [`QualifiedSqliteStoreV1::guarded`] is the one guarded
//! operation entry: admission, interlock, witness recheck, `BEGIN IMMEDIATE`
//! and a fresh native proof before the caller's effect.
//!
//! In Wave 9 this stays test-support gated (ADR-123 G13); activation is
//! #1438. Physical identity grants no key, consent or append authority.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};

use pos_core::GatewayModeBindingErrorV1;
use pos_crypto::subject_field_read::SubjectFieldOwnerReadErrorV1;
use pos_crypto::subject_nonce_ledger::SubjectStoreFileIdV1;
use rustix::fd::OwnedFd;
use rustix::fs::{self, Mode, OFlags, Stat, CWD};

use crate::owner_store_admission::OwnerStoreAdmissionV1;
use crate::owner_store_interlock::{
    check_regular, optional_file, same_file, CheckedNamespace, OBSERVE, RESOLVE,
};

pub use crate::sqlite::owner_store_binding::{
    OwnerStoreCloseErrorV1, ProtectedStoreFileBindingV1, QualifiedSqliteStoreV1,
};

/// The two companions, in diagnostic order: the WAL, then the SHM file.
const COMPANIONS: [&str; 2] = ["-wal", "-shm"];

/// Main-file identities whose native connection was retained or whose handle
/// was dropped without a proved close. The retained connection keeps its
/// inode allocated, so an entry never names a different file later.
static RETAINED: Mutex<Vec<SubjectStoreFileIdV1>> = Mutex::new(Vec::new());

/// Record `file_id` as retained for the rest of the process (ADR-123 §1: a
/// fresh context, wrapper or alias cannot escape quarantine).
pub(crate) fn record_retained(file_id: SubjectStoreFileIdV1) {
    RETAINED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(file_id);
}

/// Whether a native connection to `file_id` is retained in this process.
pub(crate) fn is_retained(file_id: SubjectStoreFileIdV1) -> bool {
    RETAINED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .contains(&file_id)
}

/// Closed refusals of the qualified owner-store constructor and its guarded
/// operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OwnerStoreBindingErrorV1 {
    /// Shared ADR-121 admission refused before any lower lock:
    /// `OperationActive` or `ContextQuarantined`.
    #[error("owner store admission refused")]
    Admission(SubjectFieldOwnerReadErrorV1),
    /// The fixed unavailable result. No native connection was retained and
    /// admission is idle again.
    #[error("protected owner store unavailable")]
    Unavailable,
    /// The persisted Gateway mode binding could not be attached; `Unbound`
    /// refuses owner readiness (ADR-110 E20 LC3). The connection was closed.
    #[error("protected owner store mode binding refused")]
    ModeBinding(GatewayModeBindingErrorV1),
    /// Closure was unproved or the native identity changed. The native
    /// connection and witnesses stay retained until process exit, the context
    /// is permanently quarantined and the main file's identity is refused by
    /// every later context in this process.
    #[error("protected owner store quarantined")]
    Quarantined,
}

/// The process-lifetime context of one protected owner store.
///
/// The trusted composition root creates exactly one and shares it with every
/// supported view (ADR-123 §1). It holds the shared ADR-121 admission and the
/// one native slot: at most one qualified native connection exists per
/// context, and a slot whose connection could not be closed safely is never
/// released.
///
/// `Default` creates an idle context with an empty native slot.
#[derive(Debug, Default)]
pub struct OwnerStoreContextV1 {
    admission: OwnerStoreAdmissionV1,
    native_slot: AtomicBool,
}

impl OwnerStoreContextV1 {
    pub(crate) const fn admission(&self) -> &OwnerStoreAdmissionV1 {
        &self.admission
    }

    /// Claim the empty native slot before opening a native connection.
    pub(crate) fn claim_native_slot(&self) -> bool {
        self.native_slot
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Release the slot after its native connection was proved closed.
    pub(crate) fn release_native_slot(&self) {
        self.native_slot.store(false, Ordering::Release);
    }
}

/// The screened main/WAL/SHM objects of one installed store (ADR-123 §4).
///
/// The namespace retains the `O_PATH` witnesses of all three files; the
/// companion stats are the provisioned or existing WAL and SHM objects.
pub(crate) struct OwnerStoreWitnessesV1 {
    namespace: CheckedNamespace,
    companions: [Stat; 2],
}

impl OwnerStoreWitnessesV1 {
    /// Screen every existing entry, provision missing companions as empty
    /// private files, then re-screen all three (ADR-123 §4 steps 1–4).
    ///
    /// An unsafe or unreadable existing entry refuses before any companion is
    /// created. Nothing is repaired, replaced or removed.
    pub(crate) fn screen(directory: &Path, main_basename: &str) -> Option<Self> {
        CheckedNamespace::open(directory, main_basename)
            .ok()
            .and_then(|existing| {
                provision(&existing.directory, main_basename)
                    .and_then(|()| CheckedNamespace::open(directory, main_basename).ok())
                    .filter(|namespace| corresponds(&existing, namespace))
            })
            .and_then(|namespace| {
                let [wal, shm] = &namespace.companions;
                wal.as_ref()
                    .zip(shm.as_ref())
                    .map(|(wal, shm)| [wal.stat, shm.stat])
                    .map(|companions| Self {
                        namespace,
                        companions,
                    })
            })
    }

    /// Recheck the directory, the retained witnesses and the current
    /// directory entries before a later native operation or managed close.
    pub(crate) fn recheck(&self) -> bool {
        self.namespace.recheck().is_ok()
    }

    /// The main file's E16 identity, `[1, st_dev, st_ino]` as SNL1 carries it.
    pub(crate) const fn store_file_id(&self) -> SubjectStoreFileIdV1 {
        SubjectStoreFileIdV1::Linux {
            device: self.namespace.main.stat.st_dev,
            inode: self.namespace.main.stat.st_ino,
        }
    }

    /// The canonical absolute main path, checked against the retained
    /// directory descriptor. It is transport for `SQLite`, not identity.
    pub(crate) fn sqlite_path(&self, directory: &Path, main_basename: &str) -> Option<PathBuf> {
        std::fs::canonicalize(directory)
            .ok()
            .filter(|canonical| self.names_directory(canonical))
            .map(|canonical| canonical.join(main_basename))
    }

    /// Whether `directory` currently names the retained directory object.
    pub(crate) fn names_directory(&self, directory: &Path) -> bool {
        fs::openat(
            CWD,
            directory,
            OBSERVE
                .union(OFlags::DIRECTORY)
                .difference(OFlags::NOFOLLOW),
            Mode::empty(),
        )
        .ok()
        .is_some_and(|resolved| same_object(&resolved, &self.namespace.directory) == Some(true))
    }

    /// Prove that the diagnostic's main, WAL and SHM descriptors are the
    /// screened objects, returning new owned `O_PATH` metadata witnesses.
    pub(crate) fn prove(&self, filestat: &str) -> Option<[OwnedFd; 3]> {
        parse_filestat(filestat).and_then(|[main, wal, shm]| {
            native_witness(main, &self.namespace.main.stat).and_then(|main| {
                native_witness(wal, &self.companions[0]).and_then(|wal| {
                    native_witness(shm, &self.companions[1]).map(|shm| [main, wal, shm])
                })
            })
        })
    }
}

/// Create each missing companion exclusively, empty and private; never write
/// through it, and close it before any `SQLite` call (ADR-123 §4 step 3).
fn provision(directory: &OwnedFd, main_basename: &str) -> Option<()> {
    COMPANIONS.iter().try_for_each(|suffix| {
        let name = format!("{main_basename}{suffix}");
        optional_file(directory, &name).ok().and_then(|existing| {
            existing.map_or_else(|| create_empty(directory, &name), |_| Some(()))
        })
    })
}

fn create_empty(directory: &OwnedFd, name: &str) -> Option<()> {
    fs::openat2(
        directory,
        name,
        OFlags::RDWR
            .union(OFlags::CREATE)
            .union(OFlags::EXCL)
            .union(OFlags::NOFOLLOW)
            .union(OFlags::CLOEXEC),
        Mode::RUSR.union(Mode::WUSR),
        RESOLVE,
    )
    .ok()
    .and_then(|created| check_regular(&created).ok())
    .map(|_| ())
}

/// Whether a re-screened namespace still names the original directory, main
/// file and every companion that already existed at the first screen.
fn corresponds(original: &CheckedNamespace, current: &CheckedNamespace) -> bool {
    same_file(&original.main.stat, &current.main.stat)
        && same_object(&original.directory, &current.directory) == Some(true)
        && original
            .companions
            .iter()
            .zip(&current.companions)
            .all(|(before, after)| {
                before.as_ref().is_none_or(|before| {
                    after
                        .as_ref()
                        .is_some_and(|after| same_file(&before.stat, &after.stat))
                })
            })
}

fn same_object(first: &OwnedFd, second: &OwnedFd) -> Option<bool> {
    fs::fstat(first)
        .and_then(|first| fs::fstat(second).map(|second| same_file(&first, &second)))
        .ok()
}

/// Open a new `O_PATH` witness to the object behind `SQLite`'s descriptor
/// without adopting, duplicating or closing that descriptor (ADR-123 §5).
fn native_witness(descriptor: i32, expected: &Stat) -> Option<OwnedFd> {
    fs::openat(
        CWD,
        format!("/proc/self/fd/{descriptor}"),
        OFlags::PATH.union(OFlags::CLOEXEC),
        Mode::empty(),
    )
    .ok()
    .filter(|witness| check_regular(witness).is_ok_and(|stat| same_file(&stat, expected)))
}

/// Object members nest at most three levels: the root, a file, then the
/// main file's `shm` or `inode` description.
const FILESTAT_OBJECT_DEPTH: u8 = 3;
const ROOT_KEYS: &[&str] = &["db", "journal"];
const MAIN_KEYS: &[&str] = &[
    "h",
    "vfs",
    "eFileLock",
    "pal",
    "shm",
    "mmapSize",
    "nFetchOut",
    "inode",
];
/// The WAL file uses the `SQLite` no-lock methods: no SHM and no inode record.
const WAL_KEYS: &[&str] = &["h", "vfs", "eFileLock", "pal", "mmapSize", "nFetchOut"];
const SHM_KEYS: &[&str] = &["h", "nRef", "id", "sharedMask", "exclMask", "pal"];
/// `unusedFd` is absent here, so a deferred same-inode descriptor refuses.
const INODE_KEYS: &[&str] = &["nRef", "nShared", "eFileLock"];

type FilestatObjectV1<'text> = Vec<(&'text str, FilestatValueV1<'text>)>;

enum FilestatValueV1<'text> {
    Integer(i64),
    Text(&'text str),
    Object(FilestatObjectV1<'text>),
}

impl<'text> FilestatValueV1<'text> {
    const fn as_integer(&self) -> Option<i64> {
        match self {
            Self::Integer(value) => Some(*value),
            _ => None,
        }
    }

    const fn as_text(&self) -> Option<&'text str> {
        match self {
            Self::Text(text) => Some(*text),
            _ => None,
        }
    }

    const fn as_object(&self) -> Option<&[(&'text str, Self)]> {
        match self {
            Self::Object(members) => Some(members.as_slice()),
            _ => None,
        }
    }
}

/// A strict reader of the fixed JSON that `sqlite_filestat` writes: no
/// whitespace, escapes, floats, arrays, duplicate keys or non-canonical
/// integers (a leading zero, `+` or `-0`; `SQLite` never emits them).
struct FilestatCursorV1<'text> {
    rest: &'text str,
}

impl<'text> FilestatCursorV1<'text> {
    fn token(&mut self, token: char) -> Option<()> {
        self.rest.strip_prefix(token).map(|rest| {
            self.rest = rest;
        })
    }

    fn text(&mut self) -> Option<&'text str> {
        self.rest
            .strip_prefix('"')
            .and_then(|quoted| quoted.split_once('"'))
            .filter(|(text, _)| !text.contains('\\'))
            .map(|(text, rest)| {
                self.rest = rest;
                text
            })
    }

    fn integer(&mut self) -> Option<i64> {
        let rest = self.rest;
        let end = rest
            .find(|character: char| character != '-' && !character.is_ascii_digit())
            .unwrap_or(rest.len());
        rest[..end]
            .parse::<i64>()
            .ok()
            .filter(|value| value.to_string() == rest[..end])
            .inspect(|_| {
                self.rest = &rest[end..];
            })
    }

    fn value(&mut self, depth: u8) -> Option<FilestatValueV1<'text>> {
        if self.rest.starts_with('"') {
            self.text().map(FilestatValueV1::Text)
        } else if self.rest.starts_with('{') && depth < FILESTAT_OBJECT_DEPTH {
            self.object(depth + 1).map(FilestatValueV1::Object)
        } else {
            self.integer().map(FilestatValueV1::Integer)
        }
    }

    fn object(&mut self, depth: u8) -> Option<FilestatObjectV1<'text>> {
        let mut members = Vec::new();
        self.token('{')?;
        loop {
            let key = self.text()?;
            self.token(':')?;
            let value = self.value(depth)?;
            if members.iter().any(|(existing, _)| *existing == key) {
                return None;
            }
            members.push((key, value));
            if self.token('}').is_some() {
                return Some(members);
            }
            self.token(',')?;
        }
    }
}

/// Parse the main, WAL and SHM descriptors from `sqlite_filestat('main')`.
///
/// Refuses malformed or unsupported output, a VFS other than `unix`, a
/// missing or duplicate identity field, a descriptor outside `3..=i32::MAX`
/// and any unexpected same-inode reference or deferred descriptor.
fn parse_filestat(filestat: &str) -> Option<[i32; 3]> {
    let mut cursor = FilestatCursorV1 { rest: filestat };
    cursor
        .object(1)
        .filter(|root| cursor.rest.is_empty() && only(root, ROOT_KEYS))
        .and_then(|root| {
            object_field(&root, "db").and_then(|main| {
                object_field(&root, "journal").and_then(|wal| {
                    file_descriptor(main, MAIN_KEYS).and_then(|main_descriptor| {
                        file_descriptor(wal, WAL_KEYS).and_then(|wal_descriptor| {
                            shm_descriptor(main).map(|shm_descriptor| {
                                [main_descriptor, wal_descriptor, shm_descriptor]
                            })
                        })
                    })
                })
            })
        })
}

/// A file's descriptor on the `unix` VFS. A file with an inode record (the
/// main file) must be its only reference.
fn file_descriptor(file: &[(&str, FilestatValueV1<'_>)], allowed: &[&str]) -> Option<i32> {
    let inode = object_field(file, "inode");
    (only(file, allowed)
        && text_field(file, "vfs") == Some("unix")
        && inode.is_some() == allowed.contains(&"inode")
        && inode.is_none_or(|inode| only(inode, INODE_KEYS) && single_reference(inode)))
    .then_some(file)
    .and_then(descriptor)
}

fn shm_descriptor(main: &[(&str, FilestatValueV1<'_>)]) -> Option<i32> {
    object_field(main, "shm")
        .filter(|shm| only(shm, SHM_KEYS) && single_reference(shm))
        .and_then(descriptor)
}

fn single_reference(object: &[(&str, FilestatValueV1<'_>)]) -> bool {
    integer_field(object, "nRef") == Some(1)
}

fn descriptor(object: &[(&str, FilestatValueV1<'_>)]) -> Option<i32> {
    integer_field(object, "h")
        .and_then(|descriptor| i32::try_from(descriptor).ok())
        .filter(|descriptor| *descriptor >= 3)
}

fn only(object: &[(&str, FilestatValueV1<'_>)], allowed: &[&str]) -> bool {
    object.iter().all(|(key, _)| allowed.contains(key))
}

fn field<'object, 'text>(
    object: &'object [(&'text str, FilestatValueV1<'text>)],
    key: &str,
) -> Option<&'object FilestatValueV1<'text>> {
    object
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, value)| value)
}

fn object_field<'object, 'text>(
    object: &'object [(&'text str, FilestatValueV1<'text>)],
    key: &str,
) -> Option<&'object [(&'text str, FilestatValueV1<'text>)]> {
    field(object, key).and_then(FilestatValueV1::as_object)
}

fn integer_field(object: &[(&str, FilestatValueV1<'_>)], key: &str) -> Option<i64> {
    field(object, key).and_then(FilestatValueV1::as_integer)
}

fn text_field<'text>(
    object: &[(&'text str, FilestatValueV1<'text>)],
    key: &str,
) -> Option<&'text str> {
    field(object, key).and_then(FilestatValueV1::as_text)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn private_directory() -> std::io::Result<tempfile::TempDir> {
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
    }

    fn create(directory: &Path, name: &str, mode: u32) -> TestResult {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(directory.join(name))?;
        std::fs::set_permissions(directory.join(name), std::fs::Permissions::from_mode(mode))?;
        Ok(())
    }

    fn filestat(main: i32, wal: i32, shm: i32) -> String {
        format!(
            "{{\"db\":{{\"h\":{main},\"vfs\":\"unix\",\"eFileLock\":\"SHARED\",\
             \"pal\":\"---/-.---.-----\",\"shm\":{{\"h\":{shm},\"nRef\":1,\"id\":0,\
             \"sharedMask\":1,\"exclMask\":0,\"pal\":\"r--/-.---.-----\"}},\
             \"inode\":{{\"nRef\":1,\"nShared\":1,\"eFileLock\":\"SHARED\"}}}},\
             \"journal\":{{\"h\":{wal},\"vfs\":\"unix\"}}}}"
        )
    }

    #[test]
    fn the_parser_reads_the_three_native_descriptors() {
        assert_eq!(
            parse_filestat(&filestat(3, 4, 2_147_483_647)),
            Some([3, 4, i32::MAX])
        );
        assert_eq!(
            parse_filestat(
                "{\"db\":{\"h\":5,\"vfs\":\"unix\",\"shm\":{\"h\":7,\"nRef\":1},\
                 \"inode\":{\"nRef\":1}},\"journal\":{\"h\":6,\"vfs\":\"unix\"}}"
            ),
            Some([5, 6, 7])
        );
    }

    #[test]
    fn the_parser_refuses_descriptors_outside_the_supported_range() {
        for (main, wal, shm) in [(2, 4, 5), (3, 2, 5), (3, 4, 2), (-1, 4, 5)] {
            assert_eq!(parse_filestat(&filestat(main, wal, shm)), None);
        }
        let oversized = filestat(3, 4, 5).replace("\"h\":5", "\"h\":2147483648");
        assert_eq!(parse_filestat(&oversized), None);
    }

    #[test]
    fn the_parser_refuses_other_vfs_references_and_deferred_descriptors() {
        let valid = filestat(3, 4, 5);
        for (from, to) in [
            (
                "\"vfs\":\"unix\",\"eFileLock\"",
                "\"vfs\":\"unix-dotfile\",\"eFileLock\"",
            ),
            (
                "\"journal\":{\"h\":4,\"vfs\":\"unix\"}",
                "\"journal\":{\"h\":4,\"vfs\":\"unix-none\"}",
            ),
            ("\"nRef\":1,\"nShared\"", "\"nRef\":2,\"nShared\""),
            ("\"nRef\":1,\"id\"", "\"nRef\":2,\"id\""),
            (
                "\"eFileLock\":\"SHARED\"}}",
                "\"eFileLock\":\"SHARED\",\"unusedFd\":7}}",
            ),
            (
                "\"journal\":{\"h\":4,",
                "\"journal\":{\"h\":4,\"inode\":{\"nRef\":1},",
            ),
            (
                "\"journal\":{\"h\":4,",
                "\"journal\":{\"h\":4,\"shm\":{\"h\":5,\"nRef\":1},",
            ),
            ("\"sharedMask\":1", "\"sharedMask\":1,\"extra\":1"),
            (
                "\"vfs\":\"unix\",\"eFileLock\"",
                "\"vfs\":\"unix\",\"extra\":1,\"eFileLock\"",
            ),
            ("\"vfs\":\"unix\"}}", "\"vfs\":\"unix\"},\"extra\":1}"),
        ] {
            assert!(valid.contains(from), "{from}");
            assert_eq!(parse_filestat(&valid.replacen(from, to, 1)), None, "{to}");
        }
    }

    #[test]
    fn the_parser_refuses_missing_and_mistyped_identity_fields() {
        for text in [
            "{\"db\":{\"h\":3,\"vfs\":\"unix\",\"shm\":{\"h\":5,\"nRef\":1},\"inode\":{\"nRef\":1}}}",
            "{\"journal\":{\"h\":4,\"vfs\":\"unix\"}}",
            "{\"db\":1,\"journal\":{\"h\":4,\"vfs\":\"unix\"}}",
            "{\"db\":{\"h\":3,\"vfs\":\"unix\",\"shm\":{\"h\":5,\"nRef\":1},\"inode\":{\"nRef\":1}},\
             \"journal\":{\"vfs\":\"unix\"}}",
            "{\"db\":{\"h\":3,\"vfs\":\"unix\",\"inode\":{\"nRef\":1}},\
             \"journal\":{\"h\":4,\"vfs\":\"unix\"}}",
            "{\"db\":{\"h\":3,\"vfs\":\"unix\",\"shm\":{\"h\":5,\"nRef\":1}},\
             \"journal\":{\"h\":4,\"vfs\":\"unix\"}}",
            "{\"db\":{\"h\":3,\"vfs\":\"unix\",\"shm\":{\"h\":5},\"inode\":{\"nRef\":1}},\
             \"journal\":{\"h\":4,\"vfs\":\"unix\"}}",
            "{\"db\":{\"h\":\"3\",\"vfs\":\"unix\",\"shm\":{\"h\":5,\"nRef\":1},\"inode\":{\"nRef\":1}},\
             \"journal\":{\"h\":4,\"vfs\":\"unix\"}}",
            "{\"db\":{\"h\":3,\"vfs\":7,\"shm\":{\"h\":5,\"nRef\":1},\"inode\":{\"nRef\":1}},\
             \"journal\":{\"h\":4,\"vfs\":\"unix\"}}",
            "{\"db\":{\"h\":3,\"vfs\":\"unix\",\"shm\":7,\"inode\":{\"nRef\":1}},\
             \"journal\":{\"h\":4,\"vfs\":\"unix\"}}",
            "{\"db\":{\"h\":3,\"vfs\":\"unix\",\"shm\":{\"h\":5,\"nRef\":1},\"inode\":7},\
             \"journal\":{\"h\":4,\"vfs\":\"unix\"}}",
        ] {
            assert_eq!(parse_filestat(text), None, "{text}");
        }
    }

    #[test]
    fn the_parser_refuses_malformed_json() {
        let valid = filestat(3, 4, 5);
        for text in [
            String::new(),
            "{}".to_owned(),
            valid.replacen('{', "", 1),
            valid.replacen("\"db\"", "db", 1),
            valid.replacen("\"db\":", "\"db\"", 1),
            valid.replacen("\"h\":3", "\"h\":3.5", 1),
            valid.replacen("\"h\":3", "\"h\":+3", 1),
            valid.replacen("\"h\":3", "\"h\":03", 1),
            valid.replacen("\"nRef\":1,\"nShared\"", "\"nRef\":01,\"nShared\"", 1),
            valid.replacen("\"h\":3", "\"h\":3-", 1),
            valid.replacen("\"h\":3,", "\"h\":3 ,", 1),
            valid.replacen("\"unix\"", "\"un\\\"ix\"", 1),
            valid.replacen("\"unix\"", "\"unix", 1),
            valid.replacen("\"h\":3,", "\"h\":3,\"h\":3,", 1),
            valid.replacen("\"db\":{\"h\":3,", "\"db\":{\"h\":3,\"db\":1,", 1),
            format!("{valid} "),
            format!("{valid}{{}}"),
            valid[..valid.len() - 1].to_owned(),
            valid.replacen("\"nShared\":1", "\"nShared\":{\"deep\":1}", 1),
            valid.replacen("\"pal\":\"---/-.---.-----\"", "\"pal\":[1]", 1),
        ] {
            assert_eq!(parse_filestat(&text), None, "{text}");
        }
    }

    #[test]
    fn the_native_slot_admits_one_connection_until_released() {
        let context = OwnerStoreContextV1::default();
        assert!(context.claim_native_slot());
        assert!(!context.claim_native_slot());
        context.release_native_slot();
        assert!(context.claim_native_slot());
        assert!(context.admission().try_enter().is_ok_and(|operation| {
            operation.complete_cleanly();
            true
        }));
    }

    #[test]
    fn screening_provisions_missing_companions_as_empty_private_files() -> TestResult {
        let directory = private_directory()?;
        create(directory.path(), "main", 0o600)?;
        let witnesses =
            OwnerStoreWitnessesV1::screen(directory.path(), "main").ok_or("screening refused")?;
        for suffix in COMPANIONS {
            let metadata =
                std::fs::symlink_metadata(directory.path().join(format!("main{suffix}")))?;
            assert!(metadata.is_file());
            assert_eq!(metadata.len(), 0);
            assert_eq!(metadata.mode() & 0o7777, 0o600);
        }
        let main = std::fs::metadata(directory.path().join("main"))?;
        assert_eq!(
            witnesses.store_file_id(),
            SubjectStoreFileIdV1::Linux {
                device: main.dev(),
                inode: main.ino()
            }
        );
        assert!(witnesses.recheck());
        assert_eq!(
            witnesses.sqlite_path(directory.path(), "main"),
            Some(std::fs::canonicalize(directory.path())?.join("main"))
        );
        Ok(())
    }

    #[test]
    fn screening_keeps_existing_companions_and_refuses_unsafe_ones_first() -> TestResult {
        let directory = private_directory()?;
        create(directory.path(), "main", 0o600)?;
        create(directory.path(), "main-wal", 0o600)?;
        std::fs::write(directory.path().join("main-wal"), b"kept")?;
        assert!(OwnerStoreWitnessesV1::screen(directory.path(), "main").is_some());
        assert_eq!(std::fs::read(directory.path().join("main-wal"))?, b"kept");

        let unsafe_directory = private_directory()?;
        create(unsafe_directory.path(), "main", 0o600)?;
        create(unsafe_directory.path(), "main-wal", 0o644)?;
        assert!(OwnerStoreWitnessesV1::screen(unsafe_directory.path(), "main").is_none());
        assert!(!unsafe_directory.path().join("main-shm").exists());

        let missing = private_directory()?;
        assert!(OwnerStoreWitnessesV1::screen(missing.path(), "main").is_none());
        assert!(!missing.path().join("main-wal").exists());
        Ok(())
    }

    #[test]
    fn an_occupied_companion_name_is_never_replaced() -> TestResult {
        let directory = private_directory()?;
        let opened = fs::openat(
            CWD,
            directory.path(),
            OBSERVE.union(OFlags::DIRECTORY),
            Mode::empty(),
        )?;
        create(directory.path(), "occupied", 0o600)?;
        std::fs::write(directory.path().join("occupied"), b"kept")?;
        assert_eq!(create_empty(&opened, "occupied"), None);
        assert_eq!(std::fs::read(directory.path().join("occupied"))?, b"kept");
        Ok(())
    }

    #[test]
    fn a_rescreen_must_name_the_original_directory_and_main_file() -> TestResult {
        let directory = private_directory()?;
        create(directory.path(), "main", 0o600)?;
        let original = CheckedNamespace::open(directory.path(), "main")?;
        assert!(corresponds(
            &original,
            &CheckedNamespace::open(directory.path(), "main")?
        ));
        let other = private_directory()?;
        create(other.path(), "main", 0o600)?;
        assert!(!corresponds(
            &original,
            &CheckedNamespace::open(other.path(), "main")?
        ));
        std::fs::rename(
            directory.path().join("main"),
            directory.path().join("old-main"),
        )?;
        create(directory.path(), "main", 0o600)?;
        assert!(!corresponds(
            &original,
            &CheckedNamespace::open(directory.path(), "main")?
        ));
        Ok(())
    }

    #[test]
    fn a_rescreen_must_name_every_companion_that_already_existed() -> TestResult {
        let directory = private_directory()?;
        create(directory.path(), "main", 0o600)?;
        create(directory.path(), "main-wal", 0o600)?;
        let original = CheckedNamespace::open(directory.path(), "main")?;
        assert!(corresponds(
            &original,
            &CheckedNamespace::open(directory.path(), "main")?
        ));
        std::fs::rename(
            directory.path().join("main-wal"),
            directory.path().join("old-wal"),
        )?;
        create(directory.path(), "main-wal", 0o600)?;
        assert!(!corresponds(
            &original,
            &CheckedNamespace::open(directory.path(), "main")?
        ));
        std::fs::remove_file(directory.path().join("main-wal"))?;
        assert!(!corresponds(
            &original,
            &CheckedNamespace::open(directory.path(), "main")?
        ));
        Ok(())
    }

    #[test]
    fn screening_retains_the_second_screen_companion_witnesses() -> TestResult {
        let directory = private_directory()?;
        create(directory.path(), "main", 0o600)?;
        create(directory.path(), "main-shm", 0o600)?;
        let witnesses =
            OwnerStoreWitnessesV1::screen(directory.path(), "main").ok_or("screening refused")?;
        for (stat, suffix) in witnesses.companions.iter().zip(COMPANIONS) {
            let metadata = std::fs::metadata(directory.path().join(format!("main{suffix}")))?;
            assert_eq!([stat.st_dev, stat.st_ino], [metadata.dev(), metadata.ino()]);
        }
        Ok(())
    }

    #[test]
    fn a_path_names_the_retained_directory_only_while_it_resolves_to_it() -> TestResult {
        let directory = private_directory()?;
        create(directory.path(), "main", 0o600)?;
        let witnesses =
            OwnerStoreWitnessesV1::screen(directory.path(), "main").ok_or("screening refused")?;
        assert!(witnesses.names_directory(directory.path()));
        let other = private_directory()?;
        assert!(!witnesses.names_directory(other.path()));
        assert!(!witnesses.names_directory(&directory.path().join("missing")));
        Ok(())
    }

    #[test]
    fn a_same_inode_native_witness_whose_metadata_drifted_is_refused() -> TestResult {
        let directory = private_directory()?;
        create(directory.path(), "main", 0o600)?;
        let witnesses =
            OwnerStoreWitnessesV1::screen(directory.path(), "main").ok_or("screening refused")?;
        let files = ["main", "main-wal", "main-shm"]
            .map(|name| std::fs::File::open(directory.path().join(name)));
        let [main_file, wal_file, shm_file] = files;
        let [main_file, wal_file, shm_file] = [main_file?, wal_file?, shm_file?];
        let [main, wal, shm] = [&main_file, &wal_file, &shm_file].map(AsRawFd::as_raw_fd);
        let text = filestat(main, wal, shm);
        assert!(witnesses.prove(&text).is_some());
        std::fs::set_permissions(
            directory.path().join("main"),
            std::fs::Permissions::from_mode(0o640),
        )?;
        assert!(witnesses.prove(&text).is_none());
        std::fs::set_permissions(
            directory.path().join("main"),
            std::fs::Permissions::from_mode(0o600),
        )?;
        assert!(witnesses.prove(&text).is_some());
        std::fs::hard_link(
            directory.path().join("main-wal"),
            directory.path().join("alias"),
        )?;
        assert!(witnesses.prove(&text).is_none());
        Ok(())
    }

    #[test]
    fn every_refusal_has_a_fixed_display_text() {
        for (error, text) in [
            (
                OwnerStoreBindingErrorV1::Admission(SubjectFieldOwnerReadErrorV1::OperationActive),
                "owner store admission refused",
            ),
            (
                OwnerStoreBindingErrorV1::Unavailable,
                "protected owner store unavailable",
            ),
            (
                OwnerStoreBindingErrorV1::ModeBinding(GatewayModeBindingErrorV1::Unbound),
                "protected owner store mode binding refused",
            ),
            (
                OwnerStoreBindingErrorV1::Quarantined,
                "protected owner store quarantined",
            ),
        ] {
            assert_eq!(error.to_string(), text);
        }
    }

    #[test]
    fn a_retained_identity_is_refused_by_every_later_lookup() {
        let retained = SubjectStoreFileIdV1::Linux {
            device: u64::MAX,
            inode: 1,
        };
        let other = SubjectStoreFileIdV1::Linux {
            device: u64::MAX,
            inode: 2,
        };
        assert!(!is_retained(retained));
        record_retained(retained);
        assert!(is_retained(retained));
        assert!(!is_retained(other));
    }

    #[test]
    fn the_proof_accepts_only_the_screened_objects() -> TestResult {
        let directory = private_directory()?;
        create(directory.path(), "main", 0o600)?;
        let witnesses =
            OwnerStoreWitnessesV1::screen(directory.path(), "main").ok_or("screening refused")?;
        create(directory.path(), "other", 0o600)?;
        let files = ["main", "main-wal", "main-shm", "other"]
            .map(|name| std::fs::File::open(directory.path().join(name)));
        let [main_file, wal_file, shm_file, other_file] = files;
        let [main_file, wal_file, shm_file, other_file] =
            [main_file?, wal_file?, shm_file?, other_file?];
        let [main, wal, shm, other] =
            [&main_file, &wal_file, &shm_file, &other_file].map(AsRawFd::as_raw_fd);
        let proved = witnesses
            .prove(&filestat(main, wal, shm))
            .ok_or("proof refused")?;
        for (witness, original) in proved.iter().zip([&main_file, &wal_file, &shm_file]) {
            assert!(same_file(&fs::fstat(witness)?, &fs::fstat(original)?));
        }
        for (main, wal, shm) in [
            (wal, main, shm),
            (main, shm, wal),
            (other, wal, shm),
            (main, other, shm),
            (main, wal, other),
            (main, wal, i32::MAX),
        ] {
            assert!(witnesses.prove(&filestat(main, wal, shm)).is_none());
        }
        assert!(witnesses.prove("{}").is_none());
        Ok(())
    }

    #[test]
    fn a_changed_directory_or_entry_refuses_the_path_and_the_recheck() -> TestResult {
        let directory = private_directory()?;
        create(directory.path(), "main", 0o600)?;
        let witnesses =
            OwnerStoreWitnessesV1::screen(directory.path(), "main").ok_or("screening refused")?;
        let other = private_directory()?;
        assert_eq!(witnesses.sqlite_path(other.path(), "main"), None);
        assert_eq!(
            witnesses.sqlite_path(&other.path().join("missing"), "main"),
            None
        );
        std::fs::rename(
            directory.path().join("main-wal"),
            directory.path().join("moved-wal"),
        )?;
        assert!(!witnesses.recheck());
        Ok(())
    }
}
