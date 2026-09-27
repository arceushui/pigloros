use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use rustix::fs::{self, AtFlags, Dir, FlockOperation, Mode, OFlags, RenameFlags, ResolveFlags};

use crate::{
    verify_oci_closure_v1, BundleAddressV1, ReleaseSourceErrorV1, ReleaseSourceV1,
    VerifiedReleaseBundleV1,
};

const PRIVATE_DIRECTORY_MODE: Mode = Mode::RWXU;
const PRIVATE_FILE_MODE: Mode = Mode::RUSR.union(Mode::WUSR);
const EMPTY_INDEX: &[u8] = br#"{"addresses":[],"version":1}"#;
const LOCK_NAME: &str = ".publisher.lock";
const INDEX_NAME: &str = "published.json";
const RELEASES_NAME: &str = "releases";
const QUARANTINE_NAME: &str = "quarantine";

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicationFaultPointV1 {
    RecoveryRootSyncBeforeNextIndexRemoval,
    InitializeReleases,
    InitializeQuarantine,
    InitializeLock,
    InitializeIndex,
    InitializeRootSync,
    OwnerWrite,
    OwnerSync,
    ManifestWrite,
    BlobWrite,
    BlobSync,
    DirectorySync,
    ReadyWrite,
    ReadySync,
    FinalRename,
    FinalCollision,
    ReleasesSync,
    NextIndexCreate,
    NextIndexWrite,
    NextIndexSync,
    IndexRename,
    RootSync,
    QuarantineRename,
    QuarantineSourceSync,
    QuarantineDirectorySync,
    QuarantineRootSync,
    RecoveryCleanupSync,
    NthSync(usize),
}

#[cfg(test)]
thread_local! {
    static PUBLICATION_FAULT: std::cell::Cell<Option<PublicationFaultPointV1>> = const {
        std::cell::Cell::new(None)
    };
    static SYNC_ATTEMPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn injected_fault(point: PublicationFaultPointV1) -> Result<(), LocalOciPublicationErrorV1> {
    PUBLICATION_FAULT.with(|fault| {
        if fault.get() == Some(point) {
            Err(LocalOciPublicationErrorV1::RecoveryRequired)
        } else {
            Ok(())
        }
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn fault_selected(point: PublicationFaultPointV1) -> bool {
    PUBLICATION_FAULT.with(|fault| fault.get() == Some(point))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn sync_fault_selected(point: Option<PublicationFaultPointV1>) -> bool {
    if point.is_some_and(fault_selected) {
        return true;
    }
    PUBLICATION_FAULT.with(|fault| match fault.get() {
        Some(PublicationFaultPointV1::NthSync(target)) => SYNC_ATTEMPTS.with(|attempts| {
            let current = attempts.get();
            attempts.set(current + 1);
            current == target
        }),
        _ => false,
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn reset_sync_attempts() {
    SYNC_ATTEMPTS.with(|attempts| attempts.set(0));
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn faulted_io_test<T, E>(
    selected: bool,
    error: E,
    operation: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    if selected {
        Err(error)
    } else {
        operation()
    }
}

macro_rules! faulted_io {
    ($selected:expr_2021, $error:expr_2021, $operation:expr_2021) => {{
        #[cfg(test)]
        {
            faulted_io_test($selected, $error, || $operation)
        }
        #[cfg(not(test))]
        {
            $operation
        }
    }};
}

macro_rules! faulted_sync {
    ($point:expr_2021, $file:expr_2021, $error:expr_2021) => {
        faulted_io!(
            sync_fault_selected($point),
            rustix::io::Errno::IO,
            fs::fsync($file)
        )
        .map_err(|_| $error)
    };
}

fn random_nonce_hex() -> Result<String, LocalOciPublicationErrorV1> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut source = File::open("/dev/urandom").map_err(|_| LocalOciPublicationErrorV1::Io)?;
    let mut nonce = [0_u8; 16];
    source
        .read_exact(&mut nonce)
        .map_err(|_| LocalOciPublicationErrorV1::Io)?;
    let mut encoded = String::with_capacity(32);
    for byte in nonce {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(encoded)
}

fn lowercase_hex(value: &str, width: usize) -> bool {
    value.len() == width
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn staging_name_parts(name: &str) -> Option<(&str, &str)> {
    let (digest, nonce) = name.strip_prefix('.')?.split_once(".staging.")?;
    (lowercase_hex(digest, 64) && lowercase_hex(nonce, 32)).then_some((digest, nonce))
}

/// Closed failures for the Linux-local OCI publisher.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LocalOciPublicationErrorV1 {
    #[error("release address is invalid")]
    InvalidAddress,
    #[error("release exceeds a V1 resource bound")]
    BoundsExceeded,
    #[error("local OCI layout is invalid")]
    InvalidLayout,
    #[error("an incompatible release already occupies this address")]
    Collision,
    #[error("local OCI I/O failed")]
    Io,
    #[error("local OCI durability synchronization failed")]
    Sync,
    #[error("local OCI lock is unavailable")]
    LockUnavailable,
    #[error("local OCI recovery is required")]
    RecoveryRequired,
    #[error("local OCI publication outcome is unknown")]
    OutcomeUnknown(BundleAddressV1),
}

/// The result of an immutable local publication attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublishOutcomeV1 {
    /// The release became visible at the durable root-index transition.
    Published(BundleAddressV1),
    /// An equivalent committed release already existed.
    AlreadyPublished(BundleAddressV1),
}

/// Address-scoped result after global recovery and full release validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryOutcomeV1 {
    /// The supplied address is durably indexed and fully revalidated.
    Committed(BundleAddressV1),
    /// The supplied address is absent from both index and final directory.
    Unpublished(BundleAddressV1),
}

/// Bounded cleanup facts from global recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryReportV1 {
    /// Addresses completed during recovery, digest sorted.
    pub committed: Vec<BundleAddressV1>,
    /// Whether the one owned stale staging directory was removed.
    pub removed_staging: u8,
    /// Whether an owned next-index file was removed.
    pub removed_next_index: bool,
}

/// A retained, descriptor-relative Linux-local OCI store root.
///
/// Its constructor initializes only the trusted root layout. Publication and
/// recovery are deliberately added together so that no incomplete writer can
/// become a public API.
#[derive(Debug)]
pub struct LocalOciPublisherV1 {
    root: File,
    owner: u32,
}

impl LocalOciPublisherV1 {
    /// Open and durably initialize a trusted `0700` local store root.
    ///
    /// # Errors
    /// Returns `InvalidLayout` unless the operator-selected root is a private
    /// directory owned by the effective UID. Every child is then opened below
    /// the retained root descriptor with no symlink or mount traversal.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, LocalOciPublicationErrorV1> {
        let root_path = root.as_ref();
        if std::fs::symlink_metadata(root_path)
            .map_err(|_| LocalOciPublicationErrorV1::InvalidLayout)?
            .file_type()
            .is_symlink()
        {
            return Err(LocalOciPublicationErrorV1::InvalidLayout);
        }
        let root = File::open(root_path).map_err(|_| LocalOciPublicationErrorV1::InvalidLayout)?;
        let owner = rustix::process::geteuid().as_raw();
        validate_private_directory(&root, owner)?;
        #[cfg(test)]
        injected_fault(PublicationFaultPointV1::InitializeReleases)?;
        create_private_directory(&root, RELEASES_NAME, owner)?;
        #[cfg(test)]
        injected_fault(PublicationFaultPointV1::InitializeQuarantine)?;
        create_private_directory(&root, QUARANTINE_NAME, owner)?;
        #[cfg(test)]
        injected_fault(PublicationFaultPointV1::InitializeLock)?;
        create_private_file(&root, LOCK_NAME, &[], owner)?;
        #[cfg(test)]
        injected_fault(PublicationFaultPointV1::InitializeIndex)?;
        create_private_file(&root, INDEX_NAME, EMPTY_INDEX, owner)?;
        #[cfg(test)]
        injected_fault(PublicationFaultPointV1::InitializeRootSync)?;
        fs::fsync(&root).map_err(|_| LocalOciPublicationErrorV1::Sync)?;
        Ok(Self { root, owner })
    }

    /// Revalidate the retained trusted root before an adapter operation.
    pub(crate) fn verify_root(&self) -> Result<(), LocalOciPublicationErrorV1> {
        validate_private_directory(&self.root, self.owner)
    }

    /// Publish one already-verified OCI closure under the exclusive store lock.
    ///
    /// # Errors
    /// Returns a closed publication error if lock, layout, or durability checks fail.
    pub fn publish(
        &self,
        bundle: &VerifiedReleaseBundleV1,
    ) -> Result<PublishOutcomeV1, LocalOciPublicationErrorV1> {
        self.verify_root()?;
        let lock = open_private_file(&self.root, LOCK_NAME)?;
        fs::flock(&lock, FlockOperation::LockExclusive)
            .map_err(|_| LocalOciPublicationErrorV1::LockUnavailable)?;
        let result = self
            .recover_locked()
            .and_then(|_| self.publish_locked(bundle));
        fs::flock(&lock, FlockOperation::Unlock)
            .map_err(|_| LocalOciPublicationErrorV1::OutcomeUnknown(bundle.address().clone()))?;
        result
    }

    /// Scan bounded private recovery state under the exclusive writer lock.
    ///
    /// # Errors
    /// Returns a closed recovery error if private state is invalid or incomplete.
    pub fn recover_all(&self) -> Result<RecoveryReportV1, LocalOciPublicationErrorV1> {
        self.verify_root()?;
        let lock = open_private_file(&self.root, LOCK_NAME)?;
        fs::flock(&lock, FlockOperation::LockExclusive)
            .map_err(|_| LocalOciPublicationErrorV1::LockUnavailable)?;
        let result = self.recover_locked();
        fs::flock(&lock, FlockOperation::Unlock)
            .map_err(|_| LocalOciPublicationErrorV1::LockUnavailable)?;
        result
    }

    /// Resolve one uncertain publication outcome under the exclusive lock.
    ///
    /// # Errors
    /// Returns a closed recovery error if global state, the indexed release,
    /// or durable root synchronization cannot be validated.
    pub fn recover(
        &self,
        address: &BundleAddressV1,
    ) -> Result<RecoveryOutcomeV1, LocalOciPublicationErrorV1> {
        self.verify_root()?;
        let lock = open_private_file(&self.root, LOCK_NAME)?;
        fs::flock(&lock, FlockOperation::LockExclusive)
            .map_err(|_| LocalOciPublicationErrorV1::LockUnavailable)?;
        let result = self.recover_locked().and_then(|_| {
            fs::fsync(&self.root).map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
            match self.read_locked(address) {
                Ok(_) => Ok(RecoveryOutcomeV1::Committed(address.clone())),
                Err(ReleaseSourceErrorV1::NotFound) => {
                    let releases = open_directory(&self.root, RELEASES_NAME)?;
                    match fs::statat(&releases, &address.digest()[7..], AtFlags::SYMLINK_NOFOLLOW) {
                        Err(rustix::io::Errno::NOENT) => {
                            Ok(RecoveryOutcomeV1::Unpublished(address.clone()))
                        }
                        _ => Err(LocalOciPublicationErrorV1::RecoveryRequired),
                    }
                }
                Err(_) => Err(LocalOciPublicationErrorV1::RecoveryRequired),
            }
        });
        fs::flock(&lock, FlockOperation::Unlock)
            .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
        result
    }

    fn recover_locked(&self) -> Result<RecoveryReportV1, LocalOciPublicationErrorV1> {
        let quarantine = open_directory(&self.root, QUARANTINE_NAME)?;
        if directory_entries(&quarantine)?.next().is_some() {
            return Err(LocalOciPublicationErrorV1::RecoveryRequired);
        }
        let releases = open_directory(&self.root, RELEASES_NAME)?;
        let index = read_limited(open_private_file(&self.root, INDEX_NAME)?, 64 * 1024)
            .map_err(|_| LocalOciPublicationErrorV1::InvalidLayout)?;
        let indexed =
            parse_root_index(&index).map_err(|_| LocalOciPublicationErrorV1::InvalidLayout)?;
        let removed_staging = self.recover_staging(&releases, &indexed)?;
        faulted_sync!(
            None,
            &releases,
            LocalOciPublicationErrorV1::RecoveryRequired
        )?;
        let removed_next_index = self.recover_next_index()?;
        faulted_sync!(
            None,
            &self.root,
            LocalOciPublicationErrorV1::RecoveryRequired
        )?;
        let finals = directory_entries(&releases)?
            .filter(|name| !name.starts_with('.'))
            .collect::<Vec<_>>();
        if finals.len() > 256 {
            return Err(LocalOciPublicationErrorV1::BoundsExceeded);
        }
        let unindexed = finals
            .into_iter()
            .map(|name| {
                if !lowercase_hex(&name, 64) {
                    self.quarantine_entry(&releases, &name, "final")?;
                    return Err(LocalOciPublicationErrorV1::RecoveryRequired);
                }
                Ok(name)
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|name| {
                !indexed
                    .iter()
                    .any(|address| address.digest() == format!("sha256:{name}"))
            })
            .collect::<Vec<_>>();
        if unindexed.len() > 1 || (unindexed.len() == 1 && indexed.len() >= 256) {
            return Err(LocalOciPublicationErrorV1::BoundsExceeded);
        }
        for address in &indexed {
            let name = &address.digest()[7..];
            let valid = open_directory(&releases, name).and_then(|directory| {
                Self::read_release(&directory, address)
                    .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)
            });
            if valid.is_err() {
                self.quarantine_entry(&releases, name, "final")?;
                return Err(LocalOciPublicationErrorV1::RecoveryRequired);
            }
        }
        let mut committed = Vec::new();
        if let Some(name) = unindexed.first() {
            let recovered = (|| {
                let final_directory = open_directory(&releases, name)?;
                let ready = read_limited(open_private_file(&final_directory, "READY")?, 256)
                    .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
                let ready = std::str::from_utf8(&ready)
                    .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
                let mut lines = ready.lines();
                if lines.next() != Some("pigloros-local-oci-ready-v1") {
                    return Err(LocalOciPublicationErrorV1::RecoveryRequired);
                }
                let digest = lines
                    .next()
                    .ok_or(LocalOciPublicationErrorV1::RecoveryRequired)?;
                let size = lines
                    .next()
                    .ok_or(LocalOciPublicationErrorV1::RecoveryRequired)?
                    .parse::<u64>()
                    .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
                if lines.next().is_some() || digest != format!("sha256:{name}") {
                    return Err(LocalOciPublicationErrorV1::RecoveryRequired);
                }
                let address = BundleAddressV1::new(digest.to_owned(), size)
                    .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
                Self::read_release(&final_directory, &address)
                    .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
                Ok(address)
            })();
            let Ok(address) = recovered else {
                self.quarantine_entry(&releases, name, "final")?;
                return Err(LocalOciPublicationErrorV1::RecoveryRequired);
            };
            self.publish_index(&address)
                .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
            committed.push(address);
        }
        Ok(RecoveryReportV1 {
            committed,
            removed_staging,
            removed_next_index,
        })
    }

    fn recover_staging(
        &self,
        releases: &File,
        indexed: &[BundleAddressV1],
    ) -> Result<u8, LocalOciPublicationErrorV1> {
        let staging = directory_entries(releases)?
            .filter(|name| name.starts_with('.'))
            .collect::<Vec<_>>();
        if staging.len() > 1 {
            return Err(LocalOciPublicationErrorV1::BoundsExceeded);
        }
        if let Some(name) = staging.first() {
            let Some((digest, nonce)) = staging_name_parts(name) else {
                self.quarantine_entry(releases, name, "staging")?;
                return Err(LocalOciPublicationErrorV1::RecoveryRequired);
            };
            if indexed
                .iter()
                .any(|address| &address.digest()[7..] == digest)
            {
                self.quarantine_entry(releases, name, "staging")?;
                return Err(LocalOciPublicationErrorV1::RecoveryRequired);
            }
            let owner = open_directory(releases, name)
                .and_then(|dir| open_private_file(&dir, "OWNER"))
                .and_then(|file| {
                    read_limited(file, 128)
                        .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)
                });
            if owner.ok().as_deref()
                != Some(format!("pigloros-local-oci-staging-v1\n{nonce}\n").as_bytes())
            {
                self.quarantine_entry(releases, name, "staging")?;
                return Err(LocalOciPublicationErrorV1::RecoveryRequired);
            }
            if remove_owned_staging(releases, name).is_err() {
                self.quarantine_entry(releases, name, "staging")?;
                return Err(LocalOciPublicationErrorV1::RecoveryRequired);
            }
            #[cfg(test)]
            injected_fault(PublicationFaultPointV1::RecoveryCleanupSync)?;
            faulted_sync!(None, releases, LocalOciPublicationErrorV1::RecoveryRequired)?;
            Ok(1)
        } else {
            Ok(0)
        }
    }

    fn recover_next_index(&self) -> Result<bool, LocalOciPublicationErrorV1> {
        let next = directory_entries(&self.root)?
            .filter(|name| name.starts_with(".published."))
            .collect::<Vec<_>>();
        if next.len() > 1 {
            return Err(LocalOciPublicationErrorV1::RecoveryRequired);
        }
        if let Some(name) = next.first() {
            let valid_name = name
                .strip_prefix(".published.")
                .and_then(|suffix| suffix.strip_suffix(".next"))
                .is_some_and(|nonce| lowercase_hex(nonce, 32));
            if !valid_name {
                self.quarantine_entry(&self.root, name, "next-index")?;
                return Err(LocalOciPublicationErrorV1::RecoveryRequired);
            }
            if open_private_file(&self.root, name).is_err() {
                self.quarantine_entry(&self.root, name, "next-index")?;
                return Err(LocalOciPublicationErrorV1::RecoveryRequired);
            }
            #[cfg(test)]
            injected_fault(PublicationFaultPointV1::RecoveryRootSyncBeforeNextIndexRemoval)?;
            faulted_sync!(
                None,
                &self.root,
                LocalOciPublicationErrorV1::RecoveryRequired
            )?;
            fs::unlinkat(&self.root, name, AtFlags::empty())
                .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
            faulted_sync!(
                None,
                &self.root,
                LocalOciPublicationErrorV1::RecoveryRequired
            )?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn publish_locked(
        &self,
        bundle: &VerifiedReleaseBundleV1,
    ) -> Result<PublishOutcomeV1, LocalOciPublicationErrorV1> {
        let address = bundle.address();
        match self.read_locked(address) {
            Ok(existing) if existing == *bundle => {
                return Ok(PublishOutcomeV1::AlreadyPublished(address.clone()));
            }
            Ok(_) => return Err(LocalOciPublicationErrorV1::Collision),
            Err(ReleaseSourceErrorV1::NotFound) => {}
            Err(_) => return Err(LocalOciPublicationErrorV1::RecoveryRequired),
        }
        let index = read_limited(open_private_file(&self.root, INDEX_NAME)?, 64 * 1024)
            .map_err(|_| LocalOciPublicationErrorV1::InvalidLayout)?;
        if parse_root_index(&index)
            .map_err(|_| LocalOciPublicationErrorV1::InvalidLayout)?
            .len()
            >= 256
        {
            return Err(LocalOciPublicationErrorV1::BoundsExceeded);
        }
        let releases = open_directory(&self.root, RELEASES_NAME)?;
        let staging_nonce = random_nonce_hex()?;
        let staging_name = format!(".{}.staging.{staging_nonce}", &address.digest()[7..]);
        fs::mkdirat(&releases, &staging_name, PRIVATE_DIRECTORY_MODE)
            .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
        let staging = open_directory(&releases, &staging_name)?;
        write_private_file(
            &staging,
            "OWNER",
            format!("pigloros-local-oci-staging-v1\n{staging_nonce}\n").as_bytes(),
        )?;
        write_private_file(
            &staging,
            "oci-layout",
            b"{\"imageLayoutVersion\":\"1.0.0\"}\n",
        )?;
        let blobs = create_and_open_directory(&staging, "blobs", self.owner)?;
        let sha256 = create_and_open_directory(&blobs, "sha256", self.owner)?;
        #[cfg(test)]
        injected_fault(PublicationFaultPointV1::ManifestWrite)?;
        write_private_file(&sha256, &address.digest()[7..], bundle.manifest())?;
        for blob in bundle.blobs() {
            write_private_file(&sha256, &blob.digest()[7..], blob.bytes())?;
        }
        let index = format!("{{\"manifests\":[{{\"digest\":\"{}\",\"mediaType\":\"{}\",\"size\":{}}}],\"schemaVersion\":2}}", address.digest(), address.media_type(), address.size());
        write_private_file(&staging, "index.json", index.as_bytes())?;
        faulted_sync!(
            Some(PublicationFaultPointV1::DirectorySync),
            &sha256,
            LocalOciPublicationErrorV1::Sync
        )?;
        faulted_sync!(None, &blobs, LocalOciPublicationErrorV1::Sync)?;
        let ready = format!(
            "pigloros-local-oci-ready-v1\n{}\n{}\n",
            address.digest(),
            address.size()
        );
        write_private_file(&staging, "READY", ready.as_bytes())?;
        faulted_sync!(None, &staging, LocalOciPublicationErrorV1::Sync)?;
        faulted_io!(
            fault_selected(PublicationFaultPointV1::FinalRename)
                || fault_selected(PublicationFaultPointV1::FinalCollision),
            if fault_selected(PublicationFaultPointV1::FinalCollision) {
                rustix::io::Errno::EXIST
            } else {
                rustix::io::Errno::IO
            },
            fs::renameat_with(
                &releases,
                &staging_name,
                &releases,
                &address.digest()[7..],
                RenameFlags::NOREPLACE,
            )
        )
        .map_err(|error| {
            if error == rustix::io::Errno::EXIST {
                LocalOciPublicationErrorV1::Collision
            } else {
                LocalOciPublicationErrorV1::Sync
            }
        })?;
        faulted_sync!(
            Some(PublicationFaultPointV1::ReleasesSync),
            &releases,
            LocalOciPublicationErrorV1::Sync
        )?;
        self.publish_index(address)?;
        Ok(PublishOutcomeV1::Published(address.clone()))
    }

    fn quarantine_entry(
        &self,
        source: &File,
        name: &str,
        kind: &str,
    ) -> Result<(), LocalOciPublicationErrorV1> {
        let quarantine = open_directory(&self.root, QUARANTINE_NAME)
            .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
        if directory_entries(&quarantine)?.next().is_some() {
            return Err(LocalOciPublicationErrorV1::RecoveryRequired);
        }
        let destination = format!(
            "{kind}.{}",
            random_nonce_hex().map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?
        );
        faulted_io!(
            fault_selected(PublicationFaultPointV1::QuarantineRename),
            rustix::io::Errno::IO,
            fs::renameat_with(
                source,
                name,
                &quarantine,
                &destination,
                RenameFlags::NOREPLACE,
            )
        )
        .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
        faulted_sync!(
            Some(PublicationFaultPointV1::QuarantineSourceSync),
            source,
            LocalOciPublicationErrorV1::RecoveryRequired
        )?;
        faulted_sync!(
            Some(PublicationFaultPointV1::QuarantineDirectorySync),
            &quarantine,
            LocalOciPublicationErrorV1::RecoveryRequired
        )?;
        faulted_sync!(
            Some(PublicationFaultPointV1::QuarantineRootSync),
            &self.root,
            LocalOciPublicationErrorV1::RecoveryRequired
        )
    }

    fn publish_index(&self, address: &BundleAddressV1) -> Result<(), LocalOciPublicationErrorV1> {
        let index = read_limited(open_private_file(&self.root, INDEX_NAME)?, 64 * 1024)
            .map_err(|_| LocalOciPublicationErrorV1::InvalidLayout)?;
        let mut addresses =
            parse_root_index(&index).map_err(|_| LocalOciPublicationErrorV1::InvalidLayout)?;
        if addresses.len() >= 256 {
            return Err(LocalOciPublicationErrorV1::BoundsExceeded);
        }
        if addresses
            .iter()
            .any(|existing| existing.digest() == address.digest())
        {
            return Err(LocalOciPublicationErrorV1::Collision);
        }
        addresses.push(address.clone());
        addresses.sort_by(|left, right| left.digest().cmp(right.digest()));
        let value = serde_json::json!({
            "addresses": addresses.iter().map(|entry| serde_json::json!({
                "digest": entry.digest(),
                "mediaType": entry.media_type(),
                "size": entry.size(),
            })).collect::<Vec<_>>(),
            "version": 1,
        });
        let bytes =
            serde_json::to_vec(&value).map_err(|_| LocalOciPublicationErrorV1::InvalidLayout)?;
        let next = format!(".published.{}.next", &address.digest()[7..39]);
        write_private_file(&self.root, &next, &bytes)?;
        faulted_io!(
            fault_selected(PublicationFaultPointV1::IndexRename),
            rustix::io::Errno::IO,
            fs::renameat_with(
                &self.root,
                &next,
                &self.root,
                INDEX_NAME,
                RenameFlags::empty(),
            )
        )
        .map_err(|_| LocalOciPublicationErrorV1::Sync)?;
        faulted_sync!(
            Some(PublicationFaultPointV1::RootSync),
            &self.root,
            LocalOciPublicationErrorV1::OutcomeUnknown(address.clone())
        )
    }
}

fn remove_owned_staging(releases: &File, name: &str) -> Result<(), LocalOciPublicationErrorV1> {
    let staging = open_directory(releases, name)?;
    let mut entries = directory_entries(&staging)?.collect::<Vec<_>>();
    entries.sort();
    if !entries.iter().any(|entry| entry == "OWNER")
        || entries.len() > 5
        || entries.iter().any(|entry| {
            !["OWNER", "READY", "oci-layout", "index.json", "blobs"].contains(&entry.as_str())
        })
    {
        return Err(LocalOciPublicationErrorV1::RecoveryRequired);
    }
    for file in ["OWNER", "READY", "oci-layout", "index.json"] {
        if entries.iter().any(|entry| entry == file) {
            open_private_file(&staging, file)?;
        }
    }
    let blobs = if entries.iter().any(|entry| entry == "blobs") {
        Some(open_directory(&staging, "blobs")?)
    } else {
        None
    };
    let sha256 = if let Some(blobs) = &blobs {
        let children = directory_entries(blobs)?.collect::<Vec<_>>();
        if children.len() > 1 || children.iter().any(|name| name != "sha256") {
            return Err(LocalOciPublicationErrorV1::RecoveryRequired);
        }
        if children.is_empty() {
            None
        } else {
            Some(open_directory(blobs, "sha256")?)
        }
    } else {
        None
    };
    let members = if let Some(sha256) = &sha256 {
        let names = directory_entries(sha256)?.collect::<Vec<_>>();
        if names.len() > 359 {
            return Err(LocalOciPublicationErrorV1::BoundsExceeded);
        }
        for member in &names {
            if !lowercase_hex(member, 64) {
                return Err(LocalOciPublicationErrorV1::RecoveryRequired);
            }
            open_private_file(sha256, member)?;
        }
        names
    } else {
        Vec::new()
    };
    if let Some(sha256) = &sha256 {
        for member in members {
            fs::unlinkat(sha256, member, AtFlags::empty())
                .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
        }
        faulted_sync!(None, sha256, LocalOciPublicationErrorV1::Sync)?;
        fs::unlinkat(
            blobs
                .as_ref()
                .ok_or(LocalOciPublicationErrorV1::RecoveryRequired)?,
            "sha256",
            AtFlags::REMOVEDIR,
        )
        .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
    }
    if let Some(blobs) = &blobs {
        faulted_sync!(None, blobs, LocalOciPublicationErrorV1::Sync)?;
        fs::unlinkat(&staging, "blobs", AtFlags::REMOVEDIR)
            .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
    }
    for file in ["READY", "index.json", "oci-layout", "OWNER"] {
        if entries.iter().any(|entry| entry == file) {
            fs::unlinkat(&staging, file, AtFlags::empty())
                .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
        }
    }
    faulted_sync!(None, &staging, LocalOciPublicationErrorV1::Sync)?;
    fs::unlinkat(releases, name, AtFlags::REMOVEDIR)
        .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)
}

fn directory_entries(
    directory: &File,
) -> Result<impl Iterator<Item = String> + use<>, LocalOciPublicationErrorV1> {
    let entries = Dir::read_from(directory)
        .map_err(|_| LocalOciPublicationErrorV1::Io)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| LocalOciPublicationErrorV1::Io)?;
    let names = entries
        .into_iter()
        .map(|entry| {
            entry
                .file_name()
                .to_str()
                .map(str::to_owned)
                .map_err(|_| LocalOciPublicationErrorV1::InvalidLayout)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(names.into_iter().filter(|name| name != "." && name != ".."))
}

impl ReleaseSourceV1 for LocalOciPublisherV1 {
    fn read_verified(
        &self,
        address: &BundleAddressV1,
    ) -> Result<VerifiedReleaseBundleV1, ReleaseSourceErrorV1> {
        self.verify_root()
            .map_err(|error| map_publication_to_source(&error))?;
        let lock = open_private_file(&self.root, LOCK_NAME)
            .map_err(|error| map_publication_to_source(&error))?;
        fs::flock(&lock, FlockOperation::LockShared)
            .map_err(|_| ReleaseSourceErrorV1::LockUnavailable)?;
        let result = self
            .reader_recovery_floor()
            .and_then(|()| self.read_locked(address));
        fs::flock(&lock, FlockOperation::Unlock)
            .map_err(|_| ReleaseSourceErrorV1::LockUnavailable)?;
        result
    }
}

impl LocalOciPublisherV1 {
    fn reader_recovery_floor(&self) -> Result<(), ReleaseSourceErrorV1> {
        let quarantine = open_directory(&self.root, QUARANTINE_NAME)
            .map_err(|error| map_publication_to_source(&error))?;
        if directory_entries(&quarantine)
            .map_err(|error| map_publication_to_source(&error))?
            .next()
            .is_some()
        {
            Err(ReleaseSourceErrorV1::RecoveryRequired)
        } else {
            Ok(())
        }
    }
}

impl LocalOciPublisherV1 {
    fn read_locked(
        &self,
        address: &BundleAddressV1,
    ) -> Result<VerifiedReleaseBundleV1, ReleaseSourceErrorV1> {
        let index = read_limited(
            open_private_file(&self.root, INDEX_NAME)
                .map_err(|error| map_publication_to_source(&error))?,
            64 * 1024,
        )?;
        let addresses = parse_root_index(&index)?;
        let indexed = addresses.iter().any(|entry| entry == address);
        if !indexed {
            return Err(ReleaseSourceErrorV1::NotFound);
        }
        let releases = open_directory(&self.root, RELEASES_NAME)
            .map_err(|error| map_publication_to_source(&error))?;
        let release = open_directory(&releases, &address.digest()[7..])
            .map_err(|error| map_publication_to_source(&error))?;
        let requested = Self::read_release(&release, address)?;
        for indexed_address in addresses.iter().filter(|entry| *entry != address) {
            let other_release = open_directory(&releases, &indexed_address.digest()[7..])
                .map_err(|_| ReleaseSourceErrorV1::RecoveryRequired)?;
            Self::read_release(&other_release, indexed_address)
                .map_err(|_| ReleaseSourceErrorV1::RecoveryRequired)?;
        }
        Ok(requested)
    }

    fn read_release(
        release: &File,
        address: &BundleAddressV1,
    ) -> Result<VerifiedReleaseBundleV1, ReleaseSourceErrorV1> {
        let mut entries = directory_entries(release)
            .map_err(|error| map_publication_to_source(&error))?
            .collect::<Vec<_>>();
        entries.sort();
        if !entries.iter().map(String::as_str).eq([
            "OWNER",
            "READY",
            "blobs",
            "index.json",
            "oci-layout",
        ]) {
            return Err(ReleaseSourceErrorV1::InvalidLayout);
        }
        let owner = read_limited(
            open_private_file(release, "OWNER")
                .map_err(|error| map_publication_to_source(&error))?,
            128,
        )?;
        let owner = std::str::from_utf8(&owner).map_err(|_| ReleaseSourceErrorV1::InvalidLayout)?;
        let nonce = owner
            .strip_prefix("pigloros-local-oci-staging-v1\n")
            .and_then(|value| value.strip_suffix('\n'))
            .ok_or(ReleaseSourceErrorV1::InvalidLayout)?;
        if !lowercase_hex(nonce, 32) {
            return Err(ReleaseSourceErrorV1::InvalidLayout);
        }
        let layout = read_limited(
            open_private_file(release, "oci-layout")
                .map_err(|error| map_publication_to_source(&error))?,
            64,
        )?;
        if layout != b"{\"imageLayoutVersion\":\"1.0.0\"}\n" {
            return Err(ReleaseSourceErrorV1::InvalidLayout);
        }
        let index = read_limited(
            open_private_file(release, "index.json")
                .map_err(|error| map_publication_to_source(&error))?,
            512,
        )?;
        let expected_index = format!("{{\"manifests\":[{{\"digest\":\"{}\",\"mediaType\":\"{}\",\"size\":{}}}],\"schemaVersion\":2}}", address.digest(), address.media_type(), address.size());
        if index != expected_index.as_bytes() {
            return Err(ReleaseSourceErrorV1::InvalidLayout);
        }
        let ready = read_limited(
            open_private_file(release, "READY")
                .map_err(|error| map_publication_to_source(&error))?,
            256,
        )?;
        let expected_ready = format!(
            "pigloros-local-oci-ready-v1\n{}\n{}\n",
            address.digest(),
            address.size()
        );
        if ready != expected_ready.as_bytes() {
            return Err(ReleaseSourceErrorV1::Uncommitted);
        }
        Self::read_release_blobs(release, address)
    }

    fn read_release_blobs(
        release: &File,
        address: &BundleAddressV1,
    ) -> Result<VerifiedReleaseBundleV1, ReleaseSourceErrorV1> {
        let blobs =
            open_directory(release, "blobs").map_err(|error| map_publication_to_source(&error))?;
        let blob_directories = directory_entries(&blobs)
            .map_err(|error| map_publication_to_source(&error))?
            .collect::<Vec<_>>();
        if !blob_directories.iter().map(String::as_str).eq(["sha256"]) {
            return Err(ReleaseSourceErrorV1::InvalidLayout);
        }
        let sha256 =
            open_directory(&blobs, "sha256").map_err(|error| map_publication_to_source(&error))?;
        let manifest = read_limited(
            open_private_file(&sha256, &address.digest()[7..])
                .map_err(|error| map_publication_to_source(&error))?,
            64 * 1024,
        )?;
        let manifest_value = crate::parse_jcs_object(&manifest)?;
        let mut descriptors = BTreeMap::new();
        if let Some(config) = manifest_value.get("config") {
            collect_descriptor(config, &mut descriptors)?;
        }
        if let Some(layers) = manifest_value
            .get("layers")
            .and_then(serde_json::Value::as_array)
        {
            for layer in layers {
                collect_descriptor(layer, &mut descriptors)?;
            }
        }
        let declared_total = descriptors
            .values()
            .try_fold(manifest.len(), |total, size| {
                usize::try_from(*size)
                    .ok()
                    .and_then(|size| total.checked_add(size))
                    .ok_or(ReleaseSourceErrorV1::BoundsExceeded)
            })?;
        if declared_total > crate::MAX_TOTAL_BYTES {
            return Err(ReleaseSourceErrorV1::BoundsExceeded);
        }
        let mut bytes = BTreeMap::new();
        for (digest, _) in descriptors {
            let hex = digest
                .strip_prefix("sha256:")
                .ok_or(ReleaseSourceErrorV1::InvalidDescriptor)?;
            let blob = read_limited(
                open_private_file(&sha256, hex)
                    .map_err(|error| map_publication_to_source(&error))?,
                32 * 1024 * 1024,
            )?;
            bytes.insert(digest, blob);
        }
        let bundle = verify_oci_closure_v1(address.clone(), manifest, bytes)?;
        let expected_blobs = std::iter::once(address.digest()[7..].to_owned())
            .chain(
                bundle
                    .blobs()
                    .iter()
                    .map(|blob| blob.digest()[7..].to_owned()),
            )
            .collect::<BTreeSet<_>>();
        let actual_blobs = directory_entries(&sha256)
            .map_err(|error| map_publication_to_source(&error))?
            .collect::<BTreeSet<_>>();
        if actual_blobs != expected_blobs {
            return Err(ReleaseSourceErrorV1::InvalidLayout);
        }
        Ok(bundle)
    }
}

fn collect_descriptor(
    value: &serde_json::Value,
    into: &mut BTreeMap<String, u64>,
) -> Result<(), ReleaseSourceErrorV1> {
    let digest = value
        .get("digest")
        .and_then(serde_json::Value::as_str)
        .ok_or(ReleaseSourceErrorV1::InvalidDescriptor)?;
    let size = value
        .get("size")
        .and_then(serde_json::Value::as_u64)
        .ok_or(ReleaseSourceErrorV1::InvalidDescriptor)?;
    if into.insert(digest.to_owned(), size).is_some() {
        return Err(ReleaseSourceErrorV1::DuplicateMember);
    }
    Ok(())
}

fn parse_root_index(bytes: &[u8]) -> Result<Vec<BundleAddressV1>, ReleaseSourceErrorV1> {
    let index = crate::parse_jcs_object(bytes).map_err(|_| ReleaseSourceErrorV1::InvalidLayout)?;
    let root = index
        .as_object()
        .ok_or(ReleaseSourceErrorV1::InvalidLayout)?;
    if root.len() != 2 || root.get("version").and_then(serde_json::Value::as_u64) != Some(1) {
        return Err(ReleaseSourceErrorV1::InvalidLayout);
    }
    let entries = root
        .get("addresses")
        .and_then(serde_json::Value::as_array)
        .ok_or(ReleaseSourceErrorV1::InvalidLayout)?;
    if entries.len() > 256 {
        return Err(ReleaseSourceErrorV1::BoundsExceeded);
    }
    let mut addresses: Vec<BundleAddressV1> = Vec::with_capacity(entries.len());
    for entry in entries {
        let object = entry
            .as_object()
            .ok_or(ReleaseSourceErrorV1::InvalidLayout)?;
        if object.len() != 3
            || object.get("mediaType").and_then(serde_json::Value::as_str)
                != Some("application/vnd.oci.image.manifest.v1+json")
        {
            return Err(ReleaseSourceErrorV1::InvalidLayout);
        }
        let digest = object
            .get("digest")
            .and_then(serde_json::Value::as_str)
            .ok_or(ReleaseSourceErrorV1::InvalidLayout)?;
        let size = object
            .get("size")
            .and_then(serde_json::Value::as_u64)
            .ok_or(ReleaseSourceErrorV1::InvalidLayout)?;
        let address = BundleAddressV1::new(digest.to_owned(), size)
            .map_err(|_| ReleaseSourceErrorV1::InvalidLayout)?;
        if addresses
            .last()
            .is_some_and(|previous| previous.digest() >= address.digest())
        {
            return Err(ReleaseSourceErrorV1::InvalidLayout);
        }
        addresses.push(address);
    }
    Ok(addresses)
}

fn read_limited(file: File, limit: usize) -> Result<Vec<u8>, ReleaseSourceErrorV1> {
    let length = usize::try_from(file.metadata().map_err(|_| ReleaseSourceErrorV1::Io)?.len())
        .map_err(|_| ReleaseSourceErrorV1::BoundsExceeded)?;
    if length > limit {
        return Err(ReleaseSourceErrorV1::BoundsExceeded);
    }
    let mut bytes = Vec::with_capacity(length);
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ReleaseSourceErrorV1::Io)?;
    if bytes.len() > limit {
        Err(ReleaseSourceErrorV1::BoundsExceeded)
    } else if bytes.len() == length {
        Ok(bytes)
    } else {
        Err(ReleaseSourceErrorV1::Io)
    }
}

const fn map_publication_to_source(error: &LocalOciPublicationErrorV1) -> ReleaseSourceErrorV1 {
    match error {
        LocalOciPublicationErrorV1::InvalidLayout => ReleaseSourceErrorV1::InvalidLayout,
        LocalOciPublicationErrorV1::Sync | LocalOciPublicationErrorV1::Io => {
            ReleaseSourceErrorV1::Io
        }
        LocalOciPublicationErrorV1::LockUnavailable => ReleaseSourceErrorV1::LockUnavailable,
        _ => ReleaseSourceErrorV1::RecoveryRequired,
    }
}

fn create_private_directory(
    root: &File,
    name: &str,
    owner: u32,
) -> Result<(), LocalOciPublicationErrorV1> {
    match fs::mkdirat(root, name, PRIVATE_DIRECTORY_MODE) {
        Ok(()) => fs::fsync(root).map_err(|_| LocalOciPublicationErrorV1::Sync)?,
        Err(rustix::io::Errno::EXIST) => {}
        Err(_) => return Err(LocalOciPublicationErrorV1::Io),
    }
    let directory = open_directory(root, name)?;
    validate_private_directory(&directory, owner)
}

fn create_and_open_directory(
    root: &File,
    name: &str,
    owner: u32,
) -> Result<File, LocalOciPublicationErrorV1> {
    create_private_directory(root, name, owner)?;
    open_directory(root, name)
}

fn write_private_file(
    root: &File,
    name: &str,
    bytes: &[u8],
) -> Result<(), LocalOciPublicationErrorV1> {
    let mut file = faulted_io!(
        (name == "OWNER" && fault_selected(PublicationFaultPointV1::OwnerWrite))
            || (name == "READY" && fault_selected(PublicationFaultPointV1::ReadyWrite))
            || (name.starts_with(".published.")
                && fault_selected(PublicationFaultPointV1::NextIndexCreate)),
        rustix::io::Errno::IO,
        fs::openat2(
            root,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            PRIVATE_FILE_MODE,
            resolution(),
        )
    )
    .map(File::from)
    .map_err(|_| LocalOciPublicationErrorV1::Io)?;
    faulted_io!(
        (name.starts_with(".published.")
            && fault_selected(PublicationFaultPointV1::NextIndexWrite))
            || (lowercase_hex(name, 64) && fault_selected(PublicationFaultPointV1::BlobWrite)),
        std::io::Error::other("injected local OCI write fault"),
        file.write_all(bytes)
    )
    .map_err(|_| LocalOciPublicationErrorV1::Io)?;
    faulted_io!(
        (name == "OWNER" && fault_selected(PublicationFaultPointV1::OwnerSync))
            || (name == "READY" && fault_selected(PublicationFaultPointV1::ReadySync))
            || (name.starts_with(".published.")
                && fault_selected(PublicationFaultPointV1::NextIndexSync))
            || (lowercase_hex(name, 64) && fault_selected(PublicationFaultPointV1::BlobSync)),
        rustix::io::Errno::IO,
        fs::fsync(&file)
    )
    .map_err(|_| LocalOciPublicationErrorV1::Sync)?;
    fs::fsync(root).map_err(|_| LocalOciPublicationErrorV1::Sync)
}

fn create_private_file(
    root: &File,
    name: &str,
    initial: &[u8],
    owner: u32,
) -> Result<(), LocalOciPublicationErrorV1> {
    let created = match fs::openat2(
        root,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        PRIVATE_FILE_MODE,
        resolution(),
    ) {
        Ok(file) => Some(File::from(file)),
        Err(rustix::io::Errno::EXIST) => None,
        Err(_) => return Err(LocalOciPublicationErrorV1::Io),
    };
    if let Some(mut file) = created {
        file.write_all(initial)
            .map_err(|_| LocalOciPublicationErrorV1::Io)?;
        fs::fsync(&file).map_err(|_| LocalOciPublicationErrorV1::Sync)?;
        fs::fsync(root).map_err(|_| LocalOciPublicationErrorV1::Sync)?;
    }
    let mut file = open_private_file(root, name)?;
    let metadata = file
        .metadata()
        .map_err(|_| LocalOciPublicationErrorV1::Io)?;
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len()
            != u64::try_from(initial.len())
                .map_err(|_| LocalOciPublicationErrorV1::BoundsExceeded)?
    {
        return Err(LocalOciPublicationErrorV1::InvalidLayout);
    }
    let mut actual = Vec::new();
    file.read_to_end(&mut actual)
        .map_err(|_| LocalOciPublicationErrorV1::Io)?;
    if actual != initial {
        return Err(LocalOciPublicationErrorV1::InvalidLayout);
    }
    Ok(())
}

fn open_directory(root: &File, name: &str) -> Result<File, LocalOciPublicationErrorV1> {
    let directory = fs::openat2(
        root,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        resolution(),
    )
    .map(File::from)
    .map_err(|_| LocalOciPublicationErrorV1::InvalidLayout)?;
    validate_private_directory(&directory, rustix::process::geteuid().as_raw())?;
    Ok(directory)
}

fn open_private_file(root: &File, name: &str) -> Result<File, LocalOciPublicationErrorV1> {
    let file = fs::openat2(
        root,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        resolution(),
    )
    .map(File::from)
    .map_err(|_| LocalOciPublicationErrorV1::InvalidLayout)?;
    let metadata = file
        .metadata()
        .map_err(|_| LocalOciPublicationErrorV1::InvalidLayout)?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(LocalOciPublicationErrorV1::InvalidLayout);
    }
    Ok(file)
}

fn validate_private_directory(file: &File, owner: u32) -> Result<(), LocalOciPublicationErrorV1> {
    let metadata = file
        .metadata()
        .map_err(|_| LocalOciPublicationErrorV1::Io)?;
    if !metadata.is_dir() || metadata.uid() != owner || metadata.mode() & 0o7777 != 0o700 {
        return Err(LocalOciPublicationErrorV1::InvalidLayout);
    }
    Ok(())
}

const fn resolution() -> ResolveFlags {
    ResolveFlags::BENEATH
        .union(ResolveFlags::NO_SYMLINKS)
        .union(ResolveFlags::NO_MAGICLINKS)
        .union(ResolveFlags::NO_XDEV)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    use sha2::{Digest as _, Sha256};

    use super::*;

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn digest(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut result = String::from("sha256:");
        for byte in Sha256::digest(bytes) {
            result.push(char::from(HEX[usize::from(byte >> 4)]));
            result.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        result
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn layer(member: &str, media_type: &str, bytes: &[u8]) -> serde_json::Value {
        serde_json::json!({
            "annotations": {"org.pigloros.plugin.member": member},
            "digest": digest(bytes),
            "mediaType": media_type,
            "size": bytes.len(),
        })
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bundle() -> Result<VerifiedReleaseBundleV1, Box<dyn std::error::Error>> {
        let pmf1 = b"pmf1".to_vec();
        let component = b"component".to_vec();
        let wit = b"wit".to_vec();
        let provenance = b"provenance".to_vec();
        let sbom = b"sbom".to_vec();
        let licence = b"licence".to_vec();
        let layers = vec![
            layer(
                "pmf1",
                "application/vnd.pigloros.plugin.manifest.v1+cbor",
                &pmf1,
            ),
            layer(
                "component",
                "application/vnd.pigloros.plugin.component.v1+wasm",
                &component,
            ),
            layer("wit", "application/vnd.pigloros.plugin.wit.v1+tar", &wit),
            layer("provenance", "application/vnd.in-toto+json", &provenance),
            layer("sbom", "application/spdx+json", &sbom),
            layer(
                &format!("licence/{}", &digest(&licence)[7..]),
                "text/plain; charset=utf-8",
                &licence,
            ),
        ];
        let manifest = serde_json::to_vec(&serde_json::json!({
            "artifactType": "application/vnd.pigloros.plugin.release.v1",
            "config": {
                "digest": digest(b"{}"),
                "mediaType": "application/vnd.oci.empty.v1+json",
                "size": 2,
            },
            "layers": layers,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "schemaVersion": 2,
        }))?;
        let address = BundleAddressV1::new(digest(&manifest), u64::try_from(manifest.len())?)?;
        let mut blobs = BTreeMap::new();
        for bytes in [
            b"{}".to_vec(),
            pmf1,
            component,
            wit,
            provenance,
            sbom,
            licence,
        ] {
            blobs.insert(digest(&bytes), bytes);
        }
        Ok(verify_oci_closure_v1(address, manifest, blobs)?)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn private_root(label: &str) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "pigloros-oci-{label}-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root)?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        Ok(root)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn publish_with_fault(
        publisher: &LocalOciPublisherV1,
        bundle: &VerifiedReleaseBundleV1,
        point: PublicationFaultPointV1,
    ) -> Result<PublishOutcomeV1, LocalOciPublicationErrorV1> {
        reset_sync_attempts();
        PUBLICATION_FAULT.with(|fault| fault.set(Some(point)));
        let outcome = publisher.publish(bundle);
        PUBLICATION_FAULT.with(|fault| fault.set(None));
        reset_sync_attempts();
        outcome
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn recover_with_nth_sync_fault(
        publisher: &LocalOciPublisherV1,
        target: usize,
    ) -> Result<RecoveryReportV1, LocalOciPublicationErrorV1> {
        reset_sync_attempts();
        PUBLICATION_FAULT.with(|fault| fault.set(Some(PublicationFaultPointV1::NthSync(target))));
        let outcome = publisher.recover_all();
        PUBLICATION_FAULT.with(|fault| fault.set(None));
        reset_sync_attempts();
        outcome
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn publish_with_nth_sync_fault(
        publisher: &LocalOciPublisherV1,
        bundle: &VerifiedReleaseBundleV1,
        target: usize,
    ) -> Result<PublishOutcomeV1, LocalOciPublicationErrorV1> {
        reset_sync_attempts();
        PUBLICATION_FAULT.with(|fault| fault.set(Some(PublicationFaultPointV1::NthSync(target))));
        let outcome = publisher.publish(bundle);
        PUBLICATION_FAULT.with(|fault| fault.set(None));
        reset_sync_attempts();
        outcome
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn published_release(
        label: &str,
    ) -> Result<
        (std::path::PathBuf, LocalOciPublisherV1, BundleAddressV1),
        Box<dyn std::error::Error>,
    > {
        let root = private_root(label)?;
        let publisher = LocalOciPublisherV1::open(&root)?;
        let bundle = bundle()?;
        let address = bundle.address().clone();
        assert_eq!(
            publisher.publish(&bundle)?,
            PublishOutcomeV1::Published(address.clone())
        );
        Ok((root, publisher, address))
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reader_rejects_mutation(
        label: &str,
        expected: ReleaseSourceErrorV1,
        mutate: impl FnOnce(&std::path::Path, &BundleAddressV1) -> std::io::Result<()>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (root, publisher, address) = published_release(label)?;
        let release = root.join("releases").join(&address.digest()[7..]);
        mutate(&release, &address)?;
        assert_eq!(publisher.read_verified(&address), Err(expected));
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn rewrite_manifest(
        release: &std::path::Path,
        address: &BundleAddressV1,
        mutate: impl FnOnce(&mut serde_json::Value),
    ) -> std::io::Result<()> {
        let path = release
            .join("blobs")
            .join("sha256")
            .join(&address.digest()[7..]);
        let mut manifest =
            serde_json::from_slice(&std::fs::read(&path)?).map_err(std::io::Error::other)?;
        mutate(&mut manifest);
        let bytes = serde_json::to_vec(&manifest).map_err(std::io::Error::other)?;
        if u64::try_from(bytes.len()).ok() != Some(address.size()) {
            return Err(std::io::Error::other(
                "rewritten manifest changed address size",
            ));
        }
        std::fs::write(path, bytes)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn recovery_rejects_shape(
        label: &str,
        expected: LocalOciPublicationErrorV1,
        setup: impl FnOnce(&std::path::Path) -> std::io::Result<()>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = private_root(label)?;
        let publisher = LocalOciPublisherV1::open(&root)?;
        setup(&root)?;
        assert_eq!(publisher.recover_all(), Err(expected));
        let quarantine = root.join("quarantine");
        for entry in std::fs::read_dir(&quarantine)? {
            let path = entry?.path();
            if path.is_dir() {
                std::fs::remove_dir_all(path)?;
            } else {
                std::fs::remove_file(path)?;
            }
        }
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn initialization_faults_retry_from_private_root_without_partial_index(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for point in [
            PublicationFaultPointV1::InitializeReleases,
            PublicationFaultPointV1::InitializeQuarantine,
            PublicationFaultPointV1::InitializeLock,
            PublicationFaultPointV1::InitializeIndex,
            PublicationFaultPointV1::InitializeRootSync,
        ] {
            let root = private_root("initialize")?;
            PUBLICATION_FAULT.with(|fault| fault.set(Some(point)));
            let failed = LocalOciPublisherV1::open(&root);
            PUBLICATION_FAULT.with(|fault| fault.set(None));
            assert!(matches!(
                failed,
                Err(LocalOciPublicationErrorV1::RecoveryRequired)
            ));
            let publisher = LocalOciPublisherV1::open(&root)?;
            assert!(publisher.recover_all()?.committed.is_empty());
            std::fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn quarantine_move_and_sync_faults_keep_unsafe_stage_closed(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for point in [
            PublicationFaultPointV1::QuarantineRename,
            PublicationFaultPointV1::QuarantineSourceSync,
            PublicationFaultPointV1::QuarantineDirectorySync,
            PublicationFaultPointV1::QuarantineRootSync,
        ] {
            let root = private_root("quarantine-fault")?;
            let publisher = LocalOciPublisherV1::open(&root)?;
            std::fs::create_dir(root.join("releases").join(".invalid-stage"))?;
            PUBLICATION_FAULT.with(|fault| fault.set(Some(point)));
            let failed = publisher.recover_all();
            PUBLICATION_FAULT.with(|fault| fault.set(None));
            assert_eq!(failed, Err(LocalOciPublicationErrorV1::RecoveryRequired));
            assert_eq!(
                publisher.recover_all(),
                Err(LocalOciPublicationErrorV1::RecoveryRequired)
            );
            let quarantine = root.join("quarantine");
            let entries = std::fs::read_dir(&quarantine)?.collect::<Result<Vec<_>, _>>()?;
            assert_eq!(entries.len(), 1);
            std::fs::remove_dir_all(entries[0].path())?;
            assert!(publisher.recover_all()?.committed.is_empty());
            std::fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn recovery_cleanup_sync_fault_requires_retry_before_publication(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = private_root("cleanup-sync")?;
        let publisher = LocalOciPublisherV1::open(&root)?;
        let bundle = bundle()?;
        let address = bundle.address().clone();
        assert_eq!(
            publish_with_fault(&publisher, &bundle, PublicationFaultPointV1::ReadyWrite),
            Err(LocalOciPublicationErrorV1::Io)
        );
        PUBLICATION_FAULT
            .with(|fault| fault.set(Some(PublicationFaultPointV1::RecoveryCleanupSync)));
        let failed = publisher.recover_all();
        PUBLICATION_FAULT.with(|fault| fault.set(None));
        assert_eq!(failed, Err(LocalOciPublicationErrorV1::RecoveryRequired));
        assert_eq!(
            publisher.read_verified(&address),
            Err(ReleaseSourceErrorV1::NotFound)
        );
        assert!(publisher.recover_all()?.committed.is_empty());
        assert_eq!(
            publisher.publish(&bundle)?,
            PublishOutcomeV1::Published(address)
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn recovery_sync_failures_are_fail_closed_and_retryable(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for target in 0..6 {
            let root = private_root("recovery-nth-sync")?;
            let publisher = LocalOciPublisherV1::open(&root)?;
            let bundle = bundle()?;
            assert_eq!(
                publish_with_fault(&publisher, &bundle, PublicationFaultPointV1::ReadyWrite),
                Err(LocalOciPublicationErrorV1::Io)
            );
            assert_eq!(
                recover_with_nth_sync_fault(&publisher, target),
                Err(LocalOciPublicationErrorV1::RecoveryRequired)
            );
            for entry in std::fs::read_dir(root.join("quarantine"))? {
                std::fs::remove_dir_all(entry?.path())?;
            }
            assert!(publisher.recover_all()?.committed.is_empty());
            std::fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn publication_sync_failures_are_recoverable_or_address_scoped(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for target in 0..7 {
            let root = private_root("publication-nth-sync")?;
            let publisher = LocalOciPublisherV1::open(&root)?;
            let bundle = bundle()?;
            let address = bundle.address().clone();
            let result = publish_with_nth_sync_fault(&publisher, &bundle, target);
            if target == 6 {
                assert_eq!(
                    result,
                    Err(LocalOciPublicationErrorV1::OutcomeUnknown(address.clone()))
                );
                assert_eq!(
                    publisher.recover(&address)?,
                    RecoveryOutcomeV1::Committed(address)
                );
            } else {
                let expected_error = if target < 2 {
                    LocalOciPublicationErrorV1::RecoveryRequired
                } else {
                    LocalOciPublicationErrorV1::Sync
                };
                assert_eq!(result, Err(expected_error));
                let report = publisher.recover_all()?;
                assert_eq!(
                    report.committed,
                    if target == 5 {
                        vec![address.clone()]
                    } else {
                        vec![]
                    }
                );
                assert_eq!(
                    publisher.publish(&bundle)?,
                    if target == 5 {
                        PublishOutcomeV1::AlreadyPublished(address)
                    } else {
                        PublishOutcomeV1::Published(address)
                    }
                );
            }
            std::fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reader_rejects_tampered_committed_release_shapes() -> Result<(), Box<dyn std::error::Error>>
    {
        reader_rejects_mutation(
            "reader-extra-entry",
            ReleaseSourceErrorV1::InvalidLayout,
            |release, _| std::fs::write(release.join("unexpected"), b"unexpected"),
        )?;
        reader_rejects_mutation(
            "reader-owner",
            ReleaseSourceErrorV1::InvalidLayout,
            |release, _| std::fs::write(release.join("OWNER"), b"broken\n"),
        )?;
        reader_rejects_mutation(
            "reader-layout",
            ReleaseSourceErrorV1::InvalidLayout,
            |release, _| std::fs::write(release.join("oci-layout"), b"{}"),
        )?;
        reader_rejects_mutation(
            "reader-index",
            ReleaseSourceErrorV1::InvalidLayout,
            |release, _| std::fs::write(release.join("index.json"), b"{}"),
        )?;
        reader_rejects_mutation(
            "reader-ready",
            ReleaseSourceErrorV1::Uncommitted,
            |release, _| std::fs::write(release.join("READY"), b"broken\n"),
        )?;
        reader_rejects_mutation(
            "reader-blob-directory",
            ReleaseSourceErrorV1::InvalidLayout,
            |release, _| std::fs::write(release.join("blobs").join("unexpected"), b"unexpected"),
        )?;
        reader_rejects_mutation(
            "reader-manifest",
            ReleaseSourceErrorV1::InvalidDescriptor,
            |release, address| {
                std::fs::write(
                    release
                        .join("blobs")
                        .join("sha256")
                        .join(&address.digest()[7..]),
                    b"{\"config\":{}}",
                )
            },
        )?;
        reader_rejects_mutation(
            "reader-layers",
            ReleaseSourceErrorV1::InvalidDescriptor,
            |release, address| {
                std::fs::write(
                    release
                        .join("blobs")
                        .join("sha256")
                        .join(&address.digest()[7..]),
                    b"{\"layers\":[{}]}",
                )
            },
        )?;
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reader_rejects_tampered_blob_closure() -> Result<(), Box<dyn std::error::Error>> {
        reader_rejects_mutation(
            "reader-missing-manifest",
            ReleaseSourceErrorV1::InvalidLayout,
            |release, address| {
                std::fs::remove_file(
                    release
                        .join("blobs")
                        .join("sha256")
                        .join(&address.digest()[7..]),
                )
            },
        )?;
        reader_rejects_mutation(
            "reader-invalid-manifest",
            ReleaseSourceErrorV1::InvalidDescriptor,
            |release, address| {
                let path = release
                    .join("blobs")
                    .join("sha256")
                    .join(&address.digest()[7..]);
                let mut bytes = std::fs::read(&path)?;
                bytes[0] = b'[';
                std::fs::write(path, bytes)
            },
        )?;
        reader_rejects_mutation(
            "reader-invalid-descriptor-digest",
            ReleaseSourceErrorV1::InvalidDescriptor,
            |release, address| {
                rewrite_manifest(release, address, |manifest| {
                    manifest["config"]["digest"] =
                        serde_json::json!(format!("x{}", "a".repeat(63)));
                })
            },
        )?;
        reader_rejects_mutation(
            "reader-missing-declared-blob",
            ReleaseSourceErrorV1::InvalidLayout,
            |release, address| {
                rewrite_manifest(release, address, |manifest| {
                    let bytes = b"missing";
                    let digest = digest(bytes);
                    manifest["layers"][5]["annotations"]["org.pigloros.plugin.member"] =
                        serde_json::json!(format!("licence/{}", &digest[7..]));
                    manifest["layers"][5]["digest"] = serde_json::json!(digest);
                    manifest["layers"][5]["size"] = serde_json::json!(bytes.len());
                })
            },
        )?;
        reader_rejects_mutation(
            "reader-extra-stored-blob",
            ReleaseSourceErrorV1::InvalidLayout,
            |release, _| {
                std::fs::write(
                    release.join("blobs").join("sha256").join("a".repeat(64)),
                    b"extra",
                )
            },
        )?;
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn recovery_rejects_malformed_staging_and_final_shapes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        recovery_rejects_shape(
            "recovery-invalid-stage-name",
            LocalOciPublicationErrorV1::RecoveryRequired,
            |root| std::fs::create_dir(root.join("releases").join(".invalid-staging")),
        )?;
        recovery_rejects_shape(
            "recovery-invalid-stage-owner",
            LocalOciPublicationErrorV1::RecoveryRequired,
            |root| {
                std::fs::create_dir(root.join("releases").join(format!(
                    ".{}.staging.{}",
                    "a".repeat(64),
                    "b".repeat(32)
                )))
            },
        )?;
        recovery_rejects_shape(
            "recovery-invalid-final-name",
            LocalOciPublicationErrorV1::RecoveryRequired,
            |root| std::fs::create_dir(root.join("releases").join("invalid-final")),
        )?;
        recovery_rejects_shape(
            "recovery-incomplete-final",
            LocalOciPublicationErrorV1::RecoveryRequired,
            |root| std::fs::create_dir(root.join("releases").join("a".repeat(64))),
        )?;
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn recovery_rejects_multiple_private_entries_and_bad_next_index(
    ) -> Result<(), Box<dyn std::error::Error>> {
        recovery_rejects_shape(
            "recovery-multiple-staging",
            LocalOciPublicationErrorV1::BoundsExceeded,
            |root| {
                std::fs::create_dir(root.join("releases").join(".first"))?;
                std::fs::create_dir(root.join("releases").join(".second"))
            },
        )?;
        recovery_rejects_shape(
            "recovery-multiple-final",
            LocalOciPublicationErrorV1::BoundsExceeded,
            |root| {
                std::fs::create_dir(root.join("releases").join("a".repeat(64)))?;
                std::fs::create_dir(root.join("releases").join("b".repeat(64)))
            },
        )?;
        recovery_rejects_shape(
            "recovery-invalid-next-index",
            LocalOciPublicationErrorV1::RecoveryRequired,
            |root| std::fs::write(root.join(".published.invalid.next"), b"invalid"),
        )?;
        recovery_rejects_shape(
            "recovery-insecure-next-index",
            LocalOciPublicationErrorV1::RecoveryRequired,
            |root| {
                std::fs::write(
                    root.join(format!(".published.{}.next", "a".repeat(32))),
                    b"insecure",
                )
            },
        )?;
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn pre_final_publication_faults_leave_only_owned_recoverable_staging(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for point in [
            PublicationFaultPointV1::OwnerSync,
            PublicationFaultPointV1::ManifestWrite,
            PublicationFaultPointV1::BlobWrite,
            PublicationFaultPointV1::BlobSync,
            PublicationFaultPointV1::DirectorySync,
            PublicationFaultPointV1::ReadyWrite,
            PublicationFaultPointV1::ReadySync,
            PublicationFaultPointV1::FinalRename,
            PublicationFaultPointV1::FinalCollision,
        ] {
            let root = private_root("pre-final")?;
            let publisher = LocalOciPublisherV1::open(&root)?;
            let bundle = bundle()?;
            let address = bundle.address().clone();
            let expected = match point {
                PublicationFaultPointV1::OwnerSync
                | PublicationFaultPointV1::BlobSync
                | PublicationFaultPointV1::DirectorySync
                | PublicationFaultPointV1::ReadySync
                | PublicationFaultPointV1::FinalRename => LocalOciPublicationErrorV1::Sync,
                PublicationFaultPointV1::BlobWrite | PublicationFaultPointV1::ReadyWrite => {
                    LocalOciPublicationErrorV1::Io
                }
                PublicationFaultPointV1::FinalCollision => LocalOciPublicationErrorV1::Collision,
                _ => LocalOciPublicationErrorV1::RecoveryRequired,
            };
            assert_eq!(
                publish_with_fault(&publisher, &bundle, point),
                Err(expected)
            );
            assert_eq!(
                publisher.read_verified(&address),
                Err(ReleaseSourceErrorV1::NotFound)
            );
            let report = publisher.recover_all()?;
            assert_eq!(report.removed_staging, 1);
            assert!(report.committed.is_empty());
            assert_eq!(
                publisher.publish(&bundle)?,
                PublishOutcomeV1::Published(address)
            );
            std::fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn owner_write_fault_quarantines_unowned_stage_before_retry(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = private_root("owner-fault")?;
        let publisher = LocalOciPublisherV1::open(&root)?;
        let bundle = bundle()?;
        let address = bundle.address().clone();
        assert_eq!(
            publish_with_fault(&publisher, &bundle, PublicationFaultPointV1::OwnerWrite),
            Err(LocalOciPublicationErrorV1::Io)
        );
        assert_eq!(
            publisher.read_verified(&address),
            Err(ReleaseSourceErrorV1::NotFound)
        );
        assert_eq!(
            publisher.recover_all(),
            Err(LocalOciPublicationErrorV1::RecoveryRequired)
        );
        let quarantine = root.join("quarantine");
        let entries = std::fs::read_dir(&quarantine)?.collect::<Result<Vec<_>, _>>()?;
        assert_eq!(entries.len(), 1);
        std::fs::remove_dir_all(entries[0].path())?;
        assert!(publisher.recover_all()?.committed.is_empty());
        assert_eq!(
            publisher.publish(&bundle)?,
            PublishOutcomeV1::Published(address)
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn post_final_faults_recover_the_one_unindexed_ready_release(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for point in [
            PublicationFaultPointV1::ReleasesSync,
            PublicationFaultPointV1::NextIndexCreate,
            PublicationFaultPointV1::NextIndexWrite,
            PublicationFaultPointV1::NextIndexSync,
            PublicationFaultPointV1::IndexRename,
        ] {
            let root = private_root("post-final")?;
            let publisher = LocalOciPublisherV1::open(&root)?;
            let bundle = bundle()?;
            let address = bundle.address().clone();
            let expected = match point {
                PublicationFaultPointV1::NextIndexCreate
                | PublicationFaultPointV1::NextIndexWrite => LocalOciPublicationErrorV1::Io,
                _ => LocalOciPublicationErrorV1::Sync,
            };
            assert_eq!(
                publish_with_fault(&publisher, &bundle, point),
                Err(expected)
            );
            assert_eq!(
                publisher.read_verified(&address),
                Err(ReleaseSourceErrorV1::NotFound)
            );
            let report = publisher.recover_all()?;
            assert_eq!(report.committed, vec![address.clone()]);
            assert_eq!(
                report.removed_next_index,
                matches!(
                    point,
                    PublicationFaultPointV1::NextIndexWrite
                        | PublicationFaultPointV1::NextIndexSync
                        | PublicationFaultPointV1::IndexRename
                )
            );
            assert_eq!(publisher.read_verified(&address)?, bundle);
            std::fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn root_sync_fault_requires_address_scoped_recovery() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = private_root("root-sync")?;
        let publisher = LocalOciPublisherV1::open(&root)?;
        let bundle = bundle()?;
        let address = bundle.address().clone();
        assert_eq!(
            publish_with_fault(&publisher, &bundle, PublicationFaultPointV1::RootSync),
            Err(LocalOciPublicationErrorV1::OutcomeUnknown(address.clone()))
        );
        assert_eq!(
            publisher.recover(&address)?,
            RecoveryOutcomeV1::Committed(address.clone())
        );
        assert_eq!(publisher.read_verified(&address)?, bundle);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn ready_write_fault_leaves_no_discoverable_release_and_retry_recovers(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "pigloros-oci-ready-fault-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root)?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        let publisher = LocalOciPublisherV1::open(&root)?;
        let bundle = bundle()?;
        let address = bundle.address().clone();
        PUBLICATION_FAULT.with(|fault| fault.set(Some(PublicationFaultPointV1::ReadyWrite)));
        let failed = publisher.publish(&bundle);
        PUBLICATION_FAULT.with(|fault| fault.set(None));
        assert_eq!(failed, Err(LocalOciPublicationErrorV1::Io));
        assert_eq!(
            publisher.read_verified(&address),
            Err(ReleaseSourceErrorV1::NotFound)
        );
        let report = publisher.recover_all()?;
        assert_eq!(report.removed_staging, 1);
        assert!(report.committed.is_empty());
        assert_eq!(
            publisher.publish(&bundle)?,
            PublishOutcomeV1::Published(address)
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn recovery_fault_before_next_index_removal_fails_closed(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "pigloros-oci-fault-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root)?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        {
            let publisher = LocalOciPublisherV1::open(&root)?;
            let next = ".published.0123456789abcdef0123456789abcdef.next";
            write_private_file(&publisher.root, next, b"next")?;
            PUBLICATION_FAULT.with(|fault| {
                fault.set(Some(
                    PublicationFaultPointV1::RecoveryRootSyncBeforeNextIndexRemoval,
                ));
            });
            assert_eq!(
                publisher.recover_all(),
                Err(LocalOciPublicationErrorV1::RecoveryRequired)
            );
            PUBLICATION_FAULT.with(|fault| fault.set(None));
            assert!(root.join(next).exists());
        }
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
