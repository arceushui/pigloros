use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use rustix::fs::{
    self, AtFlags, Dir, FlockOperation, Mode, OFlags, RenameFlags, ResolveFlags, CWD,
};

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
const EXT_SUPER_MAGIC: u64 = 0xef53;
const XFS_SUPER_MAGIC: u64 = 0x5846_5342;
const BTRFS_SUPER_MAGIC: u64 = 0x9123_683e;
const F2FS_SUPER_MAGIC: u64 = 0xf2f5_2010;

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
    DirectoryRead,
    OpenDirectory,
    OpenPrivateFile,
    ReadMetadata,
    ReadBytes,
    NthSync(usize),
    NthIo(usize),
}

#[cfg(test)]
thread_local! {
    static PUBLICATION_FAULT: std::cell::Cell<Option<PublicationFaultPointV1>> = const {
        std::cell::Cell::new(None)
    };
    static SYNC_ATTEMPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static IO_ATTEMPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
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
fn injected_io_error<E: From<rustix::io::Errno>>() -> E {
    rustix::io::Errno::IO.into()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn faulted_io_test<T, E>(
    selected: bool,
    error: E,
    operation: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let nth_selected = IO_ATTEMPTS.with(|attempts| {
        let current = attempts.get();
        attempts.set(current + 1);
        fault_selected(PublicationFaultPointV1::NthIo(current))
    });
    if selected || nth_selected {
        Err(error)
    } else {
        operation()
    }
}

macro_rules! faulted_io {
    ($operation:expr_2021) => {
        faulted_io!(false, injected_io_error(), $operation)
    };
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
    let mut source =
        faulted_io!(File::open("/dev/urandom")).map_err(|_| LocalOciPublicationErrorV1::Io)?;
    let mut nonce = [0_u8; 16];
    faulted_io!(source.read_exact(&mut nonce)).map_err(|_| LocalOciPublicationErrorV1::Io)?;
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

struct RecoveryInventory {
    staging: Vec<String>,
    unindexed: Vec<BundleAddressV1>,
}

impl LocalOciPublisherV1 {
    /// Open and durably initialize a trusted `0700` local store root.
    ///
    /// # Errors
    /// Returns `InvalidLayout` unless the operator-selected root is a private
    /// directory owned by the effective UID. Every child is then opened below
    /// the retained root descriptor with no symlink or mount traversal.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, LocalOciPublicationErrorV1> {
        let root = open_root(root.as_ref())?;
        let owner = rustix::process::geteuid().as_raw();
        validate_private_directory(&root, owner)?;
        validate_local_filesystem(&root)?;
        #[cfg(test)]
        injected_fault(PublicationFaultPointV1::InitializeReleases)?;
        create_private_directory(&root, RELEASES_NAME, owner)?;
        #[cfg(test)]
        injected_fault(PublicationFaultPointV1::InitializeQuarantine)?;
        create_private_directory(&root, QUARANTINE_NAME, owner)?;
        #[cfg(test)]
        injected_fault(PublicationFaultPointV1::InitializeLock)?;
        create_private_file(&root, LOCK_NAME, &[])?;
        #[cfg(test)]
        injected_fault(PublicationFaultPointV1::InitializeIndex)?;
        create_private_file(&root, INDEX_NAME, EMPTY_INDEX)?;
        #[cfg(test)]
        injected_fault(PublicationFaultPointV1::InitializeRootSync)?;
        faulted_sync!(None, &root, LocalOciPublicationErrorV1::Sync)?;
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
        faulted_io!(fs::flock(&lock, FlockOperation::LockExclusive))
            .map_err(|_| LocalOciPublicationErrorV1::LockUnavailable)?;
        let result = self
            .recover_locked()
            .and_then(|_| self.publish_locked(bundle));
        faulted_io!(fs::flock(&lock, FlockOperation::Unlock))
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
        faulted_io!(fs::flock(&lock, FlockOperation::LockExclusive))
            .map_err(|_| LocalOciPublicationErrorV1::LockUnavailable)?;
        let result = self.recover_locked();
        faulted_io!(fs::flock(&lock, FlockOperation::Unlock))
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
        faulted_io!(fs::flock(&lock, FlockOperation::LockExclusive))
            .map_err(|_| LocalOciPublicationErrorV1::LockUnavailable)?;
        let result = self.recover_locked().and_then(|_| {
            faulted_sync!(
                None,
                &self.root,
                LocalOciPublicationErrorV1::RecoveryRequired
            )?;
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
        faulted_io!(fs::flock(&lock, FlockOperation::Unlock))
            .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
        result
    }

    fn recover_locked(&self) -> Result<RecoveryReportV1, LocalOciPublicationErrorV1> {
        let quarantine = open_directory(&self.root, QUARANTINE_NAME)?;
        if directory_names(&quarantine)?.next().transpose()?.is_some() {
            return Err(LocalOciPublicationErrorV1::RecoveryRequired);
        }
        let releases = open_directory(&self.root, RELEASES_NAME)?;
        let index = read_limited(open_private_file(&self.root, INDEX_NAME)?, 64 * 1024)
            .map_err(|_| LocalOciPublicationErrorV1::InvalidLayout)?;
        let indexed =
            parse_root_index(&index).map_err(|_| LocalOciPublicationErrorV1::InvalidLayout)?;
        let next_index = self.next_index_candidate()?;
        let inventory = self.recovery_inventory(&releases, &indexed)?;
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
        let removed_staging = self.recover_staging(&releases, &inventory.staging)?;
        faulted_sync!(
            None,
            &releases,
            LocalOciPublicationErrorV1::RecoveryRequired
        )?;
        let removed_next_index = self.recover_next_index(next_index.as_deref())?;
        faulted_sync!(
            None,
            &self.root,
            LocalOciPublicationErrorV1::RecoveryRequired
        )?;
        let mut committed = Vec::new();
        for address in inventory.unindexed {
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

    fn recovery_inventory(
        &self,
        releases: &File,
        indexed: &[BundleAddressV1],
    ) -> Result<RecoveryInventory, LocalOciPublicationErrorV1> {
        // The raw inventory ceiling precedes all mutation. Below that bound,
        // unsafe entries must be quarantined rather than counted as candidates.
        let entries = bounded_directory_entries(releases, 258)?;
        let mut staging = Vec::new();
        let mut unindexed = Vec::new();
        for name in entries {
            if name.starts_with('.') {
                if validate_owned_staging(releases, &name, indexed).is_err() {
                    self.quarantine_entry(releases, &name, "staging")?;
                    return Err(LocalOciPublicationErrorV1::RecoveryRequired);
                }
                staging.push(name);
            } else {
                if !lowercase_hex(&name, 64) {
                    self.quarantine_entry(releases, &name, "final")?;
                    return Err(LocalOciPublicationErrorV1::RecoveryRequired);
                }
                if indexed.iter().any(|address| address.digest()[7..] == name) {
                    continue;
                }
                let Ok(address) = read_ready_release(releases, &name) else {
                    self.quarantine_entry(releases, &name, "final")?;
                    return Err(LocalOciPublicationErrorV1::RecoveryRequired);
                };
                unindexed.push(address);
            }
        }
        if staging.len() > 1
            || unindexed.len() > 1
            || (!unindexed.is_empty() && indexed.len() >= 256)
        {
            return Err(LocalOciPublicationErrorV1::BoundsExceeded);
        }
        Ok(RecoveryInventory { staging, unindexed })
    }

    fn recover_staging(
        &self,
        releases: &File,
        staging: &[String],
    ) -> Result<u8, LocalOciPublicationErrorV1> {
        if let Some(name) = staging.first() {
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

    fn next_index_candidate(&self) -> Result<Option<String>, LocalOciPublicationErrorV1> {
        let root_entries = bounded_directory_entries(&self.root, 5)
            .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
        if root_entries.iter().any(|name| {
            ![LOCK_NAME, INDEX_NAME, RELEASES_NAME, QUARANTINE_NAME].contains(&name.as_str())
                && !name.starts_with(".published.")
        }) {
            return Err(LocalOciPublicationErrorV1::RecoveryRequired);
        }
        let next = root_entries
            .into_iter()
            .filter(|name| name.starts_with(".published."))
            .collect::<Vec<_>>();
        if next.len() > 1 {
            return Err(LocalOciPublicationErrorV1::RecoveryRequired);
        }
        Ok(next.into_iter().next())
    }

    fn recover_next_index(&self, name: Option<&str>) -> Result<bool, LocalOciPublicationErrorV1> {
        if let Some(name) = name {
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
            faulted_io!(fs::unlinkat(&self.root, name, AtFlags::empty()))
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
        faulted_io!(fs::mkdirat(
            &releases,
            &staging_name,
            PRIVATE_DIRECTORY_MODE
        ))
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
        if directory_names(&quarantine)?.next().transpose()?.is_some() {
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
        let bytes = value.to_string().into_bytes();
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

fn validate_owned_staging(
    releases: &File,
    name: &str,
    indexed: &[BundleAddressV1],
) -> Result<(), LocalOciPublicationErrorV1> {
    let (digest, nonce) =
        staging_name_parts(name).ok_or(LocalOciPublicationErrorV1::RecoveryRequired)?;
    if indexed
        .iter()
        .any(|address| &address.digest()[7..] == digest)
    {
        return Err(LocalOciPublicationErrorV1::RecoveryRequired);
    }
    let directory = open_directory(releases, name)?;
    let owner = read_limited(open_private_file(&directory, "OWNER")?, 128)
        .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
    if owner == format!("pigloros-local-oci-staging-v1\n{nonce}\n").as_bytes() {
        Ok(())
    } else {
        Err(LocalOciPublicationErrorV1::RecoveryRequired)
    }
}

fn read_ready_release(
    releases: &File,
    name: &str,
) -> Result<BundleAddressV1, LocalOciPublicationErrorV1> {
    let directory = open_directory(releases, name)?;
    let ready = read_limited(open_private_file(&directory, "READY")?, 256)
        .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
    let ready =
        std::str::from_utf8(&ready).map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
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
    LocalOciPublisherV1::read_release(&directory, &address)
        .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
    Ok(address)
}

fn remove_owned_staging(releases: &File, name: &str) -> Result<(), LocalOciPublicationErrorV1> {
    let staging = open_directory(releases, name)?;
    let mut entries = bounded_directory_entries(&staging, 5)?;
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
        let children = bounded_directory_entries(blobs, 1)?;
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
        let names = bounded_directory_entries(sha256, 359)?;
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
    if let (Some(sha256), Some(blobs)) = (&sha256, &blobs) {
        for member in members {
            faulted_io!(fs::unlinkat(sha256, member, AtFlags::empty()))
                .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
        }
        faulted_sync!(None, sha256, LocalOciPublicationErrorV1::Sync)?;
        faulted_io!(fs::unlinkat(blobs, "sha256", AtFlags::REMOVEDIR,))
            .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
    }
    if let Some(blobs) = &blobs {
        faulted_sync!(None, blobs, LocalOciPublicationErrorV1::Sync)?;
        faulted_io!(fs::unlinkat(&staging, "blobs", AtFlags::REMOVEDIR))
            .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
    }
    for file in ["READY", "index.json", "oci-layout", "OWNER"] {
        if entries.iter().any(|entry| entry == file) {
            faulted_io!(fs::unlinkat(&staging, file, AtFlags::empty()))
                .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
        }
    }
    faulted_sync!(None, &staging, LocalOciPublicationErrorV1::Sync)?;
    faulted_io!(fs::unlinkat(releases, name, AtFlags::REMOVEDIR))
        .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)
}

fn directory_names(
    directory: &File,
) -> Result<
    impl Iterator<Item = Result<String, LocalOciPublicationErrorV1>> + use<>,
    LocalOciPublicationErrorV1,
> {
    let entries = faulted_io!(
        fault_selected(PublicationFaultPointV1::DirectoryRead),
        rustix::io::Errno::IO,
        Dir::read_from(directory)
    )
    .map_err(|_| LocalOciPublicationErrorV1::Io)?;
    Ok(entries.filter_map(|entry| {
        let Ok(entry) = faulted_io!(entry) else {
            return Some(Err(LocalOciPublicationErrorV1::Io));
        };
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            None
        } else {
            Some(
                name.to_str()
                    .map(str::to_owned)
                    .map_err(|_| LocalOciPublicationErrorV1::InvalidLayout),
            )
        }
    }))
}

fn bounded_directory_entries(
    directory: &File,
    limit: usize,
) -> Result<Vec<String>, LocalOciPublicationErrorV1> {
    let entries = directory_names(directory)?
        .take(limit + 1)
        .collect::<Result<Vec<_>, _>>()?;
    if entries.len() > limit {
        Err(LocalOciPublicationErrorV1::BoundsExceeded)
    } else {
        Ok(entries)
    }
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
        faulted_io!(fs::flock(&lock, FlockOperation::LockShared))
            .map_err(|_| ReleaseSourceErrorV1::LockUnavailable)?;
        let result = self
            .reader_recovery_floor()
            .and_then(|()| self.read_locked(address));
        faulted_io!(fs::flock(&lock, FlockOperation::Unlock))
            .map_err(|_| ReleaseSourceErrorV1::LockUnavailable)?;
        result
    }
}

impl LocalOciPublisherV1 {
    fn reader_recovery_floor(&self) -> Result<(), ReleaseSourceErrorV1> {
        let quarantine = open_directory(&self.root, QUARANTINE_NAME)
            .map_err(|error| map_publication_to_source(&error))?;
        if directory_names(&quarantine)
            .map_err(|error| map_publication_to_source(&error))?
            .next()
            .transpose()
            .map_err(|error| map_publication_to_source(&error))?
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
        let mut entries = bounded_directory_entries(release, 5)
            .map_err(|_| ReleaseSourceErrorV1::InvalidLayout)?;
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
        let blob_directories = bounded_directory_entries(&blobs, 1)
            .map_err(|_| ReleaseSourceErrorV1::InvalidLayout)?;
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
        for (digest, size) in descriptors {
            let hex = digest
                .strip_prefix("sha256:")
                .ok_or(ReleaseSourceErrorV1::InvalidDescriptor)?;
            let blob = read_limited(
                open_private_file(&sha256, hex)
                    .map_err(|error| map_publication_to_source(&error))?,
                usize::try_from(size)
                    .unwrap_or(32 * 1024 * 1024)
                    .min(32 * 1024 * 1024),
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
        let actual_blobs = bounded_directory_entries(&sha256, 359)
            .map_err(|_| ReleaseSourceErrorV1::InvalidLayout)?
            .into_iter()
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
    let length = faulted_io!(
        fault_selected(PublicationFaultPointV1::ReadMetadata),
        std::io::Error::other("injected local OCI metadata fault"),
        file.metadata()
    )
    .map_err(|_| ReleaseSourceErrorV1::Io)?
    .len();
    // Metadata is only an allocation hint: the bounded read enforces the
    // actual limit even if a file grows or shrinks between the two calls.
    let capacity = usize::try_from(length).unwrap_or(limit).min(limit);
    let mut bytes = Vec::with_capacity(capacity);
    faulted_io!(
        fault_selected(PublicationFaultPointV1::ReadBytes),
        std::io::Error::other("injected local OCI read fault"),
        file.take(limit as u64 + 1).read_to_end(&mut bytes)
    )
    .map_err(|_| ReleaseSourceErrorV1::Io)?;
    if bytes.len() > limit {
        Err(ReleaseSourceErrorV1::BoundsExceeded)
    } else {
        Ok(bytes)
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
    match faulted_io!(fs::mkdirat(root, name, PRIVATE_DIRECTORY_MODE)) {
        Ok(()) => faulted_sync!(None, root, LocalOciPublicationErrorV1::Sync)?,
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
    faulted_sync!(None, root, LocalOciPublicationErrorV1::Sync)
}

fn create_private_file(
    root: &File,
    name: &str,
    initial: &[u8],
) -> Result<(), LocalOciPublicationErrorV1> {
    let created = match faulted_io!(fs::openat2(
        root,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        PRIVATE_FILE_MODE,
        resolution(),
    )) {
        Ok(file) => Some(File::from(file)),
        Err(rustix::io::Errno::EXIST) => None,
        Err(_) => return Err(LocalOciPublicationErrorV1::Io),
    };
    if let Some(mut file) = created {
        faulted_io!(file.write_all(initial)).map_err(|_| LocalOciPublicationErrorV1::Io)?;
        faulted_sync!(None, &file, LocalOciPublicationErrorV1::Sync)?;
        faulted_sync!(None, root, LocalOciPublicationErrorV1::Sync)?;
    }
    // Existing committed indexes survive process restart. Only a newly created
    // index is initialized empty; every existing one is bounded and validated.
    let actual = read_limited(open_private_file(root, name)?, crate::MAX_JCS_BYTES)
        .map_err(|_| LocalOciPublicationErrorV1::InvalidLayout)?;
    if name == INDEX_NAME {
        parse_root_index(&actual)
            .map(|_| ())
            .map_err(|_| LocalOciPublicationErrorV1::InvalidLayout)
    } else if actual == initial {
        Ok(())
    } else {
        Err(LocalOciPublicationErrorV1::InvalidLayout)
    }
}

fn open_directory(root: &File, name: &str) -> Result<File, LocalOciPublicationErrorV1> {
    let directory = faulted_io!(
        fault_selected(PublicationFaultPointV1::OpenDirectory),
        rustix::io::Errno::IO,
        fs::openat2(
            root,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            resolution(),
        )
    )
    .map(File::from)
    .map_err(|_| LocalOciPublicationErrorV1::InvalidLayout)?;
    validate_private_directory(&directory, rustix::process::geteuid().as_raw())?;
    Ok(directory)
}

fn open_root(root: &Path) -> Result<File, LocalOciPublicationErrorV1> {
    fs::openat2(
        CWD,
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map(File::from)
    .map_err(|_| LocalOciPublicationErrorV1::InvalidLayout)
}

fn validate_local_filesystem(root: &File) -> Result<(), LocalOciPublicationErrorV1> {
    let filesystem_type = fs::fstatfs(root)
        .ok()
        .and_then(|filesystem| u64::try_from(filesystem.f_type).ok());
    if matches!(
        filesystem_type,
        Some(EXT_SUPER_MAGIC | XFS_SUPER_MAGIC | BTRFS_SUPER_MAGIC | F2FS_SUPER_MAGIC)
    ) {
        Ok(())
    } else {
        Err(LocalOciPublicationErrorV1::InvalidLayout)
    }
}

fn open_private_file(root: &File, name: &str) -> Result<File, LocalOciPublicationErrorV1> {
    let file = faulted_io!(
        fault_selected(PublicationFaultPointV1::OpenPrivateFile),
        rustix::io::Errno::IO,
        fs::openat2(
            root,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
            resolution(),
        )
    )
    .map(File::from)
    .map_err(|_| LocalOciPublicationErrorV1::InvalidLayout)?;
    let metadata =
        faulted_io!(file.metadata()).map_err(|_| LocalOciPublicationErrorV1::InvalidLayout)?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(LocalOciPublicationErrorV1::InvalidLayout);
    }
    Ok(file)
}

fn validate_private_directory(file: &File, owner: u32) -> Result<(), LocalOciPublicationErrorV1> {
    let metadata = faulted_io!(file.metadata()).map_err(|_| LocalOciPublicationErrorV1::Io)?;
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

    #[derive(Clone, Copy, Debug)]
    enum PublicIoScenario {
        Initialize,
        Publish,
        Read,
        RecoverCommitted,
        RecoverAbsent,
        RecoverStaging,
        RecoverNextIndex,
        RecoverFinal,
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn with_io_fault<T>(target: usize, operation: impl FnOnce() -> T) -> (T, usize) {
        IO_ATTEMPTS.with(|attempts| attempts.set(0));
        PUBLICATION_FAULT.with(|fault| fault.set(Some(PublicationFaultPointV1::NthIo(target))));
        let result = operation();
        PUBLICATION_FAULT.with(|fault| fault.set(None));
        let calls = IO_ATTEMPTS.with(std::cell::Cell::get);
        (result, calls)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_io_scenario(
        scenario: PublicIoScenario,
        target: usize,
    ) -> Result<(bool, usize), Box<dyn std::error::Error>> {
        let root = private_root("public-io")?;
        if let PublicIoScenario::Initialize = scenario {
            let (result, calls) = with_io_fault(target, || LocalOciPublisherV1::open(&root));
            let succeeded = result.is_ok();
            drop(result);
            std::fs::remove_dir_all(root)?;
            return Ok((succeeded, calls));
        }
        let publisher = LocalOciPublisherV1::open(&root)?;
        let release = bundle()?;
        match scenario {
            PublicIoScenario::Read | PublicIoScenario::RecoverCommitted => {
                publisher.publish(&release)?;
            }
            PublicIoScenario::RecoverStaging
            | PublicIoScenario::RecoverNextIndex
            | PublicIoScenario::RecoverFinal => {
                let point = match scenario {
                    PublicIoScenario::RecoverStaging => PublicationFaultPointV1::ReadyWrite,
                    PublicIoScenario::RecoverNextIndex => PublicationFaultPointV1::IndexRename,
                    _ => PublicationFaultPointV1::NextIndexCreate,
                };
                assert!(publish_with_fault(&publisher, &release, point).is_err());
            }
            _ => {}
        }
        let (succeeded, calls) = with_io_fault(target, || match scenario {
            PublicIoScenario::Initialize => false,
            PublicIoScenario::Publish => publisher.publish(&release).is_ok(),
            PublicIoScenario::Read => publisher.read_verified(release.address()).is_ok(),
            PublicIoScenario::RecoverCommitted | PublicIoScenario::RecoverAbsent => {
                publisher.recover(release.address()).is_ok()
            }
            PublicIoScenario::RecoverStaging
            | PublicIoScenario::RecoverNextIndex
            | PublicIoScenario::RecoverFinal => publisher.recover_all().is_ok(),
        });
        // An error may follow the durable commit. Any release that remains
        // discoverable must nevertheless be the complete verified bundle.
        if let Ok(visible) = publisher.read_verified(release.address()) {
            assert_eq!(visible, release);
        }
        std::fs::remove_dir_all(root)?;
        Ok((succeeded, calls))
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn every_public_io_failure_keeps_partial_releases_undiscoverable(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for scenario in [
            PublicIoScenario::Initialize,
            PublicIoScenario::Publish,
            PublicIoScenario::Read,
            PublicIoScenario::RecoverCommitted,
            PublicIoScenario::RecoverAbsent,
            PublicIoScenario::RecoverStaging,
            PublicIoScenario::RecoverNextIndex,
            PublicIoScenario::RecoverFinal,
        ] {
            let (succeeded, calls) = public_io_scenario(scenario, usize::MAX)?;
            assert!(succeeded, "baseline {scenario:?}");
            assert!(
                calls > 0 && calls < 512,
                "bounded I/O inventory {scenario:?}: {calls}"
            );
            for target in 0..calls {
                let (succeeded, _) = public_io_scenario(scenario, target)?;
                assert!(!succeeded, "ignored I/O failure {scenario:?} #{target}");
            }
        }
        Ok(())
    }

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
    ) -> (Result<PublishOutcomeV1, LocalOciPublicationErrorV1>, usize) {
        reset_sync_attempts();
        PUBLICATION_FAULT.with(|fault| fault.set(Some(PublicationFaultPointV1::NthSync(target))));
        let outcome = publisher.publish(bundle);
        PUBLICATION_FAULT.with(|fault| fault.set(None));
        let calls = SYNC_ATTEMPTS.with(std::cell::Cell::get);
        reset_sync_attempts();
        (outcome, calls)
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
            assert_eq!(
                failed.err(),
                Some(LocalOciPublicationErrorV1::RecoveryRequired)
            );
            let publisher = LocalOciPublisherV1::open(&root)?;
            assert!(publisher.recover_all()?.committed.is_empty());
            std::fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn directory_read_faults_fail_closed_at_public_boundaries(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = private_root("directory-read")?;
        let publisher = LocalOciPublisherV1::open(&root)?;
        let bundle = bundle()?;
        let address = bundle.address().clone();
        assert_eq!(
            publisher.publish(&bundle)?,
            PublishOutcomeV1::Published(address.clone())
        );
        PUBLICATION_FAULT.with(|fault| fault.set(Some(PublicationFaultPointV1::DirectoryRead)));
        assert_eq!(publisher.recover_all(), Err(LocalOciPublicationErrorV1::Io));
        assert_eq!(
            publisher.read_verified(&address),
            Err(ReleaseSourceErrorV1::Io)
        );
        PUBLICATION_FAULT.with(|fault| fault.set(None));
        assert_eq!(publisher.read_verified(&address)?, bundle);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn descriptor_relative_open_and_read_faults_fail_closed_at_reader_seam(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for (point, expected) in [
            (
                PublicationFaultPointV1::OpenDirectory,
                ReleaseSourceErrorV1::InvalidLayout,
            ),
            (
                PublicationFaultPointV1::OpenPrivateFile,
                ReleaseSourceErrorV1::InvalidLayout,
            ),
            (
                PublicationFaultPointV1::ReadMetadata,
                ReleaseSourceErrorV1::Io,
            ),
            (PublicationFaultPointV1::ReadBytes, ReleaseSourceErrorV1::Io),
        ] {
            let root = private_root("reader-fault")?;
            let publisher = LocalOciPublisherV1::open(&root)?;
            let bundle = bundle()?;
            let address = bundle.address().clone();
            publisher.publish(&bundle)?;
            PUBLICATION_FAULT.with(|fault| fault.set(Some(point)));
            assert_eq!(publisher.read_verified(&address), Err(expected));
            PUBLICATION_FAULT.with(|fault| fault.set(None));
            assert_eq!(publisher.read_verified(&address)?, bundle);
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
        let baseline_root = private_root("publication-sync-inventory")?;
        let baseline = LocalOciPublisherV1::open(&baseline_root)?;
        let release = bundle()?;
        let (result, calls) = publish_with_nth_sync_fault(&baseline, &release, usize::MAX);
        assert_eq!(
            result?,
            PublishOutcomeV1::Published(release.address().clone())
        );
        assert!(calls > 0 && calls < 128);
        std::fs::remove_dir_all(baseline_root)?;
        for target in 0..calls {
            let root = private_root("publication-nth-sync")?;
            let publisher = LocalOciPublisherV1::open(&root)?;
            let bundle = bundle()?;
            let address = bundle.address().clone();
            let (result, _) = publish_with_nth_sync_fault(&publisher, &bundle, target);
            match result {
                Err(LocalOciPublicationErrorV1::OutcomeUnknown(reported)) => {
                    assert_eq!(reported, address);
                    assert_eq!(publisher.read_verified(&address)?, bundle);
                    assert_eq!(
                        publisher.recover(&address)?,
                        RecoveryOutcomeV1::Committed(address)
                    );
                }
                Err(
                    LocalOciPublicationErrorV1::Sync | LocalOciPublicationErrorV1::RecoveryRequired,
                ) => {
                    assert_eq!(
                        publisher.read_verified(&address),
                        Err(ReleaseSourceErrorV1::NotFound)
                    );
                    let recovered = publisher.recover(&address)?;
                    let expected = match recovered {
                        RecoveryOutcomeV1::Committed(reported) => {
                            assert_eq!(reported, address);
                            PublishOutcomeV1::AlreadyPublished(address)
                        }
                        RecoveryOutcomeV1::Unpublished(reported) => {
                            assert_eq!(reported, address);
                            PublishOutcomeV1::Published(address)
                        }
                    };
                    assert_eq!(publisher.publish(&bundle)?, expected);
                }
                other => return Err(format!("unexpected sync outcome #{target}: {other:?}").into()),
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
                        serde_json::json!(format!("x{}", "a".repeat(70)));
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
            LocalOciPublicationErrorV1::RecoveryRequired,
            |root| {
                std::fs::create_dir(root.join("releases").join(".first"))?;
                std::fs::create_dir(root.join("releases").join(".second"))
            },
        )?;
        recovery_rejects_shape(
            "recovery-multiple-final",
            LocalOciPublicationErrorV1::RecoveryRequired,
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
            let expected_removed_next_index = matches!(
                point,
                PublicationFaultPointV1::NextIndexWrite
                    | PublicationFaultPointV1::NextIndexSync
                    | PublicationFaultPointV1::IndexRename
            );
            assert_eq!(report.removed_next_index, expected_removed_next_index);
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

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_entrypoints_reject_untrusted_roots_and_absent_releases(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = private_root("entrypoints")?;
        let bundle = bundle()?;
        let address = bundle.address().clone();
        let publisher = LocalOciPublisherV1::open(&root)?;
        assert_eq!(
            publisher.read_verified(&address),
            Err(ReleaseSourceErrorV1::NotFound)
        );
        assert_eq!(
            publisher.recover(&address)?,
            RecoveryOutcomeV1::Unpublished(address.clone())
        );
        assert_eq!(
            publisher.publish(&bundle)?,
            PublishOutcomeV1::Published(address.clone())
        );
        assert_eq!(
            publisher.publish(&bundle)?,
            PublishOutcomeV1::AlreadyPublished(address)
        );
        std::fs::remove_dir_all(root)?;

        let path = std::env::temp_dir().join(format!(
            "pigloros-oci-untrusted-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, b"not a directory")?;
        assert!(matches!(
            LocalOciPublisherV1::open(&path),
            Err(LocalOciPublicationErrorV1::InvalidLayout)
        ));
        std::fs::remove_file(&path)?;
        std::fs::create_dir(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
        assert!(matches!(
            LocalOciPublisherV1::open(&path),
            Err(LocalOciPublicationErrorV1::InvalidLayout)
        ));
        std::fs::remove_dir_all(path)?;
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_reader_and_recovery_reject_root_index_corruption(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for (label, index, expected) in [
            (
                "index-json",
                b"[\"not an index\"]".as_slice(),
                ReleaseSourceErrorV1::InvalidLayout,
            ),
            (
                "index-version",
                b"{\"addresses\":[],\"version\":2}",
                ReleaseSourceErrorV1::InvalidLayout,
            ),
            (
                "index-addresses",
                b"{\"addresses\":{},\"version\":1}",
                ReleaseSourceErrorV1::InvalidLayout,
            ),
            (
                "index-entry",
                b"{\"addresses\":[{}],\"version\":1}",
                ReleaseSourceErrorV1::InvalidLayout,
            ),
        ] {
            let root = private_root(label)?;
            let publisher = LocalOciPublisherV1::open(&root)?;
            let address = bundle()?.address().clone();
            std::fs::write(root.join(INDEX_NAME), index)?;
            assert_eq!(publisher.read_verified(&address), Err(expected), "{label}");
            assert_eq!(
                publisher.recover(&address),
                Err(LocalOciPublicationErrorV1::InvalidLayout),
                "{label}"
            );
            assert_eq!(
                publisher.recover_all(),
                Err(LocalOciPublicationErrorV1::InvalidLayout),
                "{label}"
            );
            std::fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_recovery_quarantines_staging_that_claims_an_indexed_address(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (root, publisher, address) = published_release("indexed-staging")?;
        let nonce = "a".repeat(32);
        let staging = root
            .join(RELEASES_NAME)
            .join(format!(".{}.staging.{nonce}", &address.digest()[7..]));
        std::fs::create_dir(&staging)?;
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700))?;
        std::fs::write(
            staging.join("OWNER"),
            format!("pigloros-local-oci-staging-v1\n{nonce}\n"),
        )?;
        std::fs::set_permissions(
            staging.join("OWNER"),
            std::fs::Permissions::from_mode(0o600),
        )?;
        assert_eq!(
            publisher.recover_all(),
            Err(LocalOciPublicationErrorV1::RecoveryRequired)
        );
        let quarantine = root.join(QUARANTINE_NAME);
        let entries = std::fs::read_dir(&quarantine)?.collect::<Result<Vec<_>, _>>()?;
        assert_eq!(entries.len(), 1);
        std::fs::remove_dir_all(entries[0].path())?;
        assert!(publisher.recover_all()?.committed.is_empty());
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
