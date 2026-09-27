use std::collections::BTreeMap;
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

/// Closed failures for the Linux-local OCI publisher.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
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
}

/// The result of an immutable local publication attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublishOutcomeV1 {
    /// The release became visible at the durable root-index transition.
    Published(BundleAddressV1),
    /// An equivalent committed release already existed.
    AlreadyPublished(BundleAddressV1),
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
        create_private_directory(&root, RELEASES_NAME, owner)?;
        create_private_directory(&root, QUARANTINE_NAME, owner)?;
        create_private_file(&root, LOCK_NAME, &[], owner)?;
        create_private_file(&root, INDEX_NAME, EMPTY_INDEX, owner)?;
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
            .map_err(|_| LocalOciPublicationErrorV1::LockUnavailable)?;
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

    fn recover_locked(&self) -> Result<RecoveryReportV1, LocalOciPublicationErrorV1> {
        let quarantine = open_directory(&self.root, QUARANTINE_NAME)?;
        if directory_entries(&quarantine)?.next().is_some() {
            return Err(LocalOciPublicationErrorV1::RecoveryRequired);
        }
        let releases = open_directory(&self.root, RELEASES_NAME)?;
        let removed_staging = self.recover_staging(&releases)?;
        let removed_next_index = self.recover_next_index()?;
        let finals = directory_entries(&releases)?
            .filter(|name| !name.starts_with('.'))
            .collect::<Vec<_>>();
        if finals.len() > 256 {
            return Err(LocalOciPublicationErrorV1::BoundsExceeded);
        }
        let index = read_limited(open_private_file(&self.root, INDEX_NAME)?, 64 * 1024)
            .map_err(|_| LocalOciPublicationErrorV1::InvalidLayout)?;
        let indexed =
            parse_root_index(&index).map_err(|_| LocalOciPublicationErrorV1::InvalidLayout)?;
        let unindexed = finals
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
        let mut committed = Vec::new();
        if let Some(name) = unindexed.first() {
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
            self.publish_index(&address)?;
            committed.push(address);
        }
        Ok(RecoveryReportV1 {
            committed,
            removed_staging,
            removed_next_index,
        })
    }

    fn recover_staging(&self, releases: &File) -> Result<u8, LocalOciPublicationErrorV1> {
        let staging = directory_entries(releases)?
            .filter(|name| name.starts_with('.'))
            .collect::<Vec<_>>();
        if staging.len() > 1 {
            return Err(LocalOciPublicationErrorV1::BoundsExceeded);
        }
        if let Some(name) = staging.first() {
            let dir = open_directory(releases, name)?;
            let owner = read_limited(open_private_file(&dir, "OWNER")?, 128)
                .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
            if !owner.starts_with(b"pigloros-local-oci-staging-v1\n") {
                self.quarantine_entry(releases, name, "staging")?;
                return Err(LocalOciPublicationErrorV1::RecoveryRequired);
            }
            remove_owned_staging(releases, name)?;
            fs::fsync(releases).map_err(|_| LocalOciPublicationErrorV1::Sync)?;
            Ok(1)
        } else {
            Ok(0)
        }
    }

    fn recover_next_index(&self) -> Result<bool, LocalOciPublicationErrorV1> {
        let next = directory_entries(&self.root)?
            .filter(|name| {
                name.starts_with(".published.")
                    && Path::new(name).extension().is_some_and(|ext| ext == "next")
            })
            .collect::<Vec<_>>();
        if next.len() > 1 {
            return Err(LocalOciPublicationErrorV1::RecoveryRequired);
        }
        if let Some(name) = next.first() {
            let file = open_private_file(&self.root, name)?;
            let metadata = file
                .metadata()
                .map_err(|_| LocalOciPublicationErrorV1::Io)?;
            if !metadata.is_file()
                || metadata.uid() != self.owner
                || metadata.mode() & 0o7777 != 0o600
            {
                self.quarantine_entry(&self.root, name, "next-index")?;
                return Err(LocalOciPublicationErrorV1::RecoveryRequired);
            }
            fs::unlinkat(&self.root, name, AtFlags::empty())
                .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
            fs::fsync(&self.root).map_err(|_| LocalOciPublicationErrorV1::Sync)?;
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
        if self.read_locked(address).is_ok() {
            return Ok(PublishOutcomeV1::AlreadyPublished(address.clone()));
        }
        let releases = open_directory(&self.root, RELEASES_NAME)?;
        let staging_name = format!(
            ".{}.staging.{}",
            &address.digest()[7..],
            &address.digest()[7..39]
        );
        fs::mkdirat(&releases, &staging_name, PRIVATE_DIRECTORY_MODE)
            .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
        let staging = open_directory(&releases, &staging_name)?;
        write_private_file(
            &staging,
            "OWNER",
            format!(
                "pigloros-local-oci-staging-v1\n{}\n",
                &address.digest()[7..39]
            )
            .as_bytes(),
        )?;
        write_private_file(
            &staging,
            "oci-layout",
            b"{\"imageLayoutVersion\":\"1.0.0\"}\n",
        )?;
        let blobs = create_and_open_directory(&staging, "blobs", self.owner)?;
        let sha256 = create_and_open_directory(&blobs, "sha256", self.owner)?;
        write_private_file(&sha256, &address.digest()[7..], bundle.manifest())?;
        for blob in bundle.blobs() {
            write_private_file(&sha256, &blob.digest()[7..], blob.bytes())?;
        }
        let index = format!("{{\"manifests\":[{{\"digest\":\"{}\",\"mediaType\":\"{}\",\"size\":{}}}],\"schemaVersion\":2}}", address.digest(), address.media_type(), address.size());
        write_private_file(&staging, "index.json", index.as_bytes())?;
        fs::fsync(&sha256).map_err(|_| LocalOciPublicationErrorV1::Sync)?;
        fs::fsync(&blobs).map_err(|_| LocalOciPublicationErrorV1::Sync)?;
        let ready = format!(
            "pigloros-local-oci-ready-v1\n{}\n{}\n",
            address.digest(),
            address.size()
        );
        write_private_file(&staging, "READY", ready.as_bytes())?;
        fs::fsync(&staging).map_err(|_| LocalOciPublicationErrorV1::Sync)?;
        fs::renameat_with(
            &releases,
            &staging_name,
            &releases,
            &address.digest()[7..],
            RenameFlags::NOREPLACE,
        )
        .map_err(|_| LocalOciPublicationErrorV1::Collision)?;
        fs::fsync(&releases).map_err(|_| LocalOciPublicationErrorV1::Sync)?;
        self.publish_index(address)?;
        Ok(PublishOutcomeV1::Published(address.clone()))
    }

    fn quarantine_entry(
        &self,
        source: &File,
        name: &str,
        kind: &str,
    ) -> Result<(), LocalOciPublicationErrorV1> {
        let quarantine = open_directory(&self.root, QUARANTINE_NAME)?;
        if directory_entries(&quarantine)?.next().is_some() {
            return Err(LocalOciPublicationErrorV1::RecoveryRequired);
        }
        let destination = format!(
            "{kind}.{}",
            name.as_bytes().iter().fold(0_u64, |hash, byte| hash
                .wrapping_mul(131)
                .wrapping_add(u64::from(*byte)))
        );
        fs::renameat_with(
            source,
            name,
            &quarantine,
            &destination,
            RenameFlags::NOREPLACE,
        )
        .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
        fs::fsync(source).map_err(|_| LocalOciPublicationErrorV1::Sync)?;
        fs::fsync(&quarantine).map_err(|_| LocalOciPublicationErrorV1::Sync)?;
        fs::fsync(&self.root).map_err(|_| LocalOciPublicationErrorV1::Sync)
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
        fs::renameat_with(
            &self.root,
            &next,
            &self.root,
            INDEX_NAME,
            RenameFlags::empty(),
        )
        .map_err(|_| LocalOciPublicationErrorV1::Sync)?;
        fs::fsync(&self.root).map_err(|_| LocalOciPublicationErrorV1::Sync)
    }
}

fn remove_owned_staging(releases: &File, name: &str) -> Result<(), LocalOciPublicationErrorV1> {
    let staging = open_directory(releases, name)?;
    let mut entries = directory_entries(&staging)?.collect::<Vec<_>>();
    entries.sort();
    for required in ["OWNER", "oci-layout", "index.json", "blobs"] {
        if !entries.iter().any(|entry| entry == required) {
            return Err(LocalOciPublicationErrorV1::RecoveryRequired);
        }
    }
    if entries.len() != 4 {
        return Err(LocalOciPublicationErrorV1::RecoveryRequired);
    }
    for file in ["OWNER", "oci-layout", "index.json"] {
        fs::unlinkat(&staging, file, AtFlags::empty())
            .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
    }
    let blobs = open_directory(&staging, "blobs")?;
    let sha256 = open_directory(&blobs, "sha256")?;
    let members = directory_entries(&sha256)?.collect::<Vec<_>>();
    if members.len() > 359 {
        return Err(LocalOciPublicationErrorV1::BoundsExceeded);
    }
    for member in members {
        fs::unlinkat(&sha256, member, AtFlags::empty())
            .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
    }
    fs::unlinkat(&blobs, "sha256", AtFlags::REMOVEDIR)
        .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
    fs::unlinkat(&staging, "blobs", AtFlags::REMOVEDIR)
        .map_err(|_| LocalOciPublicationErrorV1::RecoveryRequired)?;
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
        self.verify_root().map_err(map_publication_to_source)?;
        let lock = open_private_file(&self.root, LOCK_NAME).map_err(map_publication_to_source)?;
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
        let quarantine =
            open_directory(&self.root, QUARANTINE_NAME).map_err(map_publication_to_source)?;
        if directory_entries(&quarantine)
            .map_err(map_publication_to_source)?
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
            open_private_file(&self.root, INDEX_NAME).map_err(map_publication_to_source)?,
            64 * 1024,
        )?;
        let addresses = parse_root_index(&index)?;
        let indexed = addresses.iter().any(|entry| entry == address);
        if !indexed {
            return Err(ReleaseSourceErrorV1::NotFound);
        }
        let releases =
            open_directory(&self.root, RELEASES_NAME).map_err(map_publication_to_source)?;
        let release =
            open_directory(&releases, &address.digest()[7..]).map_err(map_publication_to_source)?;
        let ready = read_limited(
            open_private_file(&release, "READY").map_err(map_publication_to_source)?,
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
        let blobs = open_directory(&release, "blobs").map_err(map_publication_to_source)?;
        let sha256 = open_directory(&blobs, "sha256").map_err(map_publication_to_source)?;
        let manifest = read_limited(
            open_private_file(&sha256, &address.digest()[7..])
                .map_err(map_publication_to_source)?,
            64 * 1024,
        )?;
        let manifest_value = crate::oci::parse_jcs_object(&manifest)?;
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
        let mut bytes = BTreeMap::new();
        for (digest, _) in descriptors {
            let hex = digest
                .strip_prefix("sha256:")
                .ok_or(ReleaseSourceErrorV1::InvalidDescriptor)?;
            let blob = read_limited(
                open_private_file(&sha256, hex).map_err(map_publication_to_source)?,
                32 * 1024 * 1024,
            )?;
            bytes.insert(digest, blob);
        }
        verify_oci_closure_v1(address.clone(), manifest, bytes)
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
    let index =
        crate::oci::parse_jcs_object(bytes).map_err(|_| ReleaseSourceErrorV1::InvalidLayout)?;
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

fn read_limited(mut file: File, limit: usize) -> Result<Vec<u8>, ReleaseSourceErrorV1> {
    let length = usize::try_from(file.metadata().map_err(|_| ReleaseSourceErrorV1::Io)?.len())
        .map_err(|_| ReleaseSourceErrorV1::BoundsExceeded)?;
    if length > limit {
        return Err(ReleaseSourceErrorV1::BoundsExceeded);
    }
    let mut bytes = Vec::with_capacity(length);
    file.read_to_end(&mut bytes)
        .map_err(|_| ReleaseSourceErrorV1::Io)?;
    if bytes.len() == length {
        Ok(bytes)
    } else {
        Err(ReleaseSourceErrorV1::Io)
    }
}

const fn map_publication_to_source(error: LocalOciPublicationErrorV1) -> ReleaseSourceErrorV1 {
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
    let mut file = fs::openat2(
        root,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        PRIVATE_FILE_MODE,
        resolution(),
    )
    .map(File::from)
    .map_err(|_| LocalOciPublicationErrorV1::Io)?;
    file.write_all(bytes)
        .map_err(|_| LocalOciPublicationErrorV1::Io)?;
    fs::fsync(&file).map_err(|_| LocalOciPublicationErrorV1::Sync)?;
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
    fs::openat2(
        root,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        resolution(),
    )
    .map(File::from)
    .map_err(|_| LocalOciPublicationErrorV1::InvalidLayout)
}

fn open_private_file(root: &File, name: &str) -> Result<File, LocalOciPublicationErrorV1> {
    fs::openat2(
        root,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        resolution(),
    )
    .map(File::from)
    .map_err(|_| LocalOciPublicationErrorV1::InvalidLayout)
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
