//! Fixed SIC1 installation metadata. Decoding is not provider admission.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

use ciborium::value::Value;
use ed25519_dalek::VerifyingKey;
use rustix::fs::{openat2, Mode, OFlags, ResolveFlags};

use super::{digest_name, ImmutableSandboxArtifact, SelectorBoundaryError, SANDBOX_ARTIFACT_ROOT};
use crate::evaluator_protocol::{
    array, array_values, decode_canonical, encode, fixed_bytes, text, uint, ProtocolError,
};

/// The administrator endpoint is never selected by evaluator input.
pub const SANDBOX_ADMIN_SOCKET: &str = "/run/pigloros/sandbox-selector-admin.sock";
const MANIFEST_NAME: &str = "installation.cbor";
const MANIFEST_LIMIT: u64 = 16 * 1024 * 1024;
const OBJECT_LIMIT: u64 = 1024 * 1024 * 1024;
const MANIFEST_DOMAIN: &[u8] = b"PiglorOS.SelectorInstallation.v1\0";

/// A closed SIC1 object role. The numeric code is the installed wire identity.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct InstallationObjectKind(u8);

impl InstallationObjectKind {
    /// Decode one of the sixteen roles defined by ADR-069.
    ///
    /// # Errors
    /// Rejects codes outside the closed SIC1 role set.
    pub const fn from_code(code: u8) -> Result<Self, ProtocolError> {
        if code <= 15 {
            Ok(Self(code))
        } else {
            Err(ProtocolError::FieldOutOfBounds)
        }
    }

    /// Exact SIC1 wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self.0
    }

    const fn directory(self) -> &'static str {
        match self.0 {
            11 => "providers",
            12 | 13 => "images",
            _ => "authority",
        }
    }

    const fn mode(self) -> u32 {
        if self.0 == 11 {
            0o500
        } else {
            0o400
        }
    }
}

/// Location metadata, not a claim that an object passes its owning verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallationObject {
    kind: InstallationObjectKind,
    identity: [u8; 32],
    content: [u8; 32],
    length: u64,
}

impl InstallationObject {
    fn decode(value: &Value) -> Result<Self, ProtocolError> {
        let fields = array(value, 4)?;
        let code = u8::try_from(uint(&fields[0])?).map_err(|_| ProtocolError::FieldOutOfBounds)?;
        let object = Self {
            kind: InstallationObjectKind::from_code(code)?,
            identity: nonzero_digest(&fields[1])?,
            content: nonzero_digest(&fields[2])?,
            length: uint(&fields[3])?,
        };
        if object.length == 0 || object.length > OBJECT_LIMIT {
            return Err(ProtocolError::FieldOutOfBounds);
        }
        // Raw-byte roles have no separate signed-record self-digest.
        if code >= 10 && object.identity != object.content {
            return Err(ProtocolError::InvalidEncoding);
        }
        Ok(object)
    }

    /// Installed object role.
    #[must_use]
    pub const fn kind(&self) -> InstallationObjectKind {
        self.kind
    }

    /// Owning contract identity, distinct from the file's content address.
    #[must_use]
    pub const fn identity(&self) -> [u8; 32] {
        self.identity
    }

    /// BLAKE3 of the complete installed file.
    #[must_use]
    pub const fn content_digest(&self) -> [u8; 32] {
        self.content
    }

    /// Exact installed file length.
    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }
}

/// Canonically decoded SIC1 metadata. This type alone grants no authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallationManifest {
    root_key_id: String,
    root_public_key: [u8; 32],
    trust_digest: [u8; 32],
    revocation_digest: [u8; 32],
    policy_digest: [u8; 32],
    execute_socket: String,
    control_socket: String,
    required_features: Vec<String>,
    objects: Vec<InstallationObject>,
    digest: [u8; 32],
}

impl InstallationManifest {
    /// Decode exact preferred-deterministic SIC1 bytes and validate their index.
    /// Root ownership, record signatures, and full admission are separate checks.
    ///
    /// # Errors
    /// Rejects malformed, oversized, noncanonical, inconsistent, or ambiguous metadata.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let document = decode_canonical(bytes)?;
        let wrapper = array(&document, 2)?;
        let fields = array(&wrapper[0], 11)?;
        if text(&fields[0])? != "SIC1" || uint(&fields[1])? != 1 {
            return Err(ProtocolError::InvalidEncoding);
        }
        let root_key_id = text(&fields[2])?;
        if root_key_id.is_empty() || root_key_id.len() > 128 {
            return Err(ProtocolError::FieldOutOfBounds);
        }
        let root_public_key = fixed_bytes(&fields[3])?;
        VerifyingKey::from_bytes(&root_public_key).map_err(|_| ProtocolError::InvalidEncoding)?;
        let execute_socket = provider_socket(&fields[7])?;
        let control_socket = provider_socket(&fields[8])?;
        if execute_socket == control_socket {
            return Err(ProtocolError::InvalidEncoding);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(MANIFEST_DOMAIN);
        hasher.update(&encode(&wrapper[0])?);
        let digest = nonzero_digest(&wrapper[1])?;
        if hasher.finalize().as_bytes() != &digest {
            return Err(ProtocolError::InvalidEncoding);
        }
        let manifest = Self {
            root_key_id: root_key_id.to_owned(),
            root_public_key,
            trust_digest: nonzero_digest(&fields[4])?,
            revocation_digest: nonzero_digest(&fields[5])?,
            policy_digest: nonzero_digest(&fields[6])?,
            execute_socket,
            control_socket,
            required_features: decode_features(&fields[9])?,
            objects: decode_objects(&fields[10])?,
            digest,
        };
        for (code, identity) in [
            (0, manifest.trust_digest),
            (1, manifest.revocation_digest),
            (2, manifest.policy_digest),
        ] {
            manifest.object(InstallationObjectKind(code), identity)?;
        }
        Ok(manifest)
    }

    /// Resolve a typed semantic identity, never a pathname or caller-chosen root.
    ///
    /// # Errors
    /// Rejects an identity absent from the installed index.
    pub fn object(
        &self,
        kind: InstallationObjectKind,
        identity: [u8; 32],
    ) -> Result<&InstallationObject, ProtocolError> {
        self.objects
            .binary_search_by_key(&(kind, identity), |entry| (entry.kind, entry.identity))
            .map(|index| &self.objects[index])
            .map_err(|_| ProtocolError::InvalidEncoding)
    }

    /// Exact SIC1 self-digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Offline root name and key pinned by this local manifest, not by TRS1.
    #[must_use]
    pub fn offline_root(&self) -> (&str, [u8; 32]) {
        (&self.root_key_id, self.root_public_key)
    }

    /// Exact TRS1, RVS1, and APT1 identities, respectively.
    #[must_use]
    pub const fn authority_digests(&self) -> [[u8; 32]; 3] {
        [
            self.trust_digest,
            self.revocation_digest,
            self.policy_digest,
        ]
    }

    /// Installed execute and control endpoints, respectively.
    #[must_use]
    pub fn provider_sockets(&self) -> (&Path, &Path) {
        (
            Path::new(&self.execute_socket),
            Path::new(&self.control_socket),
        )
    }

    /// Canonically ordered installed host-feature identifiers.
    #[must_use]
    pub fn required_features(&self) -> &[String] {
        &self.required_features
    }

    /// Typed object index in canonical order.
    #[must_use]
    pub fn objects(&self) -> &[InstallationObject] {
        &self.objects
    }
}

fn nonzero_digest(value: &Value) -> Result<[u8; 32], ProtocolError> {
    let digest = fixed_bytes(value)?;
    if digest == [0; 32] {
        Err(ProtocolError::FieldOutOfBounds)
    } else {
        Ok(digest)
    }
}

fn provider_socket(value: &Value) -> Result<String, ProtocolError> {
    let path = text(value)?;
    let tail = path
        .strip_prefix("/run/pigloros/")
        .ok_or(ProtocolError::InvalidEncoding)?;
    if path.len() > 107
        || path.contains('\0')
        || path == super::SANDBOX_SELECTOR_SOCKET
        || path == SANDBOX_ADMIN_SOCKET
        || tail
            .split('/')
            .any(|component| matches!(component, "" | "." | ".."))
    {
        return Err(ProtocolError::InvalidEncoding);
    }
    Ok(path.to_owned())
}

fn decode_features(value: &Value) -> Result<Vec<String>, ProtocolError> {
    let values = array_values(value)?;
    require_order(values)?;
    values
        .iter()
        .map(|value| text(value).map(str::to_owned))
        .collect()
}

fn require_order(values: &[Value]) -> Result<(), ProtocolError> {
    let mut previous = None;
    for value in values {
        let encoded = encode(value)?;
        if previous
            .as_ref()
            .is_some_and(|previous| previous >= &encoded)
        {
            return Err(ProtocolError::InvalidEncoding);
        }
        previous = Some(encoded);
    }
    Ok(())
}

fn decode_objects(value: &Value) -> Result<Vec<InstallationObject>, ProtocolError> {
    let values = array_values(value)?;
    if values.is_empty() {
        return Err(ProtocolError::FieldOutOfBounds);
    }
    let objects = values
        .iter()
        .map(InstallationObject::decode)
        .collect::<Result<Vec<_>, _>>()?;
    if !objects
        .windows(2)
        .all(|pair| (pair[0].kind, pair[0].identity) < (pair[1].kind, pair[1].identity))
    {
        return Err(ProtocolError::InvalidEncoding);
    }
    Ok(objects)
}

/// Held immutable installation files, not yet authenticated provider authority.
/// The only production constructor reads the fixed root-owned installation.
#[derive(Debug)]
pub struct InstalledSelectorObjects {
    manifest_file: File,
    manifest_bytes: Vec<u8>,
    manifest: InstallationManifest,
    objects: BTreeMap<(InstallationObjectKind, [u8; 32]), ImmutableSandboxArtifact>,
}

impl InstalledSelectorObjects {
    /// Open SIC1 and retain verified descriptors for all its indexed objects.
    /// The service must also process SIR1 before authenticating any admission.
    ///
    /// # Errors
    /// Rejects unsafe ancestry, non-immutable files, invalid metadata, missing
    /// objects, or incorrect content addresses. Does not expose any socket.
    pub fn open() -> Result<Self, SelectorBoundaryError> {
        let filesystem_root = File::open("/").map_err(|_| SelectorBoundaryError::Io)?;
        let root = open_directory_chain(
            filesystem_root,
            Path::new(SANDBOX_ARTIFACT_ROOT)
                .strip_prefix("/")
                .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?,
            0,
        )?;
        Self::open_at(&root, 0)
    }

    fn open_at(root: &File, owner: u32) -> Result<Self, SelectorBoundaryError> {
        validate_directory(root, owner)?;
        let mut manifest_file = open_file(root, MANIFEST_NAME, owner, 0o400, MANIFEST_LIMIT)?;
        let mut manifest_bytes = Vec::new();
        (&mut manifest_file)
            .take(MANIFEST_LIMIT + 1)
            .read_to_end(&mut manifest_bytes)
            .map_err(|_| SelectorBoundaryError::Io)?;
        let manifest = InstallationManifest::from_cbor(&manifest_bytes)
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        let mut objects = BTreeMap::new();
        for entry in manifest.objects() {
            let directory = open_directory_chain(
                root.try_clone().map_err(|_| SelectorBoundaryError::Io)?,
                Path::new(entry.kind.directory()),
                owner,
            )?;
            let mut file = open_file(
                &directory,
                &digest_name(entry.content),
                owner,
                entry.kind.mode(),
                OBJECT_LIMIT,
            )?;
            let mut hasher = blake3::Hasher::new();
            let observed = std::io::copy(&mut (&mut file).take(entry.length + 1), &mut hasher)
                .map_err(|_| SelectorBoundaryError::Io)?;
            if observed != entry.length || hasher.finalize().as_bytes() != &entry.content {
                return Err(SelectorBoundaryError::ArtifactInvalid);
            }
            file.seek(SeekFrom::Start(0))
                .map_err(|_| SelectorBoundaryError::Io)?;
            objects.insert(
                (entry.kind, entry.identity),
                ImmutableSandboxArtifact {
                    file,
                    digest: entry.content,
                    length: entry.length,
                },
            );
        }
        Ok(Self {
            manifest_file,
            manifest_bytes,
            manifest,
            objects,
        })
    }

    /// Exact retained SIC1 bytes, including its self-digest.
    #[must_use]
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    /// Metadata from the held root-owned SIC1 descriptor.
    #[must_use]
    pub const fn manifest(&self) -> &InstallationManifest {
        &self.manifest
    }

    /// Access the retained manifest descriptor for durability operations.
    #[must_use]
    pub const fn manifest_file(&self) -> &File {
        &self.manifest_file
    }

    /// Resolve an immutable descriptor. Owning semantic and signature checks
    /// remain mandatory before this object's bytes can authorize execution.
    ///
    /// # Errors
    /// Rejects an identity not installed under the requested role.
    pub fn artifact(
        &self,
        kind: InstallationObjectKind,
        identity: [u8; 32],
    ) -> Result<&ImmutableSandboxArtifact, SelectorBoundaryError> {
        self.objects
            .get(&(kind, identity))
            .ok_or(SelectorBoundaryError::ArtifactInvalid)
    }
}

fn open_directory_chain(
    mut directory: File,
    relative: &Path,
    owner: u32,
) -> Result<File, SelectorBoundaryError> {
    validate_directory(&directory, owner)?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        };
        directory = openat2(
            &directory,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map(File::from)
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        validate_directory(&directory, owner)?;
    }
    Ok(directory)
}

fn validate_directory(directory: &File, owner: u32) -> Result<(), SelectorBoundaryError> {
    let metadata = directory
        .metadata()
        .map_err(|_| SelectorBoundaryError::Io)?;
    if !metadata.is_dir() || metadata.uid() != owner || metadata.mode() & 0o022 != 0 {
        Err(SelectorBoundaryError::ArtifactInvalid)
    } else {
        Ok(())
    }
}

fn open_file(
    root: &File,
    name: &str,
    owner: u32,
    mode: u32,
    limit: u64,
) -> Result<File, SelectorBoundaryError> {
    let file = openat2(
        root,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map(File::from)
    .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    let metadata = file.metadata().map_err(|_| SelectorBoundaryError::Io)?;
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != mode
        || metadata.len() == 0
        || metadata.len() > limit
    {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    Ok(file)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
