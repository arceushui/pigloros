//! Immutable SIC1 installation state for the root-owned selector.
//!
//! This module authenticates neither a provider nor a request. It only opens
//! and retains the administrator-installed bootstrap objects that a later
//! selector composition must authenticate before exposing its evaluator socket.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

use ciborium::value::Value;
use ed25519_dalek::VerifyingKey;
use rustix::fs::{openat2, Mode, OFlags, ResolveFlags};

use super::{SelectorBoundaryError, SANDBOX_SELECTOR_SOCKET};
use crate::evaluator_protocol::{
    array, array_values, decode_canonical, encode, fixed_bytes, text, uint, ProtocolError,
};

/// The only root-owned location from which the selector can bootstrap.
pub const SANDBOX_ARTIFACT_ROOT: &str = "/var/lib/pigloros/sandbox";
/// Root-only endpoint for the separate revocation transaction.
pub const SANDBOX_ADMIN_SOCKET: &str = "/run/pigloros/sandbox-selector-admin.sock";

const MANIFEST_NAME: &str = "installation.cbor";
const MANIFEST_LIMIT: u64 = 16 * 1024 * 1024;
const OBJECT_LIMIT: u64 = 1024 * 1024 * 1024;
const MANIFEST_DOMAIN: &[u8] = b"PiglorOS.SelectorInstallation.v1\0";

/// A closed SIC1 artifact role.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct InstallationObjectKind(u8);

impl InstallationObjectKind {
    /// Decodes one of the sixteen role codes defined by ADR-069.
    ///
    /// # Errors
    /// Returns an error for an unknown role code.
    pub const fn from_code(code: u8) -> Result<Self, ProtocolError> {
        if code <= 15 {
            Ok(Self(code))
        } else {
            Err(ProtocolError::FieldOutOfBounds)
        }
    }

    /// Returns the exact SIC1 role code.
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

    const fn required_mode(self) -> u32 {
        if self.0 == 11 {
            0o500
        } else {
            0o400
        }
    }
}

/// Immutable location metadata for one SIC1 artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallationObject {
    kind: InstallationObjectKind,
    identity: [u8; 32],
    content_digest: [u8; 32],
    byte_length: u64,
}

impl InstallationObject {
    fn decode(value: &Value) -> Result<Self, ProtocolError> {
        let fields = array(value, 4)?;
        let kind = InstallationObjectKind::from_code(
            u8::try_from(uint(&fields[0])?).map_err(|_| ProtocolError::FieldOutOfBounds)?,
        )?;
        let object = Self {
            kind,
            identity: nonzero_digest(&fields[1])?,
            content_digest: nonzero_digest(&fields[2])?,
            byte_length: uint(&fields[3])?,
        };
        if object.byte_length == 0 || object.byte_length > OBJECT_LIMIT {
            return Err(ProtocolError::FieldOutOfBounds);
        }
        if object.kind.code() >= 10 && object.identity != object.content_digest {
            return Err(ProtocolError::InvalidEncoding);
        }
        Ok(object)
    }

    /// Returns the closed artifact role.
    #[must_use]
    pub const fn kind(&self) -> InstallationObjectKind {
        self.kind
    }

    /// Returns the role-specific semantic identity.
    #[must_use]
    pub const fn identity(&self) -> [u8; 32] {
        self.identity
    }

    /// Returns the BLAKE3 content address used as the filename.
    #[must_use]
    pub const fn content_digest(&self) -> [u8; 32] {
        self.content_digest
    }

    /// Returns the exact installed file size.
    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }
}

/// Decoded SIC1 bootstrap state. It grants no provider capability by itself.
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
    /// Decodes one exact preferred-deterministic SIC1 document.
    ///
    /// # Errors
    /// Returns an error for a malformed, noncanonical, inconsistent, or
    /// ambiguous bootstrap document.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.is_empty()
            || u64::try_from(bytes.len()).map_err(|_| ProtocolError::FieldOutOfBounds)?
                > MANIFEST_LIMIT
        {
            return Err(ProtocolError::FieldOutOfBounds);
        }
        let document = decode_canonical(bytes)?;
        let wrapper = array(&document, 2)?;
        let fields = array(&wrapper[0], 11)?;
        if text(&fields[0])? != "SIC1" || uint(&fields[1])? != 1 {
            return Err(ProtocolError::UnsupportedVersion);
        }
        let root_key_id = text(&fields[2])?;
        if root_key_id.is_empty() || root_key_id.len() > 128 {
            return Err(ProtocolError::FieldOutOfBounds);
        }
        let root_public_key = fixed_bytes(&fields[3])?;
        VerifyingKey::from_bytes(&root_public_key).map_err(|_| ProtocolError::InvalidEncoding)?;
        let digest = nonzero_digest(&wrapper[1])?;
        if manifest_digest(&wrapper[0])? != digest {
            return Err(ProtocolError::DigestMismatch);
        }
        let manifest = Self {
            root_key_id: root_key_id.to_owned(),
            root_public_key,
            trust_digest: nonzero_digest(&fields[4])?,
            revocation_digest: nonzero_digest(&fields[5])?,
            policy_digest: nonzero_digest(&fields[6])?,
            execute_socket: provider_socket(&fields[7])?,
            control_socket: provider_socket(&fields[8])?,
            required_features: ordered_texts(&fields[9])?,
            objects: ordered_objects(&fields[10])?,
            digest,
        };
        if manifest.execute_socket == manifest.control_socket {
            return Err(ProtocolError::InvalidEncoding);
        }
        for (kind, identity) in [
            (InstallationObjectKind(0), manifest.trust_digest),
            (InstallationObjectKind(1), manifest.revocation_digest),
            (InstallationObjectKind(2), manifest.policy_digest),
        ] {
            manifest.object(kind, identity)?;
        }
        Ok(manifest)
    }

    /// Returns the offline root identity and public key pinned by SIC1.
    #[must_use]
    pub fn offline_root(&self) -> (&str, [u8; 32]) {
        (&self.root_key_id, self.root_public_key)
    }

    /// Returns the selected TRS1, RVS1, and APT1 identities.
    #[must_use]
    pub const fn authority_digests(&self) -> [[u8; 32]; 3] {
        [
            self.trust_digest,
            self.revocation_digest,
            self.policy_digest,
        ]
    }

    /// Returns the fixed provider execute and control endpoint paths.
    #[must_use]
    pub fn provider_sockets(&self) -> (&Path, &Path) {
        (
            Path::new(&self.execute_socket),
            Path::new(&self.control_socket),
        )
    }

    /// Returns the canonical required host feature identifiers.
    #[must_use]
    pub fn required_features(&self) -> &[String] {
        &self.required_features
    }

    /// Returns the closed, ordered SIC1 index.
    #[must_use]
    pub fn objects(&self) -> &[InstallationObject] {
        &self.objects
    }

    /// Returns SIC1's self-digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Resolves one typed installed object, never a caller-selected path.
    ///
    /// # Errors
    /// Returns an error when the object is absent.
    pub fn object(
        &self,
        kind: InstallationObjectKind,
        identity: [u8; 32],
    ) -> Result<&InstallationObject, ProtocolError> {
        self.objects
            .binary_search_by_key(&(kind, identity), |object| (object.kind, object.identity))
            .map(|index| &self.objects[index])
            .map_err(|_| ProtocolError::InvalidEncoding)
    }
}

/// A held descriptor for an immutable SIC1 artifact.
#[derive(Debug)]
pub struct HeldInstallationArtifact {
    file: File,
    object: InstallationObject,
}

impl HeldInstallationArtifact {
    /// Borrows the retained descriptor. Callers must not reopen by path.
    #[must_use]
    pub const fn file(&self) -> &File {
        &self.file
    }

    /// Returns the verified typed index entry for this descriptor.
    #[must_use]
    pub const fn object(&self) -> &InstallationObject {
        &self.object
    }

    /// Reads one bounded control artifact from its retained descriptor.
    ///
    /// # Errors
    /// Returns an error if the caller's bound does not cover the indexed file
    /// or the retained descriptor cannot be read exactly.
    pub fn read_control(&self, maximum: u64) -> Result<Vec<u8>, SelectorBoundaryError> {
        if self.object.byte_length > maximum {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        let capacity = usize::try_from(self.object.byte_length)
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        let mut file = self
            .file
            .try_clone()
            .map_err(|_| SelectorBoundaryError::Io)?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| SelectorBoundaryError::Io)?;
        let mut bytes = Vec::with_capacity(capacity);
        file.take(self.object.byte_length + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| SelectorBoundaryError::Io)?;
        if bytes.len() != capacity {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        Ok(bytes)
    }
}

/// Retained root-owned SIC1 and all of its verified immutable descriptors.
#[derive(Debug)]
pub struct InstalledSelectorState {
    manifest_file: File,
    manifest_bytes: Vec<u8>,
    manifest: InstallationManifest,
    artifacts: BTreeMap<(InstallationObjectKind, [u8; 32]), HeldInstallationArtifact>,
}

impl InstalledSelectorState {
    /// Opens the one fixed root-owned installation state.
    ///
    /// # Errors
    /// Returns an error for unsafe ancestry, links, ownership, permissions,
    /// canonical SIC1 failures, missing indexed objects, or content mismatch.
    pub fn open() -> Result<Self, SelectorBoundaryError> {
        let filesystem_root = File::open("/").map_err(|_| SelectorBoundaryError::Io)?;
        let artifact_root = open_directory_chain(
            filesystem_root,
            Path::new(SANDBOX_ARTIFACT_ROOT)
                .strip_prefix("/")
                .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?,
        )?;
        Self::open_at(&artifact_root)
    }

    fn open_at(root: &File) -> Result<Self, SelectorBoundaryError> {
        validate_directory(root)?;
        let manifest_file = open_immutable_file(root, MANIFEST_NAME, 0o400, MANIFEST_LIMIT)?;
        let manifest_bytes = read_complete_file(&manifest_file, MANIFEST_LIMIT)?;
        let manifest = InstallationManifest::from_canonical_cbor(&manifest_bytes)
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        let mut artifacts = BTreeMap::new();
        for object in manifest.objects() {
            let directory = open_directory_chain(
                root.try_clone().map_err(|_| SelectorBoundaryError::Io)?,
                Path::new(object.kind.directory()),
            )?;
            let file = open_immutable_file(
                &directory,
                &hex_name(object.content_digest),
                object.kind.required_mode(),
                object.byte_length,
            )?;
            if digest_complete_file(&file, object.byte_length)? != object.content_digest {
                return Err(SelectorBoundaryError::ArtifactInvalid);
            }
            artifacts.insert(
                (object.kind, object.identity),
                HeldInstallationArtifact {
                    file,
                    object: object.clone(),
                },
            );
        }
        Ok(Self {
            manifest_file,
            manifest_bytes,
            manifest,
            artifacts,
        })
    }

    /// Returns the retained manifest descriptor.
    #[must_use]
    pub const fn manifest_file(&self) -> &File {
        &self.manifest_file
    }

    /// Returns SIC1's original canonical bytes.
    #[must_use]
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    /// Returns the decoded manifest attached to the retained descriptor.
    #[must_use]
    pub const fn manifest(&self) -> &InstallationManifest {
        &self.manifest
    }

    /// Returns an immutable typed descriptor from the verified index.
    ///
    /// # Errors
    /// Returns an error when the requested identity is not in this SIC1 state.
    pub fn artifact(
        &self,
        kind: InstallationObjectKind,
        identity: [u8; 32],
    ) -> Result<&HeldInstallationArtifact, SelectorBoundaryError> {
        self.artifacts
            .get(&(kind, identity))
            .ok_or(SelectorBoundaryError::ArtifactInvalid)
    }
}

fn manifest_digest(unsigned: &Value) -> Result<[u8; 32], ProtocolError> {
    let bytes = encode(unsigned)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(MANIFEST_DOMAIN);
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
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
    let Some(tail) = path.strip_prefix("/run/pigloros/") else {
        return Err(ProtocolError::InvalidEncoding);
    };
    if path.len() > 107
        || path.contains('\0')
        || matches!(path, SANDBOX_SELECTOR_SOCKET | SANDBOX_ADMIN_SOCKET)
        || tail.split('/').any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(ProtocolError::InvalidEncoding);
    }
    Ok(path.to_owned())
}

fn ordered_texts(value: &Value) -> Result<Vec<String>, ProtocolError> {
    let values = array_values(value)?;
    require_preferred_order(values)?;
    values
        .iter()
        .map(|value| text(value).map(str::to_owned))
        .collect()
}

fn ordered_objects(value: &Value) -> Result<Vec<InstallationObject>, ProtocolError> {
    let values = array_values(value)?;
    if values.is_empty() || values.len() > 65_536 {
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
        return Err(ProtocolError::NonCanonicalOrder);
    }
    Ok(objects)
}

fn require_preferred_order(values: &[Value]) -> Result<(), ProtocolError> {
    let mut previous = None;
    for value in values {
        let encoded = encode(value)?;
        if previous
            .as_ref()
            .is_some_and(|previous| previous >= &encoded)
        {
            return Err(ProtocolError::NonCanonicalOrder);
        }
        previous = Some(encoded);
    }
    Ok(())
}

fn open_directory_chain(
    mut directory: File,
    relative: &Path,
) -> Result<File, SelectorBoundaryError> {
    validate_directory(&directory)?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        };
        directory = openat2(
            &directory,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH
                .union(ResolveFlags::NO_SYMLINKS)
                .union(ResolveFlags::NO_MAGICLINKS),
        )
        .map(File::from)
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        validate_directory(&directory)?;
    }
    Ok(directory)
}

fn validate_directory(directory: &File) -> Result<(), SelectorBoundaryError> {
    let metadata = directory
        .metadata()
        .map_err(|_| SelectorBoundaryError::Io)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    Ok(())
}

fn open_immutable_file(
    directory: &File,
    name: &str,
    required_mode: u32,
    maximum: u64,
) -> Result<File, SelectorBoundaryError> {
    let file = openat2(
        directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH
            .union(ResolveFlags::NO_SYMLINKS)
            .union(ResolveFlags::NO_MAGICLINKS),
    )
    .map(File::from)
    .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    let metadata = file.metadata().map_err(|_| SelectorBoundaryError::Io)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != required_mode
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    Ok(file)
}

fn read_complete_file(file: &File, maximum: u64) -> Result<Vec<u8>, SelectorBoundaryError> {
    let metadata = file.metadata().map_err(|_| SelectorBoundaryError::Io)?;
    let capacity =
        usize::try_from(metadata.len()).map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    let mut reader = file.try_clone().map_err(|_| SelectorBoundaryError::Io)?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|_| SelectorBoundaryError::Io)?;
    let mut bytes = Vec::with_capacity(capacity);
    reader
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| SelectorBoundaryError::Io)?;
    if bytes.len() != capacity {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    Ok(bytes)
}

fn digest_complete_file(
    file: &File,
    expected_length: u64,
) -> Result<[u8; 32], SelectorBoundaryError> {
    let mut reader = file.try_clone().map_err(|_| SelectorBoundaryError::Io)?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|_| SelectorBoundaryError::Io)?;
    let mut remaining = expected_length;
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut hasher = blake3::Hasher::new();
    while remaining != 0 {
        let maximum = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        let read = reader
            .read(&mut buffer[..maximum])
            .map_err(|_| SelectorBoundaryError::Io)?;
        if read == 0 {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        hasher.update(&buffer[..read]);
        remaining = remaining
            .checked_sub(read as u64)
            .ok_or(SelectorBoundaryError::ArtifactInvalid)?;
    }
    let mut extra = [0_u8; 1];
    if reader
        .read(&mut extra)
        .map_err(|_| SelectorBoundaryError::Io)?
        != 0
    {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn hex_name(digest: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::with_capacity(64);
    for byte in digest {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    name
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};

    use ciborium::value::Value;
    use ed25519_dalek::SigningKey;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn integer(value: u64) -> Value {
        Value::Integer(value.into())
    }

    fn digest(value: [u8; 32]) -> Value {
        Value::Bytes(value.to_vec())
    }

    fn object(kind: u8, content: [u8; 32], length: u64) -> Value {
        let identity = if kind < 10 { [kind + 1; 32] } else { content };
        Value::Array(vec![
            integer(u64::from(kind)),
            digest(identity),
            digest(content),
            integer(length),
        ])
    }

    fn unsigned(objects: Vec<Value>) -> Vec<Value> {
        vec![
            Value::Text("SIC1".to_owned()),
            integer(1),
            Value::Text("offline-root".to_owned()),
            digest(SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes()),
            digest([1; 32]),
            digest([2; 32]),
            digest([3; 32]),
            Value::Text("/run/pigloros/provider-execute.sock".to_owned()),
            Value::Text("/run/pigloros/provider-control.sock".to_owned()),
            Value::Array(vec![
                Value::Text("a".to_owned()),
                Value::Text("b".to_owned()),
            ]),
            Value::Array(objects),
        ]
    }

    fn encode_manifest(fields: Vec<Value>) -> Result<Vec<u8>, ProtocolError> {
        let unsigned = Value::Array(fields);
        let digest = manifest_digest(&unsigned)?;
        encode(&Value::Array(vec![unsigned, Value::Bytes(digest.to_vec())]))
    }

    fn valid_objects() -> Vec<Value> {
        (0_u8..16)
            .map(|kind| {
                let bytes = [kind + 1; 3];
                object(kind, *blake3::hash(&bytes).as_bytes(), bytes.len() as u64)
            })
            .collect()
    }

    #[test]
    fn decodes_closed_canonical_manifest() -> TestResult {
        let manifest = InstallationManifest::from_canonical_cbor(&encode_manifest(unsigned(
            valid_objects(),
        ))?)?;
        assert_eq!(manifest.offline_root().0, "offline-root");
        assert_eq!(manifest.authority_digests(), [[1; 32], [2; 32], [3; 32]]);
        assert_eq!(manifest.required_features(), ["a", "b"]);
        assert_eq!(manifest.objects().len(), 16);
        assert_eq!(
            manifest.provider_sockets(),
            (
                Path::new("/run/pigloros/provider-execute.sock"),
                Path::new("/run/pigloros/provider-control.sock")
            )
        );
        for kind in 0_u8..16 {
            let kind = InstallationObjectKind::from_code(kind)?;
            let content = *blake3::hash(&[kind.code() + 1; 3]).as_bytes();
            let identity = if kind.code() < 10 {
                [kind.code() + 1; 32]
            } else {
                content
            };
            let entry = manifest.object(kind, identity)?;
            assert_eq!(entry.kind(), kind);
            assert_eq!(entry.content_digest(), content);
            assert_eq!(entry.byte_length(), 3);
            assert!(manifest.object(kind, [0; 32]).is_err());
        }
        assert!(InstallationObjectKind::from_code(16).is_err());
        Ok(())
    }

    #[test]
    fn rejects_noncanonical_or_ambiguous_manifest_values() -> TestResult {
        let encoded = encode_manifest(unsigned(valid_objects()))?;
        for end in 0..encoded.len() {
            assert!(InstallationManifest::from_canonical_cbor(&encoded[..end]).is_err());
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert!(InstallationManifest::from_canonical_cbor(&trailing).is_err());
        for (field, value) in [
            (0, Value::Text("SIC2".to_owned())),
            (1, integer(2)),
            (2, Value::Text(String::new())),
            (4, digest([0; 32])),
            (7, Value::Text(SANDBOX_SELECTOR_SOCKET.to_owned())),
            (8, Value::Text(SANDBOX_ADMIN_SOCKET.to_owned())),
            (
                9,
                Value::Array(vec![
                    Value::Text("b".to_owned()),
                    Value::Text("a".to_owned()),
                ]),
            ),
        ] {
            let mut fields = unsigned(valid_objects());
            fields[field] = value;
            assert!(InstallationManifest::from_canonical_cbor(&encode_manifest(fields)?).is_err());
        }
        let mut duplicate = valid_objects();
        duplicate[1] = duplicate[0].clone();
        assert!(
            InstallationManifest::from_canonical_cbor(&encode_manifest(unsigned(duplicate))?)
                .is_err()
        );
        let mut unsafe_socket = unsigned(valid_objects());
        unsafe_socket[7] = Value::Text("/run/pigloros/../provider.sock".to_owned());
        assert!(
            InstallationManifest::from_canonical_cbor(&encode_manifest(unsafe_socket)?).is_err()
        );
        Ok(())
    }

    fn write_state(root: &Path) -> TestResult {
        for directory in ["authority", "providers", "images"] {
            let path = root.join(directory);
            fs::create_dir(&path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        let objects = valid_objects();
        for kind in 0_u8..16 {
            let bytes = [kind + 1; 3];
            let digest = *blake3::hash(&bytes).as_bytes();
            let directory = InstallationObjectKind::from_code(kind)?.directory();
            let path = root.join(directory).join(hex_name(digest));
            fs::write(&path, bytes)?;
            fs::set_permissions(
                path,
                fs::Permissions::from_mode(
                    InstallationObjectKind::from_code(kind)?.required_mode(),
                ),
            )?;
        }
        let manifest_path = root.join(MANIFEST_NAME);
        fs::write(&manifest_path, encode_manifest(unsigned(objects))?)?;
        fs::set_permissions(manifest_path, fs::Permissions::from_mode(0o400))?;
        Ok(())
    }

    #[test]
    fn opens_only_verified_held_descriptors() -> TestResult {
        let temporary = tempfile::tempdir()?;
        write_state(temporary.path())?;
        let root = File::open(temporary.path())?;
        let state = InstalledSelectorState::open_at(&root)?;
        assert!(!state.manifest_bytes().is_empty());
        assert!(state.manifest_file().metadata()?.is_file());
        let authority = state.artifact(InstallationObjectKind::from_code(0)?, [1; 32])?;
        assert_eq!(authority.read_control(3)?, [1; 3]);
        assert!(authority.read_control(2).is_err());
        assert!(state
            .artifact(InstallationObjectKind::from_code(0)?, [0; 32])
            .is_err());
        Ok(())
    }

    #[test]
    fn rejects_mutable_or_linked_installed_state() -> TestResult {
        let temporary = tempfile::tempdir()?;
        write_state(temporary.path())?;
        let content = *blake3::hash(&[1; 3]).as_bytes();
        let source = temporary.path().join("authority").join(hex_name(content));
        let linked = temporary.path().join("authority").join("linked");
        fs::hard_link(&source, &linked)?;
        let root = File::open(temporary.path())?;
        assert!(InstalledSelectorState::open_at(&root).is_err());
        fs::remove_file(linked)?;
        fs::remove_file(&source)?;
        symlink("elsewhere", &source)?;
        assert!(InstalledSelectorState::open_at(&root).is_err());
        Ok(())
    }

    #[test]
    fn stream_digest_detects_short_and_extended_files() -> TestResult {
        let temporary = tempfile::NamedTempFile::new()?;
        fs::write(temporary.path(), [9; 4])?;
        let file = File::open(temporary.path())?;
        assert!(digest_complete_file(&file, 3).is_err());
        assert!(digest_complete_file(&file, 5).is_err());
        assert_eq!(
            digest_complete_file(&file, 4)?,
            *blake3::hash(&[9; 4]).as_bytes()
        );
        Ok(())
    }
}
