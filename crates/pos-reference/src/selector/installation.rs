//! Immutable SIC1 installation state for the root-owned selector.
//!
//! This module authenticates neither a provider nor a request. It only opens
//! and retains the administrator-installed bootstrap objects that a later
//! selector composition must authenticate before exposing its evaluator socket.

pub mod authority;
mod cases;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

use ciborium::value::Value;
use ed25519_dalek::VerifyingKey;
use rustix::fs::{openat2, statat, AtFlags, Mode, OFlags, ResolveFlags};

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

/// A canonical case reconstructed only from authenticated SIC1 descriptors.
///
/// The root-selector composition retains this type inside the crate. It never
/// accepts a caller-provided archive, artifact path, or compatibility fallback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedInstalledCase {
    attempt: crate::evaluator::CaseAttempt,
    fixture_contract_digest: [u8; 32],
    profile_digest: [u8; 32],
    bundle_digest: [u8; 32],
}

impl ResolvedInstalledCase {
    /// Returns the exact ordinal attempt rebuilt from the verified CFB1 closure.
    #[must_use]
    pub(crate) const fn attempt(&self) -> &crate::evaluator::CaseAttempt {
        &self.attempt
    }

    /// Returns the CPF1 `FixtureContract` binding for this attempt.
    #[must_use]
    pub(crate) const fn fixture_contract_digest(&self) -> [u8; 32] {
        self.fixture_contract_digest
    }

    /// Returns the verified CPF1 identity.
    #[must_use]
    pub(crate) const fn profile_digest(&self) -> [u8; 32] {
        self.profile_digest
    }

    /// Returns the complete verified CFB1 identity.
    #[must_use]
    pub(crate) const fn bundle_digest(&self) -> [u8; 32] {
        self.bundle_digest
    }
}

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
            required_features: required_host_features(&fields[9])?,
            objects: ordered_objects(&fields[10])?,
            digest,
        };
        if manifest.execute_socket == manifest.control_socket
            || !manifest
                .required_features
                .iter()
                .map(String::as_str)
                .eq(crate::sandbox_provider_protocol::REQUIRED_HOST_FEATURES)
        {
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
        usize::try_from(self.object.byte_length)
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)
            .and_then(|capacity| {
                self.file
                    .try_clone()
                    .map_err(|_| SelectorBoundaryError::Io)
                    .and_then(rewind)
                    .and_then(|file| read_exact_file(file, self.object.byte_length + 1, capacity))
            })
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
        File::open("/")
            .map_err(|_| SelectorBoundaryError::Io)
            .and_then(|filesystem_root| {
                Path::new(SANDBOX_ARTIFACT_ROOT)
                    .strip_prefix("/")
                    .map_err(|_| SelectorBoundaryError::ArtifactInvalid)
                    .and_then(|relative| open_directory_chain(filesystem_root, relative, 0))
            })
            .and_then(|artifact_root| Self::open_at(&artifact_root))
    }

    fn open_at(root: &File) -> Result<Self, SelectorBoundaryError> {
        Self::open_at_for_owner(root, 0)
    }

    fn open_at_for_owner(root: &File, expected_owner: u32) -> Result<Self, SelectorBoundaryError> {
        validate_directory(root, expected_owner)
            .and_then(|()| ensure_no_pending_recovery(root))
            .and_then(|()| {
                open_immutable_file(root, MANIFEST_NAME, 0o400, MANIFEST_LIMIT, expected_owner)
            })
            .and_then(|manifest_file| {
                read_complete_file(&manifest_file, MANIFEST_LIMIT).and_then(|manifest_bytes| {
                    InstallationManifest::from_canonical_cbor(&manifest_bytes)
                        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)
                        .and_then(|manifest| {
                            open_indexed_artifacts(root, &manifest, expected_owner).map(
                                |artifacts| Self {
                                    manifest_file,
                                    manifest_bytes,
                                    manifest,
                                    artifacts,
                                },
                            )
                        })
                })
            })
    }

    #[cfg(test)]
    fn open_at_for_test(root: &File) -> Result<Self, SelectorBoundaryError> {
        root.metadata()
            .map_err(|_| SelectorBoundaryError::Io)
            .and_then(|metadata| Self::open_at_for_owner(root, metadata.uid()))
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

fn open_indexed_artifacts(
    root: &File,
    manifest: &InstallationManifest,
    expected_owner: u32,
) -> Result<
    BTreeMap<(InstallationObjectKind, [u8; 32]), HeldInstallationArtifact>,
    SelectorBoundaryError,
> {
    manifest
        .objects()
        .iter()
        .try_fold(BTreeMap::new(), |mut artifacts, object| {
            root.try_clone()
                .map_err(|_| SelectorBoundaryError::Io)
                .and_then(|directory_root| {
                    open_directory_chain(
                        directory_root,
                        Path::new(object.kind.directory()),
                        expected_owner,
                    )
                })
                .and_then(|directory| {
                    open_immutable_file(
                        &directory,
                        &hex_name(object.content_digest),
                        object.kind.required_mode(),
                        object.byte_length,
                        expected_owner,
                    )
                })
                .and_then(|file| {
                    digest_complete_file(&file, object.byte_length).and_then(|digest| {
                        if digest == object.content_digest {
                            artifacts.insert(
                                (object.kind, object.identity),
                                HeldInstallationArtifact {
                                    file,
                                    object: object.clone(),
                                },
                            );
                            Ok(artifacts)
                        } else {
                            Err(SelectorBoundaryError::ArtifactInvalid)
                        }
                    })
                })
        })
}

fn ensure_no_pending_recovery(root: &File) -> Result<(), SelectorBoundaryError> {
    match statat(root, "installation-update.cbor", AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(()),
        _ => Err(SelectorBoundaryError::ArtifactInvalid),
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

fn required_host_features(value: &Value) -> Result<Vec<String>, ProtocolError> {
    let values = array_values(value)?;
    let features = values
        .iter()
        .map(|value| text(value).map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    if !features
        .iter()
        .map(String::as_str)
        .eq(crate::sandbox_provider_protocol::REQUIRED_HOST_FEATURES)
    {
        return Err(ProtocolError::InvalidEncoding);
    }
    Ok(features)
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

/// Open one root-owned relative directory chain without following links.
///
/// This is crate-private because selector composition alone may validate the
/// fixed SIC1-owned provider endpoint beneath the retained installation root.
pub(crate) fn open_directory_chain(
    mut directory: File,
    relative: &Path,
    expected_owner: u32,
) -> Result<File, SelectorBoundaryError> {
    validate_directory(&directory, expected_owner)?;
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
        validate_directory(&directory, expected_owner)?;
    }
    Ok(directory)
}

fn validate_directory(directory: &File, expected_owner: u32) -> Result<(), SelectorBoundaryError> {
    directory
        .metadata()
        .map_err(|_| SelectorBoundaryError::Io)
        .and_then(|metadata| {
            if !metadata.is_dir()
                || metadata.uid() != expected_owner
                || metadata.mode() & 0o022 != 0
            {
                Err(SelectorBoundaryError::ArtifactInvalid)
            } else {
                Ok(())
            }
        })
}

fn open_immutable_file(
    directory: &File,
    name: &str,
    required_mode: u32,
    maximum: u64,
    expected_owner: u32,
) -> Result<File, SelectorBoundaryError> {
    openat2(
        directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH
            .union(ResolveFlags::NO_SYMLINKS)
            .union(ResolveFlags::NO_MAGICLINKS),
    )
    .map(File::from)
    .map_err(|_| SelectorBoundaryError::ArtifactInvalid)
    .and_then(|file| {
        file.metadata()
            .map_err(|_| SelectorBoundaryError::Io)
            .and_then(|metadata| {
                if !metadata.is_file()
                    || metadata.uid() != expected_owner
                    || metadata.nlink() != 1
                    || metadata.mode() & 0o7777 != required_mode
                    || metadata.len() == 0
                    || metadata.len() > maximum
                {
                    Err(SelectorBoundaryError::ArtifactInvalid)
                } else {
                    Ok(file)
                }
            })
    })
}

fn read_complete_file(file: &File, maximum: u64) -> Result<Vec<u8>, SelectorBoundaryError> {
    file.metadata()
        .map_err(|_| SelectorBoundaryError::Io)
        .and_then(|metadata| {
            usize::try_from(metadata.len()).map_err(|_| SelectorBoundaryError::ArtifactInvalid)
        })
        .and_then(|capacity| {
            file.try_clone()
                .map_err(|_| SelectorBoundaryError::Io)
                .and_then(rewind)
                .and_then(|file| read_exact_file(file, maximum + 1, capacity))
        })
}

fn rewind(mut file: File) -> Result<File, SelectorBoundaryError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| SelectorBoundaryError::Io)
        .map(|_| file)
}

fn read_exact_file(
    file: File,
    maximum: u64,
    capacity: usize,
) -> Result<Vec<u8>, SelectorBoundaryError> {
    let mut bytes = Vec::with_capacity(capacity);
    file.take(maximum)
        .read_to_end(&mut bytes)
        .map_err(|_| SelectorBoundaryError::Io)
        .and({
            if bytes.len() == capacity {
                Ok(bytes)
            } else {
                Err(SelectorBoundaryError::ArtifactInvalid)
            }
        })
}

fn digest_complete_file(
    file: &File,
    expected_length: u64,
) -> Result<[u8; 32], SelectorBoundaryError> {
    file.try_clone()
        .map_err(|_| SelectorBoundaryError::Io)
        .and_then(rewind)
        .and_then(|file| digest_reader(file, expected_length))
}

fn digest_reader(
    mut reader: File,
    expected_length: u64,
) -> Result<[u8; 32], SelectorBoundaryError> {
    let mut remaining = expected_length;
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut hasher = blake3::Hasher::new();
    while remaining != 0 {
        let maximum = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let Ok(read) = reader.read(&mut buffer[..maximum]) else {
            return Err(SelectorBoundaryError::Io);
        };
        if read == 0 {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        hasher.update(&buffer[..read]);
        remaining -= read as u64;
    }
    let mut extra = [0_u8; 1];
    match reader.read(&mut extra) {
        Ok(0) => Ok(*hasher.finalize().as_bytes()),
        Ok(_) => Err(SelectorBoundaryError::ArtifactInvalid),
        Err(_) => Err(SelectorBoundaryError::Io),
    }
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
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::{symlink, PermissionsExt};

    use ciborium::value::Value;
    use ed25519_dalek::{Signer, SigningKey};

    use crate::evaluator_protocol::{EvaluationRequest, SubjectAdapterKind};

    use super::authority::AuthenticatedSelectorBootstrap;
    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

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
            required_features_value(),
            Value::Array(objects),
        ]
    }

    fn required_features_value() -> Value {
        Value::Array(
            crate::sandbox_provider_protocol::REQUIRED_HOST_FEATURES
                .iter()
                .map(|feature| Value::Text((*feature).to_owned()))
                .collect(),
        )
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

    fn sign_record(magic: &str, unsigned: Value, signer: &SigningKey) -> TestResult<Vec<u8>> {
        let mut digest = blake3::Hasher::new();
        digest.update(format!("PiglorOS.{magic}.v1\0").as_bytes());
        digest.update(&encode(&unsigned)?);
        let digest = digest.finalize();
        let mut message = format!("PiglorOS.{magic}.Signature.v1\0").into_bytes();
        message.extend_from_slice(digest.as_bytes());
        Ok(encode(&Value::Array(vec![
            unsigned,
            Value::Bytes(digest.as_bytes().to_vec()),
            Value::Bytes(signer.sign(&message).to_bytes().to_vec()),
        ]))?)
    }

    fn signed_record_digest(bytes: &[u8]) -> TestResult<[u8; 32]> {
        let value: Value = ciborium::from_reader(bytes)?;
        let Value::Array(wrapper) = value else {
            return Err("signed record wrapper is not an array".into());
        };
        let Value::Bytes(digest) = wrapper.get(1).ok_or("signed record digest missing")? else {
            return Err("signed record digest is not bytes".into());
        };
        Ok(digest.as_slice().try_into()?)
    }

    fn held_artifact(
        kind: u8,
        identity: [u8; 32],
        bytes: &[u8],
    ) -> TestResult<HeldInstallationArtifact> {
        let mut file = tempfile::NamedTempFile::new()?;
        file.write_all(bytes)?;
        Ok(HeldInstallationArtifact {
            file: file.into_file(),
            object: InstallationObject {
                kind: InstallationObjectKind::from_code(kind)?,
                identity,
                content_digest: *blake3::hash(bytes).as_bytes(),
                byte_length: bytes.len().try_into()?,
            },
        })
    }

    fn authenticated_state() -> TestResult<InstalledSelectorState> {
        let root = SigningKey::from_bytes(&[1; 32]);
        let policy_signer = SigningKey::from_bytes(&[2; 32]);
        let trust_bytes = sign_record(
            "TRS1",
            Value::Array(vec![
                Value::Text("TRS1".to_owned()),
                integer(1),
                integer(1),
                Value::Array(vec![Value::Array(vec![
                    Value::Text("policy".to_owned()),
                    integer(1),
                    Value::Bytes(policy_signer.verifying_key().to_bytes().to_vec()),
                    integer(1),
                ])]),
                Value::Array(Vec::new()),
                Value::Text("root".to_owned()),
            ]),
            &root,
        )?;
        let trust_digest = signed_record_digest(&trust_bytes)?;
        let revocation_bytes = sign_record(
            "RVS1",
            Value::Array(vec![
                Value::Text("RVS1".to_owned()),
                integer(1),
                Value::Bytes(trust_digest.to_vec()),
                integer(1),
                Value::Array(Vec::new()),
                Value::Array(Vec::new()),
                Value::Array(Vec::new()),
                Value::Text("policy".to_owned()),
            ]),
            &policy_signer,
        )?;
        let revocation_digest = signed_record_digest(&revocation_bytes)?;
        let provider_binary = *blake3::hash(b"provider-binary").as_bytes();
        let hard_caps = *blake3::hash(b"hard-caps").as_bytes();
        let policy_bytes = sign_record(
            "APT1",
            Value::Array(vec![
                Value::Text("APT1".to_owned()),
                integer(1),
                integer(1),
                Value::Bytes(vec![10; 32]),
                Value::Bytes(provider_binary.to_vec()),
                Value::Array(Vec::new()),
                Value::Array(Vec::new()),
                Value::Bytes(hard_caps.to_vec()),
                Value::Bytes(vec![15; 32]),
                Value::Bytes(vec![16; 32]),
                Value::Bytes(trust_digest.to_vec()),
                Value::Bytes(revocation_digest.to_vec()),
                integer(1),
                integer(1),
                Value::Bytes(vec![17; 32]),
                Value::Text("policy".to_owned()),
            ]),
            &policy_signer,
        )?;
        let policy_digest = signed_record_digest(&policy_bytes)?;
        let artifacts = [
            (0, trust_digest, trust_bytes.as_slice()),
            (1, revocation_digest, revocation_bytes.as_slice()),
            (2, policy_digest, policy_bytes.as_slice()),
            (3, [10; 32], b"provider-manifest".as_slice()),
            (11, provider_binary, b"provider-binary".as_slice()),
            (10, hard_caps, b"hard-caps".as_slice()),
            (5, [15; 32], b"conformance-profile".as_slice()),
            (4, [16; 32], b"conformance-report".as_slice()),
            (7, [17; 32], b"syscall-set".as_slice()),
        ];
        let mut installed = BTreeMap::new();
        for (kind, identity, bytes) in artifacts {
            let artifact = held_artifact(kind, identity, bytes)?;
            installed.insert((artifact.object.kind, artifact.object.identity), artifact);
        }
        let objects = installed
            .values()
            .map(|artifact| artifact.object.clone())
            .collect();
        Ok(InstalledSelectorState {
            manifest_file: tempfile::NamedTempFile::new()?.into_file(),
            manifest_bytes: Vec::new(),
            manifest: InstallationManifest {
                root_key_id: "root".to_owned(),
                root_public_key: root.verifying_key().to_bytes(),
                trust_digest,
                revocation_digest,
                policy_digest,
                execute_socket: "/run/pigloros/provider-execute.sock".to_owned(),
                control_socket: "/run/pigloros/provider-control.sock".to_owned(),
                required_features: crate::sandbox_provider_protocol::REQUIRED_HOST_FEATURES
                    .map(str::to_owned)
                    .to_vec(),
                objects,
                digest: [1; 32],
            },
            artifacts: installed,
        })
    }

    struct ProviderAuthority {
        root: SigningKey,
        policy: SigningKey,
        release: SigningKey,
        runtime: SigningKey,
        reviewer: SigningKey,
    }

    fn provider_authority() -> ProviderAuthority {
        ProviderAuthority {
            root: SigningKey::from_bytes(&[1; 32]),
            policy: SigningKey::from_bytes(&[2; 32]),
            release: SigningKey::from_bytes(&[3; 32]),
            runtime: SigningKey::from_bytes(&[4; 32]),
            reviewer: SigningKey::from_bytes(&[5; 32]),
        }
    }

    fn ordered(values: Vec<Value>) -> TestResult<Vec<Value>> {
        let mut encoded = values
            .into_iter()
            .map(|value| encode(&value).map(|bytes| (bytes, value)))
            .collect::<Result<Vec<_>, _>>()?;
        encoded.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(encoded.into_iter().map(|(_, value)| value).collect())
    }

    fn trust_key(id: &str, role: u64, key: &SigningKey) -> Value {
        Value::Array(vec![
            Value::Text(id.to_owned()),
            integer(role),
            Value::Bytes(key.verifying_key().to_bytes().to_vec()),
            integer(2),
        ])
    }

    fn provider_trust(authority: &ProviderAuthority) -> TestResult<Vec<u8>> {
        let keys = ordered(vec![
            trust_key("policy", 1, &authority.policy),
            trust_key("release", 2, &authority.release),
            trust_key("runtime", 3, &authority.runtime),
            trust_key("reviewer", 4, &authority.reviewer),
        ])?;
        sign_record(
            "TRS1",
            Value::Array(vec![
                Value::Text("TRS1".to_owned()),
                integer(1),
                integer(2),
                Value::Array(keys),
                Value::Array(Vec::new()),
                Value::Text("root".to_owned()),
            ]),
            &authority.root,
        )
    }

    fn provider_revocation(
        authority: &ProviderAuthority,
        trust_digest: [u8; 32],
    ) -> TestResult<Vec<u8>> {
        sign_record(
            "RVS1",
            Value::Array(vec![
                Value::Text("RVS1".to_owned()),
                integer(1),
                digest(trust_digest),
                integer(3),
                Value::Array(Vec::new()),
                Value::Array(Vec::new()),
                Value::Array(Vec::new()),
                Value::Text("policy".to_owned()),
            ]),
            &authority.policy,
        )
    }

    fn feature_digest(features: &[String]) -> TestResult<[u8; 32]> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"PiglorOS.RequiredHostFeatureSet.v1\0");
        hasher.update(&encode(&Value::Array(
            features
                .iter()
                .map(|feature| Value::Text(feature.clone()))
                .collect(),
        ))?);
        Ok(*hasher.finalize().as_bytes())
    }

    fn provider_manifest(
        authority: &ProviderAuthority,
        binary_digest: [u8; 32],
        features_digest: [u8; 32],
    ) -> TestResult<Vec<u8>> {
        sign_record(
            "SPM1",
            Value::Array(vec![
                Value::Text("SPM1".to_owned()),
                integer(1),
                Value::Text("provider".to_owned()),
                digest([10; 32]),
                digest([11; 32]),
                digest(binary_digest),
                digest([12; 32]),
                Value::Text("runtime".to_owned()),
                Value::Array(vec![Value::Array(vec![
                    Value::Text("execute".to_owned()),
                    integer(1),
                    integer(1),
                ])]),
                Value::Array(vec![integer(0)]),
                digest([13; 32]),
                digest([14; 32]),
                digest([15; 32]),
                digest([16; 32]),
                integer(2),
                digest([17; 32]),
                digest(features_digest),
                Value::Text("release".to_owned()),
            ]),
            &authority.release,
        )
    }

    fn syscall_record() -> TestResult<Vec<u8>> {
        let unsigned = Value::Array(vec![
            Value::Text("SCS1".to_owned()),
            integer(1),
            integer(0),
            Value::Array(vec![Value::Text("read".to_owned())]),
            Value::Array(vec![Value::Text("read".to_owned())]),
        ]);
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"PiglorOS.SCS1.v1\0");
        hasher.update(&encode(&unsigned)?);
        Ok(encode(&Value::Array(vec![
            unsigned,
            digest(*hasher.finalize().as_bytes()),
        ]))?)
    }

    fn host_profile(authority: &ProviderAuthority) -> TestResult<Vec<u8>> {
        let proofs = ordered(
            crate::sandbox_provider_protocol::REQUIRED_HOST_FEATURES
                .iter()
                .map(|feature| {
                    Value::Array(vec![
                        Value::Text((*feature).to_owned()),
                        integer(1),
                        digest([18; 32]),
                    ])
                })
                .collect(),
        )?;
        sign_record(
            "HCP1",
            Value::Array(vec![
                Value::Text("HCP1".to_owned()),
                integer(1),
                integer(0),
                Value::Text("6.12.0".to_owned()),
                Value::Array(proofs),
                digest([19; 32]),
                digest([20; 32]),
                digest([21; 32]),
                Value::Text("runtime".to_owned()),
            ]),
            &authority.runtime,
        )
    }

    fn conformance_report(
        authority: &ProviderAuthority,
        binary_digest: [u8; 32],
        features_digest: [u8; 32],
        host_profile_digest: [u8; 32],
    ) -> TestResult<Vec<u8>> {
        let capability = Value::Array(vec![
            Value::Text("execute".to_owned()),
            integer(1),
            integer(1),
        ]);
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"PiglorOS.ProviderCapabilitySet.v1\0");
        hasher.update(&encode(&Value::Array(vec![capability]))?);
        sign_record(
            "PCR1",
            Value::Array(vec![
                Value::Text("PCR1".to_owned()),
                integer(1),
                digest([17; 32]),
                digest(binary_digest),
                digest([12; 32]),
                digest(*hasher.finalize().as_bytes()),
                digest(features_digest),
                integer(0),
                digest(host_profile_digest),
                integer(0),
                Value::Text("reviewer".to_owned()),
            ]),
            &authority.reviewer,
        )
    }

    fn provider_policy(
        authority: &ProviderAuthority,
        trust_digest: [u8; 32],
        revocation_digest: [u8; 32],
        provider_manifest: [u8; 32],
        provider_binary: [u8; 32],
        hard_caps: [u8; 32],
        conformance_report: [u8; 32],
        syscall_set: [u8; 32],
    ) -> TestResult<Vec<u8>> {
        sign_record(
            "APT1",
            Value::Array(vec![
                Value::Text("APT1".to_owned()),
                integer(1),
                integer(4),
                digest(provider_manifest),
                digest(provider_binary),
                Value::Array(Vec::new()),
                Value::Array(Vec::new()),
                digest(hard_caps),
                digest([17; 32]),
                digest(conformance_report),
                digest(trust_digest),
                digest(revocation_digest),
                integer(2),
                integer(3),
                digest(syscall_set),
                Value::Text("policy".to_owned()),
            ]),
            &authority.policy,
        )
    }

    fn admitted_state() -> TestResult<InstalledSelectorState> {
        let authority = provider_authority();
        let trust = provider_trust(&authority)?;
        let trust_digest = signed_record_digest(&trust)?;
        let revocation = provider_revocation(&authority, trust_digest)?;
        let revocation_digest = signed_record_digest(&revocation)?;
        let features = crate::sandbox_provider_protocol::REQUIRED_HOST_FEATURES
            .map(str::to_owned)
            .to_vec();
        let features_digest = feature_digest(&features)?;
        let provider_binary = b"exact provider binary";
        let provider_binary_digest = *blake3::hash(provider_binary).as_bytes();
        let hard_caps = encode(&Value::Array(vec![
            Value::Text("BHC1".to_owned()),
            integer(1),
            Value::Array(
                (0..17)
                    .map(|limit_id| Value::Array(vec![integer(limit_id), integer(2_000)]))
                    .collect(),
            ),
        ]))?;
        let hard_caps_digest = *blake3::hash(&hard_caps).as_bytes();
        let manifest = provider_manifest(&authority, provider_binary_digest, features_digest)?;
        let manifest_digest = signed_record_digest(&manifest)?;
        let syscall = syscall_record()?;
        let syscall_digest = signed_record_digest(&syscall)?;
        let host = host_profile(&authority)?;
        let host_digest = signed_record_digest(&host)?;
        let report = conformance_report(
            &authority,
            provider_binary_digest,
            features_digest,
            host_digest,
        )?;
        let report_digest = signed_record_digest(&report)?;
        let policy = provider_policy(
            &authority,
            trust_digest,
            revocation_digest,
            manifest_digest,
            provider_binary_digest,
            hard_caps_digest,
            report_digest,
            syscall_digest,
        )?;
        let policy_digest = signed_record_digest(&policy)?;
        let artifacts = [
            (0, trust_digest, trust.as_slice()),
            (1, revocation_digest, revocation.as_slice()),
            (2, policy_digest, policy.as_slice()),
            (3, manifest_digest, manifest.as_slice()),
            (4, report_digest, report.as_slice()),
            (5, [17; 32], b"conformance-profile".as_slice()),
            (6, host_digest, host.as_slice()),
            (7, syscall_digest, syscall.as_slice()),
            (10, hard_caps_digest, hard_caps.as_slice()),
            (11, provider_binary_digest, provider_binary.as_slice()),
        ];
        let mut installed = BTreeMap::new();
        for (kind, identity, bytes) in artifacts {
            let artifact = held_artifact(kind, identity, bytes)?;
            installed.insert((artifact.object.kind, artifact.object.identity), artifact);
        }
        let objects = installed
            .values()
            .map(|artifact| artifact.object.clone())
            .collect();
        Ok(InstalledSelectorState {
            manifest_file: tempfile::NamedTempFile::new()?.into_file(),
            manifest_bytes: Vec::new(),
            manifest: InstallationManifest {
                root_key_id: "root".to_owned(),
                root_public_key: authority.root.verifying_key().to_bytes(),
                trust_digest,
                revocation_digest,
                policy_digest,
                execute_socket: "/run/pigloros/provider-execute.sock".to_owned(),
                control_socket: "/run/pigloros/provider-control.sock".to_owned(),
                required_features: features,
                objects,
                digest: [1; 32],
            },
            artifacts: installed,
        })
    }

    #[test]
    fn decodes_closed_canonical_manifest() -> TestResult {
        let manifest = InstallationManifest::from_canonical_cbor(&encode_manifest(unsigned(
            valid_objects(),
        ))?)?;
        assert_eq!(manifest.offline_root().0, "offline-root");
        assert_eq!(manifest.authority_digests(), [[1; 32], [2; 32], [3; 32]]);
        assert_eq!(
            manifest.required_features(),
            crate::sandbox_provider_protocol::REQUIRED_HOST_FEATURES
        );
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
                Value::Array(vec![Value::Text("broker-lifecycle".to_owned())]),
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

    #[test]
    fn sic1_exposes_canonical_entries_and_rejects_unsafe_routes() -> TestResult {
        let encoded = encode_manifest(unsigned(valid_objects()))?;
        let manifest = InstallationManifest::from_canonical_cbor(&encoded)?;
        let (root_key_id, root_public_key) = manifest.offline_root();
        assert_eq!(root_key_id, "offline-root");
        assert_eq!(
            root_public_key,
            SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes()
        );
        assert_eq!(manifest.authority_digests(), [[1; 32], [2; 32], [3; 32]]);
        assert_eq!(
            manifest.provider_sockets(),
            (
                Path::new("/run/pigloros/provider-execute.sock"),
                Path::new("/run/pigloros/provider-control.sock"),
            )
        );
        assert_eq!(
            manifest.required_features(),
            crate::sandbox_provider_protocol::REQUIRED_HOST_FEATURES
        );
        assert_eq!(manifest.objects().len(), 16);
        assert_ne!(manifest.digest(), [0; 32]);
        let provider_binary_identity = manifest.objects()[11].identity();
        let provider_binary = manifest.object(
            InstallationObjectKind::from_code(11)?,
            provider_binary_identity,
        )?;
        assert_eq!(provider_binary.kind().code(), 11);
        assert_eq!(provider_binary.identity(), provider_binary.content_digest());
        assert_ne!(provider_binary.content_digest(), [0; 32]);
        assert_eq!(provider_binary.byte_length(), 3);
        assert!(manifest
            .object(InstallationObjectKind::from_code(11)?, [0; 32])
            .is_err());

        for path in [
            "relative-provider.sock",
            "/run/pigloros/",
            "/run/pigloros/../provider.sock",
        ] {
            let mut fields = unsigned(valid_objects());
            fields[7] = Value::Text(path.to_owned());
            assert!(InstallationManifest::from_canonical_cbor(&encode_manifest(fields)?).is_err());
        }

        let mut equal_sockets = unsigned(valid_objects());
        equal_sockets[8] = equal_sockets[7].clone();
        assert!(
            InstallationManifest::from_canonical_cbor(&encode_manifest(equal_sockets)?).is_err()
        );

        let empty_objects = unsigned(Vec::new());
        assert!(
            InstallationManifest::from_canonical_cbor(&encode_manifest(empty_objects)?).is_err()
        );

        let mut zero_length_objects = valid_objects();
        zero_length_objects[0] = object(0, *blake3::hash(&[1; 3]).as_bytes(), 0);
        assert!(
            InstallationManifest::from_canonical_cbor(&encode_manifest(unsigned(
                zero_length_objects,
            ))?)
            .is_err()
        );

        let mut mismatched_identity_objects = valid_objects();
        let Value::Array(fields) = &mut mismatched_identity_objects[10] else {
            return Err("installation object is not an array".into());
        };
        fields[1] = digest([42; 32]);
        assert!(
            InstallationManifest::from_canonical_cbor(&encode_manifest(unsigned(
                mismatched_identity_objects,
            ))?)
            .is_err()
        );
        Ok(())
    }

    fn replace_object_field(
        objects: &mut [Value],
        object_index: usize,
        field_index: usize,
        value: Value,
    ) -> TestResult {
        let Value::Array(fields) = &mut objects[object_index] else {
            return Err("installation object is not an array".into());
        };
        fields[field_index] = value;
        Ok(())
    }

    fn assert_manifest_rejected(fields: Vec<Value>) -> TestResult {
        assert!(InstallationManifest::from_canonical_cbor(&encode_manifest(fields)?).is_err());
        Ok(())
    }

    fn assert_raw_manifest_rejected(value: &Value) -> TestResult {
        assert!(InstallationManifest::from_canonical_cbor(&encode(value)?).is_err());
        Ok(())
    }

    #[test]
    fn sic1_rejects_invalid_authority_and_object_encodings() -> TestResult {
        let unsigned_manifest = Value::Array(unsigned(valid_objects()));
        let mismatched_digest = encode(&Value::Array(vec![
            unsigned_manifest,
            Value::Bytes(vec![9; 32]),
        ]))?;
        assert!(InstallationManifest::from_canonical_cbor(&mismatched_digest).is_err());

        let mut invalid_root_key = unsigned(valid_objects());
        invalid_root_key[3] = Value::Bytes(vec![0; 31]);
        assert_manifest_rejected(invalid_root_key)?;

        let mut malformed_root_key = unsigned(valid_objects());
        malformed_root_key[3] = Value::Bytes(vec![0; 32]);
        assert_manifest_rejected(malformed_root_key)?;

        for (field, value) in [
            (0, Value::Integer(2.into())),
            (1, Value::Text("one".to_owned())),
            (2, Value::Null),
        ] {
            let mut fields = unsigned(valid_objects());
            fields[field] = value;
            assert_manifest_rejected(fields)?;
        }

        for (field, value) in [
            (4, Value::Null),
            (7, Value::Bytes(vec![7; 32])),
            (9, Value::Null),
            (10, Value::Null),
        ] {
            let mut fields = unsigned(valid_objects());
            fields[field] = value;
            assert_manifest_rejected(fields)?;
        }

        for authority_field in 4..=6 {
            let mut fields = unsigned(valid_objects());
            fields[authority_field] = digest([0; 32]);
            assert_manifest_rejected(fields)?;
        }

        for features in [
            Value::Array(vec![Value::Integer(1.into())]),
            Value::Array(vec![
                Value::Text("a".to_owned()),
                Value::Text("a".to_owned()),
            ]),
        ] {
            let mut fields = unsigned(valid_objects());
            fields[9] = features;
            assert_manifest_rejected(fields)?;
        }

        let mut invalid_shape = valid_objects();
        invalid_shape[0] = Value::Array(vec![]);
        assert_manifest_rejected(unsigned(invalid_shape))?;

        let mut invalid_kind = valid_objects();
        replace_object_field(&mut invalid_kind, 0, 0, integer(16))?;
        assert_manifest_rejected(unsigned(invalid_kind))?;

        let mut out_of_range_kind = valid_objects();
        replace_object_field(&mut out_of_range_kind, 0, 0, integer(256))?;
        assert_manifest_rejected(unsigned(out_of_range_kind))?;

        let mut non_integer_kind = valid_objects();
        replace_object_field(&mut non_integer_kind, 0, 0, Value::Null)?;
        assert_manifest_rejected(unsigned(non_integer_kind))?;

        let mut invalid_kind_encoding = valid_objects();
        replace_object_field(
            &mut invalid_kind_encoding,
            0,
            0,
            Value::Text("authority".to_owned()),
        )?;
        assert_manifest_rejected(unsigned(invalid_kind_encoding))?;

        let mut zero_identity = valid_objects();
        replace_object_field(&mut zero_identity, 0, 1, digest([0; 32]))?;
        assert_manifest_rejected(unsigned(zero_identity))?;

        let mut zero_content = valid_objects();
        replace_object_field(&mut zero_content, 0, 2, digest([0; 32]))?;
        assert_manifest_rejected(unsigned(zero_content))?;

        let mut invalid_length = valid_objects();
        replace_object_field(&mut invalid_length, 0, 3, Value::Text("three".to_owned()))?;
        assert_manifest_rejected(unsigned(invalid_length))?;

        let mut missing_selected_authority = valid_objects();
        missing_selected_authority.remove(0);
        assert_manifest_rejected(unsigned(missing_selected_authority))?;
        Ok(())
    }

    #[test]
    fn sic1_rejects_invalid_outer_envelopes_and_root_identity() -> TestResult {
        assert_raw_manifest_rejected(&Value::Null)?;
        assert_raw_manifest_rejected(&Value::Array(vec![]))?;
        assert_raw_manifest_rejected(&Value::Array(vec![Value::Null, Value::Bytes(vec![1; 32])]))?;
        assert_raw_manifest_rejected(&Value::Array(vec![
            Value::Array(unsigned(valid_objects())),
            Value::Null,
        ]))?;
        assert_raw_manifest_rejected(&Value::Array(vec![
            Value::Array(vec![Value::Text("SIC1".to_owned())]),
            Value::Bytes(vec![1; 32]),
        ]))?;

        let mut oversized_root_id = unsigned(valid_objects());
        oversized_root_id[2] = Value::Text("r".repeat(129));
        assert_manifest_rejected(oversized_root_id)?;

        let mut reserved_socket = unsigned(valid_objects());
        reserved_socket[7] = Value::Text(SANDBOX_ADMIN_SOCKET.to_owned());
        assert_manifest_rejected(reserved_socket)?;

        let mut oversized_socket = unsigned(valid_objects());
        oversized_socket[7] = Value::Text(format!("/run/pigloros/{}", "s".repeat(108)));
        assert_manifest_rejected(oversized_socket)?;
        Ok(())
    }

    #[test]
    fn fixed_root_open_fails_closed_without_a_root_owned_installation() {
        assert!(InstalledSelectorState::open().is_err());
    }

    fn write_immutable_file(root: &Path, name: &str, bytes: &[u8]) -> TestResult {
        let path = root.join(name);
        fs::write(&path, bytes)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o400))?;
        Ok(())
    }

    #[test]
    fn installation_filesystem_boundaries_reject_unsafe_descriptors() -> TestResult {
        let temporary = tempfile::tempdir()?;
        let root = File::open(temporary.path())?;
        let owner = root.metadata()?.uid();
        assert!(validate_directory(&root, owner).is_ok());
        assert!(validate_directory(&root, owner.saturating_add(1)).is_err());
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o777))?;
        assert!(validate_directory(&root, owner).is_err());
        assert!(open_directory_chain(root.try_clone()?, Path::new(""), owner).is_err());
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;

        assert!(open_directory_chain(root.try_clone()?, Path::new("missing"), owner).is_err());
        assert!(open_directory_chain(root.try_clone()?, Path::new("../escape"), owner).is_err());

        fs::create_dir(temporary.path().join("unsafe-directory"))?;
        fs::set_permissions(
            temporary.path().join("unsafe-directory"),
            fs::Permissions::from_mode(0o777),
        )?;
        assert!(
            open_directory_chain(root.try_clone()?, Path::new("unsafe-directory"), owner).is_err()
        );

        fs::create_dir(temporary.path().join("directory"))?;
        assert!(open_immutable_file(&root, "directory", 0o400, 4, owner).is_err());

        write_immutable_file(temporary.path(), "regular", b"read")?;
        let regular = open_immutable_file(&root, "regular", 0o400, 4, owner)?;
        assert_eq!(read_complete_file(&regular, 4)?, b"read");
        assert!(read_complete_file(&regular, 2).is_err());
        assert!(open_immutable_file(&root, "regular", 0o400, 4, owner.saturating_add(1)).is_err());

        write_immutable_file(temporary.path(), "empty", b"")?;
        assert!(open_immutable_file(&root, "empty", 0o400, 4, owner).is_err());

        write_immutable_file(temporary.path(), "large", b"large")?;
        assert!(open_immutable_file(&root, "large", 0o400, 4, owner).is_err());

        write_immutable_file(temporary.path(), "wrong-mode", b"read")?;
        fs::set_permissions(
            temporary.path().join("wrong-mode"),
            fs::Permissions::from_mode(0o600),
        )?;
        assert!(open_immutable_file(&root, "wrong-mode", 0o400, 4, owner).is_err());

        write_immutable_file(temporary.path(), "linked", b"read")?;
        fs::hard_link(
            temporary.path().join("linked"),
            temporary.path().join("linked-copy"),
        )?;
        assert!(open_immutable_file(&root, "linked", 0o400, 4, owner).is_err());

        symlink("regular", temporary.path().join("symlink"))?;
        assert!(open_immutable_file(&root, "symlink", 0o400, 4, owner).is_err());
        assert!(open_immutable_file(&root, "missing", 0o400, 4, owner).is_err());
        Ok(())
    }

    #[test]
    fn installed_state_rejects_missing_and_mismatched_indexed_artifacts() -> TestResult {
        let missing_manifest = tempfile::tempdir()?;
        write_state(missing_manifest.path())?;
        let root = File::open(missing_manifest.path())?;
        fs::remove_file(missing_manifest.path().join(MANIFEST_NAME))?;
        assert!(InstalledSelectorState::open_at_for_test(&root).is_err());

        let malformed_manifest = tempfile::tempdir()?;
        write_state(malformed_manifest.path())?;
        let root = File::open(malformed_manifest.path())?;
        fs::set_permissions(
            malformed_manifest.path().join(MANIFEST_NAME),
            fs::Permissions::from_mode(0o600),
        )?;
        fs::write(malformed_manifest.path().join(MANIFEST_NAME), [0xff])?;
        fs::set_permissions(
            malformed_manifest.path().join(MANIFEST_NAME),
            fs::Permissions::from_mode(0o400),
        )?;
        assert!(InstalledSelectorState::open_at_for_test(&root).is_err());

        let missing_artifact_directory = tempfile::tempdir()?;
        write_state(missing_artifact_directory.path())?;
        let root = File::open(missing_artifact_directory.path())?;
        fs::rename(
            missing_artifact_directory.path().join("authority"),
            missing_artifact_directory.path().join("missing-authority"),
        )?;
        assert!(InstalledSelectorState::open_at_for_test(&root).is_err());

        let mismatched_artifact = tempfile::tempdir()?;
        write_state(mismatched_artifact.path())?;
        let root = File::open(mismatched_artifact.path())?;
        let digest = hex_name(*blake3::hash(&[1; 3]).as_bytes());
        let artifact = mismatched_artifact.path().join("authority").join(digest);
        fs::set_permissions(&artifact, fs::Permissions::from_mode(0o600))?;
        fs::write(&artifact, b"bad")?;
        fs::set_permissions(&artifact, fs::Permissions::from_mode(0o400))?;
        assert!(InstalledSelectorState::open_at_for_test(&root).is_err());
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
        if root.metadata()?.uid() != 0 {
            assert!(InstalledSelectorState::open_at(&root).is_err());
        }
        let state = InstalledSelectorState::open_at_for_test(&root)?;
        assert!(!state.manifest_bytes().is_empty());
        assert!(state.manifest_file().metadata()?.is_file());
        assert_eq!(state.manifest().objects().len(), 16);
        let authority = state.artifact(InstallationObjectKind::from_code(0)?, [1; 32])?;
        assert!(authority.file().metadata()?.is_file());
        assert_eq!(authority.read_control(3)?, [1; 3]);
        assert!(authority.read_control(2).is_err());

        let mut truncated = held_artifact(0, [9; 32], b"abc")?;
        truncated.object.byte_length = 4;
        assert!(truncated.read_control(4).is_err());
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
        assert!(InstalledSelectorState::open_at_for_test(&root).is_err());
        fs::remove_file(linked)?;
        fs::remove_file(&source)?;
        symlink("elsewhere", &source)?;
        assert!(InstalledSelectorState::open_at_for_test(&root).is_err());
        Ok(())
    }

    #[test]
    fn pending_recovery_prevents_normal_startup() -> TestResult {
        let temporary = tempfile::tempdir()?;
        write_state(temporary.path())?;
        fs::write(temporary.path().join("installation-update.cbor"), [1])?;
        let root = File::open(temporary.path())?;
        assert!(InstalledSelectorState::open_at_for_test(&root).is_err());
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

        let write_only = fs::OpenOptions::new().write(true).open(temporary.path())?;
        assert_eq!(
            digest_reader(write_only, 1),
            Err(SelectorBoundaryError::Io)
        );

        let write_only = fs::OpenOptions::new().write(true).open(temporary.path())?;
        assert_eq!(
            digest_reader(write_only, 0),
            Err(SelectorBoundaryError::Io)
        );
        Ok(())
    }

    #[test]
    fn authenticates_pinned_bootstrap_and_selected_artifacts() -> TestResult {
        let bootstrap = authenticated_state()?.authenticate_bootstrap()?;
        assert_eq!(bootstrap.trust().trust_epoch(), 1);
        assert_eq!(bootstrap.revocation().revocation_epoch(), 1);
        assert_eq!(bootstrap.policy().policy_epoch(), 1);
        assert!(bootstrap
            .installed()
            .artifact(InstallationObjectKind::from_code(3)?, [10; 32])
            .is_ok());
        Ok(())
    }

    #[test]
    fn rejects_foreign_root_or_missing_selected_artifact() -> TestResult {
        let mut foreign_root = authenticated_state()?;
        foreign_root.manifest.root_public_key =
            SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
        assert!(foreign_root.authenticate_bootstrap().is_err());

        let mut missing_selected = authenticated_state()?;
        missing_selected
            .artifacts
            .remove(&(InstallationObjectKind::from_code(4)?, [16; 32]));
        assert!(missing_selected.authenticate_bootstrap().is_err());

        let mut digest_mismatch = authenticated_state()?;
        let trust = digest_mismatch
            .artifacts
            .remove(&(
                InstallationObjectKind::from_code(0)?,
                digest_mismatch.manifest.trust_digest,
            ))
            .ok_or("authenticated state is missing the trust artifact")?;
        let replacement_digest = [99; 32];
        digest_mismatch.manifest.trust_digest = replacement_digest;
        let HeldInstallationArtifact { file, mut object } = trust;
        object.identity = replacement_digest;
        digest_mismatch.artifacts.insert(
            (InstallationObjectKind::from_code(0)?, replacement_digest),
            HeldInstallationArtifact { file, object },
        );
        assert!(digest_mismatch.authenticate_bootstrap().is_err());
        Ok(())
    }

    #[test]
    fn provider_admission_rejects_untrusted_installed_provider_records() -> TestResult {
        let bootstrap = authenticated_state()?.authenticate_bootstrap()?;
        assert!(bootstrap.admit_provider().is_err());
        Ok(())
    }

    #[test]
    fn provider_admission_rejects_missing_report_bound_host_profile() -> TestResult {
        let mut installed = admitted_state()?;
        let host_profile_kind = InstallationObjectKind::from_code(6)?;
        let host_profile = installed
            .artifacts
            .keys()
            .find(|(kind, _)| *kind == host_profile_kind)
            .copied()
            .ok_or("admitted state is missing the host profile")?;
        installed.artifacts.remove(&host_profile);
        assert!(installed
            .authenticate_bootstrap()?
            .admit_provider()
            .is_err());
        Ok(())
    }

    #[test]
    fn provider_admission_accepts_complete_retained_sic1_artifacts() -> TestResult {
        let admitted = admitted_state()?
            .authenticate_bootstrap()?
            .admit_provider()?;
        assert_eq!(admitted.bootstrap().policy().policy_epoch(), 4);
        assert_eq!(admitted.provider().manifest().provider_id, "provider");
        assert_eq!(admitted.provider().host_profile().kernel_release, "6.12.0");
        Ok(())
    }

    fn retain_case_artifact(
        state: &mut InstalledSelectorState,
        kind: u8,
        identity: [u8; 32],
        bytes: &[u8],
    ) -> TestResult {
        let artifact = held_artifact(kind, identity, bytes)?;
        let key = (artifact.object.kind, artifact.object.identity);
        state.manifest.objects.push(artifact.object.clone());
        state
            .manifest
            .objects
            .sort_by_key(|object| (object.kind, object.identity));
        state.artifacts.insert(key, artifact);
        Ok(())
    }

    fn installed_case_bootstrap(
        corpus: &crate::selector_test_support::Corpus,
    ) -> TestResult<(EvaluationRequest, AuthenticatedSelectorBootstrap)> {
        let request = EvaluationRequest::from_canonical_cbor(&corpus.request)?;
        let mut state = authenticated_state()?;
        retain_case_artifact(
            &mut state,
            14,
            request.fixture_bundle_digest,
            &corpus.archive,
        )?;
        retain_case_artifact(
            &mut state,
            15,
            request.trust_policy_snapshot_digest,
            &corpus.trust_policy,
        )?;
        state
            .authenticate_bootstrap()
            .map(|bootstrap| (request, bootstrap))
            .map_err(Into::into)
    }

    fn rebound(mut request: EvaluationRequest) -> TestResult<EvaluationRequest> {
        request.output_capability.capability_digest =
            request.expected_output_capability_digest()?;
        request.request_digest = request.digest()?;
        Ok(request)
    }

    #[test]
    fn retained_sic1_descriptors_reconstruct_the_evr1_selected_case() -> TestResult {
        let corpus = crate::selector_test_support::corpus()?;
        let (request, bootstrap) = installed_case_bootstrap(&corpus)?;
        let resolved = bootstrap.resolve_installed_case(&request, 0)?;
        assert_eq!(resolved.bundle_digest(), request.fixture_bundle_digest);
        assert_eq!(resolved.profile_digest(), request.profile_digest);
        assert_ne!(resolved.fixture_contract_digest(), [0; 32]);
        assert_eq!(resolved.attempt().case_id, "case-0");
        assert_eq!(resolved.attempt().mode, 0);
        Ok(())
    }

    #[test]
    fn retained_sic1_case_resolution_rejects_foreign_identity_and_case_selection() -> TestResult {
        let corpus = crate::selector_test_support::corpus()?;
        let (request, bootstrap) = installed_case_bootstrap(&corpus)?;
        assert!(bootstrap.resolve_installed_case(&request, 7).is_err());
        for request in [
            rebound(EvaluationRequest {
                subject_adapter: SubjectAdapterKind::PublicGatewayProtocol,
                ..request.clone()
            })?,
            rebound(EvaluationRequest {
                fixture_bundle_digest: [99; 32],
                ..request
            })?,
        ] {
            assert!(bootstrap.resolve_installed_case(&request, 0).is_err());
        }
        Ok(())
    }

    #[test]
    fn retained_sic1_case_resolution_enforces_preflight_and_verified_closure() -> TestResult {
        let invalid_signature = crate::selector_test_support::corpus_with_bundle_mutation(
            crate::selector_test_support::BundleMutation::Signature,
        )?;
        let (request, bootstrap) = installed_case_bootstrap(&invalid_signature)?;
        assert!(bootstrap.resolve_installed_case(&request, 0).is_err());

        let cap_violation = crate::selector_test_support::corpus_with_profile_mutation(
            crate::selector_test_support::ProfileMutation::SelectedClosureCapBoundary(0),
        )?;
        let (request, bootstrap) = installed_case_bootstrap(&cap_violation)?;
        assert!(bootstrap.resolve_installed_case(&request, 0).is_err());
        Ok(())
    }
}
