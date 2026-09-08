//! Root-owned immutable artifact and selector-socket boundary.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rustix::fd::AsFd;
use rustix::fs::{openat2, Mode, OFlags, ResolveFlags};
use rustix::net::sockopt::socket_peercred;

use crate::adapter_transport::{read_observation, write_attempt};
use crate::evaluator::{AdapterError, CaseAttempt, SubjectAdapter, SubjectObservation};
use crate::evaluator_protocol::SubjectAdapterKind;

/// Fixed root-owned selector endpoint. It is not configurable by an evaluator.
pub const SANDBOX_SELECTOR_SOCKET: &str = "/run/pigloros/sandbox-provider.sock";
/// Fixed digest-addressed installation root.
pub const SANDBOX_ARTIFACT_ROOT: &str = "/var/lib/pigloros/sandbox";

const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const FORBIDDEN_WRITE_MODE: u32 = 0o222;
const SELECTOR_SOCKET_MODE: u32 = 0o600;

/// Closed classes in the immutable sandbox artifact store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxArtifactKind {
    /// Canonical signed authority and policy records.
    Authority,
    /// Exact provider executables.
    Provider,
    /// Exact signed root images.
    Image,
}

impl SandboxArtifactKind {
    const fn directory(self) -> &'static str {
        match self {
            Self::Authority => "authority",
            Self::Provider => "providers",
            Self::Image => "images",
        }
    }
}

/// An opened digest-addressed artifact whose descriptor survives pathname replacement.
#[derive(Debug)]
pub struct ImmutableSandboxArtifact {
    file: File,
    digest: [u8; 32],
    length: u64,
}

impl ImmutableSandboxArtifact {
    /// Open one root-owned artifact beneath the fixed installation root.
    ///
    /// # Errors
    /// Rejects unsupported hosts, symlinks, mutable/non-root paths, non-regular
    /// files, incorrect digest-addressing, oversized bytes, and digest mismatch.
    pub fn open(
        kind: SandboxArtifactKind,
        digest: [u8; 32],
    ) -> Result<Self, SelectorBoundaryError> {
        open_under(Path::new(SANDBOX_ARTIFACT_ROOT), kind, digest, 0)
    }

    /// Exact verified content digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Exact verified byte length.
    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }

    /// Read the held immutable descriptor from its beginning.
    ///
    /// # Errors
    /// Returns a closed I/O failure if the retained file cannot be cloned or read.
    pub fn read_bytes(&self) -> Result<Vec<u8>, SelectorBoundaryError> {
        let mut file = self
            .file
            .try_clone()
            .map_err(|_| SelectorBoundaryError::Io)?;
        let mut bytes = Vec::with_capacity(
            usize::try_from(self.length).map_err(|_| SelectorBoundaryError::ArtifactInvalid)?,
        );
        file.seek(SeekFrom::Start(0))
            .map_err(|_| SelectorBoundaryError::Io)?;
        file.read_to_end(&mut bytes)
            .map_err(|_| SelectorBoundaryError::Io)?;
        Ok(bytes)
    }
}

/// Root-authenticated transport to the single selected provider.
#[derive(Debug)]
pub struct SelectorAdapter {
    kind: SubjectAdapterKind,
    subject_artifact_digest: [u8; 32],
}

impl SelectorAdapter {
    /// Bind evaluation to the fixed root-owned selector endpoint.
    #[must_use]
    pub const fn new(kind: SubjectAdapterKind, subject_artifact_digest: [u8; 32]) -> Self {
        Self {
            kind,
            subject_artifact_digest,
        }
    }

    fn invoke(&self, attempt: &CaseAttempt) -> Result<SubjectObservation, AdapterError> {
        let mut stream = connect_selector().map_err(|_| AdapterError::Unavailable)?;
        let watchdog = Duration::from_millis(attempt.watchdog_ms);
        stream
            .set_read_timeout(Some(watchdog))
            .and_then(|()| stream.set_write_timeout(Some(watchdog)))
            .map_err(|_| AdapterError::Unavailable)?;
        write_attempt(&mut stream, attempt).map_err(|_| AdapterError::ProtocolFailure)?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|_| AdapterError::ProtocolFailure)?;
        read_observation(&mut stream, attempt.budget.output_bytes)
            .map_err(|_| AdapterError::ProtocolFailure)
    }
}

impl SubjectAdapter for SelectorAdapter {
    fn kind(&self) -> SubjectAdapterKind {
        self.kind
    }

    fn subject_artifact_digest(&self) -> [u8; 32] {
        self.subject_artifact_digest
    }

    fn execute(&mut self, attempt: &CaseAttempt) -> Result<SubjectObservation, AdapterError> {
        self.invoke(attempt)
    }
}

/// Closed local selector/installation failures. No untrusted detail is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SelectorBoundaryError {
    /// Path ownership, mode, type, identity, or digest is invalid.
    #[error("sandbox selector identity or artifact is invalid")]
    ArtifactInvalid,
    /// Fixed selector socket is unavailable.
    #[error("sandbox selector is unavailable")]
    SelectorUnavailable,
    /// Bounded local I/O failed.
    #[error("sandbox selector I/O failed")]
    Io,
}

fn open_under(
    root: &Path,
    kind: SandboxArtifactKind,
    digest: [u8; 32],
    expected_uid: u32,
) -> Result<ImmutableSandboxArtifact, SelectorBoundaryError> {
    let root = File::open(root).map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    validate_owned_directory(&root, expected_uid)?;
    let directory = openat2(
        &root,
        kind.directory(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map(File::from)
    .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    validate_owned_directory(&directory, expected_uid)?;
    let name = digest_name(digest);
    let mut file = openat2(
        &directory,
        name.as_str(),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map(File::from)
    .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    let metadata = file
        .metadata()
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    if !metadata.is_file()
        || metadata.uid() != expected_uid
        || metadata.mode() & FORBIDDEN_WRITE_MODE != 0
        || metadata.len() > MAX_ARTIFACT_BYTES
    {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| SelectorBoundaryError::Io)?;
    if blake3::hash(&bytes).as_bytes() != &digest {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| SelectorBoundaryError::Io)?;
    Ok(ImmutableSandboxArtifact {
        file,
        digest,
        length: metadata.len(),
    })
}

fn validate_owned_directory(file: &File, expected_uid: u32) -> Result<(), SelectorBoundaryError> {
    let metadata = file
        .metadata()
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    if metadata.is_dir()
        && metadata.uid() == expected_uid
        && metadata.mode() & FORBIDDEN_WRITE_MODE == 0
    {
        Ok(())
    } else {
        Err(SelectorBoundaryError::ArtifactInvalid)
    }
}

fn digest_name(digest: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::with_capacity(64);
    for byte in digest {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    name
}

fn connect_selector() -> Result<UnixStream, SelectorBoundaryError> {
    let path = PathBuf::from(SANDBOX_SELECTOR_SOCKET);
    let before =
        std::fs::symlink_metadata(&path).map_err(|_| SelectorBoundaryError::SelectorUnavailable)?;
    if !before.file_type().is_socket()
        || before.uid() != 0
        || before.mode() & 0o777 != SELECTOR_SOCKET_MODE
    {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    let stream =
        UnixStream::connect(&path).map_err(|_| SelectorBoundaryError::SelectorUnavailable)?;
    let credentials =
        socket_peercred(stream.as_fd()).map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    let after =
        std::fs::symlink_metadata(path).map_err(|_| SelectorBoundaryError::SelectorUnavailable)?;
    if credentials.uid.as_raw() != 0 || before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use super::*;

    #[test]
    fn immutable_artifact_retains_verified_descriptor() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path();
        let provider_directory = root.join("providers");
        std::fs::create_dir(&provider_directory)?;
        let payload = b"provider";
        let digest = *blake3::hash(payload).as_bytes();
        let path = provider_directory.join(digest_name(digest));
        std::fs::write(&path, payload)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))?;
        std::fs::set_permissions(&provider_directory, std::fs::Permissions::from_mode(0o500))?;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o500))?;
        let uid = std::fs::metadata(root)?.uid();

        let artifact = open_under(root, SandboxArtifactKind::Provider, digest, uid)?;
        assert_eq!(artifact.digest(), digest);
        assert_eq!(artifact.length(), u64::try_from(payload.len())?);
        assert_eq!(artifact.read_bytes()?, payload);
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
        std::fs::set_permissions(&provider_directory, std::fs::Permissions::from_mode(0o700))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    #[test]
    fn immutable_artifact_rejects_mutable_or_mismatched_content(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path();
        let image_directory = root.join("images");
        std::fs::create_dir(&image_directory)?;
        let claimed = *blake3::hash(b"claimed").as_bytes();
        let path = image_directory.join(digest_name(claimed));
        std::fs::write(&path, b"changed")?;
        let uid = std::fs::metadata(root)?.uid();
        assert_eq!(
            open_under(root, SandboxArtifactKind::Image, claimed, uid).map(|_| ()),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))?;
        std::fs::set_permissions(&image_directory, std::fs::Permissions::from_mode(0o500))?;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o500))?;
        assert_eq!(
            open_under(root, SandboxArtifactKind::Image, claimed, uid).map(|_| ()),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
        std::fs::set_permissions(&image_directory, std::fs::Permissions::from_mode(0o700))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
}
