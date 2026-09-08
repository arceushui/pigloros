//! Root-owned immutable artifact and selector-socket boundary.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rustix::fd::AsFd;
use rustix::fs::{openat2, Mode, OFlags, ResolveFlags};
use rustix::net::sockopt::socket_peercred;

use crate::evaluator::{AdapterError, CaseAttempt, SubjectAdapter, SubjectObservation};
use crate::evaluator_protocol::{EvaluationRequest, SubjectAdapterKind};
use crate::selector_protocol::{decode_reply, encode_request, EncodedSelectorRequest};

/// Fixed root-owned selector endpoint. It is not configurable by an evaluator.
pub const SANDBOX_SELECTOR_SOCKET: &str = "/run/pigloros/sandbox-provider.sock";
/// Fixed digest-addressed installation root.
pub const SANDBOX_ARTIFACT_ROOT: &str = "/var/lib/pigloros/sandbox";

const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const FORBIDDEN_WRITE_MODE: u32 = 0o222;
const SELECTOR_SOCKET_MODE: u32 = 0o600;
const MAX_SELECTOR_TRAILING_BYTES: u64 = 129 * 1024 * 1024;

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
    request: EvaluationRequest,
    request_bytes: Vec<u8>,
    next_case_ordinal: Option<u16>,
    provenance: Option<[u8; 32]>,
}

impl SelectorAdapter {
    /// Bind evaluation to the fixed root-owned selector endpoint.
    #[must_use]
    pub fn new(request: &EvaluationRequest, request_bytes: &[u8]) -> Self {
        Self {
            kind: request.subject_adapter,
            subject_artifact_digest: request.subject_artifact_digest,
            request: request.clone(),
            request_bytes: request_bytes.to_vec(),
            next_case_ordinal: None,
            provenance: None,
        }
    }

    fn invoke(&mut self, attempt: &CaseAttempt) -> Result<SubjectObservation, AdapterError> {
        let ordinal = self
            .next_case_ordinal
            .take()
            .ok_or(AdapterError::ProtocolFailure)?;
        let request = encode_request(&self.request, &self.request_bytes, attempt, ordinal)?;
        let reply = Self::invoke_at(
            Path::new(SANDBOX_SELECTOR_SOCKET),
            0,
            attempt,
            &request,
            self.request.request_digest,
        )?;
        self.provenance = reply.provenance;
        reply.observation
    }

    fn invoke_at(
        socket_path: &Path,
        expected_uid: u32,
        attempt: &CaseAttempt,
        request: &EncodedSelectorRequest,
        evr1_digest: [u8; 32],
    ) -> Result<crate::selector_protocol::DecodedSelectorReply, AdapterError> {
        let mut stream =
            connect_at(socket_path, expected_uid).map_err(|_| AdapterError::Unavailable)?;
        let watchdog = Duration::from_millis(attempt.watchdog_ms);
        stream
            .set_read_timeout(Some(watchdog))
            .and_then(|()| stream.set_write_timeout(Some(watchdog)))
            .map_err(|_| AdapterError::Unavailable)?;
        let control_length =
            u32::try_from(request.control.len()).map_err(|_| AdapterError::ProtocolFailure)?;
        stream
            .write_all(&control_length.to_be_bytes())
            .and_then(|()| stream.write_all(&request.control))
            .and_then(|()| stream.write_all(&request.attempt_stream))
            .map_err(|_| AdapterError::ProtocolFailure)?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|_| AdapterError::ProtocolFailure)?;
        let mut prefix = [0; 4];
        stream
            .read_exact(&mut prefix)
            .map_err(|_| AdapterError::ProtocolFailure)?;
        let length = usize::try_from(u32::from_be_bytes(prefix))
            .map_err(|_| AdapterError::ProtocolFailure)?;
        if length == 0 || length > 16 * 1024 * 1024 {
            return Err(AdapterError::ProtocolFailure);
        }
        let mut control = vec![0; length];
        stream
            .read_exact(&mut control)
            .map_err(|_| AdapterError::ProtocolFailure)?;
        let mut trailing = Vec::new();
        stream
            .take(MAX_SELECTOR_TRAILING_BYTES + 1)
            .read_to_end(&mut trailing)
            .map_err(|_| AdapterError::ProtocolFailure)?;
        if u64::try_from(trailing.len()).map_err(|_| AdapterError::ProtocolFailure)?
            > MAX_SELECTOR_TRAILING_BYTES
        {
            return Err(AdapterError::ProtocolFailure);
        }
        decode_reply(
            &control,
            &trailing,
            request,
            evr1_digest,
            attempt.budget.output_bytes,
        )
    }
}

impl SubjectAdapter for SelectorAdapter {
    fn kind(&self) -> SubjectAdapterKind {
        self.kind
    }

    fn subject_artifact_digest(&self) -> [u8; 32] {
        self.subject_artifact_digest
    }

    fn set_case_ordinal(&mut self, ordinal: u16) {
        self.next_case_ordinal = Some(ordinal);
    }

    fn execute(&mut self, attempt: &CaseAttempt) -> Result<SubjectObservation, AdapterError> {
        self.invoke(attempt)
    }

    fn take_execution_provenance_digest(&mut self) -> Option<[u8; 32]> {
        self.provenance.take()
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

fn connect_at(path: &Path, expected_uid: u32) -> Result<UnixStream, SelectorBoundaryError> {
    let path = PathBuf::from(path);
    let before =
        std::fs::symlink_metadata(&path).map_err(|_| SelectorBoundaryError::SelectorUnavailable)?;
    if !before.file_type().is_socket()
        || before.uid() != expected_uid
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
    if credentials.uid.as_raw() != expected_uid
        || before.dev() != after.dev()
        || before.ino() != after.ino()
    {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::net::UnixListener;

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

    #[test]
    fn selector_transport_rejects_missing_wrong_type_mode_and_owner(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let missing = temporary.path().join("missing.sock");
        assert_eq!(
            connect_at(&missing, 0).map(|_| ()),
            Err(SelectorBoundaryError::SelectorUnavailable)
        );

        let regular = temporary.path().join("regular");
        std::fs::write(&regular, b"not a socket")?;
        assert_eq!(
            connect_at(&regular, 0).map(|_| ()),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );

        let socket = temporary.path().join("selector.sock");
        let listener = UnixListener::bind(&socket)?;
        let uid = std::fs::metadata(&socket)?.uid();
        assert_eq!(
            connect_at(&socket, uid).map(|_| ()),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
        assert_eq!(
            connect_at(&socket, uid.wrapping_add(1)).map(|_| ()),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        drop(listener);
        Ok(())
    }
}
