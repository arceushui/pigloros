//! Root-owned immutable artifact and selector-socket boundary.

pub mod installation;

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use rustix::fd::AsFd;
use rustix::fs::{openat2, Mode, OFlags, ResolveFlags};
use rustix::net::sockopt::socket_peercred;

use crate::evaluator::{
    AdapterError, AuthenticatedSandboxProvenance, CaseAttempt, SubjectAdapter, SubjectObservation,
};
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

struct AttemptDeadline {
    expires_at: Instant,
}

impl AttemptDeadline {
    fn new(watchdog_ms: u64) -> Result<Self, AdapterError> {
        let expires_at = Instant::now()
            .checked_add(Duration::from_millis(watchdog_ms))
            .ok_or(AdapterError::ProtocolFailure)?;
        Ok(Self { expires_at })
    }

    fn remaining(&self) -> Result<Duration, AdapterError> {
        self.expires_at
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(AdapterError::WatchdogExpired)
    }

    fn write_all(&self, stream: &mut UnixStream, mut bytes: &[u8]) -> Result<(), AdapterError> {
        while !bytes.is_empty() {
            stream
                .set_write_timeout(Some(self.remaining()?))
                .map_err(|_| AdapterError::ProtocolFailure)?;
            let written = stream.write(bytes).map_err(|error| map_timed_io(&error))?;
            if written == 0 {
                return Err(AdapterError::ProtocolFailure);
            }
            bytes = &bytes[written..];
        }
        Ok(())
    }

    fn read_exact(
        &self,
        stream: &mut UnixStream,
        mut bytes: &mut [u8],
    ) -> Result<(), AdapterError> {
        while !bytes.is_empty() {
            stream
                .set_read_timeout(Some(self.remaining()?))
                .map_err(|_| AdapterError::ProtocolFailure)?;
            let read = stream.read(bytes).map_err(|error| map_timed_io(&error))?;
            if read == 0 {
                return Err(AdapterError::ProtocolFailure);
            }
            bytes = &mut bytes[read..];
        }
        Ok(())
    }

    fn read_to_end_bounded(
        &self,
        stream: &mut UnixStream,
        maximum: u64,
    ) -> Result<Vec<u8>, AdapterError> {
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 8192];
        loop {
            stream
                .set_read_timeout(Some(self.remaining()?))
                .map_err(|_| AdapterError::ProtocolFailure)?;
            let read = stream
                .read(&mut chunk)
                .map_err(|error| map_timed_io(&error))?;
            if read == 0 {
                return Ok(bytes);
            }
            bytes.extend_from_slice(&chunk[..read]);
            if bytes.len() as u64 > maximum {
                return Err(AdapterError::ProtocolFailure);
            }
        }
    }
}

fn map_timed_io(error: &std::io::Error) -> AdapterError {
    if matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ) {
        AdapterError::WatchdogExpired
    } else {
        AdapterError::ProtocolFailure
    }
}

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
    provenance: Option<AuthenticatedSandboxProvenance>,
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
        self.invoke_with_selector(attempt, Path::new(SANDBOX_SELECTOR_SOCKET), 0)
    }

    fn invoke_with_selector(
        &mut self,
        attempt: &CaseAttempt,
        socket_path: &Path,
        expected_uid: u32,
    ) -> Result<SubjectObservation, AdapterError> {
        let ordinal = self
            .next_case_ordinal
            .take()
            .ok_or(AdapterError::ProtocolFailure)?;
        let request = encode_request(&self.request, &self.request_bytes, attempt, ordinal)?;
        let reply = Self::invoke_at(
            socket_path,
            expected_uid,
            attempt,
            &request,
            self.request.request_digest,
        )?;
        self.provenance = reply
            .provenance
            .and_then(AuthenticatedSandboxProvenance::from_validated_receipt);
        reply.observation
    }

    fn invoke_at(
        socket_path: &Path,
        expected_uid: u32,
        attempt: &CaseAttempt,
        request: &EncodedSelectorRequest,
        evr1_digest: [u8; 32],
    ) -> Result<crate::selector_protocol::DecodedSelectorReply, AdapterError> {
        if socket_path == Path::new(SANDBOX_SELECTOR_SOCKET) {
            // Root may administer these directories (including 0755), but an
            // unprivileged evaluator must not be able to replace their entries.
            let root = File::open("/").map_err(|_| AdapterError::Unavailable)?;
            let parent = socket_path
                .parent()
                .and_then(|parent| parent.strip_prefix("/").ok())
                .ok_or(AdapterError::Unavailable)?;
            validate_socket_directory(&root, parent, 0).map_err(|_| AdapterError::Unavailable)?;
        }
        let mut stream =
            connect_at(socket_path, expected_uid).map_err(|_| AdapterError::Unavailable)?;
        let deadline = AttemptDeadline::new(attempt.watchdog_ms)?;
        let control_length =
            u32::try_from(request.control.len()).map_err(|_| AdapterError::ProtocolFailure)?;
        deadline.write_all(&mut stream, &control_length.to_be_bytes())?;
        deadline.write_all(&mut stream, &request.control)?;
        deadline.write_all(&mut stream, &request.attempt_stream)?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|_| AdapterError::ProtocolFailure)?;
        let mut prefix = [0; 4];
        deadline.read_exact(&mut stream, &mut prefix)?;
        let length = usize::try_from(u32::from_be_bytes(prefix))
            .map_err(|_| AdapterError::ProtocolFailure)?;
        if length == 0 || length > 16 * 1024 * 1024 {
            return Err(AdapterError::ProtocolFailure);
        }
        let mut control = vec![0; length];
        deadline.read_exact(&mut stream, &mut control)?;
        let trailing = deadline.read_to_end_bounded(&mut stream, MAX_SELECTOR_TRAILING_BYTES)?;
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

    fn take_execution_provenance(&mut self) -> Option<AuthenticatedSandboxProvenance> {
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
    let relative_root = root
        .strip_prefix(Path::new("/"))
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    let filesystem_root = File::open("/").map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    let root = openat2(
        &filesystem_root,
        relative_root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map(File::from)
    .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
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
    let mut hasher = blake3::Hasher::new();
    let observed_length = std::io::copy(&mut (&mut file).take(metadata.len() + 1), &mut hasher)
        .map_err(|_| SelectorBoundaryError::Io)?;
    if observed_length != metadata.len() || hasher.finalize().as_bytes() != &digest {
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
    connect_at_with(path, expected_uid, connect_unix)
}

fn validate_socket_directory(
    root: &File,
    relative: &Path,
    expected_uid: u32,
) -> Result<(), SelectorBoundaryError> {
    let mut directory = root
        .try_clone()
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
    for component in std::iter::once(Component::CurDir).chain(relative.components()) {
        if component != Component::CurDir {
            let Component::Normal(name) = component else {
                return Err(SelectorBoundaryError::ArtifactInvalid);
            };
            directory = openat2(
                &directory,
                name,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            )
            .map(File::from)
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        }
        let metadata = directory
            .metadata()
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        if !metadata.is_dir() || metadata.uid() != expected_uid || metadata.mode() & 0o022 != 0 {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
    }
    Ok(())
}

fn connect_unix(path: &Path) -> std::io::Result<UnixStream> {
    UnixStream::connect(path)
}

fn connect_at_with(
    path: &Path,
    expected_uid: u32,
    connect: impl FnOnce(&Path) -> std::io::Result<UnixStream>,
) -> Result<UnixStream, SelectorBoundaryError> {
    let path = PathBuf::from(path);
    let before =
        std::fs::symlink_metadata(&path).map_err(|_| SelectorBoundaryError::SelectorUnavailable)?;
    if !before.file_type().is_socket()
        || before.uid() != expected_uid
        || before.mode() & 0o777 != SELECTOR_SOCKET_MODE
    {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    let stream = connect(&path).map_err(|_| SelectorBoundaryError::SelectorUnavailable)?;
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
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::os::fd::OwnedFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::net::UnixListener;
    use std::thread;

    use super::*;

    fn selector_request() -> EvaluationRequest {
        use crate::evaluator_protocol::{
            ImplementationIdentity, OutputCapability, SubjectAdapterKind,
        };

        EvaluationRequest {
            request_id: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0],
            profile_digest: [2; 32],
            fixture_bundle_digest: [3; 32],
            subject_adapter: SubjectAdapterKind::PublicPluginProtocol,
            subject_artifact_digest: [4; 32],
            implementation: ImplementationIdentity {
                implementation_id: "subject".to_owned(),
                source_digest: [5; 32],
                build_digest: [6; 32],
                binary_digest: [7; 32],
                public_contract_digest: [8; 32],
                organization_id: None,
            },
            execution_profile_digest: [9; 32],
            trust_policy_snapshot_digest: [10; 32],
            output_capability: OutputCapability {
                capability_digest: [11; 32],
                report_bytes_limit: 1,
                diagnostic_bytes_limit: 0,
            },
            evaluator_protocol_digest: [12; 32],
            evaluator_hard_caps_digest: [13; 32],
            sandbox_requirement: None,
            request_digest: [14; 32],
        }
    }

    fn selector_attempt() -> CaseAttempt {
        use crate::evaluator::{AttemptArtifact, AttemptTransportCaps};
        use crate::profile::DeterministicBudget;

        let artifact = |bytes: Vec<u8>| AttemptArtifact {
            digest: *blake3::hash(&bytes).as_bytes(),
            bytes,
        };
        CaseAttempt {
            case_id: "case".to_owned(),
            claim_layer: 1,
            family: 1,
            mode: 1,
            fixture_digest: [15; 32],
            schema: artifact(vec![1]),
            payload: artifact(vec![2]),
            auxiliary: Vec::new(),
            budget: DeterministicBudget {
                memory_bytes: 1,
                cpu_fuel: 1,
                host_calls: 1,
                event_count: 1,
                output_bytes: 1024,
                storage_bytes: 1,
                execution_steps: 1,
                simulation_time_ns: 1,
            },
            watchdog_ms: 1_000,
            network_allowed: false,
            capability_ids: vec!["execute".to_owned()],
            transport_caps: AttemptTransportCaps {
                max_member_bytes: 1024,
                max_attempt_bytes: 4096,
            },
        }
    }

    fn local_unavailable() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let value = ciborium::value::Value::Array(vec![
            ciborium::value::Value::Text("SLE1".to_owned()),
            ciborium::value::Value::Integer(1_u64.into()),
            ciborium::value::Value::Integer(0_u64.into()),
            ciborium::value::Value::Null,
            ciborium::value::Value::Null,
            ciborium::value::Value::Null,
            ciborium::value::Value::Null,
            ciborium::value::Value::Integer(2_u64.into()),
            ciborium::value::Value::Null,
        ]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&value, &mut bytes)?;
        Ok(bytes)
    }

    fn invoke_with_framed_reply(
        declared_length: u32,
        control: Vec<u8>,
        trailing: Vec<u8>,
    ) -> Result<crate::selector_protocol::DecodedSelectorReply, AdapterError> {
        let temporary = tempfile::tempdir().map_err(|_| AdapterError::ProtocolFailure)?;
        let socket = temporary.path().join("selector.sock");
        let listener = UnixListener::bind(&socket).map_err(|_| AdapterError::ProtocolFailure)?;
        std::fs::set_permissions(
            &socket,
            std::fs::Permissions::from_mode(SELECTOR_SOCKET_MODE),
        )
        .map_err(|_| AdapterError::ProtocolFailure)?;
        let uid = std::fs::metadata(&socket)
            .map_err(|_| AdapterError::ProtocolFailure)?
            .uid();
        let server = thread::spawn(move || -> std::io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut request = Vec::new();
            stream.read_to_end(&mut request)?;
            stream.write_all(&declared_length.to_be_bytes())?;
            stream.write_all(&control)?;
            stream.write_all(&trailing)
        });
        let request = selector_request();
        let attempt = selector_attempt();
        let encoded = encode_request(&request, b"evr1", &attempt, 0)?;
        let result = SelectorAdapter::invoke_at(&socket, uid, &attempt, &encoded, [14; 32]);
        server
            .join()
            .map_err(|_| AdapterError::ProtocolFailure)?
            .map_err(|_| AdapterError::ProtocolFailure)?;
        result
    }

    fn invoke_with_reply(
        control: Vec<u8>,
        trailing: Vec<u8>,
    ) -> Result<crate::selector_protocol::DecodedSelectorReply, AdapterError> {
        let declared_length =
            u32::try_from(control.len()).map_err(|_| AdapterError::ProtocolFailure)?;
        invoke_with_framed_reply(declared_length, control, trailing)
    }

    #[test]
    fn immutable_artifact_retains_verified_descriptor() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path();
        let provider_directory = root.join("providers");
        std::fs::create_dir(&provider_directory)?;
        let payload = vec![0x5a; 128 * 1024 + 7];
        let digest = *blake3::hash(&payload).as_bytes();
        let path = provider_directory.join(digest_name(digest));
        std::fs::write(&path, &payload)?;
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
    fn immutable_artifact_reports_a_retained_descriptor_read_failure(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let artifact = ImmutableSandboxArtifact {
            file: File::open(temporary.path())?,
            digest: [1; 32],
            length: 0,
        };
        assert_eq!(artifact.read_bytes(), Err(SelectorBoundaryError::Io));
        let (stream, _peer) = UnixStream::pair()?;
        let artifact = ImmutableSandboxArtifact {
            file: File::from(OwnedFd::from(stream)),
            digest: [1; 32],
            length: 0,
        };
        assert_eq!(artifact.read_bytes(), Err(SelectorBoundaryError::Io));
        Ok(())
    }

    #[test]
    fn artifact_kind_directories_are_closed_and_stable() {
        assert_eq!(SandboxArtifactKind::Authority.directory(), "authority");
        assert_eq!(SandboxArtifactKind::Provider.directory(), "providers");
        assert_eq!(SandboxArtifactKind::Image.directory(), "images");
    }

    #[test]
    fn immutable_artifact_rejects_invalid_path_components() -> Result<(), Box<dyn std::error::Error>>
    {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path();
        let uid = std::fs::metadata(root)?.uid();
        assert_eq!(
            open_under(
                Path::new("relative-root"),
                SandboxArtifactKind::Authority,
                [1; 32],
                uid
            )
            .map(|_| ()),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        assert_eq!(
            open_under(
                &root.join("missing"),
                SandboxArtifactKind::Authority,
                [1; 32],
                uid
            )
            .map(|_| ()),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        assert_eq!(
            open_under(
                root,
                SandboxArtifactKind::Authority,
                [1; 32],
                uid.wrapping_add(1)
            )
            .map(|_| ()),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );

        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o500))?;
        assert_eq!(
            open_under(root, SandboxArtifactKind::Authority, [1; 32], uid).map(|_| ()),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
        let authority = root.join("authority");
        std::fs::create_dir(&authority)?;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o500))?;
        assert_eq!(
            open_under(root, SandboxArtifactKind::Authority, [1; 32], uid).map(|_| ()),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        std::fs::set_permissions(&authority, std::fs::Permissions::from_mode(0o500))?;
        assert_eq!(
            open_under(root, SandboxArtifactKind::Authority, [1; 32], uid).map(|_| ()),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        std::fs::set_permissions(&authority, std::fs::Permissions::from_mode(0o700))?;
        let digest_path = authority.join(digest_name([1; 32]));
        std::fs::create_dir(&digest_path)?;
        std::fs::set_permissions(&authority, std::fs::Permissions::from_mode(0o500))?;
        assert_eq!(
            open_under(root, SandboxArtifactKind::Authority, [1; 32], uid).map(|_| ()),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
        std::fs::set_permissions(&authority, std::fs::Permissions::from_mode(0o700))?;
        std::fs::remove_dir(&digest_path)?;
        Ok(())
    }

    #[test]
    fn selector_deadline_rejects_oversized_trailing_bytes() -> Result<(), Box<dyn std::error::Error>>
    {
        let (mut reader, mut writer) = UnixStream::pair()?;
        writer.write_all(b"too large")?;
        writer.shutdown(std::net::Shutdown::Write)?;

        let deadline = AttemptDeadline::new(1_000)?;
        assert_eq!(
            deadline.read_to_end_bounded(&mut reader, 1),
            Err(AdapterError::ProtocolFailure)
        );
        Ok(())
    }

    #[test]
    fn selector_deadline_propagates_each_expired_io_phase() -> Result<(), Box<dyn std::error::Error>>
    {
        let (mut stream, _peer) = UnixStream::pair()?;
        let expired = AttemptDeadline {
            expires_at: Instant::now(),
        };
        assert_eq!(
            expired.write_all(&mut stream, b"request"),
            Err(AdapterError::WatchdogExpired)
        );
        assert_eq!(
            expired.read_exact(&mut stream, &mut [0]),
            Err(AdapterError::WatchdogExpired)
        );
        assert_eq!(
            expired.read_to_end_bounded(&mut stream, 1),
            Err(AdapterError::WatchdogExpired)
        );

        let (mut closed_stream, peer) = UnixStream::pair()?;
        drop(peer);
        assert_eq!(
            AttemptDeadline::new(1_000)?.write_all(&mut closed_stream, b"request"),
            Err(AdapterError::ProtocolFailure)
        );
        Ok(())
    }

    #[test]
    fn immutable_artifact_rejects_a_symlinked_store_root() -> Result<(), Box<dyn std::error::Error>>
    {
        let target = tempfile::tempdir()?;
        let authority = target.path().join("authority");
        std::fs::create_dir(&authority)?;
        let payload = b"authority";
        let digest = *blake3::hash(payload).as_bytes();
        let artifact = authority.join(digest_name(digest));
        std::fs::write(&artifact, payload)?;
        std::fs::set_permissions(&artifact, std::fs::Permissions::from_mode(0o400))?;
        std::fs::set_permissions(&authority, std::fs::Permissions::from_mode(0o500))?;
        std::fs::set_permissions(target.path(), std::fs::Permissions::from_mode(0o500))?;
        let uid = std::fs::metadata(target.path())?.uid();

        let parent = tempfile::tempdir()?;
        let linked_root = parent.path().join("sandbox");
        std::os::unix::fs::symlink(target.path(), &linked_root)?;
        assert_eq!(
            open_under(&linked_root, SandboxArtifactKind::Authority, digest, uid).map(|_| ()),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );

        std::fs::set_permissions(target.path(), std::fs::Permissions::from_mode(0o700))?;
        std::fs::set_permissions(&authority, std::fs::Permissions::from_mode(0o700))?;
        std::fs::set_permissions(&artifact, std::fs::Permissions::from_mode(0o600))?;
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
    fn fixed_artifact_root_rejects_an_uninstalled_digest() {
        assert_eq!(
            ImmutableSandboxArtifact::open(SandboxArtifactKind::Provider, [0; 32]).map(|_| ()),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
    }

    #[test]
    fn selector_directory_accepts_owner_writable_ancestry() -> Result<(), Box<dyn std::error::Error>>
    {
        let temporary = tempfile::tempdir()?;
        let ancestor = temporary.path().join("run");
        let parent = ancestor.join("pigloros");
        std::fs::create_dir_all(&parent)?;
        let root = File::open(temporary.path())?;
        let uid = root.metadata()?.uid();
        for mode in [0o700, 0o755, 0o555] {
            for directory in [temporary.path(), ancestor.as_path(), parent.as_path()] {
                std::fs::set_permissions(directory, std::fs::Permissions::from_mode(mode))?;
            }
            assert_eq!(
                validate_socket_directory(&root, Path::new("run/pigloros"), uid),
                Ok(())
            );
        }
        for directory in [temporary.path(), ancestor.as_path(), parent.as_path()] {
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }

    #[test]
    fn selector_directory_rejects_writable_ancestry_and_wrong_owner(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let ancestor = temporary.path().join("run");
        let parent = ancestor.join("pigloros");
        std::fs::create_dir_all(&parent)?;
        let root = File::open(temporary.path())?;
        let uid = root.metadata()?.uid();
        for directory in [temporary.path(), ancestor.as_path(), parent.as_path()] {
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
        }
        for directory in [temporary.path(), ancestor.as_path(), parent.as_path()] {
            for mode in [0o720, 0o702, 0o1777] {
                std::fs::set_permissions(directory, std::fs::Permissions::from_mode(mode))?;
                assert_eq!(
                    validate_socket_directory(&root, Path::new("run/pigloros"), uid),
                    Err(SelectorBoundaryError::ArtifactInvalid)
                );
            }
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
        }
        assert_eq!(
            validate_socket_directory(&root, Path::new("run/pigloros"), uid.wrapping_add(1)),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        Ok(())
    }

    #[test]
    fn selector_directory_rejects_symlinks_and_invalid_components(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let ancestor = temporary.path().join("run");
        let parent = ancestor.join("pigloros");
        std::fs::create_dir_all(&parent)?;
        let root = File::open(temporary.path())?;
        let uid = root.metadata()?.uid();
        std::os::unix::fs::symlink("run", temporary.path().join("linked-run"))?;
        std::os::unix::fs::symlink("pigloros", ancestor.join("linked-parent"))?;
        std::fs::write(temporary.path().join("regular"), b"not a directory")?;
        for relative in [
            "linked-run/pigloros",
            "run/linked-parent",
            "missing",
            "regular",
            "../run",
            "/run",
        ] {
            assert_eq!(
                validate_socket_directory(&root, Path::new(relative), uid),
                Err(SelectorBoundaryError::ArtifactInvalid)
            );
        }
        let regular = File::open(temporary.path().join("regular"))?;
        assert_eq!(
            validate_socket_directory(&regular, Path::new(""), uid),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
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
        assert_eq!(
            connect_at(&socket, uid).map(|_| ()),
            Err(SelectorBoundaryError::SelectorUnavailable)
        );
        Ok(())
    }

    #[test]
    fn selector_transport_rejects_endpoint_removal_and_replacement(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for replace in [false, true] {
            let temporary = tempfile::tempdir()?;
            let socket = temporary.path().join("selector.sock");
            let listener = UnixListener::bind(&socket)?;
            std::fs::set_permissions(
                &socket,
                std::fs::Permissions::from_mode(SELECTOR_SOCKET_MODE),
            )?;
            let uid = std::fs::metadata(&socket)?.uid();
            let result = connect_at_with(&socket, uid, |path| {
                let stream = UnixStream::connect(path)?;
                std::fs::remove_file(path)?;
                if replace {
                    let replacement = UnixListener::bind(path)?;
                    drop(replacement);
                }
                Ok(stream)
            });
            let expected = if replace {
                SelectorBoundaryError::ArtifactInvalid
            } else {
                SelectorBoundaryError::SelectorUnavailable
            };
            assert_eq!(result.map(|_| ()), Err(expected));
            drop(listener);
        }
        Ok(())
    }

    #[test]
    fn selector_request_rejects_a_zero_watchdog_before_exchange() {
        let request = selector_request();
        let mut attempt = selector_attempt();
        attempt.watchdog_ms = 0;
        assert!(matches!(
            encode_request(&request, b"evr1", &attempt, 0),
            Err(AdapterError::ProtocolFailure)
        ));
    }

    #[test]
    fn selector_transport_rejects_a_peer_that_closes_without_a_reply(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let socket = temporary.path().join("selector.sock");
        let listener = UnixListener::bind(&socket)?;
        std::fs::set_permissions(
            &socket,
            std::fs::Permissions::from_mode(SELECTOR_SOCKET_MODE),
        )?;
        let uid = std::fs::metadata(&socket)?.uid();
        let server = thread::spawn(move || -> std::io::Result<()> {
            let (stream, _) = listener.accept()?;
            drop(stream);
            Ok(())
        });
        let request = selector_request();
        let attempt = selector_attempt();
        let encoded = encode_request(&request, b"evr1", &attempt, 0)?;
        assert_eq!(
            SelectorAdapter::invoke_at(&socket, uid, &attempt, &encoded, [14; 32]),
            Err(AdapterError::ProtocolFailure)
        );
        server.join().map_err(|_| AdapterError::ProtocolFailure)??;
        Ok(())
    }

    #[test]
    fn selector_watchdog_is_one_absolute_exchange_deadline(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let socket = temporary.path().join("selector.sock");
        let listener = UnixListener::bind(&socket)?;
        std::fs::set_permissions(
            &socket,
            std::fs::Permissions::from_mode(SELECTOR_SOCKET_MODE),
        )?;
        let uid = std::fs::metadata(&socket)?.uid();
        let server = thread::spawn(move || -> std::io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut request = Vec::new();
            stream.read_to_end(&mut request)?;
            for byte in 1_u32.to_be_bytes() {
                if stream.write_all(&[byte]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
            Ok(())
        });
        let request = selector_request();
        let mut attempt = selector_attempt();
        attempt.watchdog_ms = 35;
        let encoded = encode_request(&request, b"evr1", &attempt, 0)?;
        assert_eq!(
            SelectorAdapter::invoke_at(&socket, uid, &attempt, &encoded, [14; 32]),
            Err(AdapterError::WatchdogExpired)
        );
        server.join().map_err(|_| AdapterError::ProtocolFailure)??;
        Ok(())
    }

    #[test]
    fn selector_transport_rejects_a_peer_that_never_finishes_its_reply(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let socket = temporary.path().join("selector.sock");
        let listener = UnixListener::bind(&socket)?;
        std::fs::set_permissions(
            &socket,
            std::fs::Permissions::from_mode(SELECTOR_SOCKET_MODE),
        )?;
        let uid = std::fs::metadata(&socket)?.uid();
        let control = local_unavailable()?;
        let control_length = u32::try_from(control.len())?;
        let server = thread::spawn(move || -> std::io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut request = Vec::new();
            stream.read_to_end(&mut request)?;
            stream.write_all(&control_length.to_be_bytes())?;
            stream.write_all(&control)?;
            thread::sleep(Duration::from_millis(250));
            Ok(())
        });
        let request = selector_request();
        let mut attempt = selector_attempt();
        attempt.watchdog_ms = 50;
        let encoded = encode_request(&request, b"evr1", &attempt, 0)?;
        assert_eq!(
            SelectorAdapter::invoke_at(&socket, uid, &attempt, &encoded, [14; 32]),
            Err(AdapterError::WatchdogExpired)
        );
        server.join().map_err(|_| AdapterError::ProtocolFailure)??;
        Ok(())
    }

    #[test]
    fn selector_adapter_requires_an_explicit_case_ordinal() {
        let request = selector_request();
        let mut adapter = SelectorAdapter::new(&request, b"evr1");
        assert_eq!(adapter.kind(), request.subject_adapter);
        assert_eq!(
            adapter.subject_artifact_digest(),
            request.subject_artifact_digest
        );
        assert_eq!(
            adapter.execute(&selector_attempt()),
            Err(AdapterError::ProtocolFailure)
        );
        let mut invalid = selector_attempt();
        invalid.case_id.clear();
        adapter.set_case_ordinal(0);
        assert_eq!(
            adapter.invoke_with_selector(&invalid, Path::new("/missing"), 0),
            Err(AdapterError::ProtocolFailure)
        );
        assert_eq!(adapter.take_execution_provenance(), None);
    }

    #[test]
    fn selector_transport_exchanges_a_bounded_local_failure(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let reply = invoke_with_reply(local_unavailable()?, Vec::new())?;
        assert_eq!(reply.observation, Err(AdapterError::Unavailable));
        assert_eq!(reply.provenance, None);
        Ok(())
    }

    #[test]
    fn selector_adapter_retains_reply_state_through_the_endpoint_seam(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let socket = temporary.path().join("selector.sock");
        let listener = UnixListener::bind(&socket)?;
        std::fs::set_permissions(
            &socket,
            std::fs::Permissions::from_mode(SELECTOR_SOCKET_MODE),
        )?;
        let uid = std::fs::metadata(&socket)?.uid();
        let control = local_unavailable()?;
        let control_length = u32::try_from(control.len())?;
        let server = thread::spawn(move || -> std::io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut request = Vec::new();
            stream.read_to_end(&mut request)?;
            stream.write_all(&control_length.to_be_bytes())?;
            stream.write_all(&control)
        });
        let request = selector_request();
        let attempt = selector_attempt();
        let mut adapter = SelectorAdapter::new(&request, b"evr1");
        adapter.set_case_ordinal(7);
        assert_eq!(
            adapter.invoke_with_selector(&attempt, &socket, uid),
            Err(AdapterError::Unavailable)
        );
        assert_eq!(adapter.take_execution_provenance(), None);
        server.join().map_err(|_| AdapterError::ProtocolFailure)??;
        Ok(())
    }

    #[test]
    fn selector_transport_rejects_empty_and_truncated_control(
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            invoke_with_reply(Vec::new(), Vec::new()),
            Err(AdapterError::ProtocolFailure)
        );
        assert_eq!(
            invoke_with_reply(vec![0xff], Vec::new()),
            Err(AdapterError::ProtocolFailure)
        );
        assert_eq!(
            invoke_with_reply(local_unavailable()?, vec![1]),
            Err(AdapterError::ProtocolFailure)
        );
        assert_eq!(
            invoke_with_framed_reply(1, Vec::new(), Vec::new()),
            Err(AdapterError::ProtocolFailure)
        );
        assert_eq!(
            invoke_with_framed_reply(16 * 1024 * 1024 + 1, Vec::new(), Vec::new()),
            Err(AdapterError::ProtocolFailure)
        );
        Ok(())
    }
}
