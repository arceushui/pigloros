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

    fn invoke_with_reply(
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
            let length = u32::try_from(control.len())
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
            stream.write_all(&length.to_be_bytes())?;
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

        let authority = root.join("authority");
        std::fs::create_dir(&authority)?;
        assert_eq!(
            open_under(root, SandboxArtifactKind::Authority, [1; 32], uid).map(|_| ()),
            Err(SelectorBoundaryError::ArtifactInvalid)
        );
        std::fs::set_permissions(&authority, std::fs::Permissions::from_mode(0o500))?;
        let digest_path = authority.join(digest_name([1; 32]));
        std::fs::create_dir(&digest_path)?;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o500))?;
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
        assert_eq!(adapter.take_execution_provenance_digest(), None);
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
        Ok(())
    }
}
