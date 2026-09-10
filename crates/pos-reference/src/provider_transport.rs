//! Bounded root-to-provider execute transport for the ADR-069 record stream.

use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ciborium::value::Value;
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::net::sockopt::socket_error;
use rustix::net::sockopt::socket_peercred;
use rustix::net::{connect, socket_with, AddressFamily, SocketAddrUnix, SocketFlags, SocketType};

use crate::root_selector::{
    RootSelectorProvider, RootSelectorProviderReply, RootSelectorServiceError,
};
use crate::sandbox_provider_protocol::{
    PayloadDescriptor, PayloadDirection, PayloadStreamValidator, RootSelectorAdmission,
    SandboxExecuteRequest, SandboxPayloadChunk, SandboxProviderError, SandboxProviderReceipt,
    SandboxProviderResult, SandboxTerminalOutcome,
};

const CONTROL_LIMIT: usize = 16 * 1024 * 1024;
const CHUNK_BYTES: usize = 1024 * 1024;
const MAX_AUDIT_RECORDS: usize = 256;
const ROOT_UID: u32 = 0;
const MAX_PAYLOAD_BYTES: u64 = 128 * 1024 * 1024;

/// A verified, root-owned staged EAO1 stream. Its bytes are never materialized
/// as one receiver-owned allocation.
#[derive(Debug)]
pub struct StagedOutput {
    file: tempfile::NamedTempFile,
    descriptor: PayloadDescriptor,
}

impl StagedOutput {
    const fn new(file: tempfile::NamedTempFile, descriptor: PayloadDescriptor) -> Self {
        Self { file, descriptor }
    }

    /// The authenticated output descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &PayloadDescriptor {
        &self.descriptor
    }

    /// Copy the staged output only after the caller has authenticated all
    /// provider lifecycle evidence.
    ///
    /// # Errors
    /// Returns a closed I/O failure when staging or destination I/O fails.
    pub fn copy_to(&mut self, writer: &mut impl Write) -> Result<(), RootSelectorServiceError> {
        let file = self.file.as_file_mut();
        file.seek(SeekFrom::Start(0))
            .or(Err(RootSelectorServiceError::Io))?;
        let mut buffer = [0_u8; 8192];
        loop {
            let read = file
                .read(&mut buffer)
                .or(Err(RootSelectorServiceError::Io))?;
            if read == 0 {
                return Ok(());
            }
            writer
                .write_all(&buffer[..read])
                .or(Err(RootSelectorServiceError::Io))?;
        }
    }

    /// Incrementally stage bytes that exactly match a bounded descriptor.
    ///
    /// # Errors
    /// Rejects oversized, short, trailing, or digest-mismatched input.
    pub fn stage_verified(
        reader: &mut impl Read,
        descriptor: PayloadDescriptor,
    ) -> Result<Self, RootSelectorServiceError> {
        if descriptor.byte_length > MAX_PAYLOAD_BYTES {
            return Err(RootSelectorServiceError::ProviderEvidence);
        }
        let mut file = tempfile::NamedTempFile::new().or(Err(RootSelectorServiceError::Io))?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"PiglorOS.SandboxOutputBytes.v1\0");
        let mut remaining = descriptor.byte_length;
        let mut buffer = [0_u8; 8192];
        while remaining != 0 {
            let maximum = usize::try_from(remaining.min(buffer.len() as u64))
                .or(Err(RootSelectorServiceError::ProviderEvidence))?;
            let read = reader
                .read(&mut buffer[..maximum])
                .or(Err(RootSelectorServiceError::Io))?;
            if read == 0 {
                return Err(RootSelectorServiceError::ProviderEvidence);
            }
            hasher.update(&buffer[..read]);
            file.write_all(&buffer[..read])
                .or(Err(RootSelectorServiceError::Io))?;
            remaining -= read as u64;
        }
        let mut trailing = [0_u8; 1];
        if reader
            .read(&mut trailing)
            .or(Err(RootSelectorServiceError::Io))?
            != 0
            || *hasher.finalize().as_bytes() != descriptor.digest
        {
            return Err(RootSelectorServiceError::ProviderEvidence);
        }
        Ok(Self::new(file, descriptor))
    }
}

/// A trusted connector is an internal seam for deterministic transport tests.
/// Production obtains it only from a validated root-owned endpoint.
pub trait ProviderConnector {
    /// Connect one fresh execute stream.
    ///
    /// # Errors
    /// Returns a closed failure when the provider cannot be connected.
    fn connect(&mut self, timeout: Duration) -> Result<UnixStream, RootSelectorServiceError>;
}

/// Immutable selected execute endpoint validated before it becomes usable.
#[derive(Clone, Debug)]
pub struct SelectedProviderEndpoint {
    path: PathBuf,
    device: u64,
    inode: u64,
    owner_uid: u32,
}

impl SelectedProviderEndpoint {
    /// Validate a root-owned provider endpoint selected by installation state.
    ///
    /// # Errors
    /// Rejects an insecure, non-root-owned, non-socket, or unstable endpoint.
    pub fn validate(path: &Path) -> Result<Self, RootSelectorServiceError> {
        if !path.is_absolute() || !root_owned_ancestors(path) {
            return Err(RootSelectorServiceError::ProviderUnavailable);
        }
        Self::from_verified_ancestry(path, ROOT_UID)
    }

    fn from_verified_ancestry(
        path: &Path,
        owner_uid: u32,
    ) -> Result<Self, RootSelectorServiceError> {
        let metadata = std::fs::symlink_metadata(path)
            .or(Err(RootSelectorServiceError::ProviderUnavailable))?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != owner_uid
            || metadata.mode() & 0o7777 != 0o600
        {
            return Err(RootSelectorServiceError::ProviderUnavailable);
        }
        Ok(Self {
            path: path.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
            owner_uid,
        })
    }
}

impl ProviderConnector for SelectedProviderEndpoint {
    fn connect(&mut self, timeout: Duration) -> Result<UnixStream, RootSelectorServiceError> {
        let before = endpoint_metadata(&self.path, self.device, self.inode, self.owner_uid)?;
        let address = SocketAddrUnix::new(&self.path)
            .or(Err(RootSelectorServiceError::ProviderUnavailable))?;
        let fd = socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .or(Err(RootSelectorServiceError::ProviderUnavailable))?;
        if connect(&fd, &address).is_err() {
            let seconds = i64::try_from(timeout.as_secs())
                .or(Err(RootSelectorServiceError::ProviderUnavailable))?;
            let timespec = Timespec {
                tv_sec: seconds,
                tv_nsec: timeout.subsec_nanos().into(),
            };
            let poll_fd = PollFd::new(&fd, PollFlags::OUT);
            if poll(&mut [poll_fd], Some(&timespec))
                .or(Err(RootSelectorServiceError::ProviderUnavailable))?
                == 0
                || socket_error(&fd)
                    .or(Err(RootSelectorServiceError::ProviderUnavailable))?
                    .is_err()
            {
                return Err(RootSelectorServiceError::ProviderUnavailable);
            }
        }
        let stream = UnixStream::from(fd);
        stream
            .set_nonblocking(false)
            .or(Err(RootSelectorServiceError::ProviderUnavailable))?;
        let after = endpoint_metadata(&self.path, self.device, self.inode, self.owner_uid)?;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(RootSelectorServiceError::ProviderUnavailable);
        }
        let peer = socket_peercred(stream.as_fd())
            .or(Err(RootSelectorServiceError::ProviderUnavailable))?;
        if peer.uid.as_raw() != self.owner_uid {
            return Err(RootSelectorServiceError::ProviderUnavailable);
        }
        Ok(stream)
    }
}

/// Concrete execute adapter for the one endpoint selected by root installation.
pub struct ProviderTransport<C = SelectedProviderEndpoint> {
    connector: C,
}

impl ProviderTransport<SelectedProviderEndpoint> {
    /// Bind the production adapter to an already installation-selected endpoint.
    #[must_use]
    pub const fn from_selected_endpoint(endpoint: SelectedProviderEndpoint) -> Self {
        Self {
            connector: endpoint,
        }
    }
}

impl<C> ProviderTransport<C> {
    /// Inject a trusted connector at the transport seam.
    #[must_use]
    pub const fn with_connector(connector: C) -> Self {
        Self { connector }
    }
}

impl<C: ProviderConnector> RootSelectorProvider for ProviderTransport<C> {
    fn execute(
        &mut self,
        request: &SandboxExecuteRequest,
        input_stream: &[u8],
        watchdog: Duration,
        admission: &RootSelectorAdmission,
    ) -> Result<RootSelectorProviderReply, RootSelectorServiceError> {
        let deadline = Deadline::new(watchdog)?;
        let mut retained_grant = None;
        for replay in 0..=1 {
            let result = self.execute_once(
                request,
                input_stream,
                admission,
                &deadline,
                &mut retained_grant,
            );
            match result {
                Ok(reply) => return Ok(reply),
                Err(ReceiveFailure::Invalid) => {
                    return Ok(RootSelectorProviderReply::EvidenceInvalid {
                        agr1_digest: retained_grant.as_ref().map(|grant| grant.digest),
                    });
                }
                Err(ReceiveFailure::Incomplete) if replay == 0 => {}
                Err(ReceiveFailure::Incomplete) => {
                    return Ok(RootSelectorProviderReply::Incomplete {
                        agr1_digest: retained_grant.as_ref().map(|grant| grant.digest),
                    });
                }
            }
        }
        Ok(RootSelectorProviderReply::Incomplete { agr1_digest: None })
    }
}

impl<C: ProviderConnector> ProviderTransport<C> {
    fn execute_once(
        &mut self,
        request: &SandboxExecuteRequest,
        input: &[u8],
        admission: &RootSelectorAdmission,
        deadline: &Deadline,
        retained_grant: &mut Option<RetainedGrant>,
    ) -> Result<RootSelectorProviderReply, ReceiveFailure> {
        let mut stream = self
            .connector
            .connect(deadline.remaining().or(Err(ReceiveFailure::Incomplete))?)
            .or(Err(ReceiveFailure::Incomplete))?;
        write_frame(
            &mut stream,
            &request
                .to_canonical_cbor()
                .or(Err(ReceiveFailure::Invalid))?,
            deadline,
        )?;
        write_input(&mut stream, request, input, deadline)?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .or(Err(ReceiveFailure::Incomplete))?;
        read_response(&mut stream, request, admission, deadline, retained_grant)
    }
}

#[derive(Clone)]
struct RetainedGrant {
    bytes: Vec<u8>,
    digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReceiveFailure {
    Incomplete,
    Invalid,
}

struct Deadline {
    expires_at: Instant,
}

impl Deadline {
    fn new(duration: Duration) -> Result<Self, RootSelectorServiceError> {
        Instant::now()
            .checked_add(duration)
            .map(|expires_at| Self { expires_at })
            .ok_or(RootSelectorServiceError::ProviderUnavailable)
    }

    fn remaining(&self) -> Result<Duration, ReceiveFailure> {
        self.expires_at
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(ReceiveFailure::Incomplete)
    }

    fn set_read(&self, stream: &UnixStream) -> Result<(), ReceiveFailure> {
        stream
            .set_read_timeout(Some(self.remaining()?))
            .or(Err(ReceiveFailure::Incomplete))
    }

    fn set_write(&self, stream: &UnixStream) -> Result<(), ReceiveFailure> {
        stream
            .set_write_timeout(Some(self.remaining()?))
            .or(Err(ReceiveFailure::Incomplete))
    }
}

fn write_input(
    stream: &mut UnixStream,
    request: &SandboxExecuteRequest,
    input: &[u8],
    deadline: &Deadline,
) -> Result<(), ReceiveFailure> {
    if input.len() as u64 != request.adapter_input.byte_length
        || output_digest_with(b"PiglorOS.SandboxInputBytes.v1\0", input)
            != request.adapter_input.digest
    {
        return Err(ReceiveFailure::Invalid);
    }
    for (index, bytes) in input.chunks(CHUNK_BYTES).enumerate() {
        let chunk = encode_chunk(
            request.request_digest,
            request.request.request_id,
            request.attempt_id,
            0,
            index as u64,
            bytes,
        )?;
        write_frame(stream, &chunk, deadline)?;
    }
    Ok(())
}

fn read_response(
    stream: &mut UnixStream,
    request: &SandboxExecuteRequest,
    admission: &RootSelectorAdmission,
    deadline: &Deadline,
    retained_grant: &mut Option<RetainedGrant>,
) -> Result<RootSelectorProviderReply, ReceiveFailure> {
    let Some(first) = read_frame(stream, deadline)? else {
        return Err(ReceiveFailure::Incomplete);
    };
    match record_magic(&first)?.as_str() {
        "SPY1" => {
            ensure_eof(stream, deadline)?;
            Ok(RootSelectorProviderReply::BeforeAdmission { result: first })
        }
        "SPE1" => {
            SandboxProviderError::from_canonical_cbor(&first).or(Err(ReceiveFailure::Invalid))?;
            ensure_eof(stream, deadline)?;
            Ok(RootSelectorProviderReply::Error { error: first })
        }
        "AGR1" => read_admitted(stream, request, admission, deadline, retained_grant, first),
        _ => Err(ReceiveFailure::Invalid),
    }
}

fn read_admitted(
    stream: &mut UnixStream,
    request: &SandboxExecuteRequest,
    admission: &RootSelectorAdmission,
    deadline: &Deadline,
    retained_grant: &mut Option<RetainedGrant>,
    grant: Vec<u8>,
) -> Result<RootSelectorProviderReply, ReceiveFailure> {
    let parsed = admission
        .authenticate_grant(request, &grant)
        .or(Err(ReceiveFailure::Invalid))?;
    let current = RetainedGrant {
        bytes: grant.clone(),
        digest: parsed.grant_digest,
    };
    if retained_grant
        .as_ref()
        .is_some_and(|previous| previous.bytes != current.bytes)
    {
        return Err(ReceiveFailure::Invalid);
    }
    *retained_grant = Some(current);
    let mut audit = Vec::new();
    let receipt = loop {
        let frame = read_frame(stream, deadline)?.ok_or(ReceiveFailure::Incomplete)?;
        match record_magic(&frame)?.as_str() {
            "SAU1" if audit.len() < MAX_AUDIT_RECORDS => audit.push(frame),
            "SPR1" => break frame,
            _ => return Err(ReceiveFailure::Invalid),
        }
    };
    if audit.is_empty() {
        return Err(ReceiveFailure::Invalid);
    }
    SandboxProviderReceipt::from_canonical_cbor(&receipt).or(Err(ReceiveFailure::Invalid))?;
    let mut staged = tempfile::NamedTempFile::new().or(Err(ReceiveFailure::Incomplete))?;
    let mut chunks = Vec::new();
    let result = loop {
        let frame = read_frame(stream, deadline)?.ok_or(ReceiveFailure::Incomplete)?;
        match record_magic(&frame)?.as_str() {
            "SBC1" => {
                let chunk = SandboxPayloadChunk::from_canonical_cbor(&frame)
                    .or(Err(ReceiveFailure::Invalid))?;
                if chunks.len() >= 128 {
                    return Err(ReceiveFailure::Invalid);
                }
                staged
                    .write_all(&chunk.bytes)
                    .or(Err(ReceiveFailure::Incomplete))?;
                chunks.push(ChunkMeta::from(&chunk));
            }
            "SPY1" => break frame,
            _ => return Err(ReceiveFailure::Invalid),
        }
    };
    ensure_eof(stream, deadline)?;
    let parsed_result =
        SandboxProviderResult::from_canonical_cbor(&result).or(Err(ReceiveFailure::Invalid))?;
    let output = stage_output(staged, chunks, request, &parsed_result)?;
    Ok(RootSelectorProviderReply::Admitted {
        grant,
        receipt,
        result,
        audit,
        output,
    })
}

#[derive(Clone)]
struct ChunkMeta {
    parent_digest: [u8; 32],
    request_id: [u8; 16],
    attempt_id: [u8; 16],
    direction: PayloadDirection,
    index: u64,
    offset: u64,
    chunk_digest: [u8; 32],
    length: usize,
}

impl From<&SandboxPayloadChunk> for ChunkMeta {
    fn from(chunk: &SandboxPayloadChunk) -> Self {
        Self {
            parent_digest: chunk.parent_digest,
            request_id: chunk.request_id,
            attempt_id: chunk.attempt_id,
            direction: chunk.direction,
            index: chunk.index,
            offset: chunk.offset,
            chunk_digest: chunk.chunk_digest,
            length: chunk.bytes.len(),
        }
    }
}

fn stage_output(
    mut file: tempfile::NamedTempFile,
    chunks: Vec<ChunkMeta>,
    request: &SandboxExecuteRequest,
    result: &SandboxProviderResult,
) -> Result<Option<StagedOutput>, ReceiveFailure> {
    match (result.outcome, result.output.as_ref()) {
        (SandboxTerminalOutcome::Completed, Some(descriptor)) => {
            let mut validator = PayloadStreamValidator::new(
                result.result_digest,
                request.request.request_id,
                request.attempt_id,
                PayloadDirection::Output,
                descriptor.clone(),
            )
            .or(Err(ReceiveFailure::Invalid))?;
            file.seek(SeekFrom::Start(0))
                .or(Err(ReceiveFailure::Incomplete))?;
            for meta in chunks {
                let mut bytes = vec![0; meta.length];
                file.read_exact(&mut bytes)
                    .or(Err(ReceiveFailure::Incomplete))?;
                validator
                    .accept(&SandboxPayloadChunk {
                        parent_digest: meta.parent_digest,
                        request_id: meta.request_id,
                        attempt_id: meta.attempt_id,
                        direction: meta.direction,
                        index: meta.index,
                        offset: meta.offset,
                        bytes,
                        chunk_digest: meta.chunk_digest,
                    })
                    .or(Err(ReceiveFailure::Invalid))?;
            }
            validator.finish().or(Err(ReceiveFailure::Invalid))?;
            Ok(Some(StagedOutput::new(file, descriptor.clone())))
        }
        (SandboxTerminalOutcome::Completed, None) => Err(ReceiveFailure::Invalid),
        (_, None) if chunks.is_empty() => Ok(None),
        _ => Err(ReceiveFailure::Invalid),
    }
}

fn write_frame(
    stream: &mut UnixStream,
    bytes: &[u8],
    deadline: &Deadline,
) -> Result<(), ReceiveFailure> {
    if bytes.is_empty() || bytes.len() > CONTROL_LIMIT {
        return Err(ReceiveFailure::Invalid);
    }
    deadline.set_write(stream)?;
    let length = u32::try_from(bytes.len()).or(Err(ReceiveFailure::Invalid))?;
    stream
        .write_all(&length.to_be_bytes())
        .or(Err(ReceiveFailure::Incomplete))?;
    deadline.set_write(stream)?;
    stream.write_all(bytes).or(Err(ReceiveFailure::Incomplete))
}

fn read_frame(
    stream: &mut UnixStream,
    deadline: &Deadline,
) -> Result<Option<Vec<u8>>, ReceiveFailure> {
    let mut prefix = [0_u8; 4];
    deadline.set_read(stream)?;
    match stream
        .read(&mut prefix)
        .or(Err(ReceiveFailure::Incomplete))?
    {
        0 => return Ok(None),
        4 => {}
        _ => return Err(ReceiveFailure::Incomplete),
    }
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > CONTROL_LIMIT {
        return Err(ReceiveFailure::Invalid);
    }
    let mut bytes = vec![0; length];
    deadline.set_read(stream)?;
    stream
        .read_exact(&mut bytes)
        .or(Err(ReceiveFailure::Incomplete))?;
    Ok(Some(bytes))
}

fn ensure_eof(stream: &mut UnixStream, deadline: &Deadline) -> Result<(), ReceiveFailure> {
    let mut byte = [0_u8; 1];
    deadline.set_read(stream)?;
    match stream.read(&mut byte).or(Err(ReceiveFailure::Incomplete))? {
        0 => Ok(()),
        _ => Err(ReceiveFailure::Invalid),
    }
}

fn record_magic(bytes: &[u8]) -> Result<String, ReceiveFailure> {
    let value: Value = ciborium::from_reader(bytes).or(Err(ReceiveFailure::Invalid))?;
    let Value::Array(wrapper) = value else {
        return Err(ReceiveFailure::Invalid);
    };
    let Some(Value::Array(unsigned)) = wrapper.first() else {
        return Err(ReceiveFailure::Invalid);
    };
    let Some(Value::Text(magic)) = unsigned.first() else {
        return Err(ReceiveFailure::Invalid);
    };
    Ok(magic.clone())
}

fn encode_chunk(
    parent: [u8; 32],
    request: [u8; 16],
    attempt: [u8; 16],
    direction: u64,
    index: u64,
    bytes: &[u8],
) -> Result<Vec<u8>, ReceiveFailure> {
    let unsigned = Value::Array(vec![
        Value::Text("SBC1".to_owned()),
        Value::Integer(1_u64.into()),
        Value::Bytes(parent.to_vec()),
        Value::Bytes(request.to_vec()),
        Value::Bytes(attempt.to_vec()),
        Value::Integer(direction.into()),
        Value::Integer(index.into()),
        Value::Integer((index * CHUNK_BYTES as u64).into()),
        Value::Bytes(bytes.to_vec()),
    ]);
    let encoded = encode_value(&unsigned)?;
    let digest = output_digest_with(b"PiglorOS.SBC1.v1\0", &encoded);
    encode_value(&Value::Array(vec![unsigned, Value::Bytes(digest.to_vec())]))
}

fn encode_value(value: &Value) -> Result<Vec<u8>, ReceiveFailure> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).or(Err(ReceiveFailure::Invalid))?;
    Ok(bytes)
}

fn output_digest_with(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn endpoint_metadata(
    path: &Path,
    device: u64,
    inode: u64,
    owner_uid: u32,
) -> Result<std::fs::Metadata, RootSelectorServiceError> {
    let metadata =
        std::fs::symlink_metadata(path).or(Err(RootSelectorServiceError::ProviderUnavailable))?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.dev() != device
        || metadata.ino() != inode
    {
        return Err(RootSelectorServiceError::ProviderUnavailable);
    }
    Ok(metadata)
}

fn root_owned_ancestors(path: &Path) -> bool {
    let Some(relative_parent) = path
        .parent()
        .and_then(|parent| parent.strip_prefix("/").ok())
    else {
        return false;
    };
    std::fs::File::open("/").is_ok_and(|root| {
        crate::selector::installation::open_directory_chain(root, relative_parent, ROOT_UID).is_ok()
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn receive<T>(result: Result<T, ReceiveFailure>) -> TestResult<T> {
        Ok(result.map_err(|failure| format!("transport failed: {failure:?}"))?)
    }

    #[test]
    fn endpoint_ancestry_requires_absolute_descriptor_validated_directories() {
        assert!(root_owned_ancestors(Path::new("/provider.sock")));
        for path in [
            "provider.sock",
            "/proc/self/provider.sock",
            "/proc/self/fd/0/provider.sock",
        ] {
            assert!(!root_owned_ancestors(Path::new(path)), "{path}");
        }
    }

    #[test]
    fn selected_endpoint_rejects_non_socket_and_untrusted_paths() -> TestResult {
        for path in ["relative.sock", "/dev/null", "/proc/self/provider.sock"] {
            assert!(SelectedProviderEndpoint::validate(Path::new(path)).is_err());
        }
        let temporary = tempfile::tempdir()?;
        let missing = temporary.path().join("missing.sock");
        assert!(SelectedProviderEndpoint::validate(&missing).is_err());
        let mut endpoint = SelectedProviderEndpoint {
            path: missing,
            device: 0,
            inode: 0,
            owner_uid: ROOT_UID,
        };
        assert!(endpoint.connect(Duration::from_millis(100)).is_err());
        let mut transport = ProviderTransport::from_selected_endpoint(endpoint);
        assert!(transport
            .connector
            .connect(Duration::from_millis(100))
            .is_err());
        Ok(())
    }

    fn output_digest(bytes: &[u8]) -> [u8; 32] {
        output_digest_with(b"PiglorOS.SandboxOutputBytes.v1\0", bytes)
    }

    #[test]
    fn verified_staging_rejects_invalid_payload_boundaries() {
        let bytes = b"complete";
        for (length, digest, mut input) in [
            (
                MAX_PAYLOAD_BYTES + 1,
                output_digest(bytes),
                bytes.as_slice(),
            ),
            (9, output_digest(bytes), bytes.as_slice()),
            (7, output_digest(bytes), bytes.as_slice()),
            (8, output_digest(b"different"), bytes.as_slice()),
        ] {
            let descriptor = PayloadDescriptor {
                byte_length: length,
                digest,
            };
            assert!(StagedOutput::stage_verified(&mut input, descriptor).is_err());
        }
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("injected read failure"))
        }
    }

    struct FragmentingReader<'a> {
        remaining: &'a [u8],
        maximum_read: usize,
    }

    impl Read for FragmentingReader<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let read = self
                .remaining
                .len()
                .min(self.maximum_read)
                .min(buffer.len());
            buffer[..read].copy_from_slice(&self.remaining[..read]);
            self.remaining = &self.remaining[read..];
            Ok(read)
        }
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("injected write failure"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn verified_staging_propagates_payload_and_eof_read_failures() {
        for byte_length in [0, 1] {
            let descriptor = PayloadDescriptor {
                byte_length,
                digest: output_digest(b""),
            };
            assert!(StagedOutput::stage_verified(&mut FailingReader, descriptor).is_err());
        }
    }

    #[test]
    fn verified_staging_rewinds_after_copy_and_destination_failure() -> TestResult {
        for bytes in [Vec::new(), vec![7; 8193]] {
            let descriptor = PayloadDescriptor {
                byte_length: bytes.len() as u64,
                digest: output_digest(&bytes),
            };
            let mut staged = StagedOutput::stage_verified(&mut bytes.as_slice(), descriptor)?;
            if !bytes.is_empty() {
                assert!(staged.copy_to(&mut FailingWriter).is_err());
            }
            for _ in 0..2 {
                let mut copied = Vec::new();
                staged.copy_to(&mut copied)?;
                assert_eq!(copied, bytes);
            }
        }
        Ok(())
    }

    #[test]
    fn verified_staging_accepts_fragmented_input_without_changing_the_payload() -> TestResult {
        let bytes = vec![7; 8193];
        let descriptor = PayloadDescriptor {
            byte_length: bytes.len() as u64,
            digest: output_digest(&bytes),
        };
        let mut reader = FragmentingReader {
            remaining: &bytes,
            maximum_read: 3,
        };
        let mut staged = StagedOutput::stage_verified(&mut reader, descriptor)?;
        let mut copied = Vec::new();
        staged.copy_to(&mut copied)?;

        assert_eq!(copied, bytes);
        Ok(())
    }

    #[test]
    fn frames_round_trip_and_reject_closed_framing_failures() -> TestResult {
        let deadline = Deadline::new(Duration::from_secs(1))?;
        let (mut sender, mut receiver) = UnixStream::pair()?;
        receive(write_frame(&mut sender, b"frame", &deadline))?;
        assert_eq!(
            receive(read_frame(&mut receiver, &deadline))?,
            Some(b"frame".to_vec())
        );
        drop(sender);
        assert_eq!(receive(read_frame(&mut receiver, &deadline))?, None);

        let (mut sender, mut receiver) = UnixStream::pair()?;
        sender.write_all(&0_u32.to_be_bytes())?;
        assert_eq!(
            read_frame(&mut receiver, &deadline),
            Err(ReceiveFailure::Invalid)
        );

        let (mut sender, mut receiver) = UnixStream::pair()?;
        sender.write_all(&u32::try_from(CONTROL_LIMIT + 1)?.to_be_bytes())?;
        assert_eq!(
            read_frame(&mut receiver, &deadline),
            Err(ReceiveFailure::Invalid)
        );

        let (mut sender, mut receiver) = UnixStream::pair()?;
        sender.write_all(&[0, 0, 0])?;
        drop(sender);
        assert_eq!(
            read_frame(&mut receiver, &deadline),
            Err(ReceiveFailure::Incomplete)
        );
        Ok(())
    }

    #[test]
    fn eof_and_deadline_helpers_fail_closed() -> TestResult {
        assert!(Deadline::new(Duration::MAX).is_err());
        let deadline = Deadline::new(Duration::from_secs(1))?;
        let (mut sender, mut receiver) = UnixStream::pair()?;
        receive(deadline.set_read(&receiver))?;
        receive(deadline.set_write(&sender))?;
        sender.write_all(&[1])?;
        assert_eq!(
            ensure_eof(&mut receiver, &deadline),
            Err(ReceiveFailure::Invalid)
        );
        drop(sender);
        assert_eq!(ensure_eof(&mut receiver, &deadline), Ok(()));

        let expired = Deadline {
            expires_at: Instant::now(),
        };
        let (sender, receiver) = UnixStream::pair()?;
        assert_eq!(expired.set_read(&receiver), Err(ReceiveFailure::Incomplete));
        assert_eq!(expired.set_write(&sender), Err(ReceiveFailure::Incomplete));
        Ok(())
    }

    fn record_with_magic(magic: &str) -> TestResult<Vec<u8>> {
        receive(encode_value(&Value::Array(vec![
            Value::Array(vec![Value::Text(magic.to_owned())]),
            Value::Bytes(vec![1; 32]),
        ])))
    }

    #[test]
    fn record_magic_requires_the_wrapped_record_shape() -> TestResult {
        assert_eq!(
            record_magic(&record_with_magic("SPY1")?),
            Ok("SPY1".to_owned())
        );
        for value in [
            Value::Null,
            Value::Array(vec![Value::Null]),
            Value::Array(vec![Value::Array(vec![Value::Null]), Value::Bytes(vec![])]),
        ] {
            assert_eq!(
                record_magic(&receive(encode_value(&value))?),
                Err(ReceiveFailure::Invalid)
            );
        }
        Ok(())
    }

    #[test]
    fn input_frames_bind_the_request_and_payload_bytes() -> TestResult {
        let input = b"input";
        let mut request = request()?;
        request.adapter_input = PayloadDescriptor {
            byte_length: input.len() as u64,
            digest: output_digest_with(b"PiglorOS.SandboxInputBytes.v1\0", input),
        };
        let deadline = Deadline::new(Duration::from_secs(1))?;
        let (mut sender, mut receiver) = UnixStream::pair()?;
        receive(write_input(&mut sender, &request, input, &deadline))?;
        let frame = receive(read_frame(&mut receiver, &deadline))?.ok_or("missing input frame")?;
        let chunk = SandboxPayloadChunk::from_canonical_cbor(&frame)?;
        assert_eq!(chunk.parent_digest, request.request_digest);
        assert_eq!(chunk.request_id, request.request.request_id);
        assert_eq!(chunk.attempt_id, request.attempt_id);
        assert_eq!(chunk.direction, PayloadDirection::Input);
        assert_eq!(chunk.index, 0);
        assert_eq!(chunk.offset, 0);
        assert_eq!(chunk.bytes, input);

        let mut wrong_length = request.clone();
        wrong_length.adapter_input.byte_length += 1;
        assert_eq!(
            write_input(&mut sender, &wrong_length, input, &deadline),
            Err(ReceiveFailure::Invalid)
        );
        let mut wrong_digest = request;
        wrong_digest.adapter_input.digest = [0; 32];
        assert_eq!(
            write_input(&mut sender, &wrong_digest, input, &deadline),
            Err(ReceiveFailure::Invalid)
        );
        Ok(())
    }

    #[test]
    fn input_frames_fail_closed_when_the_provider_disconnects() -> TestResult {
        let input = b"input";
        let mut request = request()?;
        request.adapter_input = PayloadDescriptor {
            byte_length: input.len() as u64,
            digest: output_digest_with(b"PiglorOS.SandboxInputBytes.v1\0", input),
        };
        let deadline = Deadline::new(Duration::from_secs(1))?;
        let (mut sender, receiver) = UnixStream::pair()?;
        drop(receiver);

        assert_eq!(
            write_input(&mut sender, &request, input, &deadline),
            Err(ReceiveFailure::Incomplete)
        );
        Ok(())
    }

    #[test]
    fn input_frames_preserve_chunk_order_across_the_payload_boundary() -> TestResult {
        let mut input = vec![1; CHUNK_BYTES];
        input.extend_from_slice(b"tail");
        let mut request = request()?;
        request.adapter_input = PayloadDescriptor {
            byte_length: input.len() as u64,
            digest: output_digest_with(b"PiglorOS.SandboxInputBytes.v1\0", &input),
        };
        let deadline = Deadline::new(Duration::from_secs(1))?;
        let (mut sender, mut receiver) = UnixStream::pair()?;
        let writer_request = request.clone();
        let writer_input = input.clone();
        let writer = std::thread::spawn(move || {
            Deadline::new(Duration::from_secs(1)).is_ok_and(|deadline| {
                write_input(&mut sender, &writer_request, &writer_input, &deadline).is_ok()
            })
        });

        let first = SandboxPayloadChunk::from_canonical_cbor(
            &receive(read_frame(&mut receiver, &deadline))?.ok_or("first input frame missing")?,
        )?;
        let second = SandboxPayloadChunk::from_canonical_cbor(
            &receive(read_frame(&mut receiver, &deadline))?.ok_or("second input frame missing")?,
        )?;

        assert_eq!(
            (first.index, first.offset, first.bytes),
            (0, 0, input[..CHUNK_BYTES].to_vec())
        );
        assert_eq!(
            (second.index, second.offset, second.bytes),
            (1, CHUNK_BYTES as u64, input[CHUNK_BYTES..].to_vec())
        );
        assert!(matches!(writer.join(), Ok(true)));
        Ok(())
    }

    #[test]
    fn frames_reject_a_truncated_payload_after_a_complete_prefix() -> TestResult {
        let deadline = Deadline::new(Duration::from_secs(1))?;
        let (mut sender, mut receiver) = UnixStream::pair()?;
        sender.write_all(&4_u32.to_be_bytes())?;
        sender.write_all(b"two")?;
        drop(sender);

        assert_eq!(
            read_frame(&mut receiver, &deadline),
            Err(ReceiveFailure::Incomplete)
        );
        Ok(())
    }

    fn completed(descriptor: PayloadDescriptor) -> SandboxProviderResult {
        SandboxProviderResult {
            request_id: [2; 16],
            attempt_id: [3; 16],
            outcome: SandboxTerminalOutcome::Completed,
            output: Some(descriptor),
            agr1_digest: Some([4; 32]),
            spr1_digest: Some([5; 32]),
            operational_events: vec![11, 12],
            runtime_attestation_key_id: "runtime".to_owned(),
            result_digest: [6; 32],
            signature: [7; 64],
        }
    }

    fn request() -> TestResult<SandboxExecuteRequest> {
        Ok(SandboxExecuteRequest::for_selector(
            crate::sandbox_provider_protocol::RequestAuthority {
                request_id: [2; 16],
                apt1_digest: [8; 32],
                policy_epoch: 1,
                nonce: [9; 16],
            },
            [3; 16],
            crate::sandbox_provider_protocol::ExecuteAuthority {
                evr1_digest: [1; 32],
                cpf1_digest: [1; 32],
                cfb1_digest: [1; 32],
                fixture_contract_digest: [1; 32],
                fixture_digest: [1; 32],
                execution_profile_digest: [1; 32],
                lps1_digest: [1; 32],
                sim1_digest: [1; 32],
                apt1_digest: [8; 32],
                trs1_digest: [1; 32],
                rvs1_digest: [1; 32],
                spm1_digest: [1; 32],
                pcf1_digest: [1; 32],
                pcr1_digest: [1; 32],
                hcp1_digest: [1; 32],
            },
            vec![],
            PayloadDescriptor {
                byte_length: 0,
                digest: output_digest_with(b"PiglorOS.SandboxInputBytes.v1\0", b""),
            },
            vec![],
        )?)
    }

    #[test]
    fn staged_output_requires_the_full_parent_bound_payload() -> TestResult {
        let bytes = b"complete";
        let descriptor = PayloadDescriptor {
            byte_length: bytes.len() as u64,
            digest: output_digest(bytes),
        };
        let result = completed(descriptor.clone());
        let encoded = encode_chunk(result.result_digest, [2; 16], [3; 16], 1, 0, bytes)
            .map_err(|failure| format!("chunk encoding failed: {failure:?}"))?;
        let chunk = SandboxPayloadChunk::from_canonical_cbor(&encoded)?;
        let mut file = tempfile::NamedTempFile::new()?;
        file.write_all(bytes)?;
        let staged = stage_output(file, vec![ChunkMeta::from(&chunk)], &request()?, &result)
            .map_err(|failure| format!("payload validation failed: {failure:?}"))?
            .ok_or("completed output absent")?;
        assert_eq!(staged.descriptor(), &descriptor);
        Ok(())
    }

    #[test]
    fn staged_output_reassembles_a_multi_chunk_authenticated_stream() -> TestResult {
        let first = vec![3; CHUNK_BYTES];
        let second = b"tail";
        let mut bytes = first.clone();
        bytes.extend_from_slice(second);
        let descriptor = PayloadDescriptor {
            byte_length: bytes.len() as u64,
            digest: output_digest(&bytes),
        };
        let result = completed(descriptor.clone());
        let first_chunk = SandboxPayloadChunk::from_canonical_cbor(&receive(encode_chunk(
            result.result_digest,
            [2; 16],
            [3; 16],
            1,
            0,
            &first,
        ))?)?;
        let second_chunk = SandboxPayloadChunk::from_canonical_cbor(&receive(encode_chunk(
            result.result_digest,
            [2; 16],
            [3; 16],
            1,
            1,
            second,
        ))?)?;
        let mut file = tempfile::NamedTempFile::new()?;
        file.write_all(&bytes)?;
        let mut staged = receive(stage_output(
            file,
            vec![
                ChunkMeta::from(&first_chunk),
                ChunkMeta::from(&second_chunk),
            ],
            &request()?,
            &result,
        ))?
        .ok_or("completed output absent")?;
        let mut copied = Vec::new();
        staged.copy_to(&mut copied)?;

        assert_eq!(staged.descriptor(), &descriptor);
        assert_eq!(copied, bytes);
        Ok(())
    }

    #[test]
    fn staged_output_rejects_forged_parent_and_missing_completion() -> TestResult {
        let bytes = b"complete";
        let result = completed(PayloadDescriptor {
            byte_length: bytes.len() as u64,
            digest: output_digest(bytes),
        });
        let encoded = encode_chunk([7; 32], [2; 16], [3; 16], 1, 0, bytes)
            .map_err(|failure| format!("chunk encoding failed: {failure:?}"))?;
        let chunk = SandboxPayloadChunk::from_canonical_cbor(&encoded)?;
        let mut file = tempfile::NamedTempFile::new()?;
        file.write_all(bytes)?;
        assert!(stage_output(file, vec![ChunkMeta::from(&chunk)], &request()?, &result).is_err());
        Ok(())
    }

    #[test]
    fn staged_output_only_allows_the_terminal_output_shapes() -> TestResult {
        let descriptor = PayloadDescriptor {
            byte_length: 0,
            digest: output_digest(b""),
        };
        let mut no_descriptor = completed(descriptor.clone());
        no_descriptor.output = None;
        assert!(stage_output(
            tempfile::NamedTempFile::new()?,
            Vec::new(),
            &request()?,
            &no_descriptor,
        )
        .is_err());

        let mut cancelled = completed(descriptor);
        cancelled.outcome = SandboxTerminalOutcome::Cancelled;
        cancelled.output = None;
        assert!(receive(stage_output(
            tempfile::NamedTempFile::new()?,
            Vec::new(),
            &request()?,
            &cancelled,
        ))?
        .is_none());
        Ok(())
    }

    #[test]
    fn deadline_and_frame_limits_fail_closed() -> TestResult {
        let expired = Deadline {
            expires_at: Instant::now(),
        };
        assert_eq!(expired.remaining(), Err(ReceiveFailure::Incomplete));
        let (mut sender, _) = UnixStream::pair()?;
        assert!(write_frame(
            &mut sender,
            &vec![0; CONTROL_LIMIT + 1],
            &Deadline::new(Duration::from_secs(1))?
        )
        .is_err());
        assert_eq!(
            write_frame(&mut sender, b"", &Deadline::new(Duration::from_secs(1))?),
            Err(ReceiveFailure::Invalid)
        );
        Ok(())
    }

    #[test]
    fn endpoint_mode_is_exactly_root_private_socket_mode() -> TestResult {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("provider.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&path)?;
        let metadata = std::fs::metadata(&path)?;
        for mode in [0o400, 0o200, 0o000, 0o1600, 0o2600, 0o4600] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
            assert!(endpoint_metadata(&path, metadata.dev(), metadata.ino(), ROOT_UID).is_err());
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        assert_eq!(
            endpoint_metadata(&path, metadata.dev(), metadata.ino(), ROOT_UID).is_ok(),
            metadata.uid() == ROOT_UID,
            "private socket permissions must not bypass root ownership"
        );
        Ok(())
    }

    #[test]
    fn selected_endpoint_connects_to_the_exact_private_peer() -> TestResult {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("provider.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let metadata = std::fs::symlink_metadata(&path)?;
        let owner_uid = metadata.uid();
        assert!(endpoint_metadata(&path, metadata.dev(), metadata.ino(), owner_uid ^ 1).is_err());
        assert!(SelectedProviderEndpoint::from_verified_ancestry(&path, owner_uid ^ 1).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))?;
        assert!(endpoint_metadata(&path, metadata.dev(), metadata.ino(), owner_uid).is_err());
        assert!(SelectedProviderEndpoint::from_verified_ancestry(&path, owner_uid).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        assert!(endpoint_metadata(&path, metadata.dev() ^ 1, metadata.ino(), owner_uid).is_err());
        assert!(endpoint_metadata(&path, metadata.dev(), metadata.ino() ^ 1, owner_uid).is_err());
        assert!(endpoint_metadata(&path, metadata.dev(), metadata.ino(), owner_uid).is_ok());
        let mut endpoint = SelectedProviderEndpoint::from_verified_ancestry(&path, owner_uid)?;
        let server = std::thread::spawn(move || listener.accept().map(|_| ()));

        let stream = endpoint.connect(Duration::from_secs(1))?;
        drop(stream);
        server.join().map_err(|_| "provider thread panicked")??;
        Ok(())
    }

    #[test]
    fn selected_endpoint_bounds_refused_connection_waits() -> TestResult {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("provider.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let owner_uid = std::fs::symlink_metadata(&path)?.uid();
        let endpoint = SelectedProviderEndpoint::from_verified_ancestry(&path, owner_uid)?;
        drop(listener);

        let mut oversized_wait = endpoint.clone();
        assert!(oversized_wait.connect(Duration::MAX).is_err());
        let mut refused = endpoint;
        assert!(refused.connect(Duration::from_millis(10)).is_err());
        Ok(())
    }
}
