//! Bounded root-to-provider execute transport for the SIC1-selected endpoint.
//!
//! The selector passes exact, already-constructed SPX1 bytes and input bytes.
//! This module never accepts caller-owned endpoint, image, launch-policy, or
//! authority material. It reconnects at most once for the same SPX1 after an
//! incomplete connection and releases output only after full provider evidence
//! authentication.

use std::fs::Metadata;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ciborium::value::Value;
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::net::sockopt::{socket_error, socket_peercred};
use rustix::net::{connect, socket_with, AddressFamily, SocketAddrUnix, SocketFlags, SocketType};

use crate::sandbox_provider_protocol::{
    AuthenticatedAdmissionGrant, AuthenticatedSandboxProviderReceipt,
    AuthenticatedSandboxProviderResult, PayloadDescriptor, PayloadDirection,
    PayloadStreamValidator, SandboxAuditRecord, SandboxExecuteRequest, SandboxPayloadChunk,
    SelectorGrantCommitment,
};
use crate::selector::installation::authority::AdmittedSelectorProvider;
use crate::selector::installation::open_directory_chain;
use crate::selector::SelectorBoundaryError;

const CONTROL_LIMIT: usize = 16 * 1024 * 1024;
const CHUNK_BYTES: usize = 1024 * 1024;
const MAX_AUDIT_RECORDS: usize = 256;
const ROOT_UID: u32 = 0;

/// Root-owned execute transport bound to the single SIC1-selected endpoint.
#[derive(Debug)]
pub(crate) struct ProviderTransport {
    endpoint: SelectedProviderEndpoint,
}

/// Complete provider evidence authenticated against an admitted selector provider.
#[derive(Debug)]
pub(crate) struct AuthenticatedProviderExecution {
    grant: AuthenticatedAdmissionGrant,
    receipt: AuthenticatedSandboxProviderReceipt,
    result: AuthenticatedSandboxProviderResult,
    audit: Vec<SandboxAuditRecord>,
    output: Option<StagedProviderOutput>,
}

impl AuthenticatedProviderExecution {
    /// Returns the authenticated AGR1 evidence.
    #[must_use]
    pub(crate) const fn grant(&self) -> &AuthenticatedAdmissionGrant {
        &self.grant
    }

    /// Returns the authenticated SPR1 evidence.
    #[must_use]
    pub(crate) const fn receipt(&self) -> &AuthenticatedSandboxProviderReceipt {
        &self.receipt
    }

    /// Returns the authenticated terminal SPY1 evidence.
    #[must_use]
    pub(crate) const fn result(&self) -> &AuthenticatedSandboxProviderResult {
        &self.result
    }

    /// Returns the authenticated ordered SAU1 evidence chain.
    #[must_use]
    pub(crate) fn audit(&self) -> &[SandboxAuditRecord] {
        &self.audit
    }

    /// Returns staged output after every provider evidence check has passed.
    #[must_use]
    pub(crate) fn output_mut(&mut self) -> Option<&mut StagedProviderOutput> {
        self.output.as_mut()
    }
}

/// Root-owned staged provider output that cannot be read before authentication.
#[derive(Debug)]
pub(crate) struct StagedProviderOutput {
    file: tempfile::NamedTempFile,
    descriptor: PayloadDescriptor,
}

impl StagedProviderOutput {
    fn new(file: tempfile::NamedTempFile, descriptor: PayloadDescriptor) -> Self {
        Self { file, descriptor }
    }

    /// Returns the authenticated output descriptor.
    #[must_use]
    pub(crate) const fn descriptor(&self) -> &PayloadDescriptor {
        &self.descriptor
    }

    /// Copies the staged, authenticated output to the selector-owned caller.
    ///
    /// # Errors
    /// Returns a closed I/O failure if staging or destination I/O fails.
    pub(crate) fn copy_to(&mut self, writer: &mut impl Write) -> Result<(), SelectorBoundaryError> {
        let file = self.file.as_file_mut();
        file.seek(SeekFrom::Start(0))
            .map_err(|_| SelectorBoundaryError::Io)?;
        let mut buffer = [0_u8; 8192];
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|_| SelectorBoundaryError::Io)?;
            if read == 0 {
                return Ok(());
            }
            writer
                .write_all(&buffer[..read])
                .map_err(|_| SelectorBoundaryError::Io)?;
        }
    }
}

#[derive(Clone, Debug)]
struct SelectedProviderEndpoint {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl SelectedProviderEndpoint {
    fn from_admitted(admitted: &AdmittedSelectorProvider) -> Result<Self, SelectorBoundaryError> {
        let (execute, _) = admitted
            .bootstrap()
            .installed()
            .manifest()
            .provider_sockets();
        if !root_owned_ancestors(execute) {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        let metadata = endpoint_metadata(execute, None)?;
        Ok(Self {
            path: execute.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn connect(&self, timeout: Duration) -> Result<UnixStream, SelectorBoundaryError> {
        let before = endpoint_metadata(&self.path, Some((self.device, self.inode)))?;
        let address =
            SocketAddrUnix::new(&self.path).map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        let descriptor = socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .map_err(|_| SelectorBoundaryError::SelectorUnavailable)?;
        connect(&descriptor, &address)
            .or_else(|error| {
                if error == rustix::io::Errno::INPROGRESS {
                    wait_for_connection(&descriptor, timeout)
                } else {
                    Err(error)
                }
            })
            .map_err(|_| SelectorBoundaryError::SelectorUnavailable)?;
        let stream = UnixStream::from(descriptor);
        stream
            .set_nonblocking(false)
            .map_err(|_| SelectorBoundaryError::SelectorUnavailable)?;
        let after = endpoint_metadata(&self.path, Some((self.device, self.inode)))?;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        let peer =
            socket_peercred(stream.as_fd()).map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        if peer.uid.as_raw() != ROOT_UID {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        Ok(stream)
    }
}

impl ProviderTransport {
    /// Retain the one SIC1-selected execute endpoint after root-owned validation.
    ///
    /// # Errors
    /// Returns a closed error when the admitted installation's execute endpoint
    /// is absent, replaced, insecure, or outside a root-owned descriptor chain.
    pub(crate) fn from_admitted(
        admitted: &AdmittedSelectorProvider,
    ) -> Result<Self, SelectorBoundaryError> {
        SelectedProviderEndpoint::from_admitted(admitted).map(|endpoint| Self { endpoint })
    }

    /// Execute exact constructed SPX1/input bytes and authenticate the full reply.
    ///
    /// A connection loss gets one exact recovery connection. Invalid frames or
    /// evidence fail closed without retry; a second incomplete connection fails.
    ///
    /// # Errors
    /// Returns a closed selector boundary error for invalid exact bytes,
    /// provider evidence, endpoint identity, timeouts, or I/O failure.
    pub(crate) fn execute(
        &self,
        admitted: &AdmittedSelectorProvider,
        commitment: &SelectorGrantCommitment,
        spx1: &[u8],
        input: &[u8],
        watchdog: Duration,
    ) -> Result<AuthenticatedProviderExecution, SelectorBoundaryError> {
        let request = SandboxExecuteRequest::from_canonical_cbor(spx1)
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        validate_input(&request.adapter_input, input)?;
        let deadline = Deadline::new(watchdog)?;
        let mut retained_grant = None;
        for recovery_attempt in 0..=1 {
            let result = self.execute_once(
                admitted,
                commitment,
                &request,
                spx1,
                input,
                &deadline,
                &mut retained_grant,
            );
            match result {
                Ok(execution) => return Ok(execution),
                Err(ReceiveFailure::Invalid) => return Err(SelectorBoundaryError::ArtifactInvalid),
                Err(ReceiveFailure::Incomplete) if recovery_attempt == 0 => {}
                Err(ReceiveFailure::Incomplete) => {
                    return Err(SelectorBoundaryError::SelectorUnavailable)
                }
            }
        }
        Err(SelectorBoundaryError::SelectorUnavailable)
    }

    fn execute_once(
        &self,
        admitted: &AdmittedSelectorProvider,
        commitment: &SelectorGrantCommitment,
        request: &SandboxExecuteRequest,
        spx1: &[u8],
        input: &[u8],
        deadline: &Deadline,
        retained_grant: &mut Option<Vec<u8>>,
    ) -> Result<AuthenticatedProviderExecution, ReceiveFailure> {
        let mut stream = self
            .endpoint
            .connect(deadline.remaining()?)
            .map_err(|_| ReceiveFailure::Incomplete)?;
        write_frame(&mut stream, spx1, deadline)?;
        write_input(&mut stream, request, input, deadline)?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|_| ReceiveFailure::Incomplete)?;
        read_response(
            &mut stream,
            admitted,
            commitment,
            request,
            deadline,
            retained_grant,
        )
    }
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
    fn new(duration: Duration) -> Result<Self, SelectorBoundaryError> {
        Instant::now()
            .checked_add(duration)
            .map(|expires_at| Self { expires_at })
            .ok_or(SelectorBoundaryError::SelectorUnavailable)
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
            .map_err(|_| ReceiveFailure::Incomplete)
    }

    fn set_write(&self, stream: &UnixStream) -> Result<(), ReceiveFailure> {
        stream
            .set_write_timeout(Some(self.remaining()?))
            .map_err(|_| ReceiveFailure::Incomplete)
    }
}

fn wait_for_connection(descriptor: &impl AsFd, timeout: Duration) -> rustix::io::Result<()> {
    let seconds = i64::try_from(timeout.as_secs()).map_err(|_| rustix::io::Errno::INVAL)?;
    let timeout = Timespec {
        tv_sec: seconds,
        tv_nsec: timeout.subsec_nanos().into(),
    };
    let mut descriptors = [PollFd::new(descriptor, PollFlags::OUT)];
    if poll(&mut descriptors, Some(&timeout))? == 0 || socket_error(descriptor)?.is_err() {
        return Err(rustix::io::Errno::TIMEDOUT);
    }
    Ok(())
}

fn validate_input(
    descriptor: &PayloadDescriptor,
    input: &[u8],
) -> Result<(), SelectorBoundaryError> {
    if u64::try_from(input.len()).map_err(|_| SelectorBoundaryError::ArtifactInvalid)?
        != descriptor.byte_length
        || payload_digest(PayloadDirection::Input, input) != descriptor.digest
    {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    Ok(())
}

fn write_input(
    stream: &mut UnixStream,
    request: &SandboxExecuteRequest,
    input: &[u8],
    deadline: &Deadline,
) -> Result<(), ReceiveFailure> {
    validate_input(&request.adapter_input, input).map_err(|_| ReceiveFailure::Invalid)?;
    for (index, bytes) in input.chunks(CHUNK_BYTES).enumerate() {
        let index = u64::try_from(index).map_err(|_| ReceiveFailure::Invalid)?;
        let chunk = encode_input_chunk(request, index, bytes)?;
        write_frame(stream, &chunk, deadline)?;
    }
    Ok(())
}

fn encode_input_chunk(
    request: &SandboxExecuteRequest,
    index: u64,
    bytes: &[u8],
) -> Result<Vec<u8>, ReceiveFailure> {
    let offset = index
        .checked_mul(u64::try_from(CHUNK_BYTES).map_err(|_| ReceiveFailure::Invalid)?)
        .ok_or(ReceiveFailure::Invalid)?;
    let unsigned = Value::Array(vec![
        Value::Text("SBC1".to_owned()),
        Value::Integer(1_u64.into()),
        Value::Bytes(request.request_digest.to_vec()),
        Value::Bytes(request.request.request_id.to_vec()),
        Value::Bytes(request.attempt_id.to_vec()),
        Value::Integer(0_u64.into()),
        Value::Integer(index.into()),
        Value::Integer(offset.into()),
        Value::Bytes(bytes.to_vec()),
    ]);
    let encoded = encode_value(&unsigned)?;
    let digest = record_digest("SBC1", &encoded);
    encode_value(&Value::Array(vec![unsigned, Value::Bytes(digest.to_vec())]))
}

fn read_response(
    stream: &mut UnixStream,
    admitted: &AdmittedSelectorProvider,
    commitment: &SelectorGrantCommitment,
    request: &SandboxExecuteRequest,
    deadline: &Deadline,
    retained_grant: &mut Option<Vec<u8>>,
) -> Result<AuthenticatedProviderExecution, ReceiveFailure> {
    let first = read_frame(stream, deadline)?.ok_or(ReceiveFailure::Incomplete)?;
    match record_magic(&first)?.as_str() {
        "AGR1" => read_admitted_response(
            stream,
            admitted,
            commitment,
            request,
            deadline,
            retained_grant,
            first,
        ),
        "SPE1" | "SPY1" => {
            ensure_eof(stream, deadline)?;
            Err(ReceiveFailure::Invalid)
        }
        _ => Err(ReceiveFailure::Invalid),
    }
}

fn read_admitted_response(
    stream: &mut UnixStream,
    admitted: &AdmittedSelectorProvider,
    commitment: &SelectorGrantCommitment,
    request: &SandboxExecuteRequest,
    deadline: &Deadline,
    retained_grant: &mut Option<Vec<u8>>,
    grant_bytes: Vec<u8>,
) -> Result<AuthenticatedProviderExecution, ReceiveFailure> {
    verify_retained_grant(retained_grant, &grant_bytes)?;
    let provider = admitted.provider();
    let grant = provider
        .authenticate_selector_grant(&grant_bytes, request, commitment)
        .map_err(|_| ReceiveFailure::Invalid)?;
    let (audit_bytes, receipt_bytes) = read_audit_and_receipt(stream, deadline)?;
    let receipt = provider
        .authenticate_receipt(&receipt_bytes, &grant)
        .map_err(|_| ReceiveFailure::Invalid)?;
    let (file, chunks, result_bytes) = read_output_frames(stream, deadline)?;
    let result = provider
        .authenticate_terminal_result(&result_bytes, request, &grant, &receipt)
        .map_err(|_| ReceiveFailure::Invalid)?;
    ensure_eof(stream, deadline)?;
    let audit = provider
        .authenticate_audit_chain(&audit_bytes, &receipt, &result)
        .map_err(|_| ReceiveFailure::Invalid)?;
    let output = stage_output(file, chunks, request, &result)?;
    Ok(AuthenticatedProviderExecution {
        grant,
        receipt,
        result,
        audit,
        output,
    })
}

fn verify_retained_grant(
    retained_grant: &mut Option<Vec<u8>>,
    current: &[u8],
) -> Result<(), ReceiveFailure> {
    if retained_grant
        .as_ref()
        .is_some_and(|previous| previous.as_slice() != current)
    {
        return Err(ReceiveFailure::Invalid);
    }
    *retained_grant = Some(current.to_vec());
    Ok(())
}

fn read_audit_and_receipt(
    stream: &mut UnixStream,
    deadline: &Deadline,
) -> Result<(Vec<Vec<u8>>, Vec<u8>), ReceiveFailure> {
    let mut records = Vec::new();
    loop {
        let frame = read_frame(stream, deadline)?.ok_or(ReceiveFailure::Incomplete)?;
        match record_magic(&frame)?.as_str() {
            "SAU1" if records.len() < MAX_AUDIT_RECORDS => records.push(frame),
            "SPR1" => return Ok((records, frame)),
            _ => return Err(ReceiveFailure::Invalid),
        }
    }
}

fn read_output_frames(
    stream: &mut UnixStream,
    deadline: &Deadline,
) -> Result<(tempfile::NamedTempFile, Vec<ChunkMeta>, Vec<u8>), ReceiveFailure> {
    let mut file = tempfile::NamedTempFile::new().map_err(|_| ReceiveFailure::Incomplete)?;
    let mut chunks = Vec::new();
    loop {
        let frame = read_frame(stream, deadline)?.ok_or(ReceiveFailure::Incomplete)?;
        match record_magic(&frame)?.as_str() {
            "SBC1" if chunks.len() < 128 => {
                let chunk = SandboxPayloadChunk::from_canonical_cbor(&frame)
                    .map_err(|_| ReceiveFailure::Invalid)?;
                file.write_all(&chunk.bytes)
                    .map_err(|_| ReceiveFailure::Incomplete)?;
                chunks.push(ChunkMeta::from(&chunk));
            }
            "SPY1" => return Ok((file, chunks, frame)),
            _ => return Err(ReceiveFailure::Invalid),
        }
    }
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
    result: &AuthenticatedSandboxProviderResult,
) -> Result<Option<StagedProviderOutput>, ReceiveFailure> {
    match (result.outcome, result.output.as_ref()) {
        (crate::sandbox_provider_protocol::SandboxTerminalOutcome::Completed, Some(descriptor)) => {
            let mut validator = PayloadStreamValidator::new(
                result.result_digest,
                request.request.request_id,
                request.attempt_id,
                PayloadDirection::Output,
                descriptor.clone(),
            )
            .map_err(|_| ReceiveFailure::Invalid)?;
            file.seek(SeekFrom::Start(0))
                .map_err(|_| ReceiveFailure::Incomplete)?;
            for chunk in chunks {
                let mut bytes = vec![0; chunk.length];
                file.read_exact(&mut bytes)
                    .map_err(|_| ReceiveFailure::Incomplete)?;
                validator
                    .accept(&SandboxPayloadChunk {
                        parent_digest: chunk.parent_digest,
                        request_id: chunk.request_id,
                        attempt_id: chunk.attempt_id,
                        direction: chunk.direction,
                        index: chunk.index,
                        offset: chunk.offset,
                        bytes,
                        chunk_digest: chunk.chunk_digest,
                    })
                    .map_err(|_| ReceiveFailure::Invalid)?;
            }
            validator.finish().map_err(|_| ReceiveFailure::Invalid)?;
            Ok(Some(StagedProviderOutput::new(file, descriptor.clone())))
        }
        (crate::sandbox_provider_protocol::SandboxTerminalOutcome::Completed, None) => {
            Err(ReceiveFailure::Invalid)
        }
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
    let length = u32::try_from(bytes.len()).map_err(|_| ReceiveFailure::Invalid)?;
    stream
        .write_all(&length.to_be_bytes())
        .map_err(|_| ReceiveFailure::Incomplete)?;
    deadline.set_write(stream)?;
    stream
        .write_all(bytes)
        .map_err(|_| ReceiveFailure::Incomplete)
}

fn read_frame(
    stream: &mut UnixStream,
    deadline: &Deadline,
) -> Result<Option<Vec<u8>>, ReceiveFailure> {
    let mut prefix = [0_u8; 4];
    deadline.set_read(stream)?;
    if stream
        .read(&mut prefix[..1])
        .map_err(|_| ReceiveFailure::Incomplete)?
        == 0
    {
        return Ok(None);
    }
    deadline.set_read(stream)?;
    stream
        .read_exact(&mut prefix[1..])
        .map_err(|_| ReceiveFailure::Incomplete)?;
    let length =
        usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| ReceiveFailure::Invalid)?;
    if length == 0 || length > CONTROL_LIMIT {
        return Err(ReceiveFailure::Invalid);
    }
    let mut bytes = vec![0; length];
    deadline.set_read(stream)?;
    stream
        .read_exact(&mut bytes)
        .map_err(|_| ReceiveFailure::Incomplete)?;
    Ok(Some(bytes))
}

fn ensure_eof(stream: &mut UnixStream, deadline: &Deadline) -> Result<(), ReceiveFailure> {
    let mut byte = [0_u8; 1];
    deadline.set_read(stream)?;
    if stream
        .read(&mut byte)
        .map_err(|_| ReceiveFailure::Incomplete)?
        == 0
    {
        Ok(())
    } else {
        Err(ReceiveFailure::Invalid)
    }
}

fn record_magic(bytes: &[u8]) -> Result<String, ReceiveFailure> {
    let value: Value = ciborium::from_reader(bytes).map_err(|_| ReceiveFailure::Invalid)?;
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

fn encode_value(value: &Value) -> Result<Vec<u8>, ReceiveFailure> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).map_err(|_| ReceiveFailure::Invalid)?;
    Ok(bytes)
}

fn record_digest(magic: &str, unsigned: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.");
    hasher.update(magic.as_bytes());
    hasher.update(b".v1\0");
    hasher.update(unsigned);
    *hasher.finalize().as_bytes()
}

fn payload_digest(direction: PayloadDirection, bytes: &[u8]) -> [u8; 32] {
    let domain = match direction {
        PayloadDirection::Input => b"PiglorOS.SandboxInputBytes.v1\0".as_slice(),
        PayloadDirection::Output => b"PiglorOS.SandboxOutputBytes.v1\0".as_slice(),
    };
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn endpoint_metadata(
    path: &Path,
    expected_identity: Option<(u64, u64)>,
) -> Result<Metadata, SelectorBoundaryError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| SelectorBoundaryError::SelectorUnavailable)?;
    let identity_matches = expected_identity
        .is_none_or(|(device, inode)| metadata.dev() == device && metadata.ino() == inode);
    if !metadata.file_type().is_socket()
        || metadata.uid() != ROOT_UID
        || metadata.mode() & 0o7777 != 0o600
        || !identity_matches
    {
        return Err(SelectorBoundaryError::ArtifactInvalid);
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
    std::fs::File::open("/")
        .is_ok_and(|root| open_directory_chain(root, relative_parent, ROOT_UID).is_ok())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    #[test]
    fn frames_preserve_payload_and_require_a_bounded_nonempty_length() -> TestResult {
        let (mut writer, mut reader) = UnixStream::pair()?;
        let deadline = Deadline::new(Duration::from_secs(1))?;
        write_frame(&mut writer, b"provider", &deadline)?;
        writer.shutdown(std::net::Shutdown::Write)?;
        assert_eq!(
            read_frame(&mut reader, &deadline)?,
            Some(b"provider".to_vec())
        );
        assert_eq!(read_frame(&mut reader, &deadline)?, None);
        Ok(())
    }

    #[test]
    fn frames_reject_zero_length_and_extra_trailing_bytes() -> TestResult {
        let (mut writer, mut reader) = UnixStream::pair()?;
        let deadline = Deadline::new(Duration::from_secs(1))?;
        writer.write_all(&0_u32.to_be_bytes())?;
        assert_eq!(
            read_frame(&mut reader, &deadline),
            Err(ReceiveFailure::Invalid)
        );
        let (mut writer, mut reader) = UnixStream::pair()?;
        writer.write_all(b"x")?;
        writer.shutdown(std::net::Shutdown::Write)?;
        assert_eq!(
            ensure_eof(&mut reader, &deadline),
            Err(ReceiveFailure::Invalid)
        );
        Ok(())
    }

    #[test]
    fn audit_reader_returns_spr1_with_the_preceding_ordered_sau1_frames() -> TestResult {
        let (mut writer, mut reader) = UnixStream::pair()?;
        let deadline = Deadline::new(Duration::from_secs(1))?;
        let first_audit = selector_record("SAU1")?;
        let second_audit = selector_record("SAU1")?;
        let receipt = selector_record("SPR1")?;
        for frame in [&first_audit, &second_audit, &receipt] {
            write_frame(&mut writer, frame, &deadline)?;
        }
        writer.shutdown(std::net::Shutdown::Write)?;
        assert_eq!(
            read_audit_and_receipt(&mut reader, &deadline)?,
            (vec![first_audit, second_audit], receipt)
        );
        Ok(())
    }

    #[test]
    fn audit_reader_rejects_a_non_audit_frame_before_spr1() -> TestResult {
        let (mut writer, mut reader) = UnixStream::pair()?;
        let deadline = Deadline::new(Duration::from_secs(1))?;
        write_frame(&mut writer, &selector_record("SBC1")?, &deadline)?;
        writer.shutdown(std::net::Shutdown::Write)?;
        assert_eq!(
            read_audit_and_receipt(&mut reader, &deadline),
            Err(ReceiveFailure::Invalid)
        );
        Ok(())
    }

    #[test]
    fn output_reader_requires_a_terminal_spy1_after_only_bounded_sbc1_frames() -> TestResult {
        let (mut writer, mut reader) = UnixStream::pair()?;
        let deadline = Deadline::new(Duration::from_secs(1))?;
        let result = selector_record("SPY1")?;
        write_frame(&mut writer, &result, &deadline)?;
        writer.shutdown(std::net::Shutdown::Write)?;
        let (_, chunks, terminal) = read_output_frames(&mut reader, &deadline)?;
        assert!(chunks.is_empty());
        assert_eq!(terminal, result);
        Ok(())
    }

    #[test]
    fn input_validation_binds_exact_directional_digest_and_length() {
        let input = b"exact input";
        let descriptor = PayloadDescriptor {
            byte_length: u64::try_from(input.len()).expect("test length fits u64"),
            digest: payload_digest(PayloadDirection::Input, input),
        };
        assert!(validate_input(&descriptor, input).is_ok());
        assert!(validate_input(&descriptor, b"other").is_err());
        assert!(validate_input(
            &PayloadDescriptor {
                byte_length: descriptor.byte_length + 1,
                digest: descriptor.digest,
            },
            input,
        )
        .is_err());
    }

    #[test]
    fn endpoint_validation_rejects_non_absolute_and_missing_locations() {
        assert!(!root_owned_ancestors(Path::new("provider.sock")));
        assert!(endpoint_metadata(Path::new("/missing-provider.sock"), None).is_err());
    }

    #[test]
    fn retained_grant_requires_byte_identity_across_one_recovery() {
        let mut retained = None;
        assert!(verify_retained_grant(&mut retained, b"grant").is_ok());
        assert!(verify_retained_grant(&mut retained, b"grant").is_ok());
        assert_eq!(
            verify_retained_grant(&mut retained, b"other"),
            Err(ReceiveFailure::Invalid)
        );
    }

    fn selector_record(magic: &str) -> TestResult<Vec<u8>> {
        let unsigned = Value::Array(vec![Value::Text(magic.to_owned())]);
        encode_value(&Value::Array(vec![unsigned, Value::Bytes(vec![1])]))
            .map_err(|error| error.to_string().into())
    }
}
