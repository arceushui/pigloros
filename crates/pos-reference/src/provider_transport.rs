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
    AdmittedSandboxProvider, AuthenticatedSandboxProviderResult, PayloadDescriptor,
    PayloadDirection, PayloadStreamValidator, SandboxExecuteRequest, SandboxPayloadChunk,
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
    frames: AuthenticatedProviderFrames,
    agr1_digest: [u8; 32],
    output: Option<StagedProviderOutput>,
}

/// One selected-provider terminal authenticated against the exact SPX1 request.
#[derive(Debug)]
pub(crate) enum AuthenticatedProviderTerminal {
    /// AGR1, SPR1, SPY1, and SAU1 complete provider evidence.
    Execution(AuthenticatedProviderExecution),
    /// Exact selected-runtime-signed SPE1 bytes bound to the submitted SPX1.
    Error(Vec<u8>),
}

/// Closed outcome when the selected provider cannot yield one terminal reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProviderTransportError {
    /// No AGR1 was authenticated, so the root retains its pre-admission error shape.
    BeforeAdmission,
    /// An authenticated AGR1 forbids fallback and identifies the phase-two failure.
    AfterAdmission {
        agr1_digest: [u8; 32],
        failure: PostAdmissionProviderFailure,
    },
}

/// Exact failure class after AGR1 authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PostAdmissionProviderFailure {
    /// Both the original stream and the sole recovery stream ended incomplete.
    TerminalUnavailable,
    /// A post-admission frame or evidence relationship was invalid.
    EvidenceInvalid,
}

#[derive(Debug)]
struct RetainedGrant {
    bytes: Vec<u8>,
    digest: [u8; 32],
}

impl AuthenticatedProviderExecution {
    /// Returns the digest of the authenticated AGR1 frame retained by root.
    #[must_use]
    pub(crate) const fn agr1_digest(&self) -> [u8; 32] {
        self.agr1_digest
    }

    /// Returns the exact authenticated AGR1 frame bytes for root SLY1 composition.
    #[must_use]
    pub(crate) fn agr1_bytes(&self) -> &[u8] {
        self.frames.agr1()
    }

    /// Returns the exact authenticated SPR1 frame bytes for root SLY1 composition.
    #[must_use]
    pub(crate) fn spr1_bytes(&self) -> &[u8] {
        self.frames.spr1()
    }

    /// Returns the exact authenticated terminal SPY1 frame bytes for root SLY1 composition.
    #[must_use]
    pub(crate) fn spy1_bytes(&self) -> &[u8] {
        self.frames.spy1()
    }

    /// Returns exact authenticated SAU1 frame bytes in received order for root SLY1 composition.
    #[must_use]
    pub(crate) fn sau1_frames(&self) -> &[Vec<u8>] {
        self.frames.sau1()
    }

    /// Gives root composition the verified output descriptor and a stream of its staged bytes.
    ///
    /// The descriptor and stream are borrowed from the same authenticated staging object, so a
    /// root SLY1 encoder cannot receive an unbound output stream. No staged file handle escapes.
    ///
    /// # Errors
    /// Returns a closed I/O failure when staging cannot be rewound or read, or when `compose`
    /// rejects the descriptor or output stream.
    pub(crate) fn with_verified_output<T>(
        &mut self,
        compose: impl FnOnce(&PayloadDescriptor, &mut dyn Read) -> Result<T, SelectorBoundaryError>,
    ) -> Result<Option<T>, SelectorBoundaryError> {
        self.output
            .as_mut()
            .map(|output| output.with_reader(compose))
            .transpose()
    }
}

/// Exact provider evidence frames retained only after their semantic authentication succeeds.
#[derive(Debug)]
struct AuthenticatedProviderFrames {
    agr1: Vec<u8>,
    spr1: Vec<u8>,
    spy1: Vec<u8>,
    sau1: Vec<Vec<u8>>,
}

impl AuthenticatedProviderFrames {
    const fn new(
        grant: Vec<u8>,
        receipt: Vec<u8>,
        result: Vec<u8>,
        audit_records: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            agr1: grant,
            spr1: receipt,
            spy1: result,
            sau1: audit_records,
        }
    }

    fn agr1(&self) -> &[u8] {
        &self.agr1
    }

    fn spr1(&self) -> &[u8] {
        &self.spr1
    }

    fn spy1(&self) -> &[u8] {
        &self.spy1
    }

    fn sau1(&self) -> &[Vec<u8>] {
        &self.sau1
    }
}

/// Root-owned staged provider output that cannot be read before authentication.
#[derive(Debug)]
struct StagedProviderOutput {
    file: tempfile::NamedTempFile,
    descriptor: PayloadDescriptor,
}

impl StagedProviderOutput {
    const fn new(file: tempfile::NamedTempFile, descriptor: PayloadDescriptor) -> Self {
        Self { file, descriptor }
    }

    /// Provides the authenticated descriptor and exact staged bytes together.
    ///
    /// # Errors
    /// Returns a closed I/O failure if staging cannot be rewound or read, or if `compose` fails.
    fn with_reader<T>(
        &mut self,
        compose: impl FnOnce(&PayloadDescriptor, &mut dyn Read) -> Result<T, SelectorBoundaryError>,
    ) -> Result<T, SelectorBoundaryError> {
        let file = self.file.as_file_mut();
        file.seek(SeekFrom::Start(0))
            .map_err(|_| SelectorBoundaryError::Io)?;
        compose(&self.descriptor, file)
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
    /// Returns whether the failure occurred before or after authentication of
    /// the one retained AGR1 grant.
    pub(crate) fn execute(
        &self,
        admitted: &AdmittedSandboxProvider,
        commitment: &SelectorGrantCommitment,
        spx1: &[u8],
        input: &[u8],
        watchdog: Duration,
    ) -> Result<AuthenticatedProviderTerminal, ProviderTransportError> {
        let request = SandboxExecuteRequest::from_canonical_cbor(spx1)
            .map_err(|_| ProviderTransportError::BeforeAdmission)?;
        validate_input(&request.adapter_input, input)
            .map_err(|_| ProviderTransportError::BeforeAdmission)?;
        let deadline =
            Deadline::new(watchdog).map_err(|_| ProviderTransportError::BeforeAdmission)?;
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
                Err(ReceiveFailure::Invalid) => {
                    return Err(classify_receive_failure(
                        &retained_grant,
                        PostAdmissionProviderFailure::EvidenceInvalid,
                    ));
                }
                Err(ReceiveFailure::Incomplete) if recovery_attempt == 0 => {}
                Err(ReceiveFailure::Incomplete) => {
                    return Err(classify_receive_failure(
                        &retained_grant,
                        PostAdmissionProviderFailure::TerminalUnavailable,
                    ));
                }
            }
        }
        Err(classify_receive_failure(
            &retained_grant,
            PostAdmissionProviderFailure::TerminalUnavailable,
        ))
    }

    fn execute_once(
        &self,
        admitted: &AdmittedSandboxProvider,
        commitment: &SelectorGrantCommitment,
        request: &SandboxExecuteRequest,
        spx1: &[u8],
        input: &[u8],
        deadline: &Deadline,
        retained_grant: &mut Option<RetainedGrant>,
    ) -> Result<AuthenticatedProviderTerminal, ReceiveFailure> {
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
    admitted: &AdmittedSandboxProvider,
    commitment: &SelectorGrantCommitment,
    request: &SandboxExecuteRequest,
    deadline: &Deadline,
    retained_grant: &mut Option<RetainedGrant>,
) -> Result<AuthenticatedProviderTerminal, ReceiveFailure> {
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
        "SPE1" if retained_grant.is_none() => {
            read_error_response(stream, admitted, request, deadline, first)
        }
        "SPY1" => {
            ensure_eof(stream, deadline)?;
            Err(ReceiveFailure::Invalid)
        }
        _ => Err(ReceiveFailure::Invalid),
    }
}

fn read_admitted_response(
    stream: &mut UnixStream,
    admitted: &AdmittedSandboxProvider,
    commitment: &SelectorGrantCommitment,
    request: &SandboxExecuteRequest,
    deadline: &Deadline,
    retained_grant: &mut Option<RetainedGrant>,
    grant_bytes: Vec<u8>,
) -> Result<AuthenticatedProviderTerminal, ReceiveFailure> {
    verify_retained_grant(retained_grant, &grant_bytes)?;
    let grant = admitted
        .authenticate_selector_grant(&grant_bytes, request, commitment)
        .map_err(|_| ReceiveFailure::Invalid)?;
    retain_authenticated_grant(retained_grant, grant_bytes.clone(), grant.grant_digest);
    let (audit_bytes, receipt_bytes) = read_audit_and_receipt(stream, deadline)?;
    let receipt = admitted
        .authenticate_receipt(&receipt_bytes, &grant)
        .map_err(|_| ReceiveFailure::Invalid)?;
    let (file, chunks, result_bytes) = read_output_frames(stream, deadline)?;
    let result = admitted
        .authenticate_terminal_result(&result_bytes, request, &grant, &receipt)
        .map_err(|_| ReceiveFailure::Invalid)?;
    ensure_eof(stream, deadline)?;
    admitted
        .authenticate_audit_chain(&audit_bytes, &receipt, &result)
        .map_err(|_| ReceiveFailure::Invalid)?;
    let output = stage_output(file, chunks, request, &result)?;
    Ok(AuthenticatedProviderTerminal::Execution(
        AuthenticatedProviderExecution {
            frames: AuthenticatedProviderFrames::new(
                grant_bytes,
                receipt_bytes,
                result_bytes,
                audit_bytes,
            ),
            agr1_digest: grant.grant_digest,
            output,
        },
    ))
}

fn read_error_response(
    stream: &mut UnixStream,
    admitted: &AdmittedSandboxProvider,
    request: &SandboxExecuteRequest,
    deadline: &Deadline,
    error_bytes: Vec<u8>,
) -> Result<AuthenticatedProviderTerminal, ReceiveFailure> {
    ensure_eof(stream, deadline)?;
    admitted
        .authenticate_selector_error(&error_bytes, request)
        .map_err(|_| ReceiveFailure::Invalid)?;
    Ok(AuthenticatedProviderTerminal::Error(error_bytes))
}

fn verify_retained_grant(
    retained_grant: &Option<RetainedGrant>,
    current: &[u8],
) -> Result<(), ReceiveFailure> {
    if retained_grant
        .as_ref()
        .is_some_and(|previous| previous.bytes.as_slice() != current)
    {
        return Err(ReceiveFailure::Invalid);
    }
    Ok(())
}

fn retain_authenticated_grant(
    retained_grant: &mut Option<RetainedGrant>,
    bytes: Vec<u8>,
    digest: [u8; 32],
) {
    if retained_grant.is_none() {
        *retained_grant = Some(RetainedGrant { bytes, digest });
    }
}

fn classify_receive_failure(
    retained_grant: &Option<RetainedGrant>,
    failure: PostAdmissionProviderFailure,
) -> ProviderTransportError {
    retained_grant
        .as_ref()
        .map_or(ProviderTransportError::BeforeAdmission, |grant| {
            ProviderTransportError::AfterAdmission {
                agr1_digest: grant.digest,
                failure,
            }
        })
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
        write_frame(&mut writer, b"provider", &deadline).map_err(|error| format!("{error:?}"))?;
        writer.shutdown(std::net::Shutdown::Write)?;
        assert_eq!(
            read_frame(&mut reader, &deadline).map_err(|error| format!("{error:?}"))?,
            Some(b"provider".to_vec())
        );
        assert_eq!(
            read_frame(&mut reader, &deadline).map_err(|error| format!("{error:?}"))?,
            None
        );
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
            write_frame(&mut writer, frame, &deadline).map_err(|error| format!("{error:?}"))?;
        }
        writer.shutdown(std::net::Shutdown::Write)?;
        assert_eq!(
            read_audit_and_receipt(&mut reader, &deadline).map_err(|error| format!("{error:?}"))?,
            (vec![first_audit, second_audit], receipt)
        );
        Ok(())
    }

    #[test]
    fn audit_reader_rejects_a_non_audit_frame_before_spr1() -> TestResult {
        let (mut writer, mut reader) = UnixStream::pair()?;
        let deadline = Deadline::new(Duration::from_secs(1))?;
        write_frame(&mut writer, &selector_record("SBC1")?, &deadline)
            .map_err(|error| format!("{error:?}"))?;
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
        write_frame(&mut writer, &result, &deadline).map_err(|error| format!("{error:?}"))?;
        writer.shutdown(std::net::Shutdown::Write)?;
        let (_, chunks, terminal) =
            read_output_frames(&mut reader, &deadline).map_err(|error| format!("{error:?}"))?;
        assert!(chunks.is_empty());
        assert_eq!(terminal, result);
        Ok(())
    }

    #[test]
    fn authenticated_frames_preserve_exact_record_bytes_and_sau1_order() {
        let frames = AuthenticatedProviderFrames::new(
            b"exact agr1".to_vec(),
            b"exact spr1".to_vec(),
            b"exact spy1".to_vec(),
            vec![b"first sau1".to_vec(), b"second sau1".to_vec()],
        );

        assert_eq!(frames.agr1(), b"exact agr1");
        assert_eq!(frames.spr1(), b"exact spr1");
        assert_eq!(frames.spy1(), b"exact spy1");
        assert_eq!(
            frames.sau1(),
            &[b"first sau1".to_vec(), b"second sau1".to_vec()]
        );
    }

    #[test]
    fn staged_output_keeps_descriptor_bound_to_the_stream() -> TestResult {
        let bytes = b"verified output";
        let descriptor = PayloadDescriptor {
            byte_length: u64::try_from(bytes.len()).expect("test length fits u64"),
            digest: payload_digest(PayloadDirection::Output, bytes),
        };
        let mut file = tempfile::NamedTempFile::new()?;
        file.write_all(bytes)?;
        let mut output = StagedProviderOutput::new(file, descriptor.clone());

        let streamed = output.with_reader(|bound_descriptor, reader| {
            let mut streamed = Vec::new();
            reader
                .read_to_end(&mut streamed)
                .map_err(|_| SelectorBoundaryError::Io)?;
            assert_eq!(bound_descriptor, &descriptor);
            Ok(streamed)
        })?;

        assert_eq!(streamed, bytes);
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
    fn authenticated_agr1_keeps_its_digest_when_the_sole_replay_is_incomplete() -> TestResult {
        let fixture = crate::selector_transport_test_fixture::authenticated_transport_fixture()?;
        let deadline = Deadline::new(Duration::from_secs(1))?;
        let (mut provider, mut root) = UnixStream::pair()?;
        write_frame(&mut provider, &fixture.agr1, &deadline)
            .map_err(|error| format!("AGR1 write failed: {error:?}"))?;
        provider.shutdown(std::net::Shutdown::Write)?;
        let mut retained_grant = None;
        assert!(matches!(
            read_response(
                &mut root,
                &fixture.provider,
                &fixture.commitment,
                &fixture.request,
                &deadline,
                &mut retained_grant,
            ),
            Err(ReceiveFailure::Incomplete)
        ));
        let (provider, mut root) = UnixStream::pair()?;
        provider.shutdown(std::net::Shutdown::Write)?;
        assert!(matches!(
            read_response(
                &mut root,
                &fixture.provider,
                &fixture.commitment,
                &fixture.request,
                &deadline,
                &mut retained_grant,
            ),
            Err(ReceiveFailure::Incomplete)
        ));
        let grant = fixture.provider.authenticate_selector_grant(
            &fixture.agr1,
            &fixture.request,
            &fixture.commitment,
        )?;
        assert!(matches!(
            classify_receive_failure(
                &retained_grant,
                PostAdmissionProviderFailure::TerminalUnavailable,
            ),
            ProviderTransportError::AfterAdmission {
                agr1_digest,
                failure: PostAdmissionProviderFailure::TerminalUnavailable,
            } if agr1_digest == grant.grant_digest
        ));
        Ok(())
    }

    #[test]
    fn malformed_evidence_after_authenticated_agr1_is_phase_two() -> TestResult {
        let fixture = crate::selector_transport_test_fixture::authenticated_transport_fixture()?;
        let deadline = Deadline::new(Duration::from_secs(1))?;
        let (mut provider, mut root) = UnixStream::pair()?;
        write_frame(&mut provider, &fixture.agr1, &deadline)
            .map_err(|error| format!("AGR1 write failed: {error:?}"))?;
        write_frame(&mut provider, b"malformed terminal evidence", &deadline)
            .map_err(|error| format!("malformed frame write failed: {error:?}"))?;
        provider.shutdown(std::net::Shutdown::Write)?;
        let mut retained_grant = None;
        assert!(matches!(
            read_response(
                &mut root,
                &fixture.provider,
                &fixture.commitment,
                &fixture.request,
                &deadline,
                &mut retained_grant,
            ),
            Err(ReceiveFailure::Invalid)
        ));
        let grant = fixture.provider.authenticate_selector_grant(
            &fixture.agr1,
            &fixture.request,
            &fixture.commitment,
        )?;
        assert!(matches!(
            classify_receive_failure(
                &retained_grant,
                PostAdmissionProviderFailure::EvidenceInvalid,
            ),
            ProviderTransportError::AfterAdmission {
                agr1_digest,
                failure: PostAdmissionProviderFailure::EvidenceInvalid,
            } if agr1_digest == grant.grant_digest
        ));
        Ok(())
    }

    fn selector_record(magic: &str) -> TestResult<Vec<u8>> {
        let unsigned = Value::Array(vec![Value::Text(magic.to_owned())]);
        encode_value(&Value::Array(vec![unsigned, Value::Bytes(vec![1])]))
            .map_err(|error| format!("{error:?}").into())
    }
}
