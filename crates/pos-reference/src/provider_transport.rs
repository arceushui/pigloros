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

fn artifact_invalid<T>(_: T) -> SelectorBoundaryError {
    SelectorBoundaryError::ArtifactInvalid
}

fn selector_unavailable<T>(_: T) -> SelectorBoundaryError {
    SelectorBoundaryError::SelectorUnavailable
}

fn io_error<T>(_: T) -> SelectorBoundaryError {
    SelectorBoundaryError::Io
}

fn transport_before_admission<T>(_: T) -> ProviderTransportError {
    ProviderTransportError::BeforeAdmission
}

fn receive_invalid<T>(_: T) -> ReceiveFailure {
    ReceiveFailure::Invalid
}

fn receive_incomplete<T>(_: T) -> ReceiveFailure {
    ReceiveFailure::Incomplete
}

fn invalid_errno<T>(_: T) -> rustix::io::Errno {
    rustix::io::Errno::INVAL
}

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
    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(crate) fn from_test_frames(
        grant_frame: Vec<u8>,
        receipt_frame: Vec<u8>,
        result_frame: Vec<u8>,
        audit_frames: Vec<Vec<u8>>,
        output: Option<(tempfile::NamedTempFile, PayloadDescriptor)>,
    ) -> Self {
        Self {
            frames: AuthenticatedProviderFrames::new(
                grant_frame,
                receipt_frame,
                result_frame,
                audit_frames,
            ),
            agr1_digest: [7; 32],
            output: output.map(|(file, descriptor)| StagedProviderOutput::new(file, descriptor)),
        }
    }

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
            .map_err(io_error)
            .and_then(|_| compose(&self.descriptor, file))
    }
}

#[derive(Clone, Debug)]
struct SelectedProviderEndpoint {
    path: PathBuf,
    device: u64,
    inode: u64,
    owner: u32,
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
        Self::from_validated_path(execute, ROOT_UID)
    }

    fn from_validated_path(path: &Path, owner: u32) -> Result<Self, SelectorBoundaryError> {
        endpoint_metadata(path, None, owner)
            .map(|metadata| Self::from_identity(path, &metadata, owner))
    }

    fn from_identity(path: &Path, metadata: &Metadata, owner: u32) -> Self {
        Self {
            path: path.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
            owner,
        }
    }

    fn connect(&self, timeout: Duration) -> Result<UnixStream, SelectorBoundaryError> {
        endpoint_metadata(&self.path, Some((self.device, self.inode)), self.owner)
            .and_then(|before| {
                SocketAddrUnix::new(&self.path)
                    .map_err(artifact_invalid)
                    .map(|address| (before, address))
            })
            .and_then(|(before, address)| {
                socket_with(
                    AddressFamily::UNIX,
                    SocketType::STREAM,
                    SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
                    None,
                )
                .map_err(selector_unavailable)
                .map(|descriptor| (before, address, descriptor))
            })
            .and_then(|(before, address, descriptor)| {
                complete_nonblocking_connect(connect(&descriptor, &address), &descriptor, timeout)
                    .map_err(selector_unavailable)
                    .map(|()| (before, descriptor))
            })
            .and_then(|(before, descriptor)| {
                let stream = UnixStream::from(descriptor);
                stream
                    .set_nonblocking(false)
                    .map_err(selector_unavailable)
                    .map(|()| (before, stream))
            })
            .and_then(|(before, stream)| {
                endpoint_metadata(&self.path, Some((self.device, self.inode)), self.owner)
                    .map(|after| (before, stream, after))
            })
            .and_then(|(before, stream, after)| {
                socket_peercred(stream.as_fd())
                    .map_err(artifact_invalid)
                    .map(|peer| (before, stream, after, peer))
            })
            .and_then(|(before, stream, after, peer)| {
                validate_connected_endpoint(
                    (before.dev(), before.ino()),
                    (after.dev(), after.ino()),
                    peer.uid.as_raw(),
                    self.owner,
                )
                .map(|()| stream)
            })
    }
}

const fn provider_transport(endpoint: SelectedProviderEndpoint) -> ProviderTransport {
    ProviderTransport { endpoint }
}

fn complete_nonblocking_connect(
    result: rustix::io::Result<()>,
    descriptor: &impl AsFd,
    timeout: Duration,
) -> rustix::io::Result<()> {
    match result {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::INPROGRESS) => wait_for_connection(descriptor, timeout),
        Err(error) => Err(error),
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
        SelectedProviderEndpoint::from_admitted(admitted).map(provider_transport)
    }

    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(crate) fn from_path_for_test(path: &Path) -> Result<Self, SelectorBoundaryError> {
        let metadata = std::fs::symlink_metadata(path).map_err(io_error)?;
        Ok(Self {
            endpoint: SelectedProviderEndpoint::from_identity(path, &metadata, metadata.uid()),
        })
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
        let request =
            SandboxExecuteRequest::from_canonical_cbor(spx1).map_err(transport_before_admission)?;
        validate_input(&request.adapter_input, input).map_err(transport_before_admission)?;
        let deadline = Deadline::new(watchdog).map_err(transport_before_admission)?;
        let mut retained_grant = None;
        match self.execute_once(
            admitted,
            commitment,
            &request,
            spx1,
            input,
            &deadline,
            &mut retained_grant,
        ) {
            Ok(execution) => return Ok(execution),
            Err(ReceiveFailure::Invalid) => {
                return Err(classify_receive_failure(
                    retained_grant.as_ref(),
                    PostAdmissionProviderFailure::EvidenceInvalid,
                ));
            }
            Err(ReceiveFailure::Incomplete) => {}
        }
        match self.execute_once(
            admitted,
            commitment,
            &request,
            spx1,
            input,
            &deadline,
            &mut retained_grant,
        ) {
            Ok(execution) => Ok(execution),
            Err(ReceiveFailure::Invalid) => Err(classify_receive_failure(
                retained_grant.as_ref(),
                PostAdmissionProviderFailure::EvidenceInvalid,
            )),
            Err(ReceiveFailure::Incomplete) => Err(classify_receive_failure(
                retained_grant.as_ref(),
                PostAdmissionProviderFailure::TerminalUnavailable,
            )),
        }
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
        deadline
            .remaining()
            .and_then(|remaining| self.endpoint.connect(remaining).map_err(receive_incomplete))
            .and_then(|mut stream| {
                write_frame(&mut stream, spx1, deadline)
                    .and_then(|()| write_input(&mut stream, request, input, deadline))
                    .and_then(|()| {
                        stream
                            .shutdown(std::net::Shutdown::Write)
                            .map_err(receive_incomplete)
                    })
                    .and_then(|()| {
                        read_response(
                            &mut stream,
                            admitted,
                            commitment,
                            request,
                            deadline,
                            retained_grant,
                        )
                    })
            })
    }
}

fn validate_connected_endpoint(
    before: (u64, u64),
    after: (u64, u64),
    peer_owner: u32,
    expected_owner: u32,
) -> Result<(), SelectorBoundaryError> {
    if before != after || peer_owner != expected_owner {
        Err(SelectorBoundaryError::ArtifactInvalid)
    } else {
        Ok(())
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
        self.remaining().and_then(|remaining| {
            stream
                .set_read_timeout(Some(remaining))
                .map_err(receive_incomplete)
        })
    }

    fn set_write(&self, stream: &UnixStream) -> Result<(), ReceiveFailure> {
        self.remaining().and_then(|remaining| {
            stream
                .set_write_timeout(Some(remaining))
                .map_err(receive_incomplete)
        })
    }
}

fn wait_for_connection(descriptor: &impl AsFd, timeout: Duration) -> rustix::io::Result<()> {
    i64::try_from(timeout.as_secs())
        .map_err(invalid_errno)
        .and_then(|seconds| {
            let timeout = Timespec {
                tv_sec: seconds,
                tv_nsec: timeout.subsec_nanos().into(),
            };
            let mut descriptors = [PollFd::new(descriptor, PollFlags::OUT)];
            poll(&mut descriptors, Some(&timeout))
        })
        .and_then(|ready| socket_error(descriptor).map(|error| (ready, error)))
        .and_then(|(ready, error)| ensure_connected_poll(ready, error))
}

const fn ensure_connected_poll(
    ready: usize,
    error: rustix::io::Result<()>,
) -> rustix::io::Result<()> {
    if ready == 0 || error.is_err() {
        return Err(rustix::io::Errno::TIMEDOUT);
    }
    Ok(())
}

fn validate_input(
    descriptor: &PayloadDescriptor,
    input: &[u8],
) -> Result<(), SelectorBoundaryError> {
    u64::try_from(input.len())
        .map_err(artifact_invalid)
        .and_then(|length| {
            if length != descriptor.byte_length
                || payload_digest(PayloadDirection::Input, input) != descriptor.digest
            {
                Err(SelectorBoundaryError::ArtifactInvalid)
            } else {
                Ok(())
            }
        })
}

fn write_input(
    stream: &mut UnixStream,
    request: &SandboxExecuteRequest,
    input: &[u8],
    deadline: &Deadline,
) -> Result<(), ReceiveFailure> {
    input
        .chunks(CHUNK_BYTES)
        .enumerate()
        .try_for_each(|(index, bytes)| {
            u64::try_from(index)
                .map_err(receive_invalid)
                .and_then(|index| encode_input_chunk(request, index, bytes))
                .and_then(|chunk| write_frame(stream, &chunk, deadline))
        })
}

fn encode_input_chunk(
    request: &SandboxExecuteRequest,
    index: u64,
    bytes: &[u8],
) -> Result<Vec<u8>, ReceiveFailure> {
    u64::try_from(CHUNK_BYTES)
        .map_err(receive_invalid)
        .and_then(|chunk_bytes| {
            index
                .checked_mul(chunk_bytes)
                .ok_or(ReceiveFailure::Invalid)
        })
        .and_then(|offset| {
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
            encode_value(&unsigned).and_then(|encoded| {
                let digest = record_digest("SBC1", &encoded);
                encode_value(&Value::Array(vec![unsigned, Value::Bytes(digest.to_vec())]))
            })
        })
}

fn read_response(
    stream: &mut UnixStream,
    admitted: &AdmittedSandboxProvider,
    commitment: &SelectorGrantCommitment,
    request: &SandboxExecuteRequest,
    deadline: &Deadline,
    retained_grant: &mut Option<RetainedGrant>,
) -> Result<AuthenticatedProviderTerminal, ReceiveFailure> {
    read_frame(stream, deadline)
        .and_then(|first| first.ok_or(ReceiveFailure::Incomplete))
        .and_then(|first| record_magic(&first).map(|magic| (first, magic)))
        .and_then(|(first, magic)| match magic.as_str() {
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
            "SPY1" => ensure_eof(stream, deadline).and(Err(ReceiveFailure::Invalid)),
            _ => Err(ReceiveFailure::Invalid),
        })
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
    verify_retained_grant(retained_grant.as_ref(), &grant_bytes)
        .and_then(|()| {
            admitted
                .authenticate_selector_grant(&grant_bytes, request, commitment)
                .map_err(receive_invalid)
        })
        .and_then(|grant| {
            retain_authenticated_grant(retained_grant, grant_bytes.clone(), grant.grant_digest);
            read_audit_and_receipt(stream, deadline).map(|(audit, receipt)| (grant, audit, receipt))
        })
        .and_then(|(grant, audit_bytes, receipt_bytes)| {
            admitted
                .authenticate_receipt(&receipt_bytes, &grant)
                .map_err(receive_invalid)
                .map(|receipt| (grant, audit_bytes, receipt_bytes, receipt))
        })
        .and_then(|state| {
            read_output_frames(stream, deadline)
                .map(|(file, chunks, result)| (state, file, chunks, result))
        })
        .and_then(
            |((grant, audit_bytes, receipt_bytes, receipt), file, chunks, result_bytes)| {
                admitted
                    .authenticate_terminal_result(&result_bytes, request, &grant, &receipt)
                    .map_err(receive_invalid)
                    .map(|result| {
                        (
                            grant,
                            audit_bytes,
                            receipt_bytes,
                            receipt,
                            file,
                            chunks,
                            result_bytes,
                            result,
                        )
                    })
            },
        )
        .and_then(|state| ensure_eof(stream, deadline).map(|()| state))
        .and_then(
            |(grant, audit_bytes, receipt_bytes, receipt, file, chunks, result_bytes, result)| {
                admitted
                    .authenticate_audit_chain(&audit_bytes, &receipt, &result)
                    .map_err(receive_invalid)
                    .map(|_| {
                        (
                            grant,
                            audit_bytes,
                            receipt_bytes,
                            file,
                            chunks,
                            result_bytes,
                            result,
                        )
                    })
            },
        )
        .and_then(
            |(grant, audit_bytes, receipt_bytes, file, chunks, result_bytes, result)| {
                stage_output(file, chunks, request, &result).map(|output| {
                    AuthenticatedProviderTerminal::Execution(AuthenticatedProviderExecution {
                        frames: AuthenticatedProviderFrames::new(
                            grant_bytes,
                            receipt_bytes,
                            result_bytes,
                            audit_bytes,
                        ),
                        agr1_digest: grant.grant_digest,
                        output,
                    })
                })
            },
        )
}

fn read_error_response(
    stream: &mut UnixStream,
    admitted: &AdmittedSandboxProvider,
    request: &SandboxExecuteRequest,
    deadline: &Deadline,
    error_bytes: Vec<u8>,
) -> Result<AuthenticatedProviderTerminal, ReceiveFailure> {
    ensure_eof(stream, deadline)
        .and_then(|()| {
            admitted
                .authenticate_selector_error(&error_bytes, request)
                .map_err(receive_invalid)
        })
        .map(|()| AuthenticatedProviderTerminal::Error(error_bytes))
}

fn verify_retained_grant(
    retained_grant: Option<&RetainedGrant>,
    current: &[u8],
) -> Result<(), ReceiveFailure> {
    if retained_grant.is_some_and(|previous| previous.bytes.as_slice() != current) {
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
    retained_grant: Option<&RetainedGrant>,
    failure: PostAdmissionProviderFailure,
) -> ProviderTransportError {
    retained_grant.map_or(ProviderTransportError::BeforeAdmission, |grant| {
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
    let mut file = tempfile::NamedTempFile::new().map_err(receive_incomplete)?;
    let mut chunks = Vec::new();
    loop {
        let frame = read_frame(stream, deadline)?.ok_or(ReceiveFailure::Incomplete)?;
        match record_magic(&frame)?.as_str() {
            "SBC1" if chunks.len() < 128 => {
                let chunk =
                    SandboxPayloadChunk::from_canonical_cbor(&frame).map_err(receive_invalid)?;
                file.write_all(&chunk.bytes).map_err(receive_incomplete)?;
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
    match result.output.as_ref() {
        Some(descriptor) => {
            let validator = PayloadStreamValidator::new(
                result.result_digest,
                request.request.request_id,
                request.attempt_id,
                PayloadDirection::Output,
                descriptor.clone(),
            )
            .map_err(receive_invalid);
            validator.and_then(|mut validator| {
                file.seek(SeekFrom::Start(0))
                    .map_err(receive_incomplete)
                    .and_then(|_| {
                        chunks.into_iter().try_for_each(|chunk| {
                            let mut bytes = vec![0; chunk.length];
                            file.read_exact(&mut bytes)
                                .map_err(receive_incomplete)
                                .and_then(|()| {
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
                                        .map_err(receive_invalid)
                                })
                        })
                    })
                    .and_then(|()| validator.finish().map_err(receive_invalid))
                    .map(|()| Some(StagedProviderOutput::new(file, descriptor.clone())))
            })
        }
        None if chunks.is_empty() => Ok(None),
        None => Err(ReceiveFailure::Invalid),
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
    deadline
        .set_write(stream)
        .and_then(|()| u32::try_from(bytes.len()).map_err(receive_invalid))
        .and_then(|length| {
            stream
                .write_all(&length.to_be_bytes())
                .map_err(receive_incomplete)
        })
        .and_then(|()| deadline.set_write(stream))
        .and_then(|()| stream.write_all(bytes).map_err(receive_incomplete))
}

fn read_frame(
    stream: &mut UnixStream,
    deadline: &Deadline,
) -> Result<Option<Vec<u8>>, ReceiveFailure> {
    let mut prefix = [0_u8; 4];
    deadline.set_read(stream).and_then(|()| {
        stream
            .read(&mut prefix[..1])
            .map_err(receive_incomplete)
            .and_then(|read| {
                if read == 0 {
                    return Ok(None);
                }
                deadline
                    .set_read(stream)
                    .and_then(|()| {
                        stream
                            .read_exact(&mut prefix[1..])
                            .map_err(receive_incomplete)
                    })
                    .and_then(|()| {
                        usize::try_from(u32::from_be_bytes(prefix)).map_err(receive_invalid)
                    })
                    .and_then(|length| {
                        if length == 0 || length > CONTROL_LIMIT {
                            return Err(ReceiveFailure::Invalid);
                        }
                        let mut bytes = vec![0; length];
                        deadline
                            .set_read(stream)
                            .and_then(|()| {
                                stream.read_exact(&mut bytes).map_err(receive_incomplete)
                            })
                            .map(|()| Some(bytes))
                    })
            })
    })
}

fn ensure_eof(stream: &mut UnixStream, deadline: &Deadline) -> Result<(), ReceiveFailure> {
    let mut byte = [0_u8; 1];
    deadline.set_read(stream).and_then(|()| {
        stream
            .read(&mut byte)
            .map_err(receive_incomplete)
            .and_then(|read| {
                if read == 0 {
                    Ok(())
                } else {
                    Err(ReceiveFailure::Invalid)
                }
            })
    })
}

fn record_magic(bytes: &[u8]) -> Result<String, ReceiveFailure> {
    let value: Value = ciborium::from_reader(bytes).map_err(receive_invalid)?;
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
    ciborium::into_writer(value, &mut bytes)
        .map_err(receive_invalid)
        .map(|()| bytes)
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
    expected_owner: u32,
) -> Result<Metadata, SelectorBoundaryError> {
    let metadata = std::fs::symlink_metadata(path).map_err(selector_unavailable)?;
    let identity_matches = expected_identity
        .is_none_or(|(device, inode)| metadata.dev() == device && metadata.ino() == inode);
    if !metadata.file_type().is_socket()
        || metadata.uid() != expected_owner
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
    use std::os::unix::net::UnixListener;

    use std::os::unix::fs::PermissionsExt;

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    #[test]
    fn closed_error_mappers_and_connect_completion_preserve_failure_classes() -> TestResult {
        assert_eq!(artifact_invalid(()), SelectorBoundaryError::ArtifactInvalid);
        assert_eq!(
            selector_unavailable(()),
            SelectorBoundaryError::SelectorUnavailable
        );
        assert_eq!(io_error(()), SelectorBoundaryError::Io);
        assert_eq!(
            transport_before_admission(()),
            ProviderTransportError::BeforeAdmission
        );
        assert_eq!(receive_invalid(()), ReceiveFailure::Invalid);
        assert_eq!(receive_incomplete(()), ReceiveFailure::Incomplete);
        assert_eq!(invalid_errno(()), rustix::io::Errno::INVAL);

        let directory = tempfile::tempdir()?;
        let path = directory.path().join("constructor.sock");
        let _listener = UnixListener::bind(&path)?;
        let metadata = std::fs::symlink_metadata(&path)?;
        let transport = provider_transport(SelectedProviderEndpoint::from_identity(
            &path,
            &metadata,
            metadata.uid(),
        ));
        assert_eq!(transport.endpoint.path, path);

        let (descriptor, _peer) = UnixStream::pair()?;
        assert_eq!(
            complete_nonblocking_connect(Ok(()), &descriptor, Duration::from_secs(1)),
            Ok(())
        );
        assert_eq!(
            complete_nonblocking_connect(
                Err(rustix::io::Errno::CONNREFUSED),
                &descriptor,
                Duration::from_secs(1),
            ),
            Err(rustix::io::Errno::CONNREFUSED)
        );
        assert_eq!(
            complete_nonblocking_connect(
                Err(rustix::io::Errno::INPROGRESS),
                &descriptor,
                Duration::from_secs(1),
            ),
            Ok(())
        );
        assert_eq!(
            ensure_connected_poll(0, Ok(())),
            Err(rustix::io::Errno::TIMEDOUT)
        );
        assert_eq!(
            ensure_connected_poll(1, Err(rustix::io::Errno::CONNREFUSED)),
            Err(rustix::io::Errno::TIMEDOUT)
        );
        assert_eq!(ensure_connected_poll(1, Ok(())), Ok(()));
        Ok(())
    }

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
    fn frame_io_closes_empty_oversized_and_truncated_boundaries() -> TestResult {
        let deadline = Deadline::new(Duration::from_secs(1))?;
        let (mut writer, _) = UnixStream::pair()?;
        assert_eq!(
            write_frame(&mut writer, &[], &deadline),
            Err(ReceiveFailure::Invalid)
        );
        assert_eq!(
            {
                let oversized = vec![0; CONTROL_LIMIT + 1];
                write_frame(&mut writer, &oversized, &deadline)
            },
            Err(ReceiveFailure::Invalid)
        );

        for bytes in [vec![0], vec![0, 0, 0], vec![0, 0, 0, 2, 1]] {
            let (mut writer, mut reader) = UnixStream::pair()?;
            writer.write_all(&bytes)?;
            writer.shutdown(std::net::Shutdown::Write)?;
            assert_eq!(
                read_frame(&mut reader, &deadline),
                Err(ReceiveFailure::Incomplete)
            );
        }
        let (mut writer, mut reader) = UnixStream::pair()?;
        writer.write_all(&u32::try_from(CONTROL_LIMIT + 1)?.to_be_bytes())?;
        writer.shutdown(std::net::Shutdown::Write)?;
        assert_eq!(
            read_frame(&mut reader, &deadline),
            Err(ReceiveFailure::Invalid)
        );

        let (writer, mut reader) = UnixStream::pair()?;
        writer.shutdown(std::net::Shutdown::Write)?;
        assert!(ensure_eof(&mut reader, &deadline).is_ok());
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
    fn bounded_response_readers_reject_eof_and_record_overflow() -> TestResult {
        let deadline = Deadline::new(Duration::from_secs(2))?;
        let (writer, mut reader) = UnixStream::pair()?;
        writer.shutdown(std::net::Shutdown::Write)?;
        assert_eq!(
            read_audit_and_receipt(&mut reader, &deadline),
            Err(ReceiveFailure::Incomplete)
        );

        let (mut writer, mut reader) = UnixStream::pair()?;
        let audit = selector_record("SAU1")?;
        let audit_writer = std::thread::spawn(move || -> Result<(), String> {
            let deadline = Deadline::new(Duration::from_secs(5))
                .map_err(|error| format!("audit deadline failed: {error}"))?;
            for _ in 0..=MAX_AUDIT_RECORDS {
                write_frame(&mut writer, &audit, &deadline)
                    .map_err(|error| format!("audit write failed: {error:?}"))?;
            }
            writer
                .shutdown(std::net::Shutdown::Write)
                .map_err(|error| format!("audit shutdown failed: {error}"))
        });
        assert_eq!(
            read_audit_and_receipt(&mut reader, &deadline),
            Err(ReceiveFailure::Invalid)
        );
        audit_writer.join().map_err(|_| "audit writer panicked")??;

        let (writer, mut reader) = UnixStream::pair()?;
        writer.shutdown(std::net::Shutdown::Write)?;
        assert!(matches!(
            read_output_frames(&mut reader, &deadline),
            Err(ReceiveFailure::Incomplete)
        ));
        let (mut writer, mut reader) = UnixStream::pair()?;
        write_frame(&mut writer, &selector_record("SPR1")?, &deadline)
            .map_err(|error| format!("receipt write failed: {error:?}"))?;
        writer.shutdown(std::net::Shutdown::Write)?;
        assert!(matches!(
            read_output_frames(&mut reader, &deadline),
            Err(ReceiveFailure::Invalid)
        ));

        let (mut writer, mut reader) = UnixStream::pair()?;
        writer.write_all(&[0; 4])?;
        writer.shutdown(std::net::Shutdown::Write)?;
        assert_eq!(
            read_audit_and_receipt(&mut reader, &deadline),
            Err(ReceiveFailure::Invalid)
        );

        let (mut writer, mut reader) = UnixStream::pair()?;
        writer.write_all(&[0; 4])?;
        writer.shutdown(std::net::Shutdown::Write)?;
        assert!(matches!(
            read_output_frames(&mut reader, &deadline),
            Err(ReceiveFailure::Invalid)
        ));
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
            byte_length: u64::try_from(bytes.len())?,
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
    fn input_validation_binds_exact_directional_digest_and_length() -> TestResult {
        let input = b"exact input";
        let descriptor = PayloadDescriptor {
            byte_length: u64::try_from(input.len())?,
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
        Ok(())
    }

    #[test]
    fn endpoint_validation_closes_path_owner_mode_and_identity() -> TestResult {
        assert!(!root_owned_ancestors(Path::new("provider.sock")));
        assert!(root_owned_ancestors(Path::new("/provider.sock")));
        assert!(endpoint_metadata(Path::new("/missing-provider.sock"), None, ROOT_UID).is_err());
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("provider.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let metadata = std::fs::symlink_metadata(&path)?;
        assert!(endpoint_metadata(&path, None, metadata.uid()).is_ok());
        let endpoint = SelectedProviderEndpoint::from_validated_path(&path, metadata.uid())?;
        assert_eq!(endpoint.path, path);
        assert_eq!(endpoint.device, metadata.dev());
        assert_eq!(endpoint.inode, metadata.ino());
        assert_eq!(endpoint.owner, metadata.uid());
        assert!(validate_connected_endpoint(
            (metadata.dev(), metadata.ino()),
            (metadata.dev(), metadata.ino()),
            metadata.uid(),
            metadata.uid(),
        )
        .is_ok());
        assert!(validate_connected_endpoint(
            (metadata.dev(), metadata.ino()),
            (metadata.dev(), metadata.ino() ^ 1),
            metadata.uid(),
            metadata.uid(),
        )
        .is_err());
        assert!(validate_connected_endpoint(
            (metadata.dev(), metadata.ino()),
            (metadata.dev(), metadata.ino()),
            metadata.uid() ^ 1,
            metadata.uid(),
        )
        .is_err());
        assert!(endpoint_metadata(&path, None, metadata.uid() ^ 1).is_err());
        assert!(endpoint_metadata(
            &path,
            Some((metadata.dev(), metadata.ino() ^ 1)),
            metadata.uid()
        )
        .is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))?;
        assert!(endpoint_metadata(&path, None, metadata.uid()).is_err());
        Ok(())
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
                retained_grant.as_ref(),
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
    fn retained_grant_is_write_once_and_rejects_replay_substitution() -> TestResult {
        let mut retained = None;
        retain_authenticated_grant(&mut retained, b"first".to_vec(), [1; 32]);
        retain_authenticated_grant(&mut retained, b"second".to_vec(), [2; 32]);
        let retained = retained.ok_or("grant was not retained")?;
        assert_eq!(retained.bytes, b"first");
        assert_eq!(retained.digest, [1; 32]);
        assert!(verify_retained_grant(Some(&retained), b"first").is_ok());
        assert_eq!(
            verify_retained_grant(Some(&retained), b"second"),
            Err(ReceiveFailure::Invalid)
        );
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
                retained_grant.as_ref(),
                PostAdmissionProviderFailure::EvidenceInvalid,
            ),
            ProviderTransportError::AfterAdmission {
                agr1_digest,
                failure: PostAdmissionProviderFailure::EvidenceInvalid,
            } if agr1_digest == grant.grant_digest
        ));
        Ok(())
    }

    #[test]
    fn response_authentication_rejects_each_malformed_evidence_stage() -> TestResult {
        let fixture = crate::selector_transport_test_fixture::authenticated_transport_fixture()?;
        let malformed_cases = vec![
            vec![selector_record("AGR1")?],
            vec![fixture.agr1.clone(), b"malformed audit".to_vec()],
            vec![fixture.agr1.clone(), selector_record("SPR1")?],
            std::iter::once(fixture.agr1.clone())
                .chain(fixture.sau1.clone())
                .chain([fixture.spr1.clone(), selector_record("SBC1")?])
                .collect(),
            std::iter::once(fixture.agr1.clone())
                .chain(fixture.sau1.clone())
                .chain([
                    fixture.spr1.clone(),
                    fixture.output_chunk.clone(),
                    selector_record("SPY1")?,
                ])
                .collect(),
            std::iter::once(fixture.agr1.clone())
                .chain(fixture.sau1.clone())
                .chain([
                    fixture.spr1.clone(),
                    fixture.output_chunk.clone(),
                    fixture.spy1.clone(),
                    selector_record("EXTRA")?,
                ])
                .collect(),
        ];
        for frames in malformed_cases {
            let deadline = Deadline::new(Duration::from_secs(2))?;
            let (mut provider, mut root) = UnixStream::pair()?;
            for frame in frames {
                write_frame(&mut provider, &frame, &deadline)
                    .map_err(|error| format!("evidence write failed: {error:?}"))?;
            }
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
        }
        Ok(())
    }

    #[test]
    fn complete_authenticated_response_releases_only_verified_output() -> TestResult {
        let fixture = crate::selector_transport_test_fixture::authenticated_transport_fixture()?;
        let deadline = Deadline::new(Duration::from_secs(2))?;
        let (mut provider, mut root) = UnixStream::pair()?;
        for frame in std::iter::once(&fixture.agr1)
            .chain(fixture.sau1.iter())
            .chain([&fixture.spr1, &fixture.output_chunk, &fixture.spy1])
        {
            write_frame(&mut provider, frame, &deadline)
                .map_err(|error| format!("provider frame write failed: {error:?}"))?;
        }
        provider.shutdown(std::net::Shutdown::Write)?;

        let mut retained_grant = None;
        let terminal = read_response(
            &mut root,
            &fixture.provider,
            &fixture.commitment,
            &fixture.request,
            &deadline,
            &mut retained_grant,
        )
        .map_err(|error| format!("provider response failed: {error:?}"))?;
        let AuthenticatedProviderTerminal::Execution(mut execution) = terminal else {
            return Err("expected authenticated execution".into());
        };
        assert_eq!(execution.agr1_bytes(), fixture.agr1);
        assert_eq!(execution.spr1_bytes(), fixture.spr1);
        assert_eq!(execution.spy1_bytes(), fixture.spy1);
        assert_eq!(execution.sau1_frames(), fixture.sau1);
        let grant =
            crate::sandbox_provider_protocol::AdmissionGrant::from_canonical_cbor(&fixture.agr1)?;
        assert_eq!(execution.agr1_digest(), grant.grant_digest);
        let output = execution
            .with_verified_output(|descriptor, reader| {
                let mut bytes = Vec::new();
                reader
                    .read_to_end(&mut bytes)
                    .map_err(|_| SelectorBoundaryError::Io)?;
                assert_eq!(descriptor.byte_length, bytes.len() as u64);
                Ok(bytes)
            })?
            .ok_or("completed response omitted output")?;
        assert_eq!(output, b"output");
        assert!(retained_grant.is_some());
        Ok(())
    }

    #[test]
    fn complete_authenticated_error_is_returned_without_admission_evidence() -> TestResult {
        let fixture = crate::selector_transport_test_fixture::authenticated_transport_fixture()?;
        let deadline = Deadline::new(Duration::from_secs(2))?;
        let (mut provider, mut root) = UnixStream::pair()?;
        write_frame(&mut provider, &fixture.spe1, &deadline)
            .map_err(|error| format!("provider error write failed: {error:?}"))?;
        provider.shutdown(std::net::Shutdown::Write)?;

        let mut retained_grant = None;
        let terminal = read_response(
            &mut root,
            &fixture.provider,
            &fixture.commitment,
            &fixture.request,
            &deadline,
            &mut retained_grant,
        )
        .map_err(|error| format!("provider error response failed: {error:?}"))?;
        let AuthenticatedProviderTerminal::Error(error) = terminal else {
            return Err("expected authenticated provider error".into());
        };
        assert_eq!(error, fixture.spe1);
        assert!(retained_grant.is_none());
        Ok(())
    }

    #[test]
    fn non_output_terminal_does_not_release_a_staging_file() -> TestResult {
        let fixture = crate::selector_transport_test_fixture::authenticated_transport_fixture()?;
        assert!(stage_output(
            tempfile::NamedTempFile::new()?,
            Vec::new(),
            &fixture.request,
            &fixture.non_output_result,
        )
        .map_err(|failure| format!("non-output staging failed: {failure:?}"))?
        .is_none());
        let chunk = SandboxPayloadChunk::from_canonical_cbor(&fixture.output_chunk)?;
        assert!(matches!(
            stage_output(
                tempfile::NamedTempFile::new()?,
                vec![ChunkMeta::from(&chunk)],
                &fixture.request,
                &fixture.non_output_result,
            ),
            Err(ReceiveFailure::Invalid)
        ));
        Ok(())
    }

    #[test]
    fn selected_endpoint_returns_an_authenticated_pre_admission_error() -> TestResult {
        let fixture = crate::selector_transport_test_fixture::authenticated_transport_fixture()?;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("provider.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let transport = ProviderTransport::from_path_for_test(&path)?;
        let expected_spx1 = fixture.spx1.clone();
        let error = fixture.spe1.clone();
        let provider = std::thread::spawn(move || -> Result<(), String> {
            let (mut stream, _) = listener
                .accept()
                .map_err(|failure| format!("provider accept failed: {failure}"))?;
            let deadline = Deadline::new(Duration::from_secs(5))
                .map_err(|failure| format!("provider deadline failed: {failure}"))?;
            read_expected_attempt(&mut stream, &expected_spx1, &deadline)?;
            write_frame(&mut stream, &error, &deadline)
                .map_err(|failure| format!("provider error write failed: {failure:?}"))?;
            stream
                .shutdown(std::net::Shutdown::Write)
                .map_err(|failure| format!("provider shutdown failed: {failure}"))
        });

        let terminal = transport
            .execute(
                &fixture.provider,
                &fixture.commitment,
                &fixture.spx1,
                b"input",
                Duration::from_secs(5),
            )
            .map_err(|failure| format!("provider execution failed: {failure:?}"))?;
        let AuthenticatedProviderTerminal::Error(error) = terminal else {
            return Err("expected authenticated provider error".into());
        };
        assert_eq!(error, fixture.spe1);
        provider.join().map_err(|_| "provider thread panicked")??;
        Ok(())
    }

    #[test]
    fn selected_endpoint_executes_the_complete_authenticated_exchange() -> TestResult {
        let fixture = crate::selector_transport_test_fixture::authenticated_transport_fixture()?;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("provider.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let transport = ProviderTransport::from_path_for_test(&path)?;
        let expected_spx1 = fixture.spx1.clone();
        let response_frames = std::iter::once(fixture.agr1.clone())
            .chain(fixture.sau1.clone())
            .chain([
                fixture.spr1.clone(),
                fixture.output_chunk.clone(),
                fixture.spy1.clone(),
            ])
            .collect::<Vec<_>>();
        let provider = std::thread::spawn(move || -> Result<(), String> {
            let (mut stream, _) = listener
                .accept()
                .map_err(|error| format!("provider accept failed: {error}"))?;
            let deadline = Deadline::new(Duration::from_secs(5))
                .map_err(|error| format!("provider deadline failed: {error}"))?;
            let spx1 = read_frame(&mut stream, &deadline)
                .map_err(|error| format!("SPX1 read failed: {error:?}"))?
                .ok_or("SPX1 frame missing")?;
            if spx1 != expected_spx1 {
                return Err("SPX1 bytes changed in transport".to_owned());
            }
            let input = read_frame(&mut stream, &deadline)
                .map_err(|error| format!("input read failed: {error:?}"))?
                .ok_or("input frame missing")?;
            let input = SandboxPayloadChunk::from_canonical_cbor(&input)
                .map_err(|error| format!("input chunk invalid: {error}"))?;
            if input.bytes != b"input" {
                return Err("input bytes changed in transport".to_owned());
            }
            if read_frame(&mut stream, &deadline)
                .map_err(|error| format!("input EOF read failed: {error:?}"))?
                .is_some()
            {
                return Err("unexpected extra input frame".to_owned());
            }
            for frame in response_frames {
                write_frame(&mut stream, &frame, &deadline)
                    .map_err(|error| format!("response write failed: {error:?}"))?;
            }
            stream
                .shutdown(std::net::Shutdown::Write)
                .map_err(|error| format!("provider shutdown failed: {error}"))
        });

        let terminal = transport
            .execute(
                &fixture.provider,
                &fixture.commitment,
                &fixture.spx1,
                b"input",
                Duration::from_secs(5),
            )
            .map_err(|error| format!("provider execution failed: {error:?}"))?;
        let AuthenticatedProviderTerminal::Execution(mut execution) = terminal else {
            return Err("expected authenticated execution".into());
        };
        let output = execution
            .with_verified_output(|_, reader| {
                let mut bytes = Vec::new();
                reader
                    .read_to_end(&mut bytes)
                    .map_err(|_| SelectorBoundaryError::Io)?;
                Ok(bytes)
            })?
            .ok_or("authenticated output missing")?;
        assert_eq!(output, b"output");
        provider.join().map_err(|_| "provider thread panicked")??;
        Ok(())
    }

    #[test]
    fn selected_endpoint_replays_once_after_an_authenticated_interruption() -> TestResult {
        let fixture = crate::selector_transport_test_fixture::authenticated_transport_fixture()?;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("provider.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let transport = ProviderTransport::from_path_for_test(&path)?;
        let expected_spx1 = fixture.spx1.clone();
        let agr1 = fixture.agr1.clone();
        let response_frames = fixture
            .sau1
            .clone()
            .into_iter()
            .chain([
                fixture.spr1.clone(),
                fixture.output_chunk.clone(),
                fixture.spy1.clone(),
            ])
            .collect::<Vec<_>>();
        let provider = std::thread::spawn(move || -> Result<(), String> {
            let deadline = Deadline::new(Duration::from_secs(5))
                .map_err(|error| format!("provider deadline failed: {error}"))?;
            let (mut first, _) = listener
                .accept()
                .map_err(|error| format!("first provider accept failed: {error}"))?;
            read_expected_attempt(&mut first, &expected_spx1, &deadline)?;
            write_frame(&mut first, &agr1, &deadline)
                .map_err(|error| format!("first AGR1 write failed: {error:?}"))?;
            drop(first);

            let (mut replay, _) = listener
                .accept()
                .map_err(|error| format!("replay provider accept failed: {error}"))?;
            read_expected_attempt(&mut replay, &expected_spx1, &deadline)?;
            write_frame(&mut replay, &agr1, &deadline)
                .map_err(|error| format!("replay AGR1 write failed: {error:?}"))?;
            for frame in response_frames {
                write_frame(&mut replay, &frame, &deadline)
                    .map_err(|error| format!("replay response write failed: {error:?}"))?;
            }
            replay
                .shutdown(std::net::Shutdown::Write)
                .map_err(|error| format!("provider shutdown failed: {error}"))
        });

        assert!(matches!(
            transport.execute(
                &fixture.provider,
                &fixture.commitment,
                &fixture.spx1,
                b"input",
                Duration::from_secs(5),
            ),
            Ok(AuthenticatedProviderTerminal::Execution(_))
        ));
        provider.join().map_err(|_| "provider thread panicked")??;
        Ok(())
    }

    #[test]
    fn selected_endpoint_classifies_invalid_pre_admission_evidence() -> TestResult {
        let fixture = crate::selector_transport_test_fixture::authenticated_transport_fixture()?;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("provider.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let transport = ProviderTransport::from_path_for_test(&path)?;
        let expected_spx1 = fixture.spx1.clone();
        let provider = std::thread::spawn(move || -> Result<(), String> {
            let (mut stream, _) = listener
                .accept()
                .map_err(|error| format!("provider accept failed: {error}"))?;
            let deadline = Deadline::new(Duration::from_secs(5))
                .map_err(|error| format!("provider deadline failed: {error}"))?;
            read_expected_attempt(&mut stream, &expected_spx1, &deadline)?;
            write_frame(
                &mut stream,
                &selector_record("AGR1").map_err(|error| error.to_string())?,
                &deadline,
            )
            .map_err(|error| format!("invalid AGR1 write failed: {error:?}"))?;
            stream
                .shutdown(std::net::Shutdown::Write)
                .map_err(|error| format!("provider shutdown failed: {error}"))
        });

        assert!(matches!(
            transport.execute(
                &fixture.provider,
                &fixture.commitment,
                &fixture.spx1,
                b"input",
                Duration::from_secs(5),
            ),
            Err(ProviderTransportError::BeforeAdmission)
        ));
        provider.join().map_err(|_| "provider thread panicked")??;
        Ok(())
    }

    #[test]
    fn selected_endpoint_retains_grant_when_both_terminal_attempts_end() -> TestResult {
        let fixture = crate::selector_transport_test_fixture::authenticated_transport_fixture()?;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("provider.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let transport = ProviderTransport::from_path_for_test(&path)?;
        let expected_spx1 = fixture.spx1.clone();
        let grant_frame = fixture.agr1.clone();
        let provider = std::thread::spawn(move || -> Result<(), String> {
            let deadline = Deadline::new(Duration::from_secs(5))
                .map_err(|error| format!("provider deadline failed: {error}"))?;
            for _ in 0..2 {
                let (mut stream, _) = listener
                    .accept()
                    .map_err(|error| format!("provider accept failed: {error}"))?;
                read_expected_attempt(&mut stream, &expected_spx1, &deadline)?;
                write_frame(&mut stream, &grant_frame, &deadline)
                    .map_err(|error| format!("AGR1 write failed: {error:?}"))?;
                stream
                    .shutdown(std::net::Shutdown::Write)
                    .map_err(|error| format!("provider shutdown failed: {error}"))?;
            }
            Ok(())
        });

        let grant = fixture.provider.authenticate_selector_grant(
            &fixture.agr1,
            &fixture.request,
            &fixture.commitment,
        )?;
        assert!(matches!(
            transport.execute(
                &fixture.provider,
                &fixture.commitment,
                &fixture.spx1,
                b"input",
                Duration::from_secs(5),
            ),
            Err(ProviderTransportError::AfterAdmission {
                agr1_digest,
                failure: PostAdmissionProviderFailure::TerminalUnavailable,
            }) if agr1_digest == grant.grant_digest
        ));
        provider.join().map_err(|_| "provider thread panicked")??;
        Ok(())
    }

    #[test]
    fn selected_endpoint_rejects_invalid_evidence_on_the_recovery_attempt() -> TestResult {
        let fixture = crate::selector_transport_test_fixture::authenticated_transport_fixture()?;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("provider.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let transport = ProviderTransport::from_path_for_test(&path)?;
        let expected_spx1 = fixture.spx1.clone();
        let provider = std::thread::spawn(move || -> Result<(), String> {
            let deadline = Deadline::new(Duration::from_secs(5))
                .map_err(|error| format!("provider deadline failed: {error}"))?;
            let (mut first, _) = listener
                .accept()
                .map_err(|error| format!("first provider accept failed: {error}"))?;
            read_expected_attempt(&mut first, &expected_spx1, &deadline)?;
            drop(first);

            let (mut recovery, _) = listener
                .accept()
                .map_err(|error| format!("recovery provider accept failed: {error}"))?;
            read_expected_attempt(&mut recovery, &expected_spx1, &deadline)?;
            write_frame(
                &mut recovery,
                &selector_record("AGR1").map_err(|error| error.to_string())?,
                &deadline,
            )
            .map_err(|error| format!("invalid recovery AGR1 write failed: {error:?}"))?;
            recovery
                .shutdown(std::net::Shutdown::Write)
                .map_err(|error| format!("provider shutdown failed: {error}"))
        });

        assert!(matches!(
            transport.execute(
                &fixture.provider,
                &fixture.commitment,
                &fixture.spx1,
                b"input",
                Duration::from_secs(5),
            ),
            Err(ProviderTransportError::BeforeAdmission)
        ));
        provider.join().map_err(|_| "provider thread panicked")??;
        Ok(())
    }

    #[test]
    fn execute_rejects_invalid_requests_inputs_and_deadlines_before_connecting() -> TestResult {
        let fixture = crate::selector_transport_test_fixture::authenticated_transport_fixture()?;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("provider.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let transport = ProviderTransport::from_path_for_test(&path)?;
        for result in [
            transport.execute(
                &fixture.provider,
                &fixture.commitment,
                b"not SPX1",
                b"input",
                Duration::from_secs(1),
            ),
            transport.execute(
                &fixture.provider,
                &fixture.commitment,
                &fixture.spx1,
                b"substituted input",
                Duration::from_secs(1),
            ),
            transport.execute(
                &fixture.provider,
                &fixture.commitment,
                &fixture.spx1,
                b"input",
                Duration::MAX,
            ),
        ] {
            assert!(matches!(
                result,
                Err(ProviderTransportError::BeforeAdmission)
            ));
        }
        Ok(())
    }

    #[test]
    fn input_writer_emits_the_exact_parent_bound_chunk() -> TestResult {
        let fixture = crate::selector_transport_test_fixture::authenticated_transport_fixture()?;
        let deadline = Deadline::new(Duration::from_secs(1))?;
        let (mut root, mut provider) = UnixStream::pair()?;
        write_input(&mut root, &fixture.request, b"input", &deadline)
            .map_err(|error| format!("input write failed: {error:?}"))?;
        root.shutdown(std::net::Shutdown::Write)?;

        let bytes = read_frame(&mut provider, &deadline)
            .map_err(|error| format!("input read failed: {error:?}"))?
            .ok_or("input chunk missing")?;
        let chunk = SandboxPayloadChunk::from_canonical_cbor(&bytes)?;
        assert_eq!(chunk.parent_digest, fixture.request.request_digest);
        assert_eq!(chunk.request_id, fixture.request.request.request_id);
        assert_eq!(chunk.attempt_id, fixture.request.attempt_id);
        assert_eq!(chunk.direction, PayloadDirection::Input);
        assert_eq!(chunk.index, 0);
        assert_eq!(chunk.offset, 0);
        assert_eq!(chunk.bytes, b"input");
        assert!(read_frame(&mut provider, &deadline)
            .map_err(|error| format!("input EOF read failed: {error:?}"))?
            .is_none());
        Ok(())
    }

    fn read_expected_attempt(
        stream: &mut UnixStream,
        expected_spx1: &[u8],
        deadline: &Deadline,
    ) -> Result<(), String> {
        let spx1 = read_frame(stream, deadline)
            .map_err(|error| format!("SPX1 read failed: {error:?}"))?
            .ok_or("SPX1 frame missing")?;
        if spx1 != expected_spx1 {
            return Err("SPX1 bytes changed in transport".to_owned());
        }
        let input = read_frame(stream, deadline)
            .map_err(|error| format!("input read failed: {error:?}"))?
            .ok_or("input frame missing")?;
        let input = SandboxPayloadChunk::from_canonical_cbor(&input)
            .map_err(|error| format!("input chunk invalid: {error}"))?;
        if input.bytes != b"input" {
            return Err("input bytes changed in transport".to_owned());
        }
        if read_frame(stream, deadline)
            .map_err(|error| format!("input EOF read failed: {error:?}"))?
            .is_some()
        {
            return Err("unexpected extra input frame".to_owned());
        }
        Ok(())
    }

    #[test]
    fn response_dispatch_rejects_unadmitted_and_unknown_terminal_frames() -> TestResult {
        let fixture = crate::selector_transport_test_fixture::authenticated_transport_fixture()?;
        let deadline = Deadline::new(Duration::from_secs(1))?;
        for first in [selector_record("SPY1")?, selector_record("UNKNOWN")?] {
            let (mut provider, mut root) = UnixStream::pair()?;
            write_frame(&mut provider, &first, &deadline)
                .map_err(|error| format!("terminal write failed: {error:?}"))?;
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
        }
        assert_eq!(
            classify_receive_failure(None, PostAdmissionProviderFailure::EvidenceInvalid),
            ProviderTransportError::BeforeAdmission
        );

        let (mut provider, mut root) = UnixStream::pair()?;
        write_frame(&mut provider, &selector_record("SPE1")?, &deadline)
            .map_err(|error| format!("error write failed: {error:?}"))?;
        provider.shutdown(std::net::Shutdown::Write)?;
        let mut retained_grant = Some(RetainedGrant {
            bytes: fixture.agr1.clone(),
            digest: [4; 32],
        });
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
        Ok(())
    }

    #[test]
    fn framing_helpers_reject_closed_shapes_and_expired_deadlines() -> TestResult {
        assert_eq!(record_magic(&[0xff]), Err(ReceiveFailure::Invalid));
        for value in [
            Value::Null,
            Value::Array(Vec::new()),
            Value::Array(vec![Value::Null]),
            Value::Array(vec![Value::Array(Vec::new())]),
            Value::Array(vec![Value::Array(vec![Value::Null])]),
        ] {
            let encoded =
                encode_value(&value).map_err(|error| format!("encode failed: {error:?}"))?;
            assert_eq!(record_magic(&encoded), Err(ReceiveFailure::Invalid));
        }
        assert_eq!(
            encode_input_chunk(
                &crate::selector_transport_test_fixture::authenticated_transport_fixture()?.request,
                u64::MAX,
                b"x",
            ),
            Err(ReceiveFailure::Invalid)
        );
        let expired = Deadline::new(Duration::ZERO)?;
        assert_eq!(expired.remaining(), Err(ReceiveFailure::Incomplete));
        let (stream, _) = UnixStream::pair()?;
        assert_eq!(expired.set_read(&stream), Err(ReceiveFailure::Incomplete));
        assert_eq!(expired.set_write(&stream), Err(ReceiveFailure::Incomplete));
        assert_eq!(
            wait_for_connection(&UnixStream::pair()?.0, Duration::MAX),
            Err(rustix::io::Errno::INVAL)
        );
        assert!(wait_for_connection(&UnixStream::pair()?.0, Duration::from_secs(1)).is_ok());
        Ok(())
    }

    fn selector_record(magic: &str) -> TestResult<Vec<u8>> {
        let unsigned = Value::Array(vec![Value::Text(magic.to_owned())]);
        encode_value(&Value::Array(vec![unsigned, Value::Bytes(vec![1])]))
            .map_err(|error| format!("{error:?}").into())
    }
}
