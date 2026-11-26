//! The single EVR1/SPX1 read of a root peer's execute connection, the
//! authority factory over it, and descriptor-bound input (ADR-122
//! Amendment 1 changes A to D).

use std::{
    fs::File,
    io::{self, Read, Write},
    os::unix::{fs::FileExt as _, net::UnixStream},
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use crate::{
    adapter_transport::{read_attempt, write_attempt},
    evaluator_protocol::EvaluationRequest,
    sandbox_provider_protocol::{
        AdmissionAuthority, AdmissionGrant, AdmissionGrantFields, AdmissionLedger, Agr1,
        PayloadDescriptor, PayloadDirection, PayloadStreamValidator, SandboxExecuteRequest,
        SandboxPayloadChunk, SelfDigested, TransferRecord, Verified,
    },
    selector::{
        installation::{
            authority::AdmittedSelectorProvider, InstalledSelectorState, PositionalReader,
        },
        InstallationError,
    },
    selector_protocol::execute_request_for_case,
};

use super::super::{
    AdmittedAuthority, HeldImageAdmission, JoinFault, ProviderImageSnapshot, SnapshotFault,
};
use super::{
    budget::ControlSlot, AdmittedProviderExecution, Clock, ConnectionIdentity, ExecuteRefusal,
    Execution, ExecutionSource, FailedInput, GrantFailure, GrantedExecution, GrantedFacts,
    IssuedGrant, OutputReservationRefused, PreparedProviderExecution, ProviderExecutionPolicy,
    RecheckError, RefusalCause, RetainedCase, StagingCharge, StagingError, StagingLedger,
    TransferWindow,
};

const FRAME_LIMIT: usize = 16 * 1024 * 1024;
const INPUT_LIMIT: u64 = 128 * 1024 * 1024;
/// The BHC1 limit that bounds the pending-control slots.
const CONTROL_SLOTS_ID: usize = 13;
/// The BHC1 limit that bounds the initial control deadline, in ms.
const CONTROL_DEADLINE_ID: usize = 16;
/// The only UID whose execute connection is read (R11 §6 step 6).
const ROOT_UID: u32 = 0;

fn invalid<T>(_: T) -> StagingError {
    StagingError::InvalidSource
}
fn invalid_input<T>(_: T) -> StagingError {
    StagingError::InvalidInput
}

/// The time left until `until`, or `None` once it passed.
fn left(until: Instant) -> Option<Duration> {
    until
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
}

/// Refuse once the initial control deadline passed.
fn control_left(until: Instant) -> Result<(), StagingError> {
    left(until).map(drop).ok_or(StagingError::ControlExpired)
}

/// Refuse once the input window passed.
fn window_left(until: Instant) -> Result<(), StagingError> {
    left(until)
        .map(drop)
        .ok_or(StagingError::InputWindowExpired)
}

/// `milliseconds` after `start`; `None` for a zero or unrepresentable bound.
fn deadline_after(start: Instant, milliseconds: u64) -> Option<Instant> {
    (milliseconds != 0)
        .then(|| start.checked_add(Duration::from_millis(milliseconds)))
        .flatten()
}

/// The one absolute initial control deadline and any stricter transport
/// bound the stream already carried.
#[derive(Clone, Copy, Debug)]
struct TransferDeadlines {
    initial: Instant,
    transport: Option<Instant>,
}

impl TransferDeadlines {
    /// The deadlines of a read that starts now; `None` for a zero BHC1 ID
    /// 16, a step 1 failure (ADR-122 Amendment 1 T5).
    fn new(stream: &UnixStream, control_milliseconds: u64) -> Option<Self> {
        let now = Instant::now();
        deadline_after(now, control_milliseconds).and_then(|initial| {
            stream
                .read_timeout()
                .ok()
                .zip(stream.write_timeout().ok())
                .map(|(read, write)| {
                    let transport = read
                        .into_iter()
                        .chain(write)
                        .min()
                        .and_then(|timeout| now.checked_add(timeout));
                    Self {
                        initial: transport.map_or(initial, |until| initial.min(until)),
                        transport,
                    }
                })
        })
    }

    /// The input deadline: the ELM1 ID 16 window from `spx_completed`,
    /// under any stricter transport bound.
    fn input(&self, spx_completed: Instant, milliseconds: u64) -> Result<Instant, StagingError> {
        deadline_after(spx_completed, milliseconds)
            .map(|input| self.transport.map_or(input, |until| input.min(until)))
            .ok_or(StagingError::InputWindowExpired)
    }
}

fn require_grant_turn(stream: &UnixStream) -> Result<(), StagingError> {
    use rustix::net::{recv, RecvFlags};
    match recv(
        stream,
        &mut [0_u8; 1],
        RecvFlags::PEEK.union(RecvFlags::DONTWAIT),
    ) {
        Err(rustix::io::Errno::AGAIN) => Ok(()),
        Ok(_) => Err(StagingError::InvalidSource),
        Err(error) => Err(StagingError::Io(io::Error::from(error))),
    }
}

struct TimedStream<'a> {
    stream: &'a mut UnixStream,
    until: Instant,
}

fn timed_out() -> io::Error {
    io::Error::from(io::ErrorKind::TimedOut)
}

impl Read for TimedStream<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        left(self.until).ok_or_else(timed_out).and_then(|left| {
            self.stream
                .set_read_timeout(Some(left))
                .and_then(|()| self.stream.read(bytes))
        })
    }
}

impl Write for TimedStream<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        left(self.until).ok_or_else(timed_out).and_then(|left| {
            self.stream
                .set_write_timeout(Some(left))
                .and_then(|()| self.stream.write(bytes))
        })
    }
    fn flush(&mut self) -> io::Result<()> {
        // UnixStream writes directly to the socket and has no buffered output.
        Ok(())
    }
}

#[derive(Debug)]
pub(super) struct RetainedControl {
    bytes: Vec<u8>,
    // Drop the buffer before releasing its shared byte reservation.
    _charge: StagingCharge,
}

/// One frame's declared length: nonzero and at most 16 MiB.
fn frame_length(reader: &mut impl Read) -> Result<usize, StagingError> {
    let mut prefix = [0; 4];
    reader
        .read_exact(&mut prefix)
        .map_err(StagingError::from)
        .and_then(|()| usize::try_from(u32::from_be_bytes(prefix)).map_err(invalid))
        .and_then(|length| {
            if length == 0 || length > FRAME_LIMIT {
                Err(StagingError::InvalidSource)
            } else {
                Ok(length)
            }
        })
}

/// The `length` bytes of one frame's body.
fn frame_body(reader: &mut impl Read, length: usize) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes).map(|()| bytes)
}

/// One frame, its declared length charged before it is allocated.
fn frame(reader: &mut impl Read, ledger: &StagingLedger) -> Result<RetainedControl, StagingError> {
    frame_length(reader).and_then(|length| {
        ledger.reserve_storage(length as u64).and_then(|charge| {
            frame_body(reader, length)
                .map_err(StagingError::from)
                .map(|bytes| RetainedControl {
                    bytes,
                    _charge: charge,
                })
        })
    })
}

/// Whether a ledger refusal is the closed ledger (SPE1 `14`) rather than a
/// full one (`12`).
const fn closed(refused: &StagingError) -> bool {
    matches!(refused, StagingError::CleanupFailed)
}

/// Why the single read stopped at one source frame.
enum FrameFault {
    /// Step 1: a stalled, partial or out-of-bounds frame.
    Malformed,
    /// The ledger refused the frame's declared `pending` length.
    Uncharged { pending: usize, closed: bool },
}

/// One source frame, charged before allocation.
fn source_frame(
    reader: &mut impl Read,
    ledger: &StagingLedger,
) -> Result<RetainedControl, FrameFault> {
    frame_length(reader)
        .map_err(|_| FrameFault::Malformed)
        .and_then(|length| {
            ledger
                .reserve_storage(length as u64)
                .map_err(|refused| FrameFault::Uncharged {
                    pending: length,
                    closed: closed(&refused),
                })
                .and_then(|charge| {
                    frame_body(reader, length)
                        .map_err(|_| FrameFault::Malformed)
                        .map(|bytes| RetainedControl {
                            bytes,
                            _charge: charge,
                        })
                })
        })
}

impl FrameFault {
    /// The refusal of `stream`, read until `until`, after the source frames
    /// `evaluation` it already read.
    fn refusal(
        self,
        stream: UnixStream,
        until: Instant,
        evaluation: Option<Vec<u8>>,
    ) -> SourceRefusal {
        match self {
            Self::Malformed => SourceRefusal::Malformed(stream),
            Self::Uncharged { pending, closed } => SourceRefusal::Uncharged(UnchargedSource {
                stream,
                until,
                evaluation,
                pending: Some(pending),
                closed,
            }),
        }
    }
}

/// A root peer's execute connection: the value serving's `SO_PEERCRED`
/// UID 0 check produces (ADR-069 R11 §6 step 6), and the only one
/// [`ExecuteSource::read`] accepts.
#[derive(Debug)]
pub struct ExecutePeer {
    stream: UnixStream,
}

impl ExecutePeer {
    /// Accept `stream` only if its peer's `SO_PEERCRED` UID is 0.
    ///
    /// # Errors
    /// Returns the stream of any other or unreadable peer, unread.
    pub fn authenticate(stream: UnixStream) -> Result<Self, UnixStream> {
        Self::of_uid(stream, ROOT_UID)
    }

    /// Accept `stream` only if its peer's UID is this process's effective
    /// UID. It bypasses the UID 0 check, so only this crate's own unit
    /// tests have it.
    #[cfg(test)]
    fn of_test_user(stream: UnixStream) -> Result<Self, UnixStream> {
        Self::of_uid(stream, rustix::process::geteuid().as_raw())
    }

    fn of_uid(stream: UnixStream, uid: u32) -> Result<Self, UnixStream> {
        if rustix::net::sockopt::socket_peercred(&stream).is_ok_and(|peer| peer.uid.as_raw() == uid)
        {
            Ok(Self { stream })
        } else {
            Err(stream)
        }
    }
}

/// The source of one execute exchange: its exact EVR1 and SPX1, read once
/// and charged before allocation (ADR-122 Amendment 1 change A).
///
/// Only [`Self::read`] creates one. It owns the execute stream from then
/// on, holds a pending-control slot, and carries the connection identity
/// recorded before the first source byte, the absolute initial control
/// deadline the read started, the instant SPX1 completed and the
/// `CLOCK_MONOTONIC` sample taken after it. It has no public constructor,
/// no `Clone` and no serialization:
///
/// ```compile_fail
/// use pos_reference::provider_admission::execution::ExecuteSource;
/// fn forge(source: ExecuteSource) -> (ExecuteSource, ExecuteSource) {
///     (source.clone(), source)
/// }
/// ```
///
/// ```compile_fail
/// use pos_reference::provider_admission::execution::ExecuteSource;
/// fn forge(stream: std::os::unix::net::UnixStream) -> ExecuteSource {
///     ExecuteSource { stream }
/// }
/// ```
#[derive(Debug)]
pub struct ExecuteSource {
    // The buffers drop before their charges and before the control slot.
    evaluation: RetainedControl,
    request: RetainedControl,
    control: ControlSlot,
    stream: UnixStream,
    deadlines: TransferDeadlines,
    spx_completed: Instant,
    input_start: io::Result<u64>,
    clock: Clock,
    connection: io::Result<ConnectionIdentity>,
}

/// Why the single read yielded no [`ExecuteSource`].
#[derive(Debug)]
pub enum SourceRefusal {
    /// A precedence step 1 failure: a stalled, partial or expired read, a
    /// frame length of 0 or above 16 MiB, or premature bytes after SPX1.
    /// It is answered with SPE1 `0` and null identities.
    Malformed(UnixStream),
    /// The ledger refused the pending-control slot or a frame charge: the
    /// connection goes to the bounded refusal pool at its current position
    /// (R11 Amendment 1 §7.5, item P7).
    Uncharged(UnchargedSource),
    /// The first record is no EVR1: the connection carries another
    /// operation, which serving answers itself.
    NotExecute(OtherRequest),
}

/// A connection whose first complete record is no EVR1, with that record,
/// now uncharged, and the unchanged initial control deadline.
#[derive(Debug)]
pub struct OtherRequest {
    stream: UnixStream,
    first: Vec<u8>,
    until: Instant,
}

impl OtherRequest {
    /// The stream, the first record's bytes and the initial deadline.
    #[must_use]
    pub fn into_parts(self) -> (UnixStream, Vec<u8>, Instant) {
        (self.stream, self.first, self.until)
    }
}

/// A first frame that starts no execute source.
enum NotEvaluation {
    /// The frame failed step 1.
    Fault(FrameFault),
    /// A complete record of another operation.
    Other(Vec<u8>),
}

impl NotEvaluation {
    /// The refusal of `stream`, whose initial control deadline is `until`.
    fn refusal(self, stream: UnixStream, until: Instant) -> SourceRefusal {
        match self {
            Self::Fault(fault) => fault.refusal(stream, until, None),
            Self::Other(first) => SourceRefusal::NotExecute(OtherRequest {
                stream,
                first,
                until,
            }),
        }
    }
}

/// The first frame read as an EVR1 source frame, or what it is instead.
fn evaluation_frame(
    read: Result<RetainedControl, FrameFault>,
) -> Result<RetainedControl, NotEvaluation> {
    read.map_err(NotEvaluation::Fault).and_then(|frame| {
        if names_evaluation(&frame.bytes) {
            Ok(frame)
        } else {
            Err(NotEvaluation::Other(frame.bytes))
        }
    })
}

/// Whether `bytes` is a CBOR array whose first item is the text `EVR1`.
fn names_evaluation(bytes: &[u8]) -> bool {
    ciborium::from_reader::<ciborium::Value, _>(bytes)
        .ok()
        .and_then(|value| value.into_array().ok())
        .and_then(|fields| fields.into_iter().next())
        .is_some_and(|magic| magic.as_text() == Some("EVR1"))
}

/// A connection whose source the ledger refused to charge.
///
/// It is held at its current stream position. Its rest is read uncharged,
/// under the unchanged initial control deadline, only to compute a refusal
/// code: it never becomes an [`ExecuteSource`].
#[derive(Debug)]
pub struct UnchargedSource {
    stream: UnixStream,
    until: Instant,
    evaluation: Option<Vec<u8>>,
    pending: Option<usize>,
    closed: bool,
}

impl UnchargedSource {
    /// Whether the ledger was closed after a cleanup failure (SPE1 `14`)
    /// rather than full (`12`).
    #[must_use]
    pub const fn closed(&self) -> bool {
        self.closed
    }

    /// The connection's unchanged initial control deadline: a hand-off that
    /// waits for a refusal reader waits at most until then.
    #[must_use]
    pub const fn deadline(&self) -> Instant {
        self.until
    }

    /// Give up the rest unread: the stream, for an answer that needs no
    /// identity.
    #[must_use]
    pub fn into_stream(self) -> UnixStream {
        self.stream
    }

    /// Read the rest of the source uncharged: the stream, and EVR1 then
    /// SPX1 unless a frame failed step 1.
    #[must_use]
    pub fn read_rest(self) -> (UnixStream, Option<SourceFrames>) {
        let Self {
            mut stream,
            until,
            evaluation,
            pending,
            ..
        } = self;
        let frames = rest_frames(
            &mut TimedStream {
                stream: &mut stream,
                until,
            },
            evaluation,
            pending,
        );
        (stream, frames)
    }
}

/// The two source records of an uncharged refusal read.
#[derive(Debug, Eq, PartialEq)]
pub struct SourceFrames {
    /// The EVR1 frame's bytes.
    pub evaluation: Vec<u8>,
    /// The SPX1 frame's bytes.
    pub request: Vec<u8>,
}

/// EVR1, unless it was already read, then SPX1, whose length prefix was
/// already read if `pending`.
fn rest_frames(
    reader: &mut impl Read,
    evaluation: Option<Vec<u8>>,
    pending: Option<usize>,
) -> Option<SourceFrames> {
    let (evaluation, pending) = evaluation.map_or_else(
        || (uncharged_frame(reader, pending), None),
        |evaluation| (Some(evaluation), pending),
    );
    let evaluation = evaluation?;
    uncharged_frame(reader, pending).map(|request| SourceFrames {
        evaluation,
        request,
    })
}

/// One uncharged frame, whose length prefix was already read if `pending`.
fn uncharged_frame(reader: &mut impl Read, pending: Option<usize>) -> Option<Vec<u8>> {
    pending
        .map_or_else(|| frame_length(reader).ok(), Some)
        .and_then(|length| frame_body(reader, length).ok())
}

impl ExecuteSource {
    /// Record the connection's `fstat` identity, then read EVR1 then SPX1
    /// from `peer` under the initial control deadline of the `admitted`
    /// startup BHC1 (ID 16), charging a pending-control
    /// slot (ID 13) and each declared frame length to `ledger` before
    /// allocating it. Then sample the SPX1-completion instant and
    /// `CLOCK_MONOTONIC`, in that order, and check that nothing follows
    /// SPX1 yet.
    ///
    /// # Errors
    /// [`SourceRefusal::Malformed`] for a step 1 failure;
    /// [`SourceRefusal::Uncharged`] when the ledger refused a charge.
    pub fn read(
        peer: ExecutePeer,
        ledger: &StagingLedger,
        admitted: &AdmittedSelectorProvider,
    ) -> Result<Self, SourceRefusal> {
        let caps = admitted.provider().broker_hard_caps();
        Self::read_with(
            peer,
            ledger,
            (
                caps[CONTROL_SLOTS_ID].value,
                caps[CONTROL_DEADLINE_ID].value,
            ),
            super::monotonic_ns,
        )
    }

    fn read_with(
        peer: ExecutePeer,
        ledger: &StagingLedger,
        (slots, control_milliseconds): (u64, u64),
        clock: Clock,
    ) -> Result<Self, SourceRefusal> {
        let ExecutePeer { mut stream } = peer;
        // Recorded before the first source byte; an unreadable identity is
        // carried to admission, which refuses it with `Io`.
        let connection = rustix::fs::fstat(&stream)
            .map(|stat| (stat.st_dev, stat.st_ino))
            .map_err(io::Error::from);
        let Some(deadlines) = TransferDeadlines::new(&stream, control_milliseconds) else {
            return Err(SourceRefusal::Malformed(stream));
        };
        let until = deadlines.initial;
        let control = match ledger.control(slots) {
            Ok(control) => control,
            Err(refused) => {
                return Err(SourceRefusal::Uncharged(UnchargedSource {
                    stream,
                    until,
                    evaluation: None,
                    pending: None,
                    closed: closed(&refused),
                }))
            }
        };
        let evaluation = source_frame(
            &mut TimedStream {
                stream: &mut stream,
                until,
            },
            ledger,
        );
        let evaluation = match evaluation_frame(evaluation) {
            Ok(evaluation) => evaluation,
            Err(first) => return Err(first.refusal(stream, until)),
        };
        let request = source_frame(
            &mut TimedStream {
                stream: &mut stream,
                until,
            },
            ledger,
        );
        let request = match request {
            Ok(request) => request,
            Err(fault) => return Err(fault.refusal(stream, until, Some(evaluation.bytes))),
        };
        let spx_completed = Instant::now();
        let input_start = clock();
        if require_grant_turn(&stream).is_err() {
            return Err(SourceRefusal::Malformed(stream));
        }
        Ok(Self {
            evaluation,
            request,
            control,
            stream,
            deadlines,
            spx_completed,
            input_start,
            clock,
            connection,
        })
    }

    /// The exact canonical EVR1 bytes.
    #[must_use]
    pub fn evaluation(&self) -> &[u8] {
        &self.evaluation.bytes
    }

    /// The exact canonical SPX1 bytes.
    #[must_use]
    pub fn request(&self) -> &[u8] {
        &self.request.bytes
    }

    /// The absolute initial control deadline the read started, which also
    /// bounds a repeat's wait on the attempt it joins (R11 Amendment 1 §7.5,
    /// item P1).
    #[must_use]
    pub const fn deadline(&self) -> Instant {
        self.deadlines.initial
    }

    /// Give up the source: its slot and charges are released, and the
    /// stream is returned for a refusal.
    ///
    /// The stream may still carry the shortened read timeout of the single
    /// read's initial deadline, possibly already expired. Serving must set
    /// the SPE1 refusal's own write deadline on it explicitly before writing
    /// (journal 22582).
    #[must_use]
    pub fn into_stream(self) -> UnixStream {
        self.stream
    }
}

/// The case, policy and authority reconstructed for one source.
struct Reconstructed {
    snapshot: ProviderImageSnapshot,
    attempt: crate::evaluator::CaseAttempt,
    policy: ProviderExecutionPolicy,
    authority: AdmittedAuthority,
}

/// An image-check refusal: a different image or binary is `ImageIdentity`
/// (SPE1 `9`), an I/O failure stays an installation failure (`11`).
const fn image_fault(error: InstallationError) -> StagingError {
    match error {
        InstallationError::ArtifactInvalid => StagingError::ImageIdentity,
        InstallationError::Io => StagingError::Source(InstallationError::Io),
    }
}

const fn snapshot_fault(fault: SnapshotFault) -> StagingError {
    match fault {
        SnapshotFault::Image(error) => image_fault(error),
        SnapshotFault::Launch(error) => StagingError::Source(error),
    }
}

const fn join_fault(fault: JoinFault) -> StagingError {
    match fault {
        JoinFault::Authority(error) => StagingError::Source(error),
        JoinFault::Image(error) => image_fault(error),
    }
}

/// The held-image join against the current installation: its SIC1 open,
/// installation digest, authority and retained image.
fn joined(snapshot: &ProviderImageSnapshot) -> Result<HeldImageAdmission<'_>, StagingError> {
    snapshot
        .join_current(InstalledSelectorState::open(), SystemTime::now)
        .map_err(join_fault)
}

/// R11 Amendment 1 §7.5 rows 7 to 7b, in order: the case from the retained
/// installation and the complete SPX1 equality; the supported mode; the
/// retained, then the current authority through the one SIC1 open; the
/// image and binary identity; then the launch policy and the commitment.
fn reconstruct(
    (evaluation, request): (&[u8], &[u8]),
    installation: &Arc<AdmittedSelectorProvider>,
    open: impl FnOnce() -> Result<InstalledSelectorState, InstallationError>,
) -> Result<Reconstructed, StagingError> {
    let evaluation = EvaluationRequest::from_canonical_cbor(evaluation).map_err(invalid)?;
    let request = SandboxExecuteRequest::from_canonical_cbor(request).map_err(invalid)?;
    let ordinal = u16::from_be_bytes([
        request.request.request_id[14],
        request.request.request_id[15],
    ]);
    let resolved = installation
        .bootstrap()
        .resolve_installed_case(&evaluation, ordinal)?;
    let input = input_descriptor(resolved.attempt())?;
    if execute_request_for_case(
        installation,
        &evaluation,
        &resolved,
        input,
        ordinal,
        request.request.nonce,
    )? != request
    {
        return Err(StagingError::InvalidSource);
    }
    let authority = ProviderImageSnapshot::join_authority(installation, &request, open())?;
    let snapshot =
        ProviderImageSnapshot::checked(Arc::clone(installation), request, SystemTime::now)
            .map_err(snapshot_fault)?;
    let attempt = resolved.into_attempt();
    let commitment = installation
        .provider()
        .derive_selector_grant_commitment(
            snapshot.image(),
            snapshot.launch_policy(),
            &evaluation,
            &attempt,
            &[],
        )
        .map_err(invalid)?;
    let policy = ProviderExecutionPolicy {
        request_digest: snapshot.request().request_digest,
        input: snapshot.request().adapter_input.clone(),
        commitment,
    };
    Ok(Reconstructed {
        snapshot,
        attempt,
        policy,
        authority,
    })
}

/// The source fields the reservation keeps.
struct Received {
    records: [RetainedControl; 2],
    deadlines: TransferDeadlines,
    spx_completed: Instant,
    input_start: io::Result<u64>,
    clock: Clock,
    connection: io::Result<ConnectionIdentity>,
}

/// R11 Amendment 1 §7.5 row R: the deadlines, the clock, the connection
/// identity and the premature bytes, then the policy-bound reservation and
/// the case buffers.
fn reserve(
    checked: Reconstructed,
    received: Received,
    ledger: &StagingLedger,
    stream: &UnixStream,
) -> Result<(Execution, Instant), StagingError> {
    let Reconstructed {
        snapshot,
        attempt,
        policy,
        authority,
    } = checked;
    let Received {
        records,
        deadlines,
        spx_completed,
        input_start,
        clock,
        connection,
    } = received;
    control_left(deadlines.initial)?;
    let input_deadline = deadlines.input(spx_completed, policy.limit(16))?;
    window_left(input_deadline)?;
    let start = input_start?;
    let connection = connection?;
    require_grant_turn(stream)?;
    // The input ceiling and the floor before any reservation, then the
    // closed and full ledger (rows 2, 6, 14, 12).
    let (slot, input) = ledger.prepare(authority, &policy)?;
    let expected = ledger
        .reserve_storage(case_buffer_bytes(&attempt))
        .map(|charge| RetainedCase {
            attempt,
            _charge: charge,
        })?;
    Ok((
        Execution {
            source: Arc::new(ExecutionSource {
                snapshot,
                expected,
                policy,
                _records: records,
            }),
            slot,
            input,
            ledger: ledger.clone(),
            input_deadline,
            window: TransferWindow::new(spx_completed, start, input_deadline),
            clock,
            connection,
        },
        deadlines.initial,
    ))
}

struct DigestWriter {
    hasher: blake3::Hasher,
    length: u64,
}

// Called only after the bounded canonical writer validated the complete case;
// its buffers are strictly smaller than that at-most-128-MiB representation.
fn case_buffer_bytes(attempt: &crate::evaluator::CaseAttempt) -> u64 {
    attempt.case_id.len() as u64
        + attempt.schema.bytes.len() as u64
        + attempt.payload.bytes.len() as u64
        + attempt
            .auxiliary
            .iter()
            .map(|artifact| artifact.bytes.len() as u64)
            .sum::<u64>()
        + attempt
            .capability_ids
            .iter()
            .map(|id| id.len() as u64)
            .sum::<u64>()
}

impl Write for DigestWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = self
            .length
            .checked_add(bytes.len() as u64)
            .filter(|length| *length <= INPUT_LIMIT)
            .ok_or_else(|| io::Error::other("input exceeds protocol ceiling"))?;
        self.hasher.update(bytes);
        self.length = length;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn input_descriptor(
    expected: &crate::evaluator::CaseAttempt,
) -> Result<PayloadDescriptor, StagingError> {
    let mut writer = DigestWriter {
        hasher: blake3::Hasher::new(),
        length: 0,
    };
    writer.hasher.update(b"PiglorOS.SandboxInputBytes.v1\0");
    write_attempt(&mut writer, expected)
        .map_err(invalid)
        .map(|()| PayloadDescriptor {
            byte_length: writer.length,
            digest: *writer.hasher.finalize().as_bytes(),
        })
}

/// A signed, verified AGR1: its canonical bytes, its self-digest and the
/// admitted facts it is retained with.
struct SignedGrant {
    bytes: Vec<u8>,
    digest: [u8; 32],
    facts: Arc<GrantedFacts>,
}

impl<C> PreparedProviderExecution<C> {
    /// The sole authority factory (ADR-122 Amendment 1 change C): admit the
    /// `source` against the provider admission retained at runtime startup.
    ///
    /// In the order of R11 Amendment 1 §7.5 it independently decodes both
    /// records again and reconstructs the case from the retained
    /// `installation` without reopening SIC1; joins the request to the
    /// current installation through the one SIC1 open (pending SIR1,
    /// installation digest, authority); checks the image and binary identity;
    /// admits the launch policy and derives the commitment. Then `claim` takes the
    /// caller's lifecycle claim (port step A), and the deadlines, the clock,
    /// the connection identity, the premature bytes, the policy-bound
    /// reservation and the case buffers follow (row R). The pending-control
    /// slot is released once the reservation is published.
    ///
    /// # Errors
    /// An [`ExecuteRefusal`] that returns the stream with the first failure,
    /// after every slot, charge, claim and reservation was released.
    pub fn admit<E>(
        source: ExecuteSource,
        ledger: &StagingLedger,
        installation: &Arc<AdmittedSelectorProvider>,
        claim: impl FnOnce(&SandboxExecuteRequest) -> Result<C, E>,
    ) -> Result<Self, Box<ExecuteRefusal<E>>> {
        Self::admit_with(
            source,
            ledger,
            installation,
            InstalledSelectorState::open,
            claim,
        )
    }

    fn admit_with<E>(
        source: ExecuteSource,
        ledger: &StagingLedger,
        installation: &Arc<AdmittedSelectorProvider>,
        open: impl FnOnce() -> Result<InstalledSelectorState, InstallationError>,
        claim: impl FnOnce(&SandboxExecuteRequest) -> Result<C, E>,
    ) -> Result<Self, Box<ExecuteRefusal<E>>> {
        let ExecuteSource {
            evaluation,
            request,
            control,
            stream,
            deadlines,
            spx_completed,
            input_start,
            clock,
            connection,
        } = source;
        let admitted = reconstruct((&evaluation.bytes, &request.bytes), installation, open)
            .map_err(RefusalCause::Staging)
            .and_then(|checked| {
                claim(checked.snapshot.request())
                    .map(|claimed| (checked, claimed))
                    .map_err(RefusalCause::Claim)
            })
            .and_then(|(checked, claimed)| {
                let received = Received {
                    records: [evaluation, request],
                    deadlines,
                    spx_completed,
                    input_start,
                    clock,
                    connection,
                };
                reserve(checked, received, ledger, &stream)
                    .map(|reserved| (reserved, claimed))
                    .map_err(RefusalCause::Staging)
            });
        drop(control);
        match admitted {
            Ok(((execution, initial_deadline), claim)) => Ok(Self {
                execution,
                claim,
                initial_deadline,
                stream,
            }),
            Err(cause) => Err(Box::new(ExecuteRefusal { stream, cause })),
        }
    }

    /// Independently derived policy; no caller can replace its values.
    #[must_use]
    pub fn policy(&self) -> &ProviderExecutionPolicy {
        &self.execution.source.policy
    }

    /// Canonical source identity for this exchange.
    #[must_use]
    pub fn request(&self) -> &SandboxExecuteRequest {
        self.execution.source.snapshot.request()
    }

    /// Shared byte ownership for the private staging file's unlink lifetime.
    #[must_use]
    pub fn staging_charge(&self) -> StagingCharge {
        self.execution.input.clone()
    }

    /// Refuse this exchange for `cause`, releasing everything but the stream.
    pub(super) fn refuse<E>(self, cause: RefusalCause<E>) -> ExecuteRefusal<E> {
        ExecuteRefusal {
            stream: self.stream,
            cause,
        }
    }

    /// The AGR1 signed by `sign` and its admitted facts, once the initial
    /// control deadline, the held-image join and the floor passed before
    /// signing (ADR-122 Amendment 1 invariant 1b). The input window and the
    /// premature bytes are checked only after signing, in
    /// [`Self::before_write`].
    fn signed_grant<S>(
        &self,
        sign: impl FnOnce(SelfDigested<Agr1>) -> Result<Verified<Agr1>, S>,
    ) -> Result<SignedGrant, StagingError> {
        control_left(self.initial_deadline)?;
        let source = &self.execution.source;
        let snapshot = &source.snapshot;
        let authority = joined(snapshot)?.authority();
        self.execution.slot.recheck(authority)?;
        let request = snapshot.request();
        let a = &request.authority;
        let admitted = snapshot.admitted.provider();
        let (grant, grant_digest) = AdmissionGrant::self_digested(AdmissionGrantFields {
            request_id: request.request.request_id,
            attempt_id: request.attempt_id,
            authority: AdmissionAuthority {
                evr1_digest: a.evr1_digest,
                fixture_contract_digest: a.fixture_contract_digest,
                fixture_digest: a.fixture_digest,
                execution_profile_digest: a.execution_profile_digest,
                lps1_digest: a.lps1_digest,
                sim1_digest: a.sim1_digest,
                apt1_digest: a.apt1_digest,
                trs1_digest: a.trs1_digest,
                rvs1_digest: a.rvs1_digest,
                spm1_digest: a.spm1_digest,
                pcf1_digest: a.pcf1_digest,
                pcr1_digest: a.pcr1_digest,
                hcp1_digest: a.hcp1_digest,
            },
            trust_epoch: authority.trust_epoch,
            revocation_epoch: authority.revocation_epoch,
            policy_epoch: authority.policy_epoch,
            elm1_digest: source.policy.effective_limits_digest(),
            input_digest: source.policy.input.digest,
            exchange_plan_digests: Vec::new(),
            expected_launch_policy_digest: a.lps1_digest,
            expected_readback_set_digest: source.policy.expected_readback_digest(),
            runtime_attestation_key_id: snapshot.runtime_attestation_key_id().to_owned(),
        })
        .ok()
        .and_then(|record| sign(record).ok())
        .and_then(|verified| {
            AdmissionGrant::new(verified, admitted.runtime_attestation_key())
                .and_then(|grant| {
                    grant
                        .to_canonical_cbor()
                        .map(|bytes| (bytes, grant.grant_digest()))
                })
                .ok()
        })
        .ok_or(StagingError::SignerFault)?;
        // A Local attempt's admission is derived from the grant just
        // authenticated, the same commitment and the exact LPS1, and the
        // request's plans: none in V1, whose non-empty list row 7 refuses.
        let local = admitted
            .authenticate_grant_with_local_network(
                &grant,
                request,
                (snapshot.image(), snapshot.launch_policy()),
                (&source.policy.commitment, snapshot.launch_policy_bytes()),
            )
            .map_err(|_| StagingError::GrantCommitmentMismatch)?;
        Ok(SignedGrant {
            bytes: grant,
            digest: grant_digest,
            facts: Arc::new(GrantedFacts {
                limits: source.policy.effective_limits().to_vec(),
                limits_digest: source.policy.effective_limits_digest(),
                mode: snapshot.launch_policy().execution_mode,
                local,
                provider_binary_digest: admitted.manifest().binary_digest,
                negative_probe_evidence: admitted.host_profile().negative_probe_evidence,
            }),
        })
    }

    /// The checks after signing, immediately before the write, because the
    /// signer may block: the held-image join, the floor, both deadlines and
    /// the premature bytes (R11 Amendment 1 §7.5 row W).
    fn before_write(&self) -> Result<(), StagingError> {
        joined(&self.execution.source.snapshot)
            .and_then(|image| {
                self.execution
                    .slot
                    .recheck(image.authority())
                    .map_err(StagingError::from)
            })
            .and_then(|()| control_left(self.initial_deadline))
            .and_then(|()| window_left(self.execution.input_deadline))
            .and_then(|()| require_grant_turn(&self.stream))
    }

    /// Sign and write AGR1 solely from this policy on the owned connection.
    ///
    /// `sign` receives the sealed AGR1 record and returns it signed under
    /// the runtime-attestation key, verified before emission (ADR-069 R9
    /// §5). After the last pre-write check, `convert` converts the claim for
    /// the AGR1 digest as the very last check: its refusal writes no byte.
    /// Once the grant is completely written, the live attempts and
    /// incomplete inputs of the ledger and the write's completion time are
    /// retained with its exact bytes.
    pub(super) fn grant<W, E, S>(
        self,
        sign: impl FnOnce(SelfDigested<Agr1>) -> Result<Verified<Agr1>, S>,
        convert: impl FnOnce(C, [u8; 32]) -> Result<W, E>,
    ) -> Result<(W, GrantedExecution), GrantFailure<E>> {
        let checked = self
            .signed_grant(sign)
            .and_then(|signed| self.before_write().map(|()| signed));
        let SignedGrant {
            bytes: grant,
            digest,
            facts,
        } = match checked {
            Ok(signed) => signed,
            Err(error) => {
                return Err(GrantFailure::Refused(Box::new(
                    self.refuse(RefusalCause::Staging(error)),
                )))
            }
        };
        let Self {
            execution,
            claim,
            initial_deadline,
            mut stream,
        } = self;
        let write = match convert(claim, digest) {
            Ok(write) => write,
            Err(refused) => {
                return Err(GrantFailure::Refused(Box::new(ExecuteRefusal {
                    stream,
                    cause: RefusalCause::Claim(refused),
                })))
            }
        };
        // Grant output starts here. Later peer bytes can only be input; they
        // cannot reopen the independently validated source records.
        let usage = execution.ledger.usage();
        let mut writer = TimedStream {
            stream: &mut stream,
            until: initial_deadline.min(execution.input_deadline),
        };
        // Once completely written, the selector holds AGR1: the attempt is
        // admitted, and an expiry from here on fails its input.
        let written = u32::try_from(grant.len())
            .map_err(io::Error::other)
            .and_then(|length| writer.write_all(&length.to_be_bytes()))
            .and_then(|()| writer.write_all(&grant));
        match written {
            Ok(()) => {
                let grant = IssuedGrant {
                    bytes: grant.into(),
                    digest,
                    admission: AdmissionLedger {
                        active_attempts: usage.attempts,
                        incomplete_inputs: usage.queued_inputs,
                    },
                    issued_at: (execution.clock)().ok(),
                    admitted: facts,
                };
                Ok((
                    write,
                    GrantedExecution {
                        execution,
                        grant,
                        stream,
                    },
                ))
            }
            Err(error) => {
                // The claim's converted slot is removed: no attempt exists.
                drop(write);
                Err(GrantFailure::Interrupted(StagingError::Io(error)))
            }
        }
    }
}

impl GrantedExecution {
    pub(super) const fn grant(&self) -> &IssuedGrant {
        &self.grant
    }

    /// The failed input of an exchange interrupted before any input byte
    /// was accepted, finished now: TME1 progress 0, `input.complete =
    /// false`, code 10 (Redmine #443 journal 22592).
    pub(super) fn interrupted(&self) -> FailedInput {
        FailedInput {
            error: StagingError::Incomplete,
            attempt_id: self.execution.source.snapshot.request().attempt_id,
            grant: self.grant.clone(),
            transfer: self.execution.transfer(0, (self.execution.clock)().ok()),
        }
    }

    /// Receive and verify complete SBC1/EAI1 into the retained private
    /// `file`, returning the stream with the result.
    ///
    /// The input transfer is recorded as TME1 `input`: it started when the
    /// complete SPX1 frame was read, its deadline is the ELM1 ID 16 window
    /// from then, and it finished when the final chunk and the whole-payload
    /// digest verified, or when the input failed. A failed input's final
    /// chunk is not counted, so it is never complete.
    pub(super) fn receive(
        self,
        file: &File,
    ) -> (
        Result<AdmittedProviderExecution, Box<FailedInput>>,
        UnixStream,
    ) {
        let Self {
            execution,
            grant,
            mut stream,
        } = self;
        let mut received = ReceivedInput {
            accepted: 0,
            finished: None,
        };
        let verified = execution.verify_input(&mut stream, file, &mut received);
        let transfer = execution.transfer(
            received.accepted,
            received.finished.unwrap_or_else(execution.clock).ok(),
        );
        let admitted = match verified {
            Ok((verified_input, root_image, proof, authority)) => {
                execution.input.finish_input();
                Ok(AdmittedProviderExecution {
                    source: execution.source,
                    verified_input,
                    root_image,
                    proof,
                    authority,
                    grant,
                    transfer,
                    connection: execution.connection,
                    _input: execution.input,
                    slot: execution.slot,
                })
            }
            Err(error) => Err(Box::new(FailedInput {
                error,
                attempt_id: execution.source.snapshot.request().attempt_id,
                grant,
                transfer,
            })),
        };
        (admitted, stream)
    }
}

impl Execution {
    fn transfer(&self, accepted: u64, finish: Option<u64>) -> Option<TransferRecord> {
        let expected = self.source.policy.input.byte_length;
        finish.map(|finish| self.window.record(expected, accepted, finish))
    }

    fn verify_input(
        &self,
        stream: &mut UnixStream,
        file: &File,
        received: &mut ReceivedInput,
    ) -> Result<VerifiedParts, StagingError> {
        let request = self.source.snapshot.request();
        let mut validator = PayloadStreamValidator::new(
            request.request_digest,
            request.request.request_id,
            request.attempt_id,
            PayloadDirection::Input,
            self.source.policy.input.clone(),
        )
        .map_err(invalid_input)?;
        let mut reader = TimedStream {
            stream,
            until: self.input_deadline,
        };
        let mut offset = 0;
        while offset < self.source.policy.input.byte_length {
            received.accepted = offset;
            let record = frame(&mut reader, &self.ledger)?;
            let chunk =
                SandboxPayloadChunk::from_canonical_cbor(&record.bytes).map_err(invalid_input)?;
            validator.accept(&chunk).map_err(invalid_input)?;
            file.write_all_at(&chunk.bytes, offset)?;
            offset += chunk.bytes.len() as u64;
            drop(record);
        }
        validator.finish().map_err(invalid_input)?;
        received.finished = Some((self.clock)());
        if reader.read(&mut [0; 1])? != 0 || file.metadata()?.len() != offset {
            return Err(StagingError::InvalidInput);
        }
        let _decoded_input = self
            .ledger
            .reserve_storage(case_buffer_bytes(&self.source.expected.attempt))?;
        let actual = read_attempt(PositionalReader::new(file)).map_err(invalid_input)?;
        if actual != self.source.expected.attempt {
            return Err(StagingError::InvalidInput);
        }
        window_left(self.input_deadline)?;
        let (root_image, proof, authority) = {
            let image = joined(&self.source.snapshot)?;
            self.slot.recheck(image.authority())?;
            (
                image.root_image.try_clone()?,
                Arc::clone(&image.proof),
                image.authority(),
            )
        };
        let verified_input = file.try_clone()?;
        received.accepted = offset;
        Ok((verified_input, root_image, proof, authority))
    }
}

/// How far an input transfer got.
///
/// Every chunk before the one being received was accepted. The final
/// chunk's bytes count only once the whole input was admitted, so a failed
/// input is never complete (owner decision, 2026-11-16: a post-AGR1 input
/// failure has `input.complete = false`, code 10).
struct ReceivedInput {
    /// The accepted bytes.
    accepted: u64,
    /// When the final chunk and the payload digest verified.
    finished: Option<std::io::Result<u64>>,
}

/// The verified input descriptor, the held root image, its proof and the
/// authority it was rechecked under.
type VerifiedParts = (
    File,
    File,
    Arc<crate::sandbox_provider_protocol::VerifiedSandboxImageProof>,
    AdmittedAuthority,
);

impl AdmittedProviderExecution {
    /// Exact independently reconstructed policy bound to these input bytes.
    #[must_use]
    pub fn policy(&self) -> &ProviderExecutionPolicy {
        &self.source.policy
    }

    /// Descriptor-bearing image admission retained from this input's context.
    #[must_use]
    pub fn image_admission(&self) -> HeldImageAdmission<'_> {
        HeldImageAdmission {
            snapshot: &self.source.snapshot,
            root_image: &self.root_image,
            proof: self.proof.clone(),
            authority: self.authority,
        }
    }

    /// The AGR1 this input was admitted under.
    #[must_use]
    pub const fn grant(&self) -> &IssuedGrant {
        &self.grant
    }

    /// TME1 `input`: the complete input transfer; `None` if the clock could
    /// not report when it finished.
    #[must_use]
    pub const fn transfer(&self) -> Option<TransferRecord> {
        self.transfer
    }

    /// The execute connection's `fstat` `(st_dev, st_ino)`, recorded by the
    /// source reader before its first source byte: the identity of the one
    /// stream this exchange read, wrote AGR1 to and received input from
    /// (ADR-122 Amendment 1 invariant 2, T7).
    ///
    /// A read-only view (change C allows those). No serving code reads it
    /// yet, but it is public on purpose: as `pub(crate)` the identity would
    /// be read only by tests, so the field would be dead code in the
    /// library.
    #[must_use]
    pub const fn connection(&self) -> (u64, u64) {
        self.connection
    }

    /// Recheck current installation and the live provider control floor.
    ///
    /// # Errors
    /// [`RecheckError::AuthorityChanged`] for stale or substituted
    /// authority; [`RecheckError::Ledger`] for a raised control floor or a
    /// closed ledger.
    pub fn recheck(&self) -> Result<AdmittedAuthority, RecheckError> {
        self.image_admission()
            .recheck_authority()
            .map_err(|_| RecheckError::AuthorityChanged)
            .and_then(|authority| {
                self.slot
                    .recheck(authority)
                    .map(|()| authority)
                    .map_err(RecheckError::Ledger)
            })
    }

    /// Read exactly from the descriptor whose complete case was verified.
    ///
    /// # Errors
    /// Returns an I/O error for an invalid range or descriptor read failure.
    pub fn read_exact_at(&self, bytes: &mut [u8], offset: u64) -> io::Result<()> {
        if offset
            .checked_add(bytes.len() as u64)
            .is_none_or(|end| end > self.policy().input.byte_length)
        {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        self.verified_input.read_exact_at(bytes, offset)
    }

    /// Reserve this attempt's one output of exactly ELM1\[8\] bytes, keeping
    /// the attempt counted while the charge lives (ADR-069 R10 §4.7).
    ///
    /// `None` once the reservation was made: an attempt has one output.
    /// Otherwise the reservation, or why the ledger refused it.
    #[must_use = "a dropped reservation releases its bytes at once"]
    pub fn reserve_output(&self) -> Option<Result<StagingCharge, OutputReservationRefused>> {
        self.slot.output(self.policy())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::evaluator_protocol::encode;
    use crate::provider_admission::execution::{StagingDirectory, StagingLimits, StagingUsage};
    use crate::provider_admission::test_support::StagedInstallation;
    use ciborium::value::Value;
    use std::convert::Infallible;
    use std::fmt::Debug;
    use std::io::Cursor;
    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    const LARGE: StagingLimits = StagingLimits {
        aggregate_bytes: 512 * 1024 * 1024,
    };

    /// `result`, or its refusal as a test error.
    fn ok<T, E: Debug>(result: Result<T, E>) -> TestResult<T> {
        result.map_err(|error| format!("{error:?}").into())
    }

    /// This process's own user as the peer, and a short source deadline.
    fn peer(stream: UnixStream) -> TestResult<ExecutePeer> {
        ok(ExecutePeer::of_test_user(stream))
    }

    fn write_frame(selector: &mut UnixStream, bytes: &[u8]) -> TestResult {
        selector.write_all(&u32::try_from(bytes.len())?.to_be_bytes())?;
        selector.write_all(bytes)?;
        Ok(())
    }

    /// Read a test source of `evaluation` then `request` under `caps`.
    fn read_frames(
        ledger: &StagingLedger,
        caps: (u64, u64),
        frames: &[&[u8]],
        trailing: &[u8],
    ) -> TestResult<(Result<ExecuteSource, SourceRefusal>, UnixStream)> {
        let (provider, mut selector) = UnixStream::pair()?;
        for frame in frames {
            write_frame(&mut selector, frame)?;
        }
        selector.write_all(trailing)?;
        Ok((
            ExecuteSource::read_with(peer(provider)?, ledger, caps, super::super::monotonic_ns),
            selector,
        ))
    }

    fn malformed(result: &Result<ExecuteSource, SourceRefusal>) -> bool {
        matches!(result, Err(SourceRefusal::Malformed(_)))
    }

    /// The smallest record the reader takes for EVR1: a CBOR array whose
    /// first item is the text `EVR1` (six bytes).
    const EVR: &[u8] = &[0x81, 0x64, b'E', b'V', b'R', b'1'];

    fn source_frames(evaluation: &[u8], request: &[u8]) -> SourceFrames {
        SourceFrames {
            evaluation: evaluation.to_vec(),
            request: request.to_vec(),
        }
    }

    fn uncharged(result: Result<ExecuteSource, SourceRefusal>) -> TestResult<UnchargedSource> {
        match result {
            Err(SourceRefusal::Uncharged(source)) => Ok(source),
            other => Err(format!("not handed off: {other:?}").into()),
        }
    }

    #[test]
    fn frames_validate_lengths_and_charge_before_allocating() -> TestResult {
        let ledger = StagingLedger::new(StagingLimits { aggregate_bytes: 3 });
        for length in [0, u32::MAX] {
            assert!(matches!(
                frame(&mut Cursor::new(length.to_be_bytes()), &ledger),
                Err(StagingError::InvalidSource)
            ));
        }
        assert!(matches!(
            frame(&mut Cursor::new(4_u32.to_be_bytes()), &ledger),
            Err(StagingError::AggregateExceeded)
        ));
        assert!(frame(&mut Cursor::new([0, 0, 0, 3, 1]), &ledger).is_err());
        assert_eq!(ledger.usage().reserved_bytes, 0);
        let record = frame(&mut Cursor::new([0, 0, 0, 3, 1, 2, 3]), &ledger)?;
        assert_eq!(record.bytes, [1, 2, 3]);
        assert_eq!(ledger.usage().reserved_bytes, 3);
        drop(record);
        assert_eq!(ledger.usage().reserved_bytes, 0);
        Ok(())
    }

    #[test]
    fn maximum_control_frame_is_admissible_without_enclosing_overhead() -> TestResult {
        // Independent wire-size oracle: the protocol permits 16 MiB, excluding
        // the four-byte prefix. Do not derive test input from the production cap.
        let maximum = 16_777_216;
        let ledger = StagingLedger::new(StagingLimits {
            aggregate_bytes: maximum as u64,
        });
        let mut bytes = u32::try_from(maximum)?.to_be_bytes().to_vec();
        bytes.resize(maximum + 4, 1);
        let record = frame(&mut Cursor::new(bytes), &ledger)?;
        assert_eq!(record.bytes.len(), maximum);
        drop(record);
        assert_eq!(ledger.usage().reserved_bytes, 0);
        Ok(())
    }

    #[test]
    fn timed_reads_and_writes_keep_the_original_absolute_deadline() -> TestResult {
        let now = Instant::now();
        assert_eq!(deadline_after(now, 0), None);
        assert_eq!(deadline_after(now, 5), Some(now + Duration::from_millis(5)));
        let expired = now
            .checked_sub(Duration::from_secs(1))
            .ok_or("clock range")?;
        assert!(matches!(
            control_left(expired),
            Err(StagingError::ControlExpired)
        ));
        assert!(matches!(
            window_left(expired),
            Err(StagingError::InputWindowExpired)
        ));
        let later = now + Duration::from_secs(5);
        control_left(later)?;
        window_left(later)?;
        let (mut first, mut second) = UnixStream::pair()?;
        let mut timed = TimedStream {
            stream: &mut first,
            until: later,
        };
        timed.write_all(b"ab")?;
        timed.flush()?;
        let mut bytes = [0; 2];
        second.read_exact(&mut bytes)?;
        assert_eq!(bytes, *b"ab");
        second.write_all(b"cd")?;
        timed.read_exact(&mut bytes)?;
        assert_eq!(bytes, *b"cd");
        timed.until = expired;
        assert_eq!(
            timed.read(&mut bytes).map_err(|error| error.kind()).err(),
            Some(io::ErrorKind::TimedOut)
        );
        assert_eq!(
            timed.write(b"e").map_err(|error| error.kind()).err(),
            Some(io::ErrorKind::TimedOut)
        );
        Ok(())
    }

    #[test]
    fn source_and_input_preserve_stricter_original_transport_bounds() -> TestResult {
        let (stream, _peer) = UnixStream::pair()?;
        let unrestricted = TransferDeadlines::new(&stream, 10_000).ok_or("refused")?;
        assert!(unrestricted.transport.is_none());
        assert!(unrestricted.input(Instant::now(), 1_000)? < unrestricted.initial);
        stream.set_read_timeout(Some(Duration::from_millis(100)))?;
        stream.set_write_timeout(Some(Duration::from_millis(50)))?;
        let strict = TransferDeadlines::new(&stream, 10_000).ok_or("refused")?;
        let original = strict.transport.ok_or("missing original transport bound")?;
        assert_eq!(strict.initial, original);
        assert_eq!(strict.input(Instant::now(), 10_000)?, original);
        assert!(strict.input(Instant::now(), 1)? < original);
        // A zero BHC1 ID 16 or ELM1 ID 16 leaves no window at all.
        assert!(TransferDeadlines::new(&stream, 0).is_none());
        assert!(matches!(
            strict.input(Instant::now(), 0),
            Err(StagingError::InputWindowExpired)
        ));
        let spx_completed = Instant::now()
            .checked_sub(Duration::from_secs(5))
            .ok_or("clock range")?;
        assert!(matches!(
            window_left(unrestricted.input(spx_completed, 1_000)?),
            Err(StagingError::InputWindowExpired)
        ));
        Ok(())
    }

    #[test]
    fn the_recorded_window_is_the_enforced_one_and_its_last_instant_is_complete() -> TestResult {
        let started = Instant::now();
        let deadline = started
            .checked_add(Duration::from_millis(5))
            .ok_or("clock range")?;
        let window = TransferWindow::new(started, 100, deadline);
        assert_eq!((window.start, window.deadline), (100, 5_000_100));
        // Admitted at the very end of the enforced window: complete.
        let last = window.record(7, 7, window.deadline);
        assert!(last.complete);
        assert_eq!(
            (
                last.start,
                last.deadline,
                last.finish,
                last.expected_bytes,
                last.accepted_bytes
            ),
            (100, 5_000_100, 5_000_100, 7, 7)
        );
        assert!(!window.record(7, 7, window.deadline + 1).complete);
        assert!(!window.record(7, 6, window.start).complete);
        // A deadline that is already past leaves an empty window.
        let empty = TransferWindow::new(deadline, 100, started);
        assert_eq!(empty.deadline, 100);
        Ok(())
    }

    #[test]
    fn a_negative_or_overflowing_clock_time_is_invalid_data() {
        let at = |tv_sec: i64, tv_nsec: i64| {
            super::super::timespec_ns(rustix::time::Timespec { tv_sec, tv_nsec })
                .map_err(|error| error.kind())
        };
        assert_eq!(at(0, 0), Ok(0));
        assert_eq!(at(1, 5), Ok(1_000_000_005));
        assert_eq!(at(18_446_744_073, 709_551_615), Ok(u64::MAX));
        for (seconds, nanoseconds) in [
            (-1, 0),
            (0, -1),
            (i64::MAX, 0),
            (18_446_744_073, 709_551_616),
        ] {
            assert_eq!(
                at(seconds, nanoseconds),
                Err(std::io::ErrorKind::InvalidData),
                "{seconds} s {nanoseconds} ns"
            );
        }
    }

    #[test]
    fn the_production_clock_reads_clock_monotonic() -> TestResult {
        let sample = || {
            super::super::timespec_ns(rustix::time::clock_gettime(
                rustix::time::ClockId::Monotonic,
            ))
        };
        let before = sample()?;
        let now = super::super::monotonic_ns()?;
        let after = sample()?;
        assert!(
            (before..=after).contains(&now),
            "{before} <= {now} <= {after}"
        );
        Ok(())
    }

    #[test]
    fn source_turn_rejects_queued_extra_bytes_and_early_eof_without_consuming() -> TestResult {
        let (mut provider, mut selector) = UnixStream::pair()?;
        require_grant_turn(&provider)?;
        selector.write_all(b"x")?;
        assert!(matches!(
            require_grant_turn(&provider),
            Err(StagingError::InvalidSource)
        ));
        let mut byte = [0];
        provider.read_exact(&mut byte)?;
        assert_eq!(byte, *b"x");
        selector.shutdown(std::net::Shutdown::Write)?;
        assert!(matches!(
            require_grant_turn(&provider),
            Err(StagingError::InvalidSource)
        ));
        // A reset peer is an I/O failure, not a premature byte.
        let (provider, selector) = UnixStream::pair()?;
        provider.try_clone()?.write_all(b"unread")?;
        drop(selector);
        assert!(matches!(
            require_grant_turn(&provider),
            Err(StagingError::Io(error)) if error.kind() == io::ErrorKind::ConnectionReset
        ));
        Ok(())
    }

    #[test]
    fn incremental_descriptor_matches_the_canonical_complete_case() -> TestResult {
        let (_, _, resolved) = crate::selector::installation::tests::root_selector_fixture()?;
        let descriptor = input_descriptor(resolved.attempt())?;
        let mut bytes = Vec::new();
        write_attempt(&mut bytes, resolved.attempt())?;
        assert_eq!(descriptor.byte_length, bytes.len() as u64);
        let mut hash = blake3::Hasher::new();
        hash.update(b"PiglorOS.SandboxInputBytes.v1\0");
        hash.update(&bytes);
        assert_eq!(descriptor.digest, *hash.finalize().as_bytes());
        let mut changed = resolved.into_attempt();
        changed.watchdog_ms += 1;
        assert_ne!(descriptor, input_descriptor(&changed)?);
        let retained = case_buffer_bytes(&changed);
        let mut larger = changed.clone();
        larger.case_id.push_str("-retained");
        larger.schema.bytes.extend_from_slice(b"schema");
        larger.payload.bytes.extend_from_slice(b"payload");
        larger.capability_ids.push("capability-a".to_owned());
        larger.capability_ids.push("capability-bb".to_owned());
        // Measure the independently chosen retained byte additions, including
        // nonempty capability strings rather than only the default fixture.
        assert_eq!(case_buffer_bytes(&larger), retained + 9 + 6 + 7 + 12 + 13);
        let extra = b"aux";
        changed.auxiliary.push(crate::evaluator::AttemptArtifact {
            digest: *blake3::hash(extra).as_bytes(),
            bytes: extra.to_vec(),
        });
        assert_eq!(case_buffer_bytes(&changed), retained + 3);
        assert!(case_buffer_bytes(&changed) < input_descriptor(&changed)?.byte_length);
        let mut bounded = DigestWriter {
            hasher: blake3::Hasher::new(),
            // Independent 128-MiB canonical-input boundary, before the last byte.
            length: 134_217_727,
        };
        assert_eq!(bounded.write(b"x")?, 1);
        assert_eq!(bounded.length, 134_217_728);
        assert!(bounded.write(b"x").is_err());
        bounded.length = u64::MAX;
        assert!(bounded.write(b"x").is_err());
        bounded.flush()?;
        assert!(matches!(invalid(()), StagingError::InvalidSource));
        assert!(matches!(invalid_input(()), StagingError::InvalidInput));
        changed.watchdog_ms = 0;
        assert!(matches!(
            input_descriptor(&changed),
            Err(StagingError::InvalidSource)
        ));
        Ok(())
    }

    #[test]
    fn only_a_root_peer_is_accepted_and_its_stream_is_returned_unread() -> TestResult {
        let (stream, mut other) = UnixStream::pair()?;
        let root = rustix::process::geteuid().as_raw() == 0;
        let stream = match ExecutePeer::authenticate(stream) {
            Ok(peer) => {
                assert!(root);
                peer.stream
            }
            Err(stream) => {
                assert!(!root);
                stream
            }
        };
        // Another user's peer is refused and its stream comes back unread.
        let refused = ExecutePeer::of_uid(stream, rustix::process::geteuid().as_raw() + 1);
        let mut stream = ok(refused.map(|_| ()).err().ok_or("accepted"))?;
        other.write_all(b"x")?;
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        assert_eq!(byte, *b"x");
        peer(stream)?;
        Ok(())
    }

    #[test]
    fn the_single_read_holds_both_frames_their_charges_and_a_control_slot() -> TestResult {
        let ledger = StagingLedger::new(StagingLimits { aggregate_bytes: 8 });
        let (read, mut selector) = read_frames(&ledger, (1, 5_000), &[EVR, b"sp"], b"")?;
        let source = ok(read)?;
        assert_eq!((source.evaluation(), source.request()), (EVR, &b"sp"[..]));
        assert_eq!(
            ledger.usage(),
            StagingUsage {
                reserved_bytes: 8,
                pending_controls: 1,
                ..StagingUsage::default()
            }
        );
        assert!(source.spx_completed <= Instant::now());
        assert!(source.input_start.is_ok());
        let mut stream = source.into_stream();
        assert_eq!(ledger.usage(), StagingUsage::default());
        // The returned stream is the very connection that was read.
        stream.write_all(b"z")?;
        let mut byte = [0];
        selector.read_exact(&mut byte)?;
        assert_eq!(byte, *b"z");
        Ok(())
    }

    #[test]
    fn step_one_failures_of_the_single_read_hold_nothing() -> TestResult {
        let ledger = StagingLedger::new(LARGE);
        // A zero BHC1 ID 16 (ADR-122 Amendment 1 T5 iv).
        assert!(malformed(
            &read_frames(&ledger, (1, 0), &[EVR, b"s"], b"")?.0
        ));
        // A zero length, an EVR1 or SPX1 frame that never completes, and a
        // premature byte at the SPX1 frame boundary.
        let (provider, mut selector) = UnixStream::pair()?;
        selector.write_all(&0_u32.to_be_bytes())?;
        let read = ExecuteSource::read_with(
            peer(provider)?,
            &ledger,
            (1, 5_000),
            super::super::monotonic_ns,
        );
        assert!(malformed(&read));
        let (provider, mut selector) = UnixStream::pair()?;
        selector.write_all(&3_u32.to_be_bytes())?;
        selector.shutdown(std::net::Shutdown::Write)?;
        let read = ExecuteSource::read_with(
            peer(provider)?,
            &ledger,
            (1, 5_000),
            super::super::monotonic_ns,
        );
        assert!(malformed(&read));
        let (read, _selector) = read_frames(&ledger, (1, 20), &[EVR], b"\0\0")?;
        assert!(malformed(&read));
        // A stalled peer: the initial deadline expires during SPX1.
        let (read, _selector) = read_frames(&ledger, (1, 20), &[EVR], b"")?;
        assert!(malformed(&read));
        let (read, _selector) = read_frames(&ledger, (1, 5_000), &[EVR, b"spx"], b"x")?;
        assert!(malformed(&read));
        // A frame above 16 MiB.
        let (provider, mut selector) = UnixStream::pair()?;
        selector.write_all(&16_777_217_u32.to_be_bytes())?;
        let read = ExecuteSource::read_with(
            peer(provider)?,
            &ledger,
            (1, 5_000),
            super::super::monotonic_ns,
        );
        assert!(malformed(&read));
        assert_eq!(ledger.usage(), StagingUsage::default());
        Ok(())
    }

    #[test]
    fn a_refused_charge_hands_the_connection_off_at_its_current_position() -> TestResult {
        // No control slot: nothing was read.
        let ledger = StagingLedger::new(LARGE);
        let (read, mut selector) = read_frames(&ledger, (0, 5_000), &[EVR, b"spx"], b"")?;
        let handed = uncharged(read)?;
        assert!(!handed.closed());
        assert!(handed.deadline() > Instant::now());
        // Given up unread, the stream still holds the whole source.
        let mut stream = handed.into_stream();
        stream.write_all(b"z")?;
        let mut byte = [0];
        selector.read_exact(&mut byte)?;
        assert_eq!(byte, *b"z");
        let mut prefix = [0; 4];
        stream.read_exact(&mut prefix)?;
        assert_eq!(u32::from_be_bytes(prefix) as usize, EVR.len());
        let (read, _selector) = read_frames(&ledger, (0, 5_000), &[EVR, b"spx"], b"")?;
        let handed = uncharged(read)?;
        assert_eq!(ledger.usage(), StagingUsage::default());
        let (_, frames) = handed.read_rest();
        assert_eq!(frames, Some(source_frames(EVR, b"spx")));
        // EVR1's declared length is refused: its prefix was read.
        let small = StagingLedger::new(StagingLimits { aggregate_bytes: 5 });
        let (read, _selector) = read_frames(&small, (1, 5_000), &[EVR, b"sp"], b"")?;
        let handed = uncharged(read)?;
        assert_eq!(small.usage(), StagingUsage::default());
        assert_eq!(handed.read_rest().1, Some(source_frames(EVR, b"sp")));
        // SPX1's declared length is refused: EVR1 is carried, uncharged.
        let small = StagingLedger::new(StagingLimits { aggregate_bytes: 6 });
        let (read, _selector) = read_frames(&small, (1, 5_000), &[EVR, b"spx1"], b"")?;
        let handed = uncharged(read)?;
        assert_eq!(small.usage(), StagingUsage::default());
        assert_eq!(handed.read_rest().1, Some(source_frames(EVR, b"spx1")));
        // A rest that fails step 1 yields no frames, but the stream.
        let (read, _selector) = read_frames(&small, (1, 50), &[EVR], b"\0\0\0\x09")?;
        let (mut stream, frames) = uncharged(read)?.read_rest();
        assert_eq!(frames, None);
        stream.write_all(b"z")?;
        let (read, _selector) = read_frames(&ledger, (0, 50), &[], b"")?;
        assert_eq!(uncharged(read)?.read_rest().1, None);
        // A closed ledger is told apart from a full one.
        let closed = StagingLedger::new(LARGE);
        closed.close_for_reconciliation();
        let (read, _selector) = read_frames(&closed, (1, 5_000), &[EVR, b"s"], b"")?;
        assert!(uncharged(read)?.closed());
        Ok(())
    }

    #[test]
    fn a_first_record_that_is_no_evr1_is_returned_uncharged() -> TestResult {
        let ledger = StagingLedger::new(LARGE);
        // Another operation's record, and bytes that are no CBOR at all.
        for first in [&[0x81, 0x64, b'S', b'D', b'Q', b'1'][..], b"\xff"] {
            let (read, mut selector) = read_frames(&ledger, (1, 5_000), &[first], b"")?;
            let Err(SourceRefusal::NotExecute(other)) = read else {
                return Err(format!("{read:?}").into());
            };
            let (mut stream, bytes, until) = other.into_parts();
            assert_eq!(bytes, first);
            assert!(until > Instant::now());
            assert_eq!(ledger.usage(), StagingUsage::default());
            stream.write_all(b"z")?;
            let mut byte = [0];
            selector.read_exact(&mut byte)?;
            assert_eq!(byte, *b"z");
        }
        // The reader keeps the deadline it started.
        let (read, _selector) = read_frames(&ledger, (1, 5_000), &[EVR, b"s"], b"")?;
        let source = ok(read)?;
        assert_eq!(source.deadline(), source.deadlines.initial);
        Ok(())
    }

    /// A clock that cannot report the time.
    fn broken_clock() -> io::Result<u64> {
        Err(io::Error::from(io::ErrorKind::InvalidData))
    }

    #[test]
    fn an_unreadable_source_clock_is_carried_to_admission() -> TestResult {
        let ledger = StagingLedger::new(LARGE);
        let (provider, mut selector) = UnixStream::pair()?;
        write_frame(&mut selector, EVR)?;
        write_frame(&mut selector, b"s")?;
        let source = ok(ExecuteSource::read_with(
            peer(provider)?,
            &ledger,
            (1, 5_000),
            broken_clock,
        ))?;
        assert_eq!(
            source.input_start.as_ref().map_err(io::Error::kind).err(),
            Some(io::ErrorKind::InvalidData)
        );
        Ok(())
    }

    #[test]
    fn refusals_name_their_cause_and_the_image_code() {
        assert!(matches!(
            image_fault(InstallationError::ArtifactInvalid),
            StagingError::ImageIdentity
        ));
        assert!(matches!(
            image_fault(InstallationError::Io),
            StagingError::Source(InstallationError::Io)
        ));
        assert!(matches!(
            snapshot_fault(SnapshotFault::Image(InstallationError::ArtifactInvalid)),
            StagingError::ImageIdentity
        ));
        assert!(matches!(
            snapshot_fault(SnapshotFault::Launch(InstallationError::ArtifactInvalid)),
            StagingError::Source(InstallationError::ArtifactInvalid)
        ));
        assert!(matches!(
            join_fault(JoinFault::Authority(InstallationError::ArtifactInvalid)),
            StagingError::Source(InstallationError::ArtifactInvalid)
        ));
        assert!(matches!(
            join_fault(JoinFault::Image(InstallationError::ArtifactInvalid)),
            StagingError::ImageIdentity
        ));
        assert!(closed(&StagingError::CleanupFailed));
        assert!(!closed(&StagingError::AggregateExceeded));
    }

    fn isolated(test: &str) -> Result<bool, Box<dyn std::error::Error>> {
        if std::env::var_os("PIGLOROS_PRIVILEGED_COMPOSITION_TEST").is_some() {
            assert_eq!(rustix::process::geteuid().as_raw(), 0);
            return Ok(true);
        }
        let runner = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/run-isolated-test.sh");
        let output = std::process::Command::new(runner)
            .arg(std::env::current_exe()?)
            .arg(format!(
                "provider_admission::execution::source::tests::{test}"
            ))
            .output()?;
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(false)
    }

    /// The provider admission a runtime retains at startup.
    fn startup() -> TestResult<Arc<AdmittedSelectorProvider>> {
        Ok(Arc::new(
            InstalledSelectorState::open()?
                .authenticate_bootstrap()?
                .admit_provider()?,
        ))
    }

    /// The single read of the staged source, written by the selector end.
    fn source_pair(
        staged: &StagedInstallation,
        ledger: &StagingLedger,
        installation: &AdmittedSelectorProvider,
    ) -> TestResult<(ExecuteSource, UnixStream)> {
        let (provider, mut selector) = UnixStream::pair()?;
        staged.write_source(&mut selector)?;
        let peer = ok(ExecutePeer::authenticate(provider))?;
        Ok((
            ok(ExecuteSource::read(peer, ledger, installation))?,
            selector,
        ))
    }

    fn admit(
        source: ExecuteSource,
        ledger: &StagingLedger,
        installation: &Arc<AdmittedSelectorProvider>,
    ) -> Result<PreparedProviderExecution, Box<ExecuteRefusal>> {
        PreparedProviderExecution::admit(source, ledger, installation, |_| Ok::<(), Infallible>(()))
    }

    fn prepared_pair(
        staged: &StagedInstallation,
        ledger: &StagingLedger,
    ) -> TestResult<(PreparedProviderExecution, UnixStream)> {
        let installation = startup()?;
        let (source, selector) = source_pair(staged, ledger, &installation)?;
        Ok((ok(admit(source, ledger, &installation))?, selector))
    }

    /// The stream and staging error of an exchange refused before AGR1.
    fn refused<T: Debug, E: Debug>(
        result: Result<T, Box<ExecuteRefusal<E>>>,
    ) -> TestResult<(UnixStream, StagingError)> {
        match result.map_err(|refusal| refusal.into_parts()) {
            Err((stream, RefusalCause::Staging(error))) => Ok((stream, error)),
            other => Err(format!("not a staging refusal: {other:?}").into()),
        }
    }

    fn grant(prepared: PreparedProviderExecution) -> TestResult<GrantedExecution> {
        ok(prepared.grant(StagedInstallation::sign_grant, |(), _| {
            Ok::<(), Infallible>(())
        }))
        .map(|((), granted)| granted)
    }

    /// The pre-write refusal of a grant.
    fn grant_refused<E: Debug>(
        result: Result<((), GrantedExecution), GrantFailure<E>>,
    ) -> TestResult<(UnixStream, StagingError)> {
        match result {
            Err(GrantFailure::Refused(refusal)) => refused::<(), E>(Err(refusal)),
            other => Err(format!("not refused before the write: {other:?}").into()),
        }
    }

    fn staging_directory() -> TestResult<(tempfile::TempDir, StagingDirectory)> {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let temporary = tempfile::tempdir()?;
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))?;
        let held = File::open(temporary.path())?;
        let owner = held.metadata()?.uid();
        Ok((
            temporary,
            StagingDirectory::from_held_directory(held, owner)?,
        ))
    }

    // A separate wire oracle deliberately does not call the validator under test.
    fn write_chunk(
        staged: &StagedInstallation,
        selector: &mut UnixStream,
        payload: &[u8],
        parent: [u8; 32],
        trailing: &[u8],
    ) -> TestResult {
        let request = SandboxExecuteRequest::from_canonical_cbor(staged.request())?;
        let unsigned = Value::Array(vec![
            Value::Text("SBC1".to_owned()),
            Value::Integer(1.into()),
            Value::Bytes(parent.to_vec()),
            Value::Bytes(request.request.request_id.to_vec()),
            Value::Bytes(request.attempt_id.to_vec()),
            Value::Integer(0.into()),
            Value::Integer(0.into()),
            Value::Integer(0.into()),
            Value::Bytes(payload.to_vec()),
        ]);
        let mut hash = blake3::Hasher::new();
        hash.update(b"PiglorOS.SBC1.v1\0");
        hash.update(&encode(&unsigned)?);
        let bytes = encode(&Value::Array(vec![
            unsigned,
            Value::Bytes(hash.finalize().as_bytes().to_vec()),
        ]))?;
        selector.write_all(&u32::try_from(bytes.len())?.to_be_bytes())?;
        selector.write_all(&bytes)?;
        selector.write_all(trailing)?;
        selector.shutdown(std::net::Shutdown::Write)?;
        Ok(())
    }

    /// The failed input of an input refused after its AGR1 was sent.
    fn failed_input(
        received: (
            Result<AdmittedProviderExecution, Box<FailedInput>>,
            UnixStream,
        ),
    ) -> TestResult<Box<FailedInput>> {
        match received.0 {
            Err(failed) => Ok(failed),
            Ok(_) => Err("the input was admitted".into()),
        }
    }

    #[test]
    fn the_factory_reads_nothing_and_opens_the_installation_once() -> TestResult {
        if !isolated("the_factory_reads_nothing_and_opens_the_installation_once")? {
            return Ok(());
        }
        let staged = StagedInstallation::stage_execution()?;
        let installation = startup()?;
        let ledger = StagingLedger::new(LARGE);
        let (source, mut selector) = source_pair(&staged, &ledger, &installation)?;
        let started = source.deadlines.initial;
        let mut opened = 0;
        let prepared = ok(PreparedProviderExecution::admit_with(
            source,
            &ledger,
            &installation,
            || {
                opened += 1;
                InstalledSelectorState::open()
            },
            |_| Ok::<(), Infallible>(()),
        ))?;
        // T2: one SIC1 open, at the held-image join. T5 i: the factory
        // enforces the deadline the read started, never a later one.
        assert_eq!(opened, 1);
        assert_eq!(prepared.initial_deadline, started);
        // T1: a canary written after the read is the only unread byte, and
        // the pre-write premature-byte check refuses it with no AGR1 byte.
        selector.write_all(b"!")?;
        assert_eq!(rustix::io::ioctl_fionread(&prepared.stream)?, 1);
        let (stream, error) =
            grant_refused(prepared.grant(StagedInstallation::sign_grant, |(), _| {
                Ok::<(), Infallible>(())
            }))?;
        assert!(matches!(error, StagingError::InvalidSource), "{error:?}");
        // Closing with the canary unread may reset the peer; either way no
        // AGR1 byte arrives.
        drop(stream);
        assert!(match selector.read(&mut [0]) {
            Ok(length) => length == 0,
            Err(error) => error.kind() == io::ErrorKind::ConnectionReset,
        });
        assert_eq!(ledger.usage(), StagingUsage::default());
        Ok(())
    }

    #[test]
    fn port_refusals_follow_precedence_and_release_everything() -> TestResult {
        if !isolated("port_refusals_follow_precedence_and_release_everything")? {
            return Ok(());
        }
        let staged = StagedInstallation::stage_execution()?;
        let installation = startup()?;
        let ledger = StagingLedger::new(LARGE);
        // Port step A: the caller's claim refusal comes back as its own.
        let (source, _selector) = source_pair(&staged, &ledger, &installation)?;
        let refusal =
            PreparedProviderExecution::<()>::admit(source, &ledger, &installation, |_| {
                Err("claimed")
            })
            .map(drop)
            .err()
            .ok_or("admitted")?;
        assert!(matches!(
            refusal.into_parts().1,
            RefusalCause::Claim("claimed")
        ));
        assert_eq!(ledger.usage(), StagingUsage::default());
        // T4: a request whose authority differs from the retained one, even
        // though no serving step 6 ran.
        let request = staged.changed_request(|request| request.authority.trs1_digest[0] ^= 1)?;
        let (provider, mut selector) = UnixStream::pair()?;
        write_frame(&mut selector, staged.evaluation())?;
        write_frame(&mut selector, &request)?;
        let source = ok(ExecuteSource::read(
            ok(ExecutePeer::authenticate(provider))?,
            &ledger,
            &installation,
        ))?;
        let (_, error) = refused(admit(source, &ledger, &installation))?;
        assert!(matches!(error, StagingError::InvalidSource), "{error:?}");
        // T5 ii: an initial deadline that expires before the reservation.
        let (mut source, _selector) = source_pair(&staged, &ledger, &installation)?;
        source.deadlines.initial = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .ok_or("clock range")?;
        let (_, error) = refused(admit(source, &ledger, &installation))?;
        assert!(matches!(error, StagingError::ControlExpired), "{error:?}");
        Ok(())
    }

    /// Row 7: a non-empty plan list is never adopted from SPX1: the equality
    /// with the reconstructed request is mode-independent.
    #[test]
    fn a_request_carrying_plans_is_refused_at_row_7() -> TestResult {
        if !isolated("a_request_carrying_plans_is_refused_at_row_7")? {
            return Ok(());
        }
        let staged = StagedInstallation::stage_execution()?;
        let installation = startup()?;
        let ledger = StagingLedger::new(LARGE);
        let plan = crate::sandbox_provider_protocol::NetworkExchangePlan::fixture(
            [9; 16],
            0,
            "network",
            b"request",
            b"response",
        )?;
        let request = staged.changed_request(|request| request.network_plans = vec![plan])?;
        let (provider, mut selector) = UnixStream::pair()?;
        write_frame(&mut selector, staged.evaluation())?;
        write_frame(&mut selector, &request)?;
        let source = ok(ExecuteSource::read(
            ok(ExecutePeer::authenticate(provider))?,
            &ledger,
            &installation,
        ))?;
        let (_, error) = refused(admit(source, &ledger, &installation))?;
        assert!(matches!(error, StagingError::InvalidSource), "{error:?}");
        assert_eq!(ledger.usage(), StagingUsage::default());
        Ok(())
    }

    #[test]
    fn installation_digest_identity_and_clock_refusals_release_everything() -> TestResult {
        if !isolated("installation_digest_identity_and_clock_refusals_release_everything")? {
            return Ok(());
        }
        let staged = StagedInstallation::stage_execution()?;
        let installation = startup()?;
        let ledger = StagingLedger::new(LARGE);
        // T3: a current SIC1 whose installation digest alone differs from the
        // retained one is refused at the factory's join, before any
        // reservation.
        let (source, _selector) = source_pair(&staged, &ledger, &installation)?;
        let (_, error) = refused(PreparedProviderExecution::admit_with(
            source,
            &ledger,
            &installation,
            || InstalledSelectorState::open().map(|state| state.with_installation_digest([2; 32])),
            |_| Ok::<(), Infallible>(()),
        ))?;
        assert!(
            matches!(
                error,
                StagingError::Source(crate::selector::InstallationError::ArtifactInvalid)
            ),
            "{error:?}"
        );
        assert_eq!(ledger.usage(), StagingUsage::default());
        // An unreadable connection identity refuses with `Io`.
        let (mut source, _selector) = source_pair(&staged, &ledger, &installation)?;
        source.connection = Err(io::Error::other("fstat"));
        let (_, error) = refused(admit(source, &ledger, &installation))?;
        assert!(
            matches!(&error, StagingError::Io(error) if error.to_string() == "fstat"),
            "{error:?}"
        );
        assert_eq!(ledger.usage(), StagingUsage::default());
        // The unreadable SPX1-completion clock refuses before AGR1.
        let (provider, mut selector) = UnixStream::pair()?;
        staged.write_source(&mut selector)?;
        let caps = installation.provider().broker_hard_caps();
        let source = ok(ExecuteSource::read_with(
            ok(ExecutePeer::authenticate(provider))?,
            &ledger,
            (caps[13].value, caps[16].value),
            broken_clock,
        ))?;
        let (_, error) = refused(admit(source, &ledger, &installation))?;
        assert!(
            matches!(&error, StagingError::Io(error) if error.kind() == io::ErrorKind::InvalidData),
            "{error:?}"
        );
        // T9: dropping a source returns the ledger to its prior usage.
        let (source, _selector) = source_pair(&staged, &ledger, &installation)?;
        assert_ne!(ledger.usage(), StagingUsage::default());
        drop(source);
        assert_eq!(ledger.usage(), StagingUsage::default());
        Ok(())
    }

    #[test]
    fn the_floor_and_a_closed_ledger_precede_a_full_aggregate() -> TestResult {
        if !isolated("the_floor_and_a_closed_ledger_precede_a_full_aggregate")? {
            return Ok(());
        }
        let staged = StagedInstallation::stage_execution()?;
        let installation = startup()?;
        let ledger = StagingLedger::new(LARGE);
        // A source read while there was room, then an aggregate filled to
        // its cap.
        let full =
            |ledger: &StagingLedger| -> TestResult<(ExecuteSource, UnixStream, StagingCharge)> {
                let (source, selector) = source_pair(&staged, ledger, &installation)?;
                let rest = LARGE.aggregate_bytes - ledger.usage().reserved_bytes;
                Ok((source, selector, ledger.reserve_storage(rest)?))
            };
        let (source, _selector, filler) = full(&ledger)?;
        let (_, error) = refused(admit(source, &ledger, &installation))?;
        assert!(
            matches!(error, StagingError::AggregateExceeded),
            "{error:?}"
        );
        drop(filler);
        // Row R: the floor (6) before any reservation (12).
        let (source, _selector, filler) = full(&ledger)?;
        ledger.raise_floor(super::super::ControlFloor {
            revocation_epoch: u64::MAX,
            policy_epoch: u64::MAX,
        });
        let (_, error) = refused(admit(source, &ledger, &installation))?;
        assert!(
            matches!(error, StagingError::BelowControlFloor),
            "{error:?}"
        );
        // And before the closed ledger (14).
        drop(filler);
        let (source, _selector, filler) = full(&ledger)?;
        ledger.close_for_reconciliation();
        let (_, error) = refused(admit(source, &ledger, &installation))?;
        assert!(
            matches!(error, StagingError::BelowControlFloor),
            "{error:?}"
        );
        drop(filler);
        assert_eq!(ledger.usage().reserved_bytes, 0);
        Ok(())
    }

    #[test]
    fn a_changed_image_fails_the_installation_join_first() -> TestResult {
        if !isolated("a_changed_image_fails_the_installation_join_first")? {
            return Ok(());
        }
        let staged = StagedInstallation::stage_execution()?;
        let installation = startup()?;
        let ledger = StagingLedger::new(LARGE);
        let request = SandboxExecuteRequest::from_canonical_cbor(staged.request())?;
        let sim1 = installation
            .bootstrap()
            .installed()
            .artifact(
                crate::selector::installation::InstallationObjectKind::IMAGE_MANIFEST,
                request.authority.sim1_digest,
            )?
            .read_control(16 * 1024 * 1024)?;
        let manifest =
            crate::sandbox_provider_protocol::SignedImageManifest::from_canonical_cbor(&sim1)?;
        let root = installation.bootstrap().installed().artifact(
            crate::selector::installation::InstallationObjectKind::ROOT_IMAGE,
            manifest.root_image_blake3_digest,
        )?;
        let mut byte = [0];
        root.file().read_exact_at(&mut byte, 0)?;
        byte[0] ^= 1;
        // The held descriptor is read-only and the container drops every
        // capability: its owner makes the same inode writable, writes it,
        // and restores the mode.
        {
            use std::os::{fd::AsRawFd as _, unix::fs::PermissionsExt as _};
            let path = format!("/proc/self/fd/{}", root.file().as_raw_fd());
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            std::fs::OpenOptions::new()
                .write(true)
                .open(&path)?
                .write_all_at(&byte, 0)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))?;
        }
        // SIC1 verifies every indexed object's bytes when the join opens it,
        // so the change is refused at row 10, before the image check of row
        // 11: the precedence base §4 orders. ImageIdentity itself is the
        // image check's own refusal (see
        // `an_image_check_failure_is_image_identity`).
        let (source, _selector) = source_pair(&staged, &ledger, &installation)?;
        let (_, error) = refused(admit(source, &ledger, &installation))?;
        assert!(
            matches!(
                error,
                StagingError::Source(InstallationError::ArtifactInvalid)
            ),
            "{error:?}"
        );
        assert_eq!(ledger.usage(), StagingUsage::default());
        Ok(())
    }

    // Row 11: a proof no longer valid at host time fails the image check
    // itself, in the retained snapshot and in the join, and both give
    // ImageIdentity (SPE1 `9`).
    #[test]
    fn an_image_check_failure_is_image_identity() -> TestResult {
        use std::time::UNIX_EPOCH;
        let admitted = Arc::new(
            crate::selector::installation::tests::admitted_state()?
                .authenticate_bootstrap()?
                .admit_provider()?,
        );
        let request = crate::provider_admission::tests::request_for(&admitted)?;
        let expired = || UNIX_EPOCH + Duration::from_secs(2_200_000_000);
        let valid = || UNIX_EPOCH + Duration::from_hours(500_000);
        let fault = ProviderImageSnapshot::checked(Arc::clone(&admitted), request.clone(), expired)
            .err()
            .ok_or("an expired proof was admitted")?;
        assert!(matches!(snapshot_fault(fault), StagingError::ImageIdentity));
        let snapshot = ok(ProviderImageSnapshot::checked(admitted, request, valid))?;
        let current = crate::selector::installation::tests::admitted_state()
            .map_err(|_| InstallationError::Io);
        let fault = snapshot
            .join_current(current, expired)
            .err()
            .ok_or("an expired proof was joined")?;
        assert!(matches!(join_fault(fault), StagingError::ImageIdentity));
        Ok(())
    }

    #[test]
    fn signer_and_commitment_faults_write_no_grant_byte() -> TestResult {
        if !isolated("signer_and_commitment_faults_write_no_grant_byte")? {
            return Ok(());
        }
        let staged = StagedInstallation::stage_execution()?;
        let ledger = StagingLedger::new(LARGE);
        for fault in ["error", "foreign key", "commitment"] {
            let (mut prepared, mut selector) = prepared_pair(&staged, &ledger)?;
            if fault == "commitment" {
                let source =
                    Arc::get_mut(&mut prepared.execution.source).ok_or("shared fixture source")?;
                source.policy.input.digest[0] ^= 1;
            }
            let result = prepared.grant(
                |record| match fault {
                    "error" => Err(io::Error::other("signer unavailable")),
                    "foreign key" => StagedInstallation::sign_grant_with(&[5; 32], record),
                    _ => StagedInstallation::sign_grant(record),
                },
                |(), _| Ok::<(), Infallible>(()),
            );
            let (stream, error) = grant_refused(result)?;
            assert!(
                match fault {
                    "commitment" => matches!(error, StagingError::GrantCommitmentMismatch),
                    _ => matches!(error, StagingError::SignerFault),
                },
                "{fault}: {error:?}"
            );
            drop(stream);
            assert_eq!(selector.read(&mut [0])?, 0, "{fault}");
            assert_eq!(ledger.usage(), StagingUsage::default());
        }
        // The conversion is the last check: its refusal writes no byte.
        let (prepared, mut selector) = prepared_pair(&staged, &ledger)?;
        let mut digest = None;
        let result = prepared.grant(StagedInstallation::sign_grant, |(), grant| {
            digest = Some(grant);
            Err::<(), _>("fenced")
        });
        let Err(GrantFailure::Refused(refusal)) = result else {
            return Err(format!("{result:?}").into());
        };
        let (stream, cause) = refusal.into_parts();
        assert!(matches!(cause, RefusalCause::Claim("fenced")));
        assert!(digest.is_some_and(|digest| digest != [0; 32]));
        drop(stream);
        assert_eq!(selector.read(&mut [0])?, 0);
        assert_eq!(ledger.usage(), StagingUsage::default());
        Ok(())
    }

    #[test]
    fn peer_reset_is_reported_before_grant_output_and_failed_writes_consume_the_grant() -> TestResult
    {
        if !isolated(
            "peer_reset_is_reported_before_grant_output_and_failed_writes_consume_the_grant",
        )? {
            return Ok(());
        }
        let staged = StagedInstallation::stage_execution()?;
        let ledger = StagingLedger::new(LARGE);
        let (prepared, selector) = prepared_pair(&staged, &ledger)?;
        let mut outgoing = prepared.stream.try_clone()?;
        let mut selector = Some(selector);
        let result = prepared.grant(
            |message| {
                outgoing.write_all(b"unread")?;
                drop(selector.take());
                StagedInstallation::sign_grant(message)
            },
            |(), _| Ok::<(), Infallible>(()),
        );
        let (stream, error) = grant_refused(result)?;
        assert!(
            matches!(&error, StagingError::Io(error) if error.kind() == io::ErrorKind::ConnectionReset),
            "{error:?}"
        );
        drop((stream, outgoing));
        assert_eq!(ledger.usage(), StagingUsage::default());

        // A write that began and failed is not retried, and no SPE1 follows.
        let (prepared, selector) = prepared_pair(&staged, &ledger)?;
        selector.shutdown(std::net::Shutdown::Read)?;
        let mut converted = false;
        let result = prepared.grant(StagedInstallation::sign_grant, |(), _| {
            converted = true;
            Ok::<(), Infallible>(())
        });
        assert!(
            matches!(result, Err(GrantFailure::Interrupted(StagingError::Io(_)))),
            "{result:?}"
        );
        assert!(converted);
        drop(selector);
        assert_eq!(ledger.usage(), StagingUsage::default());

        // L7: an interrupted write drops the stream, and no clone of it
        // survives, so the selector reads EOF after the bytes it was sent.
        // A full, nonblocking send buffer makes the AGR1 write fail.
        let (prepared, mut selector) = prepared_pair(&staged, &ledger)?;
        let filler = prepared.stream.try_clone()?;
        filler.set_nonblocking(true)?;
        let mut sent = 0;
        while let Ok(written) = (&filler).write(&[0; 4096]) {
            sent += written;
        }
        drop(filler);
        let result = prepared.grant(StagedInstallation::sign_grant, |(), _| {
            Ok::<(), Infallible>(())
        });
        assert!(
            matches!(result, Err(GrantFailure::Interrupted(StagingError::Io(_)))),
            "{result:?}"
        );
        selector.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut received = Vec::new();
        selector.read_to_end(&mut received)?;
        assert!(received.len() >= sent && sent > 0);
        assert!(received[..sent].iter().all(|byte| *byte == 0));
        assert_eq!(ledger.usage(), StagingUsage::default());
        Ok(())
    }

    #[test]
    fn verified_chunk_identity_digest_and_private_storage_fail_closed() -> TestResult {
        if !isolated("verified_chunk_identity_digest_and_private_storage_fail_closed")? {
            return Ok(());
        }
        let staged = StagedInstallation::stage_execution()?;
        for fault in [
            "parent",
            "digest",
            "read-only",
            "overlong",
            "trailing",
            "floor",
            "installation",
        ] {
            let ledger = StagingLedger::new(LARGE);
            let (prepared, mut selector) = prepared_pair(&staged, &ledger)?;
            let expected = prepared.policy().input.byte_length;
            let window = prepared.execution.window;
            let digest = prepared.request().request_digest;
            let granted = grant(prepared)?;
            let temporary = tempfile::NamedTempFile::new()?;
            let file = if fault == "read-only" {
                File::open(temporary.path())?
            } else {
                temporary.reopen()?
            };
            if fault == "overlong" {
                file.set_len(staged.input().len() as u64 + 1)?;
            }
            let mut payload = staged.input().to_vec();
            if fault == "digest" {
                payload[0] ^= 1;
            }
            let parent = if fault == "parent" {
                [0x71; 32]
            } else {
                digest
            };
            let trailing: &[u8] = if fault == "trailing" { b"x" } else { b"" };
            write_chunk(&staged, &mut selector, &payload, parent, trailing)?;
            if fault == "floor" {
                ledger.raise_floor(super::super::ControlFloor {
                    revocation_epoch: u64::MAX,
                    policy_epoch: u64::MAX,
                });
            }
            let manifest =
                std::path::Path::new(crate::selector::installation::SANDBOX_ARTIFACT_ROOT)
                    .join(crate::selector::installation::MANIFEST_NAME);
            let saved = if fault == "installation" {
                let bytes = std::fs::read(&manifest)?;
                std::fs::remove_file(&manifest)?;
                Some(bytes)
            } else {
                None
            };
            let result = failed_input(granted.receive(&file));
            if let Some(bytes) = saved {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::write(&manifest, bytes)?;
                std::fs::set_permissions(&manifest, std::fs::Permissions::from_mode(0o400))?;
            }
            let failed = result?;
            let error = failed.error();
            assert!(
                match fault {
                    "read-only" => matches!(error, StagingError::Io(_)),
                    "floor" => matches!(error, StagingError::BelowControlFloor),
                    "installation" => matches!(error, StagingError::Source(_)),
                    _ => matches!(error, StagingError::InvalidInput),
                },
                "{fault}: {error:?}"
            );
            // The one chunk is the final chunk: a failed input never counts
            // it, so the transfer is incomplete however far it got.
            let transfer = failed.transfer().ok_or("no transfer")?;
            assert_eq!(
                (transfer.start, transfer.deadline, transfer.expected_bytes),
                (window.start, window.deadline, expected),
                "{fault}"
            );
            assert_eq!(transfer.accepted_bytes, 0, "{fault}");
            assert!(!transfer.complete, "{fault}");
            assert!(transfer.start <= transfer.finish, "{fault}");
            assert_ne!(failed.grant().bytes(), &[] as &[u8]);
            assert_eq!(ledger.usage().attempts, 0);
            assert_eq!(ledger.usage().reserved_bytes, 0);
        }
        Ok(())
    }

    #[test]
    fn an_input_window_that_expires_after_a_complete_grant_fails_the_admitted_input() -> TestResult
    {
        if !isolated(
            "an_input_window_that_expires_after_a_complete_grant_fails_the_admitted_input",
        )? {
            return Ok(());
        }
        let staged = StagedInstallation::stage_execution()?;
        let ledger = StagingLedger::new(LARGE);
        let (prepared, mut selector) = prepared_pair(&staged, &ledger)?;
        let attempt_id = prepared.request().attempt_id;
        let mut granted = grant(prepared)?;
        let sent = frame(&mut selector, &ledger)?.bytes;
        // The prebuilt interruption names this attempt and its grant.
        let interrupted = granted.interrupted();
        assert!(matches!(interrupted.error(), StagingError::Incomplete));
        assert_eq!(interrupted.attempt_id(), attempt_id);
        assert_eq!(interrupted.grant().bytes(), sent.as_slice());
        let transfer = interrupted.transfer().ok_or("no transfer")?;
        assert_eq!(transfer.accepted_bytes, 0);
        assert!(!transfer.complete);
        drop(interrupted);
        // The window ends right after AGR1 was completely written: the
        // selector holds the grant, so the attempt is admitted and fails.
        granted.execution.input_deadline = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .ok_or("clock range")?;
        staged.write_input(&mut selector)?;
        selector.shutdown(std::net::Shutdown::Write)?;
        let file = tempfile::tempfile()?;
        let failed = failed_input(granted.receive(&file))?;
        assert!(
            matches!(failed.error(), StagingError::Io(_)),
            "{:?}",
            failed.error()
        );
        assert_eq!(failed.attempt_id(), attempt_id);
        assert_eq!(failed.grant().bytes(), sent.as_slice());
        assert!(failed.transfer().is_some_and(|transfer| !transfer.complete));
        assert_eq!(ledger.usage(), StagingUsage::default());
        Ok(())
    }

    #[test]
    fn an_unreadable_clock_after_agr1_leaves_no_time() -> TestResult {
        if !isolated("an_unreadable_clock_after_agr1_leaves_no_time")? {
            return Ok(());
        }
        let staged = StagedInstallation::stage_execution()?;
        let ledger = StagingLedger::new(LARGE);
        for complete in [true, false] {
            // After AGR1 the grant's issue time and the transfer are absent.
            let (mut prepared, mut selector) = prepared_pair(&staged, &ledger)?;
            prepared.execution.clock = broken_clock;
            let granted = grant(prepared)?;
            assert_eq!(granted.interrupted().transfer(), None);
            drop(frame(&mut selector, &ledger)?);
            if complete {
                staged.write_input(&mut selector)?;
            }
            selector.shutdown(std::net::Shutdown::Write)?;
            let file = tempfile::tempfile()?;
            match granted.receive(&file).0 {
                Ok(admitted) => {
                    assert!(complete);
                    assert_eq!(admitted.grant().issued_at(), None);
                    assert_eq!(admitted.transfer(), None);
                }
                Err(failed) => {
                    assert!(!complete);
                    assert_eq!(failed.grant().issued_at(), None);
                    assert_eq!(failed.transfer(), None);
                }
            }
            assert_eq!(ledger.usage(), StagingUsage::default());
        }
        Ok(())
    }

    #[test]
    fn the_input_window_is_anchored_at_the_read_sample() -> TestResult {
        if !isolated("the_input_window_is_anchored_at_the_read_sample")? {
            return Ok(());
        }
        let staged = StagedInstallation::stage_execution()?;
        let installation = startup()?;
        let ledger = StagingLedger::new(LARGE);
        let (provider, mut selector) = UnixStream::pair()?;
        staged.write_source(&mut selector)?;
        let caps = installation.provider().broker_hard_caps();
        let source = ok(ExecuteSource::read_with(
            ok(ExecutePeer::authenticate(provider))?,
            &ledger,
            (caps[13].value, caps[16].value),
            || Ok(1_234),
        ))?;
        let completed = source.spx_completed;
        let prepared = ok(admit(source, &ledger, &installation))?;
        // T6: TME1 `input.start` is the reader's sample, and the enforced
        // deadline is the ELM1 ID 16 window from the SPX1-completion instant.
        assert_eq!(prepared.execution.window.start, 1_234);
        assert_eq!(
            prepared.execution.input_deadline,
            completed + Duration::from_millis(prepared.policy().limit(16))
        );
        Ok(())
    }

    #[test]
    fn independent_eai_decode_and_case_comparison_survive_crossed_private_facts() -> TestResult {
        if !isolated("independent_eai_decode_and_case_comparison_survive_crossed_private_facts")? {
            return Ok(());
        }
        let staged = StagedInstallation::stage_execution()?;
        for fault in ["decode", "case", "decoded-budget"] {
            let ledger = StagingLedger::new(StagingLimits {
                aggregate_bytes: 1024 * 1024,
            });
            let (prepared, mut selector) = prepared_pair(&staged, &ledger)?;
            let parent = prepared.request().request_digest;
            let mut granted = grant(prepared)?;
            let mut payload = staged.input().to_vec();
            // These are impossible-state faults after the real authenticated
            // factory, scoped to private test access. They prove the final
            // decoder/comparison/reservation guards independently of the
            // already verified source descriptor, with no production bypass.
            let source =
                Arc::get_mut(&mut granted.execution.source).ok_or("shared fixture source")?;
            match fault {
                "decode" => {
                    payload.fill(0);
                    let mut hash = blake3::Hasher::new();
                    hash.update(b"PiglorOS.SandboxInputBytes.v1\0");
                    hash.update(&payload);
                    source.policy.input.digest = *hash.finalize().as_bytes();
                }
                "case" => source.expected.attempt.watchdog_ms += 1,
                _ => source.expected.attempt.schema.bytes.resize(1024 * 1024, 0),
            }
            drop(frame(&mut selector, &ledger)?);
            write_chunk(&staged, &mut selector, &payload, parent, b"")?;
            let file = tempfile::tempfile()?;
            let failed = failed_input(granted.receive(&file))?;
            let error = failed.error();
            assert!(
                match fault {
                    "decoded-budget" => matches!(error, StagingError::AggregateExceeded),
                    _ => matches!(error, StagingError::InvalidInput),
                },
                "{fault}: {error:?}"
            );
            // Every byte arrived in time, but the input was not admitted.
            assert!(
                failed.transfer().is_some_and(|transfer| !transfer.complete),
                "{fault}"
            );
            assert_eq!(ledger.usage(), StagingUsage::default());
        }
        Ok(())
    }

    #[test]
    fn prepared_deadlines_are_not_restarted_by_signing_and_authority_is_rechecked() -> TestResult {
        if !isolated("prepared_deadlines_are_not_restarted_by_signing_and_authority_is_rechecked")?
        {
            return Ok(());
        }
        let staged = StagedInstallation::stage_execution()?;
        for fault in ["initial", "input", "floor", "installation"] {
            let ledger = StagingLedger::new(LARGE);
            let (mut prepared, mut selector) = prepared_pair(&staged, &ledger)?;
            let expired = Instant::now()
                .checked_sub(Duration::from_secs(1))
                .ok_or("clock range")?;
            // Set only private clocks; no sleeps, clock reset, or alternate
            // admission constructor is introduced into the production path.
            if fault == "initial" {
                prepared.initial_deadline = expired;
            }
            if fault == "floor" {
                ledger.raise_floor(super::super::ControlFloor {
                    revocation_epoch: u64::MAX,
                    policy_epoch: u64::MAX,
                });
            }
            let manifest =
                std::path::Path::new(crate::selector::installation::SANDBOX_ARTIFACT_ROOT)
                    .join(crate::selector::installation::MANIFEST_NAME);
            let saved = if fault == "installation" {
                let bytes = std::fs::read(&manifest)?;
                std::fs::remove_file(&manifest)?;
                Some(bytes)
            } else {
                None
            };
            if fault == "input" {
                prepared.execution.input_deadline = expired;
            }
            let result = grant_refused(prepared.grant(StagedInstallation::sign_grant, |(), _| {
                Ok::<(), Infallible>(())
            }));
            if let Some(bytes) = saved {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::write(&manifest, bytes)?;
                std::fs::set_permissions(&manifest, std::fs::Permissions::from_mode(0o400))?;
            }
            let (stream, error) = result?;
            assert!(
                match fault {
                    "floor" => matches!(error, StagingError::BelowControlFloor),
                    "installation" => matches!(error, StagingError::Source(_)),
                    "initial" => matches!(error, StagingError::ControlExpired),
                    _ => matches!(error, StagingError::InputWindowExpired),
                },
                "{fault}: {error:?}"
            );
            drop(stream);
            assert_eq!(selector.read(&mut [0])?, 0);
            assert_eq!(ledger.usage().attempts, 0);
            assert_eq!(ledger.usage().reserved_bytes, 0);
        }
        Ok(())
    }

    #[test]
    fn source_failure_releases_control_and_reconstructed_case_reservations() -> TestResult {
        if !isolated("source_failure_releases_control_and_reconstructed_case_reservations")? {
            return Ok(());
        }
        let ledger = StagingLedger::new(LARGE);
        let staged = StagedInstallation::stage_execution()?;
        let installation = startup()?;
        let controls = (0..256)
            .map(|_| ledger.control(256))
            .collect::<Result<Vec<_>, _>>()?;
        let (provider, mut selector) = UnixStream::pair()?;
        staged.write_source(&mut selector)?;
        let read = ExecuteSource::read(
            ok(ExecutePeer::authenticate(provider))?,
            &ledger,
            &installation,
        );
        assert!(!uncharged(read)?.closed());
        drop(controls);
        assert_eq!(ledger.usage(), StagingUsage::default());
        let case = read_attempt(staged.input())?;
        let source_bytes = staged.evaluation().len() as u64 + staged.request().len() as u64;
        let short = StagingLedger::new(StagingLimits {
            aggregate_bytes: source_bytes + case_buffer_bytes(&case) - 1,
        });
        let (source, _selector) = source_pair(&staged, &short, &installation)?;
        let (_, error) = refused(admit(source, &short, &installation))?;
        assert!(
            matches!(error, StagingError::AggregateExceeded),
            "{error:?}"
        );
        assert_eq!(short.usage(), StagingUsage::default());
        let request = staged.changed_request(|request| {
            request.request.request_id[14..].copy_from_slice(&u16::MAX.to_be_bytes());
            request.attempt_id[14..].copy_from_slice(&0x7fff_u16.to_be_bytes());
        })?;
        let (provider, mut selector) = UnixStream::pair()?;
        for record in [staged.evaluation(), request.as_slice()] {
            write_frame(&mut selector, record)?;
        }
        let source = ok(ExecuteSource::read(
            ok(ExecutePeer::authenticate(provider))?,
            &ledger,
            &installation,
        ))?;
        let (_, error) = refused(admit(source, &ledger, &installation))?;
        assert!(matches!(error, StagingError::Source(_)), "{error:?}");
        assert_eq!(ledger.usage(), StagingUsage::default());
        Ok(())
    }

    #[test]
    fn residual_cleanup_closes_new_sources_and_grants_even_during_signing() -> TestResult {
        use std::os::unix::fs::MetadataExt as _;

        #[derive(Clone, Copy, Debug)]
        enum Replacement {
            Directory,
            RegularFile,
            SymbolicLink,
            HardLink,
        }

        if !isolated("residual_cleanup_closes_new_sources_and_grants_even_during_signing")? {
            return Ok(());
        }

        let staged = StagedInstallation::stage_execution()?;
        let installation = startup()?;
        for (during_signing, replacement) in [
            (false, Replacement::Directory),
            (true, Replacement::Directory),
            (false, Replacement::RegularFile),
            (true, Replacement::RegularFile),
            (false, Replacement::SymbolicLink),
            (true, Replacement::SymbolicLink),
            (false, Replacement::HardLink),
            (true, Replacement::HardLink),
        ] {
            let ledger = StagingLedger::new(LARGE);
            let (prepared, mut selector) = prepared_pair(&staged, &ledger)?;
            let (failed, failed_selector) = prepared_pair(&staged, &ledger)?;
            let (temporary, staging) = staging_directory()?;
            let input = ok(staging.create_input([6; 16], failed))?;
            let leaf = temporary.path().join("06".repeat(16));
            let residual = temporary.path().join("residual");
            std::fs::write(&leaf, b"retained owned bytes")?;
            let fail_cleanup = || -> io::Result<()> {
                std::fs::rename(&leaf, &residual)?;
                match replacement {
                    Replacement::Directory => std::fs::create_dir(&leaf)?,
                    Replacement::RegularFile => std::fs::write(&leaf, b"foreign bytes")?,
                    Replacement::SymbolicLink => std::os::unix::fs::symlink(&residual, &leaf)?,
                    Replacement::HardLink => std::fs::hard_link(&residual, &leaf)?,
                }
                let before = std::fs::symlink_metadata(&leaf)?;
                drop(input);
                let after = std::fs::symlink_metadata(&leaf)?;
                assert_eq!(
                    (after.dev(), after.ino()),
                    (before.dev(), before.ino()),
                    "cleanup must preserve {replacement:?}, during_signing={during_signing}"
                );
                Ok(())
            };
            let result = if during_signing {
                prepared.grant(
                    |message| {
                        fail_cleanup()?;
                        StagedInstallation::sign_grant(message)
                    },
                    |(), _| Ok::<(), Infallible>(()),
                )
            } else {
                fail_cleanup()?;
                prepared.grant(
                    |_| {
                        Err(io::Error::other(
                            "closed admission must not invoke the signer",
                        ))
                    },
                    |(), _| Ok::<(), Infallible>(()),
                )
            };
            let (stream, error) = grant_refused(result)?;
            assert!(matches!(error, StagingError::CleanupFailed), "{error:?}");
            assert_eq!(std::fs::read(residual)?, b"retained owned bytes");
            let (next, _next_selector) = UnixStream::pair()?;
            let read =
                ExecuteSource::read(ok(ExecutePeer::authenticate(next))?, &ledger, &installation);
            assert!(uncharged(read)?.closed());
            drop((stream, failed_selector));
            assert_eq!(selector.read(&mut [0])?, 0);
            assert_eq!(ledger.usage().reserved_bytes, 0);
            assert_eq!(ledger.usage().leaked_files, 1);
            assert!(matches!(
                ledger.reserve_storage(0),
                Err(StagingError::CleanupFailed)
            ));
        }
        Ok(())
    }

    #[test]
    fn a_staging_file_that_cannot_be_created_refuses_before_agr1() -> TestResult {
        if !isolated("a_staging_file_that_cannot_be_created_refuses_before_agr1")? {
            return Ok(());
        }
        let staged = StagedInstallation::stage_execution()?;
        let ledger = StagingLedger::new(LARGE);
        let (prepared, mut selector) = prepared_pair(&staged, &ledger)?;
        let (temporary, staging) = staging_directory()?;
        // T11: an existing entry is never adopted, and no AGR1 byte follows.
        std::fs::write(temporary.path().join("09".repeat(16)), b"x")?;
        let (stream, error) = refused(staging.create_input([9; 16], prepared))?;
        assert!(matches!(error, StagingError::Io(_)), "{error:?}");
        drop(stream);
        assert_eq!(selector.read(&mut [0])?, 0);
        assert_eq!(ledger.usage(), StagingUsage::default());
        Ok(())
    }

    /// An issued grant answers its Local admission with exactly the one it was
    /// given, and with none otherwise (ADR-069 R14 §3.5).
    #[test]
    fn an_issued_grant_carries_the_local_admission_it_was_given() {
        use crate::sandbox_provider_protocol::{
            LocalNetworkAdmission, NetworkProxyLimits, SandboxExecutionMode,
        };
        let grant = IssuedGrant::fixture([1; 32], Vec::new(), SandboxExecutionMode::Local);
        assert_eq!(grant.local_network(), None);
        let admission = LocalNetworkAdmission::fixture(
            [2; 16],
            AdmissionAuthority::fixture(),
            [1, 2, 3],
            Vec::new(),
            NetworkProxyLimits {
                request_bytes: 1,
                response_bytes: 2,
                milliseconds: 3,
            },
        );
        let carrying = grant.with_local_network(admission.clone());
        assert_eq!(carrying.local_network(), Some(&admission));
    }

    /// The admitted facts the terminal records need are retained with the
    /// grant: ELM1 under the digest AGR1 names, the mode, and SPR1's
    /// provider binary and negative-probe digests (Redmine #443 journal
    /// 22723).
    fn assert_granted_facts(entry: &super::super::AdmittedEntry<'_>, elm1_digest: [u8; 32]) {
        let issued = entry.grant();
        assert_eq!(issued.effective_limits(), entry.policy().effective_limits());
        assert_eq!(issued.effective_limits_digest(), elm1_digest);
        let snapshot = entry.admission().snapshot();
        assert_eq!(
            issued.execution_mode(),
            snapshot.launch_policy().execution_mode
        );
        // Only a Local grant carries an admission (ADR-069 R14 §3.5); the
        // staged installation is Air-Gapped, so a grant that carried one
        // here would be wired wrongly.
        assert_eq!(
            issued.local_network().is_some(),
            issued.execution_mode()
                == crate::sandbox_provider_protocol::SandboxExecutionMode::Local
        );
        let provider = snapshot.admitted.provider();
        assert_eq!(
            issued.provider_binary_digest(),
            provider.manifest().binary_digest
        );
        assert_eq!(
            issued.negative_probe_evidence(),
            provider.host_profile().negative_probe_evidence
        );
    }

    /// The staged exchange read once, admitted, staged and granted, with
    /// the selector end.
    fn granted_input(
        staged: &StagedInstallation,
        ledger: &StagingLedger,
    ) -> TestResult<(tempfile::TempDir, super::super::GrantedInput, UnixStream)> {
        let (provider, mut selector) = UnixStream::pair()?;
        staged.write_source(&mut selector)?;
        let installation = startup()?;
        let source = ok(ExecuteSource::read(
            ok(ExecutePeer::authenticate(provider))?,
            ledger,
            &installation,
        ))?;
        let prepared = ok(admit(source, ledger, &installation))?;
        let (temporary, staging) = staging_directory()?;
        let input = ok(staging.create_input([8; 16], prepared))?;
        let ((), granted) = ok(input.send_grant(StagedInstallation::sign_grant, |(), _| {
            Ok::<(), Infallible>(())
        }))?;
        Ok((temporary, granted, selector))
    }

    #[test]
    fn admitted_input_preserves_bytes_policy_and_the_live_floor() -> TestResult {
        if !isolated("admitted_input_preserves_bytes_policy_and_the_live_floor")? {
            return Ok(());
        }
        let staged = StagedInstallation::stage_execution()?;
        let ledger = StagingLedger::new(LARGE);
        let (_temporary, granted, mut selector) = granted_input(&staged, &ledger)?;
        let grant = frame(&mut selector, &ledger)?;
        let sent_grant =
            crate::sandbox_provider_protocol::AdmissionGrant::from_canonical_cbor(&grant.bytes)?;
        let sent_bytes = grant.bytes.clone();
        drop(grant);
        assert_eq!(granted.grant().bytes(), sent_bytes.as_slice());
        staged.write_input(&mut selector)?;
        selector.shutdown(std::net::Shutdown::Write)?;
        let (verified, stream) = granted.receive();
        let verified = ok(verified)?;
        // T7: the stream AGR1 was written to and input received from has the
        // identity the reader recorded before its first source byte.
        let returned = rustix::fs::fstat(&stream)?;
        assert_eq!(
            verified.entry().retain().connection(),
            (returned.st_dev, returned.st_ino)
        );
        let expected_request = SandboxExecuteRequest::from_canonical_cbor(staged.request())?;
        assert_eq!(verified.len(), staged.input().len() as u64);
        assert!(!verified.is_empty());
        // Cancel and reconcile requests must name exactly the AGR1 sent.
        assert_eq!(verified.entry().grant_digest(), sent_grant.grant_digest());
        assert_ne!(sent_grant.grant_digest(), [0; 32]);
        // The exact AGR1 bytes are retained, with the ledger when it was
        // issued: this attempt live and its input still incomplete.
        let issued = verified.entry().grant();
        assert_eq!(issued.bytes(), sent_bytes.as_slice());
        assert_eq!(issued.digest(), sent_grant.grant_digest());
        assert_eq!(
            issued.admission(),
            AdmissionLedger {
                active_attempts: 1,
                incomplete_inputs: 1,
            }
        );
        let transfer = verified.entry().transfer().ok_or("no transfer")?;
        assert!(transfer.complete);
        assert_eq!(
            (transfer.expected_bytes, transfer.accepted_bytes),
            (verified.len(), verified.len())
        );
        let issued_at = issued.issued_at().ok_or("no issue time")?;
        assert!(transfer.start <= issued_at && issued_at <= transfer.finish);
        assert_granted_facts(&verified.entry(), sent_grant.elm1_digest);
        assert!(transfer.finish <= transfer.deadline);
        assert_eq!(
            verified.entry().policy().request_digest(),
            expected_request.request_digest
        );
        verified.entry().recheck()?;
        let mut readback = vec![0xff; staged.input().len()];
        verified.read_exact_at(&mut readback, 0)?;
        assert_eq!(readback, staged.input());
        let execution = verified.entry().retain();
        // The attempt's one output: exactly ELM1[8] bytes, reserved once
        // through either handle and released with its charge.
        let before = ledger.usage().reserved_bytes;
        let output = verified
            .reserve_output()
            .ok_or("the first output reservation was refused")??;
        assert_eq!(
            ledger.usage().reserved_bytes - before,
            verified.entry().policy().effective_limits()[8].value
        );
        assert!(execution.reserve_output().is_none());
        assert!(verified.reserve_output().is_none());
        drop(output);
        assert_eq!(ledger.usage().reserved_bytes, before);
        let length = verified.len();
        execution.read_exact_at(&mut [], length)?;
        let mut last = [0xff];
        execution.read_exact_at(&mut last, length - 1)?;
        assert_eq!(
            last[0],
            *staged.input().last().ok_or("empty admitted input")?
        );
        for offset in [length, length + 1, u64::MAX] {
            assert_eq!(
                execution
                    .read_exact_at(&mut [0], offset)
                    .err()
                    .map(|error| error.kind()),
                Some(io::ErrorKind::UnexpectedEof)
            );
        }
        ledger.raise_floor(super::super::ControlFloor {
            revocation_epoch: u64::MAX,
            policy_epoch: u64::MAX,
        });
        assert!(matches!(
            verified.entry().recheck(),
            Err(RecheckError::Ledger(
                super::super::RecheckLedgerError::BelowControlFloor
            ))
        ));
        drop((verified, execution, stream));
        assert_eq!(ledger.usage().reserved_bytes, 0);
        assert_eq!(ledger.usage().attempts, 0);
        Ok(())
    }

    #[test]
    fn retained_input_closes_before_its_bytes_and_attempt_are_released() -> TestResult {
        use std::os::{fd::AsRawFd as _, unix::fs::MetadataExt as _};

        if !isolated("retained_input_closes_before_its_bytes_and_attempt_are_released")? {
            return Ok(());
        }
        let staged = StagedInstallation::stage_execution()?;
        let ledger = StagingLedger::new(LARGE);
        let (prepared, mut selector) = prepared_pair(&staged, &ledger)?;
        let input_reservation = prepared.staging_charge();
        let (temporary, staging) = staging_directory()?;
        let input = ok(staging.create_input([7; 16], prepared))?;
        let ((), granted) = ok(input.send_grant(StagedInstallation::sign_grant, |(), _| {
            Ok::<(), Infallible>(())
        }))?;
        drop(frame(&mut selector, &ledger)?);
        staged.write_input(&mut selector)?;
        selector.shutdown(std::net::Shutdown::Write)?;
        let verified = ok(granted.receive().0)?;
        let execution = verified.entry().retain();
        let metadata = execution.verified_input.metadata()?;
        let descriptor_path = format!("/proc/self/fd/{}", execution.verified_input.as_raw_fd());
        // Keep unrelated source-buffer charges out of this input-charge checkpoint.
        let retained_source = Arc::clone(&execution.source);
        drop(verified);
        assert!(!temporary.path().join("07".repeat(16)).exists());
        let retained = std::fs::metadata(&descriptor_path)?;
        assert_eq!(
            (retained.dev(), retained.ino()),
            (metadata.dev(), metadata.ino())
        );
        let mut byte = [0];
        execution.read_exact_at(&mut byte, 0)?;
        assert_eq!(byte[0], staged.input()[0]);
        let before = ledger.usage();
        let (reached_tx, reached_rx) = std::sync::mpsc::channel();
        let (proceed_tx, proceed_rx) = std::sync::mpsc::channel();
        input_reservation.before_release_for_test(reached_tx, proceed_rx);
        drop(input_reservation);
        let (closed, at_release) = std::thread::scope(|scope| -> TestResult<_> {
            let worker = scope.spawn(move || drop(execution));
            let reached = reached_rx.recv_timeout(Duration::from_secs(5));
            let closed = std::fs::symlink_metadata(descriptor_path)
                .is_err_and(|error| error.kind() == io::ErrorKind::NotFound);
            let at_release = ledger.usage();
            // Always unblock the destructor before inspecting fallible observations.
            let resumed = proceed_tx.send(());
            let joined = worker.join();
            reached?;
            resumed?;
            joined.map_err(|_| "input destructor panicked")?;
            Ok((closed, at_release))
        })?;
        drop(retained_source);
        assert!(
            closed,
            "the input descriptor must close before its charge releases"
        );
        assert_eq!(at_release, before);
        assert_eq!(before.attempts, 1);
        assert_eq!(ledger.usage(), StagingUsage::default());
        Ok(())
    }
}
