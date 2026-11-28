//! Serving an `Open` runtime's execute connections through its execute port
//! (ADR-069 R11 §7.3 and Amendment 1 §7.5; ADR-122 Amendment 1).
//!
//! The connection's two source frames are read once, charged, by the
//! pos-reference reader. A first record that is no EVR1 is another
//! operation: describe is answered here, and cancel and reconcile are handed
//! to the control pool (ADR-069 R15 N13). A refused charge hands the connection, at
//! its stream position, to the bounded uncharged readers (item P7). Then:
//!
//! 1. steps 2 to 6 run on the decoded views, and the admission state is
//!    read again (§7.2): no longer `Open` gives `11`, `Revoked` zero bytes;
//! 2. port step J: an exact repeat joins the attempt it repeats and replays
//!    its stored full response, waiting at most until the initial control
//!    deadline (item P1);
//! 3. the factory admits the source in §7.5 order, taking the lifecycle
//!    claim (step A), and the staging file is created (step S);
//! 4. AGR1 is signed and written, the claim converted as the last check
//!    (step W). A refusal before the write is the §7.5 SPE1; a signing fault
//!    writes zero bytes and closes execute admission (R9 §5); a write that
//!    began and failed writes nothing more (base §4);
//! 5. the input is received; the admitted attempt runs, or its failed input
//!    is recorded, and its signed terminal response is retained and written:
//!    the SAU1 chain and SPR1, the output SBC1 records within the ELM1 ID 16
//!    window from their start, then SPY1. An output transfer that times out
//!    re-issues the response (R9 §4.7).

use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pos_reference::provider_admission::execution::{
    ExecutePeer, ExecuteRefusal, ExecuteSource, GrantFailure, OtherRequest,
    PreparedProviderExecution, RefusalCause, SourceRefusal, StagingError, UnchargedSource,
};
use pos_reference::sandbox_provider_protocol::{
    SandboxPayloadChunk, SandboxProviderErrorCode, TransferRecord,
};
use pos_reference::selector::InstallationError;

use super::{
    close_answered, Classified, Deadlined, Place, Refusal, RequestIdentity, Responder,
    RESPONSE_DEADLINE,
};
use crate::provider_runtime::port::{mode_plan, ExecutePort};
use crate::{sign_verified, AttemptLifecycleError, ExchangeClaim, RetainedResponse};

/// The ELM1 limit whose window bounds an output transfer (R9 §4.6.5: IDs 7
/// and 16 act through `input` and `output-transfer`).
const TRANSFER_WINDOW_ID: usize = 16;

/// What port step J found.
pub(super) enum Join {
    /// No exchange holds the attempt: admit the request afresh.
    Fresh,
    /// The repeat's answer.
    Answer(Answer),
}

/// How an exchange that is not admitted afresh is answered.
pub(super) enum Answer {
    /// The stored full response to replay.
    Replay(Arc<RetainedResponse>),
    /// The exchange's SPE1.
    Refused(SandboxProviderErrorCode),
    /// No response will exist: nothing is written (R9 §5).
    Silent,
}

/// The answer of a lifecycle refusal (R11 Amendment 1 §7.5 rows J and A):
/// a reconciled attempt is `15`, other bytes `16`, a full table `12`, a
/// response that will never be signed nothing, and a fence `11`. So is an
/// attempt another exchange claimed after this one's step J, whose source
/// is spent and cannot be joined afresh.
const fn lifecycle_answer(error: &AttemptLifecycleError) -> Answer {
    match error {
        AttemptLifecycleError::UnknownAttempt => {
            Answer::Refused(SandboxProviderErrorCode::UnknownAttempt)
        }
        AttemptLifecycleError::RequestConflict => {
            Answer::Refused(SandboxProviderErrorCode::RequestIdentityConflict)
        }
        AttemptLifecycleError::TooManyLiveAttempts => {
            Answer::Refused(SandboxProviderErrorCode::AdmissionBusy)
        }
        AttemptLifecycleError::ResponseUnavailable => Answer::Silent,
        _ => Answer::Refused(SandboxProviderErrorCode::SandboxUnavailable),
    }
}

/// The SPE1 code of a source, admission or staging refusal before AGR1 (R11
/// Amendment 1 §7.5). A signing fault has none: it writes zero bytes.
const fn staging_code(error: &StagingError) -> Option<SandboxProviderErrorCode> {
    use SandboxProviderErrorCode as Code;
    match error {
        StagingError::SignerFault | StagingError::GrantCommitmentMismatch => None,
        StagingError::InvalidSource | StagingError::Source(InstallationError::ArtifactInvalid) => {
            Some(Code::AuthorityMismatch)
        }
        StagingError::ImageIdentity => Some(Code::ImageIdentityMismatch),
        StagingError::InputTooLarge => Some(Code::FieldOutOfBounds),
        StagingError::BelowControlFloor => Some(Code::TrustRevoked),
        StagingError::CleanupFailed => Some(Code::CleanupFailed),
        StagingError::QueueFull
        | StagingError::AttemptsExhausted
        | StagingError::AggregateExceeded
        | StagingError::ControlSlotsExhausted => Some(Code::AdmissionBusy),
        StagingError::InputWindowExpired => Some(Code::PayloadTransferTimeout),
        // The initial control deadline after step 6 (item P1), and every
        // I/O failure after step 6.
        _ => Some(Code::SandboxUnavailable),
    }
}

/// How far one output transfer got.
#[derive(Debug, Eq, PartialEq)]
enum Transfer {
    /// Every output record was written.
    Complete,
    /// The window ran out: the transfer as far as it got, `None` when a time
    /// of it could not be read.
    TimedOut(Option<TransferRecord>),
    /// The connection failed otherwise.
    Broken,
}

/// The payload bytes one output SBC1 record carries.
fn payload_length(record: &[u8]) -> u64 {
    SandboxPayloadChunk::from_canonical_cbor(record).map_or(0, |chunk| chunk.bytes.len() as u64)
}

/// One frame, written whole or not at all as far as the caller cares.
fn write_frame(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    u32::try_from(bytes.len())
        .map_err(io::Error::other)
        .and_then(|length| writer.write_all(&length.to_be_bytes()))
        .and_then(|()| writer.write_all(bytes))
}

/// Write the output `records`, which carry `expected` payload bytes, to
/// `stream` within `window` from now; `clock` reads `CLOCK_MONOTONIC`.
fn transfer_output(
    stream: &UnixStream,
    records: &[Vec<u8>],
    (expected, window): (u64, Duration),
    clock: fn() -> io::Result<u64>,
) -> Transfer {
    let started = Instant::now();
    let start = clock().ok();
    let mut writer = Deadlined::until(stream, started + window);
    let mut accepted = 0;
    for record in records {
        match write_frame(&mut writer, record) {
            Ok(()) => accepted += payload_length(record),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                let window = u64::try_from(window.as_nanos()).unwrap_or(u64::MAX);
                return Transfer::TimedOut(start.zip(clock().ok()).map(|(start, finish)| {
                    TransferRecord {
                        start,
                        deadline: start.saturating_add(window),
                        finish,
                        expected_bytes: expected,
                        accepted_bytes: accepted,
                        complete: false,
                    }
                }));
            }
            Err(_) => return Transfer::Broken,
        }
    }
    Transfer::Complete
}

impl Responder<'_> {
    /// Serve an answered connection of an `Open` runtime through `port`,
    /// holding its answered `place`.
    pub(super) fn serve_port(
        &self,
        port: &ExecutePort,
        stream: UnixStream,
        place: Option<Place<'_>>,
    ) {
        // Serving's peer check already passed on this socket, whose
        // `SO_PEERCRED` is fixed at connect: the reader takes only its
        // root-peer value, so this check cannot fail where that one passed.
        if let Ok(peer) = ExecutePeer::authenticate(stream) {
            match ExecuteSource::read(peer, &port.ledger, self.admitted) {
                Ok(source) => self.execute(port, source),
                Err(SourceRefusal::Malformed(stream)) => {
                    Self::conclude(&stream, self.refuse(Refusal::UNIDENTIFIED));
                }
                Err(SourceRefusal::Uncharged(handed)) => self.serve_handoff(handed),
                Err(SourceRefusal::NotExecute(other)) => self.answer_other(other, place),
            }
        }
    }

    /// Another operation on the execute socket: its first record, then the
    /// rest of the request up to its EOF, under the unchanged deadline. A
    /// cancel or reconcile is handed, with its answered `place`, to the
    /// control pool.
    fn answer_other(&self, other: OtherRequest, place: Option<Place<'_>>) {
        let (stream, first, until) = other.into_parts();
        let classified = self.classify_single(&first);
        io::copy(&mut Deadlined::until(&stream, until), &mut io::sink()).ok();
        match classified {
            Ok(Classified {
                identity,
                control: Some(control),
            }) => self.answer_control(&stream, (identity, control), until, place),
            Ok(Classified { identity, .. }) => {
                Self::conclude(&stream, self.answer_identity(identity));
            }
            Err(refusal) => Self::conclude(&stream, self.refuse(refusal)),
        }
    }

    /// A connection whose source charge the ledger refused, waiting for an
    /// uncharged reader ahead of any new read (item P7), then read to the
    /// end of its source for its code: a step failure's, the join of an
    /// exact repeat, or `12` (`14` for a closed ledger).
    fn serve_handoff(&self, handed: UnchargedSource) {
        let until = handed.deadline();
        let Some(permit) = self.refusals.wait(until) else {
            return self.unserved(&handed.into_stream());
        };
        let closed = handed.closed();
        let (stream, frames) = handed.read_rest();
        drop(permit);
        let classified = frames.map_or(Err(Refusal::UNIDENTIFIED), |frames| {
            self.classify_records(&frames.evaluation, Ok(&frames.request))
        });
        match classified {
            Ok(identity) => self.answer_busy(&stream, identity, until, closed),
            Err(refusal) => Self::conclude(&stream, self.refuse(refusal)),
        }
    }

    /// Steps 2 to 6, the admission-state check, port step J, then the
    /// factory and the grant.
    fn execute(&self, port: &ExecutePort, source: ExecuteSource) {
        let identity = match self.classify_records(source.evaluation(), Ok(source.request())) {
            Ok(identity) => identity,
            Err(refusal) => return Self::conclude(&source.into_stream(), self.refuse(refusal)),
        };
        // In `Revoked` the connection closes with zero bytes (R11 §7.1).
        if self.revocation.observer().revoked() {
            return;
        }
        if self.open_port().is_none() {
            return Self::conclude(
                &source.into_stream(),
                self.authenticated(identity, SandboxProviderErrorCode::SandboxUnavailable),
            );
        }
        let until = source.deadline();
        match Self::join(port, identity, until) {
            Join::Fresh => self.admit(port, source, identity),
            Join::Answer(answer) => self.reply(port, &source.into_stream(), identity, answer),
        }
    }

    /// Port step J for `identity`, waiting until `until`.
    pub(super) fn join(port: &ExecutePort, identity: RequestIdentity, until: Instant) -> Join {
        let attempt_id = identity.attempt_id.unwrap_or_default();
        match port.join_until(attempt_id, identity.request_digest, until) {
            // The repeat's own initial control deadline passed while it
            // waited: the provider's delay, not the request's (item P1).
            None => Join::Answer(Answer::Refused(
                SandboxProviderErrorCode::SandboxUnavailable,
            )),
            Some(Ok(None)) => Join::Fresh,
            Some(Ok(Some(response))) => Join::Answer(Answer::Replay(response)),
            Some(Err(error)) => Join::Answer(lifecycle_answer(&error)),
        }
    }

    /// Reply to an exchange that is not admitted afresh.
    pub(super) fn reply(
        &self,
        port: &ExecutePort,
        stream: &UnixStream,
        identity: RequestIdentity,
        answer: Answer,
    ) {
        match answer {
            Answer::Replay(response) => self.deliver(port, stream, identity, &response, false),
            Answer::Refused(code) => Self::conclude(stream, self.authenticated(identity, code)),
            Answer::Silent => {}
        }
    }

    /// The answer of a source, admission or staging refusal before AGR1:
    /// its §7.5 SPE1, or nothing after a signing fault, which closes execute
    /// admission (R9 §5).
    fn staging_answer(port: &ExecutePort, error: &StagingError) -> Answer {
        staging_code(error).map_or_else(
            || {
                port.close();
                Answer::Silent
            },
            Answer::Refused,
        )
    }

    /// Answer a refusal of the factory or the grant.
    fn refused(
        &self,
        port: &ExecutePort,
        identity: RequestIdentity,
        refusal: ExecuteRefusal<AttemptLifecycleError>,
    ) {
        let (stream, cause) = refusal.into_parts();
        let answer = match cause {
            RefusalCause::Staging(error) => Self::staging_answer(port, &error),
            RefusalCause::Claim(error) => lifecycle_answer(&error),
        };
        self.reply(port, &stream, identity, answer);
    }

    /// Port steps 7 to W, then the input and the attempt.
    fn admit(&self, port: &ExecutePort, source: ExecuteSource, identity: RequestIdentity) {
        let prepared =
            match PreparedProviderExecution::admit(source, &port.ledger, self.admitted, |request| {
                port.lifecycle.claim(
                    request.attempt_id,
                    request.request.request_id,
                    request.request_digest,
                )
            }) {
                Ok(prepared) => prepared,
                Err(refusal) => return self.refused(port, identity, *refusal),
            };
        let staged = match port
            .staging
            .create_input(prepared.request().attempt_id, prepared)
        {
            Ok(staged) => staged,
            Err(refusal) => {
                let (stream, RefusalCause::Staging(error)) = refusal.into_parts();
                let answer = Self::staging_answer(port, &error);
                return self.reply(port, &stream, identity, answer);
            }
        };
        let key = self.key();
        let granted = staged.send_grant(
            |record| sign_verified(&**self.signer, key, record),
            |claim: ExchangeClaim<'_>, digest| claim.convert(digest),
        );
        let (write, granted) = match granted {
            Ok(granted) => granted,
            Err(GrantFailure::Refused(refusal)) => return self.refused(port, identity, *refusal),
            // The AGR1 write began: no byte follows (base §4).
            Err(GrantFailure::Interrupted(_)) => return,
        };
        let interrupted = granted.interrupted();
        let awaited = write.written(Box::new(move || interrupted), &**self.signer, key);
        let (received, stream) = granted.receive();
        let response = match received {
            Ok(verified) => {
                let plan = mode_plan(verified.entry().grant());
                awaited
                    .admit(verified)
                    .and_then(|owned| port.run(owned, plan, self.signer, key))
            }
            Err(failed) => awaited
                .record_failed_input(&failed)
                .and_then(|ended| port.lifecycle.retain_response(ended, &**self.signer, key)),
        };
        // After AGR1 every refusal is a provider fault, never a silent
        // request failure (R11 §7.5): `admit` and `record_failed_input`
        // refuse only an input of another attempt or AGR1, which ends the
        // awaited attempt faulted and quarantines the lifecycle, and a fence
        // or cancellation since the conversion never refuses them (item
        // P8). `retain_response` refuses a response that cannot be
        // assembled or signed, which quarantines the lifecycle, or an
        // attempt this exchange no longer holds under its AGR1 (unknown or
        // mismatched), a provider bug that stores nothing. No response
        // exists to write: nothing is emitted (R9 §5).
        response
            .inspect_err(|error| {
                // DIAGNOSTIC: why no response exists after AGR1.
                std::io::Write::write_fmt(
                    &mut io::stderr(),
                    format_args!("pos-sandboxd diag: no response after AGR1: {error:?}\n"),
                )
                .ok();
            })
            .inspect(|response| self.deliver(port, &stream, identity, response, true))
            .ok();
    }

    /// Write the stored full response (ADR-069 §4), less the AGR1 this
    /// connection already received when `granted`: the SAU1 chain and SPR1,
    /// the output records within the ELM1 ID 16 window, then SPY1. An output
    /// transfer that times out re-issues the response (R9 §4.7) and ends the
    /// connection.
    fn deliver(
        &self,
        port: &ExecutePort,
        stream: &UnixStream,
        identity: RequestIdentity,
        response: &Arc<RetainedResponse>,
        granted: bool,
    ) {
        let window =
            Duration::from_millis(response.grant().effective_limits()[TRANSFER_WINDOW_ID].value);
        self.deliver_within(
            port,
            stream,
            (identity, response),
            granted,
            |stream, records, expected| {
                transfer_output(
                    stream,
                    records,
                    (expected, window),
                    crate::launcher::clock::monotonic_ns,
                )
            },
        );
    }

    /// [`Self::deliver`] with the output `transfer` of the records, which
    /// carry the given payload bytes, to the stream.
    ///
    /// SPY1 is written only once the lifecycle recorded this response as
    /// delivered, which no re-issue may then replace; a response replaced
    /// meanwhile gets no SPY1 on this connection (base §4).
    fn deliver_within(
        &self,
        port: &ExecutePort,
        stream: &UnixStream,
        (identity, response): (RequestIdentity, &Arc<RetainedResponse>),
        granted: bool,
        transfer: impl FnOnce(&UnixStream, &[Vec<u8>], u64) -> Transfer,
    ) {
        let attempt_id = identity.attempt_id.unwrap_or_default();
        let frames: Vec<&[u8]> = response.frames().collect();
        let (outputs, expected) = response.output();
        let result = frames.len() - 1;
        let head = &frames[usize::from(granted)..result - outputs.len()];
        let mut writing = Deadlined::new(stream, RESPONSE_DEADLINE);
        let written = head
            .iter()
            .try_for_each(|frame| write_frame(&mut writing, frame))
            .is_ok();
        let transferred = written.then(|| transfer(stream, outputs, expected));
        match transferred {
            Some(Transfer::Complete) => {
                if port.lifecycle.claim_delivery(attempt_id, response) {
                    write_frame(
                        &mut Deadlined::new(stream, RESPONSE_DEADLINE),
                        frames[result],
                    )
                    .ok();
                } else {
                    writeln!(
                        io::stderr(),
                        "pos-sandboxd: an output transfer completed after its response was re-issued; the connection ends without SPY1"
                    )
                    .ok();
                }
            }
            // No byte of SPY1 was written here: this connection's own
            // response may be re-issued, unless another connection or an
            // SCY1 delivered it, or it was re-issued already.
            Some(Transfer::TimedOut(record)) => {
                port.lifecycle
                    .reissue_response(attempt_id, response, record, &**self.signer, self.key())
                    .ok();
            }
            Some(Transfer::Broken) | None => {}
        }
        close_answered(stream);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
