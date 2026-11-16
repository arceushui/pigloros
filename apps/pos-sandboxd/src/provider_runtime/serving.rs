//! Serving both bound endpoints while the runtime is `Starting`, `Open` or
//! `ReconcileFailed` (ADR-069 R11 §6 steps 5 to 7, §7.1, §7.2 and §7.4).
//!
//! One acceptor polls both listeners. Before every accept it checks both
//! endpoints, and after it the accepted one; a failed check closes both
//! listeners for the life of the process. Every connection is dropped with
//! zero bytes read and written unless its `SO_PEERCRED` UID is 0.
//!
//! Each execute-socket connection gets one worker thread. At most
//! `min(BHC1 limit 13, 256)` are answered at once. A connection that
//! arrives while all of them are busy, or every connection when that bound
//! is 0, is accepted and refused with SPE1 `12 AdmissionBusy` (owner
//! decision, Redmine #1358 journal 22582). An SPE1 `12` binds the
//! authenticated request, so the refusing worker first reads it under the
//! same rules; at most `max(bound, 1)` such refusals run at once, and the
//! execute listener is not polled while they are all busy.
//!
//! On the execute socket the request first passes validation precedence
//! steps 1 to 6 under the initial control deadline (BHC1 limit 16), each
//! failure with that step's SPE1 code. An expired deadline is a step 1
//! failure (journal 22582). Then `describe` gets the SDY1 of the startup
//! authority in every state. Execute gets SPE1 `11 SandboxUnavailable` in
//! every state: no execute port is composed yet (R11 §7.3, #443). Cancel and
//! reconcile get SPE1 `11` while the runtime is `Starting` or
//! `ReconcileFailed`, and SPE1 `15 UnknownAttempt` once it is `Open`:
//! without an execute port no attempt can enter this runtime, so every
//! attempt is unknown (R11 §10 invariant 15). Whatever the request
//! left unread is read first, so the peer sees the answer and a clean EOF.
//! Each record is signed by the runtime key, verified before emission,
//! written under its own short deadline and followed by server write EOF.
//!
//! The control socket's RCC1/RCU1 responder is not composed yet (R11 §15
//! slice 5): a root control connection is closed with zero bytes read and
//! written, which is the responder's own answer to every exchange it does
//! not acknowledge (R11 §8.4).
//!
//! There is no SIGTERM handler (journal 22582): the leaves of a killed
//! runtime are removed by the selector (R11 §5.0 step 3), and the endpoints
//! remove their own leaves when serving ends on a listener-invariant failure.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::OnceLock;
use std::thread::{self, Scope, ScopedJoinHandle};
use std::time::{Duration, Instant};

use pos_reference::control_framing;
use pos_reference::evaluator_protocol::{EvaluationRequest, ProtocolError};
use pos_reference::sandbox_provider_protocol::{
    RequestAuthority, SandboxCancelRequest, SandboxDescribeRequest, SandboxDescribeResponse,
    SandboxDescribeResponseFields, SandboxExecuteRequest, SandboxProviderError,
    SandboxProviderErrorCode, SandboxProviderErrorFields, SandboxProviderProtocolError,
    SandboxReconcileRequest,
};
use pos_reference::selector::installation::authority::AdmittedSelectorProvider;
use rustix::event::{poll, PollFd, PollFlags, Timespec};

use super::endpoint::ProviderEndpoint;
use super::{unavailable, AdmissionState, ProviderRuntimeError};
use crate::{sign_verified, AdmittedRuntimeKey, KeyFileRuntimeSigner, RuntimeSignerError};

/// The framing bound of every provider record (ADR-069 §4).
const FRAME_LIMIT: usize = 16 * 1024 * 1024;
/// The BHC1 limit that bounds the initial control deadline, in ms.
const CONTROL_DEADLINE_LIMIT_ID: usize = 16;
/// The response's own write deadline, which starts when the answer is
/// ready, so a request that used up its deadline is still answered.
const RESPONSE_DEADLINE: Duration = Duration::from_secs(1);
/// How long the acceptor waits before it accepts again after an accept
/// that produced no connection (such as `EMFILE`), and before it rechecks a
/// full refusal pool.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(10);
const RECHECK: Timespec = Timespec {
    tv_sec: 0,
    tv_nsec: 10_000_000,
};

/// The SPE1 operation codes.
const DESCRIBE: u8 = 0;
const EXECUTE: u8 = 1;
const CANCEL: u8 = 2;
const RECONCILE: u8 = 3;

/// The SPE1 code of the validation precedence step (R11 §7.2) that a
/// provider-protocol request failed.
const fn request_step(error: SandboxProviderProtocolError) -> SandboxProviderErrorCode {
    match error {
        SandboxProviderProtocolError::InvalidEncoding => SandboxProviderErrorCode::InvalidEncoding,
        SandboxProviderProtocolError::UnsupportedVersion => {
            SandboxProviderErrorCode::UnsupportedVersion
        }
        // Fields that must agree are bounded fields of one record (journal
        // 22582).
        SandboxProviderProtocolError::FieldOutOfBounds
        | SandboxProviderProtocolError::InconsistentFields => {
            SandboxProviderErrorCode::FieldOutOfBounds
        }
        SandboxProviderProtocolError::NonCanonicalOrder => {
            SandboxProviderErrorCode::NonCanonicalOrder
        }
        // Step 5 checks self-digests and signatures. A request carries no
        // signature, so its decoder never reports one invalid.
        SandboxProviderProtocolError::DigestMismatch
        | SandboxProviderProtocolError::SignatureInvalid => {
            SandboxProviderErrorCode::DigestMismatch
        }
    }
}

/// The SPE1 code of the precedence step the EVR1 source record failed.
/// EVR1 holds no set-like field, so its decoder never reports an order
/// failure; were it to, that is the record's encoding.
const fn evaluation_step(error: ProtocolError) -> SandboxProviderErrorCode {
    match error {
        ProtocolError::InvalidEncoding | ProtocolError::NonCanonicalOrder => {
            SandboxProviderErrorCode::InvalidEncoding
        }
        ProtocolError::UnsupportedVersion => SandboxProviderErrorCode::UnsupportedVersion,
        ProtocolError::FieldOutOfBounds => SandboxProviderErrorCode::FieldOutOfBounds,
        ProtocolError::DigestMismatch => SandboxProviderErrorCode::DigestMismatch,
    }
}

/// The authenticated identities a refusal after step 5 binds.
#[derive(Clone, Copy, Debug)]
struct RequestIdentity {
    operation: u8,
    request_id: [u8; 16],
    request_digest: [u8; 32],
    attempt_id: Option<[u8; 16]>,
}

/// Why a request gets an SPE1, and which identities it binds.
#[derive(Clone, Copy, Debug)]
enum Refusal {
    /// Steps 1 to 5: the request is not a valid record. Its operation is
    /// known only once its magic was read (step 2).
    Invalid {
        operation: Option<u8>,
        code: SandboxProviderErrorCode,
    },
    /// Step 6 and later: the request is authenticated.
    Authenticated {
        identity: RequestIdentity,
        code: SandboxProviderErrorCode,
    },
}

impl Refusal {
    /// A record whose operation cannot be identified, including one whose
    /// magic names no operation: SPE1 cannot encode code 1 without an
    /// operation (journal 22582).
    const UNIDENTIFIED: Self = Self::Invalid {
        operation: None,
        code: SandboxProviderErrorCode::InvalidEncoding,
    };

    /// A record of `operation` that failed the step with `code`. A step 1
    /// failure names no operation: the magic is read only after it.
    fn invalid(operation: u8, code: SandboxProviderErrorCode) -> Self {
        Self::Invalid {
            operation: (code != SandboxProviderErrorCode::InvalidEncoding).then_some(operation),
            code,
        }
    }
}

/// Whether a connection is answered or refused for capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Admission {
    /// One of the `min(BHC1 13, 256)` answered connections.
    Answered,
    /// Beyond them: SPE1 `12` after precedence steps 1 to 6.
    Busy,
}

/// The live workers of one acceptor.
struct Workers<'scope> {
    answered: Vec<ScopedJoinHandle<'scope, ()>>,
    refusing: Vec<ScopedJoinHandle<'scope, ()>>,
}

/// The startup authority that answers requests, its one signer, and the
/// admission state restart reconciliation sets (unset while `Starting`).
pub(super) struct Responder<'a> {
    admitted: &'a AdmittedSelectorProvider,
    signer: &'a KeyFileRuntimeSigner,
    admission: &'a OnceLock<AdmissionState>,
}

impl<'a> Responder<'a> {
    pub(super) const fn new(
        admitted: &'a AdmittedSelectorProvider,
        signer: &'a KeyFileRuntimeSigner,
        admission: &'a OnceLock<AdmissionState>,
    ) -> Self {
        Self {
            admitted,
            signer,
            admission,
        }
    }

    /// Serve `execute` and `control` until a listener invariant fails,
    /// answering at most `pool` execute connections at once.
    pub(super) fn serve(
        &self,
        execute: &ProviderEndpoint,
        control: &ProviderEndpoint,
        pool: usize,
    ) -> ProviderRuntimeError {
        thread::scope(|scope| {
            let mut workers = Workers {
                answered: Vec::new(),
                refusing: Vec::new(),
            };
            loop {
                if let Err(error) = self.serve_once(scope, &mut workers, execute, control, pool) {
                    break error;
                }
            }
        })
    }

    fn serve_once<'scope>(
        &'scope self,
        scope: &'scope Scope<'scope, '_>,
        workers: &mut Workers<'scope>,
        execute: &ProviderEndpoint,
        control: &ProviderEndpoint,
        pool: usize,
    ) -> Result<(), ProviderRuntimeError> {
        workers.answered.retain(|worker| !worker.is_finished());
        workers.refusing.retain(|worker| !worker.is_finished());
        // While every answered and every refusing slot is busy the execute
        // listener is not polled; the control listener and both endpoint
        // checks still are.
        let accepting = workers.answered.len() < pool || workers.refusing.len() < pool.max(1);
        let mut ready = [
            PollFd::new(control.listener(), PollFlags::IN),
            PollFd::new(
                execute.listener(),
                if accepting {
                    PollFlags::IN
                } else {
                    PollFlags::empty()
                },
            ),
        ];
        poll(&mut ready, (!accepting).then_some(&RECHECK))
            .map_err(unavailable)
            .map(|_| {
                (
                    !ready[0].revents().is_empty(),
                    accepting && !ready[1].revents().is_empty(),
                )
            })
            .and_then(|readiness| {
                execute
                    .verify()
                    .and_then(|()| control.verify())
                    .map(|()| readiness)
            })
            .and_then(|(control_ready, execute_ready)| {
                // A control connection is dropped unread and unanswered
                // (module docs).
                control_ready
                    .then(|| control.accept())
                    .transpose()
                    .map(|control_accepted| {
                        control_accepted.is_some_and(|accepted| accepted.is_none())
                    })
                    .and_then(|control_missed| {
                        execute_ready
                            .then(|| execute.accept())
                            .transpose()
                            .map(|accepted| (control_missed, execute_ready, accepted.flatten()))
                    })
            })
            .map(|(control_missed, execute_ready, accepted)| {
                // An accept that produced nothing (such as `EMFILE`) backs
                // off briefly instead of spinning on a listener that stays
                // readable.
                let missed = control_missed || (execute_ready && accepted.is_none());
                thread::sleep(ACCEPT_BACKOFF * u32::from(missed));
                let admission = if workers.answered.len() < pool {
                    Admission::Answered
                } else {
                    Admission::Busy
                };
                // A worker that cannot be spawned drops its connection.
                let spawned = accepted.and_then(|stream| {
                    thread::Builder::new()
                        .spawn_scoped(scope, move || self.answer(&stream, admission))
                        .ok()
                });
                match admission {
                    Admission::Answered => workers.answered.extend(spawned),
                    Admission::Busy => workers.refusing.extend(spawned),
                }
            })
    }

    /// Answer one execute-socket connection, then send server write EOF. A
    /// peer that is not root is dropped with zero bytes read and written.
    fn answer(&self, stream: &UnixStream, admission: Admission) {
        if root_peer(stream) {
            self.answer_root(stream, admission);
        }
    }

    /// Answer a root peer's connection: read it under the initial control
    /// deadline, then write the answer under its own deadline.
    fn answer_root(&self, stream: &UnixStream, admission: Admission) {
        let limits = self.admitted.provider().broker_hard_caps();
        let mut reading = Deadlined::new(
            stream,
            Duration::from_millis(limits[CONTROL_DEADLINE_LIMIT_ID].value),
        );
        let response = match (self.classify(&mut reading), admission) {
            (Ok(identity), Admission::Busy) => self.refuse(Refusal::Authenticated {
                identity,
                code: SandboxProviderErrorCode::AdmissionBusy,
            }),
            (Ok(identity), Admission::Answered) if identity.operation == DESCRIBE => {
                self.describe(identity.request_id)
            }
            (Ok(identity), Admission::Answered) => self.refuse(Refusal::Authenticated {
                identity,
                code: self.closed(identity.operation),
            }),
            (Err(refusal), _) => self.refuse(refusal),
        };
        let mut writing = Deadlined::new(stream, RESPONSE_DEADLINE);
        response
            .and_then(|bytes| control_framing::write_frame(&mut writing, &bytes, FRAME_LIMIT).ok());
        stream.shutdown(std::net::Shutdown::Write).ok();
        // Bytes the peer sends after its request (R11 does not require it to
        // half-close an execute connection) are read until its EOF, so the
        // close cannot reset the connection before the answer is read.
        io::copy(
            &mut Deadlined::new(stream, RESPONSE_DEADLINE),
            &mut io::sink(),
        )
        .ok();
    }

    /// Validation precedence steps 1 to 6: the authenticated identities of
    /// the request, or its refusal. Execute's SPX1 follows its EVR1 and the
    /// selector sends nothing more before AGR1; after any other record the
    /// rest of the request is read up to its EOF.
    fn classify(&self, stream: &mut Deadlined<'_>) -> Result<RequestIdentity, Refusal> {
        match read_record(stream) {
            Ok(first) if record_operation(&first) == Some(EXECUTE) => {
                self.classify_execute(&first, stream)
            }
            first => {
                let classified = first.and_then(|first| self.classify_single(&first));
                io::copy(stream, &mut io::sink()).ok();
                classified
            }
        }
    }

    /// Describe, cancel, reconcile, or a record that names none of them.
    fn classify_single(&self, first: &[u8]) -> Result<RequestIdentity, Refusal> {
        match record_operation(first) {
            Some(DESCRIBE) => SandboxDescribeRequest::from_canonical_cbor(first)
                .map_err(|error| Refusal::invalid(DESCRIBE, request_step(error)))
                .and_then(|request| {
                    self.authorize(
                        &request.request,
                        true,
                        RequestIdentity {
                            operation: DESCRIBE,
                            request_id: request.request.request_id,
                            request_digest: request.request_digest,
                            attempt_id: None,
                        },
                    )
                }),
            Some(CANCEL) => SandboxCancelRequest::from_canonical_cbor(first)
                .map_err(|error| Refusal::invalid(CANCEL, request_step(error)))
                .and_then(|request| {
                    self.authorize(
                        &request.request,
                        true,
                        RequestIdentity {
                            operation: CANCEL,
                            request_id: request.request.request_id,
                            request_digest: request.request_digest,
                            attempt_id: Some(request.attempt_id),
                        },
                    )
                }),
            Some(RECONCILE) => SandboxReconcileRequest::from_canonical_cbor(first)
                .map_err(|error| Refusal::invalid(RECONCILE, request_step(error)))
                .and_then(|request| {
                    self.authorize(
                        &request.request,
                        true,
                        RequestIdentity {
                            operation: RECONCILE,
                            request_id: request.request.request_id,
                            request_digest: request.request_digest,
                            attempt_id: Some(request.attempt_id),
                        },
                    )
                }),
            _ => Err(Refusal::UNIDENTIFIED),
        }
    }

    /// Execute: EVR1, then SPX1, both under the same deadline. An invalid
    /// EVR1 still has its SPX1 read, so nothing the selector sent is left.
    fn classify_execute(
        &self,
        evaluation: &[u8],
        stream: &mut Deadlined<'_>,
    ) -> Result<RequestIdentity, Refusal> {
        let evaluation = EvaluationRequest::from_canonical_cbor(evaluation)
            .map_err(|error| Refusal::invalid(EXECUTE, evaluation_step(error)));
        let request = read_record(stream);
        evaluation
            .and(request)
            .and_then(|bytes| {
                SandboxExecuteRequest::from_canonical_cbor(&bytes)
                    .map_err(|error| Refusal::invalid(EXECUTE, request_step(error)))
            })
            .and_then(|request| {
                let installed = self.admitted.bootstrap().installed().manifest();
                let authority = &request.authority;
                let current = installed.authority_digests()
                    == [
                        authority.trs1_digest,
                        authority.rvs1_digest,
                        authority.apt1_digest,
                    ];
                self.authorize(
                    &request.request,
                    current,
                    RequestIdentity {
                        operation: EXECUTE,
                        request_id: request.request.request_id,
                        request_digest: request.request_digest,
                        attempt_id: Some(request.attempt_id),
                    },
                )
            })
    }

    /// Step 6: the request names the retained APT1 and its policy epoch, and
    /// `current` holds for the operation's other authority (execute's TRS1
    /// and RVS1). Any difference is `7 AuthorityMismatch`; serving never
    /// emits `6 TrustRevoked`, which is reserved for revocation found in the
    /// retained authority itself, fixed for the runtime's life (R11 D9,
    /// journal 22582).
    fn authorize(
        &self,
        request: &RequestAuthority,
        current: bool,
        identity: RequestIdentity,
    ) -> Result<RequestIdentity, Refusal> {
        let policy = self.admitted.bootstrap().policy();
        if current
            && request.apt1_digest == policy.policy_digest()
            && request.policy_epoch == policy.policy_epoch()
        {
            Ok(identity)
        } else {
            Err(Refusal::Authenticated {
                identity,
                code: SandboxProviderErrorCode::AuthorityMismatch,
            })
        }
    }

    /// The SPE1 code of an authenticated execute, cancel or reconcile
    /// request (module docs, R11 §7.1).
    fn closed(&self, operation: u8) -> SandboxProviderErrorCode {
        match (self.admission.get(), operation) {
            (Some(AdmissionState::Open { .. }), CANCEL | RECONCILE) => {
                SandboxProviderErrorCode::UnknownAttempt
            }
            _ => SandboxProviderErrorCode::SandboxUnavailable,
        }
    }

    fn key(&self) -> AdmittedRuntimeKey<'_> {
        AdmittedRuntimeKey::new(
            &self
                .admitted
                .provider()
                .manifest()
                .runtime_attestation_key_id,
            self.admitted.provider().runtime_attestation_key(),
        )
    }

    /// The signed SDY1 of the startup authority (R11 §7.4).
    fn describe(&self, request_id: [u8; 16]) -> Option<Vec<u8>> {
        let provider = self.admitted.provider();
        let key = self.key();
        SandboxDescribeResponse::self_digested(SandboxDescribeResponseFields {
            request_id,
            spm1_digest: provider.manifest().manifest_digest,
            provider_binary_digest: provider.manifest().binary_digest,
            hcp1_digest: provider.host_profile().profile_digest,
            active_apt1_digest: self.admitted.bootstrap().policy().policy_digest(),
            runtime_attestation_key_id: provider.manifest().runtime_attestation_key_id.clone(),
        })
        .map_err(RuntimeSignerError::from)
        .and_then(|record| sign_verified(self.signer, key, record))
        .and_then(|verified| {
            SandboxDescribeResponse::new(verified, provider.runtime_attestation_key())
                .map_err(RuntimeSignerError::from)
        })
        .and_then(|response| {
            response
                .to_canonical_cbor()
                .map_err(RuntimeSignerError::from)
        })
        .ok()
    }

    /// The signed SPE1 of `refusal`, with `safe-detail = null` (R11 §7.2).
    fn refuse(&self, refusal: Refusal) -> Option<Vec<u8>> {
        let provider = self.admitted.provider();
        let (operation, identity, code) = match refusal {
            Refusal::Invalid { operation, code } => (operation, None, code),
            Refusal::Authenticated { identity, code } => {
                (Some(identity.operation), Some(identity), code)
            }
        };
        SandboxProviderError::self_digested(SandboxProviderErrorFields {
            operation,
            request_id: identity.map(|identity| identity.request_id),
            request_digest: identity.map(|identity| identity.request_digest),
            attempt_id: identity.and_then(|identity| identity.attempt_id),
            code,
            safe_detail: None,
            runtime_attestation_key_id: provider.manifest().runtime_attestation_key_id.clone(),
        })
        .map_err(RuntimeSignerError::from)
        .and_then(|record| sign_verified(self.signer, self.key(), record))
        .and_then(|verified| {
            SandboxProviderError::new(verified, provider.runtime_attestation_key())
                .map_err(RuntimeSignerError::from)
        })
        .and_then(|error| error.to_canonical_cbor().map_err(RuntimeSignerError::from))
        .ok()
    }
}

/// Whether the `SO_PEERCRED` UID of `stream`'s peer is 0 (R11 §6 step 6).
fn root_peer(stream: &UnixStream) -> bool {
    rustix::net::sockopt::socket_peercred(stream).is_ok_and(|peer| peer.uid.is_root())
}

/// One complete frame, or step 1's refusal.
fn read_record(stream: &mut impl Read) -> Result<Vec<u8>, Refusal> {
    control_framing::read_frame(stream, FRAME_LIMIT)
        .ok()
        .flatten()
        .ok_or(Refusal::UNIDENTIFIED)
}

/// The operation a record's magic names: SDQ1, EVR1 (execute's first
/// source record), SCQ1 or SRQ1. The magic is the first field of a flat
/// record such as EVR1, or of the unsigned prefix of a self-digested one.
fn record_operation(bytes: &[u8]) -> Option<u8> {
    ciborium::from_reader::<ciborium::Value, _>(bytes)
        .ok()
        .and_then(|value| value.into_array().ok())
        .and_then(|fields| fields.into_iter().next())
        .and_then(|first| {
            first
                .into_text()
                .or_else(|prefix| {
                    prefix
                        .into_array()
                        .ok()
                        .and_then(|fields| fields.into_iter().next())
                        .and_then(|magic| magic.into_text().ok())
                        .ok_or(())
                })
                .ok()
        })
        .and_then(|magic| match magic.as_str() {
            "SDQ1" => Some(DESCRIBE),
            "EVR1" => Some(EXECUTE),
            "SCQ1" => Some(CANCEL),
            "SRQ1" => Some(RECONCILE),
            _ => None,
        })
}

/// A stream whose every read and write ends at `until`.
struct Deadlined<'a> {
    stream: &'a UnixStream,
    until: Instant,
}

impl<'a> Deadlined<'a> {
    /// `stream`, ending `duration` from now. A duration too long for the
    /// clock ends at once.
    fn new(stream: &'a UnixStream, duration: Duration) -> Self {
        let now = Instant::now();
        Self {
            stream,
            until: now.checked_add(duration).unwrap_or(now),
        }
    }

    fn remaining(&self) -> io::Result<Duration> {
        self.until
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))
    }
}

impl Read for Deadlined<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.remaining()
            .and_then(|remaining| self.stream.set_read_timeout(Some(remaining)))
            .and_then(|()| {
                let mut stream = self.stream;
                stream.read(buffer)
            })
    }
}

impl Write for Deadlined<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.remaining()
            .and_then(|remaining| self.stream.set_write_timeout(Some(remaining)))
            .and_then(|()| {
                let mut stream = self.stream;
                stream.write(bytes)
            })
    }

    fn flush(&mut self) -> io::Result<()> {
        // A Unix stream has no buffered output.
        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
