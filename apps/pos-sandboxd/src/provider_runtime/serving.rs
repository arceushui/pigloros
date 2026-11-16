//! Serving both bound endpoints while the runtime is `Starting` (ADR-069 R11
//! §6 steps 5 to 7, §7.1, §7.2 and §7.4).
//!
//! One acceptor polls both listeners. Before every accept it checks both
//! endpoints, and after it the accepted one; a failed check closes both
//! listeners for the life of the process. Each execute-socket connection
//! gets one worker thread; at most `min(BHC1 limit 13, 256)` unfinished
//! connections are open at once, and further connections wait in the
//! listen backlog. Every connection is dropped with zero bytes read and
//! written unless its `SO_PEERCRED` UID is 0.
//!
//! On the execute socket the request first passes validation precedence
//! steps 1 to 6 under the initial control deadline (BHC1 limit 16), each
//! failure with that step's SPE1 code. Then `describe` gets the SDY1 of the
//! startup authority, and every other operation SPE1 `11
//! SandboxUnavailable`: restart reconciliation has not opened admission.
//! Each record is signed by the runtime key, verified before emission, and
//! followed by server write EOF.
//!
//! The control socket's RCC1/RCU1 responder is not composed yet (R11 §15
//! slice 5): a root control connection is closed with zero bytes read and
//! written, which is the responder's own answer to every exchange it does
//! not acknowledge (R11 §8.4).

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
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
use rustix::event::{poll, PollFd, PollFlags};

use super::endpoint::ProviderEndpoint;
use super::{unavailable, ProviderRuntimeError};
use crate::{sign_verified, AdmittedRuntimeKey, KeyFileRuntimeSigner, RuntimeSignerError};

/// The framing bound of every provider record (ADR-069 §4).
const FRAME_LIMIT: usize = 16 * 1024 * 1024;
/// The BHC1 limit that bounds the initial control deadline, in ms.
const CONTROL_DEADLINE_LIMIT_ID: usize = 16;

/// The SPE1 operation codes.
const DESCRIBE: u8 = 0;
const EXECUTE: u8 = 1;
const CANCEL: u8 = 2;
const RECONCILE: u8 = 3;

/// Validation precedence steps 1 to 5 (R11 §7.2) for SPE1-family records.
const PROVIDER_RECORD_STEPS: [(SandboxProviderProtocolError, SandboxProviderErrorCode); 7] = [
    (
        SandboxProviderProtocolError::InvalidEncoding,
        SandboxProviderErrorCode::InvalidEncoding,
    ),
    (
        SandboxProviderProtocolError::UnsupportedVersion,
        SandboxProviderErrorCode::UnsupportedVersion,
    ),
    (
        SandboxProviderProtocolError::FieldOutOfBounds,
        SandboxProviderErrorCode::FieldOutOfBounds,
    ),
    // Fields that must agree are bounded fields of one record.
    (
        SandboxProviderProtocolError::InconsistentFields,
        SandboxProviderErrorCode::FieldOutOfBounds,
    ),
    (
        SandboxProviderProtocolError::NonCanonicalOrder,
        SandboxProviderErrorCode::NonCanonicalOrder,
    ),
    (
        SandboxProviderProtocolError::DigestMismatch,
        SandboxProviderErrorCode::DigestMismatch,
    ),
    // A request carries no signature, so this cannot occur (R11 §7.2).
    (
        SandboxProviderProtocolError::SignatureInvalid,
        SandboxProviderErrorCode::SignatureInvalid,
    ),
];

/// Validation precedence steps 1 to 5 for the EVR1 source record.
const EVALUATION_STEPS: [(ProtocolError, SandboxProviderErrorCode); 5] = [
    (
        ProtocolError::InvalidEncoding,
        SandboxProviderErrorCode::InvalidEncoding,
    ),
    (
        ProtocolError::UnsupportedVersion,
        SandboxProviderErrorCode::UnsupportedVersion,
    ),
    (
        ProtocolError::FieldOutOfBounds,
        SandboxProviderErrorCode::FieldOutOfBounds,
    ),
    (
        ProtocolError::NonCanonicalOrder,
        SandboxProviderErrorCode::NonCanonicalOrder,
    ),
    (
        ProtocolError::DigestMismatch,
        SandboxProviderErrorCode::DigestMismatch,
    ),
];

/// The SPE1 code of the precedence step that `error` failed.
fn step_code<E: PartialEq + Copy, const N: usize>(
    error: E,
    steps: [(E, SandboxProviderErrorCode); N],
) -> SandboxProviderErrorCode {
    steps
        .into_iter()
        .find(|(step, _)| *step == error)
        .map_or(SandboxProviderErrorCode::InvalidEncoding, |(_, code)| code)
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
    /// A record whose operation cannot be identified.
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

/// The startup authority that answers requests, and its one signer.
pub(super) struct Responder<'a> {
    admitted: &'a AdmittedSelectorProvider,
    signer: &'a KeyFileRuntimeSigner,
}

impl<'a> Responder<'a> {
    pub(super) const fn new(
        admitted: &'a AdmittedSelectorProvider,
        signer: &'a KeyFileRuntimeSigner,
    ) -> Self {
        Self { admitted, signer }
    }

    /// Serve `execute` and `control` until a listener invariant fails, with
    /// at most `pool` unfinished execute connections.
    pub(super) fn serve(
        &self,
        execute: &ProviderEndpoint,
        control: &ProviderEndpoint,
        pool: usize,
    ) -> ProviderRuntimeError {
        thread::scope(|scope| {
            let mut workers = Vec::new();
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
        workers: &mut Vec<ScopedJoinHandle<'scope, ()>>,
        execute: &ProviderEndpoint,
        control: &ProviderEndpoint,
        pool: usize,
    ) -> Result<(), ProviderRuntimeError> {
        workers.retain(|worker| !worker.is_finished());
        if workers.len() >= pool {
            // Accept nothing more until the oldest connection ends.
            workers.remove(0).join().ok();
            return Ok(());
        }
        let mut ready = [
            PollFd::new(execute.listener(), PollFlags::IN),
            PollFd::new(control.listener(), PollFlags::IN),
        ];
        poll(&mut ready, None)
            .map_err(unavailable)
            .map(|_| {
                (
                    !ready[0].revents().is_empty(),
                    !ready[1].revents().is_empty(),
                )
            })
            .and_then(|readiness| {
                execute
                    .verify()
                    .and_then(|()| control.verify())
                    .map(|()| readiness)
            })
            .and_then(|(execute_ready, control_ready)| {
                // A control connection is dropped unread and unanswered
                // (module docs).
                control_ready
                    .then(|| control.accept())
                    .transpose()
                    .and_then(|_| execute_ready.then(|| execute.accept()).transpose())
            })
            .map(|accepted| {
                workers.extend(
                    accepted
                        .flatten()
                        .map(|stream| scope.spawn(move || self.answer(&stream))),
                );
            })
    }

    /// Answer one execute-socket connection, then send server write EOF. A
    /// peer that is not root is dropped with zero bytes read and written.
    fn answer(&self, stream: &UnixStream) {
        if root_peer(stream) {
            self.answer_root(stream);
        }
    }

    /// Answer a root peer's connection under the initial control deadline.
    fn answer_root(&self, stream: &UnixStream) {
        let limits = self.admitted.provider().broker_hard_caps();
        let now = Instant::now();
        let mut deadlined = Deadlined {
            stream,
            until: now
                .checked_add(Duration::from_millis(
                    limits[CONTROL_DEADLINE_LIMIT_ID].value,
                ))
                .unwrap_or(now),
        };
        let response = match self.classify(&mut deadlined) {
            Ok(request_id) => self.describe(request_id),
            Err(refusal) => self.refuse(refusal),
        };
        response.and_then(|bytes| {
            control_framing::write_frame(&mut deadlined, &bytes, FRAME_LIMIT).ok()
        });
        stream.shutdown(std::net::Shutdown::Write).ok();
    }

    /// Validation precedence steps 1 to 6, then the `Starting` admission
    /// state: the request ID of an admitted `describe`, or the refusal.
    fn classify(&self, stream: &mut impl Read) -> Result<[u8; 16], Refusal> {
        let first = read_record(stream)?;
        match record_operation(&first) {
            Some(DESCRIBE) => SandboxDescribeRequest::from_canonical_cbor(&first)
                .map_err(|error| {
                    Refusal::invalid(DESCRIBE, step_code(error, PROVIDER_RECORD_STEPS))
                })
                .and_then(|request| {
                    let identity = RequestIdentity {
                        operation: DESCRIBE,
                        request_id: request.request.request_id,
                        request_digest: request.request_digest,
                        attempt_id: None,
                    };
                    self.authorize(&request.request, true, identity)
                        .map(|()| request.request.request_id)
                }),
            Some(EXECUTE) => self.classify_execute(&first, stream),
            Some(CANCEL) => SandboxCancelRequest::from_canonical_cbor(&first)
                .map_err(|error| Refusal::invalid(CANCEL, step_code(error, PROVIDER_RECORD_STEPS)))
                .and_then(|request| {
                    self.refuse_attempt_request(
                        &request.request,
                        RequestIdentity {
                            operation: CANCEL,
                            request_id: request.request.request_id,
                            request_digest: request.request_digest,
                            attempt_id: Some(request.attempt_id),
                        },
                    )
                }),
            Some(RECONCILE) => SandboxReconcileRequest::from_canonical_cbor(&first)
                .map_err(|error| {
                    Refusal::invalid(RECONCILE, step_code(error, PROVIDER_RECORD_STEPS))
                })
                .and_then(|request| {
                    self.refuse_attempt_request(
                        &request.request,
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

    /// Execute: EVR1, then SPX1, both under the same deadline.
    fn classify_execute(
        &self,
        evaluation: &[u8],
        stream: &mut impl Read,
    ) -> Result<[u8; 16], Refusal> {
        EvaluationRequest::from_canonical_cbor(evaluation)
            .map_err(|error| Refusal::invalid(EXECUTE, step_code(error, EVALUATION_STEPS)))
            .and_then(|_| read_record(stream))
            .and_then(|bytes| {
                SandboxExecuteRequest::from_canonical_cbor(&bytes).map_err(|error| {
                    Refusal::invalid(EXECUTE, step_code(error, PROVIDER_RECORD_STEPS))
                })
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
                let identity = RequestIdentity {
                    operation: EXECUTE,
                    request_id: request.request.request_id,
                    request_digest: request.request_digest,
                    attempt_id: Some(request.attempt_id),
                };
                self.authorize(&request.request, current, identity).and(Err(
                    Refusal::Authenticated {
                        identity,
                        code: SandboxProviderErrorCode::SandboxUnavailable,
                    },
                ))
            })
    }

    /// Step 6 for a cancel or reconcile request, then its `Starting` refusal.
    fn refuse_attempt_request(
        &self,
        request: &RequestAuthority,
        identity: RequestIdentity,
    ) -> Result<[u8; 16], Refusal> {
        self.authorize(request, true, identity)
            .and(Err(Refusal::Authenticated {
                identity,
                code: SandboxProviderErrorCode::SandboxUnavailable,
            }))
    }

    /// Step 6: the request names the retained APT1 and its policy epoch, and
    /// `current` holds for the operation's other authority.
    fn authorize(
        &self,
        request: &RequestAuthority,
        current: bool,
        identity: RequestIdentity,
    ) -> Result<(), Refusal> {
        let policy = self.admitted.bootstrap().policy();
        if current
            && request.apt1_digest == policy.policy_digest()
            && request.policy_epoch == policy.policy_epoch()
        {
            Ok(())
        } else {
            Err(Refusal::Authenticated {
                identity,
                code: SandboxProviderErrorCode::AuthorityMismatch,
            })
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

impl Deadlined<'_> {
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
