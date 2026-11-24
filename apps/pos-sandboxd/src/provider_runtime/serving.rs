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
//! same rules. Every read the ledger does not charge (refusals, every read
//! while `Starting` or `ReconcileFailed`, and the hand-off of a refused
//! source charge) shares one pool of at most `max(bound, 1)` readers, and a
//! waiting hand-off is served first (R11 Amendment 1, item P7); the
//! execute listener is not polled while the pool has no room, and a refusal
//! is accepted only with its reader place in hand.
//!
//! Serving samples the admission state when it begins reading (R11
//! Amendment 1 §7.5). An answered connection of an `Open` runtime whose
//! execute admission is open is read once, charged, by the execute port
//! (`port`): execute is admitted there in §7.5 order and answered with AGR1
//! and its stored response, or with that table's SPE1. Any other
//! connection is read uncharged and first passes validation precedence
//! steps 1 to 6 under the initial control deadline (BHC1 limit 16), each
//! failure with that step's SPE1 code; an expired deadline is a step 1
//! failure (journal 22582). Then `describe` gets the SDY1 of the startup
//! authority in every state. Execute read uncharged gets SPE1 `11
//! SandboxUnavailable`: the runtime is not `Open`, or its execute admission
//! closed. Whatever the request left unread is read first, so the peer sees
//! the answer and a clean EOF. Each record is signed by the runtime key,
//! verified before emission, written under its own short deadline and
//! followed by server write EOF.
//!
//! Cancel and reconcile are answered from their own control pool of
//! `min(BHC1 13, 256)` places (ADR-069 R15 N13). The operation is known only
//! after the first record: an answered worker or a refusal reader that reads
//! an SCQ1 or SRQ1 hands the connection, at its stream position, to the
//! control pool, which frees its execute worker or reader place; a full
//! control pool gets `12`. After step 6 the admission state is checked
//! again: `Revoked` writes zero bytes, `Starting` and `ReconcileFailed` get
//! `11`, and an `Open` runtime answers from its lifecycle, also once fenced
//! or with execute admission closed (R15 §3.3).
//!
//! A root control connection is answered by the one
//! [`super::RevocationUpdateResponder`] (R11 §8), on the acceptor itself:
//! every exchange ends 100 ms after its accept, its fence included, so the
//! acceptor waits at most that long. Its live attempt state is the
//! lifecycle once the runtime is `Open`. Before that no attempt can exist,
//! so the view is empty. Any exchange closes execute admission for the life
//! of the process (`ExecuteClosed` before the fence, `Fenced` after it,
//! R11 D9). An acknowledged RVS1 that revokes this runtime's key, SPM1 or
//! binary makes it `Revoked`: execute-socket connections are then closed
//! after the peer check with zero bytes written, and the responder signs
//! nothing more but may resend its retained RCA1.
//!
//! There is no SIGTERM handler (journal 22582): the leaves of a killed
//! runtime are removed by the selector (R11 §5.0 step 3), and the endpoints
//! remove their own leaves when serving ends on a listener-invariant failure.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread::{self, Scope};
use std::time::{Duration, Instant};

use pos_reference::control_framing;
use pos_reference::evaluator_protocol::{EvaluationRequest, ProtocolError};
use pos_reference::sandbox_provider_protocol::{
    RequestAuthority, SandboxCancelRequest, SandboxDescribeRequest, SandboxDescribeResponse,
    SandboxDescribeResponseFields, SandboxExecuteRequest, SandboxProviderError,
    SandboxProviderErrorCode, SandboxProviderErrorFields, SandboxProviderProtocolError,
    SandboxReconcileRequest,
};
use pos_reference::sandbox_provider_protocol::{
    SandboxRevocationSnapshot, SandboxTrustRole, SandboxTrustSnapshot,
};
use pos_reference::selector::installation::authority::{
    AdmittedSelectorProvider, AuthorityResolution,
};
use rustix::event::{poll, PollFd, PollFlags, Timespec};

use super::endpoint::ProviderEndpoint;
use super::port::ExecutePort;
use super::refusal_pool::{Place, Places, ReaderPermit, RefusalPool};
use super::{
    unavailable, AdmissionState, ExchangeObserver, ExchangeOutcome, LiveAttempts,
    ProviderRuntimeError, RevocationUpdateResponder,
};
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

/// The only UID whose connections either socket answers (R11 §6 step 6).
const ROOT_UID: u32 = 0;

/// The control-socket exchange bound from accept (R11 §8.3 step 1).
const CONTROL_EXCHANGE: Duration = Duration::from_millis(100);

/// The control states, in the only order they advance (R11 §7.1, §8.4).
const LIVE: u8 = 0;
const EXECUTE_CLOSED: u8 = 1;
const FENCED: u8 = 2;
const REVOKED: u8 = 3;

/// The end of a control exchange `accepted` at that instant.
pub(super) fn exchange_deadline(accepted: Instant) -> Instant {
    accepted + CONTROL_EXCHANGE
}

/// The live runtime's control state (R11 §7.1, §8.4). It only advances:
/// `Live`, `ExecuteClosed` once an exchange began, `Fenced` once one
/// reached the fence, and `Revoked` once an acknowledged RVS1 revokes this
/// runtime's key, SPM1 or binary. Execute admission is open only while it
/// is `Live`.
#[derive(Debug)]
struct ControlState<'a> {
    state: AtomicU8,
    admitted: &'a AdmittedSelectorProvider,
}

impl ControlState<'_> {
    fn advance(&self, state: u8) {
        self.state.fetch_max(state, Ordering::AcqRel);
    }

    /// Whether no control exchange began: execute admission may be open.
    fn live(&self) -> bool {
        self.state.load(Ordering::Acquire) == LIVE
    }

    fn revoked(&self) -> bool {
        self.state.load(Ordering::Acquire) == REVOKED
    }
}

impl ExchangeObserver for ControlState<'_> {
    fn fencing(&self) {
        self.advance(FENCED);
    }

    fn acknowledging(&self, trust: &SandboxTrustSnapshot, next: &SandboxRevocationSnapshot) {
        let manifest = self.admitted.provider().manifest();
        let revoked = next.provider_revoked(&manifest.manifest_digest)
            || next.provider_revoked(&manifest.binary_digest)
            || next
                .active_key(
                    trust,
                    &manifest.runtime_attestation_key_id,
                    SandboxTrustRole::ProviderRuntimeAttestation,
                )
                .is_err();
        self.advance(if revoked { REVOKED } else { FENCED });
    }
}

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

/// An authenticated cancel or reconcile request, for the control pool.
#[derive(Debug)]
enum Control {
    Cancel(SandboxCancelRequest),
    Reconcile(SandboxReconcileRequest),
}

/// A request that passed steps 1 to 6: its identities, and the decoded
/// request of a cancel or reconcile.
#[derive(Debug)]
struct Classified {
    identity: RequestIdentity,
    control: Option<Control>,
}

impl From<RequestIdentity> for Classified {
    fn from(identity: RequestIdentity) -> Self {
        Self {
            identity,
            control: None,
        }
    }
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

/// The startup authority that answers requests, its one signer, the
/// admission state restart reconciliation sets (unset while `Starting`),
/// the revocation responder and the control state it leaves, the one peer
/// UID both sockets answer, the answered-pool bound and the pool of
/// uncharged readers.
pub(super) struct Responder<'a> {
    admitted: &'a Arc<AdmittedSelectorProvider>,
    signer: &'a Arc<KeyFileRuntimeSigner>,
    admission: &'a OnceLock<AdmissionState>,
    revocation:
        RevocationUpdateResponder<'a, KeyFileRuntimeSigner, LiveAttempts<'a>, ControlState<'a>>,
    peer_uid: u32,
    /// The answered execute workers, at most `min(BHC1 13, 256)`.
    answered: Places,
    /// The control pool that answers cancel and reconcile, of the same
    /// bound (R15 N13).
    control: Places,
    refusals: RefusalPool,
    /// The joins of exact repeats beyond the answered pool (item P10): at
    /// most `max(pool, 1)` wait and deliver at once, so a busy connection's
    /// thread stays bounded like an uncharged read's (item P7).
    joins: RefusalPool,
}

impl<'a> Responder<'a> {
    /// The responder of the startup authority `admitted` and its `signer`
    /// over `admission`, answering at most `pool` execute connections at
    /// once.
    pub(super) fn new(
        admitted: &'a Arc<AdmittedSelectorProvider>,
        signer: &'a Arc<KeyFileRuntimeSigner>,
        admission: &'a OnceLock<AdmissionState>,
        pool: usize,
    ) -> Self {
        let provider = admitted.provider();
        Self {
            admitted,
            signer,
            admission,
            revocation: RevocationUpdateResponder::new(
                signer,
                AdmittedRuntimeKey::new(
                    provider.manifest().runtime_attestation_key_id.as_str(),
                    provider.runtime_attestation_key(),
                ),
                AuthorityResolution::Live {
                    retained_revocation_digest: admitted.bootstrap().revocation().snapshot_digest(),
                },
                LiveAttempts(admission),
                ControlState {
                    state: AtomicU8::new(LIVE),
                    admitted,
                },
            ),
            peer_uid: ROOT_UID,
            answered: Places::new(pool),
            control: Places::new(pool),
            refusals: RefusalPool::new(pool),
            joins: RefusalPool::new(pool),
        }
    }

    /// Serve `execute` and `control` until a listener invariant fails.
    pub(super) fn serve(
        &self,
        execute: &ProviderEndpoint,
        control: &ProviderEndpoint,
    ) -> ProviderRuntimeError {
        thread::scope(|scope| loop {
            if let Err(error) = self.serve_once(scope, execute, control) {
                break error;
            }
        })
    }

    fn serve_once<'scope>(
        &'scope self,
        scope: &'scope Scope<'scope, '_>,
        execute: &ProviderEndpoint,
        control: &ProviderEndpoint,
    ) -> Result<(), ProviderRuntimeError> {
        let accepting = accepting(self.answered.has_room(), self.refusals.has_room());
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
            .map(|_| readiness(accepting, ready[0].revents(), ready[1].revents()))
            .and_then(|readiness| {
                execute
                    .verify()
                    .and_then(|()| control.verify())
                    .map(|()| readiness)
            })
            .and_then(|(control_ready, execute_ready)| {
                // A control connection is answered on the acceptor, within
                // its exchange deadline (module docs).
                control_ready
                    .then(|| control.accept())
                    .transpose()
                    .map(|control_accepted| {
                        control_accepted.is_some_and(|accepted| {
                            accepted
                                .as_ref()
                                .map(|stream| self.exchange(stream, Instant::now()))
                                .is_none()
                        })
                    })
                    .map(|control_missed| (control_missed, execute_ready))
            })
            .and_then(|(control_missed, execute_ready)| {
                // An answered place is taken before the accept, so the
                // acceptor never admits more than the pool.
                let place = execute_ready.then(|| self.answered.take()).flatten();
                let admission = if place.is_some() {
                    Admission::Answered
                } else {
                    Admission::Busy
                };
                self.accept_execute(execute, execute_ready, admission)
                    .map(|(accepted, permit)| {
                        (
                            missed(control_missed, execute_ready, accepted.is_some()),
                            admission,
                            (accepted, permit, place),
                        )
                    })
            })
            .map(|(missed, admission, (accepted, permit, place))| {
                thread::sleep(ACCEPT_BACKOFF * u32::from(missed));
                // A worker that cannot be spawned drops its connection and
                // frees its place.
                accepted.and_then(|stream| {
                    thread::Builder::new()
                        .spawn_scoped(scope, move || {
                            self.answer_placed(stream, admission, permit, place);
                        })
                        .ok()
                });
            })
    }

    /// Accept a `ready` execute connection of `admission`. A refusal is
    /// accepted only with its uncharged reader place in hand, so it never
    /// waits behind a connection accepted before it; with no place nothing
    /// is accepted, and the acceptor backs off and polls again.
    fn accept_execute(
        &self,
        execute: &ProviderEndpoint,
        ready: bool,
        admission: Admission,
    ) -> Result<(Option<UnixStream>, Option<ReaderPermit<'_>>), ProviderRuntimeError> {
        ready
            .then(|| {
                let permit = (admission == Admission::Busy)
                    .then(|| self.refusals.wait(Instant::now()))
                    .flatten();
                (admission == Admission::Answered || permit.is_some())
                    .then(|| execute.accept())
                    .transpose()
                    .map(|accepted| (accepted.flatten(), permit))
            })
            .transpose()
            .map(Option::unwrap_or_default)
    }

    /// Answer one execute-socket connection holding no answered place.
    #[cfg(test)]
    fn answer(&self, stream: UnixStream, admission: Admission, permit: Option<ReaderPermit<'_>>) {
        self.answer_placed(stream, admission, permit, None);
    }

    /// Answer one execute-socket connection, holding its answered `place`
    /// until it is answered or handed to the control pool, then send server
    /// write EOF. A peer that is not root is dropped with zero bytes read
    /// and written; so is every peer once the runtime is `Revoked`, after
    /// the peer check.
    fn answer_placed(
        &self,
        stream: UnixStream,
        admission: Admission,
        permit: Option<ReaderPermit<'_>>,
        place: Option<Place<'_>>,
    ) {
        if self.answers(&stream) {
            self.answer_root(stream, admission, (permit, place));
        }
    }

    /// Whether an execute-socket peer gets an answer: it is root, checked
    /// first, and the runtime is not `Revoked`.
    fn answers(&self, stream: &UnixStream) -> bool {
        trusted_peer(stream, self.peer_uid) && !self.revocation.observer().revoked()
    }

    /// Answer one control-socket connection, `accepted` at that instant,
    /// then send server write EOF once an RCA1 was written. A peer that is
    /// not root is dropped with zero bytes read and written.
    fn exchange(&self, stream: &UnixStream, accepted: Instant) {
        if trusted_peer(stream, self.peer_uid) && self.respond(stream, accepted) {
            stream.shutdown(std::net::Shutdown::Write).ok();
        }
    }

    /// Answer a root peer's control connection through the revocation
    /// responder: whether it acknowledged or resent an RCA1. The exchange
    /// closes execute admission before anything is read; the responder
    /// reports the fence and the acknowledgement before each has an effect.
    fn respond(&self, stream: &UnixStream, accepted: Instant) -> bool {
        self.revocation.observer().advance(EXECUTE_CLOSED);
        let deadline = exchange_deadline(accepted);
        matches!(
            self.revocation
                .respond(&mut Deadlined::until(stream, deadline), deadline),
            ExchangeOutcome::Acknowledged | ExchangeOutcome::Resent
        )
    }

    /// The execute port of an `Open` runtime, whatever its execute
    /// admission and control state: cancel and reconcile are answered from
    /// its lifecycle (R15 §3.3).
    fn opened(&self) -> Option<&ExecutePort> {
        match self.admission.get() {
            Some(AdmissionState::Open(port)) => Some(port),
            _ => None,
        }
    }

    /// The execute port, while the runtime is `Open` with execute admission
    /// still open on it and in the control state.
    fn open_port(&self) -> Option<&ExecutePort> {
        match self.admission.get() {
            Some(AdmissionState::Open(port))
                if port.open() && self.revocation.observer().live() =>
            {
                Some(port)
            }
            _ => None,
        }
    }

    /// Answer a root peer's connection by its admission-state sample (R11
    /// Amendment 1 §7.5): an answered connection of an `Open` runtime with
    /// the port composed is read once, charged, by the port; any other is
    /// read uncharged, as one of the bounded refusal readers.
    fn answer_root(
        &self,
        stream: UnixStream,
        admission: Admission,
        (permit, place): (Option<ReaderPermit<'_>>, Option<Place<'_>>),
    ) {
        match (self.open_port(), admission) {
            (Some(port), Admission::Answered) => self.serve_port(port, stream, place),
            _ => self.answer_uncharged(&stream, admission, (permit, place)),
        }
    }

    /// Read a connection uncharged, under the initial control deadline,
    /// holding an uncharged reader's place (item P7), then write the answer
    /// under its own deadline.
    fn answer_uncharged(
        &self,
        stream: &UnixStream,
        admission: Admission,
        (permit, place): (Option<ReaderPermit<'_>>, Option<Place<'_>>),
    ) {
        let limits = self.admitted.provider().broker_hard_caps();
        let mut reading = Deadlined::new(
            stream,
            Duration::from_millis(limits[CONTROL_DEADLINE_LIMIT_ID].value),
        );
        let until = reading.until;
        let Some(permit) = permit.or_else(|| self.refusals.wait(until)) else {
            return self.unserved(stream);
        };
        let classified = self.classify(&mut reading);
        drop(permit);
        match (classified, admission) {
            (
                Ok(Classified {
                    identity,
                    control: Some(control),
                }),
                _,
            ) => self.answer_control(stream, (identity, control), until, place),
            (Ok(Classified { identity, .. }), Admission::Busy) => {
                self.answer_busy(stream, identity, until, false);
            }
            (Ok(Classified { identity, .. }), Admission::Answered) => {
                let response = self.answer_identity(identity);
                Self::conclude(stream, response);
            }
            (Err(refusal), _) => Self::conclude(stream, self.refuse(refusal)),
        }
    }

    /// Hand an authenticated cancel or reconcile, read in full, to the
    /// control pool (R15 N13): its execute worker `place`, if any, is freed
    /// first, and a full control pool gets `12`. After step 6 `Revoked`
    /// writes zero bytes, a runtime that is not `Open` gets `11`, and an
    /// `Open` one answers from its lifecycle.
    fn answer_control(
        &self,
        stream: &UnixStream,
        (identity, control): (RequestIdentity, Control),
        until: Instant,
        place: Option<Place<'_>>,
    ) {
        drop(place);
        if self.revocation.observer().revoked() {
            return;
        }
        let held = self.control.take();
        let response = match (self.opened(), &held) {
            (None, _) => self.authenticated(identity, SandboxProviderErrorCode::SandboxUnavailable),
            (Some(_), None) => {
                self.authenticated(identity, SandboxProviderErrorCode::AdmissionBusy)
            }
            (Some(port), Some(_)) => self.control_answer(port, identity, &control, until),
        };
        Self::conclude(stream, response);
        drop(held);
    }

    /// The SCY1 or SRY1 that answers `control`, or its SPE1; nothing when
    /// the answer cannot be signed (R9 §5).
    fn control_answer(
        &self,
        port: &ExecutePort,
        identity: RequestIdentity,
        control: &Control,
        until: Instant,
    ) -> Option<Vec<u8>> {
        let signing = (&**self.signer, self.key());
        let answered = match control {
            Control::Cancel(request) => port.cancel(request, (until, self.interval()), signing),
            Control::Reconcile(request) => port.reconcile(request, until, signing),
        };
        answered.map_or_else(
            |code| code.and_then(|code| self.authenticated(identity, code)),
            Some,
        )
    }

    /// One initial control interval, BHC1 limit 16.
    fn interval(&self) -> Duration {
        Duration::from_millis(
            self.admitted.provider().broker_hard_caps()[CONTROL_DEADLINE_LIMIT_ID].value,
        )
    }

    /// An authenticated request beyond the answered pool: an exact repeat
    /// of an attempt the port holds joins it (item P10) while a busy join's
    /// place is free; any other request, and a repeat with none free, gets
    /// `12`, or `14` once the ledger was `closed`.
    fn answer_busy(
        &self,
        stream: &UnixStream,
        identity: RequestIdentity,
        until: Instant,
        closed: bool,
    ) {
        let code = if closed {
            SandboxProviderErrorCode::CleanupFailed
        } else {
            SandboxProviderErrorCode::AdmissionBusy
        };
        // A place is taken only by an exact repeat the port may join.
        let joining = self
            .open_port()
            .filter(|_| identity.operation == EXECUTE)
            .and_then(|port| Some(port).zip(self.joins.wait(Instant::now())));
        match joining {
            Some((port, _place)) => match Self::join(port, identity, until) {
                Join::Fresh => Self::conclude(stream, self.authenticated(identity, code)),
                Join::Answer(answer) => self.reply(port, stream, identity, answer),
            },
            None => Self::conclude(stream, self.authenticated(identity, code)),
        }
    }

    /// The answer of an authenticated describe or execute read in full: the
    /// SDY1 of describe, and SPE1 `11` for an execute the port does not
    /// answer (R11 §7.1).
    fn answer_identity(&self, identity: RequestIdentity) -> Option<Vec<u8>> {
        if identity.operation == DESCRIBE {
            self.describe(identity.request_id)
        } else {
            self.authenticated(identity, SandboxProviderErrorCode::SandboxUnavailable)
        }
    }

    /// The signed SPE1 `code` for the authenticated `identity`.
    fn authenticated(
        &self,
        identity: RequestIdentity,
        code: SandboxProviderErrorCode,
    ) -> Option<Vec<u8>> {
        self.refuse(Refusal::Authenticated { identity, code })
    }

    /// Answer a connection that waited for an uncharged reader until its
    /// initial control deadline and was never read: the item P13 answer,
    /// recorded in diagnostics as a provider-side stall (R11 Amendment 1
    /// §7.5, owner decision 2026-11-24).
    fn unserved(&self, stream: &UnixStream) {
        writeln!(
            io::stderr(),
            "pos-sandboxd: provider-side stall: an execute connection waited for an uncharged reader until its initial control deadline"
        )
        .ok();
        Self::conclude(stream, self.refuse(unserved_reader()));
    }

    /// Write `response`, if any, under its own deadline, then send server
    /// write EOF. Bytes the peer sends after its request (R11 does not
    /// require it to half-close an execute connection) are read until its
    /// EOF, so the close cannot reset the connection before the answer is
    /// read.
    fn conclude(stream: &UnixStream, response: Option<Vec<u8>>) {
        let mut writing = Deadlined::new(stream, RESPONSE_DEADLINE);
        response
            .and_then(|bytes| control_framing::write_frame(&mut writing, &bytes, FRAME_LIMIT).ok());
        close_answered(stream);
    }

    /// Validation precedence steps 1 to 6: the authenticated identities of
    /// the request, or its refusal. Execute's SPX1 follows its EVR1 and the
    /// selector sends nothing more before AGR1; after any other record the
    /// rest of the request is read up to its EOF.
    fn classify(&self, stream: &mut Deadlined<'_>) -> Result<Classified, Refusal> {
        match read_record(stream) {
            Ok(first) if record_operation(&first) == Some(EXECUTE) => {
                self.classify_execute(&first, stream).map(Classified::from)
            }
            first => {
                let classified = first.and_then(|first| self.classify_single(&first));
                io::copy(stream, &mut io::sink()).ok();
                classified
            }
        }
    }

    /// Describe, cancel, reconcile, or a record that names none of them.
    fn classify_single(&self, first: &[u8]) -> Result<Classified, Refusal> {
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
                })
                .map(Classified::from),
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
                    .map(|identity| Classified {
                        identity,
                        control: Some(Control::Cancel(request)),
                    })
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
                    .map(|identity| Classified {
                        identity,
                        control: Some(Control::Reconcile(request)),
                    })
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
        let request = read_record(stream);
        self.classify_records(evaluation, request.as_deref().map_err(|refusal| *refusal))
    }

    /// Steps 2 to 6 of an execute whose EVR1 and SPX1 were read: either
    /// record's step failure, EVR1's first.
    fn classify_records(
        &self,
        evaluation: &[u8],
        request: Result<&[u8], Refusal>,
    ) -> Result<RequestIdentity, Refusal> {
        let evaluation = EvaluationRequest::from_canonical_cbor(evaluation)
            .map_err(|error| Refusal::invalid(EXECUTE, evaluation_step(error)));
        evaluation
            .and(request)
            .and_then(|bytes| {
                SandboxExecuteRequest::from_canonical_cbor(bytes)
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

/// Whether the acceptor polls the execute listener, given whether an
/// answered place is free and whether the uncharged reader pool has room:
/// while every answered place is taken and the reader pool has no room (or
/// a hand-off waits for it) it is not polled; the control listener and both
/// endpoint checks still are.
const fn accepting(answered: bool, room: bool) -> bool {
    answered || room
}

/// The refusal of a connection that waited for an uncharged reader until
/// its initial control deadline and was never read (R11 Amendment 1 §7.5,
/// invariant 30): no identity was authenticated, so SPE1 can encode only
/// code `0` with null identities. This is the single place that answer is
/// chosen (item P13, accepted as option (a) on 2026-11-24).
const fn unserved_reader() -> Refusal {
    Refusal::UNIDENTIFIED
}

/// Send server write EOF, then read what the peer still sends until its EOF
/// or the response deadline.
fn close_answered(stream: &UnixStream) {
    stream.shutdown(std::net::Shutdown::Write).ok();
    io::copy(
        &mut Deadlined::new(stream, RESPONSE_DEADLINE),
        &mut io::sink(),
    )
    .ok();
}

/// Whether one poll found the control and the execute listener ready. The
/// execute listener counts only while `accepting`: while it is not polled
/// for input, whatever else it reports is no connection to accept.
const fn readiness(accepting: bool, control: PollFlags, execute: PollFlags) -> (bool, bool) {
    (!control.is_empty(), accepting && !execute.is_empty())
}

/// Whether an accept produced nothing (such as `EMFILE`): a control accept
/// that `control_missed`, or an execute accept that was `execute_ready` but
/// not `execute_accepted`. Then the acceptor backs off briefly instead of
/// spinning on a listener that stays readable.
const fn missed(control_missed: bool, execute_ready: bool, execute_accepted: bool) -> bool {
    control_missed || (execute_ready && !execute_accepted)
}

/// Whether the `SO_PEERCRED` UID of `stream`'s peer is `uid` (R11 §6 step
/// 6: [`ROOT_UID`] outside tests).
fn trusted_peer(stream: &UnixStream, uid: u32) -> bool {
    rustix::net::sockopt::socket_peercred(stream).is_ok_and(|peer| peer.uid.as_raw() == uid)
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
pub(super) struct Deadlined<'a> {
    stream: &'a UnixStream,
    until: Instant,
}

impl<'a> Deadlined<'a> {
    /// `stream`, ending at `until`.
    pub(super) const fn until(stream: &'a UnixStream, until: Instant) -> Self {
        Self { stream, until }
    }

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

mod port;
use port::Join;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
