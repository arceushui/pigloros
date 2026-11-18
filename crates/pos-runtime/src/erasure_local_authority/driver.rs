//! `LocalErasureDriverV1`: the only lifecycle caller of the single-host
//! erasure authority (ADR-136 §1, §5 and §6; ticket #1431).
//!
//! The driver runs every lifecycle command of a Local request through the
//! host: authorization, the access freeze, each attempt's dispatch, the
//! owner work of the dispatched commands through `LocalErasureExecutorV1`,
//! each acknowledgement and each receipt. It prepares each step from the
//! committed state, has `LocalErasureSignerV1` sign what needs a signature,
//! and submits the lifecycle command, so it chooses nothing a signature or
//! admission covers. Every step is one durable transition, so a crash
//! anywhere resumes at the next step on restart.

use pos_core::{
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementV1, ErasureHostErrorV1,
    ErasureLifecycleV1, ErasureOwnerResultV1, ErasureReceiptInputV1, ErasureReceiptV1,
    ErasureReferenceV1, ErasureReplayClaimV1, ErasureRetryAdmissionV1, ErasureStateTransitionV1,
};

use super::freeze::LOCAL_FREEZE_POSITION;
use super::{
    LocalErasureExecutorV1, LocalErasureSignerV1, LocalErasureSigningRequestV1,
    LOCAL_ERASURE_MAX_REPREPARE_V1,
};
use crate::erasure_host::{LocalAttemptPreparationV1, LocalFreezePreparationV1};
use crate::ErasureExecutionHostV1;

/// The one durable transition [`LocalErasureDriverV1::step`] committed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalErasureStepV1 {
    /// The request was authorized under its own ERAZ1.
    Authorized,
    /// The request was rejected at the authorize stage under `CA(ELREJ1)`,
    /// because its ERAZ1 no longer verifies.
    Rejected,
    /// Access was frozen under a purpose-0 ELS1.
    Frozen,
    /// The freeze committed `Rejected(ScopeInvalid)` under `CA(ERAZ1)`.
    FreezeRejected,
    /// This attempt was admitted and dispatched. Boxed only to keep the
    /// variants a similar size.
    Dispatched(Box<ErasureRetryAdmissionV1>),
    /// This owner result was acknowledged under a purpose-1 ELS1.
    Acknowledged(Box<ErasureOwnerResultV1>),
    /// The active attempt closed with this receipt under a purpose-2 ELS1.
    Finalized(Box<ErasureReceiptV1>),
    /// Nothing is due: the request is complete or rejected, a partial
    /// failure that is not retried automatically, or not held by the host.
    Idle,
}

/// The outcome of the startup sweep (ADR-136 §5; owner decision Q13 on
/// #1431).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalErasureSweepV1 {
    /// This many unreferenced objects were deleted.
    Swept(usize),
    /// A read failed or a tag held more than 4,096 objects, so nothing was
    /// deleted; startup goes on.
    Skipped,
}

/// The single-host erasure driver of one deployment.
pub struct LocalErasureDriverV1 {
    signer: LocalErasureSignerV1,
}

/// The transition of an access freeze under `provenance` (ADR-136 §6: the
/// freeze position is 1).
const fn freeze_transition(provenance: ErasureReferenceV1) -> ErasureStateTransitionV1 {
    ErasureStateTransitionV1 {
        lifecycle: ErasureLifecycleV1::AccessFrozen,
        freeze_position: Some(LOCAL_FREEZE_POSITION),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        acknowledged_targets: Vec::new(),
        replay_claim: ErasureReplayClaimV1::Exact,
        provenance,
    }
}

/// The acknowledgement of `result` under the ELS1 `evidence`.
const fn acknowledgement(
    result: &ErasureOwnerResultV1,
    evidence: ErasureReferenceV1,
) -> ErasureAcknowledgementV1 {
    let destruction = result.command().destruction;
    ErasureAcknowledgementV1 {
        obligation: destruction.obligation,
        target: destruction.target,
        owner: destruction.owner,
        evidence,
        outcome: if result.error().is_none() {
            ErasureAcknowledgementOutcomeV1::Acknowledged
        } else {
            ErasureAcknowledgementOutcomeV1::Negative
        },
    }
}

/// Run one prepare, sign and command sequence, preparing again while the
/// command finds the signed body stale, at most `max_reprepare` times in
/// all (ADR-136 §5, *Stale snapshot*). This bounds the unreferenced ELS1
/// objects one step leaves to `max_reprepare`; past it the step is
/// deferred to the next pass with its last error.
fn reprepared<T>(
    mut sequence: impl FnMut() -> Result<T, ErasureHostErrorV1>,
) -> Result<T, ErasureHostErrorV1> {
    let mut outcome = sequence();
    for _ in 1..LOCAL_ERASURE_MAX_REPREPARE_V1 {
        if !matches!(
            outcome,
            Err(ErasureHostErrorV1::StaleGeneration | ErasureHostErrorV1::AuthorizationDenied)
        ) {
            break;
        }
        outcome = sequence();
    }
    outcome
}

impl LocalErasureDriverV1 {
    /// A driver that signs with `signer`.
    #[must_use]
    pub const fn new(signer: LocalErasureSignerV1) -> Self {
        Self { signer }
    }

    /// The startup sweep of unreferenced ELS1, ELO1, ELAD1, ELCG1, ELNEG1
    /// and ELRP1 objects, run once the verified inventory is installed and
    /// before routes open (ADR-136 §5, *Sweep*). It keeps the closure of
    /// every committed reference and every object of an active attempt,
    /// deletes at most 4,096 objects, and is skipped, never failed, on a
    /// read error or more than 4,096 objects of one tag.
    pub fn sweep(host: &mut ErasureExecutionHostV1) -> LocalErasureSweepV1 {
        host.command_sender()
            .ok()
            .and_then(|mut sender| sender.sweep_local_erasure_objects())
            .map_or(LocalErasureSweepV1::Skipped, LocalErasureSweepV1::Swept)
    }

    /// Drive every request the host holds as far as it goes now, and
    /// return how many of them were deferred to the next pass by an error.
    ///
    /// # Errors
    /// The payload-free error of a host whose requests cannot be listed.
    pub fn run(&self, host: &mut ErasureExecutionHostV1) -> Result<usize, ErasureHostErrorV1> {
        host.command_sender()
            .and_then(|mut sender| sender.local_erasure_requests())
            .map(|requests| {
                requests
                    .into_iter()
                    .filter(|request| self.drive(host, *request).is_err())
                    .count()
            })
    }

    /// Commit the one durable transition the first request with one due
    /// needs, in the host's request order, and return it;
    /// [`LocalErasureStepV1::Idle`] when no request has one due.
    ///
    /// A request whose step fails is passed over: its step committed
    /// nothing and it resumes on a later call. A serving host calls this
    /// once per store command, so every other command of the host
    /// interleaves between two transitions (ADR-136 §5; owner decision D7
    /// of 2026-11-18 on #1413).
    ///
    /// # Errors
    /// The payload-free error of a host whose requests cannot be listed.
    pub fn advance(
        &self,
        host: &mut ErasureExecutionHostV1,
    ) -> Result<LocalErasureStepV1, ErasureHostErrorV1> {
        host.command_sender()
            .and_then(|mut sender| sender.local_erasure_requests())
            .map(|requests| {
                requests
                    .into_iter()
                    .find_map(|request| {
                        self.step(host, request)
                            .ok()
                            .filter(|step| *step != LocalErasureStepV1::Idle)
                    })
                    .unwrap_or(LocalErasureStepV1::Idle)
            })
    }

    /// Step `request` until nothing is due, and return the last step taken,
    /// [`LocalErasureStepV1::Idle`] when none was.
    ///
    /// # Errors
    /// The first step's error; the request resumes from there on the next
    /// pass.
    pub fn drive(
        &self,
        host: &mut ErasureExecutionHostV1,
        request: ErasureReferenceV1,
    ) -> Result<LocalErasureStepV1, ErasureHostErrorV1> {
        let mut last = LocalErasureStepV1::Idle;
        loop {
            match self.step(host, request)? {
                LocalErasureStepV1::Idle => return Ok(last),
                step => last = step,
            }
        }
    }

    /// Commit the one durable transition `request` needs next.
    ///
    /// - `submitted`: authorize it under its ERAZ1, or, when the authority
    ///   refuses that ERAZ1 with `AuthorizationDenied`, reject it under a
    ///   retained ELREJ1. The rejection is permanent, whatever the cause,
    ///   including a root-grant chain that advanced while the host was
    ///   down: the subject must resubmit (owner decision (c) of the #1431
    ///   review).
    /// - `authorized`: freeze it under a purpose-0 ELS1 over the prepared
    ///   body, after the preparation retained ELB1, ELLR1, TPS1 and ELB1S;
    ///   or commit the freeze rejection of a closure over its bound under
    ///   its ERAZ1 (Q11).
    /// - frozen with an active attempt: run the outbox through the executor,
    ///   which fences key destruction on the store's Erasure Host Timeline,
    ///   and acknowledge the first owner result under a purpose-1 ELS1;
    ///   once every command is acknowledged, finalize the receipt under a
    ///   purpose-2 ELS1.
    /// - frozen without one: dispatch the attempt that is due, attempt 0 or
    ///   an automatic retry of a transient negative (Q10), after its ELB1
    ///   is retained.
    ///
    /// # Errors
    /// The payload-free error of the step, which commits nothing more: a
    /// signer refusal, an admission refusal such as a retry refused while
    /// another request of the subject holds it, an expired TPS1 or bundle,
    /// or a store failure.
    pub fn step(
        &self,
        host: &mut ErasureExecutionHostV1,
        request: ErasureReferenceV1,
    ) -> Result<LocalErasureStepV1, ErasureHostErrorV1> {
        host.read_sender()
            .and_then(|mut reads| reads.erasure_state(request))
            .and_then(|state| {
                state.map_or(Ok(LocalErasureStepV1::Idle), |state| {
                    let authorization = state.request().authorization();
                    match state.lifecycle() {
                        ErasureLifecycleV1::Submitted => {
                            Self::authorize(host, request, authorization)
                        }
                        ErasureLifecycleV1::Authorized => self.freeze(host, request, authorization),
                        ErasureLifecycleV1::Complete | ErasureLifecycleV1::Rejected => {
                            Ok(LocalErasureStepV1::Idle)
                        }
                        ErasureLifecycleV1::AccessFrozen
                        | ErasureLifecycleV1::DestructionDispatched
                        | ErasureLifecycleV1::AwaitingAcknowledgements
                        | ErasureLifecycleV1::PartialFailure => self.attempt(host, request),
                    }
                })
            })
    }

    /// Authorize a submitted request, or reject it at the authorize stage
    /// when its ERAZ1 no longer verifies. Every `AuthorizationDenied` at
    /// this stage is a permanent rejection that needs a resubmission; any
    /// other error defers the step.
    fn authorize(
        host: &mut ErasureExecutionHostV1,
        request: ErasureReferenceV1,
        authorization: ErasureReferenceV1,
    ) -> Result<LocalErasureStepV1, ErasureHostErrorV1> {
        host.command_sender().and_then(|mut sender| {
            match sender.authorize_erasure_request(request, authorization) {
                Ok(_) => Ok(LocalErasureStepV1::Authorized),
                Err(ErasureHostErrorV1::AuthorizationDenied) => sender
                    .reject_local_erasure(request)
                    .map(|_| LocalErasureStepV1::Rejected),
                Err(error) => Err(error),
            }
        })
    }

    /// Freeze an authorized request, or commit its freeze rejection.
    fn freeze(
        &self,
        host: &mut ErasureExecutionHostV1,
        request: ErasureReferenceV1,
        authorization: ErasureReferenceV1,
    ) -> Result<LocalErasureStepV1, ErasureHostErrorV1> {
        reprepared(|| {
            host.command_sender()
                .and_then(|mut sender| sender.prepare_local_freeze(request))
                .and_then(|preparation| match preparation {
                    LocalFreezePreparationV1::Sign(body) => self
                        .signer
                        .sign(
                            host,
                            LocalErasureSigningRequestV1::FreezeAuthorization { request, body },
                        )
                        .map(|signature| (signature, LocalErasureStepV1::Frozen)),
                    LocalFreezePreparationV1::CommitsRejection => {
                        Ok((authorization, LocalErasureStepV1::FreezeRejected))
                    }
                })
                .and_then(|(provenance, step)| {
                    host.command_sender()
                        .and_then(|mut sender| {
                            sender.freeze_access(request, &freeze_transition(provenance))
                        })
                        .map(|_| step)
                })
        })
    }

    /// The next attempt step of a frozen request: run the first command of
    /// the active attempt's outbox through the executor, which fences key
    /// destruction on the store's Erasure Host Timeline, and acknowledge its
    /// owner result; with the outbox empty, finalize the active attempt or
    /// dispatch the attempt that is due.
    ///
    /// The outbox orders keys first and the local replica last, so the
    /// replica's purge runs once per attempt, after every other owner.
    fn attempt(
        &self,
        host: &mut ErasureExecutionHostV1,
        request: ErasureReferenceV1,
    ) -> Result<LocalErasureStepV1, ErasureHostErrorV1> {
        host.command_sender()
            .and_then(|mut sender| {
                sender
                    .dispatched_owner_commands(request)
                    .and_then(|commands| {
                        commands
                            .first()
                            .map(|command| LocalErasureExecutorV1::run(&mut sender, command))
                            .transpose()
                    })
            })
            .and_then(|executed| match executed {
                Some(result) => self.acknowledged(host, request, &result),
                None => self.next_attempt(host, request),
            })
    }

    /// Acknowledge `result` under a purpose-1 ELS1 over its ELO1.
    fn acknowledged(
        &self,
        host: &mut ErasureExecutionHostV1,
        request: ErasureReferenceV1,
        result: &ErasureOwnerResultV1,
    ) -> Result<LocalErasureStepV1, ErasureHostErrorV1> {
        self.signer
            .sign(
                host,
                LocalErasureSigningRequestV1::OwnerResult {
                    owner_result: result.owner_result(),
                },
            )
            .and_then(|evidence| {
                host.command_sender().and_then(|mut sender| {
                    sender.acknowledge_erasure(request, acknowledgement(result, evidence))
                })
            })
            .map(|_| LocalErasureStepV1::Acknowledged(Box::new(*result)))
    }

    /// Finalize the active attempt, or dispatch the attempt that is due.
    fn next_attempt(
        &self,
        host: &mut ErasureExecutionHostV1,
        request: ErasureReferenceV1,
    ) -> Result<LocalErasureStepV1, ErasureHostErrorV1> {
        host.command_sender()
            .and_then(|mut sender| sender.prepare_local_attempt(request))
            .and_then(|preparation| match preparation {
                LocalAttemptPreparationV1::Active => self.finalized(host, request),
                LocalAttemptPreparationV1::Dispatch(admission) => host
                    .command_sender()
                    .and_then(|mut sender| sender.dispatch_erasure_destruction(request, &admission))
                    .map(|_| LocalErasureStepV1::Dispatched(admission)),
                LocalAttemptPreparationV1::Idle => Ok(LocalErasureStepV1::Idle),
            })
    }

    /// Finalize the active attempt under a purpose-2 ELS1 over its ERCB1.
    fn finalized(
        &self,
        host: &mut ErasureExecutionHostV1,
        request: ErasureReferenceV1,
    ) -> Result<LocalErasureStepV1, ErasureHostErrorV1> {
        reprepared(|| {
            host.command_sender()
                .and_then(|mut sender| sender.prepare_local_receipt(request))
                .and_then(|preparation| {
                    self.signer
                        .sign(
                            host,
                            LocalErasureSigningRequestV1::ReceiptBody {
                                request,
                                body: preparation.body,
                            },
                        )
                        .map(|signature| ErasureReceiptInputV1 {
                            signature,
                            ..preparation.input
                        })
                })
                .and_then(|input| {
                    host.command_sender()
                        .and_then(|mut sender| sender.finalize_erasure_request(request, &input))
                })
                .map(|receipt| LocalErasureStepV1::Finalized(Box::new(receipt)))
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// A sequence that fails with each of `errors`, then succeeds.
    fn counted(errors: &[ErasureHostErrorV1]) -> (Result<usize, ErasureHostErrorV1>, usize) {
        let mut calls = 0;
        let outcome = reprepared(|| {
            calls += 1;
            errors.get(calls - 1).map_or(Ok(calls), |error| Err(*error))
        });
        (outcome, calls)
    }

    #[test]
    fn a_stale_body_is_prepared_again_at_most_max_reprepare_times_in_all() {
        assert_eq!(LOCAL_ERASURE_MAX_REPREPARE_V1, 3);
        // A first success runs once.
        assert_eq!(counted(&[]), (Ok(1), 1));
        // A stale generation or a refused, stale signed body is prepared
        // again, and a later success ends the step.
        assert_eq!(
            counted(&[
                ErasureHostErrorV1::StaleGeneration,
                ErasureHostErrorV1::AuthorizationDenied
            ]),
            (Ok(3), 3)
        );
        // Three stale bodies defer the step with the last error.
        assert_eq!(
            counted(&[ErasureHostErrorV1::StaleGeneration; 4]),
            (Err(ErasureHostErrorV1::StaleGeneration), 3)
        );
        // Any other error defers it at once.
        assert_eq!(
            counted(&[ErasureHostErrorV1::Conflict]),
            (Err(ErasureHostErrorV1::Conflict), 1)
        );
    }
}
