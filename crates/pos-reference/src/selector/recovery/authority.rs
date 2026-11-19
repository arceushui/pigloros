//! The root-owned termination authority and its two proofs (ADR-069 R12
//! §4.3, §6).
//!
//! [`ProviderTerminationAuthority`] is the only code that mints a proof. It
//! asks the port for an observation, checks the observation against its
//! target, then runs the selector's own kernel checks. Only then does it
//! mint. Every proof carries the transaction's identity and the recovery
//! operation's ID, so proofs of two operations never combine.

use std::marker::PhantomData;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::host::RecoveryHost;
use super::port::{
    PreviousRuntimeIds, PreviousRuntimeObservation, PreviousRuntimeTarget, RecoverySlotTarget,
    VerifiedProviderBinary,
};
use super::session::{CleanupGuard, RecoveryPeerSession};
use super::{
    PendingRecoveryTarget, RecoveryError, RecoveryOperationId, RecoveryTransactionIdentity,
};
use crate::selector::runtime_lifecycle::{CgroupPath, ObservationChallenge, ProviderLifecyclePort};

/// The previous runtime's termination and reconciliation bound: ADR-069
/// §9's 10 s restart bound. The adapter extends it only by the #1200 D2
/// recent-activation wait (R12 §7.4).
const PREVIOUS_RUNTIME_BOUND: Duration = Duration::from_secs(10);
/// The longest #1200 D2 recent-activation wait the adapter may add to the
/// previous-runtime bound, and only when it reports one (R12 §7.1, §7.4).
const RECENT_ACTIVATION_WAIT: Duration = Duration::from_secs(70);
/// The slot reconciliation bound at operation start (R12 §6 step 4, m4).
const SLOT_RECONCILE_BOUND: Duration = Duration::from_secs(5);

mod sealed {
    /// Only this module names the proof states.
    pub trait Sealed {}
}

/// The state of a [`PreviousRuntimeTerminationProof`].
///
/// It is sealed: no other crate can add a state.
///
/// ```compile_fail,E0277
/// use pos_reference::selector::recovery::{PreviousRuntimeTerminationProof, ProofState};
///
/// enum Forged {}
/// impl ProofState for Forged {}
/// ```
pub trait ProofState: sealed::Sealed {}

/// A proof that no peer start has consumed yet.
#[derive(Debug)]
pub enum Unconsumed {}

/// A proof whose one peer start completed.
#[derive(Debug)]
pub enum Consumed {}

impl sealed::Sealed for Unconsumed {}
impl sealed::Sealed for Consumed {}
impl ProofState for Unconsumed {}
impl ProofState for Consumed {}

/// The selector's proof that the previous runtime of one pending SIR1 is
/// terminated and reconciled, and its recovery-peer slot is empty (R12 §6
/// steps 1 to 5).
///
/// It names its transaction and operation. Its fields are private:
///
/// ```compile_fail,E0451
/// use pos_reference::selector::recovery::{PreviousRuntimeTerminationProof, Unconsumed};
///
/// let _ = PreviousRuntimeTerminationProof::<Unconsumed> {
///     identity: todo!(),
///     operation: todo!(),
///     state: std::marker::PhantomData,
/// };
/// ```
///
/// It is not `Clone`:
///
/// ```compile_fail,E0277
/// use pos_reference::selector::recovery::{PreviousRuntimeTerminationProof, Unconsumed};
///
/// fn duplicate<T: Clone>() {}
/// duplicate::<PreviousRuntimeTerminationProof<Unconsumed>>();
/// ```
///
/// One unconsumed proof authorizes one peer start, and only a consumed one
/// completes recovery (R12 I2):
///
/// ```compile_fail,E0382
/// use pos_reference::selector::recovery::{
///     PendingRecoveryTarget, PreviousRuntimeTerminationProof, ProviderTerminationAuthority,
///     Unconsumed,
/// };
/// use pos_reference::selector::runtime_lifecycle::ProviderLifecyclePort;
///
/// fn twice<P: ProviderLifecyclePort + ?Sized>(
///     authority: &ProviderTerminationAuthority<P>,
///     target: &PendingRecoveryTarget,
///     proof: PreviousRuntimeTerminationProof<Unconsumed>,
/// ) {
///     let _ = authority.start_recovery_peer(target, proof);
///     let _ = authority.start_recovery_peer(target, proof);
/// }
/// ```
///
/// ```compile_fail,E0308
/// use pos_reference::sandbox_provider_protocol::AuthenticatedRevocationAcknowledgement;
/// use pos_reference::selector::recovery::{
///     complete_recovery, PendingRecoveryTarget, PreviousRuntimeTerminationProof,
///     RecoveryPeerTerminationProof, Unconsumed,
/// };
///
/// fn early(
///     target: PendingRecoveryTarget,
///     proof: PreviousRuntimeTerminationProof<Unconsumed>,
///     acknowledgement: AuthenticatedRevocationAcknowledgement,
///     peer: RecoveryPeerTerminationProof,
/// ) {
///     let _ = complete_recovery(target, proof, acknowledgement, peer);
/// }
/// ```
#[derive(Debug)]
pub struct PreviousRuntimeTerminationProof<S: ProofState> {
    pub(super) identity: RecoveryTransactionIdentity,
    pub(super) operation: RecoveryOperationId,
    state: PhantomData<S>,
}

impl PreviousRuntimeTerminationProof<Unconsumed> {
    /// The one peer start this proof authorized has completed.
    pub(super) fn consume(self) -> PreviousRuntimeTerminationProof<Consumed> {
        PreviousRuntimeTerminationProof {
            identity: self.identity,
            operation: self.operation,
            state: PhantomData,
        }
    }
}

impl PreviousRuntimeTerminationProof<Unconsumed> {
    /// Whether this proof names `target`'s transaction and operation.
    fn names(&self, target: &PendingRecoveryTarget) -> bool {
        self.identity == target.identity && self.operation == target.operation
    }
}

/// The root-owned authority that terminates a previous runtime and starts
/// its recovery peer through the one production lifecycle port (R12 §3).
///
/// Only the root selector constructs it, so no wire, configuration,
/// environment or argument value selects the port.
pub struct ProviderTerminationAuthority<P: ProviderLifecyclePort + ?Sized> {
    port: Arc<P>,
    host: RecoveryHost,
}

impl<P: ProviderLifecyclePort + ?Sized> ProviderTerminationAuthority<P> {
    /// The authority over `port`, checking against `host`.
    pub(crate) const fn new(port: Arc<P>, host: RecoveryHost) -> Self {
        Self { port, host }
    }

    pub(super) const fn host(&self) -> &RecoveryHost {
        &self.host
    }

    pub(super) fn port(&self) -> &P {
        &self.port
    }

    /// R12 §6 steps 1 to 5: terminate and reconcile the previous runtime of
    /// `target`, reconcile its recovery-peer slot and remove its exact stale
    /// leaf, then mint the proof.
    ///
    /// # Errors
    /// Returns a [`RecoveryError`] for a port failure, a forged or foreign
    /// observation, a live recorded process, a remaining control group, or
    /// a leaf that is not the exact refusing socket. No proof is minted.
    pub fn terminate_previous_runtime(
        &self,
        target: &PendingRecoveryTarget,
    ) -> Result<PreviousRuntimeTerminationProof<Unconsumed>, RecoveryError> {
        self.terminate_runtime(target)
            .and_then(|()| self.host.deadline_after(SLOT_RECONCILE_BOUND))
            .and_then(|deadline| self.reconcile_slot(target, deadline, None))
            .and_then(|()| self.host.remove_stale_leaf(target.endpoint_id()))
            .map(|()| PreviousRuntimeTerminationProof {
                identity: target.identity.duplicate(),
                operation: target.operation,
                state: PhantomData,
            })
    }

    /// R12 §6 steps 1 to 3.
    fn terminate_runtime(&self, target: &PendingRecoveryTarget) -> Result<(), RecoveryError> {
        let identity = &target.identity;
        let ids = PreviousRuntimeIds {
            provider_binary_digest: target.records.provider_binary_digest(),
            runtime_instance_id: identity.previous_runtime_instance_id,
            lifecycle_scope_id: identity.previous_lifecycle_scope_id,
            recovery_lifecycle_scope_id: target.recovery_lifecycle_scope_id(),
        };
        let (pid, ticks) = target.records.main_process();
        fresh_challenge()
            .and_then(|challenge| {
                self.host
                    .deadline_after(PREVIOUS_RUNTIME_BOUND)
                    .map(|deadline| (challenge, deadline))
            })
            .and_then(|(challenge, deadline)| {
                self.port
                    .terminate_previous_runtime(
                        &PreviousRuntimeTarget::new(
                            challenge,
                            target.records.provider_id(),
                            &ids,
                            &identity.previous_live_attempt_ids,
                        ),
                        deadline,
                    )
                    .map_err(RecoveryError::Lifecycle)
                    .and_then(|observed| {
                        // The adapter may outlast the 10 s bound only by the
                        // recent-activation wait it reports applying, at
                        // most 70 s; anything later is refused.
                        let wait = observed.activation_wait();
                        require(wait <= RECENT_ACTIVATION_WAIT, RecoveryError::Observation)
                            .and_then(|()| self.require_within(deadline, wait))
                            .and_then(|()| verify_previous(&observed, challenge, target))
                    })
            })
            .and_then(|control_group| {
                RecoveryHost::require_process_absent(pid, ticks)
                    .and_then(|()| self.host.require_cgroup_absent(&control_group))
            })
    }

    /// Reconcile `target`'s recovery-peer slot by `deadline` and prove its
    /// control group absent, which must be `started` when the peer started
    /// (R12 §6 steps 4 and 12).
    pub(super) fn reconcile_slot(
        &self,
        target: &PendingRecoveryTarget,
        deadline: Instant,
        started: Option<&CgroupPath>,
    ) -> Result<(), RecoveryError> {
        let scope = target.recovery_lifecycle_scope_id();
        fresh_challenge()
            .and_then(|challenge| {
                self.port
                    .reconcile_recovery_slot(&RecoverySlotTarget::new(challenge, scope), deadline)
                    .map_err(RecoveryError::Lifecycle)
                    .and_then(|observed| {
                        self.require_within(deadline, Duration::ZERO)
                            .map(|()| observed)
                    })
                    .and_then(|observed| {
                        require(
                            observed.challenge() == challenge
                                && observed.recovery_lifecycle_scope_id() == scope
                                && started
                                    .is_none_or(|started| started == observed.control_group()),
                            RecoveryError::Observation,
                        )
                        .map(|()| observed)
                    })
            })
            .and_then(|observed| self.host.require_cgroup_absent(observed.control_group()))
    }

    /// The selector's clock has not passed `deadline` plus `grace`: a port
    /// that returned after its deadline yields no proof.
    pub(super) fn require_within(
        &self,
        deadline: Instant,
        grace: Duration,
    ) -> Result<(), RecoveryError> {
        deadline
            .checked_add(grace)
            .ok_or(RecoveryError::DeadlineExceeded)
            .and_then(|latest| require(self.host.now() <= latest, RecoveryError::DeadlineExceeded))
    }

    /// The sole authorization of one peer start (R12 §6 step 6).
    ///
    /// It consumes `proof` whatever the result, checks that it names
    /// `target`'s transaction and operation, and re-hashes the previous
    /// provider binary to the SIR1 digest. It starts nothing: the session's
    /// `conclude` performs the start, so an `Err` always means that no
    /// process was created.
    ///
    /// # Errors
    /// Returns [`RecoveryError::Mismatch`] for a proof of another
    /// transaction or operation, and [`RecoveryError::Binary`] when the
    /// binary no longer has the SIR1 digest.
    pub fn start_recovery_peer<'a>(
        &'a self,
        target: &'a PendingRecoveryTarget,
        proof: PreviousRuntimeTerminationProof<Unconsumed>,
    ) -> Result<RecoveryPeerSession<'a, P>, RecoveryError> {
        require(proof.names(target), RecoveryError::Mismatch)
            .and_then(|()| {
                target
                    .records
                    .verified_provider_binary()
                    .map_err(|_| RecoveryError::Binary)
            })
            .map(|(path, digest)| RecoveryPeerSession {
                target,
                proof,
                binary: VerifiedProviderBinary::new(path, digest),
                guard: CleanupGuard::unarmed(self, target),
            })
    }
}

/// R12 §6 step 2: the observation echoes `challenge`, names the SIR1 scope,
/// and reports a sorted, unique subset of the previous-live set. Returns the
/// terminated unit's control group.
fn verify_previous(
    observed: &PreviousRuntimeObservation,
    challenge: ObservationChallenge,
    target: &PendingRecoveryTarget,
) -> Result<CgroupPath, RecoveryError> {
    let identity = &target.identity;
    let reconciled = observed.reconciled_attempt_ids();
    require(
        observed.challenge() == challenge
            && observed.lifecycle_scope_id() == identity.previous_lifecycle_scope_id
            && reconciled.windows(2).all(|pair| pair[0] < pair[1])
            && reconciled.iter().all(|attempt| {
                identity
                    .previous_live_attempt_ids
                    .binary_search(attempt)
                    .is_ok()
            }),
        RecoveryError::Observation,
    )
    .map(|()| observed.control_group().clone())
}

/// One fresh nonzero challenge.
pub(super) fn fresh_challenge() -> Result<ObservationChallenge, RecoveryError> {
    ObservationChallenge::fresh().map_err(RecoveryError::Boundary)
}

pub(super) const fn require(condition: bool, error: RecoveryError) -> Result<(), RecoveryError> {
    if condition {
        Ok(())
    } else {
        Err(error)
    }
}
