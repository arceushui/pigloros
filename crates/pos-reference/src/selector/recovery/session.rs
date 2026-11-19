//! One recovery-peer session: the single start, the 100 ms exchange and the
//! unconditional cleanup (ADR-069 R12 §6 steps 7 to 13, §4.3 guard).

use std::net::Shutdown;
use std::time::Duration;

use super::authority::{
    fresh_challenge, require, Consumed, PreviousRuntimeTerminationProof,
    ProviderTerminationAuthority, Unconsumed,
};
use super::port::{
    RecoveryPeerLaunch, RecoveryPeerObservation, RecoverySlotTarget, VerifiedProviderBinary,
};
use super::{
    PendingRecoveryTarget, RecoveryError, RecoveryOperationId, RecoveryTransactionIdentity,
};
use crate::control_framing;
use crate::sandbox_provider_protocol::AuthenticatedRevocationAcknowledgement;
use crate::selector::runtime_lifecycle::{CgroupPath, ProviderLifecyclePort};

/// The peer's start-to-readiness bound (owner decision O2).
const PEER_START_BOUND: Duration = Duration::from_secs(5);
/// The recovery control exchange's absolute bound.
const EXCHANGE_BOUND: Duration = Duration::from_millis(100);
/// The forced cleanup's absolute bound, from the end of the exchange.
const CLEANUP_BOUND: Duration = Duration::from_secs(5);
/// One control frame's bound: an RCA1 is at most 16 MiB.
const FRAME_LIMIT: usize = 16 * 1024 * 1024;

/// The selector's proof that the one recovery peer answered and was cleaned.
///
/// The peer of one operation answered with a valid RCA1 and server EOF, and
/// its slot was then reconciled, its control group proven absent and its
/// leaf removed (R12 §6 step 12).
///
/// Its fields are private:
///
/// ```compile_fail,E0451
/// use pos_reference::selector::recovery::RecoveryPeerTerminationProof;
///
/// let _ = RecoveryPeerTerminationProof {
///     identity: todo!(),
///     operation: todo!(),
///     acknowledgement_digest: [0; 32],
///     acknowledgement: Vec::new(),
/// };
/// ```
///
/// It is not `Clone`:
///
/// ```compile_fail,E0277
/// use pos_reference::selector::recovery::RecoveryPeerTerminationProof;
///
/// fn duplicate<T: Clone>() {}
/// duplicate::<RecoveryPeerTerminationProof>();
/// ```
#[derive(Debug)]
pub struct RecoveryPeerTerminationProof {
    pub(super) identity: RecoveryTransactionIdentity,
    pub(super) operation: RecoveryOperationId,
    pub(super) acknowledgement_digest: [u8; 32],
    acknowledgement: Vec<u8>,
}

impl RecoveryPeerTerminationProof {
    /// The exact RCA1 bytes the peer sent.
    pub(crate) fn acknowledgement_bytes(&self) -> &[u8] {
        &self.acknowledgement
    }
}

/// The session of one authorized peer start.
///
/// Its fields are private:
///
/// ```compile_fail,E0451
/// use pos_reference::selector::recovery::RecoveryPeerSession;
/// use pos_reference::selector::runtime_lifecycle::ProviderLifecyclePort;
///
/// fn forge<P: ProviderLifecyclePort>() -> RecoveryPeerSession<'static, P> {
///     RecoveryPeerSession {
///         target: todo!(),
///         proof: todo!(),
///         binary: todo!(),
///         guard: todo!(),
///     }
/// }
/// ```
///
/// It is not `Clone`:
///
/// ```compile_fail,E0277
/// use pos_reference::selector::recovery::RecoveryPeerSession;
/// use pos_reference::selector::runtime_lifecycle::ProviderLifecyclePort;
///
/// fn duplicate<T: Clone>() {}
/// fn session<P: ProviderLifecyclePort + 'static>() {
///     duplicate::<RecoveryPeerSession<'static, P>>();
/// }
/// ```
pub struct RecoveryPeerSession<'a, P: ProviderLifecyclePort + ?Sized> {
    pub(super) target: &'a PendingRecoveryTarget,
    pub(super) proof: PreviousRuntimeTerminationProof<Unconsumed>,
    pub(super) binary: VerifiedProviderBinary,
    pub(super) guard: CleanupGuard<'a, P>,
}

/// The two proofs and the authenticated RCA1 of one concluded session.
pub type ConcludedRecovery = (
    PreviousRuntimeTerminationProof<Consumed>,
    AuthenticatedRevocationAcknowledgement,
    RecoveryPeerTerminationProof,
);

/// What the exchange established before cleanup.
struct Exchanged {
    acknowledgement: AuthenticatedRevocationAcknowledgement,
    bytes: Vec<u8>,
}

impl<P: ProviderLifecyclePort + ?Sized> RecoveryPeerSession<'_, P> {
    /// Starts the peer, runs the 100 ms exchange, then always fences,
    /// terminates and reconciles the slot under 5 s (R12 §6 steps 7 to 13).
    ///
    /// The pair of proofs is minted only after a valid RCA1, server EOF and
    /// a proven-clean cleanup.
    ///
    /// # Errors
    /// Returns a [`RecoveryError`] for any failure of the start, the
    /// selector's checks, the exchange or the cleanup. The SIR1 stays.
    pub fn conclude(mut self) -> Result<ConcludedRecovery, RecoveryError> {
        let target = self.target;
        self.guard.arm();
        let mut started = None;
        let exchanged = self.start_and_exchange(&mut started);
        // R12 §6 step 12: whatever the exchange did, the stream is dropped
        // and the slot reconciled under one fresh 5 s deadline.
        let cleaned = self.guard.clean(started.as_ref());
        self.guard.disarm();
        exchanged.and_then(|exchanged| {
            cleaned.map(|()| {
                let acknowledgement_digest = exchanged.acknowledgement.acknowledgement_digest();
                (
                    self.proof.consume(),
                    exchanged.acknowledgement,
                    RecoveryPeerTerminationProof {
                        identity: target.identity.duplicate(),
                        operation: target.operation,
                        acknowledgement_digest,
                        acknowledgement: exchanged.bytes,
                    },
                )
            })
        })
    }

    /// R12 §6 steps 7 to 11. `started` records the peer's control group
    /// once the port reported the start.
    fn start_and_exchange(
        &self,
        started: &mut Option<CgroupPath>,
    ) -> Result<Exchanged, RecoveryError> {
        let authority = self.guard.authority;
        let host = authority.host();
        let target = self.target;
        let endpoint = target.endpoint_id();
        fresh_challenge()
            .and_then(|challenge| {
                host.deadline_after(PEER_START_BOUND)
                    .map(|deadline| (challenge, deadline))
            })
            .and_then(|(challenge, deadline)| {
                let launch = RecoveryPeerLaunch::new(
                    RecoverySlotTarget::new(challenge, target.recovery_lifecycle_scope_id()),
                    endpoint,
                    &self.binary,
                );
                let observed = authority
                    .port()
                    .start_recovery_peer(&launch, deadline)
                    .map_err(RecoveryError::Lifecycle);
                if let Ok(observed) = &observed {
                    *started = Some(observed.control_group().clone());
                }
                observed.and_then(|observed| {
                    require(
                        observed.challenge() == challenge
                            && observed.recovery_lifecycle_scope_id()
                                == target.recovery_lifecycle_scope_id(),
                        RecoveryError::Observation,
                    )
                    .map(|()| observed)
                })
            })
            .and_then(|observed| self.verify_started(&observed).map(|leaf| (observed, leaf)))
            .and_then(|(observed, leaf)| self.exchange(&observed, leaf))
    }

    /// R12 §6 step 8.
    fn verify_started(
        &self,
        observed: &RecoveryPeerObservation,
    ) -> Result<super::host::LeafIdentity, RecoveryError> {
        let host = self.guard.authority.host();
        host.verify_peer_process(
            observed.main_pid(),
            observed.main_start_time_ticks(),
            observed.control_group(),
            (
                self.binary.digest(),
                self.target.records.provider_binary_length(),
            ),
        )
        .and_then(|()| host.ready_leaf(self.target.endpoint_id()))
    }

    /// R12 §6 steps 9 to 11: one connection, RCC1 and RCU1, write EOF, one
    /// RCA1 and server EOF, all before the 100 ms deadline on the selector's
    /// clock, then RCA1 authenticated under the SIR1 runtime key.
    fn exchange(
        &self,
        observed: &RecoveryPeerObservation,
        leaf: super::host::LeafIdentity,
    ) -> Result<Exchanged, RecoveryError> {
        let host = self.guard.authority.host();
        let target = self.target;
        let endpoint = target.endpoint_id();
        target
            .records
            .context_bytes()
            .map_err(RecoveryError::Boundary)
            .and_then(|context| {
                host.deadline_after(EXCHANGE_BOUND)
                    .map(|deadline| (context, deadline))
            })
            .and_then(|(context, deadline)| {
                host.connect_peer(endpoint, observed.main_pid())
                    .and_then(|stream| host.require_same_leaf(endpoint, leaf).map(|()| stream))
                    .and_then(|stream| {
                        let mut clocked = host.clocked(&stream, deadline);
                        control_framing::write_frame(&mut clocked, &context, FRAME_LIMIT)
                            .and_then(|()| {
                                control_framing::write_frame(
                                    &mut clocked,
                                    target.records.revocation_update_bytes(),
                                    FRAME_LIMIT,
                                )
                            })
                            .map_err(|_| RecoveryError::Exchange)
                            .and_then(|()| {
                                stream
                                    .shutdown(Shutdown::Write)
                                    .map_err(|_| RecoveryError::Exchange)
                            })
                            .and_then(|()| {
                                control_framing::read_frame(&mut clocked, FRAME_LIMIT)
                                    .ok()
                                    .flatten()
                                    .ok_or(RecoveryError::Exchange)
                            })
                            .and_then(|bytes| {
                                control_framing::require_eof(&mut clocked)
                                    .map_err(|_| RecoveryError::Exchange)
                                    .and_then(|()| {
                                        require(clocked.within_deadline(), RecoveryError::Exchange)
                                    })
                                    .map(|()| bytes)
                            })
                    })
            })
            .and_then(|bytes| {
                target
                    .authenticate_recovery_acknowledgement(&bytes)
                    .map(|acknowledgement| Exchanged {
                        acknowledgement,
                        bytes,
                    })
            })
    }
}

/// The session's unwinding guard (R12 §4.3 m2). Armed immediately before
/// the port's start and disarmed only after the cleanup ran, it cleans the
/// slot once more if it drops armed, which happens only on unwinding.
pub(super) struct CleanupGuard<'a, P: ProviderLifecyclePort + ?Sized> {
    authority: &'a ProviderTerminationAuthority<P>,
    target: &'a PendingRecoveryTarget,
    armed: bool,
}

impl<'a, P: ProviderLifecyclePort + ?Sized> CleanupGuard<'a, P> {
    pub(super) const fn unarmed(
        authority: &'a ProviderTerminationAuthority<P>,
        target: &'a PendingRecoveryTarget,
    ) -> Self {
        Self {
            authority,
            target,
            armed: false,
        }
    }

    const fn arm(&mut self) {
        self.armed = true;
    }

    const fn disarm(&mut self) {
        self.armed = false;
    }

    /// R12 §6 step 12 under one fresh 5 s deadline: reconcile the slot,
    /// prove the peer's control group absent, and remove the exact leaf,
    /// all before the deadline.
    fn clean(&self, started: Option<&CgroupPath>) -> Result<(), RecoveryError> {
        let host = self.authority.host();
        host.deadline_after(CLEANUP_BOUND).and_then(|deadline| {
            self.authority
                .reconcile_slot(self.target, deadline, started)
                .and_then(|()| host.remove_stale_leaf(self.target.endpoint_id()))
                .and_then(|()| require(host.now() <= deadline, RecoveryError::DeadlineExceeded))
        })
    }
}

impl<P: ProviderLifecyclePort + ?Sized> Drop for CleanupGuard<'_, P> {
    fn drop(&mut self) {
        if self.armed {
            // Unwinding: SIR1 stays and the selector stays closed whatever
            // this cleanup reports.
            let _cleanup = self.clean(None);
        }
    }
}
