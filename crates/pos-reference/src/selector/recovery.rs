//! Sealed recovery proof transitions for one authenticated SIR1 transaction.
//!
//! This module owns the recovery-domain state machine, not process control or
//! socket I/O. A concrete lifecycle adapter supplies those effects through the
//! typed ports below. The selector can therefore release recovery completion
//! only after a previous-runtime proof is consumed, a recovery peer has been
//! cleaned up, and its exact RCA1 response has been authenticated.

use std::marker::PhantomData;

const RECOVERY_IDENTITY_DOMAIN: &[u8] = b"PiglorOS.RecoveryTransactionIdentity.v1\0";
const MAX_LIVE_ATTEMPTS: usize = 256;

/// Closed failures at the root-owned recovery seam.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum RecoveryDomainError {
    /// The authenticated SIR1 identity is malformed or ambiguous.
    #[error("sandbox recovery transaction identity is invalid")]
    InvalidTransactionIdentity,
    /// The previous provider runtime was not proven reconciled to empty.
    #[error("sandbox previous runtime termination was not proven")]
    PreviousRuntimeTerminationRejected,
    /// The dedicated recovery peer could not start under its allocated slot.
    #[error("sandbox recovery peer did not start")]
    RecoveryPeerStartRejected,
    /// Recovery-peer exchange or slot cleanup did not complete.
    #[error("sandbox recovery peer exchange or cleanup did not complete")]
    RecoveryPeerExchangeOrCleanupRejected,
    /// RCA1 was absent, malformed, forged, or bound to another transaction.
    #[error("sandbox recovery acknowledgement was not authenticated")]
    RecoveryAcknowledgementRejected,
    /// The recovery peer did not have one exact observed process identity.
    #[error("sandbox recovery peer identity is invalid")]
    RecoveryPeerIdentityInvalid,
    /// Two sealed capabilities bind different recovery transactions.
    #[error("sandbox recovery proofs bind different transactions")]
    CrossTransactionProof,
}

/// One root-selected runtime/lifecycle/endpoint slot for the recovery peer.
///
/// SIR1 creates this slot. Callers cannot provide an arbitrary endpoint while
/// starting recovery because the slot's identifiers are private and remain
/// bound into [`RecoveryTransactionIdentity`].
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct RecoveryPeerSlot {
    runtime_instance_id: [u8; 16],
    lifecycle_scope_id: [u8; 16],
    endpoint_id: [u8; 16],
}

impl RecoveryPeerSlot {
    /// Reconstitutes the slot only after the enclosing SIR1 was authenticated.
    ///
    /// # Errors
    /// Returns a closed failure for zero or non-distinct SIR1 slot identities.
    pub(crate) const fn from_authenticated_sir1(
        runtime_instance_id: [u8; 16],
        lifecycle_scope_id: [u8; 16],
        endpoint_id: [u8; 16],
    ) -> Result<Self, RecoveryDomainError> {
        if runtime_instance_id == [0; 16]
            || lifecycle_scope_id == [0; 16]
            || endpoint_id == [0; 16]
            || runtime_instance_id == lifecycle_scope_id
            || runtime_instance_id == endpoint_id
            || lifecycle_scope_id == endpoint_id
        {
            Err(RecoveryDomainError::InvalidTransactionIdentity)
        } else {
            Ok(Self {
                runtime_instance_id,
                lifecycle_scope_id,
                endpoint_id,
            })
        }
    }

    /// Root-selected recovery-peer runtime identity.
    #[must_use]
    pub(crate) const fn runtime_instance_id(&self) -> [u8; 16] {
        self.runtime_instance_id
    }

    /// Root-selected recovery-peer lifecycle-scope identity.
    #[must_use]
    pub(crate) const fn lifecycle_scope_id(&self) -> [u8; 16] {
        self.lifecycle_scope_id
    }

    /// Root-selected recovery-peer endpoint identity.
    #[must_use]
    pub(crate) const fn endpoint_id(&self) -> [u8; 16] {
        self.endpoint_id
    }
}

/// One authenticated SIR1 recovery transaction identity.
///
/// This is the only identity bound by both sealed proofs. It commits the
/// SIR1, previous provider, previous runtime/lifecycle scope, complete ordered
/// live-attempt set, and the root-selected recovery-peer slot.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct RecoveryTransactionIdentity {
    sir1_digest: [u8; 32],
    previous_provider_binding_digest: [u8; 32],
    previous_runtime_instance_id: [u8; 16],
    previous_lifecycle_scope_id: [u8; 16],
    previous_live_attempt_ids: Vec<[u8; 16]>,
    recovery_peer_slot: RecoveryPeerSlot,
}

impl RecoveryTransactionIdentity {
    fn from_authenticated_sir1(
        sir1_digest: [u8; 32],
        previous_provider_binding_digest: [u8; 32],
        previous_runtime_instance_id: [u8; 16],
        previous_lifecycle_scope_id: [u8; 16],
        previous_live_attempt_ids: Vec<[u8; 16]>,
        recovery_peer_slot: RecoveryPeerSlot,
    ) -> Result<Self, RecoveryDomainError> {
        if sir1_digest == [0; 32]
            || previous_provider_binding_digest == [0; 32]
            || previous_runtime_instance_id == [0; 16]
            || previous_lifecycle_scope_id == [0; 16]
            || previous_runtime_instance_id == previous_lifecycle_scope_id
            || previous_live_attempt_ids.len() > MAX_LIVE_ATTEMPTS
            || previous_live_attempt_ids.contains(&[0; 16])
            || !previous_live_attempt_ids
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        {
            Err(RecoveryDomainError::InvalidTransactionIdentity)
        } else {
            Ok(Self {
                sir1_digest,
                previous_provider_binding_digest,
                previous_runtime_instance_id,
                previous_lifecycle_scope_id,
                previous_live_attempt_ids,
                recovery_peer_slot,
            })
        }
    }

    /// Exact SIR1 self-digest for this recovery transaction.
    #[must_use]
    pub(crate) const fn sir1_digest(&self) -> [u8; 32] {
        self.sir1_digest
    }

    /// Exact prior-provider binding committed by SIR1.
    #[must_use]
    pub(crate) const fn previous_provider_binding_digest(&self) -> [u8; 32] {
        self.previous_provider_binding_digest
    }

    /// Exact previous root-selected runtime identity.
    #[must_use]
    pub(crate) const fn previous_runtime_instance_id(&self) -> [u8; 16] {
        self.previous_runtime_instance_id
    }

    /// Exact previous root-selected lifecycle scope.
    #[must_use]
    pub(crate) const fn previous_lifecycle_scope_id(&self) -> [u8; 16] {
        self.previous_lifecycle_scope_id
    }

    /// Full SIR1-committed live-attempt set, in canonical order.
    #[must_use]
    pub(crate) fn previous_live_attempt_ids(&self) -> &[[u8; 16]] {
        &self.previous_live_attempt_ids
    }

    /// Exact root-selected recovery-peer slot.
    #[must_use]
    pub(crate) const fn recovery_peer_slot(&self) -> &RecoveryPeerSlot {
        &self.recovery_peer_slot
    }

    fn binding_digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(RECOVERY_IDENTITY_DOMAIN);
        hasher.update(&self.sir1_digest);
        hasher.update(&self.previous_provider_binding_digest);
        hasher.update(&self.previous_runtime_instance_id);
        hasher.update(&self.previous_lifecycle_scope_id);
        for attempt_id in &self.previous_live_attempt_ids {
            hasher.update(attempt_id);
        }
        hasher.update(&self.recovery_peer_slot.runtime_instance_id);
        hasher.update(&self.recovery_peer_slot.lifecycle_scope_id);
        hasher.update(&self.recovery_peer_slot.endpoint_id);
        *hasher.finalize().as_bytes()
    }
}

/// Authenticated SIR1 recovery state before any termination work begins.
///
/// The canonical SIR1 decoder is the only intended caller of
/// [`Self::from_authenticated_sir1`]. This value has no decode, clone, or
/// reconstruction path after a proof begins consuming it.
#[must_use]
#[derive(Debug)]
pub(crate) struct PendingRecovery {
    identity: RecoveryTransactionIdentity,
}

impl PendingRecovery {
    /// Enter the sealed state machine from already authenticated SIR1 fields.
    ///
    /// # Errors
    /// Returns a closed failure when authenticated fields cannot express one
    /// canonical recovery transaction identity.
    pub(crate) fn from_authenticated_sir1(
        sir1_digest: [u8; 32],
        previous_provider_binding_digest: [u8; 32],
        previous_runtime_instance_id: [u8; 16],
        previous_lifecycle_scope_id: [u8; 16],
        previous_live_attempt_ids: Vec<[u8; 16]>,
        recovery_peer_slot: RecoveryPeerSlot,
    ) -> Result<Self, RecoveryDomainError> {
        RecoveryTransactionIdentity::from_authenticated_sir1(
            sir1_digest,
            previous_provider_binding_digest,
            previous_runtime_instance_id,
            previous_lifecycle_scope_id,
            previous_live_attempt_ids,
            recovery_peer_slot,
        )
        .map(|identity| Self { identity })
    }

    /// Consume the pending transaction after the exact previous scope is empty.
    ///
    /// # Errors
    /// Returns the closed lifecycle-port failure. On failure the pending
    /// transaction is consumed, so callers cannot retry with substitute proof
    /// inputs or begin a peer for an unproven prior runtime.
    pub(crate) fn terminate_previous_runtime(
        self,
        lifecycle: &mut impl PreviousRuntimeTerminationPort,
    ) -> Result<PreviousRuntimeTerminationProof<Unconsumed>, RecoveryDomainError> {
        lifecycle
            .terminate_and_reconcile(&PreviousRuntimeTerminationRequest {
                identity: &self.identity,
            })
            .map(|()| PreviousRuntimeTerminationProof {
                identity: self.identity,
                state: PhantomData,
            })
    }
}

/// Typed request delivered to #214's previous-runtime lifecycle adapter.
///
/// The request borrows a sealed identity. It never accepts caller-provided
/// runtime, lifecycle, attempt, or resource identifiers.
#[derive(Debug)]
pub(crate) struct PreviousRuntimeTerminationRequest<'a> {
    identity: &'a RecoveryTransactionIdentity,
}

impl PreviousRuntimeTerminationRequest<'_> {
    /// SIR1-bound recovery transaction identity.
    #[must_use]
    pub(crate) const fn transaction_identity(&self) -> &RecoveryTransactionIdentity {
        self.identity
    }
}

/// Port implemented by #214's root-owned previous-runtime lifecycle adapter.
///
/// A successful return means the adapter terminated the exact SIR1-bound
/// runtime, descendants, live attempts, and transaction-owned resources, then
/// reconciled the whole scope to empty. This module deliberately does not
/// implement systemd or process cleanup.
pub(crate) trait PreviousRuntimeTerminationPort {
    /// Terminate and reconcile the exact sealed previous-runtime scope.
    fn terminate_and_reconcile(
        &mut self,
        request: &PreviousRuntimeTerminationRequest<'_>,
    ) -> Result<(), RecoveryDomainError>;
}

/// Marker carried by a previous-runtime proof before recovery-peer start.
#[derive(Debug)]
pub(crate) struct Unconsumed {
    _private: (),
}

/// Marker carried by a previous-runtime proof after peer exchange and cleanup.
#[derive(Debug)]
pub(crate) struct Consumed {
    _private: (),
}

/// Non-serializable proof that the exact previous SIR1-bound scope is empty.
///
/// It is linear: it has no clone, decoder, public constructor, or conversion
/// back to [`Unconsumed`]. Starting a peer consumes the unconsumed state.
#[must_use]
#[derive(Debug)]
pub(crate) struct PreviousRuntimeTerminationProof<State> {
    identity: RecoveryTransactionIdentity,
    state: PhantomData<State>,
}

impl PreviousRuntimeTerminationProof<Unconsumed> {
    /// Start the one recovery peer allocated by the sealed SIR1 identity.
    ///
    /// # Errors
    /// Returns the closed peer-start failure. On failure the unconsumed proof
    /// is consumed, preventing a retry with another endpoint or identity.
    pub(crate) fn start_recovery_peer(
        self,
        peer: &mut impl RecoveryPeerPort,
    ) -> Result<RecoveryPeerSession, RecoveryDomainError> {
        peer.start(&RecoveryPeerRequest {
            identity: &self.identity,
        })
        .map(|()| RecoveryPeerSession { previous: self })
    }
}

/// Typed request delivered to the dedicated recovery-peer transport adapter.
///
/// It is built only by the state machine and binds both the recovery exchange
/// and RCA1 authentication to one [`RecoveryTransactionIdentity`].
#[derive(Debug)]
pub(crate) struct RecoveryPeerRequest<'a> {
    identity: &'a RecoveryTransactionIdentity,
}

impl RecoveryPeerRequest<'_> {
    /// SIR1-bound recovery transaction identity.
    #[must_use]
    pub(crate) const fn transaction_identity(&self) -> &RecoveryTransactionIdentity {
        self.identity
    }
}

/// Raw recovery-peer result returned only after the adapter's peer cleanup.
///
/// This is not a proof: its RCA1 bytes must still be authenticated through
/// [`RecoveryResponseAuthenticator`] before the state machine can transition.
#[derive(Debug)]
pub(crate) struct RecoveryPeerExchange {
    acknowledgement_bytes: Vec<u8>,
    recovery_peer_pid: u64,
    recovery_peer_start_time_ticks: u64,
}

impl RecoveryPeerExchange {
    /// Construct the adapter result after the peer scope has been cleaned up.
    ///
    /// # Errors
    /// Returns a closed failure for an absent RCA1 payload or invalid peer PID.
    pub(crate) fn after_cleanup(
        acknowledgement_bytes: Vec<u8>,
        recovery_peer_pid: u64,
        recovery_peer_start_time_ticks: u64,
    ) -> Result<Self, RecoveryDomainError> {
        if acknowledgement_bytes.is_empty() {
            Err(RecoveryDomainError::RecoveryAcknowledgementRejected)
        } else if recovery_peer_pid == 0 {
            Err(RecoveryDomainError::RecoveryPeerIdentityInvalid)
        } else {
            Ok(Self {
                acknowledgement_bytes,
                recovery_peer_pid,
                recovery_peer_start_time_ticks,
            })
        }
    }
}

/// Port implemented by #354's recovery-peer socket and #214 cleanup adapter.
///
/// Its second operation may return only after the dedicated peer has reached
/// EOF and its complete transaction-owned resource scope was reconciled empty.
/// It returns raw RCA1 bytes; authentication remains a separate mandatory
/// recovery-domain operation.
pub(crate) trait RecoveryPeerPort {
    /// Start the recovery peer at the root-selected slot.
    fn start(&mut self, request: &RecoveryPeerRequest<'_>) -> Result<(), RecoveryDomainError>;

    /// Exchange with the started peer and clean up its exact resource scope.
    fn exchange_and_cleanup(
        &mut self,
        request: &RecoveryPeerRequest<'_>,
    ) -> Result<RecoveryPeerExchange, RecoveryDomainError>;
}

/// Opaque RCA1 digest released only by the selector's authenticated verifier.
#[derive(Debug)]
pub(crate) struct AuthenticatedRecoveryAcknowledgement {
    acknowledgement_digest: [u8; 32],
}

impl AuthenticatedRecoveryAcknowledgement {
    /// Seal an exact nonzero RCA1 self-digest after authentication.
    ///
    /// # Errors
    /// Returns a closed failure for the absent sentinel digest.
    pub(crate) const fn from_authenticated_rca1(
        acknowledgement_digest: [u8; 32],
    ) -> Result<Self, RecoveryDomainError> {
        if acknowledgement_digest == [0; 32] {
            Err(RecoveryDomainError::RecoveryAcknowledgementRejected)
        } else {
            Ok(Self {
                acknowledgement_digest,
            })
        }
    }

    fn digest(&self) -> [u8; 32] {
        self.acknowledgement_digest
    }
}

/// Mandatory RCA1 authentication port for the exact sealed transaction.
///
/// #354 will adapt the selector's retained previous runtime key and RCU1/RCC1
/// state to this port. The transport adapter cannot bypass this interface by
/// returning a digest instead of raw response bytes.
pub(crate) trait RecoveryResponseAuthenticator {
    /// Authenticate raw RCA1 for the exact recovery-peer request.
    fn authenticate(
        &mut self,
        request: &RecoveryPeerRequest<'_>,
        acknowledgement_bytes: &[u8],
    ) -> Result<AuthenticatedRecoveryAcknowledgement, RecoveryDomainError>;
}

/// Private linear owner of an in-flight recovery-peer exchange.
///
/// The session holds the only unconsumed previous-runtime proof. It can return
/// completion proofs only after both cleanup and response authentication.
#[must_use]
#[derive(Debug)]
pub(crate) struct RecoveryPeerSession {
    previous: PreviousRuntimeTerminationProof<Unconsumed>,
}

impl RecoveryPeerSession {
    /// Authenticate RCA1 and finish cleanup before releasing both proofs.
    ///
    /// # Errors
    /// Returns a closed exchange, cleanup, or authentication failure. In every
    /// failure case the private session is consumed and no proof is released.
    pub(crate) fn authenticate_and_cleanup(
        self,
        peer: &mut impl RecoveryPeerPort,
        authenticator: &mut impl RecoveryResponseAuthenticator,
    ) -> Result<
        (
            PreviousRuntimeTerminationProof<Consumed>,
            RecoveryPeerTerminationProof,
        ),
        RecoveryDomainError,
    > {
        let request = RecoveryPeerRequest {
            identity: &self.previous.identity,
        };
        peer.exchange_and_cleanup(&request).and_then(|exchange| {
            authenticator
                .authenticate(&request, &exchange.acknowledgement_bytes)
                .map(|acknowledgement| {
                    let transaction_binding_digest = self.previous.identity.binding_digest();
                    let previous = PreviousRuntimeTerminationProof {
                        identity: self.previous.identity,
                        state: PhantomData,
                    };
                    let recovery_peer = RecoveryPeerTerminationProof {
                        transaction_binding_digest,
                        acknowledgement_digest: acknowledgement.digest(),
                        recovery_peer_pid: exchange.recovery_peer_pid,
                        recovery_peer_start_time_ticks: exchange.recovery_peer_start_time_ticks,
                    };
                    (previous, recovery_peer)
                })
        })
    }
}

/// Non-serializable proof that the recovery peer's exact scope is empty.
///
/// This proof is bound to one [`RecoveryTransactionIdentity`], the exact
/// authenticated RCA1 digest, and the observed recovery-peer PID/start-time.
#[must_use]
#[derive(Debug)]
pub(crate) struct RecoveryPeerTerminationProof {
    transaction_binding_digest: [u8; 32],
    acknowledgement_digest: [u8; 32],
    recovery_peer_pid: u64,
    recovery_peer_start_time_ticks: u64,
}

/// Matched sealed capabilities ready for #354's durable recovery completion.
#[must_use]
#[derive(Debug)]
pub(crate) struct RecoveryCompletion {
    identity: RecoveryTransactionIdentity,
    acknowledgement_digest: [u8; 32],
    recovery_peer_pid: u64,
    recovery_peer_start_time_ticks: u64,
}

impl RecoveryCompletion {
    /// Exact SIR1-bound identity whose durable recovery may now complete.
    #[must_use]
    pub(crate) const fn transaction_identity(&self) -> &RecoveryTransactionIdentity {
        &self.identity
    }

    /// Exact authenticated RCA1 self-digest.
    #[must_use]
    pub(crate) const fn acknowledgement_digest(&self) -> [u8; 32] {
        self.acknowledgement_digest
    }

    /// Exact observed recovery-peer PID.
    #[must_use]
    pub(crate) const fn recovery_peer_pid(&self) -> u64 {
        self.recovery_peer_pid
    }

    /// Exact observed recovery-peer process start time.
    #[must_use]
    pub(crate) const fn recovery_peer_start_time_ticks(&self) -> u64 {
        self.recovery_peer_start_time_ticks
    }
}

/// Match the consumed previous proof and recovery-peer proof for finalization.
///
/// # Errors
/// Returns a closed failure when the proof pair is from different SIR1
/// transactions. Both arguments are consumed in every outcome.
pub(crate) fn complete_recovery(
    previous: PreviousRuntimeTerminationProof<Consumed>,
    recovery_peer: RecoveryPeerTerminationProof,
) -> Result<RecoveryCompletion, RecoveryDomainError> {
    if previous.identity.binding_digest() != recovery_peer.transaction_binding_digest {
        Err(RecoveryDomainError::CrossTransactionProof)
    } else {
        Ok(RecoveryCompletion {
            identity: previous.identity,
            acknowledgement_digest: recovery_peer.acknowledgement_digest,
            recovery_peer_pid: recovery_peer.recovery_peer_pid,
            recovery_peer_start_time_ticks: recovery_peer.recovery_peer_start_time_ticks,
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    struct RecordingLifecyclePort {
        result: Result<(), RecoveryDomainError>,
        observed_binding: Option<[u8; 32]>,
    }

    impl PreviousRuntimeTerminationPort for RecordingLifecyclePort {
        fn terminate_and_reconcile(
            &mut self,
            request: &PreviousRuntimeTerminationRequest<'_>,
        ) -> Result<(), RecoveryDomainError> {
            self.observed_binding = Some(request.transaction_identity().binding_digest());
            self.result
        }
    }

    struct RecordingRecoveryPeerPort {
        start_result: Result<(), RecoveryDomainError>,
        exchange_result: Option<Result<RecoveryPeerExchange, RecoveryDomainError>>,
        observed_start_binding: Option<[u8; 32]>,
        observed_exchange_binding: Option<[u8; 32]>,
    }

    impl RecoveryPeerPort for RecordingRecoveryPeerPort {
        fn start(&mut self, request: &RecoveryPeerRequest<'_>) -> Result<(), RecoveryDomainError> {
            self.observed_start_binding = Some(request.transaction_identity().binding_digest());
            self.start_result
        }

        fn exchange_and_cleanup(
            &mut self,
            request: &RecoveryPeerRequest<'_>,
        ) -> Result<RecoveryPeerExchange, RecoveryDomainError> {
            self.observed_exchange_binding =
                Some(request.transaction_identity().binding_digest());
            self.exchange_result
                .take()
                .unwrap_or(Err(RecoveryDomainError::RecoveryPeerExchangeOrCleanupRejected))
        }
    }

    struct RecordingAuthenticator {
        result: Option<Result<AuthenticatedRecoveryAcknowledgement, RecoveryDomainError>>,
        observed_binding: Option<[u8; 32]>,
        observed_response: Option<Vec<u8>>,
    }

    impl RecoveryResponseAuthenticator for RecordingAuthenticator {
        fn authenticate(
            &mut self,
            request: &RecoveryPeerRequest<'_>,
            acknowledgement_bytes: &[u8],
        ) -> Result<AuthenticatedRecoveryAcknowledgement, RecoveryDomainError> {
            self.observed_binding = Some(request.transaction_identity().binding_digest());
            self.observed_response = Some(acknowledgement_bytes.to_vec());
            self.result
                .take()
                .unwrap_or(Err(RecoveryDomainError::RecoveryAcknowledgementRejected))
        }
    }

    fn pending(seed: u8) -> Result<PendingRecovery, RecoveryDomainError> {
        let slot = RecoveryPeerSlot::from_authenticated_sir1(
            [seed.wrapping_add(4); 16],
            [seed.wrapping_add(5); 16],
            [seed.wrapping_add(6); 16],
        )?;
        PendingRecovery::from_authenticated_sir1(
            [seed; 32],
            [seed.wrapping_add(1); 32],
            [seed.wrapping_add(2); 16],
            [seed.wrapping_add(3); 16],
            vec![[seed.wrapping_add(7); 16], [seed.wrapping_add(8); 16]],
            slot,
        )
    }

    fn successful_lifecycle() -> RecordingLifecyclePort {
        RecordingLifecyclePort {
            result: Ok(()),
            observed_binding: None,
        }
    }

    fn successful_peer() -> Result<RecordingRecoveryPeerPort, RecoveryDomainError> {
        Ok(RecordingRecoveryPeerPort {
            start_result: Ok(()),
            exchange_result: Some(RecoveryPeerExchange::after_cleanup(vec![1, 2], 7, 11)),
            observed_start_binding: None,
            observed_exchange_binding: None,
        })
    }

    fn successful_authenticator() -> Result<RecordingAuthenticator, RecoveryDomainError> {
        Ok(RecordingAuthenticator {
            result: Some(AuthenticatedRecoveryAcknowledgement::from_authenticated_rca1([9; 32])),
            observed_binding: None,
            observed_response: None,
        })
    }

    fn complete(seed: u8) -> Result<
        (
            PreviousRuntimeTerminationProof<Consumed>,
            RecoveryPeerTerminationProof,
        ),
        RecoveryDomainError,
    > {
        let mut lifecycle = successful_lifecycle();
        let previous = pending(seed)?.terminate_previous_runtime(&mut lifecycle)?;
        let mut peer = successful_peer()?;
        let session = previous.start_recovery_peer(&mut peer)?;
        let mut authenticator = successful_authenticator()?;
        session.authenticate_and_cleanup(&mut peer, &mut authenticator)
    }

    fn assert_error<T>(result: Result<T, RecoveryDomainError>, expected: RecoveryDomainError) {
        assert_eq!(result.err(), Some(expected));
    }

    #[test]
    fn recovery_identity_rejects_ambiguous_sir1_fields() -> Result<(), RecoveryDomainError> {
        let valid_slot = RecoveryPeerSlot::from_authenticated_sir1([4; 16], [5; 16], [6; 16])?;
        assert_error(
            PendingRecovery::from_authenticated_sir1(
                [0; 32],
                [1; 32],
                [2; 16],
                [3; 16],
                Vec::new(),
                valid_slot,
            ),
            RecoveryDomainError::InvalidTransactionIdentity,
        );
        assert_error(
            RecoveryPeerSlot::from_authenticated_sir1([1; 16], [1; 16], [2; 16]),
            RecoveryDomainError::InvalidTransactionIdentity,
        );
        let slot = RecoveryPeerSlot::from_authenticated_sir1([4; 16], [5; 16], [6; 16])?;
        assert_error(
            PendingRecovery::from_authenticated_sir1(
                [1; 32],
                [2; 32],
                [3; 16],
                [4; 16],
                vec![[7; 16], [7; 16]],
                slot,
            ),
            RecoveryDomainError::InvalidTransactionIdentity,
        );
        assert_error(
            RecoveryPeerExchange::after_cleanup(Vec::new(), 7, 11),
            RecoveryDomainError::RecoveryAcknowledgementRejected,
        );
        assert_error(
            RecoveryPeerExchange::after_cleanup(vec![1], 0, 11),
            RecoveryDomainError::RecoveryPeerIdentityInvalid,
        );
        assert_error(
            AuthenticatedRecoveryAcknowledgement::from_authenticated_rca1([0; 32]),
            RecoveryDomainError::RecoveryAcknowledgementRejected,
        );
        Ok(())
    }

    #[test]
    fn recovery_transitions_only_after_lifecycle_peer_and_rca1_authentication(
    ) -> Result<(), RecoveryDomainError> {
        let mut lifecycle = successful_lifecycle();
        let previous = pending(1)?.terminate_previous_runtime(&mut lifecycle)?;
        let binding = lifecycle
            .observed_binding
            .ok_or(RecoveryDomainError::PreviousRuntimeTerminationRejected)?;
        let mut peer = successful_peer()?;
        let session = previous.start_recovery_peer(&mut peer)?;
        assert_eq!(peer.observed_start_binding, Some(binding));
        let mut authenticator = successful_authenticator()?;
        let (consumed, recovery_peer) =
            session.authenticate_and_cleanup(&mut peer, &mut authenticator)?;
        assert_eq!(peer.observed_exchange_binding, Some(binding));
        assert_eq!(authenticator.observed_binding, Some(binding));
        assert_eq!(authenticator.observed_response, Some(vec![1, 2]));
        let completion = complete_recovery(consumed, recovery_peer)?;
        let identity = completion.transaction_identity();
        assert_eq!(identity.sir1_digest(), [1; 32]);
        assert_eq!(identity.previous_provider_binding_digest(), [2; 32]);
        assert_eq!(identity.previous_runtime_instance_id(), [3; 16]);
        assert_eq!(identity.previous_lifecycle_scope_id(), [4; 16]);
        assert_eq!(identity.previous_live_attempt_ids(), &[[8; 16], [9; 16]]);
        let slot = identity.recovery_peer_slot();
        assert_eq!(slot.runtime_instance_id(), [5; 16]);
        assert_eq!(slot.lifecycle_scope_id(), [6; 16]);
        assert_eq!(slot.endpoint_id(), [7; 16]);
        assert_eq!(completion.acknowledgement_digest(), [9; 32]);
        assert_eq!(completion.recovery_peer_pid(), 7);
        assert_eq!(completion.recovery_peer_start_time_ticks(), 11);
        Ok(())
    }

    #[test]
    fn recovery_fails_closed_at_each_typed_port() -> Result<(), RecoveryDomainError> {
        let mut rejected_lifecycle = RecordingLifecyclePort {
            result: Err(RecoveryDomainError::PreviousRuntimeTerminationRejected),
            observed_binding: None,
        };
        assert_error(
            pending(1)?.terminate_previous_runtime(&mut rejected_lifecycle),
            RecoveryDomainError::PreviousRuntimeTerminationRejected,
        );

        let mut lifecycle = successful_lifecycle();
        let previous = pending(2)?.terminate_previous_runtime(&mut lifecycle)?;
        let mut rejected_start = RecordingRecoveryPeerPort {
            start_result: Err(RecoveryDomainError::RecoveryPeerStartRejected),
            exchange_result: None,
            observed_start_binding: None,
            observed_exchange_binding: None,
        };
        assert_error(
            previous.start_recovery_peer(&mut rejected_start),
            RecoveryDomainError::RecoveryPeerStartRejected,
        );

        let previous = pending(3)?.terminate_previous_runtime(&mut lifecycle)?;
        let mut cleanup_failure = RecordingRecoveryPeerPort {
            start_result: Ok(()),
            exchange_result: Some(Err(RecoveryDomainError::RecoveryPeerExchangeOrCleanupRejected)),
            observed_start_binding: None,
            observed_exchange_binding: None,
        };
        let session = previous.start_recovery_peer(&mut cleanup_failure)?;
        let mut authenticator = successful_authenticator()?;
        assert_error(
            session.authenticate_and_cleanup(&mut cleanup_failure, &mut authenticator),
            RecoveryDomainError::RecoveryPeerExchangeOrCleanupRejected,
        );

        let previous = pending(4)?.terminate_previous_runtime(&mut lifecycle)?;
        let mut peer = successful_peer()?;
        let session = previous.start_recovery_peer(&mut peer)?;
        let mut rejected_authenticator = RecordingAuthenticator {
            result: Some(Err(RecoveryDomainError::RecoveryAcknowledgementRejected)),
            observed_binding: None,
            observed_response: None,
        };
        assert_error(
            session.authenticate_and_cleanup(&mut peer, &mut rejected_authenticator),
            RecoveryDomainError::RecoveryAcknowledgementRejected,
        );
        Ok(())
    }

    #[test]
    fn recovery_completion_rejects_cross_transaction_proofs() -> Result<(), RecoveryDomainError> {
        let (previous, _) = complete(1)?;
        let (_, recovery_peer) = complete(2)?;
        assert_error(
            complete_recovery(previous, recovery_peer),
            RecoveryDomainError::CrossTransactionProof,
        );
        Ok(())
    }
}
