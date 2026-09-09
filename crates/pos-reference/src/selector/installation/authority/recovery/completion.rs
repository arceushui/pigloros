//! Sealed termination evidence for the provider-neutral recovery state machine.

use super::PendingInstallationRecovery;
use crate::sandbox_provider_protocol::AuthenticatedRevocationAcknowledgement;
use crate::selector::SelectorBoundaryError;

/// Root-owned capability held only by the concrete lifecycle adapter.
///
/// There is intentionally no public constructor. Possessing this value means
/// the adapter is inside the selector's privileged termination boundary.
#[derive(Debug)]
pub struct ProviderTerminationAuthority {
    pub(crate) _private: (),
}

impl ProviderTerminationAuthority {
    /// Seal proof that the exact previous runtime, descendants, attempts, and
    /// transaction-owned resource namespace have been reconciled to empty.
    pub fn prove_previous_termination(
        &self,
        recovery: &PendingInstallationRecovery,
    ) -> Result<PreviousRuntimeTerminationProof, SelectorBoundaryError> {
        let snapshot = &recovery.snapshot;
        Ok(PreviousRuntimeTerminationProof {
            sir1_digest: recovery.sir1_digest,
            previous_provider_binding_digest: snapshot.previous_provider_digest()?,
            previous_runtime_ids: snapshot.previous_runtime_ids(),
            previous_live_attempt_ids: snapshot.previous_live_attempt_ids().to_vec(),
            recovery_slot_ids: snapshot.recovery_slot_ids(),
            proof_identity: random_id(),
        })
    }

    /// Seal proof that the dedicated recovery peer and every slot-owned
    /// resource are absent after authenticated RCA1 and server EOF.
    ///
    /// # Errors
    /// Rejects a zero peer PID or an acknowledgement/proof from another transaction.
    pub fn prove_recovery_peer_termination(
        &self,
        recovery: &PendingInstallationRecovery,
        previous: &PreviousRuntimeTerminationProof,
        acknowledgement: &AuthenticatedRevocationAcknowledgement,
        recovery_peer_pid: u64,
        recovery_peer_start_time_ticks: u64,
    ) -> Result<RecoveryPeerTerminationProof, SelectorBoundaryError> {
        recovery.verify_previous_proof(previous)?;
        recovery.verify_acknowledgement(acknowledgement)?;
        if recovery_peer_pid == 0 {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        Ok(RecoveryPeerTerminationProof {
            sir1_digest: recovery.sir1_digest,
            previous_proof_identity: previous.proof_identity,
            recovery_slot_ids: recovery.snapshot.recovery_slot_ids(),
            recovery_peer_pid,
            recovery_peer_start_time_ticks,
            acknowledgement_digest: acknowledgement.acknowledgement_digest(),
            proof_identity: random_id(),
        })
    }
}

/// Non-serializable proof that the exact previous provider scope is empty.
#[derive(Debug)]
pub struct PreviousRuntimeTerminationProof {
    sir1_digest: [u8; 32],
    previous_provider_binding_digest: [u8; 32],
    previous_runtime_ids: ([u8; 16], [u8; 16]),
    previous_live_attempt_ids: Vec<[u8; 16]>,
    recovery_slot_ids: [[u8; 16]; 3],
    proof_identity: [u8; 16],
}

/// Non-serializable proof that the dedicated recovery peer scope is empty.
#[derive(Debug)]
pub struct RecoveryPeerTerminationProof {
    sir1_digest: [u8; 32],
    previous_proof_identity: [u8; 16],
    recovery_slot_ids: [[u8; 16]; 3],
    recovery_peer_pid: u64,
    recovery_peer_start_time_ticks: u64,
    acknowledgement_digest: [u8; 32],
    proof_identity: [u8; 16],
}

impl PendingInstallationRecovery {
    pub(super) fn verify_previous_proof(
        &self,
        proof: &PreviousRuntimeTerminationProof,
    ) -> Result<(), SelectorBoundaryError> {
        let snapshot = &self.snapshot;
        if proof.sir1_digest != self.sir1_digest
            || proof.previous_provider_binding_digest != snapshot.previous_provider_digest()?
            || proof.previous_runtime_ids != snapshot.previous_runtime_ids()
            || proof.previous_live_attempt_ids != snapshot.previous_live_attempt_ids()
            || proof.recovery_slot_ids != snapshot.recovery_slot_ids()
            || proof.proof_identity == [0; 16]
        {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        Ok(())
    }

    pub(super) fn verify_peer_proof(
        &self,
        previous: &PreviousRuntimeTerminationProof,
        acknowledgement: &AuthenticatedRevocationAcknowledgement,
        proof: &RecoveryPeerTerminationProof,
    ) -> Result<(), SelectorBoundaryError> {
        if proof.sir1_digest != self.sir1_digest
            || proof.previous_proof_identity != previous.proof_identity
            || proof.recovery_slot_ids != self.snapshot.recovery_slot_ids()
            || proof.recovery_peer_pid == 0
            || proof.acknowledgement_digest != acknowledgement.acknowledgement_digest()
            || proof.proof_identity == [0; 16]
        {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        let _ = proof.recovery_peer_start_time_ticks;
        Ok(())
    }
}

fn random_id() -> [u8; 16] {
    loop {
        let candidate = rand::random();
        if candidate != [0; 16] {
            return candidate;
        }
    }
}
