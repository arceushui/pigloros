//! Stateful selector validation for RCU1 revocation updates and RCA1 acknowledgements.

use std::collections::BTreeMap;

use ciborium::value::Value;

use super::codec::{
    bounded_array, byte_string, decode_document, digest32, id16, key_id, require_canonical_order,
    signed, uint, verify_digest, verify_signature,
};
use super::{
    SandboxProviderProtocolError, SandboxRevocationSnapshot, SandboxTrustError, SandboxTrustRole,
    SandboxTrustSnapshot,
};

const REVOCATION_ACK_DEADLINE_MS: u64 = 100;

/// Closed selector-side revocation-update failures.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SandboxRevocationUpdateError {
    /// A request or acknowledgement violates its wire contract.
    #[error(transparent)]
    Protocol(#[from] SandboxProviderProtocolError),
    /// A signer or authority snapshot is invalid.
    #[error(transparent)]
    Trust(#[from] SandboxTrustError),
    /// A request identity was reused with different canonical bytes.
    #[error("sandbox revocation request identity conflicts with retained state")]
    RequestIdentityConflict,
    /// Another revocation update is awaiting acknowledgement.
    #[error("sandbox revocation update is already in flight")]
    UpdateInFlight,
    /// The provider did not acknowledge cancellation before the deadline.
    #[error("sandbox revocation acknowledgement deadline expired")]
    AcknowledgementDeadline,
    /// RCA1 does not acknowledge the exact pending update and cancellation set.
    #[error("sandbox revocation acknowledgement does not match the pending update")]
    AcknowledgementMismatch,
}

/// Administrator-authenticated RCU1 request and its next RVS1 snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationUpdateRequest {
    /// Stable idempotency identity.
    pub request_id: [u8; 16],
    /// RVS1 that was current when this update began.
    pub previous_revocation_digest: [u8; 32],
    /// Authenticated immediate-successor RVS1.
    pub next_revocation: SandboxRevocationSnapshot,
    /// Fresh selector nonce.
    pub selector_nonce: [u8; 16],
    /// Administrator-policy signer.
    pub policy_signer_key_id: String,
    /// Exact RCU1 self-digest.
    pub request_digest: [u8; 32],
    signature: [u8; 64],
}

impl RevocationUpdateRequest {
    /// Authenticate one RCU1 against the selector's current trust and revocation state.
    ///
    /// # Errors
    /// Rejects malformed, forged, stale, skipped, or internally inconsistent updates.
    pub fn authenticate(
        bytes: &[u8],
        trust: &SandboxTrustSnapshot,
        current: &SandboxRevocationSnapshot,
    ) -> Result<Self, SandboxRevocationUpdateError> {
        let document = decode_document(bytes)?;
        let (fields, request_digest, signature) = signed::<8>(&document, "RCU1")?;
        let next_bytes = byte_string(&fields[4])?;
        let request = Self {
            request_id: id16(&fields[2])?,
            previous_revocation_digest: digest32(&fields[3])?,
            next_revocation: SandboxRevocationSnapshot::authenticate(next_bytes, trust)?,
            selector_nonce: id16(&fields[6])?,
            policy_signer_key_id: key_id(&fields[7])?,
            request_digest,
            signature,
        };
        request.validate(fields, trust, current)?;
        Ok(request)
    }

    fn validate(
        &self,
        unsigned: &[Value; 8],
        trust: &SandboxTrustSnapshot,
        current: &SandboxRevocationSnapshot,
    ) -> Result<(), SandboxRevocationUpdateError> {
        if self.previous_revocation_digest != current.snapshot_digest()
            || digest32(&unsigned[5])? != self.next_revocation.snapshot_digest()
        {
            return Err(SandboxTrustError::AuthorityMismatch.into());
        }
        current.validate_immediate_epoch_for_same_registry(&self.next_revocation)?;
        verify_digest("RCU1", unsigned, self.request_digest)?;
        let key = current.active_key(
            trust,
            &self.policy_signer_key_id,
            SandboxTrustRole::AdministratorPolicy,
        )?;
        verify_signature("RCU1", &self.request_digest, &self.signature, &key).map_err(Into::into)
    }
}

/// Runtime-authenticated RCA1 acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationAcknowledgement {
    /// RCU1 request identity.
    pub request_id: [u8; 16],
    /// Newly installed RVS1 digest.
    pub revocation_digest: [u8; 32],
    /// Canonically ordered attempts cancelled before acknowledgement.
    pub cancelled_attempt_ids: Vec<[u8; 16]>,
    /// Runtime-attestation signer.
    pub runtime_attestation_key_id: String,
    /// Exact RCA1 self-digest.
    pub acknowledgement_digest: [u8; 32],
    signature: [u8; 64],
}

impl RevocationAcknowledgement {
    pub(super) fn authenticate(
        bytes: &[u8],
        runtime_key_id: &str,
        runtime_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<Self, SandboxRevocationUpdateError> {
        let document = decode_document(bytes)?;
        let (fields, acknowledgement_digest, signature) = signed::<7>(&document, "RCA1")?;
        if uint(&fields[5])? != 0 {
            return Err(SandboxProviderProtocolError::InconsistentFields.into());
        }
        let cancelled_values = bounded_array(&fields[4], 0)?;
        require_canonical_order(cancelled_values)?;
        let acknowledgement = Self {
            request_id: id16(&fields[2])?,
            revocation_digest: digest32(&fields[3])?,
            cancelled_attempt_ids: cancelled_values
                .iter()
                .map(id16)
                .collect::<Result<Vec<_>, _>>()?,
            runtime_attestation_key_id: key_id(&fields[6])?,
            acknowledgement_digest,
            signature,
        };
        verify_digest("RCA1", fields, acknowledgement.acknowledgement_digest)?;
        if acknowledgement.runtime_attestation_key_id != runtime_key_id {
            return Err(SandboxRevocationUpdateError::AcknowledgementMismatch);
        }
        verify_signature(
            "RCA1",
            &acknowledgement.acknowledgement_digest,
            &acknowledgement.signature,
            runtime_key,
        )?;
        Ok(acknowledgement)
    }
}

#[derive(Clone, Debug)]
struct PendingRevocationUpdate {
    request: RevocationUpdateRequest,
    wire_digest: [u8; 32],
    expected_cancelled_attempt_ids: Vec<[u8; 16]>,
    deadline_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CompletedRevocationUpdate {
    request: [u8; 32],
    wire: [u8; 32],
    acknowledgement: [u8; 32],
}

impl CompletedRevocationUpdate {
    const fn matches_request(self, identity: RequestIdentity) -> bool {
        self.request == identity.request_digest && self.wire == identity.wire_digest
    }
}

/// Selector-owned state that serializes revocation transitions and retains replay identity.
#[derive(Clone, Debug)]
pub struct SelectorRevocationState {
    current: SandboxRevocationSnapshot,
    pending: Option<PendingRevocationUpdate>,
    completed: BTreeMap<[u8; 16], CompletedRevocationUpdate>,
}

impl SelectorRevocationState {
    /// Start with the selector's authenticated current RVS1.
    #[must_use]
    pub const fn new(current: SandboxRevocationSnapshot) -> Self {
        Self {
            current,
            pending: None,
            completed: BTreeMap::new(),
        }
    }

    /// Authenticate and retain one in-flight RCU1 transition.
    ///
    /// `now_ms` is supplied by the selector's monotonic clock. The caller must
    /// pass the exact sorted identities of attempts that the provider must cancel.
    ///
    /// # Errors
    /// Rejects identity conflicts, concurrent updates, invalid authority, and
    /// unsorted or duplicate cancellation identities.
    pub fn begin_update(
        &mut self,
        bytes: &[u8],
        trust: &SandboxTrustSnapshot,
        expected_cancelled_attempt_ids: Vec<[u8; 16]>,
        now_ms: u64,
    ) -> Result<(), SandboxRevocationUpdateError> {
        validate_cancelled_attempts(&expected_cancelled_attempt_ids)?;
        let identity = request_identity(bytes)?;
        if let Some(completed) = self.completed.get(&identity.request_id) {
            return if completed.matches_request(identity) {
                Ok(())
            } else {
                Err(SandboxRevocationUpdateError::RequestIdentityConflict)
            };
        }
        if let Some(pending) = &self.pending {
            return if pending.request.request_id == identity.request_id
                && pending.request.request_digest == identity.request_digest
                && pending.wire_digest == identity.wire_digest
            {
                Ok(())
            } else if pending.request.request_id == identity.request_id {
                Err(SandboxRevocationUpdateError::RequestIdentityConflict)
            } else {
                Err(SandboxRevocationUpdateError::UpdateInFlight)
            };
        }
        let request = RevocationUpdateRequest::authenticate(bytes, trust, &self.current)?;
        let deadline_ms = now_ms
            .checked_add(REVOCATION_ACK_DEADLINE_MS)
            .ok_or(SandboxRevocationUpdateError::AcknowledgementDeadline)?;
        self.pending = Some(PendingRevocationUpdate {
            request,
            wire_digest: identity.wire_digest,
            expected_cancelled_attempt_ids,
            deadline_ms,
        });
        Ok(())
    }

    /// Authenticate RCA1, require exact cancellation, and atomically advance RVS1.
    ///
    /// # Errors
    /// Rejects missing/late/forged acknowledgements and any mismatch with RCU1.
    pub fn acknowledge(
        &mut self,
        bytes: &[u8],
        runtime_key_id: &str,
        runtime_key: &ed25519_dalek::VerifyingKey,
        now_ms: u64,
    ) -> Result<(), SandboxRevocationUpdateError> {
        let acknowledgement =
            RevocationAcknowledgement::authenticate(bytes, runtime_key_id, runtime_key)?;
        if let Some(completed) = self.completed.get(&acknowledgement.request_id) {
            return if completed.acknowledgement == acknowledgement.acknowledgement_digest {
                Ok(())
            } else {
                Err(SandboxRevocationUpdateError::RequestIdentityConflict)
            };
        }
        let pending = self
            .pending
            .as_ref()
            .ok_or(SandboxRevocationUpdateError::AcknowledgementMismatch)?;
        if now_ms > pending.deadline_ms {
            return Err(SandboxRevocationUpdateError::AcknowledgementDeadline);
        }
        if acknowledgement.request_id != pending.request.request_id
            || acknowledgement.revocation_digest
                != pending.request.next_revocation.snapshot_digest()
            || acknowledgement.cancelled_attempt_ids != pending.expected_cancelled_attempt_ids
        {
            return Err(SandboxRevocationUpdateError::AcknowledgementMismatch);
        }
        let pending = self
            .pending
            .take()
            .ok_or(SandboxRevocationUpdateError::AcknowledgementMismatch)?;
        self.current = pending.request.next_revocation;
        self.completed.insert(
            acknowledgement.request_id,
            CompletedRevocationUpdate {
                request: pending.request.request_digest,
                wire: pending.wire_digest,
                acknowledgement: acknowledgement.acknowledgement_digest,
            },
        );
        Ok(())
    }

    /// Current RVS1 after every fully acknowledged transition.
    #[must_use]
    pub const fn current(&self) -> &SandboxRevocationSnapshot {
        &self.current
    }
}

#[derive(Clone, Copy)]
struct RequestIdentity {
    request_id: [u8; 16],
    request_digest: [u8; 32],
    wire_digest: [u8; 32],
}

fn request_identity(bytes: &[u8]) -> Result<RequestIdentity, SandboxProviderProtocolError> {
    let document = decode_document(bytes)?;
    let (fields, request_digest, _) = signed::<8>(&document, "RCU1")?;
    Ok(RequestIdentity {
        request_id: id16(&fields[2])?,
        request_digest,
        wire_digest: *blake3::hash(bytes).as_bytes(),
    })
}

fn validate_cancelled_attempts(attempts: &[[u8; 16]]) -> Result<(), SandboxProviderProtocolError> {
    if attempts.len() > 256
        || attempts.contains(&[0; 16])
        || !attempts.windows(2).all(|pair| pair[0] < pair[1])
    {
        Err(SandboxProviderProtocolError::NonCanonicalOrder)
    } else {
        Ok(())
    }
}
