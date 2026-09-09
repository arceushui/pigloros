//! Stateful selector validation for RCU1 revocation updates and RCA1 acknowledgements.

use std::collections::BTreeMap;

use ciborium::value::Value;

use super::codec::{
    bounded_array, byte_string, bytes_value, decode_document, digest32, encode, id16, key_id,
    record_digest, require_canonical_order, self_digested, signed, uint, uint_value, verify_digest,
    verify_signature,
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
    /// An overdue provider and its attempts must be terminated before admission reopens.
    #[error("sandbox provider termination is required before revocation admission reopens")]
    ProviderTerminationRequired,
    /// The provider did not acknowledge cancellation before the deadline.
    #[error("sandbox revocation acknowledgement deadline expired")]
    AcknowledgementDeadline,
    /// RCA1 does not acknowledge the exact pending update and cancellation set.
    #[error("sandbox revocation acknowledgement does not match the pending update")]
    AcknowledgementMismatch,
}

/// Root-channel-only RCC1 binding for one exact committed SIR1 transaction.
///
/// This record carries no policy authority. The provider trusts it only on the
/// authenticated root-owned control channel immediately before its exact RCU1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryCancellationContext {
    /// Exact committed SIR1 self-digest.
    pub sir1_digest: [u8; 32],
    /// Domain-separated digest of the exact previous-provider binding in SIR1.
    pub previous_provider_binding_digest: [u8; 32],
    /// Domain-separated digest of the exact RCU1 bytes.
    pub rcu1_wire_digest: [u8; 32],
    /// Complete fenced attempt snapshot for the previous runtime.
    pub previous_live_attempt_ids: Vec<[u8; 16]>,
    /// Exact affected subset that RCA1 must report cancelled.
    pub required_cancelled_attempt_ids: Vec<[u8; 16]>,
    /// Exact RCC1 self-digest.
    pub context_digest: [u8; 32],
}

impl RecoveryCancellationContext {
    /// Construct exact RCC1 from one committed SIR1 and its exact RCU1 bytes.
    ///
    /// # Errors
    /// Rejects zero digests, malformed attempt sets, a non-subset cancellation
    /// set, or an empty/oversized RCU1 document.
    pub fn for_committed_recovery(
        sir1_digest: [u8; 32],
        previous_provider_binding_digest: [u8; 32],
        rcu1_bytes: &[u8],
        previous_live_attempt_ids: Vec<[u8; 16]>,
        required_cancelled_attempt_ids: Vec<[u8; 16]>,
    ) -> Result<Self, SandboxRevocationUpdateError> {
        decode_document(rcu1_bytes)?;
        let rcu1_wire_digest = wire_digest(rcu1_bytes);
        let mut context = Self {
            sir1_digest,
            previous_provider_binding_digest,
            rcu1_wire_digest,
            previous_live_attempt_ids,
            required_cancelled_attempt_ids,
            context_digest: [0; 32],
        };
        context.validate_sets()?;
        context.context_digest =
            record_digest("RCC1", &Value::Array(context.unsigned_fields().to_vec()))?;
        Ok(context)
    }

    /// Decode exact preferred-deterministic RCC1 bytes.
    ///
    /// # Errors
    /// Rejects malformed, legacy, reordered, inconsistent, or digest-invalid records.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxRevocationUpdateError> {
        let document = decode_document(bytes)?;
        let (fields, context_digest) = self_digested::<7>(&document, "RCC1")?;
        let context = Self {
            sir1_digest: digest32(&fields[2])?,
            previous_provider_binding_digest: digest32(&fields[3])?,
            rcu1_wire_digest: digest32(&fields[4])?,
            previous_live_attempt_ids: decode_attempts(&fields[5])?,
            required_cancelled_attempt_ids: decode_attempts(&fields[6])?,
            context_digest,
        };
        context.validate_sets()?;
        verify_digest("RCC1", fields, context.context_digest)?;
        Ok(context)
    }

    /// Encode the exact RCC1 wrapper sent immediately before RCU1.
    ///
    /// # Errors
    /// Rejects an internally altered context.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SandboxRevocationUpdateError> {
        self.verify()?;
        let unsigned = self.unsigned_fields();
        Ok(encode(&Value::Array(vec![
            Value::Array(unsigned.to_vec()),
            bytes_value(&self.context_digest),
        ]))?)
    }

    fn verify(&self) -> Result<(), SandboxRevocationUpdateError> {
        self.validate_sets()?;
        verify_digest("RCC1", &self.unsigned_fields(), self.context_digest).map_err(Into::into)
    }

    fn validate_sets(&self) -> Result<(), SandboxRevocationUpdateError> {
        if self.sir1_digest == [0; 32]
            || self.previous_provider_binding_digest == [0; 32]
            || self.rcu1_wire_digest == [0; 32]
        {
            return Err(SandboxProviderProtocolError::FieldOutOfBounds.into());
        }
        validate_cancelled_attempts(&self.previous_live_attempt_ids)?;
        validate_cancelled_attempts(&self.required_cancelled_attempt_ids)?;
        if self.required_cancelled_attempt_ids.iter().any(|attempt| {
            self.previous_live_attempt_ids
                .binary_search(attempt)
                .is_err()
        }) {
            return Err(SandboxProviderProtocolError::InconsistentFields.into());
        }
        Ok(())
    }

    fn unsigned_fields(&self) -> [Value; 7] {
        [
            Value::Text("RCC1".to_owned()),
            uint_value(1),
            bytes_value(&self.sir1_digest),
            bytes_value(&self.previous_provider_binding_digest),
            bytes_value(&self.rcu1_wire_digest),
            attempt_values(&self.previous_live_attempt_ids),
            attempt_values(&self.required_cancelled_attempt_ids),
        ]
    }
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
    /// Exact committed SIR1 acknowledged by the previous provider runtime.
    pub sir1_digest: [u8; 32],
    /// Exact previous-provider binding acknowledged by the runtime.
    pub previous_provider_binding_digest: [u8; 32],
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
        let (fields, acknowledgement_digest, signature) = signed::<9>(&document, "RCA1")?;
        if uint(&fields[7])? != 0 {
            return Err(SandboxProviderProtocolError::InconsistentFields.into());
        }
        let cancelled_values = bounded_array(&fields[6], 0)?;
        require_canonical_order(cancelled_values)?;
        let acknowledgement = Self {
            request_id: id16(&fields[2])?,
            revocation_digest: digest32(&fields[3])?,
            sir1_digest: digest32(&fields[4])?,
            previous_provider_binding_digest: digest32(&fields[5])?,
            cancelled_attempt_ids: cancelled_values
                .iter()
                .map(id16)
                .collect::<Result<Vec<_>, _>>()?,
            runtime_attestation_key_id: key_id(&fields[8])?,
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
    context: RecoveryCancellationContext,
    deadline_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CompletedRevocationUpdate {
    request: [u8; 32],
    wire: [u8; 32],
    context: [u8; 32],
    acknowledgement: [u8; 32],
}

impl CompletedRevocationUpdate {
    fn matches_request(self, identity: RequestIdentity, context: [u8; 32]) -> bool {
        self.request == identity.request_digest
            && self.wire == identity.wire_digest
            && self.context == context
    }
}

/// Selector-owned state that serializes revocation transitions and retains replay identity.
#[derive(Clone, Debug)]
pub struct SelectorRevocationState {
    current: SandboxRevocationSnapshot,
    runtime_key_id: String,
    runtime_key: ed25519_dalek::VerifyingKey,
    pending: Option<PendingRevocationUpdate>,
    recovery_required: Option<RecoveryCancellationContext>,
    completed: BTreeMap<[u8; 16], CompletedRevocationUpdate>,
}

impl SelectorRevocationState {
    /// Start with the selector's authenticated current RVS1 and resolve the
    /// provider runtime authority from that snapshot.
    ///
    /// # Errors
    /// Rejects an unknown, revoked, or incorrectly role-bound runtime key.
    pub fn new(
        current: SandboxRevocationSnapshot,
        trust: &SandboxTrustSnapshot,
        runtime_key_id: impl Into<String>,
    ) -> Result<Self, SandboxRevocationUpdateError> {
        let runtime_key_id = runtime_key_id.into();
        let runtime_key = current.active_key(
            trust,
            &runtime_key_id,
            SandboxTrustRole::ProviderRuntimeAttestation,
        )?;
        Ok(Self {
            current,
            runtime_key_id,
            runtime_key,
            pending: None,
            recovery_required: None,
            completed: BTreeMap::new(),
        })
    }

    /// Authenticate and retain one in-flight RCU1 transition.
    ///
    /// `now_ms` is supplied by the selector's monotonic clock. The caller must
    /// pass the exact SIR1-derived RCC1 context for the adjacent RCU1.
    ///
    /// # Errors
    /// Rejects identity conflicts, concurrent updates, invalid authority, an
    /// altered RCC1/RCU1 binding, or invalid attempt sets.
    pub fn begin_update(
        &mut self,
        bytes: &[u8],
        trust: &SandboxTrustSnapshot,
        context: RecoveryCancellationContext,
        now_ms: u64,
    ) -> Result<(), SandboxRevocationUpdateError> {
        context.verify()?;
        if context.rcu1_wire_digest != wire_digest(bytes) {
            return Err(SandboxRevocationUpdateError::AcknowledgementMismatch);
        }
        if self.recovery_required.is_some() {
            return Err(SandboxRevocationUpdateError::ProviderTerminationRequired);
        }
        let identity = request_identity(bytes)?;
        if let Some(completed) = self.completed.get(&identity.request_id) {
            return if completed.matches_request(identity, context.context_digest) {
                Ok(())
            } else {
                Err(SandboxRevocationUpdateError::RequestIdentityConflict)
            };
        }
        if let Some(pending) = &self.pending {
            return if pending.request.request_id == identity.request_id
                && pending.request.request_digest == identity.request_digest
                && pending.wire_digest == identity.wire_digest
                && pending.context == context
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
            context,
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
        now_ms: u64,
    ) -> Result<(), SandboxRevocationUpdateError> {
        let acknowledgement = RevocationAcknowledgement::authenticate(
            bytes,
            &self.runtime_key_id,
            &self.runtime_key,
        )?;
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
            || acknowledgement.sir1_digest != pending.context.sir1_digest
            || acknowledgement.previous_provider_binding_digest
                != pending.context.previous_provider_binding_digest
            || acknowledgement.cancelled_attempt_ids
                != pending.context.required_cancelled_attempt_ids
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
                context: pending.context.context_digest,
                acknowledgement: acknowledgement.acknowledgement_digest,
            },
        );
        Ok(())
    }

    /// Abandon an overdue transition and retain its exact committed recovery context.
    ///
    /// The root selector must complete the SIR1-bound termination protocol before
    /// beginning another update. A transition at or before its deadline remains pending.
    #[must_use]
    pub fn expire_overdue(&mut self, now_ms: u64) -> Option<RecoveryCancellationContext> {
        if let Some(required) = &self.recovery_required {
            return Some(required.clone());
        }
        let overdue = self
            .pending
            .as_ref()
            .is_some_and(|pending| now_ms > pending.deadline_ms);
        if !overdue {
            return None;
        }
        let required = self.pending.take()?.context;
        self.recovery_required = Some(required.clone());
        Some(required)
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
    if attempts.len() > 256 {
        return Err(SandboxProviderProtocolError::NonCanonicalOrder);
    }
    if attempts.contains(&[0; 16]) {
        return Err(SandboxProviderProtocolError::NonCanonicalOrder);
    }
    if !attempts.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(SandboxProviderProtocolError::NonCanonicalOrder);
    }
    Ok(())
}

fn decode_attempts(value: &Value) -> Result<Vec<[u8; 16]>, SandboxProviderProtocolError> {
    let values = bounded_array(value, 0)?;
    require_canonical_order(values)?;
    values.iter().map(id16).collect()
}

fn attempt_values(attempts: &[[u8; 16]]) -> Value {
    Value::Array(attempts.iter().map(bytes_value).collect())
}

fn wire_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.RCU1.Wire.v1\0");
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}
