//! Authentication of RCC1, RCU1, and RCA1 revocation-update records.
//!
//! The root selector owns durable update state and lifecycle transitions; this
//! module validates the exact records and authority context crossing that seam.

use ciborium::value::Value;

use super::codec::{
    bounded_array, byte_string, bytes_value, decode_document, digest32, encode, id16, key_id,
    record_digest, require_canonical_order, self_digested, signed, uint, uint_value, verify_digest,
    verify_signature,
};
use super::{
    attempt_values, SandboxProviderProtocolError, SandboxRevocationSnapshot, SandboxTrustError,
    SandboxTrustRole, SandboxTrustSnapshot,
};

/// Closed selector-side revocation-update failures.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SandboxRevocationUpdateError {
    /// A request or acknowledgement violates its wire contract.
    #[error(transparent)]
    Protocol(#[from] SandboxProviderProtocolError),
    /// A signer or authority snapshot is invalid.
    #[error(transparent)]
    Trust(#[from] SandboxTrustError),
    /// RCA1 does not acknowledge the exact pending update and cancellation set.
    #[error("sandbox revocation acknowledgement does not match the pending update")]
    AcknowledgementMismatch,
}

/// Root-channel-only RCC1 binding for one exact committed SIR1 transaction.
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
    /// Rejects zero identities, malformed attempt sets, a non-subset cancellation
    /// set, or an invalid RCU1 document.
    pub fn for_committed_recovery(
        sir1_digest: [u8; 32],
        previous_provider_binding_digest: [u8; 32],
        rcu1_bytes: &[u8],
        previous_live_attempt_ids: Vec<[u8; 16]>,
        required_cancelled_attempt_ids: Vec<[u8; 16]>,
    ) -> Result<Self, SandboxRevocationUpdateError> {
        decode_document(rcu1_bytes)
            .map_err(SandboxRevocationUpdateError::from)
            .and_then(|_| {
                let mut context = Self {
                    sir1_digest,
                    previous_provider_binding_digest,
                    rcu1_wire_digest: wire_digest(rcu1_bytes),
                    previous_live_attempt_ids,
                    required_cancelled_attempt_ids,
                    context_digest: [0; 32],
                };
                context.validate().and_then(|()| {
                    record_digest("RCC1", &Value::Array(context.unsigned_fields().to_vec()))
                        .map_err(SandboxRevocationUpdateError::from)
                        .map(|context_digest| {
                            context.context_digest = context_digest;
                            context
                        })
                })
            })
    }

    /// Decode one exact preferred-deterministic RCC1.
    ///
    /// # Errors
    /// Rejects malformed, legacy, reordered, inconsistent, or digest-invalid records.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxRevocationUpdateError> {
        decode_document(bytes)
            .map_err(SandboxRevocationUpdateError::from)
            .and_then(|document| {
                let (fields, context_digest) = self_digested::<7>(&document, "RCC1")?;
                let context = Self {
                    sir1_digest: digest32(&fields[2])?,
                    previous_provider_binding_digest: digest32(&fields[3])?,
                    rcu1_wire_digest: digest32(&fields[4])?,
                    previous_live_attempt_ids: decode_attempts(&fields[5])?,
                    required_cancelled_attempt_ids: decode_attempts(&fields[6])?,
                    context_digest,
                };
                context.verify().map(|()| context)
            })
    }

    /// Encode the exact RCC1 wrapper sent immediately before RCU1.
    ///
    /// # Errors
    /// Rejects an internally altered context.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SandboxRevocationUpdateError> {
        self.verify().and_then(|()| {
            encode(&Value::Array(vec![
                Value::Array(self.unsigned_fields().to_vec()),
                bytes_value(&self.context_digest),
            ]))
            .map_err(Into::into)
        })
    }

    fn verify(&self) -> Result<(), SandboxRevocationUpdateError> {
        self.validate().and_then(|()| {
            verify_digest("RCC1", &self.unsigned_fields(), self.context_digest).map_err(Into::into)
        })
    }

    fn validate(&self) -> Result<(), SandboxRevocationUpdateError> {
        if self.sir1_digest == [0; 32]
            || self.previous_provider_binding_digest == [0; 32]
            || self.rcu1_wire_digest == [0; 32]
        {
            return Err(SandboxProviderProtocolError::FieldOutOfBounds.into());
        }
        validate_attempts(&self.previous_live_attempt_ids)
            .map_err(SandboxRevocationUpdateError::from)
            .and_then(|()| {
                validate_attempts(&self.required_cancelled_attempt_ids)
                    .map_err(SandboxRevocationUpdateError::from)
            })
            .and_then(|()| {
                if self.required_cancelled_attempt_ids.iter().any(|attempt| {
                    self.previous_live_attempt_ids
                        .binary_search(attempt)
                        .is_err()
                }) {
                    Err(SandboxProviderProtocolError::InconsistentFields.into())
                } else {
                    Ok(())
                }
            })
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
        decode_document(bytes)
            .map_err(SandboxRevocationUpdateError::from)
            .and_then(|document| {
                let (fields, request_digest, signature) = signed::<8>(&document, "RCU1")?;
                let next_bytes = byte_string(&fields[4])?;
                SandboxRevocationSnapshot::authenticate(next_bytes, trust)
                    .map_err(SandboxRevocationUpdateError::from)
                    .and_then(|next_revocation| {
                        let request = Self {
                            request_id: id16(&fields[2])?,
                            previous_revocation_digest: digest32(&fields[3])?,
                            next_revocation,
                            selector_nonce: id16(&fields[6])?,
                            policy_signer_key_id: key_id(&fields[7])?,
                            request_digest,
                            signature,
                        };
                        request.validate(fields, trust, current).map(|()| request)
                    })
            })
    }

    fn validate(
        &self,
        unsigned: &[Value; 8],
        trust: &SandboxTrustSnapshot,
        current: &SandboxRevocationSnapshot,
    ) -> Result<(), SandboxRevocationUpdateError> {
        digest32(&unsigned[5])
            .map_err(SandboxRevocationUpdateError::from)
            .and_then(|next_digest| {
                if self.previous_revocation_digest == current.snapshot_digest()
                    && next_digest == self.next_revocation.snapshot_digest()
                {
                    Ok(())
                } else {
                    Err(SandboxTrustError::AuthorityMismatch.into())
                }
            })
            .and_then(|()| {
                current
                    .validate_immediate_epoch_for_same_registry(&self.next_revocation)
                    .map_err(SandboxRevocationUpdateError::from)
            })
            .and_then(|()| {
                verify_digest("RCU1", unsigned, self.request_digest)
                    .map_err(SandboxRevocationUpdateError::from)
            })
            .and_then(|()| {
                current
                    .active_key(
                        trust,
                        &self.policy_signer_key_id,
                        SandboxTrustRole::AdministratorPolicy,
                    )
                    .map_err(SandboxRevocationUpdateError::from)
            })
            .and_then(|key| {
                verify_signature("RCU1", &self.request_digest, &self.signature, &key)
                    .map_err(SandboxRevocationUpdateError::from)
            })
    }
}

/// Runtime-authenticated RCA1 acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationAcknowledgement {
    /// RCU1 request identity.
    pub request_id: [u8; 16],
    /// Newly installed RVS1 digest.
    pub revocation_digest: [u8; 32],
    /// Exact committed SIR1 identity.
    pub sir1_digest: [u8; 32],
    /// Exact previous provider/runtime binding committed by SIR1.
    pub previous_provider_binding_digest: [u8; 32],
    /// Canonically ordered attempts cancelled before acknowledgement.
    pub cancelled_attempt_ids: Vec<[u8; 16]>,
    /// Runtime-attestation signer.
    pub runtime_attestation_key_id: String,
    /// Exact RCA1 self-digest.
    pub acknowledgement_digest: [u8; 32],
    signature: [u8; 64],
}

/// RCA1 authenticated against one exact previous runtime and committed RCC1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedRevocationAcknowledgement {
    request_id: [u8; 16],
    revocation_digest: [u8; 32],
    sir1_digest: [u8; 32],
    previous_provider_binding_digest: [u8; 32],
    cancelled_attempt_ids: Vec<[u8; 16]>,
    acknowledgement_digest: [u8; 32],
}

impl AuthenticatedRevocationAcknowledgement {
    /// Exact authenticated RCA1 self-digest.
    #[must_use]
    pub const fn acknowledgement_digest(&self) -> [u8; 32] {
        self.acknowledgement_digest
    }

    pub(crate) fn matches_context(
        &self,
        context: &RecoveryCancellationContext,
        request_id: [u8; 16],
        revocation_digest: [u8; 32],
    ) -> bool {
        self.request_id == request_id
            && self.revocation_digest == revocation_digest
            && self.sir1_digest == context.sir1_digest
            && self.previous_provider_binding_digest == context.previous_provider_binding_digest
            && self.cancelled_attempt_ids == context.required_cancelled_attempt_ids
    }
}

impl RevocationAcknowledgement {
    /// Authenticate one RCA1 against its exact previous-runtime authority.
    ///
    /// Relationship checks against the committed SIR1 and RCC1 remain the
    /// root selector's responsibility.
    ///
    /// # Errors
    /// Rejects malformed, forged, noncanonical, nonterminal, or foreign-key
    /// acknowledgements.
    pub fn authenticate(
        bytes: &[u8],
        runtime_key_id: &str,
        runtime_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<Self, SandboxRevocationUpdateError> {
        decode_document(bytes)
            .map_err(SandboxRevocationUpdateError::from)
            .and_then(|document| {
                let (fields, acknowledgement_digest, signature) = signed::<9>(&document, "RCA1")?;
                if uint(&fields[7])? != 0 {
                    return Err(SandboxProviderProtocolError::InconsistentFields.into());
                }
                bounded_array(&fields[6], 0)
                    .and_then(|cancelled_values| {
                        require_canonical_order(cancelled_values).map(|()| cancelled_values)
                    })
                    .and_then(|cancelled_values| {
                        cancelled_values
                            .iter()
                            .map(id16)
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .and_then(|cancelled_attempt_ids| {
                        Ok(Self {
                            request_id: id16(&fields[2])?,
                            revocation_digest: digest32(&fields[3])?,
                            sir1_digest: digest32(&fields[4])?,
                            previous_provider_binding_digest: digest32(&fields[5])?,
                            cancelled_attempt_ids,
                            runtime_attestation_key_id: key_id(&fields[8])?,
                            acknowledgement_digest,
                            signature,
                        })
                    })
                    .map_err(SandboxRevocationUpdateError::from)
                    .and_then(|acknowledgement| {
                        validate_attempts(&acknowledgement.cancelled_attempt_ids)
                            .map_err(SandboxRevocationUpdateError::from)
                            .map(|()| acknowledgement)
                    })
                    .and_then(|acknowledgement| {
                        verify_digest("RCA1", fields, acknowledgement.acknowledgement_digest)
                            .map_err(SandboxRevocationUpdateError::from)
                            .map(|()| acknowledgement)
                    })
                    .and_then(|acknowledgement| {
                        if acknowledgement.runtime_attestation_key_id == runtime_key_id {
                            Ok(acknowledgement)
                        } else {
                            Err(SandboxRevocationUpdateError::AcknowledgementMismatch)
                        }
                    })
                    .and_then(|acknowledgement| {
                        verify_signature(
                            "RCA1",
                            &acknowledgement.acknowledgement_digest,
                            &acknowledgement.signature,
                            runtime_key,
                        )
                        .map(|()| acknowledgement)
                        .map_err(SandboxRevocationUpdateError::from)
                    })
            })
    }

    /// Authenticate RCA1 and bind it to the exact committed update context.
    ///
    /// # Errors
    /// Rejects a forged runtime signature or any request, RVS1, SIR1, provider,
    /// cancellation-set, or remaining-count mismatch.
    pub fn authenticate_for_context(
        bytes: &[u8],
        runtime_key_id: &str,
        runtime_key: &ed25519_dalek::VerifyingKey,
        context: &RecoveryCancellationContext,
        request_id: [u8; 16],
        revocation_digest: [u8; 32],
    ) -> Result<AuthenticatedRevocationAcknowledgement, SandboxRevocationUpdateError> {
        context.verify().and_then(|()| {
            Self::authenticate(bytes, runtime_key_id, runtime_key).and_then(|acknowledgement| {
                let authenticated = AuthenticatedRevocationAcknowledgement {
                    request_id: acknowledgement.request_id,
                    revocation_digest: acknowledgement.revocation_digest,
                    sir1_digest: acknowledgement.sir1_digest,
                    previous_provider_binding_digest: acknowledgement
                        .previous_provider_binding_digest,
                    cancelled_attempt_ids: acknowledgement.cancelled_attempt_ids,
                    acknowledgement_digest: acknowledgement.acknowledgement_digest,
                };
                if authenticated.matches_context(context, request_id, revocation_digest) {
                    Ok(authenticated)
                } else {
                    Err(SandboxRevocationUpdateError::AcknowledgementMismatch)
                }
            })
        })
    }
}

fn validate_attempts(attempts: &[[u8; 16]]) -> Result<(), SandboxProviderProtocolError> {
    if attempts.contains(&[0; 16]) || !attempts.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(SandboxProviderProtocolError::NonCanonicalOrder);
    }
    Ok(())
}

fn decode_attempts(value: &Value) -> Result<Vec<[u8; 16]>, SandboxProviderProtocolError> {
    bounded_array(value, 0).and_then(|values| {
        require_canonical_order(values).and_then(|()| {
            values
                .iter()
                .map(id16)
                .collect::<Result<Vec<_>, _>>()
                .and_then(|attempts| validate_attempts(&attempts).map(|()| attempts))
        })
    })
}

fn wire_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.RCU1.Wire.v1\0");
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}
