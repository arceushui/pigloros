//! ADR-069 captured network evidence and offline Replay validation.

mod frames;
pub use frames::{NetworkExchangeFailure, NetworkExchangeReply, NetworkExchangeRequest};

use ciborium::value::Value;

use super::{
    codec::{
        bytes_value, decode_document, digest_with_domain, encode, record_digest, text_value,
        uint_value,
    },
    NetworkExchangePlan, SandboxProviderProtocolError,
};

const REQUEST_DOMAIN: &[u8] = b"PiglorOS.NetworkRequestBytes.v1\0";
const RESPONSE_DOMAIN: &[u8] = b"PiglorOS.NetworkResponseBytes.v1\0";
const TRANSCRIPT_DOMAIN: &[u8] = b"PiglorOS.NetworkExchangeTranscript.v1\0";

/// The single accepted NRP1 policy: retain captured response artifacts indefinitely.
///
/// This record identifies the policy. Durable storage must independently fulfill
/// it; constructing the record neither persists nor authorizes access to bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkRetentionPolicy {
    /// NRP1 mode 0; no deletion or expiry is permitted by this version.
    RetainIndefinitely,
}

impl NetworkRetentionPolicy {
    /// Decode the exact canonical NRP1 indefinite-retention record.
    ///
    /// # Errors
    /// Rejects every different mode, encoding, version, shape, or digest.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxProviderProtocolError> {
        Self::RetainIndefinitely
            .to_canonical_cbor()
            .and_then(|expected| {
                if bytes == expected {
                    Ok(Self::RetainIndefinitely)
                } else {
                    Err(SandboxProviderProtocolError::InvalidEncoding)
                }
            })
    }

    /// Return the canonical NRP1 bytes for the one accepted policy.
    ///
    /// # Errors
    /// Returns a protocol error if CBOR serialization fails.
    pub fn to_canonical_cbor(self) -> Result<Vec<u8>, SandboxProviderProtocolError> {
        self.digest()
            .and_then(|digest| encode(&Value::Array(vec![self.unsigned(), bytes_value(&digest)])))
    }

    /// Return NRP1's self-digest, used by plans and transcripts.
    ///
    /// # Errors
    /// Returns a protocol error if CBOR serialization fails.
    pub fn digest(self) -> Result<[u8; 32], SandboxProviderProtocolError> {
        record_digest("NRP1", &self.unsigned())
    }

    fn unsigned(self) -> Value {
        match self {
            Self::RetainIndefinitely => {
                Value::Array(vec![text_value("NRP1"), uint_value(1), uint_value(0)])
            }
        }
    }
}

/// One NXT1 transcript bound to a specific attempt, planned occurrence and capture.
///
/// Private fields prevent mutation after validation. This is content evidence,
/// not provider admission, a signed receipt, storage durability, or permission
/// to read an artifact. The caller must supply an independently authorized plan.
#[derive(Clone, Debug, PartialEq)]
pub struct NetworkExchangeTranscript {
    unsigned: Value,
    digest: [u8; 32],
}

impl NetworkExchangeTranscript {
    /// Validate the complete capture before releasing response bytes as evidence.
    ///
    /// Does no network or storage I/O. The proxy must separately validate the
    /// request before forwarding it; this final capture check is not that gate.
    ///
    /// # Errors
    /// Rejects an invalid plan, unsupported retention, zero attempt, or unequal
    /// request/response length or digest. A failed exchange has no transcript.
    pub fn capture(
        attempt_id: [u8; 16],
        plan: &NetworkExchangePlan,
        request: &[u8],
        response: &[u8],
    ) -> Result<Self, SandboxProviderProtocolError> {
        plan.validate().and_then(|()| {
            if request.len() as u64 != plan.request_length
                || content_digest(REQUEST_DOMAIN, request) != plan.request_digest
            {
                return Err(SandboxProviderProtocolError::DigestMismatch);
            }
            Self::from_response(attempt_id, plan, response)
        })
    }

    /// Resolve an exact NXT1 and captured artifact for offline Replay.
    ///
    /// The authorized report must supply `attempt_id` and `plan`; the stored
    /// transcript cannot choose its own lookup authority. This method checks all
    /// canonical transcript fields and the captured artifact without live I/O.
    /// Missing captures must be reported unavailable by the storage caller.
    ///
    /// # Errors
    /// Rejects malformed, noncanonical or substituted records, foreign attempts
    /// or occurrences, invalid plans, and missing/mismatched artifact bytes.
    pub fn verify_replay(
        bytes: &[u8],
        attempt_id: [u8; 16],
        plan: &NetworkExchangePlan,
        response: &[u8],
    ) -> Result<Self, SandboxProviderProtocolError> {
        decode_document(bytes).and_then(|document| {
            plan.validate().and_then(|()| {
                Self::from_response(attempt_id, plan, response).and_then(|expected| {
                    if document == expected.document() {
                        Ok(expected)
                    } else {
                        Err(SandboxProviderProtocolError::DigestMismatch)
                    }
                })
            })
        })
    }

    /// Return the complete canonical NXT1 wrapper.
    ///
    /// # Errors
    /// Returns a protocol error if CBOR serialization fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SandboxProviderProtocolError> {
        encode(&self.document())
    }

    /// The semantic transcript digest for the signed provider receipt.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    fn from_response(
        attempt_id: [u8; 16],
        plan: &NetworkExchangePlan,
        response: &[u8],
    ) -> Result<Self, SandboxProviderProtocolError> {
        if attempt_id == [0; 16] {
            return Err(SandboxProviderProtocolError::FieldOutOfBounds);
        }
        validate_retention(plan).and_then(|retention| {
            if response.len() as u64 > plan.response_maximum {
                return Err(SandboxProviderProtocolError::DigestMismatch);
            }
            let response_digest = content_digest(RESPONSE_DOMAIN, response);
            if response_digest != plan.expected_response_digest {
                return Err(SandboxProviderProtocolError::DigestMismatch);
            }
            let unsigned = Value::Array(vec![
                text_value("NXT1"),
                uint_value(1),
                bytes_value(&attempt_id),
                bytes_value(&plan.exchange_id),
                uint_value(plan.occurrence),
                bytes_value(&plan.plan_digest),
                uint_value(plan.request_length),
                bytes_value(&plan.request_digest),
                uint_value(response.len() as u64),
                bytes_value(&response_digest),
                bytes_value(&response_digest),
                bytes_value(&retention),
            ]);
            digest_with_domain(TRANSCRIPT_DOMAIN, &unsigned).map(|digest| Self { unsigned, digest })
        })
    }

    fn document(&self) -> Value {
        Value::Array(vec![self.unsigned.clone(), bytes_value(&self.digest)])
    }
}

fn validate_retention(
    plan: &NetworkExchangePlan,
) -> Result<[u8; 32], SandboxProviderProtocolError> {
    NetworkRetentionPolicy::RetainIndefinitely
        .digest()
        .and_then(|retention| {
            if retention == plan.retention_policy_digest {
                Ok(retention)
            } else {
                Err(SandboxProviderProtocolError::InconsistentFields)
            }
        })
}

fn content_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}
