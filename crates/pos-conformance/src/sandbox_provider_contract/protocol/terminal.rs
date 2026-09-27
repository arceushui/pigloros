use super::super::codec::{
    array, bounded_text, decode, digest, fixed, optional_fixed, sign, text, uint, validate_magic,
    value_bytes, value_optional_bytes, value_text, value_uint, verify,
};
use super::super::{
    SandboxContractErrorV1, MAX_SANDBOX_IDENTIFIER_BYTES_V1, MAX_SANDBOX_PROVIDER_ENTRIES_V1,
    MAX_SANDBOX_SAFE_DETAIL_BYTES_V1,
};
use super::receipt::SandboxProviderReceiptV1;
use super::{encode_signed, validate_signed_bytes};
use ciborium::value::Value;

use super::payload::{
    decode_payload_descriptor, payload_descriptor_value, PayloadDescriptorV1, PayloadDirectionV1,
};

const SPY1: &str = "SPY1";
const SPE1: &str = "SPE1";
const LAUNCHER_READY_EVENT: u64 = 11;
const EXECUTION_RELEASED_EVENT: u64 = 12;
const EXECUTION_RELEASE_DENIED_EVENT: u64 = 13;

/// Closed SPY1 terminal result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxTerminalOutcomeV1 {
    /// Execution completed with output and complete evidence.
    Completed,
    /// Admitted execution was cancelled and cleaned up.
    Cancelled,
    /// No admission grant was issued because the provider was unavailable.
    UnavailableBeforeAdmission,
    /// No admission grant was issued because authority was rejected.
    Rejected,
    /// An admitted attempt became unavailable and was cleaned up.
    UnavailableAfterAdmission,
}

/// Exact signed SPY1 terminal response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxProviderResultV1 {
    /// Nonzero request identity.
    pub request_id: [u8; 16],
    /// Nonzero attempt identity.
    pub attempt_id: [u8; 16],
    /// Closed terminal outcome.
    pub outcome: SandboxTerminalOutcomeV1,
    /// Output present only for Completed.
    pub output: Option<PayloadDescriptorV1>,
    /// AGR1 digest present for every post-admission outcome.
    pub agr1_digest: Option<[u8; 32]>,
    /// SPR1 digest present for every post-admission outcome.
    pub spr1_digest: Option<[u8; 32]>,
    /// Ordered closed operational-event codes.
    pub operational_events: Vec<u64>,
    /// Runtime-attestation signing-key identifier.
    pub runtime_attestation_key_id: String,
    /// Self-digest of the exact SPY1-U array.
    pub result_digest: [u8; 32],
    /// Runtime-attestation Ed25519 signature.
    pub signature: [u8; 64],
}

/// Closed SPE1 failure code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxProviderErrorCodeV1 {
    InvalidEncoding,
    UnsupportedVersion,
    FieldOutOfBounds,
    NonCanonicalOrder,
    DigestMismatch,
    SignatureInvalid,
    TrustRevoked,
    AuthorityMismatch,
    ProviderCapabilityMissing,
    ImageIdentityMismatch,
    SelfTestFailed,
    SandboxUnavailable,
    AdmissionBusy,
    AuditUnavailable,
    CleanupFailed,
    UnknownAttempt,
    RequestIdentityConflict,
    PayloadTransferTimeout,
}

/// Exact signed SPE1 failure response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxProviderErrorV1 {
    /// Operation, when framing identified it.
    pub operation: Option<u8>,
    /// Request identity, once authenticated.
    pub request_id: Option<[u8; 16]>,
    /// Request digest, once authenticated.
    pub request_digest: Option<[u8; 32]>,
    /// Attempt identity, once authenticated.
    pub attempt_id: Option<[u8; 16]>,
    /// Closed safe failure code.
    pub code: SandboxProviderErrorCodeV1,
    /// Optional bounded safe detail without secrets or host paths.
    pub safe_detail: Option<String>,
    /// Runtime-attestation signing-key identifier.
    pub runtime_attestation_key_id: String,
    /// Self-digest of the exact SPE1-U array.
    pub error_digest: [u8; 32],
    /// Runtime-attestation Ed25519 signature.
    pub signature: [u8; 64],
}

impl SandboxTerminalOutcomeV1 {
    const fn code(self) -> u64 {
        match self {
            Self::Completed => 0,
            Self::Cancelled => 1,
            Self::UnavailableBeforeAdmission => 2,
            Self::Rejected => 3,
            Self::UnavailableAfterAdmission => 4,
        }
    }

    const fn from_code(code: u64) -> Result<Self, SandboxContractErrorV1> {
        match code {
            0 => Ok(Self::Completed),
            1 => Ok(Self::Cancelled),
            2 => Ok(Self::UnavailableBeforeAdmission),
            3 => Ok(Self::Rejected),
            4 => Ok(Self::UnavailableAfterAdmission),
            _ => Err(SandboxContractErrorV1::InvalidEncoding),
        }
    }
}

fn event_position(events: &[u64], event: u64) -> Option<usize> {
    events.iter().position(|candidate| *candidate == event)
}

fn valid_lifecycle_prefix(events: &[u64]) -> bool {
    matches!(
        events,
        [] | [LAUNCHER_READY_EVENT]
            | [
                LAUNCHER_READY_EVENT,
                EXECUTION_RELEASED_EVENT | EXECUTION_RELEASE_DENIED_EVENT
            ]
    )
}

fn validate_terminal_event_shape(
    outcome: SandboxTerminalOutcomeV1,
    events: &[u64],
) -> Result<(), SandboxContractErrorV1> {
    let valid = match outcome {
        SandboxTerminalOutcomeV1::UnavailableBeforeAdmission
        | SandboxTerminalOutcomeV1::Rejected => events.is_empty(),
        SandboxTerminalOutcomeV1::Completed => {
            events == [LAUNCHER_READY_EVENT, EXECUTION_RELEASED_EVENT]
        }
        SandboxTerminalOutcomeV1::Cancelled => {
            events.split_last().is_some_and(|(terminal, lifecycle)| {
                *terminal == 1 && valid_lifecycle_prefix(lifecycle)
            })
        }
        SandboxTerminalOutcomeV1::UnavailableAfterAdmission => {
            events.split_last().is_some_and(|(terminal, lifecycle)| {
                (*terminal == 0 || (2..=10).contains(terminal)) && valid_lifecycle_prefix(lifecycle)
            })
        }
    };
    valid
        .then_some(())
        .ok_or(SandboxContractErrorV1::InconsistentFields)
}

fn validate_lifecycle_events(
    outcome: SandboxTerminalOutcomeV1,
    events: &[u64],
    receipt: &SandboxProviderReceiptV1,
) -> Result<(), SandboxContractErrorV1> {
    let ready = event_position(events, LAUNCHER_READY_EVENT);
    let released = event_position(events, EXECUTION_RELEASED_EVENT);
    let denied = event_position(events, EXECUTION_RELEASE_DENIED_EVENT);
    let stage_matches = if receipt.release1_digest.is_some() {
        denied.is_none()
            && ready
                .zip(released)
                .is_some_and(|(ready, released)| ready < released)
    } else if receipt.ready1_digest.is_some() {
        ready.is_some()
            && released.is_none()
            && denied.is_none_or(|denied| ready.is_some_and(|ready| ready < denied))
    } else {
        ready.is_none() && released.is_none() && denied.is_none()
    };
    let outcome_matches = outcome != SandboxTerminalOutcomeV1::Completed
        || (receipt.ready1_digest.is_some()
            && receipt.release1_digest.is_some()
            && denied.is_none());
    (stage_matches && outcome_matches)
        .then_some(())
        .ok_or(SandboxContractErrorV1::InconsistentFields)
}

impl SandboxProviderResultV1 {
    /// Seal this terminal result with the supplied runtime-attestation key.
    ///
    /// # Errors
    /// Returns a closed contract error when an unsigned field is invalid.
    pub fn sign(mut self, key: &ed25519_dalek::SigningKey) -> Result<Self, SandboxContractErrorV1> {
        self.validate_unsigned()?;
        self.result_digest = digest(SPY1, &self.unsigned_value())?;
        self.signature = sign(SPY1, &self.result_digest, key);
        Ok(self)
    }

    /// Validate the closed terminal union and its self-digest.
    ///
    /// # Errors
    /// Returns a closed contract error for invalid terminal data.
    pub fn validate(&self) -> Result<(), SandboxContractErrorV1> {
        self.validate_unsigned()?;
        validate_signed_bytes(&self.signature)?;
        (self.result_digest == digest(SPY1, &self.unsigned_value())?)
            .then_some(())
            .ok_or(SandboxContractErrorV1::DigestMismatch)
    }

    /// Verify this result with an authorized runtime-attestation key.
    ///
    /// # Errors
    /// Returns a closed error when shape, digest, or signature verification fails.
    pub fn verify_signature(
        &self,
        key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), SandboxContractErrorV1> {
        self.validate()?;
        verify(SPY1, &self.result_digest, &self.signature, key)
    }

    /// Validate this result against the exact referenced SPR1 lifecycle evidence.
    ///
    /// # Errors
    /// Returns a closed error when identities, authority, or lifecycle events disagree.
    pub fn validate_receipt_lifecycle(
        &self,
        receipt: &SandboxProviderReceiptV1,
    ) -> Result<(), SandboxContractErrorV1> {
        self.validate()?;
        receipt.validate()?;
        if self.attempt_id != receipt.attempt_id
            || self.agr1_digest != Some(receipt.authority.agr1_digest)
            || self.spr1_digest != Some(receipt.receipt_digest)
            || self.runtime_attestation_key_id != receipt.runtime_attestation_key_id
        {
            return Err(SandboxContractErrorV1::InconsistentFields);
        }
        validate_lifecycle_events(self.outcome, &self.operational_events, receipt)
    }

    /// Encode exact deterministic-CBOR SPY1 bytes.
    ///
    /// # Errors
    /// Returns a closed contract error when validation or encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SandboxContractErrorV1> {
        self.validate()?;
        encode_signed(&self.unsigned_value(), &self.result_digest, &self.signature)
    }

    /// Decode exact deterministic-CBOR SPY1 bytes.
    ///
    /// # Errors
    /// Returns a closed contract error for every malformed or noncanonical input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxContractErrorV1> {
        let value = decode(bytes)?;
        let fields = array::<3>(&value)?;
        let unsigned = array::<10>(&fields[0])?;
        validate_magic(unsigned, SPY1)?;
        let result = Self {
            request_id: fixed(&unsigned[2])?,
            attempt_id: fixed(&unsigned[3])?,
            outcome: SandboxTerminalOutcomeV1::from_code(uint(&unsigned[4])?)?,
            output: decode_output(&unsigned[5])?,
            agr1_digest: optional_fixed(&unsigned[6])?,
            spr1_digest: optional_fixed(&unsigned[7])?,
            operational_events: decode_uint_list(&unsigned[8])?,
            runtime_attestation_key_id: text(&unsigned[9])?.to_owned(),
            result_digest: fixed(&fields[1])?,
            signature: fixed(&fields[2])?,
        };
        result.validate().map(|()| result)
    }

    fn validate_unsigned(&self) -> Result<(), SandboxContractErrorV1> {
        if self.request_id == [0; 16]
            || self.attempt_id == [0; 16]
            || !bounded_text(
                &self.runtime_attestation_key_id,
                MAX_SANDBOX_IDENTIFIER_BYTES_V1,
            )
            || self.operational_events.len() > MAX_SANDBOX_PROVIDER_ENTRIES_V1
            || self.operational_events.iter().any(|code| *code > 13)
        {
            return Err(SandboxContractErrorV1::FieldOutOfBounds);
        }
        validate_terminal_event_shape(self.outcome, &self.operational_events)?;
        self.output.as_ref().map_or(Ok(()), |output| {
            output.validate_for_direction(PayloadDirectionV1::Output)
        })?;
        let valid_union = match self.outcome {
            SandboxTerminalOutcomeV1::Completed => {
                self.output.is_some()
                    && nonzero_optional(self.agr1_digest)
                    && nonzero_optional(self.spr1_digest)
            }
            SandboxTerminalOutcomeV1::Cancelled
            | SandboxTerminalOutcomeV1::UnavailableAfterAdmission => {
                self.output.is_none()
                    && nonzero_optional(self.agr1_digest)
                    && nonzero_optional(self.spr1_digest)
            }
            SandboxTerminalOutcomeV1::UnavailableBeforeAdmission
            | SandboxTerminalOutcomeV1::Rejected => {
                self.output.is_none() && self.agr1_digest.is_none() && self.spr1_digest.is_none()
            }
        };
        valid_union
            .then_some(())
            .ok_or(SandboxContractErrorV1::InconsistentFields)
    }

    fn unsigned_value(&self) -> Value {
        Value::Array(vec![
            value_text(SPY1),
            value_uint(1),
            value_bytes(&self.request_id),
            value_bytes(&self.attempt_id),
            value_uint(self.outcome.code()),
            self.output.as_ref().map_or(Value::Null, output_value),
            value_optional_bytes(self.agr1_digest.as_ref()),
            value_optional_bytes(self.spr1_digest.as_ref()),
            Value::Array(
                self.operational_events
                    .iter()
                    .map(|value| value_uint(*value))
                    .collect(),
            ),
            value_text(&self.runtime_attestation_key_id),
        ])
    }
}

fn output_value(value: &PayloadDescriptorV1) -> Value {
    payload_descriptor_value(value)
}

fn decode_output(value: &Value) -> Result<Option<PayloadDescriptorV1>, SandboxContractErrorV1> {
    if value == &Value::Null {
        return Ok(None);
    }
    decode_payload_descriptor(value).map(Some)
}

fn decode_uint_list(value: &Value) -> Result<Vec<u64>, SandboxContractErrorV1> {
    let Value::Array(values) = value else {
        return Err(SandboxContractErrorV1::InvalidEncoding);
    };
    values.iter().map(uint).collect()
}

fn nonzero_optional(value: Option<[u8; 32]>) -> bool {
    matches!(value, Some(digest) if digest != [0; 32])
}

impl SandboxProviderErrorCodeV1 {
    const fn requires_identified_operation(self) -> bool {
        !matches!(self, Self::InvalidEncoding)
    }

    const fn requires_authenticated_request(self) -> bool {
        !matches!(
            self,
            Self::InvalidEncoding
                | Self::UnsupportedVersion
                | Self::FieldOutOfBounds
                | Self::NonCanonicalOrder
                | Self::DigestMismatch
                | Self::SignatureInvalid
        )
    }

    const fn code(self) -> u64 {
        match self {
            Self::InvalidEncoding => 0,
            Self::UnsupportedVersion => 1,
            Self::FieldOutOfBounds => 2,
            Self::NonCanonicalOrder => 3,
            Self::DigestMismatch => 4,
            Self::SignatureInvalid => 5,
            Self::TrustRevoked => 6,
            Self::AuthorityMismatch => 7,
            Self::ProviderCapabilityMissing => 8,
            Self::ImageIdentityMismatch => 9,
            Self::SelfTestFailed => 10,
            Self::SandboxUnavailable => 11,
            Self::AdmissionBusy => 12,
            Self::AuditUnavailable => 13,
            Self::CleanupFailed => 14,
            Self::UnknownAttempt => 15,
            Self::RequestIdentityConflict => 16,
            Self::PayloadTransferTimeout => 17,
        }
    }

    const fn from_code(code: u64) -> Result<Self, SandboxContractErrorV1> {
        match code {
            0 => Ok(Self::InvalidEncoding),
            1 => Ok(Self::UnsupportedVersion),
            2 => Ok(Self::FieldOutOfBounds),
            3 => Ok(Self::NonCanonicalOrder),
            4 => Ok(Self::DigestMismatch),
            5 => Ok(Self::SignatureInvalid),
            6 => Ok(Self::TrustRevoked),
            7 => Ok(Self::AuthorityMismatch),
            8 => Ok(Self::ProviderCapabilityMissing),
            9 => Ok(Self::ImageIdentityMismatch),
            10 => Ok(Self::SelfTestFailed),
            11 => Ok(Self::SandboxUnavailable),
            12 => Ok(Self::AdmissionBusy),
            13 => Ok(Self::AuditUnavailable),
            14 => Ok(Self::CleanupFailed),
            15 => Ok(Self::UnknownAttempt),
            16 => Ok(Self::RequestIdentityConflict),
            17 => Ok(Self::PayloadTransferTimeout),
            _ => Err(SandboxContractErrorV1::InvalidEncoding),
        }
    }
}

impl SandboxProviderErrorV1 {
    /// Seal this error with the supplied runtime-attestation key.
    ///
    /// # Errors
    /// Returns a closed contract error when an unsigned field is invalid.
    pub fn sign(mut self, key: &ed25519_dalek::SigningKey) -> Result<Self, SandboxContractErrorV1> {
        self.validate_unsigned()?;
        self.error_digest = digest(SPE1, &self.unsigned_value())?;
        self.signature = sign(SPE1, &self.error_digest, key);
        Ok(self)
    }

    /// Validate nullability, bounds, and self-digest.
    ///
    /// # Errors
    /// Returns a closed contract error for invalid error data.
    pub fn validate(&self) -> Result<(), SandboxContractErrorV1> {
        self.validate_unsigned()?;
        validate_signed_bytes(&self.signature)?;
        (self.error_digest == digest(SPE1, &self.unsigned_value())?)
            .then_some(())
            .ok_or(SandboxContractErrorV1::DigestMismatch)
    }

    /// Verify this error with an authorized runtime-attestation key.
    ///
    /// # Errors
    /// Returns a closed error when shape, digest, or signature verification fails.
    pub fn verify_signature(
        &self,
        key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), SandboxContractErrorV1> {
        self.validate()?;
        verify(SPE1, &self.error_digest, &self.signature, key)
    }

    /// Encode exact deterministic-CBOR SPE1 bytes.
    ///
    /// # Errors
    /// Returns a closed contract error when validation or encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SandboxContractErrorV1> {
        self.validate()?;
        encode_signed(&self.unsigned_value(), &self.error_digest, &self.signature)
    }

    /// Decode exact deterministic-CBOR SPE1 bytes.
    ///
    /// # Errors
    /// Returns a closed contract error for every malformed or noncanonical input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxContractErrorV1> {
        let value = decode(bytes)?;
        let fields = array::<3>(&value)?;
        let unsigned = array::<9>(&fields[0])?;
        validate_magic(unsigned, SPE1)?;
        let error = Self {
            operation: decode_optional_u8(&unsigned[2])?,
            request_id: optional_fixed(&unsigned[3])?,
            request_digest: optional_fixed(&unsigned[4])?,
            attempt_id: optional_fixed(&unsigned[5])?,
            code: SandboxProviderErrorCodeV1::from_code(uint(&unsigned[6])?)?,
            safe_detail: decode_optional_text(&unsigned[7])?,
            runtime_attestation_key_id: text(&unsigned[8])?.to_owned(),
            error_digest: fixed(&fields[1])?,
            signature: fixed(&fields[2])?,
        };
        error.validate().map(|()| error)
    }

    fn validate_unsigned(&self) -> Result<(), SandboxContractErrorV1> {
        if self.operation.is_some_and(|value| value > 3)
            || self.request_id == Some([0; 16])
            || self.request_digest == Some([0; 32])
            || self.attempt_id == Some([0; 16])
            || self.safe_detail.as_ref().is_some_and(|value| {
                value.is_empty()
                    || value.len() > MAX_SANDBOX_SAFE_DETAIL_BYTES_V1
                    || value.contains('\0')
            })
            || !bounded_text(
                &self.runtime_attestation_key_id,
                MAX_SANDBOX_IDENTIFIER_BYTES_V1,
            )
        {
            return Err(SandboxContractErrorV1::FieldOutOfBounds);
        }
        if (self.request_digest.is_some() && self.request_id.is_none())
            || (self.attempt_id.is_some()
                && (self.operation.is_none() || self.request_id.is_none()))
        {
            return Err(SandboxContractErrorV1::InconsistentFields);
        }
        if self.code.requires_identified_operation() && self.operation.is_none() {
            return Err(SandboxContractErrorV1::InconsistentFields);
        }
        if self.code.requires_authenticated_request() {
            let attempt_identity_matches_operation = if self.operation == Some(0) {
                self.attempt_id.is_none()
            } else {
                self.attempt_id.is_some()
            };
            if self.request_id.is_none()
                || self.request_digest.is_none()
                || !attempt_identity_matches_operation
            {
                return Err(SandboxContractErrorV1::InconsistentFields);
            }
        }
        if self.code == SandboxProviderErrorCodeV1::PayloadTransferTimeout
            && (self.operation != Some(1)
                || self.request_id.is_none()
                || self.request_digest.is_none()
                || self.attempt_id.is_none())
        {
            return Err(SandboxContractErrorV1::InconsistentFields);
        }
        Ok(())
    }

    fn unsigned_value(&self) -> Value {
        Value::Array(vec![
            value_text(SPE1),
            value_uint(1),
            self.operation
                .map_or(Value::Null, |value| value_uint(u64::from(value))),
            value_optional_bytes(self.request_id.as_ref()),
            value_optional_bytes(self.request_digest.as_ref()),
            value_optional_bytes(self.attempt_id.as_ref()),
            value_uint(self.code.code()),
            self.safe_detail
                .as_ref()
                .map_or(Value::Null, |value| value_text(value)),
            value_text(&self.runtime_attestation_key_id),
        ])
    }
}

fn decode_optional_u8(value: &Value) -> Result<Option<u8>, SandboxContractErrorV1> {
    if value == &Value::Null {
        Ok(None)
    } else {
        u8::try_from(uint(value)?)
            .map(Some)
            .map_err(|_| SandboxContractErrorV1::FieldOutOfBounds)
    }
}

fn decode_optional_text(value: &Value) -> Result<Option<String>, SandboxContractErrorV1> {
    if value == &Value::Null {
        Ok(None)
    } else {
        text(value).map(|value| Some(value.to_owned()))
    }
}
