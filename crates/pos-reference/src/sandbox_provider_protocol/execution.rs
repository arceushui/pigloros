use ciborium::value::Value;

use super::codec::{
    array, bounded_array, byte_string, bytes_value, decode_digest_list, decode_document,
    decode_identifiers, decode_u8_list, digest32, digest_list_value, id16, identifier,
    invalid_digest_list, key_id, nonzero_optional, optional_bytes_value, optional_digest,
    optional_digest_value, optional_id16, optional_text, optional_u8, require_signature,
    self_digested, signed, text_value, uint, uint_value, valid_key_id, validate_identifier_order,
    validate_magic, verify_digest, verify_digest_with_domain, verify_signature,
    MAX_INPUT_BYTES_U64, MAX_LIST_ENTRIES, MAX_SAFE_DETAIL_BYTES,
};
use super::operations::{decode_request_authority, validate_request_authority, RequestAuthority};
use super::SandboxProviderProtocolError;

const PAYLOAD_CHUNK_BYTES: usize = 1024 * 1024;
const MAX_PAYLOAD_CHUNKS: u64 = 128;
const LAUNCHER_READY_EVENT: u8 = 11;
const EXECUTION_RELEASED_EVENT: u8 = 12;
const EXECUTION_RELEASE_DENIED_EVENT: u8 = 13;

/// Direction of one provider payload transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadDirection {
    Input,
    Output,
}

impl PayloadDirection {
    const fn code(self) -> u64 {
        match self {
            Self::Input => 0,
            Self::Output => 1,
        }
    }

    const fn decode(value: u64) -> Result<Self, SandboxProviderProtocolError> {
        match value {
            0 => Ok(Self::Input),
            1 => Ok(Self::Output),
            _ => Err(SandboxProviderProtocolError::FieldOutOfBounds),
        }
    }

    const fn domain(self) -> &'static [u8] {
        match self {
            Self::Input => b"PiglorOS.SandboxInputBytes.v1\0",
            Self::Output => b"PiglorOS.SandboxOutputBytes.v1\0",
        }
    }
}

/// Exact bounded payload descriptor carried by SPX1 or SPY1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadDescriptor {
    pub byte_length: u64,
    pub digest: [u8; 32],
}

fn validate_payload_descriptor(
    descriptor: &PayloadDescriptor,
    direction: PayloadDirection,
) -> Result<(), SandboxProviderProtocolError> {
    if descriptor.byte_length > MAX_INPUT_BYTES_U64 {
        return Err(SandboxProviderProtocolError::FieldOutOfBounds);
    }
    if descriptor.byte_length == 0 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(direction.domain());
        if descriptor.digest != *hasher.finalize().as_bytes() {
            return Err(SandboxProviderProtocolError::DigestMismatch);
        }
    }
    Ok(())
}

/// Independently decoded parent-bound SBC1 payload chunk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxPayloadChunk {
    pub parent_digest: [u8; 32],
    pub request_id: [u8; 16],
    pub attempt_id: [u8; 16],
    pub direction: PayloadDirection,
    pub index: u64,
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub chunk_digest: [u8; 32],
}

impl SandboxPayloadChunk {
    /// Decode and fully validate exact canonical SBC1 bytes.
    ///
    /// # Errors
    /// Returns a closed protocol error for malformed, noncanonical, or invalid bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxProviderProtocolError> {
        let value = decode_document(bytes)?;
        let (fields, chunk_digest) = self_digested::<9>(&value, "SBC1")?;
        let chunk = Self {
            parent_digest: digest32(&fields[2])?,
            request_id: id16(&fields[3])?,
            attempt_id: id16(&fields[4])?,
            direction: PayloadDirection::decode(uint(&fields[5])?)?,
            index: uint(&fields[6])?,
            offset: uint(&fields[7])?,
            bytes: byte_string(&fields[8])?.to_vec(),
            chunk_digest,
        };
        chunk.validate(fields).map(|()| chunk)
    }

    fn validate(&self, fields: &[Value; 9]) -> Result<(), SandboxProviderProtocolError> {
        let expected_offset = self
            .index
            .checked_mul(PAYLOAD_CHUNK_BYTES as u64)
            .ok_or(SandboxProviderProtocolError::FieldOutOfBounds)?;
        if self.parent_digest == [0; 32]
            || self.index >= MAX_PAYLOAD_CHUNKS
            || self.offset != expected_offset
            || self.bytes.is_empty()
            || self.bytes.len() > PAYLOAD_CHUNK_BYTES
        {
            return Err(SandboxProviderProtocolError::FieldOutOfBounds);
        }
        verify_digest("SBC1", fields, self.chunk_digest)
    }

    fn unsigned_value(&self) -> [Value; 9] {
        [
            text_value("SBC1"),
            uint_value(1),
            bytes_value(&self.parent_digest),
            bytes_value(&self.request_id),
            bytes_value(&self.attempt_id),
            uint_value(self.direction.code()),
            uint_value(self.index),
            uint_value(self.offset),
            bytes_value(&self.bytes),
        ]
    }
}

/// Independent incremental validator for one non-interleaved SBC1 sequence.
pub struct PayloadStreamValidator {
    parent_digest: [u8; 32],
    request_id: [u8; 16],
    attempt_id: [u8; 16],
    direction: PayloadDirection,
    descriptor: PayloadDescriptor,
    next_index: u64,
    accepted_bytes: u64,
    hasher: blake3::Hasher,
}

impl PayloadStreamValidator {
    /// Begin one descriptor-bound transfer.
    ///
    /// # Errors
    /// Returns a closed error for invalid identities or an oversized descriptor.
    pub fn new(
        parent_digest: [u8; 32],
        request_id: [u8; 16],
        attempt_id: [u8; 16],
        direction: PayloadDirection,
        descriptor: PayloadDescriptor,
    ) -> Result<Self, SandboxProviderProtocolError> {
        if parent_digest == [0; 32] || request_id == [0; 16] || attempt_id == [0; 16] {
            return Err(SandboxProviderProtocolError::FieldOutOfBounds);
        }
        validate_payload_descriptor(&descriptor, direction)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(direction.domain());
        Ok(Self {
            parent_digest,
            request_id,
            attempt_id,
            direction,
            descriptor,
            next_index: 0,
            accepted_bytes: 0,
            hasher,
        })
    }

    /// Accept the next exact contiguous chunk.
    ///
    /// # Errors
    /// Rejects foreign, duplicate, reordered, gapped, or wrongly sized chunks.
    pub fn accept(
        &mut self,
        chunk: &SandboxPayloadChunk,
    ) -> Result<(), SandboxProviderProtocolError> {
        chunk.validate(&chunk.unsigned_value())?;
        let remaining = self
            .descriptor
            .byte_length
            .saturating_sub(self.accepted_bytes);
        let expected_size = remaining.min(PAYLOAD_CHUNK_BYTES as u64);
        let identity_mismatch = chunk.parent_digest != self.parent_digest
            || chunk.request_id != self.request_id
            || chunk.attempt_id != self.attempt_id
            || chunk.direction != self.direction;
        let position_mismatch =
            chunk.index != self.next_index || chunk.offset != self.accepted_bytes;
        if identity_mismatch
            || position_mismatch
            || chunk.bytes.len() as u64 != expected_size
            || expected_size == 0
        {
            return Err(SandboxProviderProtocolError::InconsistentFields);
        }
        self.hasher.update(&chunk.bytes);
        self.accepted_bytes += expected_size;
        self.next_index += 1;
        Ok(())
    }

    /// Finish after the exact descriptor length and digest have been observed.
    ///
    /// # Errors
    /// Rejects missing chunks or an aggregate digest mismatch.
    pub fn finish(self) -> Result<(), SandboxProviderProtocolError> {
        if self.accepted_bytes != self.descriptor.byte_length {
            return Err(SandboxProviderProtocolError::InconsistentFields);
        }
        (self.hasher.finalize().as_bytes() == &self.descriptor.digest)
            .then_some(())
            .ok_or(SandboxProviderProtocolError::DigestMismatch)
    }
}

/// Named NXP1 network exchange plan nested in SPX1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkExchangePlan {
    pub exchange_id: [u8; 16],
    pub occurrence: u64,
    pub capability_id: String,
    pub request_length: u64,
    pub request_digest: [u8; 32],
    pub response_maximum: u64,
    pub expected_response_digest: [u8; 32],
    pub retention_policy_digest: [u8; 32],
    pub plan_digest: [u8; 32],
}

/// Named fifteen-digest authority block carried by SPX1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecuteAuthority {
    pub evr1_digest: [u8; 32],
    pub cpf1_digest: [u8; 32],
    pub cfb1_digest: [u8; 32],
    pub fixture_contract_digest: [u8; 32],
    pub fixture_digest: [u8; 32],
    pub execution_profile_digest: [u8; 32],
    pub lps1_digest: [u8; 32],
    pub sim1_digest: [u8; 32],
    pub apt1_digest: [u8; 32],
    pub trs1_digest: [u8; 32],
    pub rvs1_digest: [u8; 32],
    pub spm1_digest: [u8; 32],
    pub pcf1_digest: [u8; 32],
    pub pcr1_digest: [u8; 32],
    pub hcp1_digest: [u8; 32],
}

/// Independently decoded SPX1 execute request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxExecuteRequest {
    pub request: RequestAuthority,
    pub attempt_id: [u8; 16],
    pub authority: ExecuteAuthority,
    pub capability_ids: Vec<String>,
    pub adapter_input: PayloadDescriptor,
    pub network_plans: Vec<NetworkExchangePlan>,
    pub request_digest: [u8; 32],
}

impl SandboxExecuteRequest {
    /// Decode and fully validate exact canonical SPX1 bytes.
    ///
    /// # Errors
    /// Returns a closed protocol error for malformed or inconsistent input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxProviderProtocolError> {
        let value = decode_document(bytes)?;
        let (fields, request_digest) = self_digested::<22>(&value, "SPX1")?;
        let request = Self {
            request: decode_request_authority(&fields[2])?,
            attempt_id: id16(&fields[3])?,
            authority: ExecuteAuthority::decode(&fields[4..19])?,
            capability_ids: decode_identifiers(&fields[19])?,
            adapter_input: decode_payload_descriptor(&fields[20])?,
            network_plans: decode_network_plans(&fields[21])?,
            request_digest,
        };
        request.validate(fields).map(|()| request)
    }

    fn validate(&self, unsigned: &[Value; 22]) -> Result<(), SandboxProviderProtocolError> {
        validate_request_authority(&self.request)?;
        if self.attempt_id == [0; 16]
            || self.authority.has_zero_digest()
            || self.request.apt1_digest != self.authority.apt1_digest
            || self.capability_ids.len() > MAX_LIST_ENTRIES
            || self.network_plans.len() > MAX_LIST_ENTRIES
        {
            return Err(SandboxProviderProtocolError::FieldOutOfBounds);
        }
        validate_payload_descriptor(&self.adapter_input, PayloadDirection::Input)?;
        validate_identifier_order(&self.capability_ids)?;
        validate_network_plans(&self.network_plans)?;
        verify_digest("SPX1", unsigned, self.request_digest)
    }
}

/// Named thirteen-digest authority block carried by AGR1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionAuthority {
    pub evr1_digest: [u8; 32],
    pub fixture_contract_digest: [u8; 32],
    pub fixture_digest: [u8; 32],
    pub execution_profile_digest: [u8; 32],
    pub lps1_digest: [u8; 32],
    pub sim1_digest: [u8; 32],
    pub apt1_digest: [u8; 32],
    pub trs1_digest: [u8; 32],
    pub rvs1_digest: [u8; 32],
    pub spm1_digest: [u8; 32],
    pub pcf1_digest: [u8; 32],
    pub pcr1_digest: [u8; 32],
    pub hcp1_digest: [u8; 32],
}

/// Independently decoded signed AGR1 admission grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionGrant {
    pub request_id: [u8; 16],
    pub attempt_id: [u8; 16],
    pub authority: AdmissionAuthority,
    pub trust_epoch: u64,
    pub revocation_epoch: u64,
    pub policy_epoch: u64,
    pub elm1_digest: [u8; 32],
    pub input_digest: [u8; 32],
    pub exchange_plan_digests: Vec<[u8; 32]>,
    pub expected_launch_policy_digest: [u8; 32],
    pub expected_readback_set_digest: [u8; 32],
    pub runtime_attestation_key_id: String,
    pub grant_digest: [u8; 32],
    pub signature: [u8; 64],
}

impl AdmissionGrant {
    /// Decode and fully validate exact canonical AGR1 bytes.
    ///
    /// # Errors
    /// Returns a closed protocol error for malformed or inconsistent input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxProviderProtocolError> {
        let value = decode_document(bytes)?;
        let (fields, grant_digest, signature) = signed::<26>(&value, "AGR1")?;
        let grant = Self {
            request_id: id16(&fields[2])?,
            attempt_id: id16(&fields[3])?,
            authority: AdmissionAuthority::decode(&fields[4..17])?,
            trust_epoch: uint(&fields[17])?,
            revocation_epoch: uint(&fields[18])?,
            policy_epoch: uint(&fields[19])?,
            elm1_digest: digest32(&fields[20])?,
            input_digest: digest32(&fields[21])?,
            exchange_plan_digests: decode_digest_list(&fields[22])?,
            expected_launch_policy_digest: digest32(&fields[23])?,
            expected_readback_set_digest: digest32(&fields[24])?,
            runtime_attestation_key_id: key_id(&fields[25])?,
            grant_digest,
            signature,
        };
        grant.validate(fields).map(|()| grant)
    }

    /// Verify AGR1 using a caller-authorized runtime-attestation key.
    ///
    /// # Errors
    /// Returns a closed protocol error when validation or verification fails.
    pub fn verify_signature(
        &self,
        key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), SandboxProviderProtocolError> {
        let unsigned = self.unsigned_value();
        self.validate(&unsigned)?;
        verify_signature("AGR1", &self.grant_digest, &self.signature, key)
    }

    fn validate(&self, unsigned: &[Value; 26]) -> Result<(), SandboxProviderProtocolError> {
        if self.request_id == [0; 16]
            || self.attempt_id == [0; 16]
            || self.authority.has_zero_digest()
            || [
                self.elm1_digest,
                self.input_digest,
                self.expected_launch_policy_digest,
                self.expected_readback_set_digest,
            ]
            .contains(&[0; 32])
            || invalid_digest_list(&self.exchange_plan_digests)
            || !valid_key_id(&self.runtime_attestation_key_id)
        {
            return Err(SandboxProviderProtocolError::FieldOutOfBounds);
        }
        require_signature(&self.signature)?;
        verify_digest("AGR1", unsigned, self.grant_digest)
    }

    fn unsigned_value(&self) -> [Value; 26] {
        [
            text_value("AGR1"),
            uint_value(1),
            bytes_value(&self.request_id),
            bytes_value(&self.attempt_id),
            bytes_value(&self.authority.evr1_digest),
            bytes_value(&self.authority.fixture_contract_digest),
            bytes_value(&self.authority.fixture_digest),
            bytes_value(&self.authority.execution_profile_digest),
            bytes_value(&self.authority.lps1_digest),
            bytes_value(&self.authority.sim1_digest),
            bytes_value(&self.authority.apt1_digest),
            bytes_value(&self.authority.trs1_digest),
            bytes_value(&self.authority.rvs1_digest),
            bytes_value(&self.authority.spm1_digest),
            bytes_value(&self.authority.pcf1_digest),
            bytes_value(&self.authority.pcr1_digest),
            bytes_value(&self.authority.hcp1_digest),
            uint_value(self.trust_epoch),
            uint_value(self.revocation_epoch),
            uint_value(self.policy_epoch),
            bytes_value(&self.elm1_digest),
            bytes_value(&self.input_digest),
            digest_list_value(&self.exchange_plan_digests),
            bytes_value(&self.expected_launch_policy_digest),
            bytes_value(&self.expected_readback_set_digest),
            text_value(&self.runtime_attestation_key_id),
        ]
    }
}

/// Closed SPY1 terminal outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxTerminalOutcome {
    Completed,
    Cancelled,
    UnavailableBeforeAdmission,
    Rejected,
    UnavailableAfterAdmission,
}

impl SandboxTerminalOutcome {
    const fn code(self) -> u64 {
        match self {
            Self::Completed => 0,
            Self::Cancelled => 1,
            Self::UnavailableBeforeAdmission => 2,
            Self::Rejected => 3,
            Self::UnavailableAfterAdmission => 4,
        }
    }

    const fn decode(code: u64) -> Result<Self, SandboxProviderProtocolError> {
        match code {
            0 => Ok(Self::Completed),
            1 => Ok(Self::Cancelled),
            2 => Ok(Self::UnavailableBeforeAdmission),
            3 => Ok(Self::Rejected),
            4 => Ok(Self::UnavailableAfterAdmission),
            _ => Err(SandboxProviderProtocolError::InvalidEncoding),
        }
    }
}

fn event_position(events: &[u8], event: u8) -> Option<usize> {
    events.iter().position(|candidate| *candidate == event)
}

fn valid_lifecycle_prefix(events: &[u8]) -> bool {
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
    outcome: SandboxTerminalOutcome,
    events: &[u8],
) -> Result<(), SandboxProviderProtocolError> {
    let valid = match outcome {
        SandboxTerminalOutcome::UnavailableBeforeAdmission | SandboxTerminalOutcome::Rejected => {
            events.is_empty()
        }
        SandboxTerminalOutcome::Completed => {
            events == [LAUNCHER_READY_EVENT, EXECUTION_RELEASED_EVENT]
        }
        SandboxTerminalOutcome::Cancelled => {
            events.split_last().is_some_and(|(terminal, lifecycle)| {
                *terminal == 1 && valid_lifecycle_prefix(lifecycle)
            })
        }
        SandboxTerminalOutcome::UnavailableAfterAdmission => {
            events.split_last().is_some_and(|(terminal, lifecycle)| {
                (*terminal == 0 || (2..=10).contains(terminal)) && valid_lifecycle_prefix(lifecycle)
            })
        }
    };
    valid
        .then_some(())
        .ok_or(SandboxProviderProtocolError::InconsistentFields)
}

fn validate_lifecycle_events(
    outcome: SandboxTerminalOutcome,
    events: &[u8],
    receipt: &SandboxProviderReceipt,
) -> Result<(), SandboxProviderProtocolError> {
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
    let outcome_matches = outcome != SandboxTerminalOutcome::Completed
        || (receipt.ready1_digest.is_some()
            && receipt.release1_digest.is_some()
            && denied.is_none());
    (stage_matches && outcome_matches)
        .then_some(())
        .ok_or(SandboxProviderProtocolError::InconsistentFields)
}

/// Independently decoded signed SPY1 terminal result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxProviderResult {
    pub request_id: [u8; 16],
    pub attempt_id: [u8; 16],
    pub outcome: SandboxTerminalOutcome,
    pub output: Option<PayloadDescriptor>,
    pub agr1_digest: Option<[u8; 32]>,
    pub spr1_digest: Option<[u8; 32]>,
    pub operational_events: Vec<u8>,
    pub runtime_attestation_key_id: String,
    pub result_digest: [u8; 32],
    pub signature: [u8; 64],
}

impl SandboxProviderResult {
    /// Decode and fully validate exact canonical SPY1 bytes.
    ///
    /// # Errors
    /// Returns a closed protocol error for malformed or inconsistent input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxProviderProtocolError> {
        let value = decode_document(bytes)?;
        let (fields, result_digest, signature) = signed::<10>(&value, "SPY1")?;
        let result = Self {
            request_id: id16(&fields[2])?,
            attempt_id: id16(&fields[3])?,
            outcome: SandboxTerminalOutcome::decode(uint(&fields[4])?)?,
            output: decode_output(&fields[5])?,
            agr1_digest: optional_digest(&fields[6])?,
            spr1_digest: optional_digest(&fields[7])?,
            operational_events: decode_u8_list(&fields[8])?,
            runtime_attestation_key_id: key_id(&fields[9])?,
            result_digest,
            signature,
        };
        result.validate(fields).map(|()| result)
    }

    /// Verify SPY1 using a caller-authorized runtime-attestation key.
    ///
    /// # Errors
    /// Returns a closed protocol error when validation or verification fails.
    pub fn verify_signature(
        &self,
        key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), SandboxProviderProtocolError> {
        let unsigned = self.unsigned_value();
        self.validate(&unsigned)?;
        verify_signature("SPY1", &self.result_digest, &self.signature, key)
    }

    /// Validate this result against the exact referenced SPR1 lifecycle evidence.
    ///
    /// # Errors
    /// Returns a closed error when identities, authority, or lifecycle events disagree.
    pub fn validate_receipt_lifecycle(
        &self,
        receipt: &SandboxProviderReceipt,
    ) -> Result<(), SandboxProviderProtocolError> {
        self.validate(&self.unsigned_value())?;
        receipt.validate(&receipt.unsigned_value())?;
        if self.attempt_id != receipt.attempt_id
            || self.agr1_digest != Some(receipt.authority.agr1_digest)
            || self.spr1_digest != Some(receipt.receipt_digest)
            || self.runtime_attestation_key_id != receipt.runtime_attestation_key_id
        {
            return Err(SandboxProviderProtocolError::InconsistentFields);
        }
        validate_lifecycle_events(self.outcome, &self.operational_events, receipt)
    }

    fn validate(&self, unsigned: &[Value; 10]) -> Result<(), SandboxProviderProtocolError> {
        if self.request_id == [0; 16]
            || self.attempt_id == [0; 16]
            || self.operational_events.len() > MAX_LIST_ENTRIES
            || self.operational_events.iter().any(|code| *code > 13)
            || !valid_key_id(&self.runtime_attestation_key_id)
        {
            return Err(SandboxProviderProtocolError::FieldOutOfBounds);
        }
        validate_terminal_event_shape(self.outcome, &self.operational_events)?;
        require_signature(&self.signature)?;
        self.output.as_ref().map_or(Ok(()), |output| {
            validate_payload_descriptor(output, PayloadDirection::Output)
        })?;
        let post_admission = nonzero_optional(self.agr1_digest)
            && nonzero_optional(self.spr1_digest)
            && self.output.is_none();
        let valid = match self.outcome {
            SandboxTerminalOutcome::Completed => {
                self.output.is_some()
                    && nonzero_optional(self.agr1_digest)
                    && nonzero_optional(self.spr1_digest)
            }
            SandboxTerminalOutcome::Cancelled
            | SandboxTerminalOutcome::UnavailableAfterAdmission => post_admission,
            SandboxTerminalOutcome::UnavailableBeforeAdmission
            | SandboxTerminalOutcome::Rejected => {
                self.output.is_none() && self.agr1_digest.is_none() && self.spr1_digest.is_none()
            }
        };
        if !valid {
            return Err(SandboxProviderProtocolError::InconsistentFields);
        }
        verify_digest("SPY1", unsigned, self.result_digest)
    }

    fn unsigned_value(&self) -> [Value; 10] {
        [
            text_value("SPY1"),
            uint_value(1),
            bytes_value(&self.request_id),
            bytes_value(&self.attempt_id),
            uint_value(self.outcome.code()),
            self.output.as_ref().map_or(Value::Null, output_value),
            optional_digest_value(self.agr1_digest.as_ref()),
            optional_digest_value(self.spr1_digest.as_ref()),
            Value::Array(
                self.operational_events
                    .iter()
                    .map(|code| uint_value(u64::from(*code)))
                    .collect(),
            ),
            text_value(&self.runtime_attestation_key_id),
        ]
    }
}

/// Closed SPE1 failure code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxProviderErrorCode {
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
    AttemptInProgress,
    PayloadTransferTimeout,
}

impl SandboxProviderErrorCode {
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
            Self::AttemptInProgress => 17,
            Self::PayloadTransferTimeout => 18,
        }
    }

    const fn decode(code: u64) -> Result<Self, SandboxProviderProtocolError> {
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
            17 => Ok(Self::AttemptInProgress),
            18 => Ok(Self::PayloadTransferTimeout),
            _ => Err(SandboxProviderProtocolError::InvalidEncoding),
        }
    }
}

/// Independently decoded signed SPE1 failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxProviderError {
    pub operation: Option<u8>,
    pub request_id: Option<[u8; 16]>,
    pub request_digest: Option<[u8; 32]>,
    pub attempt_id: Option<[u8; 16]>,
    pub code: SandboxProviderErrorCode,
    pub safe_detail: Option<String>,
    pub runtime_attestation_key_id: String,
    pub error_digest: [u8; 32],
    pub signature: [u8; 64],
}

impl SandboxProviderError {
    /// Decode and fully validate exact canonical SPE1 bytes.
    ///
    /// # Errors
    /// Returns a closed protocol error for malformed or inconsistent input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxProviderProtocolError> {
        let value = decode_document(bytes)?;
        let (fields, error_digest, signature) = signed::<9>(&value, "SPE1")?;
        let error = Self {
            operation: optional_u8(&fields[2])?,
            request_id: optional_id16(&fields[3])?,
            request_digest: optional_digest(&fields[4])?,
            attempt_id: optional_id16(&fields[5])?,
            code: SandboxProviderErrorCode::decode(uint(&fields[6])?)?,
            safe_detail: optional_text(&fields[7], MAX_SAFE_DETAIL_BYTES)?,
            runtime_attestation_key_id: key_id(&fields[8])?,
            error_digest,
            signature,
        };
        error.validate(fields).map(|()| error)
    }

    /// Verify SPE1 using a caller-authorized runtime-attestation key.
    ///
    /// # Errors
    /// Returns a closed protocol error when validation or verification fails.
    pub fn verify_signature(
        &self,
        key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), SandboxProviderProtocolError> {
        let unsigned = self.unsigned_value();
        self.validate(&unsigned)?;
        verify_signature("SPE1", &self.error_digest, &self.signature, key)
    }

    fn validate(&self, unsigned: &[Value; 9]) -> Result<(), SandboxProviderProtocolError> {
        if self.operation.is_some_and(|operation| operation > 3)
            || self.request_id == Some([0; 16])
            || self.request_digest == Some([0; 32])
            || self.attempt_id == Some([0; 16])
            || !valid_key_id(&self.runtime_attestation_key_id)
            || self.safe_detail.as_ref().is_some_and(|detail| {
                detail.is_empty() || detail.len() > MAX_SAFE_DETAIL_BYTES || detail.contains('\0')
            })
        {
            return Err(SandboxProviderProtocolError::FieldOutOfBounds);
        }
        require_signature(&self.signature)?;
        if (self.request_digest.is_some() && self.request_id.is_none())
            || (self.attempt_id.is_some()
                && (self.operation.is_none() || self.request_id.is_none()))
        {
            return Err(SandboxProviderProtocolError::InconsistentFields);
        }
        if self.code == SandboxProviderErrorCode::PayloadTransferTimeout
            && (self.operation != Some(1)
                || self.request_id.is_none()
                || self.request_digest.is_none()
                || self.attempt_id.is_none())
        {
            return Err(SandboxProviderProtocolError::InconsistentFields);
        }
        verify_digest("SPE1", unsigned, self.error_digest)
    }

    fn unsigned_value(&self) -> [Value; 9] {
        [
            text_value("SPE1"),
            uint_value(1),
            self.operation
                .map_or(Value::Null, |operation| uint_value(u64::from(operation))),
            optional_bytes_value(self.request_id.as_ref()),
            optional_digest_value(self.request_digest.as_ref()),
            optional_bytes_value(self.attempt_id.as_ref()),
            uint_value(self.code.code()),
            self.safe_detail
                .as_ref()
                .map_or(Value::Null, |detail| text_value(detail)),
            text_value(&self.runtime_attestation_key_id),
        ]
    }
}

/// Named eight-digest authority block carried by SPR1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptAuthority {
    pub agr1_digest: [u8; 32],
    pub spm1_digest: [u8; 32],
    pub provider_binary_digest: [u8; 32],
    pub lps1_digest: [u8; 32],
    pub sim1_digest: [u8; 32],
    pub apt1_digest: [u8; 32],
    pub trs1_digest: [u8; 32],
    pub rvs1_digest: [u8; 32],
}

/// Independently decoded signed SPR1 attempt receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxProviderReceipt {
    pub attempt_id: [u8; 16],
    pub authority: ReceiptAuthority,
    pub trust_epoch: u64,
    pub revocation_epoch: u64,
    pub policy_epoch: u64,
    pub hcp1_digest: [u8; 32],
    pub elm1_digest: [u8; 32],
    pub network_transcript_digests: Vec<[u8; 32]>,
    pub ready1_digest: Option<[u8; 32]>,
    pub release1_digest: Option<[u8; 32]>,
    pub requested_configuration_evidence: [u8; 32],
    pub kernel_observation_evidence: [u8; 32],
    pub negative_probe_evidence: [u8; 32],
    pub termination_evidence: [u8; 32],
    pub sau1_digest: [u8; 32],
    pub runtime_attestation_key_id: String,
    pub receipt_digest: [u8; 32],
    pub signature: [u8; 64],
}

impl SandboxProviderReceipt {
    /// Decode and fully validate exact canonical SPR1 bytes.
    ///
    /// # Errors
    /// Returns a closed protocol error for malformed or inconsistent input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxProviderProtocolError> {
        let value = decode_document(bytes)?;
        let (fields, receipt_digest, signature) = signed::<25>(&value, "SPR1")?;
        let receipt = Self {
            attempt_id: id16(&fields[2])?,
            authority: ReceiptAuthority::decode(&fields[3..11])?,
            trust_epoch: uint(&fields[11])?,
            revocation_epoch: uint(&fields[12])?,
            policy_epoch: uint(&fields[13])?,
            hcp1_digest: digest32(&fields[14])?,
            elm1_digest: digest32(&fields[15])?,
            network_transcript_digests: decode_digest_list(&fields[16])?,
            ready1_digest: optional_digest(&fields[17])?,
            release1_digest: optional_digest(&fields[18])?,
            requested_configuration_evidence: digest32(&fields[19])?,
            kernel_observation_evidence: digest32(&fields[20])?,
            negative_probe_evidence: digest32(&fields[21])?,
            termination_evidence: digest32(&fields[22])?,
            sau1_digest: digest32(&fields[23])?,
            runtime_attestation_key_id: key_id(&fields[24])?,
            receipt_digest,
            signature,
        };
        receipt.validate(fields).map(|()| receipt)
    }

    /// Verify SPR1 using a caller-authorized runtime-attestation key.
    ///
    /// # Errors
    /// Returns a closed protocol error when validation or verification fails.
    pub fn verify_signature(
        &self,
        key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), SandboxProviderProtocolError> {
        let unsigned = self.unsigned_value();
        self.validate(&unsigned)?;
        verify_signature("SPR1", &self.receipt_digest, &self.signature, key)
    }

    fn validate(&self, unsigned: &[Value; 25]) -> Result<(), SandboxProviderProtocolError> {
        if self.attempt_id == [0; 16]
            || self.authority.has_zero_digest()
            || [
                self.hcp1_digest,
                self.elm1_digest,
                self.requested_configuration_evidence,
                self.kernel_observation_evidence,
                self.negative_probe_evidence,
                self.termination_evidence,
                self.sau1_digest,
            ]
            .contains(&[0; 32])
            || invalid_digest_list(&self.network_transcript_digests)
            || self.ready1_digest == Some([0; 32])
            || self.release1_digest == Some([0; 32])
            || !valid_key_id(&self.runtime_attestation_key_id)
        {
            return Err(SandboxProviderProtocolError::FieldOutOfBounds);
        }
        if self.release1_digest.is_some() && self.ready1_digest.is_none() {
            return Err(SandboxProviderProtocolError::InconsistentFields);
        }
        require_signature(&self.signature)?;
        verify_digest("SPR1", unsigned, self.receipt_digest)
    }

    fn unsigned_value(&self) -> [Value; 25] {
        [
            text_value("SPR1"),
            uint_value(1),
            bytes_value(&self.attempt_id),
            bytes_value(&self.authority.agr1_digest),
            bytes_value(&self.authority.spm1_digest),
            bytes_value(&self.authority.provider_binary_digest),
            bytes_value(&self.authority.lps1_digest),
            bytes_value(&self.authority.sim1_digest),
            bytes_value(&self.authority.apt1_digest),
            bytes_value(&self.authority.trs1_digest),
            bytes_value(&self.authority.rvs1_digest),
            uint_value(self.trust_epoch),
            uint_value(self.revocation_epoch),
            uint_value(self.policy_epoch),
            bytes_value(&self.hcp1_digest),
            bytes_value(&self.elm1_digest),
            digest_list_value(&self.network_transcript_digests),
            optional_digest_value(self.ready1_digest.as_ref()),
            optional_digest_value(self.release1_digest.as_ref()),
            bytes_value(&self.requested_configuration_evidence),
            bytes_value(&self.kernel_observation_evidence),
            bytes_value(&self.negative_probe_evidence),
            bytes_value(&self.termination_evidence),
            bytes_value(&self.sau1_digest),
            text_value(&self.runtime_attestation_key_id),
        ]
    }
}

impl ExecuteAuthority {
    fn decode(fields: &[Value]) -> Result<Self, SandboxProviderProtocolError> {
        let fields: &[Value; 15] = fields
            .try_into()
            .map_err(|_| SandboxProviderProtocolError::InvalidEncoding)?;
        Ok(Self {
            evr1_digest: digest32(&fields[0])?,
            cpf1_digest: digest32(&fields[1])?,
            cfb1_digest: digest32(&fields[2])?,
            fixture_contract_digest: digest32(&fields[3])?,
            fixture_digest: digest32(&fields[4])?,
            execution_profile_digest: digest32(&fields[5])?,
            lps1_digest: digest32(&fields[6])?,
            sim1_digest: digest32(&fields[7])?,
            apt1_digest: digest32(&fields[8])?,
            trs1_digest: digest32(&fields[9])?,
            rvs1_digest: digest32(&fields[10])?,
            spm1_digest: digest32(&fields[11])?,
            pcf1_digest: digest32(&fields[12])?,
            pcr1_digest: digest32(&fields[13])?,
            hcp1_digest: digest32(&fields[14])?,
        })
    }

    const fn digests(&self) -> [[u8; 32]; 15] {
        [
            self.evr1_digest,
            self.cpf1_digest,
            self.cfb1_digest,
            self.fixture_contract_digest,
            self.fixture_digest,
            self.execution_profile_digest,
            self.lps1_digest,
            self.sim1_digest,
            self.apt1_digest,
            self.trs1_digest,
            self.rvs1_digest,
            self.spm1_digest,
            self.pcf1_digest,
            self.pcr1_digest,
            self.hcp1_digest,
        ]
    }

    fn has_zero_digest(&self) -> bool {
        self.digests().contains(&[0; 32])
    }
}

macro_rules! named_digest_authority {
    ($type:ty, $count:literal, $($field:ident),+ $(,)?) => {
        impl $type {
            fn decode(fields: &[Value]) -> Result<Self, SandboxProviderProtocolError> {
                let fields: &[Value; $count] = fields
                    .try_into()
                    .map_err(|_| SandboxProviderProtocolError::InvalidEncoding)?;
                let [$($field),+] = fields;
                Ok(Self {
                    $($field: digest32($field)?),+
                })
            }

            const fn digests(&self) -> [[u8; 32]; $count] {
                [$(self.$field),+]
            }

            fn has_zero_digest(&self) -> bool {
                self.digests().contains(&[0; 32])
            }
        }
    };
}

named_digest_authority!(
    AdmissionAuthority,
    13,
    evr1_digest,
    fixture_contract_digest,
    fixture_digest,
    execution_profile_digest,
    lps1_digest,
    sim1_digest,
    apt1_digest,
    trs1_digest,
    rvs1_digest,
    spm1_digest,
    pcf1_digest,
    pcr1_digest,
    hcp1_digest,
);

named_digest_authority!(
    ReceiptAuthority,
    8,
    agr1_digest,
    spm1_digest,
    provider_binary_digest,
    lps1_digest,
    sim1_digest,
    apt1_digest,
    trs1_digest,
    rvs1_digest,
);

fn decode_payload_descriptor(
    value: &Value,
) -> Result<PayloadDescriptor, SandboxProviderProtocolError> {
    let fields = array::<2>(value)?;
    Ok(PayloadDescriptor {
        byte_length: uint(&fields[0])?,
        digest: digest32(&fields[1])?,
    })
}

fn decode_network_plans(
    value: &Value,
) -> Result<Vec<NetworkExchangePlan>, SandboxProviderProtocolError> {
    bounded_array(value, 0)?
        .iter()
        .map(|value| {
            let fields = array::<11>(value)?;
            validate_magic(fields, "NXP1")?;
            let plan = NetworkExchangePlan {
                exchange_id: id16(&fields[2])?,
                occurrence: uint(&fields[3])?,
                capability_id: identifier(&fields[4])?,
                request_length: uint(&fields[5])?,
                request_digest: digest32(&fields[6])?,
                response_maximum: uint(&fields[7])?,
                expected_response_digest: digest32(&fields[8])?,
                retention_policy_digest: digest32(&fields[9])?,
                plan_digest: digest32(&fields[10])?,
            };
            validate_network_plan(&plan, fields)?;
            Ok(plan)
        })
        .collect()
}

fn validate_network_plan(
    value: &NetworkExchangePlan,
    fields: &[Value; 11],
) -> Result<(), SandboxProviderProtocolError> {
    if value.exchange_id == [0; 16]
        || value.request_length > MAX_INPUT_BYTES_U64
        || value.request_digest == [0; 32]
        || !(1..=MAX_INPUT_BYTES_U64).contains(&value.response_maximum)
        || value.expected_response_digest == [0; 32]
        || value.retention_policy_digest == [0; 32]
    {
        return Err(SandboxProviderProtocolError::FieldOutOfBounds);
    }
    verify_digest_with_domain(
        b"PiglorOS.NetworkExchangePlan.v1\0",
        &fields[..10],
        value.plan_digest,
    )
}

fn validate_network_plans(
    values: &[NetworkExchangePlan],
) -> Result<(), SandboxProviderProtocolError> {
    for (index, value) in values.iter().enumerate() {
        let encoded = network_plan_value(value);
        validate_network_plan(value, &encoded)?;
        let mut expected = 0_u64;
        for candidate in &values[..index] {
            if candidate.exchange_id == value.exchange_id {
                expected += 1;
            }
        }
        if value.occurrence != expected {
            return Err(SandboxProviderProtocolError::InconsistentFields);
        }
    }
    Ok(())
}

fn network_plan_value(value: &NetworkExchangePlan) -> [Value; 11] {
    [
        text_value("NXP1"),
        uint_value(1),
        bytes_value(&value.exchange_id),
        uint_value(value.occurrence),
        text_value(&value.capability_id),
        uint_value(value.request_length),
        bytes_value(&value.request_digest),
        uint_value(value.response_maximum),
        bytes_value(&value.expected_response_digest),
        bytes_value(&value.retention_policy_digest),
        bytes_value(&value.plan_digest),
    ]
}

fn decode_output(value: &Value) -> Result<Option<PayloadDescriptor>, SandboxProviderProtocolError> {
    if value == &Value::Null {
        return Ok(None);
    }
    decode_payload_descriptor(value).map(Some)
}

fn output_value(value: &PayloadDescriptor) -> Value {
    Value::Array(vec![
        uint_value(value.byte_length),
        bytes_value(&value.digest),
    ])
}
