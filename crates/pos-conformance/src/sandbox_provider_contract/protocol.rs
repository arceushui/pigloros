use std::collections::BTreeMap;

use ciborium::value::Value;

use crate::identifier;

use super::codec::{
    array, bytes, decode, digest, digest_with_domain, encode, fixed, optional_fixed, sign, text,
    uint, validate_magic, value_bytes, value_optional_bytes, value_text, value_uint, verify,
};
use super::{
    SandboxContractErrorV1, MAX_SANDBOX_PAYLOAD_BYTES_V1, MAX_SANDBOX_PAYLOAD_CHUNKS_V1,
    MAX_SANDBOX_PROVIDER_ENTRIES_V1, SANDBOX_PAYLOAD_CHUNK_BYTES_V1,
};

const SPX1: &str = "SPX1";
const AGR1: &str = "AGR1";
const SPY1: &str = "SPY1";
const SPE1: &str = "SPE1";
const SPR1: &str = "SPR1";
const SBC1: &str = "SBC1";
const NXP1: &str = "NXP1";
const NXP1_DIGEST_DOMAIN: &[u8] = b"PiglorOS.NetworkExchangePlan.v1\0";
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_INPUT_BYTES: usize = 128 * 1024 * 1024;
const MAX_SAFE_DETAIL_BYTES: usize = 256;
const LAUNCHER_READY_EVENT: u64 = 11;
const EXECUTION_RELEASED_EVENT: u64 = 12;
const EXECUTION_RELEASE_DENIED_EVENT: u64 = 13;

/// Authority repeated by every Sandbox Provider request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestAuthorityV1 {
    /// Nonzero request identity.
    pub request_id: [u8; 16],
    /// Active administrator policy digest.
    pub apt1_digest: [u8; 32],
    /// Active policy epoch.
    pub policy_epoch: u64,
    /// Nonzero caller nonce.
    pub nonce: [u8; 16],
}

/// Direction of one provider payload transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadDirectionV1 {
    /// Evaluator-to-provider adapter input.
    Input,
    /// Provider-to-evaluator adapter output.
    Output,
}

impl PayloadDirectionV1 {
    const fn code(self) -> u64 {
        match self {
            Self::Input => 0,
            Self::Output => 1,
        }
    }

    const fn from_code(code: u64) -> Result<Self, SandboxContractErrorV1> {
        match code {
            0 => Ok(Self::Input),
            1 => Ok(Self::Output),
            _ => Err(SandboxContractErrorV1::FieldOutOfBounds),
        }
    }

    const fn digest_domain(self) -> &'static [u8] {
        match self {
            Self::Input => b"PiglorOS.SandboxInputBytes.v1\0",
            Self::Output => b"PiglorOS.SandboxOutputBytes.v1\0",
        }
    }
}

/// Bounded content-addressed payload descriptor carried by SPX1 or SPY1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadDescriptorV1 {
    /// Exact payload byte length.
    pub byte_length: u64,
    /// Direction-separated BLAKE3 digest of the complete payload.
    pub digest: [u8; 32],
}

impl PayloadDescriptorV1 {
    /// Construct a descriptor from exact payload bytes.
    ///
    /// # Errors
    /// Returns a closed error when the payload exceeds 128 MiB.
    pub fn from_bytes(
        direction: PayloadDirectionV1,
        bytes: &[u8],
    ) -> Result<Self, SandboxContractErrorV1> {
        let byte_length =
            u64::try_from(bytes.len()).map_err(|_| SandboxContractErrorV1::FieldOutOfBounds)?;
        if byte_length > MAX_SANDBOX_PAYLOAD_BYTES_V1 {
            return Err(SandboxContractErrorV1::FieldOutOfBounds);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(direction.digest_domain());
        hasher.update(bytes);
        Ok(Self {
            byte_length,
            digest: *hasher.finalize().as_bytes(),
        })
    }

    fn validate_for_direction(
        &self,
        direction: PayloadDirectionV1,
    ) -> Result<(), SandboxContractErrorV1> {
        if self.byte_length > MAX_SANDBOX_PAYLOAD_BYTES_V1 {
            return Err(SandboxContractErrorV1::FieldOutOfBounds);
        }
        if self.byte_length == 0 && self.digest != Self::from_bytes(direction, &[])?.digest {
            return Err(SandboxContractErrorV1::DigestMismatch);
        }
        Ok(())
    }
}

/// One self-digested, parent-bound SBC1 payload chunk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxPayloadChunkV1 {
    pub parent_digest: [u8; 32],
    pub request_id: [u8; 16],
    pub attempt_id: [u8; 16],
    pub direction: PayloadDirectionV1,
    pub index: u64,
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub chunk_digest: [u8; 32],
}

/// Exact NXP1 planned network exchange.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkExchangePlanV1 {
    /// Nonzero exchange identity.
    pub exchange_id: [u8; 16],
    /// Zero-based occurrence for this exchange identity.
    pub occurrence: u64,
    /// Exact admitted network capability identifier.
    pub capability_id: String,
    /// Exact request byte length.
    pub request_length: u64,
    /// Domain-separated request-byte digest.
    pub request_digest: [u8; 32],
    /// Maximum accepted response bytes.
    pub response_maximum: u64,
    /// Domain-separated expected response digest.
    pub expected_response_digest: [u8; 32],
    /// Exact NRP1 retention-policy digest.
    pub retention_policy_digest: [u8; 32],
    /// Self-digest over fields zero through nine.
    pub plan_digest: [u8; 32],
}

impl NetworkExchangePlanV1 {
    /// Compute and install the exact NXP1 plan digest.
    ///
    /// # Errors
    /// Returns a closed error when a plan field is invalid.
    pub fn seal(mut self) -> Result<Self, SandboxContractErrorV1> {
        self.validate_unsigned()?;
        self.plan_digest = digest_with_domain(NXP1_DIGEST_DOMAIN, &self.unsigned_value())?;
        Ok(self)
    }

    fn validate(&self) -> Result<(), SandboxContractErrorV1> {
        self.validate_unsigned()?;
        (self.plan_digest == digest_with_domain(NXP1_DIGEST_DOMAIN, &self.unsigned_value())?)
            .then_some(())
            .ok_or(SandboxContractErrorV1::DigestMismatch)
    }

    fn validate_unsigned(&self) -> Result<(), SandboxContractErrorV1> {
        if self.exchange_id == [0; 16]
            || !identifier(&self.capability_id, MAX_IDENTIFIER_BYTES)
            || self.request_length > MAX_INPUT_BYTES as u64
            || self.request_digest == [0; 32]
            || !(1..=128 * 1024 * 1024).contains(&self.response_maximum)
            || self.expected_response_digest == [0; 32]
            || self.retention_policy_digest == [0; 32]
        {
            Err(SandboxContractErrorV1::FieldOutOfBounds)
        } else {
            Ok(())
        }
    }

    fn unsigned_fields(&self) -> Vec<Value> {
        vec![
            value_text(NXP1),
            value_uint(1),
            value_bytes(&self.exchange_id),
            value_uint(self.occurrence),
            value_text(&self.capability_id),
            value_uint(self.request_length),
            value_bytes(&self.request_digest),
            value_uint(self.response_maximum),
            value_bytes(&self.expected_response_digest),
            value_bytes(&self.retention_policy_digest),
        ]
    }

    fn unsigned_value(&self) -> Value {
        Value::Array(self.unsigned_fields())
    }

    fn value(&self) -> Value {
        let mut fields = self.unsigned_fields();
        fields.push(value_bytes(&self.plan_digest));
        Value::Array(fields)
    }

    fn from_value(value: &Value) -> Result<Self, SandboxContractErrorV1> {
        let fields = array::<11>(value)?;
        validate_magic(fields, NXP1)?;
        let plan = Self {
            exchange_id: fixed(&fields[2])?,
            occurrence: uint(&fields[3])?,
            capability_id: text(&fields[4])?.to_owned(),
            request_length: uint(&fields[5])?,
            request_digest: fixed(&fields[6])?,
            response_maximum: uint(&fields[7])?,
            expected_response_digest: fixed(&fields[8])?,
            retention_policy_digest: fixed(&fields[9])?,
            plan_digest: fixed(&fields[10])?,
        };
        plan.validate().map(|()| plan)
    }
}

/// Exact self-digested SPX1 execute request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxExecuteRequestV1 {
    /// Common request authority.
    pub authority: RequestAuthorityV1,
    /// Nonzero attempt identity.
    pub attempt_id: [u8; 16],
    /// Exact EVR1 digest.
    pub evr1_digest: [u8; 32],
    /// Exact CPF1 digest.
    pub cpf1_digest: [u8; 32],
    /// Exact CFB1 digest.
    pub cfb1_digest: [u8; 32],
    /// Exact fixture-contract digest.
    pub fixture_contract_digest: [u8; 32],
    /// Exact fixture digest.
    pub fixture_digest: [u8; 32],
    /// Exact execution-profile digest.
    pub execution_profile_digest: [u8; 32],
    /// Exact LPS1 digest.
    pub lps1_digest: [u8; 32],
    /// Exact SIM1 digest.
    pub sim1_digest: [u8; 32],
    /// Exact APT1 digest.
    pub apt1_digest: [u8; 32],
    /// Exact TRS1 digest.
    pub trs1_digest: [u8; 32],
    /// Exact RVS1 digest.
    pub rvs1_digest: [u8; 32],
    /// Exact selected SPM1 digest.
    pub spm1_digest: [u8; 32],
    /// Exact PCF1 digest.
    pub pcf1_digest: [u8; 32],
    /// Exact PCR1 digest.
    pub pcr1_digest: [u8; 32],
    /// Exact HCP1 digest.
    pub hcp1_digest: [u8; 32],
    /// Strictly canonically ordered exact capability identifiers.
    pub capability_ids: Vec<String>,
    /// Exact bounded adapter input.
    pub adapter_input: PayloadDescriptorV1,
    /// Caller-ordered exchange plans.
    pub network_plans: Vec<NetworkExchangePlanV1>,
    /// Self-digest of the exact SPX1-U array.
    pub request_digest: [u8; 32],
}

/// Exact signed AGR1 admission grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionGrantV1 {
    /// Nonzero request identity.
    pub request_id: [u8; 16],
    /// Nonzero attempt identity.
    pub attempt_id: [u8; 16],
    /// Named authority and artifact identities bound by the admission decision.
    pub authority: AdmissionAuthorityV1,
    /// Independent trust epoch.
    pub trust_epoch: u64,
    /// Independent revocation epoch.
    pub revocation_epoch: u64,
    /// Independent policy epoch.
    pub policy_epoch: u64,
    /// Exact ELM1 digest.
    pub elm1_digest: [u8; 32],
    /// Exact adapter-input digest.
    pub input_digest: [u8; 32],
    /// Ordered NXP1 plan digests.
    pub exchange_plan_digests: Vec<[u8; 32]>,
    /// Expected launch-policy digest.
    pub expected_launch_policy_digest: [u8; 32],
    /// Expected readback-set digest.
    pub expected_readback_set_digest: [u8; 32],
    /// Runtime-attestation signing-key identifier.
    pub runtime_attestation_key_id: String,
    /// Self-digest of the exact AGR1-U array.
    pub grant_digest: [u8; 32],
    /// Runtime-attestation Ed25519 signature.
    pub signature: [u8; 64],
}

/// Provider-neutral authority identities bound by AGR1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionAuthorityV1 {
    /// Exact EVR1 digest.
    pub evr1_digest: [u8; 32],
    /// Exact fixture-contract digest.
    pub fixture_contract_digest: [u8; 32],
    /// Exact fixture digest.
    pub fixture_digest: [u8; 32],
    /// Exact execution-profile digest.
    pub execution_profile_digest: [u8; 32],
    /// Exact LPS1 digest.
    pub lps1_digest: [u8; 32],
    /// Exact SIM1 digest.
    pub sim1_digest: [u8; 32],
    /// Exact APT1 digest.
    pub apt1_digest: [u8; 32],
    /// Exact TRS1 digest.
    pub trs1_digest: [u8; 32],
    /// Exact RVS1 digest.
    pub rvs1_digest: [u8; 32],
    /// Exact SPM1 digest.
    pub spm1_digest: [u8; 32],
    /// Exact PCF1 digest.
    pub pcf1_digest: [u8; 32],
    /// Exact PCR1 digest.
    pub pcr1_digest: [u8; 32],
    /// Exact HCP1 digest.
    pub hcp1_digest: [u8; 32],
}

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
    AttemptInProgress,
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

/// Exact signed SPR1 attempt receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxProviderReceiptV1 {
    /// Nonzero attempt identity.
    pub attempt_id: [u8; 16],
    /// Named admission, provider, image, and policy identities.
    pub authority: ReceiptAuthorityV1,
    /// Independent trust epoch.
    pub trust_epoch: u64,
    /// Independent revocation epoch.
    pub revocation_epoch: u64,
    /// Independent policy epoch.
    pub policy_epoch: u64,
    /// Exact HCP1 digest.
    pub hcp1_digest: [u8; 32],
    /// Exact ELM1 digest.
    pub elm1_digest: [u8; 32],
    /// Ordered NXT1 transcript digests.
    pub network_transcript_digests: Vec<[u8; 32]>,
    /// Exact `ReadyV1` digest, once a valid ready message existed.
    pub ready1_digest: Option<[u8; 32]>,
    /// Exact `ReleaseV1` digest, once a valid release was issued.
    pub release1_digest: Option<[u8; 32]>,
    /// Final requested-configuration evidence digest.
    pub requested_configuration_evidence: [u8; 32],
    /// Final kernel-observation evidence digest.
    pub kernel_observation_evidence: [u8; 32],
    /// Final trusted-negative-probe evidence digest.
    pub negative_probe_evidence: [u8; 32],
    /// Final termination evidence digest.
    pub termination_evidence: [u8; 32],
    /// Terminal SAU1 digest.
    pub sau1_digest: [u8; 32],
    /// Runtime-attestation signing-key identifier.
    pub runtime_attestation_key_id: String,
    /// Self-digest of the exact SPR1-U array.
    pub receipt_digest: [u8; 32],
    /// Runtime-attestation Ed25519 signature.
    pub signature: [u8; 64],
}

/// Provider-neutral authority identities bound by SPR1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptAuthorityV1 {
    /// Exact AGR1 digest.
    pub agr1_digest: [u8; 32],
    /// Exact SPM1 digest.
    pub spm1_digest: [u8; 32],
    /// Exact provider-binary digest.
    pub provider_binary_digest: [u8; 32],
    /// Exact LPS1 digest.
    pub lps1_digest: [u8; 32],
    /// Exact SIM1 digest.
    pub sim1_digest: [u8; 32],
    /// Exact APT1 digest.
    pub apt1_digest: [u8; 32],
    /// Exact TRS1 digest.
    pub trs1_digest: [u8; 32],
    /// Exact RVS1 digest.
    pub rvs1_digest: [u8; 32],
}

impl SandboxPayloadChunkV1 {
    /// Compute and install the SBC1 self-digest.
    ///
    /// # Errors
    /// Returns a closed error when an unsigned field is invalid.
    pub fn seal(mut self) -> Result<Self, SandboxContractErrorV1> {
        self.validate_unsigned()?;
        self.chunk_digest = digest(SBC1, &self.unsigned_value())?;
        Ok(self)
    }

    /// Validate the chunk shape and self-digest.
    ///
    /// # Errors
    /// Returns a closed error for malformed chunk metadata or bytes.
    pub fn validate(&self) -> Result<(), SandboxContractErrorV1> {
        self.validate_unsigned()?;
        (self.chunk_digest == digest(SBC1, &self.unsigned_value())?)
            .then_some(())
            .ok_or(SandboxContractErrorV1::DigestMismatch)
    }

    /// Encode exact deterministic-CBOR SBC1 bytes.
    ///
    /// # Errors
    /// Returns a closed error when validation or encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SandboxContractErrorV1> {
        self.validate()?;
        encode(&Value::Array(vec![
            self.unsigned_value(),
            value_bytes(&self.chunk_digest),
        ]))
    }

    /// Decode exact deterministic-CBOR SBC1 bytes.
    ///
    /// # Errors
    /// Returns a closed error for malformed or noncanonical bytes.
    pub fn from_canonical_cbor(document_bytes: &[u8]) -> Result<Self, SandboxContractErrorV1> {
        let value = decode(document_bytes)?;
        let wrapper = array::<2>(&value)?;
        let fields = array::<9>(&wrapper[0])?;
        validate_magic(fields, SBC1)?;
        let chunk = Self {
            parent_digest: fixed(&fields[2])?,
            request_id: fixed(&fields[3])?,
            attempt_id: fixed(&fields[4])?,
            direction: PayloadDirectionV1::from_code(uint(&fields[5])?)?,
            index: uint(&fields[6])?,
            offset: uint(&fields[7])?,
            bytes: bytes(&fields[8])?.to_vec(),
            chunk_digest: fixed(&wrapper[1])?,
        };
        chunk.validate().map(|()| chunk)
    }

    fn validate_unsigned(&self) -> Result<(), SandboxContractErrorV1> {
        let expected_offset = self
            .index
            .checked_mul(SANDBOX_PAYLOAD_CHUNK_BYTES_V1 as u64)
            .ok_or(SandboxContractErrorV1::FieldOutOfBounds)?;
        if self.parent_digest == [0; 32]
            || self.request_id == [0; 16]
            || self.attempt_id == [0; 16]
            || self.index >= MAX_SANDBOX_PAYLOAD_CHUNKS_V1
            || self.offset != expected_offset
            || self.bytes.is_empty()
            || self.bytes.len() > SANDBOX_PAYLOAD_CHUNK_BYTES_V1
        {
            Err(SandboxContractErrorV1::FieldOutOfBounds)
        } else {
            Ok(())
        }
    }

    fn unsigned_value(&self) -> Value {
        Value::Array(vec![
            value_text(SBC1),
            value_uint(1),
            value_bytes(&self.parent_digest),
            value_bytes(&self.request_id),
            value_bytes(&self.attempt_id),
            value_uint(self.direction.code()),
            value_uint(self.index),
            value_uint(self.offset),
            value_bytes(&self.bytes),
        ])
    }
}

/// Incremental validator for one non-interleaved SBC1 payload sequence.
pub struct PayloadStreamValidatorV1 {
    parent_digest: [u8; 32],
    request_id: [u8; 16],
    attempt_id: [u8; 16],
    direction: PayloadDirectionV1,
    descriptor: PayloadDescriptorV1,
    next_index: u64,
    accepted_bytes: u64,
    hasher: blake3::Hasher,
}

impl PayloadStreamValidatorV1 {
    /// Begin validating one descriptor-bound transfer.
    ///
    /// # Errors
    /// Returns a closed error for zero identities or an oversized descriptor.
    pub fn new(
        parent_digest: [u8; 32],
        request_id: [u8; 16],
        attempt_id: [u8; 16],
        direction: PayloadDirectionV1,
        descriptor: PayloadDescriptorV1,
    ) -> Result<Self, SandboxContractErrorV1> {
        descriptor.validate_for_direction(direction)?;
        if parent_digest == [0; 32] || request_id == [0; 16] || attempt_id == [0; 16] {
            return Err(SandboxContractErrorV1::FieldOutOfBounds);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(direction.digest_domain());
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
    /// Rejects a foreign, duplicate, reordered, gapped, or wrongly sized chunk.
    pub fn accept(&mut self, chunk: &SandboxPayloadChunkV1) -> Result<(), SandboxContractErrorV1> {
        chunk.validate()?;
        let remaining = self
            .descriptor
            .byte_length
            .saturating_sub(self.accepted_bytes);
        let expected_size = remaining.min(SANDBOX_PAYLOAD_CHUNK_BYTES_V1 as u64);
        let identity_mismatch = chunk.parent_digest != self.parent_digest
            || chunk.request_id != self.request_id
            || chunk.attempt_id != self.attempt_id
            || chunk.direction != self.direction;
        let position_mismatch = chunk.index != self.next_index
            || chunk.offset != self.accepted_bytes
            || chunk.bytes.len() as u64 != expected_size
            || expected_size == 0;
        if identity_mismatch || position_mismatch {
            return Err(SandboxContractErrorV1::InconsistentFields);
        }
        self.hasher.update(&chunk.bytes);
        self.accepted_bytes += expected_size;
        self.next_index += 1;
        Ok(())
    }

    /// Finish after the exact descriptor length and digest have been observed.
    ///
    /// # Errors
    /// Rejects missing chunks or an aggregate payload-digest mismatch.
    pub fn finish(self) -> Result<(), SandboxContractErrorV1> {
        if self.accepted_bytes != self.descriptor.byte_length {
            return Err(SandboxContractErrorV1::InconsistentFields);
        }
        (self.hasher.finalize().as_bytes() == &self.descriptor.digest)
            .then_some(())
            .ok_or(SandboxContractErrorV1::DigestMismatch)
    }
}

// Implementations are kept below the data model so the public field order is
// readable beside ADR-069's wire order.

impl SandboxExecuteRequestV1 {
    /// Compute and install the exact SPX1 request digest.
    ///
    /// # Errors
    /// Returns a closed contract error when an unsigned field is invalid.
    pub fn seal(mut self) -> Result<Self, SandboxContractErrorV1> {
        self.validate_unsigned()?;
        self.request_digest = digest(SPX1, &self.unsigned_value())?;
        Ok(self)
    }

    /// Validate shape, relationships local to SPX1, ordering, and self-digest.
    ///
    /// # Errors
    /// Returns a closed contract error for invalid request data.
    pub fn validate(&self) -> Result<(), SandboxContractErrorV1> {
        self.validate_unsigned()?;
        (self.request_digest == digest(SPX1, &self.unsigned_value())?)
            .then_some(())
            .ok_or(SandboxContractErrorV1::DigestMismatch)
    }

    /// Encode exact deterministic-CBOR SPX1 bytes.
    ///
    /// # Errors
    /// Returns a closed contract error when validation or encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SandboxContractErrorV1> {
        self.validate()?;
        encode(&Value::Array(vec![
            self.unsigned_value(),
            value_bytes(&self.request_digest),
        ]))
    }

    /// Decode exact deterministic-CBOR SPX1 bytes.
    ///
    /// # Errors
    /// Returns a closed contract error for every malformed or noncanonical input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxContractErrorV1> {
        let value = decode(bytes)?;
        let fields = array::<2>(&value)?;
        let unsigned = array::<22>(&fields[0])?;
        validate_magic(unsigned, SPX1)?;
        let request = Self {
            authority: decode_request_authority(&unsigned[2])?,
            attempt_id: fixed(&unsigned[3])?,
            evr1_digest: fixed(&unsigned[4])?,
            cpf1_digest: fixed(&unsigned[5])?,
            cfb1_digest: fixed(&unsigned[6])?,
            fixture_contract_digest: fixed(&unsigned[7])?,
            fixture_digest: fixed(&unsigned[8])?,
            execution_profile_digest: fixed(&unsigned[9])?,
            lps1_digest: fixed(&unsigned[10])?,
            sim1_digest: fixed(&unsigned[11])?,
            apt1_digest: fixed(&unsigned[12])?,
            trs1_digest: fixed(&unsigned[13])?,
            rvs1_digest: fixed(&unsigned[14])?,
            spm1_digest: fixed(&unsigned[15])?,
            pcf1_digest: fixed(&unsigned[16])?,
            pcr1_digest: fixed(&unsigned[17])?,
            hcp1_digest: fixed(&unsigned[18])?,
            capability_ids: decode_identifiers(&unsigned[19])?,
            adapter_input: decode_payload_descriptor(&unsigned[20])?,
            network_plans: decode_network_plans(&unsigned[21])?,
            request_digest: fixed(&fields[1])?,
        };
        request.validate().map(|()| request)
    }

    fn validate_unsigned(&self) -> Result<(), SandboxContractErrorV1> {
        validate_request_authority(&self.authority)?;
        let digests = self.bound_digests();
        if self.attempt_id == [0; 16]
            || digests.contains(&[0; 32])
            || self.authority.apt1_digest != self.apt1_digest
            || self.capability_ids.len() > MAX_SANDBOX_PROVIDER_ENTRIES_V1
            || self.network_plans.len() > MAX_SANDBOX_PROVIDER_ENTRIES_V1
        {
            return Err(SandboxContractErrorV1::FieldOutOfBounds);
        }
        self.adapter_input
            .validate_for_direction(PayloadDirectionV1::Input)?;
        if self
            .capability_ids
            .iter()
            .any(|value| !identifier(value, MAX_IDENTIFIER_BYTES))
            || !self
                .capability_ids
                .windows(2)
                .all(|pair| pair[0].as_bytes() < pair[1].as_bytes())
        {
            return Err(SandboxContractErrorV1::NonCanonicalOrder);
        }
        self.network_plans
            .iter()
            .try_for_each(NetworkExchangePlanV1::validate)?;
        let mut next_occurrence = BTreeMap::new();
        for plan in &self.network_plans {
            let expected = next_occurrence.entry(plan.exchange_id).or_insert(0);
            if plan.occurrence != *expected {
                return Err(SandboxContractErrorV1::InconsistentFields);
            }
            *expected += 1;
        }
        Ok(())
    }

    const fn bound_digests(&self) -> [[u8; 32]; 15] {
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

    fn unsigned_value(&self) -> Value {
        let mut fields = vec![
            value_text(SPX1),
            value_uint(1),
            request_authority_value(&self.authority),
            value_bytes(&self.attempt_id),
        ];
        fields.extend(self.bound_digests().iter().map(|value| value_bytes(value)));
        fields.push(Value::Array(
            self.capability_ids
                .iter()
                .map(|value| value_text(value))
                .collect(),
        ));
        fields.push(payload_descriptor_value(&self.adapter_input));
        fields.push(Value::Array(
            self.network_plans
                .iter()
                .map(NetworkExchangePlanV1::value)
                .collect(),
        ));
        Value::Array(fields)
    }
}

fn request_authority_value(value: &RequestAuthorityV1) -> Value {
    Value::Array(vec![
        value_bytes(&value.request_id),
        value_bytes(&value.apt1_digest),
        value_uint(value.policy_epoch),
        value_bytes(&value.nonce),
    ])
}

fn decode_request_authority(value: &Value) -> Result<RequestAuthorityV1, SandboxContractErrorV1> {
    let fields = array::<4>(value)?;
    Ok(RequestAuthorityV1 {
        request_id: fixed(&fields[0])?,
        apt1_digest: fixed(&fields[1])?,
        policy_epoch: uint(&fields[2])?,
        nonce: fixed(&fields[3])?,
    })
}

fn validate_request_authority(value: &RequestAuthorityV1) -> Result<(), SandboxContractErrorV1> {
    if value.request_id == [0; 16] || value.apt1_digest == [0; 32] || value.nonce == [0; 16] {
        Err(SandboxContractErrorV1::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

fn payload_descriptor_value(value: &PayloadDescriptorV1) -> Value {
    Value::Array(vec![
        value_uint(value.byte_length),
        value_bytes(&value.digest),
    ])
}

fn decode_payload_descriptor(value: &Value) -> Result<PayloadDescriptorV1, SandboxContractErrorV1> {
    let fields = array::<2>(value)?;
    Ok(PayloadDescriptorV1 {
        byte_length: uint(&fields[0])?,
        digest: fixed(&fields[1])?,
    })
}

fn decode_identifiers(value: &Value) -> Result<Vec<String>, SandboxContractErrorV1> {
    let Value::Array(values) = value else {
        return Err(SandboxContractErrorV1::InvalidEncoding);
    };
    values
        .iter()
        .map(|value| text(value).map(ToOwned::to_owned))
        .collect()
}

fn decode_network_plans(
    value: &Value,
) -> Result<Vec<NetworkExchangePlanV1>, SandboxContractErrorV1> {
    let Value::Array(values) = value else {
        return Err(SandboxContractErrorV1::InvalidEncoding);
    };
    values
        .iter()
        .map(NetworkExchangePlanV1::from_value)
        .collect()
}

impl AdmissionGrantV1 {
    /// Seal this grant with the supplied runtime-attestation key.
    ///
    /// # Errors
    /// Returns a closed contract error when an unsigned field is invalid.
    pub fn sign(mut self, key: &ed25519_dalek::SigningKey) -> Result<Self, SandboxContractErrorV1> {
        self.validate_unsigned()?;
        self.grant_digest = digest(AGR1, &self.unsigned_value())?;
        self.signature = sign(AGR1, &self.grant_digest, key);
        Ok(self)
    }

    /// Validate shape, ordering, and self-digest.
    ///
    /// # Errors
    /// Returns a closed contract error for invalid grant data.
    pub fn validate(&self) -> Result<(), SandboxContractErrorV1> {
        self.validate_unsigned()?;
        validate_signed_bytes(&self.signature)?;
        (self.grant_digest == digest(AGR1, &self.unsigned_value())?)
            .then_some(())
            .ok_or(SandboxContractErrorV1::DigestMismatch)
    }

    /// Verify this grant with an authorized runtime-attestation key.
    ///
    /// # Errors
    /// Returns a closed error when shape, digest, or signature verification fails.
    pub fn verify_signature(
        &self,
        key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), SandboxContractErrorV1> {
        self.validate()?;
        verify(AGR1, &self.grant_digest, &self.signature, key)
    }

    /// Encode exact deterministic-CBOR AGR1 bytes.
    ///
    /// # Errors
    /// Returns a closed contract error when validation or encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SandboxContractErrorV1> {
        self.validate()?;
        encode_signed(&self.unsigned_value(), &self.grant_digest, &self.signature)
    }

    /// Decode exact deterministic-CBOR AGR1 bytes.
    ///
    /// # Errors
    /// Returns a closed contract error for every malformed or noncanonical input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxContractErrorV1> {
        let value = decode(bytes)?;
        let fields = array::<3>(&value)?;
        let unsigned = array::<26>(&fields[0])?;
        validate_magic(unsigned, AGR1)?;
        let grant = Self {
            request_id: fixed(&unsigned[2])?,
            attempt_id: fixed(&unsigned[3])?,
            authority: AdmissionAuthorityV1::from_fields(&unsigned[4..17])?,
            trust_epoch: uint(&unsigned[17])?,
            revocation_epoch: uint(&unsigned[18])?,
            policy_epoch: uint(&unsigned[19])?,
            elm1_digest: fixed(&unsigned[20])?,
            input_digest: fixed(&unsigned[21])?,
            exchange_plan_digests: decode_digest_list(&unsigned[22])?,
            expected_launch_policy_digest: fixed(&unsigned[23])?,
            expected_readback_set_digest: fixed(&unsigned[24])?,
            runtime_attestation_key_id: text(&unsigned[25])?.to_owned(),
            grant_digest: fixed(&fields[1])?,
            signature: fixed(&fields[2])?,
        };
        grant.validate().map(|()| grant)
    }

    fn validate_unsigned(&self) -> Result<(), SandboxContractErrorV1> {
        let trailing = [
            self.elm1_digest,
            self.input_digest,
            self.expected_launch_policy_digest,
            self.expected_readback_set_digest,
        ];
        if self.request_id == [0; 16]
            || self.attempt_id == [0; 16]
            || self.authority.has_zero_digest()
            || trailing.contains(&[0; 32])
            || self.exchange_plan_digests.len() > MAX_SANDBOX_PROVIDER_ENTRIES_V1
            || self.exchange_plan_digests.contains(&[0; 32])
            || !bounded_text(&self.runtime_attestation_key_id, MAX_IDENTIFIER_BYTES)
        {
            Err(SandboxContractErrorV1::FieldOutOfBounds)
        } else {
            Ok(())
        }
    }

    fn unsigned_value(&self) -> Value {
        let mut fields = vec![
            value_text(AGR1),
            value_uint(1),
            value_bytes(&self.request_id),
            value_bytes(&self.attempt_id),
        ];
        fields.extend(self.authority.values());
        fields.extend([
            value_uint(self.trust_epoch),
            value_uint(self.revocation_epoch),
            value_uint(self.policy_epoch),
            value_bytes(&self.elm1_digest),
            value_bytes(&self.input_digest),
            Value::Array(
                self.exchange_plan_digests
                    .iter()
                    .map(|value| value_bytes(value))
                    .collect(),
            ),
            value_bytes(&self.expected_launch_policy_digest),
            value_bytes(&self.expected_readback_set_digest),
            value_text(&self.runtime_attestation_key_id),
        ]);
        Value::Array(fields)
    }
}

fn encode_signed(
    unsigned: &Value,
    self_digest: &[u8; 32],
    signature: &[u8; 64],
) -> Result<Vec<u8>, SandboxContractErrorV1> {
    encode(&Value::Array(vec![
        unsigned.clone(),
        value_bytes(self_digest),
        value_bytes(signature),
    ]))
}

fn validate_signed_bytes(signature: &[u8; 64]) -> Result<(), SandboxContractErrorV1> {
    if signature == &[0; 64] {
        Err(SandboxContractErrorV1::SignatureInvalid)
    } else {
        Ok(())
    }
}

impl AdmissionAuthorityV1 {
    fn from_fields(fields: &[Value]) -> Result<Self, SandboxContractErrorV1> {
        let fields: &[Value; 13] = fields
            .try_into()
            .map_err(|_| SandboxContractErrorV1::InvalidEncoding)?;
        Ok(Self {
            evr1_digest: fixed(&fields[0])?,
            fixture_contract_digest: fixed(&fields[1])?,
            fixture_digest: fixed(&fields[2])?,
            execution_profile_digest: fixed(&fields[3])?,
            lps1_digest: fixed(&fields[4])?,
            sim1_digest: fixed(&fields[5])?,
            apt1_digest: fixed(&fields[6])?,
            trs1_digest: fixed(&fields[7])?,
            rvs1_digest: fixed(&fields[8])?,
            spm1_digest: fixed(&fields[9])?,
            pcf1_digest: fixed(&fields[10])?,
            pcr1_digest: fixed(&fields[11])?,
            hcp1_digest: fixed(&fields[12])?,
        })
    }

    const fn digests(&self) -> [[u8; 32]; 13] {
        [
            self.evr1_digest,
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

    fn values(&self) -> Vec<Value> {
        self.digests()
            .into_iter()
            .map(|value| value_bytes(&value))
            .collect()
    }
}

fn decode_digest_list(value: &Value) -> Result<Vec<[u8; 32]>, SandboxContractErrorV1> {
    let Value::Array(values) = value else {
        return Err(SandboxContractErrorV1::InvalidEncoding);
    };
    values.iter().map(fixed).collect()
}

const fn bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum
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
            || !bounded_text(&self.runtime_attestation_key_id, MAX_IDENTIFIER_BYTES)
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
            17 => Ok(Self::AttemptInProgress),
            18 => Ok(Self::PayloadTransferTimeout),
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
                value.is_empty() || value.len() > MAX_SAFE_DETAIL_BYTES || value.contains('\0')
            })
            || !bounded_text(&self.runtime_attestation_key_id, MAX_IDENTIFIER_BYTES)
        {
            return Err(SandboxContractErrorV1::FieldOutOfBounds);
        }
        if (self.request_digest.is_some() && self.request_id.is_none())
            || (self.attempt_id.is_some()
                && (self.operation.is_none() || self.request_id.is_none()))
        {
            return Err(SandboxContractErrorV1::InconsistentFields);
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

impl SandboxProviderReceiptV1 {
    /// Seal this receipt with the supplied runtime-attestation key.
    ///
    /// # Errors
    /// Returns a closed contract error when an unsigned field is invalid.
    pub fn sign(mut self, key: &ed25519_dalek::SigningKey) -> Result<Self, SandboxContractErrorV1> {
        self.validate_unsigned()?;
        self.receipt_digest = digest(SPR1, &self.unsigned_value())?;
        self.signature = sign(SPR1, &self.receipt_digest, key);
        Ok(self)
    }

    /// Validate evidence bindings, bounds, and self-digest.
    ///
    /// # Errors
    /// Returns a closed contract error for invalid receipt data.
    pub fn validate(&self) -> Result<(), SandboxContractErrorV1> {
        self.validate_unsigned()?;
        validate_signed_bytes(&self.signature)?;
        (self.receipt_digest == digest(SPR1, &self.unsigned_value())?)
            .then_some(())
            .ok_or(SandboxContractErrorV1::DigestMismatch)
    }

    /// Verify this receipt with an authorized runtime-attestation key.
    ///
    /// # Errors
    /// Returns a closed error when shape, digest, or signature verification fails.
    pub fn verify_signature(
        &self,
        key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), SandboxContractErrorV1> {
        self.validate()?;
        verify(SPR1, &self.receipt_digest, &self.signature, key)
    }

    /// Encode exact deterministic-CBOR SPR1 bytes.
    ///
    /// # Errors
    /// Returns a closed contract error when validation or encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SandboxContractErrorV1> {
        self.validate()?;
        encode_signed(
            &self.unsigned_value(),
            &self.receipt_digest,
            &self.signature,
        )
    }

    /// Decode exact deterministic-CBOR SPR1 bytes.
    ///
    /// # Errors
    /// Returns a closed contract error for every malformed or noncanonical input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxContractErrorV1> {
        let value = decode(bytes)?;
        let fields = array::<3>(&value)?;
        let unsigned = array::<25>(&fields[0])?;
        validate_magic(unsigned, SPR1)?;
        let receipt = Self {
            attempt_id: fixed(&unsigned[2])?,
            authority: ReceiptAuthorityV1::from_fields(&unsigned[3..11])?,
            trust_epoch: uint(&unsigned[11])?,
            revocation_epoch: uint(&unsigned[12])?,
            policy_epoch: uint(&unsigned[13])?,
            hcp1_digest: fixed(&unsigned[14])?,
            elm1_digest: fixed(&unsigned[15])?,
            network_transcript_digests: decode_digest_list(&unsigned[16])?,
            ready1_digest: optional_fixed(&unsigned[17])?,
            release1_digest: optional_fixed(&unsigned[18])?,
            requested_configuration_evidence: fixed(&unsigned[19])?,
            kernel_observation_evidence: fixed(&unsigned[20])?,
            negative_probe_evidence: fixed(&unsigned[21])?,
            termination_evidence: fixed(&unsigned[22])?,
            sau1_digest: fixed(&unsigned[23])?,
            runtime_attestation_key_id: text(&unsigned[24])?.to_owned(),
            receipt_digest: fixed(&fields[1])?,
            signature: fixed(&fields[2])?,
        };
        receipt.validate().map(|()| receipt)
    }

    fn validate_unsigned(&self) -> Result<(), SandboxContractErrorV1> {
        let evidence = [
            self.hcp1_digest,
            self.elm1_digest,
            self.requested_configuration_evidence,
            self.kernel_observation_evidence,
            self.negative_probe_evidence,
            self.termination_evidence,
            self.sau1_digest,
        ];
        if self.attempt_id == [0; 16]
            || self.authority.has_zero_digest()
            || evidence.contains(&[0; 32])
            || self.network_transcript_digests.len() > MAX_SANDBOX_PROVIDER_ENTRIES_V1
            || self.network_transcript_digests.contains(&[0; 32])
            || self.ready1_digest == Some([0; 32])
            || self.release1_digest == Some([0; 32])
            || !bounded_text(&self.runtime_attestation_key_id, MAX_IDENTIFIER_BYTES)
        {
            return Err(SandboxContractErrorV1::FieldOutOfBounds);
        }
        if self.release1_digest.is_some() && self.ready1_digest.is_none() {
            return Err(SandboxContractErrorV1::InconsistentFields);
        }
        Ok(())
    }

    fn unsigned_value(&self) -> Value {
        let mut fields = vec![
            value_text(SPR1),
            value_uint(1),
            value_bytes(&self.attempt_id),
        ];
        fields.extend(self.authority.values());
        fields.extend([
            value_uint(self.trust_epoch),
            value_uint(self.revocation_epoch),
            value_uint(self.policy_epoch),
            value_bytes(&self.hcp1_digest),
            value_bytes(&self.elm1_digest),
            Value::Array(
                self.network_transcript_digests
                    .iter()
                    .map(|value| value_bytes(value))
                    .collect(),
            ),
            value_optional_bytes(self.ready1_digest.as_ref()),
            value_optional_bytes(self.release1_digest.as_ref()),
            value_bytes(&self.requested_configuration_evidence),
            value_bytes(&self.kernel_observation_evidence),
            value_bytes(&self.negative_probe_evidence),
            value_bytes(&self.termination_evidence),
            value_bytes(&self.sau1_digest),
            value_text(&self.runtime_attestation_key_id),
        ]);
        Value::Array(fields)
    }
}

impl ReceiptAuthorityV1 {
    fn from_fields(fields: &[Value]) -> Result<Self, SandboxContractErrorV1> {
        let fields: &[Value; 8] = fields
            .try_into()
            .map_err(|_| SandboxContractErrorV1::InvalidEncoding)?;
        Ok(Self {
            agr1_digest: fixed(&fields[0])?,
            spm1_digest: fixed(&fields[1])?,
            provider_binary_digest: fixed(&fields[2])?,
            lps1_digest: fixed(&fields[3])?,
            sim1_digest: fixed(&fields[4])?,
            apt1_digest: fixed(&fields[5])?,
            trs1_digest: fixed(&fields[6])?,
            rvs1_digest: fixed(&fields[7])?,
        })
    }

    const fn digests(&self) -> [[u8; 32]; 8] {
        [
            self.agr1_digest,
            self.spm1_digest,
            self.provider_binary_digest,
            self.lps1_digest,
            self.sim1_digest,
            self.apt1_digest,
            self.trs1_digest,
            self.rvs1_digest,
        ]
    }

    fn has_zero_digest(&self) -> bool {
        self.digests().contains(&[0; 32])
    }

    fn values(&self) -> Vec<Value> {
        self.digests()
            .into_iter()
            .map(|value| value_bytes(&value))
            .collect()
    }
}
